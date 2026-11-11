//! G1.6zn in `ab-test --scenario to-ram`: the system in RAM, and the system
//! disk pulled out of the running router.
//!
//! The image is installed as every scenario does it (`ab::fresh`, the disk
//! on virtio), then booted from the same disk as a USB stick (`usb-storage`
//! on an xHCI controller, what the notebook of 2026-11-11 booted from):
//!
//! 1. with the option off, as a baseline: the boot time, and the option
//!    set on through the control channel (`system.boot.set`);
//! 2. with it on: the root goes to RAM through dm-verity (the init's line
//!    gives the copy's time), the boot time again; then the stick is taken
//!    out with QEMU's monitor (`device_del`, a USB surprise removal). The
//!    console shows one line and none of the kernel's I/O errors, the
//!    control channel still answers, the health check says it, a commit is
//!    refused with the line, and Safe Mode still changes the router;
//! 3. with it off again: the same line, saying the system runs from the
//!    disk that went away.

#![allow(clippy::indexing_slicing)]

use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::ab::{Ctx, Numbers, Vm, check, fresh, qemu_machine, ready_s, shell_line, start};

/// The kernel's lines for a missing disk: what the console no longer shows.
const IO_ERRORS: [&str; 5] = [
    "SQUASHFS error",
    "EXT4-fs error",
    "I/O error",
    "bread failed",
    "Buffer I/O",
];

/// The installed disk as a USB stick, with a monitor to pull it out.
fn boot_usb(ctx: &mut Ctx, name: &str, mon: &Path) -> Result<Vm, String> {
    let _ = std::fs::remove_file(mon);
    let mut cmd: Command = qemu_machine(ctx.kvm, ctx.fw, &ctx.work.join("vars.fd"));
    cmd.arg("-monitor")
        .arg(format!("unix:{},server=on,wait=off", mon.display()));
    cmd.args(["-device", "qemu-xhci,id=xhci"]);
    cmd.arg("-drive").arg(format!(
        "file={},if=none,id=stick,format=qcow2",
        ctx.work.join("disk.qcow2").display()
    ));
    cmd.args([
        "-device",
        "usb-storage,bus=xhci.0,drive=stick,id=sysdisk,removable=on,bootindex=1",
    ]);
    cmd.args(["-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0"]);
    let mut log = ctx.log.try_clone().map_err(|e| e.to_string())?;
    start(&mut log, name, cmd)
}

/// `… in 412 ms` of the init's line.
fn copy_ms(line: &str) -> Option<u64> {
    let (head, _) = line.rsplit_once(" ms")?;
    head.rsplit(' ').next()?.parse().ok()
}

fn health(vm: &mut Vm, log: &mut std::fs::File, key: &str) -> Result<Value, String> {
    let v = vm.ok(log, "system.health.check", "{}")?;
    let checks = v.get("checks").cloned().unwrap_or(v);
    checks
        .as_array()
        .and_then(|a| a.iter().find(|c| c["key"] == key).cloned())
        .ok_or_else(|| format!("no {key} health check: {checks}"))
}

pub(super) fn scenario(ctx: &mut Ctx, n: &mut Numbers) -> Result<(), String> {
    let mut log = ctx.log.try_clone().map_err(|e| e.to_string())?;
    let mon = ctx.work.join("to-ram.monitor");
    let mut vm = fresh(ctx, n, "to-ram", &[])?;
    vm.poweroff(&mut log)?;
    drop(vm);

    // 1. From the stick, option off.
    let mut vm = boot_usb(ctx, "to-ram/usb-disk", &mon)?;
    let r = vm.expect_all(&mut log, &["ready:", "maintenance shell"], 120)?;
    n.put(
        "USB stick, root on the disk: kernel → daemon ready",
        ready_s(r.first().map_or("", String::as_str)),
    );
    let d = health(&mut vm, &mut log, "system.disk")?;
    check(d["severity"] == "ok", format!("system.disk on the disk: {d}"))?;
    let v = vm.ok(&mut log, "system.boot.set", r#"{"to_ram":true}"#)?;
    check(v["next_boot"] == "ram", format!("system.boot.set: {v}"))?;
    // The package service keeps it where the init reads it.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let f = shell_line(&mut vm, &mut log, "cat /config/package/boot.json")?;
        if f.contains("\"to_ram\":true") {
            break;
        }
        check(Instant::now() < deadline, format!("boot.json never said to_ram: {f}"))?;
        std::thread::sleep(Duration::from_millis(500));
    }
    vm.poweroff(&mut log)?;
    drop(vm);

    // 2. From RAM, and the stick pulled out.
    let mut vm = boot_usb(ctx, "to-ram/ram", &mon)?;
    let r = vm.expect_all(&mut log, &["system in RAM:", "ready:", "maintenance shell"], 120)?;
    let copied = r.first().map_or("", String::as_str);
    check(!copied.contains("running from the disk"), format!("stayed on the disk: {copied}"))?;
    n.put(
        "root to RAM through dm-verity (USB stick in QEMU)",
        copy_ms(copied).map_or_else(|| "?".into(), |ms| format!("{ms} ms")),
    );
    n.put(
        "USB stick, root in RAM: kernel → daemon ready",
        ready_s(r.get(1).map_or("", String::as_str)),
    );
    let b = vm.ok(&mut log, "system.boot.print", "{}")?;
    check(b["running"]["in_ram"] == true, format!("system.boot.print: {b}"))?;
    let mem = shell_line(&mut vm, &mut log, "grep -E 'MemAvailable|Shmem:' /proc/meminfo | tr -s ' ' | tr '\\n' ' '")?;
    n.put("memory with the root in RAM", mem);
    let out = super::hotplug::hmp(&mon, "device_del sysdisk")?;
    let _ = writeln!(log, "monitor: device_del sysdisk → {}", out.trim());
    let line = vm.expect(&mut log, &["removed: the router keeps running from RAM"], 30)?;
    check(line.contains("system disk"), format!("the line: {line}"))?;
    // What the console shows after it: the line, and nothing of the disk.
    let after = vm.lines_for(&mut log, 8);
    let noisy: Vec<&String> = after
        .iter()
        .filter(|l| IO_ERRORS.iter().any(|e| l.contains(e)))
        .collect();
    check(noisy.is_empty(), format!("I/O errors on the console after the line: {noisy:?}"))?;
    // The router answers, and says what happened.
    let d = health(&mut vm, &mut log, "system.disk")?;
    check(d["severity"] == "error", format!("system.disk after the removal: {d}"))?;
    let refused = vm.run(&mut log, "system.identity.set", r#"{"name":"lost"}"#)?;
    check(
        refused["ok"] == false && refused.to_string().contains("removed"),
        format!("a commit without the disk: {refused}"),
    )?;
    vm.ok(&mut log, "config.safe-mode.enter", "{}")?;
    vm.ok(&mut log, "system.identity.set", r#"{"name":"for-now"}"#)?;
    vm.ok(&mut log, "config.safe-mode.cancel", "{}")?;
    let after = vm.lines_for(&mut log, 3);
    let noisy = after.iter().filter(|l| IO_ERRORS.iter().any(|e| l.contains(e))).count();
    check(noisy == 0, "I/O errors on the console while the router was used")?;
    n.put("system disk pulled out, root in RAM", "one line; control channel answers; commit refused".to_owned());
    drop(vm);

    // 3. Option off again, and the stick pulled out of a root on it.
    let mut vm = boot_usb(ctx, "to-ram/back", &mon)?;
    vm.expect_all(&mut log, &["system in RAM:", "ready:", "maintenance shell"], 120)?;
    vm.ok(&mut log, "system.boot.set", r#"{"to_ram":false}"#)?;
    let deadline = Instant::now() + Duration::from_secs(15);
    while !shell_line(&mut vm, &mut log, "cat /config/package/boot.json")?.contains("\"to_ram\":false") {
        check(Instant::now() < deadline, "boot.json never said to_ram false")?;
        std::thread::sleep(Duration::from_millis(500));
    }
    vm.poweroff(&mut log)?;
    drop(vm);
    let mut vm = boot_usb(ctx, "to-ram/disk-pulled", &mon)?;
    let r = vm.expect_all(&mut log, &["ready:", "maintenance shell"], 120)?;
    check(
        !r.iter().any(|l| l.contains("system in RAM")),
        "the option off still copied the root",
    )?;
    super::hotplug::hmp(&mon, "device_del sysdisk")?;
    vm.expect(&mut log, &["removed: the system runs from that disk"], 30)?;
    n.put("system disk pulled out, root on it", "one line".to_owned());
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn copy_time_from_the_line() {
        let l = "corerouter-init: system in RAM: 87 MiB of root read from sda through dm-verity in 412 ms; the system disk can go";
        assert_eq!(super::copy_ms(l), Some(412));
        assert_eq!(super::copy_ms("nothing"), None);
    }
}
