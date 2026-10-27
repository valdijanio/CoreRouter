//! G1.6c: `cargo xtask os install-test` — the installer and the VM images
//! in QEMU, as the user (OVMF, KVM or TCG), no root, no real disk:
//!
//! 1. `cd`: the ISO as a CD, a blank 2 GiB virtual disk; the installer runs
//!    unattended through the test's fw_cfg flag (it names the disk twice,
//!    a management address for eth0 and the maintenance shell), powers off.
//! 2. `disk`: the installed disk alone, through the boot entry the
//!    installer wrote: slot A on dm-verity, the management address applied
//!    (TLS ping from the host), FRR's daemons up, a BGP instance and peer
//!    pushed to bgpd (the session is FRR's), saved.
//! 3. `usb`: the ISO as a USB stick (the hybrid GPT), installing again over
//!    the same disk keeping its configuration; the next boot still has the
//!    address (once) and the BGP config, pushed again to the new FRR.
//! 4. `qcow2` and `ova`: the VM images boot as they are (the removable-media
//!    path), with the console setup offered (no address yet).

#![allow(clippy::indexing_slicing)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::ab::{Numbers, Vm, check, fresh_vars, qemu_base, ready_s, slot, start};

const MGMT: &str = "eth0,10.0.2.15/24,10.0.2.2";

fn autoinstall(keep: bool) -> String {
    serde_json::json!({
        "disk": "vda",
        "confirm": "vda",
        "keep_config": keep,
        "append": "corerouter.shell=ttyS0",
        "mgmt": MGMT,
        "then": "poweroff",
    })
    .to_string()
}

struct T {
    work: PathBuf,
    images: PathBuf,
    kvm: bool,
    log: std::fs::File,
    n: Numbers,
}

impl T {
    fn vars(&self) -> PathBuf {
        self.work.join("vars.fd")
    }

    /// The installer from `medium` onto `target.qcow2`.
    fn install(&mut self, medium: &str, keep: bool) -> Result<(), String> {
        let iso = self.images.join("corerouter-install.iso");
        let mut cmd = qemu_base(self.kvm, &self.vars());
        cmd.arg("-drive").arg(format!(
            "file={},if=none,id=target,format=qcow2",
            self.work.join("target.qcow2").display()
        ));
        cmd.args(["-device", "virtio-blk-pci,drive=target"]);
        match medium {
            "cd" => {
                cmd.arg("-drive").arg(format!(
                    "file={},if=none,id=cd,format=raw,media=cdrom,readonly=on",
                    iso.display()
                ));
                cmd.args(["-device", "ide-cd,drive=cd,bootindex=0"]);
            }
            _ => {
                cmd.arg("-drive").arg(format!(
                    "file={},if=none,id=stick,format=raw,readonly=on",
                    iso.display()
                ));
                cmd.args([
                    "-device",
                    "qemu-xhci",
                    "-device",
                    "usb-storage,drive=stick,removable=on,bootindex=0",
                ]);
            }
        }
        cmd.arg("-fw_cfg").arg(format!(
            "name=opt/org.corerouter/autoinstall,string={}",
            autoinstall(keep).replace(',', ",,")
        ));
        cmd.args([
            "-netdev",
            "user,id=n0",
            "-device",
            "virtio-net-pci,netdev=n0",
        ]);
        let name = format!("install/{medium}");
        let mut vm = start(&mut self.log, &name, cmd)?;
        let line = vm.expect(&mut self.log, &["INSTALLED", "install failed"], 300)?;
        check(line.contains("INSTALLED"), format!("[{name}] {line}"))?;
        let total = vm.wait_exit(&mut self.log, 60)?;
        self.n
            .put(&format!("{medium}: installer line"), line.trim().to_owned());
        self.n.put(
            &format!("{medium}: qemu start → powered off after the install"),
            format!("{:.1} s", total.as_secs_f64()),
        );
        Ok(())
    }

    /// The installed disk alone, through the firmware's boot entries.
    fn boot_disk(&mut self, name: &str, port: u16) -> Result<Vm, String> {
        let mut cmd = qemu_base(self.kvm, &self.vars());
        cmd.arg("-drive").arg(format!(
            "file={},if=virtio,format=qcow2",
            self.work.join("target.qcow2").display()
        ));
        cmd.arg("-netdev").arg(format!(
            "user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:{}",
            super::GUEST_TLS_PORT
        ));
        cmd.args(["-device", "virtio-net-pci,netdev=n0"]);
        start(&mut self.log, name, cmd)
    }

    /// A VM image as it is (a throw-away overlay), fresh NVRAM. With
    /// `setup`, the console setup is answered on the serial console (port,
    /// address, gateway, admin password) and the address pinged over TLS.
    fn boot_image(
        &mut self,
        name: &str,
        file: &Path,
        format: &str,
        setup: bool,
    ) -> Result<(), String> {
        fresh_vars(&self.vars())?;
        let port = super::free_port()?;
        let mut cmd = qemu_base(self.kvm, &self.vars());
        cmd.arg("-drive").arg(format!(
            "file={},if=virtio,format={format},snapshot=on",
            file.display()
        ));
        cmd.arg("-netdev").arg(format!(
            "user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:{}",
            super::GUEST_TLS_PORT
        ));
        cmd.args(["-device", "virtio-net-pci,netdev=n0"]);
        let mut log = self.log.try_clone().map_err(|e| e.to_string())?;
        let mut vm = start(&mut log, name, cmd)?;
        let t = Instant::now();
        let r = vm.expect_all(
            &mut log,
            &["ready:", "FRR up:", "first-boot setup on the console"],
            120,
        )?;
        self.n.put(
            &format!(
                "{name}: kernel → daemon ready (qemu start → ready {:.1} s)",
                t.elapsed().as_secs_f64()
            ),
            ready_s(r.first().map_or("", String::as_str)),
        );
        if !setup {
            return Ok(());
        }
        answer(&mut vm, &mut log, "no management address is set", "")?;
        answer(&mut vm, &mut log, "Ports:", "")?;
        answer(&mut vm, &mut log, "Port [", "10.0.2.15/24")?;
        answer(&mut vm, &mut log, "Address/prefix", "10.0.2.2")?;
        answer(&mut vm, &mut log, "has no password", "corerouter-test-1")?;
        answer(&mut vm, &mut log, "New admin password", "corerouter-test-1")?;
        vm.expect(&mut log, &["admin password: set"], 30)?;
        vm.expect(&mut log, &["Done. Manage it"], 30)?;
        let mut ping = Err(String::new());
        for _ in 0..10 {
            ping = super::tls_ping(port);
            if ping.is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        self.n
            .put(&format!("{name}: console setup, then TLS ping"), ping?);
        Ok(())
    }
}

/// Types `text` once a line with `after` went by (the prompt itself has no
/// newline; the installer drops what was typed before it asks).
fn answer(vm: &mut Vm, log: &mut std::fs::File, after: &str, text: &str) -> Result<String, String> {
    let l = vm.expect(log, &[after], 60)?;
    std::thread::sleep(Duration::from_millis(800));
    vm.stdin_write(format!("{text}\n").as_bytes())?;
    Ok(l)
}

/// The installer by hand, on the serial console, from the USB stick: the
/// stick is refused, a mistyped name writes nothing, then a real install
/// keeping the configuration.
fn interactive(t: &mut T) -> Result<(), String> {
    let iso = t.images.join("corerouter-install.iso");
    let mut cmd = qemu_base(t.kvm, &t.vars());
    cmd.arg("-drive").arg(format!(
        "file={},if=none,id=target,format=qcow2",
        t.work.join("target.qcow2").display()
    ));
    cmd.args(["-device", "virtio-blk-pci,drive=target"]);
    cmd.arg("-drive").arg(format!(
        "file={},if=none,id=stick,format=raw,readonly=on",
        iso.display()
    ));
    cmd.args([
        "-device",
        "qemu-xhci",
        "-device",
        "usb-storage,drive=stick,removable=on,bootindex=0",
    ]);
    let mut log = t.log.try_clone().map_err(|e| e.to_string())?;
    let mut vm = start(&mut log, "install/interactive", cmd)?;
    let row = vm.expect(&mut log, &["not offered: the installer medium"], 120)?;
    check(row.contains("sda"), format!("the stick is not sda: {row}"))?;
    std::thread::sleep(Duration::from_millis(800));
    vm.stdin_write(b"sda\n")?;
    vm.expect(
        &mut log,
        &["sda cannot be the target: the installer medium"],
        30,
    )?;
    answer(&mut vm, &mut log, "CoreRouter", "vda")?;
    answer(&mut vm, &mut log, "ALL DATA ON vda WILL BE ERASED", "y")?;
    answer(
        &mut vm,
        &mut log,
        "Management address for the first boot",
        "",
    )?;
    vm.expect(&mut log, &["(e.g. eth0"], 30)?;
    std::thread::sleep(Duration::from_millis(800));
    vm.stdin_write(b"vdb\n")?;
    vm.expect(&mut log, &["Nothing was written."], 30)?;
    answer(&mut vm, &mut log, "CoreRouter", "1")?;
    answer(&mut vm, &mut log, "ALL DATA ON vda WILL BE ERASED", "y")?;
    answer(
        &mut vm,
        &mut log,
        "Management address for the first boot",
        "",
    )?;
    vm.expect(&mut log, &["(e.g. eth0"], 30)?;
    std::thread::sleep(Duration::from_millis(800));
    vm.stdin_write(b"vda\n")?;
    let line = vm.expect(&mut log, &["INSTALLED", "install failed"], 120)?;
    check(
        line.contains("INSTALLED") && line.contains("configuration kept"),
        format!("[interactive] {line}"),
    )?;
    std::thread::sleep(Duration::from_millis(800));
    vm.stdin_write(b"\n")?;
    vm.wait_exit(&mut log, 60)?;
    t.n.put(
        "interactive (USB): stick refused, wrong name refused, then",
        line.trim().to_owned(),
    );
    Ok(())
}

/// `sh` in the guest: the output of `cmd`, marked.
fn sh(vm: &mut Vm, log: &mut std::fs::File, cmd: &str) -> Result<String, String> {
    let line = format!("{cmd} 2>&1 | tr '\\n' ' ' | sed \"s/^/@@$((2+2))S /\"; echo\n");
    vm.stdin_write(line.as_bytes())?;
    let got = vm.expect(log, &["@@4S "], 60)?;
    Ok(got.split("@@4S ").nth(1).unwrap_or("").trim().to_owned())
}

fn until(
    vm: &mut Vm,
    log: &mut std::fs::File,
    secs: u64,
    cmd: &str,
    params: &str,
    pred: impl Fn(&Value) -> bool,
) -> Result<Value, String> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let v = vm.run(log, cmd, params)?;
        if pred(&v) {
            return Ok(v);
        }
        if Instant::now() >= deadline {
            return Err(format!("{cmd}: never matched: {v}"));
        }
        std::thread::sleep(Duration::from_millis(700));
    }
}

/// What every boot of the installed disk must show.
fn check_installed(t: &mut T, vm: &mut Vm, port: u16, first: bool) -> Result<(), String> {
    let mut log = t.log.try_clone().map_err(|e| e.to_string())?;
    let r = vm.expect_all(&mut log, &["ready:", "maintenance shell", "FRR up:"], 120)?;
    let what = if first {
        "first boot"
    } else {
        "boot after the reinstall"
    };
    t.n.put(
        &format!("installed disk, {what}: kernel → daemon ready"),
        ready_s(r.first().map_or("", String::as_str)),
    );
    t.n.put(
        &format!("installed disk, {what}: FRR"),
        r.get(2)
            .and_then(|l| l.split("FRR up: ").nth(1))
            .unwrap_or("?")
            .to_owned(),
    );
    let p = vm.print_until(&mut log, 30, |v| {
        v.get("running").and_then(Value::as_str) == Some("a")
    })?;
    check(
        slot(&p, "a")["verity"] == Value::Bool(true),
        format!("not slot A on dm-verity: {p}"),
    )?;
    // The installer's address, applied once (the reinstall keeps the
    // configuration and the marker).
    let a = until(vm, &mut log, 30, "ip.address.list", "{}", |v| {
        v["result"].as_array().is_some_and(|a| !a.is_empty())
    })?;
    let n = a["result"].as_array().map_or(0, Vec::len);
    check(n == 1, format!("expected one address, got {a}"))?;
    let mut ping = Err(String::new());
    for _ in 0..10 {
        ping = super::tls_ping(port);
        if ping.is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if let Err(e) = &ping {
        let diag = sh(
            vm,
            &mut log,
            "grep -iE 'management|interface|error|warn' /var/log/corerouter-daemon.log | tail -20; ip addr 2>&1 | head -20",
        )?;
        return Err(format!("{e}; guest: {diag}"));
    }
    t.n.put(
        &format!("{what}: TLS ping on the management address"),
        ping?,
    );
    // FRR: the daemons, the frr service attached.
    let vty = sh(vm, &mut log, "ls /var/run/frr/ | grep -c 'vty$'")?;
    t.n.put(&format!("{what}: FRR vty sockets"), vty.clone());
    check(
        vty.trim().parse::<u32>().unwrap_or(0) >= 7,
        format!("FRR vty sockets: {vty}"),
    )?;
    let s = until(
        vm,
        &mut log,
        30,
        "system.service.print",
        r#"{"name":"frr"}"#,
        |v| {
            v["result"][0]["state"] == "running"
                && v["result"][0]["last_event"]
                    .as_str()
                    .is_some_and(|e| e.contains("FRR"))
        },
    )?;
    t.n.put(
        &format!("{what}: frr service"),
        s["result"][0]["last_event"].to_string(),
    );
    if first {
        vm.ok(
            &mut log,
            "routing.bgp.instance.set",
            r#"{"asn":65001,"router_id":"10.0.2.15"}"#,
        )?;
        vm.ok(
            &mut log,
            "routing.bgp.connection.add",
            r#"{"name":"peer1","remote_address":"10.0.2.2","remote_as":65002}"#,
        )?;
    }
    let c = until(vm, &mut log, 30, "routing.bgp.connection.list", "{}", |v| {
        v["result"][0]["state"]
            .as_str()
            .is_some_and(|s| s != "unknown" && s != "disabled")
    })?;
    t.n.put(
        &format!("{what}: BGP peer state (from bgpd)"),
        c["result"][0]["state"].to_string(),
    );
    let rss = sh(
        vm,
        &mut log,
        "for p in mgmtd zebra staticd bgpd ospfd ospf6d ldpd bfdd corerouter-daemon; do printf '%s=%s ' $p $(grep VmRSS /proc/$(pidof -s $p)/status | tr -s ' ' | cut -d' ' -f2); done",
    )?;
    t.n.put(&format!("{what}: RSS KiB"), rss);
    let mem = sh(
        vm,
        &mut log,
        "grep -E 'MemTotal|MemAvailable' /proc/meminfo | tr -s ' '",
    )?;
    t.n.put(&format!("{what}: memory"), mem);
    vm.poweroff(&mut log)
}

pub fn install_test(root: &Path, images: &Path, args: &[String]) -> Result<(), String> {
    let mut tcg = false;
    for a in args {
        match a.as_str() {
            "--tcg" => tcg = true,
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    for f in [
        "corerouter-install.iso",
        "corerouter.qcow2",
        "corerouter.ova",
    ] {
        check(
            images.join(f).exists(),
            format!(
                "{} missing: run `cargo xtask os build` first",
                images.join(f).display()
            ),
        )?;
    }
    let work = root.join("os/out/install-test");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let log_path = work.join("console.log");
    let log = std::fs::File::create(&log_path).map_err(|e| e.to_string())?;
    let started = Instant::now();
    let mut t = T {
        work: work.clone(),
        images: images.to_owned(),
        kvm: !tcg && super::kvm_usable(),
        log,
        n: Numbers(Vec::new()),
    };
    eprintln!(
        "install-test ({}), console → {}",
        if t.kvm { "KVM" } else { "TCG" },
        log_path.display()
    );
    let st = Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2"])
        .arg(work.join("target.qcow2"))
        .arg("2G")
        .status()
        .map_err(|e| format!("qemu-img: {e}"))?;
    check(st.success(), "qemu-img create failed")?;
    fresh_vars(&t.vars())?;

    t.install("cd", false)?;
    let port = super::free_port()?;
    let mut vm = t.boot_disk("disk/first", port)?;
    check_installed(&mut t, &mut vm, port, true)?;
    drop(vm);

    t.install("usb", true)?;
    let port = super::free_port()?;
    let mut vm = t.boot_disk("disk/reinstalled", port)?;
    check_installed(&mut t, &mut vm, port, false)?;
    drop(vm);

    interactive(&mut t)?;

    let qcow2 = images.join("corerouter.qcow2");
    t.boot_image("qcow2", &qcow2, "qcow2", true)?;
    let st = Command::new("tar")
        .arg("-C")
        .arg(&work)
        .arg("-xf")
        .arg(images.join("corerouter.ova"))
        .status()
        .map_err(|e| format!("tar: {e}"))?;
    check(st.success(), "tar -xf corerouter.ova failed")?;
    t.boot_image("ova", &work.join("corerouter-disk1.vmdk"), "vmdk", false)?;

    let _ = writeln!(t.log, "===== done =====");
    eprintln!(
        "\ninstall-test ok in {:.1} s ({}):",
        started.elapsed().as_secs_f64(),
        if t.kvm { "KVM" } else { "TCG" }
    );
    for (k, v) in &t.n.0 {
        eprintln!("  {k}: {v}");
    }
    let _ = std::fs::remove_file(work.join("target.qcow2"));
    let _ = std::fs::remove_file(work.join("corerouter-disk1.vmdk"));
    Ok(())
}
