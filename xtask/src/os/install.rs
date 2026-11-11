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
//! 4. `live`: the ISO without the flag, over that disk: the image from RAM,
//!    DHCP on `ether1`, the router's work refused, the disk not touched.
//!    `live_install`: `system.install.*` on an empty disk, a disk with data
//!    (the console's code; the power button) and the boot of what it wrote.
//! 5. `qcow2` and `ova`: the VM images boot as they are (the removable-media
//!    path), with the console setup offered (no address yet).
//!
//! 6. `live_modules` (G1.6za): an ISO whose only port is a card with its
//!    driver in a module: the port comes from the signed payload, carries the
//!    management, installs over itself; a second card plugged in gets a port
//!    and an address.
//!
//! G1.6g: `--firmware seabios` does all of that by BIOS, through GRUB.

#![allow(clippy::indexing_slicing)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::ab::{Firmware, Numbers, Vm, check, fresh_vars, qemu_machine, ready_s, slot, start};

/// The kernel's name, as an installer from before G1.6m wrote it (or a
/// VM's old NVRAM keeps it): the first boot applies it to `ether1`.
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
    /// The admin password of the VM `live_cli` talks to.
    admin: String,
    /// The certificate must be the one seen before.
    strict: bool,
    root: PathBuf,
    work: PathBuf,
    images: PathBuf,
    kvm: bool,
    fw: Firmware,
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
        let mut cmd = qemu_machine(self.kvm, self.fw, &self.vars());
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
        let mut cmd = qemu_machine(self.kvm, self.fw, &self.vars());
        cmd.arg("-drive").arg(format!(
            "file={},if=virtio,format=qcow2",
            self.work.join("target.qcow2").display()
        ));
        cmd.arg("-netdev").arg(format!(
            "user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:{}",
            super::GUEST_TLS_PORT
        ));
        cmd.args(["-device", "virtio-net-pci,netdev=n0"]);
        // G1.6m: two more ports; the one with the address is ether1 (the
        // first in bus order).
        for i in 1..=2 {
            cmd.arg("-netdev").arg(format!("user,id=n{i}"));
            cmd.arg("-device")
                .arg(format!("virtio-net-pci,netdev=n{i}"));
        }
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
        let mut cmd = qemu_machine(self.kvm, self.fw, &self.vars());
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
        // G1.6m: no default answers; the port by number, confirmed; a
        // summary and an explicit yes.
        // G1.6zg: one screen (who, the ports, what needs attention), the
        // invitation at its end; the questions in numbered steps.
        vm.expect(&mut log, &["no port has a management address yet"], 30)?;
        answer(&mut vm, &mut log, "no command shell", "")?;
        vm.expect(&mut log, &["[1/4] Management port"], 30)?;
        let row = answer(&mut vm, &mut log, "  1  ether1 ", "1")?;
        check(
            row.contains("52:54:") && row.contains(" off "),
            format!("port list: {row}"),
        )?;
        answer(&mut vm, &mut log, "Port (number or name)", "y")?;
        answer(&mut vm, &mut log, "Use ether1", "10.0.2.15/24")?;
        answer(&mut vm, &mut log, "Address/prefix", "10.0.2.2")?;
        answer(
            &mut vm,
            &mut log,
            "admin has no password",
            "corerouter-test-1",
        )?;
        answer(&mut vm, &mut log, "New admin password", "corerouter-test-1")?;
        answer(&mut vm, &mut log, "Admin     new password", "y")?;
        vm.expect(&mut log, &["OK  admin password set"], 30)?;
        vm.expect(
            &mut log,
            &["Done: the router has its management address"],
            30,
        )?;
        // The status follows, with the way in; Enter on the quiet console
        // shows it again, not a shell.
        vm.expect(&mut log, &["Web   https://10.0.2.15/"], 30)?;
        vm.expect(
            &mut log,
            &["CLI   corerouter-cli --connect tls://10.0.2.15"],
            30,
        )?;
        answer(&mut vm, &mut log, "to show this status again", "")?;
        vm.expect(&mut log, &["Web   https://10.0.2.15/"], 30)?;
        let row = vm.expect(&mut log, &["ether1 "], 30)?;
        check(
            row.contains("10.0.2.15/24"),
            format!("status after Enter: {row}"),
        )?;
        // The serial console is coloured by default, and a test reads it
        // all the same.
        check(
            vm.colored() > 0,
            "no console line came with colour".to_owned(),
        )?;
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
    let mut cmd = qemu_machine(t.kvm, t.fw, &t.vars());
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
    cmd.args([
        "-netdev",
        "user,id=n0",
        "-device",
        "virtio-net-pci,netdev=n0",
    ]);
    let mut log = t.log.try_clone().map_err(|e| e.to_string())?;
    let mut vm = start(&mut log, "install/interactive", cmd)?;
    // G1.6y: the ISO boots live; `i` on its console is the installer.
    answer(&mut vm, &mut log, "NOT INSTALLED", "i")?;
    // G1.6zg: what is not offered has no number, and the reason on a line
    // of its own.
    let row = vm.expect(&mut log, &["  -  sda ", "not offered:"], 120)?;
    check(
        row.contains("  -  sda "),
        format!("the stick is not sda: {row}"),
    )?;
    vm.expect(&mut log, &["not offered: the installer medium"], 30)?;
    std::thread::sleep(Duration::from_millis(800));
    vm.stdin_write(b"sda\n")?;
    vm.expect(
        &mut log,
        &["sda cannot be the target: the installer medium"],
        30,
    )?;
    // G1.6zg: the steps. [2/5] Disk: the table again, then the disk by
    // name; it holds a CoreRouter whose configuration can be kept.
    vm.expect(&mut log, &["[2/5] Disk"], 30)?;
    answer(&mut vm, &mut log, "CoreRouter", "vda")?;
    answer(&mut vm, &mut log, "OK  vda: ", "y")?;
    // G1.6m: the ports by the router's names; one that is not there is
    // refused, then none.
    vm.expect(
        &mut log,
        &["[3/5] Management address for the first boot"],
        30,
    )?;
    let row = vm.expect(&mut log, &["ether1 ", "e.g. ether1"], 30)?;
    check(
        row.contains("52:54:"),
        format!("installer port list: {row}"),
    )?;
    answer(&mut vm, &mut log, "e.g. ether1", "eth9 192.0.2.10/24")?;
    answer(&mut vm, &mut log, "There is no port eth9 here.", "")?;
    // [4/5] Confirm: anything but the disk's name goes back to the disks.
    vm.expect(&mut log, &["[4/5] Confirm"], 30)?;
    let row = answer(&mut vm, &mut log, "ALL DATA ON vda WILL BE ERASED", "vdb")?;
    check(row.contains("!! ALL DATA"), format!("the warning: {row}"))?;
    vm.expect(&mut log, &["Nothing was written."], 30)?;
    // One disk to offer: Enter takes it, and nothing is written yet.
    answer(&mut vm, &mut log, "CoreRouter", "")?;
    answer(&mut vm, &mut log, "OK  vda: ", "y")?;
    answer(&mut vm, &mut log, "e.g. ether1", "")?;
    let row = vm.expect(&mut log, &["Holds "], 30)?;
    check(
        row.contains("its configuration is kept"),
        format!("what the confirmation says is kept: {row}"),
    )?;
    answer(&mut vm, &mut log, "Address ", "vda")?;
    vm.expect(&mut log, &["[5/5] Write"], 30)?;
    let row = vm.expect(&mut log, &["Writing vda:"], 60)?;
    check(
        row.contains(" 100%") && row.contains("MiB/s"),
        format!("the progress line: {row}"),
    )?;
    let line = vm.expect(&mut log, &["INSTALLED", "install failed"], 120)?;
    check(
        line.contains("OK  INSTALLED CoreRouter") && line.contains("configuration kept"),
        format!("[interactive] {line}"),
    )?;
    vm.expect(&mut log, &["Next: remove the installation medium"], 30)?;
    std::thread::sleep(Duration::from_millis(800));
    vm.stdin_write(b"\n")?;
    vm.wait_exit(&mut log, 60)?;
    t.n.put(
        "interactive (USB): stick refused, wrong name refused, then",
        line.trim().to_owned(),
    );
    Ok(())
}

/// `corerouter-cli run` on the guest over TLS, as the first operator: `admin`
/// without a password, the certificate accepted on first use.
fn live_cli(t: &T, cli: &Path, port: u16, id: &str, params: &str) -> Result<String, String> {
    let home = t.work.join("live-home");
    std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
    let mut cmd = Command::new(cli);
    cmd.args([
        "--connect",
        &format!("tls://127.0.0.1:{port}"),
        "--user",
        "admin",
    ]);
    if !t.strict {
        cmd.arg("--accept-new-cert");
    }
    let out = cmd
        .args(["run", id, params])
        .env("HOME", &home)
        .env("COREROUTER_KNOWN_HOSTS", home.join("known_hosts"))
        .env("COREROUTER_PASSWORD", &t.admin)
        .env("RUST_LOG", "off")
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("{}: {e}", cli.display()))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        Ok(text)
    } else {
        Err(text)
    }
}

/// G1.6y: the ISO boots live with an installed CoreRouter on the (read-only)
/// disk: the root in RAM, `/config` a tmpfs and not that disk's, no FRR, an
/// address by DHCP on `ether1`, the router's work refused, and nothing
/// survives. The port forward is the operator's GUI.
fn live(t: &mut T) -> Result<(), String> {
    let cli = super::push::cli(&t.root)?;
    let iso = t.images.join("corerouter-install.iso");
    fresh_vars(&t.vars())?;
    let port = super::free_port()?;
    let mut cmd = qemu_machine(t.kvm, t.fw, &t.vars());
    cmd.arg("-drive").arg(format!(
        "file={},if=none,id=target,format=qcow2,readonly=on",
        t.work.join("target.qcow2").display()
    ));
    cmd.args(["-device", "virtio-blk-pci,drive=target"]);
    cmd.arg("-drive").arg(format!(
        "file={},if=none,id=cd,format=raw,media=cdrom,readonly=on",
        iso.display()
    ));
    cmd.args(["-device", "ide-cd,drive=cd,bootindex=0"]);
    let web = super::free_port()?;
    cmd.arg("-netdev").arg(format!(
        "user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:{},hostfwd=tcp:127.0.0.1:{web}-:{}",
        super::GUEST_TLS_PORT,
        super::GUEST_WEB_PORT
    ));
    cmd.args(["-device", "virtio-net-pci,netdev=n0"]);
    let mut log = t.log.try_clone().map_err(|e| e.to_string())?;
    let booted = Instant::now();
    let mut vm = start(&mut log, "live", cmd)?;
    vm.expect_all(
        &mut log,
        &[
            "MiB in RAM, signed by key",
            "/config: tmpfs (live image",
            "eth0→ether1 (",
            "ready:",
            "NOT INSTALLED",
        ],
        120,
    )?;
    t.n.put(
        "live: qemu start → console says not installed",
        format!("{:.1} s", booted.elapsed().as_secs_f64()),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    let addresses = loop {
        let got = live_cli(t, &cli, port, "ip.address.list", "{}").unwrap_or_default();
        if got.contains("10.0.2.15") {
            break got;
        }
        check(Instant::now() < deadline, format!("no DHCP address: {got}"))?;
        std::thread::sleep(Duration::from_millis(500));
    };
    check(
        addresses.contains("ether1"),
        format!("address: {addresses}"),
    )?;
    // The other way in: the browser's GUI.
    t.n.put("live: the web GUI answers", super::web_files(web)?);
    let e = live_cli(
        t,
        &cli,
        port,
        "ip.pool.add",
        r#"{"name":"p","ranges":"10.0.0.2-10.0.0.9"}"#,
    )
    .err()
    .unwrap_or_default();
    check(
        e.contains("live image"),
        format!("a pool was not refused: {e}"),
    )?;
    let e = live_cli(t, &cli, port, "system.package.print", "{}")?;
    check(
        e.contains("not installed"),
        format!("the package service looked at the disk: {e}"),
    )?;
    let services = live_cli(t, &cli, port, "system.resource.process.print", "{}")?;
    check(
        !services.contains("zebra") && !services.contains("mgmtd"),
        format!("FRR runs in the live image: {services}"),
    )?;
    t.n.put(
        "live: admin over TLS, DHCP on ether1, a pool refused",
        "ok".to_owned(),
    );
    Ok(())
}

/// A press of the ACPI power button.
fn power_button(qmp: &Path) -> Result<(), String> {
    use std::io::{BufRead, BufReader, Write as _};
    let s = std::os::unix::net::UnixStream::connect(qmp).map_err(|e| format!("qmp: {e}"))?;
    let mut w = s.try_clone().map_err(|e| e.to_string())?;
    let mut r = BufReader::new(s);
    let mut line = String::new();
    r.read_line(&mut line).map_err(|e| e.to_string())?;
    for cmd in ["qmp_capabilities", "system_powerdown"] {
        writeln!(w, "{{\"execute\":\"{cmd}\"}}").map_err(|e| e.to_string())?;
        // Events (POWERDOWN) can come before the answer.
        loop {
            line.clear();
            let n = r.read_line(&mut line).map_err(|e| e.to_string())?;
            check(
                n > 0 && !line.contains("\"error\""),
                format!("qmp {cmd}: {line}"),
            )?;
            if line.contains("\"return\"") {
                break;
            }
        }
    }
    Ok(())
}

/// `system.install.print` until the scan is in, as JSON.
fn install_print(t: &T, cli: &Path, port: u16) -> Result<serde_json::Value, String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let got = live_cli(t, cli, port, "system.install.print", "{}").unwrap_or_default();
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(got.trim())
            && v["scanned"] == true
            && v["medium"].is_object()
        {
            return Ok(v);
        }
        check(Instant::now() < deadline, format!("no scan: {got}"))?;
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// A live VM with two writable raw disks (serials `BLANK`, `DATA`) and the
/// power button on a QMP socket.
fn live_two_disks(t: &mut T, name: &str, port: u16) -> Result<(Vm, PathBuf), String> {
    let iso = t.images.join("corerouter-install.iso");
    fresh_vars(&t.vars())?;
    let qmp = t.work.join(format!("{name}.qmp"));
    let _ = std::fs::remove_file(&qmp);
    let mut cmd = qemu_machine(t.kvm, t.fw, &t.vars());
    // The least the live image takes: the install and a login with a password
    // must fit too. The last `-m` wins.
    cmd.args(["-m", "320"]);
    cmd.arg("-qmp")
        .arg(format!("unix:{},server=on,wait=off", qmp.display()));
    for (id, serial) in [("blank", "BLANK"), ("data", "DATA")] {
        cmd.arg("-drive").arg(format!(
            "file={},if=none,id={id},format=raw",
            t.work.join(format!("{name}-{id}.raw")).display()
        ));
        cmd.arg("-device")
            .arg(format!("virtio-blk-pci,drive={id},serial={serial}"));
    }
    cmd.arg("-drive").arg(format!(
        "file={},if=none,id=cd,format=raw,media=cdrom,readonly=on",
        iso.display()
    ));
    cmd.args(["-device", "ide-cd,drive=cd,bootindex=0"]);
    cmd.arg("-netdev").arg(format!(
        "user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:{}",
        super::GUEST_TLS_PORT
    ));
    cmd.args(["-device", "virtio-net-pci,netdev=n0"]);
    let mut log = t.log.try_clone().map_err(|e| e.to_string())?;
    let mut vm = start(&mut log, name, cmd)?;
    vm.expect(&mut log, &["ready:"], 120)?;
    Ok((vm, qmp))
}

/// Two disks of 2 GiB: all zero, and zero but for a btrfs-like signature past
/// the first 64 KiB (what the first version called empty).
fn two_disks(t: &T, name: &str) -> Result<(), String> {
    use std::io::{Seek, Write as _};
    for (id, signature) in [("blank", false), ("data", true)] {
        let mut f = std::fs::File::create(t.work.join(format!("{name}-{id}.raw")))
            .map_err(|e| e.to_string())?;
        f.set_len(2 << 30).map_err(|e| e.to_string())?;
        if signature {
            f.seek(std::io::SeekFrom::Start((64 << 10) + 64))
                .map_err(|e| e.to_string())?;
            f.write_all(b"_BHRfS_M").map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn disk_named<'a>(v: &'a serde_json::Value, serial: &str) -> Result<&'a serde_json::Value, String> {
    v["disks"]
        .as_array()
        .and_then(|a| a.iter().find(|d| d["serial"] == serial))
        .ok_or_else(|| format!("no disk with serial {serial}: {v}"))
}

fn run_params(d: &serde_json::Value, typed: &str, code: Option<&str>) -> String {
    let mut p = serde_json::json!({
        "disk": d["name"], "serial": d["serial"], "size": d["bytes"], "typed_name": typed,
    });
    if let Some(c) = code {
        p["code"] = serde_json::json!(c);
    }
    p.to_string()
}

/// `system.install.print` until the job ended; its result.
fn install_result(t: &T, cli: &Path, port: u16) -> Result<serde_json::Value, String> {
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let v = install_print(t, cli, port)?;
        if v["job"].is_null() && !v["result"].is_null() {
            return Ok(v["result"].clone());
        }
        check(
            Instant::now() < deadline,
            format!("install did not end: {v}"),
        )?;
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// What the install wrote, alone, with the ISO still in the drive; `nic` is
/// the QEMU card.
fn boot_written(
    t: &T,
    log: &mut std::fs::File,
    name: &str,
    disk: &str,
    port: u16,
    nic: &str,
) -> Result<Vm, String> {
    let mut cmd = qemu_machine(t.kvm, t.fw, &t.vars());
    cmd.arg("-drive").arg(format!(
        "file={},if=none,id=d,format=raw",
        t.work.join(disk).display()
    ));
    cmd.args(["-device", "virtio-blk-pci,drive=d"]);
    cmd.arg("-drive").arg(format!(
        "file={},if=none,id=cd,format=raw,media=cdrom,readonly=on",
        t.images.join("corerouter-install.iso").display()
    ));
    cmd.args(["-device", "ide-cd,drive=cd"]);
    cmd.arg("-netdev").arg(format!(
        "user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:{}",
        super::GUEST_TLS_PORT
    ));
    cmd.arg("-device").arg(format!("{nic},netdev=n0"));
    start(log, name, cmd)
}

/// G1.6y: installing through the commands. A disk with data needs the code
/// from the console (wrong ones refused, `system.shutdown` refused meanwhile);
/// the disk then boots. An empty disk needs the name; the power button pressed
/// three times stands for the code and, once the challenge is gone, powers off.
fn live_install(t: &mut T) -> Result<(), String> {
    let cli = super::push::cli(&t.root)?;
    let mut log = t.log.try_clone().map_err(|e| e.to_string())?;

    // A disk with data, by the code.
    two_disks(t, "live1")?;
    let port = super::free_port()?;
    let (mut vm, _) = live_two_disks(t, "live1", port)?;
    let v = install_print(t, &cli, port)?;
    let (blank, data) = (
        disk_named(&v, "BLANK")?.clone(),
        disk_named(&v, "DATA")?.clone(),
    );
    check(blank["holds"] == "empty", format!("blank disk: {blank}"))?;
    check(
        data["holds"] == "data",
        format!("a filesystem past 64 KiB called: {data}"),
    )?;
    check(data["confirm"] == "name+code", format!("{data}"))?;
    // The test the window shows before anything is erased.
    live_cli(t, &cli, port, "system.install.test", "{}")?;
    let deadline = Instant::now() + Duration::from_secs(40);
    let net = loop {
        let v = install_print(t, &cli, port)?;
        let dhcp = v["network"]["ports"][0]["address"].is_string();
        if v["testing"] == false && dhcp {
            break v["network"].clone();
        }
        check(Instant::now() < deadline, format!("network test: {v}"))?;
        if v["testing"] == false {
            live_cli(t, &cli, port, "system.install.test", "{}")?;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    let first = &net["ports"][0];
    check(
        net["connected_port"] == "ether1"
            && first["name"] == "ether1"
            && first["connected"] == true
            && first["driver"] == "virtio_net"
            && first["link"] == true
            && first["gateway_ok"] == true,
        format!("network test: {net}"),
    )?;
    t.n.put("live: network test", net.to_string());
    let name = data["name"].as_str().unwrap_or_default().to_owned();
    let refused = |p: String, want: &str, t: &T| -> Result<(), String> {
        let e = live_cli(t, &cli, port, "system.install.run", &p)
            .err()
            .unwrap_or_default();
        check(e.contains(want), format!("{p}: wanted '{want}': {e}"))
    };
    refused(run_params(&data, "wrong", None), "nothing was written", t)?;
    refused(run_params(&data, &name, None), "challenge", t)?;
    let ask = serde_json::json!({"disk": name, "serial": "DATA"}).to_string();
    live_cli(t, &cli, port, "system.install.challenge", &ask)?;
    let line = vm.expect(&mut log, &["*** Code: "], 20)?;
    let code = line
        .split("*** Code: ")
        .nth(1)
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or_default()
        .to_owned();
    check(code.len() == 6, format!("code on the console: {line}"))?;
    let printed = live_cli(t, &cli, port, "system.install.print", "{}")?;
    check(!printed.contains(&code), "print shows the code".to_owned())?;
    refused(run_params(&data, &name, Some("WRONG0")), "2 tries", t)?;
    let e = live_cli(t, &cli, port, "system.shutdown", r#"{"confirm":true}"#)
        .err()
        .unwrap_or_default();
    check(
        e.contains("code"),
        format!("shutdown during a challenge: {e}"),
    )?;
    // The password set here must be the router's. Test value, on a disposable VM.
    live_cli(
        t,
        &cli,
        port,
        "user.set",
        r#"{"name":"admin","password":"live-test-pass-1"}"#,
    )?;
    t.admin = "live-test-pass-1".to_owned();
    let mut p: serde_json::Value =
        serde_json::from_str(&run_params(&data, &name, Some(&code))).map_err(|e| e.to_string())?;
    p["mgmt_port"] = serde_json::json!("ether1");
    p["mgmt_mode"] = serde_json::json!("dhcp");
    live_cli(t, &cli, port, "system.install.run", &p.to_string())?;
    let r = install_result(t, &cli, port)?;
    check(r["ok"] == true, format!("install: {r}"))?;
    check(r["boot_entry"].is_string(), format!("boot entry: {r}"))?;
    check(
        r["first_boot_error"].is_null(),
        format!("first boot data: {r}"),
    )?;
    t.n.put(
        "live: disk with data, by the console's code",
        format!("{} ms, {r}", r["total_ms"]),
    );
    live_cli(t, &cli, port, "system.reboot", r#"{"confirm":true}"#)?;
    vm.wait_exit(&mut log, 60)?;
    // The firmware's new entry boots the disk, with the ISO still in; the
    // GUI's connection comes back: same certificate, the password, DHCP.
    t.strict = true;
    // Same host and port: the entry in known_hosts is what proves it.
    let port2 = port;
    let mut booted = boot_written(
        t,
        &mut log,
        "live1/disk",
        "live1-data.raw",
        port2,
        "virtio-net-pci",
    )?;
    booted.expect_all(
        &mut log,
        &[
            "/config: /dev/",
            "FRR up",
            "ready:",
            "install: management: DHCP on ether1",
        ],
        120,
    )?;
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        let got = live_cli(t, &cli, port2, "ip.address.list", "{}").unwrap_or_else(|e| e);
        if got.contains("10.0.2.15") {
            break;
        }
        check(
            Instant::now() < deadline,
            format!("no address after the install: {got}"),
        )?;
        std::thread::sleep(Duration::from_millis(500));
    }
    let info = live_cli(t, &cli, port2, "ip.dhcp-client.list", "{}")?;
    check(info.contains("ether1"), format!("the DHCP choice: {info}"))?;
    let users = live_cli(t, &cli, port2, "user.list", "{}")?;
    check(
        users.contains("\"no_password\":false") || users.contains("\"no_password\": false"),
        format!("the password: {users}"),
    )?;
    drop(booted);
    t.strict = false;
    t.admin = String::new();
    t.n.put(
        "live: the disk boots with the same certificate, the password and DHCP on ether1",
        "ok".to_owned(),
    );

    // The empty disk, by the name; the button.
    two_disks(t, "live2")?;
    let port = super::free_port()?;
    let (mut vm, qmp) = live_two_disks(t, "live2", port)?;
    let v = install_print(t, &cli, port)?;
    let data = disk_named(&v, "DATA")?.clone();
    let name = data["name"].as_str().unwrap_or_default().to_owned();
    let ask = serde_json::json!({"disk": name, "serial": "DATA"}).to_string();
    live_cli(t, &cli, port, "system.install.challenge", &ask)?;
    vm.expect(&mut log, &["*** Code: "], 20)?;
    for _ in 0..3 {
        power_button(&qmp)?;
        vm.expect(&mut log, &["power button: counted"], 10)?;
    }
    vm.expect(&mut log, &["*** Power button: confirmed"], 10)?;
    let v = install_print(t, &cli, port)?;
    check(v["challenge"]["presence"] == true, format!("presence: {v}"))?;
    live_cli(t, &cli, port, "system.install.cancel", "{}")?;
    let blank = disk_named(&v, "BLANK")?.clone();
    let name = blank["name"].as_str().unwrap_or_default().to_owned();
    let mut p: serde_json::Value =
        serde_json::from_str(&run_params(&blank, &name, None)).map_err(|e| e.to_string())?;
    p["mgmt_port"] = serde_json::json!("ether1");
    p["mgmt_mode"] = serde_json::json!("static");
    p["mgmt_address"] = serde_json::json!("10.0.2.15/24");
    p["mgmt_gateway"] = serde_json::json!("10.0.2.2");
    p["mgmt_dns"] = serde_json::json!(["10.0.2.3"]);
    live_cli(t, &cli, port, "system.install.run", &p.to_string())?;
    let r = install_result(t, &cli, port)?;
    check(r["ok"] == true, format!("install: {r}"))?;
    check(
        r["first_boot_error"].is_null(),
        format!("first boot data: {r}"),
    )?;
    t.n.put(
        "live: empty disk by its name, button stands for the code",
        "ok".to_owned(),
    );
    // No challenge open: the button is a power button again.
    std::thread::sleep(Duration::from_millis(600));
    power_button(&qmp)?;
    vm.wait_exit(&mut log, 60)?;
    t.n.put(
        "live: the power button powers off with no challenge",
        "ok".to_owned(),
    );
    t.strict = true;
    let port3 = port;
    let mut booted = boot_written(
        t,
        &mut log,
        "live2/disk",
        "live2-blank.raw",
        port3,
        "virtio-net-pci",
    )?;
    booted.expect_all(
        &mut log,
        &["ready:", "install: management: 10.0.2.15/24 on ether1"],
        120,
    )?;
    let routes = live_cli(t, &cli, port3, "ip.route.list", "{}")?;
    check(
        routes.contains("10.0.2.2"),
        format!("the static gateway: {routes}"),
    )?;
    drop(booted);
    t.strict = false;
    t.n.put(
        "live: static management applied on the first boot",
        "ok".to_owned(),
    );
    Ok(())
}

/// The card of G1.6za's test: its driver exists only as a module in the ISO's
/// kernel, and its revision makes the driver refuse to open the port without
/// its firmware file (`e100/d102e_ucode.bin`, on the image's root).
const MODULE_NIC: &str = "i82551,mac=52:54:00:e1:00:01,bus=pcie.0,addr=0x10";
const MODULE_NIC_MAC: &str = "52:54:00:e1:00:01";
/// Plugged in with the live image running; another driver in a module.
const PLUGGED_MAC: &str = "52:54:00:9c:4e:02";

/// G1.6za: the ISO on a machine whose only port is a card with its driver in
/// a module. Nothing but the signed payload can make that port: the address
/// by DHCP and everything after it come through the card. Then a card plugged
/// in with the live image running gets a port and an address, and the install
/// made through the first card boots and answers on it.
fn live_modules(t: &mut T) -> Result<(), String> {
    let cli = super::push::cli(&t.root)?;
    let iso = t.images.join("corerouter-install.iso");
    let mut log = t.log.try_clone().map_err(|e| e.to_string())?;
    fresh_vars(&t.vars())?;
    two_disks(t, "mods")?;
    let port = super::free_port()?;
    let mon = t.work.join("mods.monitor");
    let _ = std::fs::remove_file(&mon);
    let mut cmd = qemu_machine(t.kvm, t.fw, &t.vars());
    // The least the live image takes, as in `live_two_disks`.
    cmd.args(["-m", "320"]);
    cmd.arg("-monitor")
        .arg(format!("unix:{},server=on,wait=off", mon.display()));
    cmd.arg("-drive").arg(format!(
        "file={},if=none,id=blank,format=raw",
        t.work.join("mods-blank.raw").display()
    ));
    cmd.args(["-device", "virtio-blk-pci,drive=blank,serial=BLANK"]);
    cmd.arg("-drive").arg(format!(
        "file={},if=none,id=cd,format=raw,media=cdrom,readonly=on",
        iso.display()
    ));
    cmd.args(["-device", "ide-cd,drive=cd,bootindex=0"]);
    cmd.arg("-netdev").arg(format!(
        "user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:{}",
        super::GUEST_TLS_PORT
    ));
    cmd.arg("-device").arg(format!("{MODULE_NIC},netdev=n0"));
    cmd.args([
        "-device",
        "pcie-root-port,id=hp0,bus=pcie.0,chassis=9,slot=9",
        "-netdev",
        "user,id=n1,net=10.0.3.0/24,restrict=on",
    ]);
    let booted = Instant::now();
    let mut vm = start(&mut log, "live/modules", cmd)?;
    let r = vm.expect_all(
        &mut log,
        &[
            "live: driver modules from",
            "driver e100 loaded",
            &format!("eth0→ether1 ({MODULE_NIC_MAC})"),
            "ready:",
            "NOT INSTALLED",
        ],
        120,
    )?;
    t.n.put(
        "live modules: the payload",
        r.first().cloned().unwrap_or_default().trim().to_owned(),
    );
    t.n.put(
        "live modules: the driver",
        r.get(1).cloned().unwrap_or_default().trim().to_owned(),
    );
    t.n.put(
        "live modules: qemu start → console says not installed",
        format!("{:.1} s", booted.elapsed().as_secs_f64()),
    );
    // All the way through the card (and so through its firmware file).
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let got = live_cli(t, &cli, port, "ip.address.list", "{}").unwrap_or_else(|e| e);
        if got.contains("10.0.2.15") && got.contains("ether1") {
            break;
        }
        check(
            Instant::now() < deadline,
            format!("no DHCP address through the module's card: {got}"),
        )?;
        std::thread::sleep(Duration::from_millis(500));
    }
    t.n.put(
        "live modules: qemu start → admin over TLS through the card",
        format!("{:.1} s", booted.elapsed().as_secs_f64()),
    );
    // The window's network test names the driver.
    live_cli(t, &cli, port, "system.install.test", "{}")?;
    let deadline = Instant::now() + Duration::from_secs(40);
    let net = loop {
        let v = install_print(t, &cli, port)?;
        if v["testing"] == false && v["network"]["ports"][0]["address"].is_string() {
            break v["network"].clone();
        }
        check(Instant::now() < deadline, format!("network test: {v}"))?;
        std::thread::sleep(Duration::from_millis(500));
    };
    let first = &net["ports"][0];
    check(
        net["connected_port"] == "ether1"
            && first["driver"] == "e100"
            && first["connected"] == true
            && first["link"] == true,
        format!("network test: {net}"),
    )?;
    // A card plugged in now: the same payload, by the device messages.
    let t3 = Instant::now();
    super::hotplug::hmp(
        &mon,
        &format!("device_add pcnet,bus=hp0,id=hot,netdev=n1,mac={PLUGGED_MAC}"),
    )?;
    vm.expect_all(
        &mut log,
        &["driver pcnet32 loaded", &format!("→ether2 ({PLUGGED_MAC})")],
        30,
    )?;
    t.n.put(
        "live modules: card plugged in → driver loaded and port named",
        format!("{} ms", t3.elapsed().as_millis()),
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let got = live_cli(t, &cli, port, "ip.address.list", "{}").unwrap_or_else(|e| e);
        if got.contains("10.0.3.15") {
            break;
        }
        check(
            Instant::now() < deadline,
            format!("no DHCP on the card plugged in: {got}"),
        )?;
        std::thread::sleep(Duration::from_millis(500));
    }
    t.n.put(
        "live modules: card plugged in → address by DHCP",
        format!("{} ms", t3.elapsed().as_millis()),
    );
    // The install, managed through the card.
    let v = install_print(t, &cli, port)?;
    let blank = disk_named(&v, "BLANK")?.clone();
    let name = blank["name"].as_str().unwrap_or_default().to_owned();
    let mut p: serde_json::Value =
        serde_json::from_str(&run_params(&blank, &name, None)).map_err(|e| e.to_string())?;
    p["mgmt_port"] = serde_json::json!("ether1");
    p["mgmt_mode"] = serde_json::json!("dhcp");
    live_cli(t, &cli, port, "system.install.run", &p.to_string())?;
    let r = install_result(t, &cli, port)?;
    check(r["ok"] == true, format!("install: {r}"))?;
    live_cli(t, &cli, port, "system.reboot", r#"{"confirm":true}"#)?;
    vm.wait_exit(&mut log, 60)?;
    // The installed kernel, its own modules, the same card and certificate.
    t.strict = true;
    let mut disk = boot_written(
        t,
        &mut log,
        "live/modules-disk",
        "mods-blank.raw",
        port,
        "i82551,mac=52:54:00:e1:00:01",
    )?;
    disk.expect_all(&mut log, &["driver e100 loaded", "ready:"], 120)?;
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        let got = live_cli(t, &cli, port, "ip.address.list", "{}").unwrap_or_else(|e| e);
        if got.contains("10.0.2.15") {
            break;
        }
        check(
            Instant::now() < deadline,
            format!("no address after the install: {got}"),
        )?;
        std::thread::sleep(Duration::from_millis(500));
    }
    drop(disk);
    t.strict = false;
    t.n.put(
        "live modules: installed through the card; the disk answers on it",
        "ok".to_owned(),
    );
    Ok(())
}

/// G1.6za: a byte changed in the payload on the medium. The hash in the signed
/// index stops it before anything is mounted, the console says so, and the
/// live image comes up anyway: a built-in card has its port, the card that
/// needs a module has none, and no module of any kind was loaded.
fn live_modules_tampered(t: &mut T) -> Result<(), String> {
    let mut iso =
        std::fs::read(t.images.join("corerouter-install.iso")).map_err(|e| e.to_string())?;
    let img = std::fs::read(t.images.join("live-modules.img")).map_err(|e| e.to_string())?;
    let head = img.get(..4096).ok_or("live-modules.img: too short")?;
    // ISO 9660 files start on a 2 KiB sector.
    let at = (0..iso.len())
        .step_by(2048)
        .find(|&o| iso.get(o..o + head.len()) == Some(head))
        .ok_or("the payload is not on the ISO")?;
    iso[at + img.len() / 2] ^= 0xff;
    let bad = t.work.join("tampered.iso");
    std::fs::write(&bad, &iso).map_err(|e| e.to_string())?;
    drop(iso);
    fresh_vars(&t.vars())?;
    let mut log = t.log.try_clone().map_err(|e| e.to_string())?;
    let mut cmd = qemu_machine(t.kvm, t.fw, &t.vars());
    cmd.arg("-drive").arg(format!(
        "file={},if=none,id=cd,format=raw,media=cdrom,readonly=on",
        bad.display()
    ));
    cmd.args(["-device", "ide-cd,drive=cd,bootindex=0"]);
    cmd.args([
        "-netdev",
        "user,id=n0",
        "-device",
        "virtio-net-pci,netdev=n0",
        "-netdev",
        "user,id=n1,restrict=on",
    ]);
    cmd.arg("-device").arg(format!("{MODULE_NIC},netdev=n1"));
    let mut vm = start(&mut log, "live/tampered", cmd)?;
    let r = vm.expect_all(
        &mut log,
        &[
            "live: driver modules: the module payload on the medium does not match",
            "port names:",
            "ready:",
            "NOT INSTALLED",
        ],
        120,
    )?;
    let names = r.get(1).cloned().unwrap_or_default();
    check(
        names.contains("→ether1") && !names.contains(MODULE_NIC_MAC),
        format!("ports with a refused payload: {names}"),
    )?;
    drop(vm);
    let text = std::fs::read(t.work.join("console.log")).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&text);
    let section = text
        .rsplit("===== live/tampered =====")
        .next()
        .unwrap_or_default();
    check(
        !section.contains("driver e100 loaded"),
        "a driver loaded from a refused payload".to_owned(),
    )?;
    let _ = std::fs::remove_file(&bad);
    t.n.put(
        "live modules: a changed payload is refused, the live image comes up",
        "ok".to_owned(),
    );
    Ok(())
}

/// `sh` in the guest: the output of `cmd`, marked.
pub(super) fn sh(vm: &mut Vm, log: &mut std::fs::File, cmd: &str) -> Result<String, String> {
    let line = format!("{cmd} 2>&1 | tr '\\n' ' ' | sed \"s/^/@@$((2+2))S /\"; echo\n");
    vm.stdin_write(line.as_bytes())?;
    let got = vm.expect(log, &["@@4S "], 60)?;
    Ok(got.split("@@4S ").nth(1).unwrap_or("").trim().to_owned())
}

pub(super) fn until(
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
    let mut pats = vec!["ready:", "maintenance shell", "FRR up:", "eth0→ether1 ("];
    if first {
        // G1.6m: the entry's `eth0` lands on ether1, and the console says
        // where the address came from.
        pats.push("management address 10.0.2.15/24 on ether1, gateway 10.0.2.2, from the kernel command line");
    }
    let r = vm.expect_all(&mut log, &pats, 120)?;
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
    if t.fw == Firmware::SeaBios {
        // G1.6g: GRUB handed over the slot's line, quoting and all.
        let c = sh(
            vm,
            &mut log,
            "{ cat /proc/cmdline; grep -c ' / squashfs ' /proc/mounts; cat /sys/block/dm-0/dm/name; }",
        )?;
        check(
            c.contains("corerouter.slot=a")
                && c.contains("\"dm-mod.create=vroot,")
                && c.contains(" 1 vroot"),
            format!("not slot A on dm-verity through GRUB: {c}"),
        )?;
        t.n.put(
            &format!("{what}: slot A on dm-verity through GRUB"),
            "yes".to_owned(),
        );
    }
    // G1.6zc: tty1 is a console a person can read. After a UEFI boot there
    // is no VGA text mode: the kernel must draw on the firmware's
    // framebuffer (fbcon), or the screen stays on the firmware's last frame.
    let con = sh(
        vm,
        &mut log,
        "for c in /sys/class/vtconsole/vtcon*; do echo \"$(cat $c/name)=$(cat $c/bind)\"; done",
    )?;
    let want = match t.fw {
        Firmware::Ovmf => "frame buffer device=1",
        Firmware::SeaBios => "VGA+=1",
    };
    check(
        con.contains(want),
        format!("screen console: expected '{want}', got: {con}"),
    )?;
    t.n.put(&format!("{what}: screen console (tty1)"), con.clone());
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
    // G1.6m: RouterOS names in bus order, kept in /config; no device the
    // kernel made on its own (bond0, dummy0, gre0, sit0…); the marker of
    // the installer's address written.
    // (`bonding_masters` is a file of the bonding driver, not a link.)
    let links = sh(vm, &mut log, "cd /sys/class/net && ls -d */ | tr -d /")?;
    check(
        links.trim() == "ether1 ether2 ether3 lo",
        format!("links: {links}"),
    )?;
    t.n.put(&format!("{what}: links"), links.trim().to_owned());
    let marker = sh(
        vm,
        &mut log,
        "{ cat /config/.installer-mgmt-applied; echo; grep -c '^ether' /config/.port-names; }",
    )?;
    check(
        marker.starts_with("ether1,10.0.2.15/24,10.0.2.2") && marker.ends_with('3'),
        format!("marker and port map: {marker}"),
    )?;
    // G1.6m: the maintenance shell comes back after an `exit` (it stayed a
    // zombie: PID 1 reaped only its own process group).
    vm.stdin_write(b"exit\n")?;
    vm.expect(&mut log, &["maintenance shell on /dev/ttyS0"], 30)?;
    std::thread::sleep(Duration::from_millis(800));
    let z = sh(
        vm,
        &mut log,
        "grep -l '^State:.*Z' /proc/[0-9]*/status 2>/dev/null | wc -l",
    )?;
    check(
        z.trim() == "0",
        format!("zombies after the shell exit: {z}"),
    )?;
    t.n.put(
        &format!("{what}: shell after exit"),
        "started again, no zombies".to_owned(),
    );
    // FRR: the daemons always on (G1.6i starts the others when the config
    // uses them), the frr service attached.
    let vty = sh(vm, &mut log, "ls /var/run/frr/ | grep -c 'vty$'")?;
    t.n.put(&format!("{what}: FRR vty sockets"), vty.clone());
    // G1.6i: mgmtd, zebra and staticd; the others start with their config.
    check(
        vty.trim().parse::<u32>().unwrap_or(0) >= 3,
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
                // "attached to FRR in …", then (a boot with routing
                // config) "frr 10.7.1: running config installed".
                && v["result"][0]["last_event"]
                    .as_str()
                    .is_some_and(|e| e.to_ascii_lowercase().contains("frr"))
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

/// G1.6g: what was installed here boots under the other firmware.
fn cross_boot(t: &mut T) -> Result<(), String> {
    let installed = t.fw;
    let r = (|| {
        if installed == Firmware::Ovmf {
            // The installer writes GRUB's line too: address, shell and all.
            t.fw = Firmware::SeaBios;
            let port = super::free_port()?;
            let mut vm = t.boot_disk("disk/uefi-to-bios", port)?;
            return check_installed(t, &mut vm, port, false);
        }
        // An empty NVRAM: the removable path, then the entries it provisions.
        // Parameters from the installer are GRUB's alone, so no shell here:
        // what shows the slot is the console.
        t.fw = Firmware::Ovmf;
        fresh_vars(&t.vars())?;
        let mut log = t.log.try_clone().map_err(|e| e.to_string())?;
        for name in ["disk/bios-to-uefi", "disk/bios-to-uefi-entry"] {
            let port = super::free_port()?;
            let mut vm = t.boot_disk(name, port)?;
            vm.expect(&mut log, &["ready:"], 120)?;
            std::thread::sleep(Duration::from_secs(3));
            drop(vm);
        }
        Ok(())
    })();
    t.fw = installed;
    r
}

pub fn install_test(root: &Path, images: &Path, args: &[String]) -> Result<(), String> {
    let mut tcg = false;
    let mut fw = Firmware::Ovmf;
    let mut only_modules = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--tcg" => tcg = true,
            "--firmware" => fw = Firmware::parse(it.next().map(String::as_str))?,
            "--only" => {
                let what = it.next().map(String::as_str);
                check(
                    what == Some("live-modules"),
                    format!("--only {what:?}: only live-modules"),
                )?;
                only_modules = true;
            }
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
    let work = super::out_dir(root)?.join("install-test");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let log_path = work.join("console.log");
    let log = std::fs::File::create(&log_path).map_err(|e| e.to_string())?;
    let started = Instant::now();
    let mut t = T {
        admin: String::new(),
        strict: false,
        root: root.to_owned(),
        work: work.clone(),
        images: images.to_owned(),
        kvm: !tcg && super::kvm_usable(),
        fw,
        log,
        n: Numbers(Vec::new()),
    };
    eprintln!(
        "install-test ({}, {}), console → {}",
        if t.kvm { "KVM" } else { "TCG" },
        fw.name(),
        log_path.display()
    );
    if only_modules {
        live_modules(&mut t)?;
        live_modules_tampered(&mut t)?;
        eprintln!("\nlive-modules ok ({}):", fw.name());
        for (k, v) in &t.n.0 {
            eprintln!("  {k}: {v}");
        }
        return Ok(());
    }
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

    cross_boot(&mut t)?;

    interactive(&mut t)?;
    live(&mut t)?;
    live_install(&mut t)?;
    live_modules(&mut t)?;
    live_modules_tampered(&mut t)?;

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
        "\ninstall-test ok in {:.1} s ({}, {}):",
        started.elapsed().as_secs_f64(),
        if t.kvm { "KVM" } else { "TCG" },
        fw.name()
    );
    for (k, v) in &t.n.0 {
        eprintln!("  {k}: {v}");
    }
    let _ = std::fs::remove_file(work.join("target.qcow2"));
    let _ = std::fs::remove_file(work.join("corerouter-disk1.vmdk"));
    for f in ["mods-blank.raw", "mods-data.raw"] {
        let _ = std::fs::remove_file(work.join(f));
    }
    Ok(())
}
