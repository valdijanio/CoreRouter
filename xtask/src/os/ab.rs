//! G1.6b: the A/B image's QEMU test, and the calls to `corerouter-image`
//! (`apps/corerouter-image`: seal, packages, keys — the xtask may not use
//! workspace crates, so the signing code lives in that app).
//!
//! - `ab-test`: the scenarios in QEMU as the user (OVMF, KVM or TCG):
//!   update A→B confirmed; a B that does not confirm falls back; a package
//!   with a bad signature or a changed payload is refused; a boot parameter
//!   that does not boot falls back; G1.6e: a package pushed over the
//!   network (TLS, `corerouter-cli upload --wait`) is installed, confirmed
//!   and keeps `/config`, the password and the certificate, and a bad one
//!   pushed the same way falls back. Driven through the serial console's
//!   maintenance shell (`corerouter.shell=ttyS0`, carried into the slots'
//!   boot entries) and `corerouter-init run <command>`.
//!
//! The private key: `--key <pkcs8>` or `$COREROUTER_IMAGE_KEY`; without
//! either, a development key generated once in `<out>/keys/` (the build's
//! directory, `os/out.rs`; never in git nor in the image). The image only
//! carries the public key.

// `serde_json::Value` indexing (`v["slots"]`) gives `Null` for a missing
// key and never panics; the lint cannot tell it from slice indexing.
#![allow(clippy::indexing_slicing)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use serde_json::Value;

const OVMF_CODE: &str = "/usr/share/OVMF/OVMF_CODE_4M.fd";
const OVMF_VARS: &str = "/usr/share/OVMF/OVMF_VARS_4M.fd";

/// `corerouter-image`, built next to this xtask (same target directory).
pub fn tool(root: &Path) -> Result<PathBuf, String> {
    let st = Command::new(crate::cargo_bin())
        .args(["build", "-q", "-p", "corerouter-image"])
        .current_dir(root)
        .status()
        .map_err(|e| format!("cargo: {e}"))?;
    check(st.success(), "cargo build -p corerouter-image failed")?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let p = exe.with_file_name("corerouter-image");
    check(p.exists(), format!("{} missing", p.display()))?;
    Ok(p)
}

pub(super) fn run_tool(tool: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new(tool)
        .args(args)
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("{}: {e}", tool.display()))?;
    check(
        out.status.success(),
        format!("corerouter-image {}: failed", args.join(" ")),
    )?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The signing key and the public-key directory (`corerouter-image key`),
/// under `top`, the build's directory.
pub fn ensure_key(
    top: &Path,
    tool: &Path,
    given: Option<&Path>,
) -> Result<(PathBuf, PathBuf), String> {
    let keys = top.join("keys");
    let keys = keys.to_string_lossy().into_owned();
    let mut args = vec!["key", "--keys", keys.as_str()];
    let given = given.map(|g| g.to_string_lossy().into_owned());
    if let Some(g) = &given {
        args.extend(["--key", g.as_str()]);
    }
    let v: Value =
        serde_json::from_str(run_tool(tool, &args)?.trim()).map_err(|e| e.to_string())?;
    let path = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .ok_or_else(|| format!("key: no {k}"))
    };
    Ok((path("key")?, path("pub")?))
}

/// Another package of the sealed build: version suffix, build + 1, maybe
/// another root file system or key.
fn package(
    ctx: &Ctx,
    out: &Path,
    suffix: &str,
    squashfs: Option<&Path>,
    key: Option<&Path>,
) -> Result<String, String> {
    let info = run_tool(
        &ctx.tool,
        &[
            "info",
            &ctx.images.join("corerouter.crpkg").to_string_lossy(),
        ],
    )?;
    let m: Value = serde_json::from_str(info.trim()).map_err(|e| e.to_string())?;
    let version = format!("{}{suffix}", m["version"].as_str().unwrap_or("0"));
    let build = (m["build"].as_u64().unwrap_or(0) + 1).to_string();
    let images = ctx.images.to_string_lossy().into_owned();
    let keys = super::out_dir(&ctx.root)?
        .join("keys")
        .to_string_lossy()
        .into_owned();
    let out_s = out.to_string_lossy().into_owned();
    let mut args = vec![
        "package",
        "--images",
        images.as_str(),
        "--out",
        out_s.as_str(),
        "--version",
        version.as_str(),
        "--build",
        build.as_str(),
    ];
    let sq = squashfs.map(|p| p.to_string_lossy().into_owned());
    if let Some(sq) = &sq {
        args.extend(["--squashfs", sq.as_str()]);
    }
    let k = key.map(|p| p.to_string_lossy().into_owned());
    match &k {
        Some(k) => args.extend(["--key", k.as_str()]),
        None => args.extend(["--keys", keys.as_str()]),
    }
    run_tool(&ctx.tool, &args)?;
    Ok(version)
}

fn read(p: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))
}
// --------------------------------------------------------------- ab-test --

pub(super) struct Ctx {
    root: PathBuf,
    tool: PathBuf,
    pub(super) work: PathBuf,
    images: PathBuf,
    pub(super) kvm: bool,
    pub(super) fw: Firmware,
    pub(super) log: std::fs::File,
    /// G1.6e: a host port forwarded to the guest's TLS control port.
    fwd: Option<u16>,
}

/// One QEMU run (it exits on the guest's reboot: `-no-reboot`).
pub(super) struct Vm {
    child: Child,
    stdin: ChildStdin,
    rx: mpsc::Receiver<String>,
    started: Instant,
    name: String,
    /// Console lines that came with colour (G1.6zg).
    colored: Arc<AtomicUsize>,
}

const SHELL_APPEND: &str = "ip=10.0.2.15::10.0.2.2:255.255.255.0::eth0:off corerouter.shell=ttyS0";

/// The firmware a test machine boots (G1.6g).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Firmware {
    Ovmf,
    SeaBios,
}

impl Firmware {
    /// `--firmware <name>`.
    pub(super) fn parse(s: Option<&str>) -> Result<Self, String> {
        match s {
            Some("ovmf") => Ok(Firmware::Ovmf),
            Some("seabios") => Ok(Firmware::SeaBios),
            other => Err(format!(
                "--firmware {}: ovmf or seabios",
                other.unwrap_or("needs a value")
            )),
        }
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Firmware::Ovmf => "OVMF",
            Firmware::SeaBios => "SeaBIOS",
        }
    }
}

/// The QEMU machine every image test boots: q35, 2 vCPUs, 1 GiB, serial
/// console on stdio, OVMF with the NVRAM in `vars`, no reboot (a guest
/// reboot ends the run).
pub(super) fn qemu_base(kvm: bool, vars: &Path) -> Command {
    qemu_machine(kvm, Firmware::Ovmf, vars)
}

/// [`qemu_base`] with the firmware chosen (SeaBIOS is QEMU's default, it has
/// no NVRAM).
pub(super) fn qemu_machine(kvm: bool, fw: Firmware, vars: &Path) -> Command {
    qemu_board("q35", kvm, fw, vars)
}

/// [`qemu_machine`] on another board (`pc`: the old PCI one, as Proxmox's
/// default, where a SCSI controller goes).
pub(super) fn qemu_board(board: &str, kvm: bool, fw: Firmware, vars: &Path) -> Command {
    let mut cmd = Command::new("qemu-system-x86_64");
    let accel = format!("{board},accel={}", if kvm { "kvm" } else { "tcg" });
    cmd.args(["-machine", &accel, "-cpu", if kvm { "host" } else { "max" }]);
    cmd.args([
        "-smp", "2", "-m", "1024", "-display", "none", "-monitor", "none",
    ]);
    cmd.args(["-serial", "stdio", "-no-reboot"]);
    if fw == Firmware::Ovmf {
        cmd.arg("-drive")
            .arg(format!("if=pflash,format=raw,readonly=on,file={OVMF_CODE}"));
        cmd.arg("-drive")
            .arg(format!("if=pflash,format=raw,file={}", vars.display()));
    }
    cmd.args(["-device", "virtio-rng-pci"]);
    cmd
}

/// A fresh copy of OVMF's empty NVRAM at `to`.
pub(super) fn fresh_vars(to: &Path) -> Result<(), String> {
    std::fs::copy(OVMF_VARS, to)
        .map(|_| ())
        .map_err(|e| format!("{OVMF_VARS}: {e} (package ovmf)"))
}

/// Starts `cmd` with its serial console read line by line.
pub(super) fn start(log: &mut std::fs::File, name: &str, mut cmd: Command) -> Result<Vm, String> {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("qemu-system-x86_64: {e}"))?;
    let stdin = child.stdin.take().ok_or("qemu stdin")?;
    let stdout = child.stdout.take().ok_or("qemu stdout")?;
    let (tx, rx) = mpsc::channel();
    let colored = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&colored);
    std::thread::Builder::new()
        .name("qemu-serial".into())
        .spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(raw) = line else { break };
                // G1.6zg: the consoles are coloured; a test reads the text
                // a person reads.
                let line = super::console_text(&raw);
                if line != raw {
                    seen.fetch_add(1, Ordering::Relaxed);
                }
                if tx.send(line).is_err() {
                    break;
                }
            }
        })
        .map_err(|e| e.to_string())?;
    let _ = writeln!(log, "===== {name} =====");
    eprintln!("   [{name}] qemu started");
    Ok(Vm {
        child,
        stdin,
        rx,
        started: Instant::now(),
        name: name.to_owned(),
        colored,
    })
}

impl Ctx {
    fn boot(&mut self, name: &str, first: bool, extra: &[&Path]) -> Result<Vm, String> {
        let mut cmd = qemu_machine(self.kvm, self.fw, &self.work.join("vars.fd"));
        cmd.arg("-drive").arg(format!(
            "file={},if=virtio,format=qcow2",
            self.work.join("disk.qcow2").display()
        ));
        for p in extra {
            cmd.arg("-drive").arg(format!(
                "file={},if=virtio,format=raw,readonly=on",
                p.display()
            ));
        }
        let netdev = match self.fwd {
            Some(port) => format!(
                "user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:{}",
                super::GUEST_TLS_PORT
            ),
            None => "user,id=n0".to_owned(),
        };
        cmd.args(["-netdev", &netdev, "-device", "virtio-net-pci,netdev=n0"]);
        if first {
            // The factory boot: the firmware loads the kernel QEMU hands it,
            // with the test's platform arguments; the image provisions its
            // boot entries (carrying those arguments) and later boots go
            // through the firmware's boot manager, or GRUB.
            cmd.arg("-kernel").arg(self.images.join("bzImage"));
            cmd.arg("-append").arg(SHELL_APPEND);
        }
        start(&mut self.log, name, cmd)
    }
}

impl Vm {
    /// How many console lines came with colour so far (G1.6zg).
    pub(super) fn colored(&self) -> usize {
        self.colored.load(Ordering::Relaxed)
    }

    /// The next console line that contains one of `pats`; error on a
    /// timeout, on QEMU exiting, and on a kernel panic unless one of `pats`
    /// is "Kernel panic".
    pub(super) fn expect(
        &mut self,
        log: &mut std::fs::File,
        pats: &[&str],
        secs: u64,
    ) -> Result<String, String> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(format!(
                    "[{}] timeout ({secs} s) waiting for {pats:?}",
                    self.name
                ));
            }
            match self.rx.recv_timeout(left.min(Duration::from_millis(500))) {
                Ok(line) => {
                    let _ = writeln!(log, "{line}");
                    if line.contains("corerouter-init") || line.contains("Kernel panic") {
                        eprintln!("   [{}] | {}", self.name, line.trim_end());
                    }
                    if let Some(p) = pats.iter().find(|p| line.contains(**p)) {
                        let _ = p;
                        return Ok(line);
                    }
                    if line.contains("Kernel panic") {
                        return Err(format!("[{}] kernel panic: {line}", self.name));
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(format!(
                        "[{}] qemu exited while waiting for {pats:?}",
                        self.name
                    ));
                }
            }
        }
    }

    /// Waits until a line with each of `pats` went by, in any order;
    /// returns the lines, in `pats`' order.
    pub(super) fn expect_all(
        &mut self,
        log: &mut std::fs::File,
        pats: &[&str],
        secs: u64,
    ) -> Result<Vec<String>, String> {
        let mut got: Vec<Option<String>> = vec![None; pats.len()];
        let deadline = Instant::now() + Duration::from_secs(secs);
        while got.iter().any(Option::is_none) {
            let left = deadline
                .saturating_duration_since(Instant::now())
                .as_secs()
                .max(1);
            let want: Vec<&str> = pats
                .iter()
                .zip(&got)
                .filter(|(_, g)| g.is_none())
                .map(|(p, _)| *p)
                .collect();
            let line = self.expect(log, &want, left)?;
            for (p, g) in pats.iter().zip(got.iter_mut()) {
                if g.is_none() && line.contains(p) {
                    *g = Some(line.clone());
                }
            }
        }
        Ok(got.into_iter().flatten().collect())
    }

    /// Every console line for `secs` seconds (G1.6zn: what follows an event).
    pub(super) fn lines_for(&mut self, log: &mut std::fs::File, secs: u64) -> Vec<String> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        let mut out = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return out;
            }
            match self.rx.recv_timeout(left) {
                Ok(line) => {
                    let _ = writeln!(log, "{line}");
                    out.push(line);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return out,
            }
        }
    }

    /// Types `b` on the guest's serial console.
    pub(super) fn stdin_write(&mut self, b: &[u8]) -> Result<(), String> {
        self.stdin
            .write_all(b)
            .and_then(|_| self.stdin.flush())
            .map_err(|e| format!("serial: {e}"))
    }

    /// Runs a command in the guest's shell; the JSON answer.
    pub(super) fn run(
        &mut self,
        log: &mut std::fs::File,
        command: &str,
        params: &str,
    ) -> Result<Value, String> {
        // `$((1+1))`: the echoed command line never matches the marker.
        let line =
            format!("corerouter-init run {command} '{params}' 2>&1 | sed \"s/^/@@$((1+1))R /\"\n");
        self.stdin
            .write_all(line.as_bytes())
            .map_err(|e| format!("serial: {e}"))?;
        self.stdin.flush().map_err(|e| e.to_string())?;
        let got = self.expect(log, &["@@2R "], 60)?;
        let text = got.split("@@2R ").nth(1).unwrap_or("").trim();
        let v: Value =
            serde_json::from_str(text).map_err(|_| format!("[{}] {command}: {text}", self.name))?;
        Ok(v)
    }

    pub(super) fn ok(
        &mut self,
        log: &mut std::fs::File,
        command: &str,
        params: &str,
    ) -> Result<Value, String> {
        let v = self.run(log, command, params)?;
        if v.get("ok") != Some(&Value::Bool(true)) {
            return Err(format!("[{}] {command} {params}: {v}", self.name));
        }
        Ok(v.get("result").cloned().unwrap_or(Value::Null))
    }

    /// `system.package.print` until `pred` holds.
    pub(super) fn print_until(
        &mut self,
        log: &mut std::fs::File,
        secs: u64,
        pred: impl Fn(&Value) -> bool,
    ) -> Result<Value, String> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let v = self.ok(log, "system.package.print", "{}")?;
            if pred(&v) {
                return Ok(v);
            }
            if Instant::now() >= deadline {
                return Err(format!("[{}] package state never matched: {v}", self.name));
            }
            std::thread::sleep(Duration::from_millis(700));
        }
    }

    pub(super) fn wait_exit(
        &mut self,
        log: &mut std::fs::File,
        secs: u64,
    ) -> Result<Duration, String> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            while let Ok(l) = self.rx.try_recv() {
                let _ = writeln!(log, "{l}");
                if l.contains("corerouter-init") || l.contains("Kernel panic") {
                    eprintln!("   [{}] | {}", self.name, l.trim_end());
                }
            }
            if let Ok(Some(_)) = self.child.try_wait() {
                return Ok(self.started.elapsed());
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                return Err(format!("[{}] did not reboot within {secs} s", self.name));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    pub(super) fn poweroff(&mut self, log: &mut std::fs::File) -> Result<(), String> {
        let _ = self.stdin.write_all(b"poweroff\n");
        let _ = self.stdin.flush();
        self.wait_exit(log, 60).map(|_| ())
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One measured number, printed at the end.
pub(super) struct Numbers(pub(super) Vec<(String, String)>);

impl Numbers {
    pub(super) fn put(&mut self, k: &str, v: impl Into<String>) {
        let v = v.into();
        eprintln!("   = {k}: {v}");
        self.0.push((k.to_owned(), v));
    }
}

pub(super) fn ready_s(line: &str) -> String {
    super::parse_ready(line)
        .map(|s| format!("{s:.3} s"))
        .unwrap_or_else(|| "?".into())
}

pub(super) fn slot<'a>(v: &'a Value, s: &str) -> &'a Value {
    v.get("slots")
        .and_then(Value::as_array)
        .and_then(|a| {
            a.iter()
                .find(|x| x.get("slot").and_then(Value::as_str) == Some(s))
        })
        .unwrap_or(&Value::Null)
}

pub(super) fn check(cond: bool, what: impl Into<String>) -> Result<(), String> {
    if cond { Ok(()) } else { Err(what.into()) }
}

/// A fresh disk (qcow2 over disk.img) and NVRAM, booted once the factory way
/// and once through the boot entries it created. Returns the second run,
/// on slot A with dm-verity.
pub(super) fn fresh(
    ctx: &mut Ctx,
    n: &mut Numbers,
    scenario: &str,
    extra: &[&Path],
) -> Result<Vm, String> {
    new_disk(ctx)?;
    let mut log = ctx.log.try_clone().map_err(|e| e.to_string())?;
    let mut vm = ctx.boot(&format!("{scenario}/factory"), true, &[])?;
    let r = vm.expect_all(&mut log, &["ready:", "maintenance shell"], 120)?;
    if scenario == "update" {
        n.put(
            "boot without dm-verity (fallback path): kernel → daemon ready",
            ready_s(r.first().map_or("", String::as_str)),
        );
    }
    // On a BIOS the entry comes with the image: this is the line, with what it
    // carries.
    vm.print_until(&mut log, 30, |v| {
        slot(v, "a")["cmdline"]
            .as_str()
            .is_some_and(|c| c.contains("corerouter.shell="))
    })?;
    vm.poweroff(&mut log)?;
    drop(vm);
    let mut vm = ctx.boot(&format!("{scenario}/slot-a"), false, extra)?;
    let r = vm.expect_all(&mut log, &["ready:", "maintenance shell"], 120)?;
    if scenario == "update" {
        n.put(
            "boot with dm-verity (boot entry of slot A): kernel → daemon ready",
            ready_s(r.first().map_or("", String::as_str)),
        );
    }
    let v = vm.print_until(&mut log, 30, |v| {
        v.get("running").and_then(Value::as_str) == Some("a")
    })?;
    check(
        slot(&v, "a")["verity"] == Value::Bool(true),
        format!("slot A is not on dm-verity: {}", slot(&v, "a")),
    )?;
    let firmware = match ctx.fw {
        Firmware::Ovmf => "uefi",
        Firmware::SeaBios => "bios",
    };
    check(v["firmware"] == firmware, format!("firmware: {v}"))?;
    Ok(vm)
}

/// G1.6zm: a disk booted once (its boot entries in the NVRAM), then
/// another image written over it with the NVRAM kept, as on the notebook of
/// 2026-11-11. The other image is `disk.img` with its verity tree changed,
/// so the old entries' command line does not fit it: the firmware must pass
/// over them (they name the ESP GUID the first boot gave the disk) and
/// boot the disk's removable-media path, and that boot gives the ESP a new
/// GUID. Before G1.6zm the entries matched the image's fixed ESP GUID and
/// the kernel stopped on `verity: metadata block … is corrupted`.
fn scenario_reflash(ctx: &mut Ctx, n: &mut Numbers) -> Result<(), String> {
    let mut log = ctx.log.try_clone().map_err(|e| e.to_string())?;
    let mut vm = fresh(ctx, n, "reflash", &[])?;
    let v = vm.print_until(&mut log, 30, |v| v["running"] == "a")?;
    // An image from before G1.6zm says nothing (and fails below, at the
    // next image's boot: that is the defect this scenario shows).
    let first = v["esp_guid"].as_str().unwrap_or(IMAGE_ESP_GUID).to_owned();
    if v.get("esp_guid").is_some() {
        check(
            first != IMAGE_ESP_GUID,
            format!("the first boot left the image's ESP GUID: {first}"),
        )?;
    }
    vm.poweroff(&mut log)?;
    drop(vm);
    let other = other_image(ctx)?;
    let disk = ctx.work.join("disk.qcow2");
    let _ = std::fs::remove_file(&disk);
    let st = Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2", "-F", "raw", "-b"])
        .arg(&other)
        .arg(&disk)
        .status()
        .map_err(|e| format!("qemu-img: {e}"))?;
    check(st.success(), "qemu-img create failed")?;
    let t = Instant::now();
    let mut vm = ctx.boot("reflash/next-image", false, &[])?;
    let line = vm.expect(&mut log, &["boot partition: GUID"], 120)?;
    check(
        !line.contains(&first),
        format!("the next image's ESP kept the old GUID: {line}"),
    )?;
    vm.expect(&mut log, &["ready:"], 120)?;
    n.put(
        "image written over a disk whose NVRAM has the old one's entries: firmware → ready",
        format!("{:.1} s", t.elapsed().as_secs_f64()),
    );
    drop(vm);
    let _ = std::fs::remove_file(&other);
    Ok(())
}

/// The ESP GUID `disk.img` carries (`crates/sysupdate/src/lib.rs`).
const IMAGE_ESP_GUID: &str = "4f9a520b-35f7-4633-a4bb-e9f871d1473c";

/// `disk.img` with the first block of slot A's verity tree changed: what a
/// boot entry of another image finds when its hash is checked.
fn other_image(ctx: &Ctx) -> Result<PathBuf, String> {
    use std::os::unix::fs::FileExt;
    let info = run_tool(
        &ctx.tool,
        &[
            "info",
            &ctx.images.join("corerouter.crpkg").to_string_lossy(),
        ],
    )?;
    let m: Value = serde_json::from_str(info.trim()).map_err(|e| format!("info: {e}"))?;
    let blocks = m["rootfs"]["data_blocks"]
        .as_u64()
        .ok_or("info: no rootfs.data_blocks")?;
    let out = ctx.work.join("other.img");
    std::fs::copy(ctx.images.join("disk.img"), &out).map_err(|e| e.to_string())?;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&out)
        .map_err(|e| e.to_string())?;
    let start = partition_start(&f, "rootfs-a")?;
    f.write_all_at(&[0xA5; 4096], start + blocks * 4096)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

/// Byte offset of GPT partition `name` in a disk image of 512-byte blocks.
fn partition_start(f: &std::fs::File, name: &str) -> Result<u64, String> {
    use std::os::unix::fs::FileExt;
    let mut hdr = [0u8; 92];
    f.read_exact_at(&mut hdr, 512).map_err(|e| e.to_string())?;
    check(&hdr[..8] == b"EFI PART", "no GPT")?;
    let u64_at = |b: &[u8], at: usize| -> u64 {
        b.get(at..at + 8)
            .and_then(|x| x.try_into().ok())
            .map_or(0, u64::from_le_bytes)
    };
    let u32_at = |b: &[u8], at: usize| -> u32 {
        b.get(at..at + 4)
            .and_then(|x| x.try_into().ok())
            .map_or(0, u32::from_le_bytes)
    };
    let (lba, count, size) = (
        u64_at(&hdr, 72),
        u32_at(&hdr, 80),
        u32_at(&hdr, 84) as usize,
    );
    let mut entries = vec![0u8; count as usize * size];
    f.read_exact_at(&mut entries, lba * 512)
        .map_err(|e| e.to_string())?;
    for e in entries.chunks(size) {
        let units: Vec<u16> = e
            .get(56..128)
            .unwrap_or_default()
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c.get(1).copied().unwrap_or(0)]))
            .take_while(|u| *u != 0)
            .collect();
        if String::from_utf16_lossy(&units) == name {
            return Ok(u64_at(e, 32) * 512);
        }
    }
    Err(format!("no partition {name}"))
}

/// A new disk (qcow2 over disk.img) and an empty NVRAM.
fn new_disk(ctx: &Ctx) -> Result<(), String> {
    let disk = ctx.work.join("disk.qcow2");
    let _ = std::fs::remove_file(&disk);
    let st = Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2", "-F", "raw", "-b"])
        .arg(ctx.images.join("disk.img"))
        .arg(&disk)
        .status()
        .map_err(|e| format!("qemu-img: {e}"))?;
    check(st.success(), "qemu-img create failed")?;
    if ctx.fw == Firmware::Ovmf {
        fresh_vars(&ctx.work.join("vars.fd"))?;
    }
    Ok(())
}

/// The result of job `queued` (what the queuing command answered).
fn result_of(
    vm: &mut Vm,
    log: &mut std::fs::File,
    queued: &Value,
    secs: u64,
) -> Result<Value, String> {
    let id = queued.get("job").cloned().unwrap_or(Value::Null);
    let v = vm.print_until(log, secs, |v| v["result"]["id"] == id && v["job"].is_null())?;
    Ok(v.get("result").cloned().unwrap_or(Value::Null))
}

fn scenario_update(ctx: &mut Ctx, n: &mut Numbers) -> Result<(), String> {
    let pkg = ctx.work.join("b.crpkg");
    let version = package(ctx, &pkg, "-b", None, None)?;
    n.put(
        "package size",
        format!(
            "{:.1} MiB",
            std::fs::metadata(&pkg).map(|m| m.len()).unwrap_or(0) as f64 / 1048576.0
        ),
    );
    let mut log = ctx.log.try_clone().map_err(|e| e.to_string())?;
    let mut vm = fresh(ctx, n, "update", &[&pkg])?;
    vm.ok(
        &mut log,
        "system.tuning.boot.set",
        r#"{"key":"iommu","value":"pt"}"#,
    )?;
    // G1.6zf: the init's own option goes the same way. `on`: look for the
    // motherboard's sensor chip in a virtual machine too, so the next boot
    // shows that PID 1 got it (no such chip here: it says nobody answered).
    vm.ok(
        &mut log,
        "system.tuning.boot.set",
        r#"{"key":"corerouter.sensors","value":"on"}"#,
    )?;
    let q = vm.ok(&mut log, "system.package.check", r#"{"path":"/dev/vdb"}"#)?;
    let c = result_of(&mut vm, &mut log, &q, 60)?;
    check(
        c["ok"] == Value::Bool(true) && c["result"]["signature"] == "ok",
        format!("check: {c}"),
    )?;
    // The router reboots as soon as the slot is written: the numbers come
    // back with the trial's state.
    vm.ok(
        &mut log,
        "system.package.update",
        r#"{"path":"/dev/vdb","timeout":120}"#,
    )?;
    vm.wait_exit(&mut log, 120)?;
    drop(vm);
    let mut vm = ctx.boot("update/trial-b", false, &[])?;
    let r = vm.expect_all(
        &mut log,
        &[
            "trial boot of slot b",
            "sensors: no motherboard sensor chip answered",
        ],
        120,
    )?;
    n.put(
        "trial boot of slot B: corerouter.sensors=on reached PID 1",
        r.get(1)
            .map_or("", |l| l.split("corerouter-init: ").last().unwrap_or(""))
            .trim()
            .to_owned(),
    );
    let r = vm.expect_all(
        &mut log,
        &[
            "ready:",
            "maintenance shell",
            "trial boot of slot b confirmed",
        ],
        120,
    )?;
    n.put(
        "trial boot of slot B: kernel → daemon ready",
        ready_s(r.first().map_or("", String::as_str)),
    );
    n.put(
        "trial boot: qemu start → confirmed (includes the 10 s grace)",
        format!("{:.1} s", vm.started.elapsed().as_secs_f64()),
    );
    let v = vm.print_until(&mut log, 30, |v| v["primary"] == "b")?;
    check(
        v["running"] == "b" && v["last"]["result"] == "confirmed",
        format!("after confirm: {v}"),
    )?;
    let rr = &v["last"]["stats"];
    n.put(
        "write slot B (kernel + rootfs, streamed and hashed)",
        format!(
            "{} ms for {:.1} MiB",
            rr["write_ms"],
            rr["bytes"].as_f64().unwrap_or(0.0) / 1048576.0
        ),
    );
    n.put(
        "read back + verity tree of slot B",
        format!("{} ms", rr["verify_ms"]),
    );
    n.put("config snapshot", format!("{} ms", rr["snapshot_ms"]));
    n.put("update command total", format!("{} ms", rr["total_ms"]));
    check(
        rr["cmdline"]
            .as_str()
            .is_some_and(|c| c.contains("iommu=pt")),
        "slot B's command line lacks the tuning parameter",
    )?;
    check(
        slot(&v, "b")["verity"] == Value::Bool(true),
        "slot B not on dm-verity",
    )?;
    check(
        slot(&v, "b")["version"] == version.as_str(),
        "slot B version",
    )?;
    let a_line = slot(&v, "a")["cmdline"].as_str().unwrap_or("");
    check(
        !a_line.contains("iommu=pt"),
        "the running slot's command line changed",
    )?;
    vm.poweroff(&mut log)?;
    drop(vm);
    let mut vm = ctx.boot("update/b-again", false, &[])?;
    vm.expect_all(&mut log, &["ready:", "maintenance shell"], 120)?;
    let v = vm.print_until(&mut log, 30, |v| v["supported"] == Value::Bool(true))?;
    check(
        v["running"] == "b" && v["trial"].is_null(),
        format!("second boot: {v}"),
    )?;
    vm.poweroff(&mut log)?;
    Ok(())
}

/// The build's rootfs with a daemon that never answers.
fn broken_squashfs(ctx: &Ctx) -> Result<PathBuf, String> {
    let host = ctx
        .images
        .parent()
        .map(|p| p.join("host/bin"))
        .unwrap_or_default();
    let tool = |n: &str| {
        let p = host.join(n);
        if p.exists() { p } else { PathBuf::from(n) }
    };
    let dir = ctx.work.join("broken-root");
    let _ = std::fs::remove_dir_all(&dir);
    let st = Command::new(tool("unsquashfs"))
        .args(["-q", "-n", "-d"])
        .arg(&dir)
        .arg(ctx.images.join("rootfs.squashfs"))
        .status()
        .map_err(|e| format!("unsquashfs: {e}"))?;
    check(st.success(), "unsquashfs failed")?;
    let daemon = dir.join("usr/bin/corerouter-daemon");
    std::fs::write(
        &daemon,
        "#!/bin/sh\n# G1.6b test: a daemon that never answers.\nexec sleep 100000\n",
    )
    .map_err(|e| e.to_string())?;
    let out = ctx.work.join("broken.squashfs");
    let _ = std::fs::remove_file(&out);
    let st = Command::new(tool("mksquashfs"))
        .arg(&dir)
        .arg(&out)
        .args(["-comp", "zstd", "-all-root", "-noappend", "-quiet"])
        .status()
        .map_err(|e| format!("mksquashfs: {e}"))?;
    check(st.success(), "mksquashfs failed")?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(out)
}

fn scenario_no_confirm(ctx: &mut Ctx, n: &mut Numbers) -> Result<(), String> {
    let squashfs = broken_squashfs(ctx)?;
    let pkg = ctx.work.join("broken.crpkg");
    package(ctx, &pkg, "-broken", Some(&squashfs), None)?;
    let mut log = ctx.log.try_clone().map_err(|e| e.to_string())?;
    let mut vm = fresh(ctx, n, "no-confirm", &[&pkg])?;
    vm.ok(
        &mut log,
        "system.package.update",
        r#"{"path":"/dev/vdb","timeout":30}"#,
    )?;
    vm.wait_exit(&mut log, 120)?;
    drop(vm);
    let mut vm = ctx.boot("no-confirm/trial-b", false, &[])?;
    vm.expect(&mut log, &["trial boot of slot b"], 120)?;
    vm.expect(&mut log, &["not confirmed in 30 s"], 90)?;
    let t = vm.wait_exit(&mut log, 60)?;
    n.put(
        "unconfirmed trial: qemu start → reboot (timeout 30 s)",
        format!("{:.1} s", t.as_secs_f64()),
    );
    drop(vm);
    let mut vm = ctx.boot("no-confirm/back-on-a", false, &[])?;
    vm.expect(
        &mut log,
        &["back on slot a after the trial of slot b failed"],
        120,
    )?;
    vm.expect_all(&mut log, &["ready:", "maintenance shell"], 120)?;
    let v = vm.print_until(&mut log, 30, |v| v["running"] == "a")?;
    check(
        v["last"]["result"] == "rolled-back" && slot(&v, "b")["state"] == "failed",
        format!("after rollback: {v}"),
    )?;
    check(v["primary"] == "a", "primary is not A")?;
    vm.poweroff(&mut log)?;
    Ok(())
}

fn scenario_bad_signature(ctx: &mut Ctx, n: &mut Numbers) -> Result<(), String> {
    // A key the image does not trust, generated now and thrown away.
    let foreign = ctx.work.join("foreign.pk8");
    run_tool(&ctx.tool, &["genkey", &foreign.to_string_lossy()])?;
    let pkg = ctx.work.join("foreign.crpkg");
    package(ctx, &pkg, "-foreign", None, Some(&foreign))?;
    let _ = std::fs::remove_file(&foreign);
    let tampered = ctx.work.join("tampered.crpkg");
    package(ctx, &tampered, "-tampered", None, None)?;
    let mut bytes = read(&tampered)?;
    let at = bytes.len().saturating_sub(100_000);
    if let Some(b) = bytes.get_mut(at) {
        *b ^= 0x5a;
    }
    std::fs::write(&tampered, &bytes).map_err(|e| e.to_string())?;
    let mut log = ctx.log.try_clone().map_err(|e| e.to_string())?;
    let mut vm = fresh(ctx, n, "bad-signature", &[&pkg, &tampered])?;
    let q = vm.ok(&mut log, "system.package.update", r#"{"path":"/dev/vdb"}"#)?;
    let r = result_of(&mut vm, &mut log, &q, 60)?;
    check(
        r["ok"] == Value::Bool(false)
            && r["error"]
                .as_str()
                .is_some_and(|e| e.contains("does not trust")),
        format!("foreign key: {r}"),
    )?;
    n.put("foreign-key package", format!("refused: {}", r["error"]));
    // The tampered one: same trusted key, a payload byte changed after signing.
    let q = vm.ok(&mut log, "system.package.update", r#"{"path":"/dev/vdc"}"#)?;
    let r = result_of(&mut vm, &mut log, &q, 120)?;
    let v = vm.print_until(&mut log, 30, |v| v["supported"] == Value::Bool(true))?;
    let e = r["error"].as_str().unwrap_or("");
    check(e.contains("signed hashes"), format!("tampered: {e}"))?;
    n.put("tampered package", format!("refused: {e}"));
    check(
        slot(&v, "b")["state"] == "empty" && v["trial"].is_null(),
        format!("slot B changed: {v}"),
    )?;
    vm.poweroff(&mut log)?;
    Ok(())
}

fn scenario_bad_param(ctx: &mut Ctx, n: &mut Numbers) -> Result<(), String> {
    let mut log = ctx.log.try_clone().map_err(|e| e.to_string())?;
    let mut vm = fresh(ctx, n, "bad-param", &[])?;
    vm.ok(
        &mut log,
        "system.tuning.boot.set",
        r#"{"key":"intel_idle.max_cstate","value":"1"}"#,
    )?;
    vm.ok(
        &mut log,
        "system.tuning.boot.apply",
        r#"{"drill":true,"timeout":60}"#,
    )?;
    vm.wait_exit(&mut log, 120)?;
    drop(vm);
    let mut vm = ctx.boot("bad-param/trial-b", false, &[])?;
    vm.expect(&mut log, &["Kernel panic"], 120)?;
    let t = vm.wait_exit(&mut log, 60)?;
    n.put(
        "boot parameter that does not boot: qemu start → reset (panic=10)",
        format!("{:.1} s", t.as_secs_f64()),
    );
    drop(vm);
    let mut vm = ctx.boot("bad-param/back-on-a", false, &[])?;
    vm.expect(
        &mut log,
        &["back on slot a after the trial of slot b failed"],
        120,
    )?;
    vm.expect_all(&mut log, &["ready:", "maintenance shell"], 120)?;
    let v = vm.print_until(&mut log, 30, |v| v["running"] == "a")?;
    check(
        v["last"]["result"] == "rolled-back",
        format!("after the drill: {v}"),
    )?;
    let r = &v["last"]["stats"];
    check(
        r["cmdline"]
            .as_str()
            .is_some_and(|c| c.contains("intel_idle.max_cstate=1")),
        "slot B lacked the parameter",
    )?;
    n.put(
        "clone running slot to B (boot parameters)",
        format!("write {} ms, verify {} ms", r["write_ms"], r["verify_ms"]),
    );
    check(
        !slot(&v, "a")["cmdline"]
            .as_str()
            .unwrap_or("")
            .contains("intel_idle"),
        "the running slot's command line changed",
    )?;
    // G1.6zx: the slot B that did not come up left its panic in the UEFI
    // variables; slot A says it, with the boot it happened in.
    if ctx.fw == Firmware::Ovmf {
        let c = crash_of_previous_boot(&mut vm, &mut log)?;
        check(
            c["slot"] == "b",
            format!("the trial's panic does not name slot b: {c}"),
        )?;
        n.put(
            "trial slot that panicked, seen from slot A (G1.6zx)",
            c["summary"].as_str().unwrap_or("?").to_owned(),
        );
    }
    vm.poweroff(&mut log)?;
    Ok(())
}

/// G1.6zx: the dump this boot found (the previous boot's panic), checked as
/// the operator sees it: `system.crash.print`, the router's log, nothing
/// left in pstore, the copy in `/config/crash`.
fn crash_of_previous_boot(vm: &mut Vm, log: &mut std::fs::File) -> Result<Value, String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let c = loop {
        let v = vm.ok(log, "system.crash.print", "{}")?;
        let first = v["crashes"][0].clone();
        if first["this_boot"] == true {
            break first;
        }
        check(
            Instant::now() < deadline,
            format!("no crash from the previous boot: {v}"),
        )?;
        std::thread::sleep(Duration::from_millis(700));
    };
    check(
        c["reason"] == "panic"
            && c["summary"]
                .as_str()
                .is_some_and(|s| s.contains("Kernel panic")),
        format!("crash: {c}"),
    )?;
    let lines = vm.ok(log, "log.print", r#"{"find":"previous boot ended"}"#)?;
    check(
        lines.as_array().is_some_and(|a| !a.is_empty()),
        format!("not in the router's log: {lines}"),
    )?;
    let left = shell_line(vm, log, "ls /sys/fs/pstore | wc -l")?;
    check(left == "0", format!("{left} record(s) left in pstore"))?;
    let saved = shell_line(vm, log, "ls /config/crash | wc -l")?;
    check(
        saved.parse::<u32>().is_ok_and(|n| n >= 1),
        format!("/config/crash: {saved}"),
    )?;
    Ok(c)
}

/// Free bytes of the UEFI variable store (`statfs` of efivarfs).
fn nvram_free(vm: &mut Vm, log: &mut std::fs::File) -> Result<u64, String> {
    let l = shell_line(vm, log, "df -k /sys/firmware/efi/efivars | tail -1")?;
    // BusyBox `df` counts KiB.
    l.split_whitespace()
        .nth(3)
        .and_then(|w| w.parse::<u64>().ok())
        .map(|k| k * 1024)
        .ok_or_else(|| format!("df of efivarfs: {l}"))
}

/// Writes 1 KiB variables of [`FILL_GUID`] until about [`FILL_LEAVES`] is
/// left; `free` is updated. efivarfs answers `statfs` from a cache for a
/// while (rate limited): the variables go in steps, the space is read after
/// a pause. Returns how many were written.
fn fill_nvram(
    vm: &mut Vm,
    log: &mut std::fs::File,
    free: &mut u64,
    first: u64,
) -> Result<u64, String> {
    let mut written: u64 = 0;
    for _ in 0..40 {
        if *free <= FILL_LEAVES + 2048 {
            break;
        }
        let step = ((*free - FILL_LEAVES) / 1200).clamp(1, 64);
        let n = first + written;
        let got = shell_line(
            vm,
            log,
            &format!(
                "cd /sys/firmware/efi/efivars; k=0; while [ $k -lt {step} ] && printf '\\007\\000\\000\\000%01024d' 0 > fill{n}-$k-{FILL_GUID} 2>/dev/null; do k=$((k+1)); done; cd /; sleep 3; echo $k"
            ),
        )?;
        written += got.parse::<u64>().unwrap_or(0);
        *free = nvram_free(vm, log)?;
    }
    Ok(written)
}

/// The daemon's `EFI_MIN_FREE` (`corerouter_engine::crash_log`: two dumps
/// of 16 KiB, 4 KiB of boot entries, the kernel's 5 KiB; the xtask uses no
/// workspace crate).
const EFI_MIN_FREE: u64 = 41 << 10;
/// A GUID of no one's: the variables that fill the NVRAM in the test.
const FILL_GUID: &str = "6b1c0f41-2b5e-4f59-9c4b-1f0d3a0b7e21";
/// What the filled NVRAM keeps free: less than the daemon's
/// `EFI_MIN_FREE` (41 KiB), more than the A/B update's entries and the
/// kernel's reserve (9 KiB).
const FILL_LEAVES: u64 = 16 << 10;

/// G1.6zx: a panic's record goes to the UEFI variables and the next boot
/// takes it out (`system.crash.print`, the log, `/config/crash`); then the
/// NVRAM is filled, as other systems' entries do: the daemon turns
/// `efi_pstore` off at boot (health warning), a panic takes no NVRAM, and
/// the A/B update still writes its boot entries and comes up on B.
fn scenario_crash(ctx: &mut Ctx, n: &mut Numbers) -> Result<(), String> {
    let pkg = ctx.work.join("crash-b.crpkg");
    package(ctx, &pkg, "-b", None, None)?;
    let mut log = ctx.log.try_clone().map_err(|e| e.to_string())?;
    let mut vm = fresh(ctx, n, "crash", &[&pkg])?;
    let free0 = nvram_free(&mut vm, &mut log)?;
    let v = vm.ok(&mut log, "system.crash.print", "{}")?;
    check(
        v["backend"] == "efi_pstore" && v["efi"]["enabled"] == true,
        format!("efi_pstore is not armed: {v}"),
    )?;
    vm.stdin_write(b"echo c > /proc/sysrq-trigger\n")?;
    vm.expect(&mut log, &["Kernel panic"], 60)?;
    let t = vm.wait_exit(&mut log, 60)?;
    drop(vm);
    let _ = t;
    let mut vm = ctx.boot("crash/after-panic", false, &[&pkg])?;
    vm.expect_all(&mut log, &["ready:", "maintenance shell"], 120)?;
    let c = crash_of_previous_boot(&mut vm, &mut log)?;
    check(
        c["summary"]
            .as_str()
            .is_some_and(|s| s.contains("sysrq triggered crash")),
        format!("{c}"),
    )?;
    // Erased: no dump variable can be read. efivarfs keeps the names it
    // listed at mount (pstore erases in the firmware, not through it), so a
    // name may still be listed until the next boot; reading it gives no
    // bytes (**medido**: 0 against 828 for one not erased). The room they took comes back only when the
    // firmware reclaims its store at a boot (EDK2 does not reclaim at run
    // time), so the free space is not compared here.
    let dumps = shell_line(
        &mut vm,
        &mut log,
        "n=0; for f in /sys/firmware/efi/efivars/dump-type*; do [ \"$(cat \"$f\" 2>/dev/null | wc -c)\" -gt 0 ] && n=$((n+1)); done; echo $n",
    )?;
    check(
        dumps == "0",
        format!("{dumps} dump variable(s) still readable in the NVRAM"),
    )?;
    let free1 = nvram_free(&mut vm, &mut log)?;
    n.put(
        "panic recorded in UEFI variables, logged and erased at the next boot",
        format!(
            "{} part(s), NVRAM free {free0} B before, {free1} B after (the firmware reclaims later)",
            c["parts"]
        ),
    );
    // Fill the NVRAM with 1 KiB variables of another GUID until about
    // FILL_LEAVES is left, and boot again. The firmware reclaims its store
    // at a boot when it runs short (the erased dumps' room comes back:
    // 17 408 → 43 196 B free, **medido**), so it is filled again until a
    // boot starts with less than EFI_MIN_FREE.
    let mut written: u64 = 0;
    let mut rounds = Vec::new();
    let v = loop {
        let mut free = nvram_free(&mut vm, &mut log)?;
        written += fill_nvram(&mut vm, &mut log, &mut free, written)?;
        vm.poweroff(&mut log)?;
        drop(vm);
        vm = ctx.boot("crash/nvram-full", false, &[&pkg])?;
        vm.expect_all(&mut log, &["ready:", "maintenance shell"], 120)?;
        let v = vm.ok(&mut log, "system.crash.print", "{}")?;
        let at_boot = v["efi"]["free"].as_u64().unwrap_or(0);
        rounds.push(format!("{free} B left, {at_boot} B at the next boot"));
        if at_boot < EFI_MIN_FREE || rounds.len() >= 3 {
            break v;
        }
    };
    n.put(
        "NVRAM filled by another GUID (1 KiB variables)",
        format!("{written} written; {}", rounds.join("; ")),
    );
    let listed = shell_line(
        &mut vm,
        &mut log,
        "ls /sys/firmware/efi/efivars | grep -c '^dump-type'",
    )?;
    check(
        listed == "0",
        format!("{listed} dump variable(s) listed after a reboot"),
    )?;
    check(
        v["efi"]["turned_off"] == true && v["efi"]["enabled"] == false,
        format!("efi_pstore stayed on with the NVRAM short: {v}"),
    )?;
    let free = v["efi"]["free"].as_u64().unwrap_or(0);
    let h = vm.ok(&mut log, "system.health.check", "{}")?;
    check(
        h["checks"].as_array().is_some_and(|a| {
            a.iter()
                .any(|c| c["key"] == "kernel.crash-store" && c["severity"] == "warning")
        }),
        format!("no crash-store warning: {h}"),
    )?;
    vm.stdin_write(b"echo c > /proc/sysrq-trigger\n")?;
    vm.expect(&mut log, &["Kernel panic"], 60)?;
    vm.wait_exit(&mut log, 60)?;
    drop(vm);
    let mut vm = ctx.boot("crash/full-after-panic", false, &[&pkg])?;
    vm.expect_all(&mut log, &["ready:", "maintenance shell"], 120)?;
    let free2 = nvram_free(&mut vm, &mut log)?;
    let v = vm.ok(&mut log, "system.crash.print", "{}")?;
    check(
        v["crashes"][0]["this_boot"] != true,
        format!("a panic with efi_pstore off left a record: {v}"),
    )?;
    n.put(
        "panic with the NVRAM short: no record, NVRAM free",
        format!("{free} → {free2} B"),
    );
    // The A/B update still has room for its boot entries.
    vm.print_until(&mut log, 60, |v| v["running"] == "a")?;
    update_and_confirm(ctx, &mut log, vm, "b", "crash/trial-b")?;
    Ok(())
}

/// A shell command's output line on the guest's console.
pub(super) fn shell_line(
    vm: &mut Vm,
    log: &mut std::fs::File,
    cmd: &str,
) -> Result<String, String> {
    vm.stdin_write(format!("{cmd} 2>&1 | sed \"s/^/@@$((2+1))S /\"\n").as_bytes())?;
    let got = vm.expect(log, &["@@3S "], 30)?;
    Ok(got.split("@@3S ").nth(1).unwrap_or("").trim().to_owned())
}

/// `corerouter-cli upload` of `pkg` to the guest over TLS, in the
/// background (it waits for the reboots the test drives).
fn push_cli(ctx: &Ctx, cli: &Path, fp: &str, pkg: &Path, params: &str) -> Result<Child, String> {
    let port = ctx.fwd.ok_or("no forwarded port")?;
    let home = ctx.work.join("push-home");
    std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
    Command::new(cli)
        .args([
            "--connect",
            &format!("tls://127.0.0.1:{port}"),
            "--user",
            "admin",
            "--fingerprint",
            fp,
        ])
        .arg("upload")
        .arg(pkg)
        .args([params, "--wait"])
        .env("HOME", &home)
        .env("COREROUTER_PASSWORD", PUSH_PASSWORD)
        .env("RUST_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {e}", cli.display()))
}

const PUSH_PASSWORD: &str = "ab-test-push-Pw1";

/// G1.6e: push over the network. Slot A gets a password, an identity and
/// its certificate; the package goes over TLS in chunks straight to slot
/// B; after the reboot the same certificate (pinned), password and
/// identity answer from B. Then a package whose daemon never answers is
/// pushed the same way: its trial is not confirmed and B comes back.
fn scenario_push(ctx: &mut Ctx, n: &mut Numbers) -> Result<(), String> {
    // The CLI `os push` runs (same build, same target).
    let cli = super::push::cli(&ctx.root)?;
    let pkg = ctx.work.join("push-b.crpkg");
    let version = package(ctx, &pkg, "-push", None, None)?;
    ctx.fwd = Some(super::free_port()?);
    let mut log = ctx.log.try_clone().map_err(|e| e.to_string())?;
    let r = (|| -> Result<(), String> {
        let mut vm = fresh(ctx, n, "push", &[])?;
        vm.ok(
            &mut log,
            "user.set",
            &format!(r#"{{"name":"admin","password":"{PUSH_PASSWORD}"}}"#),
        )?;
        vm.ok(&mut log, "system.identity.set", r#"{"name":"push-kept"}"#)?;
        let fp = shell_line(
            &mut vm,
            &mut log,
            "grep -o 'SHA256:[0-9A-F:]*' /var/log/corerouter-daemon.log | tail -n 1",
        )?;
        check(
            fp.starts_with("SHA256:") && fp.len() > 60,
            format!("certificate fingerprint: '{fp}'"),
        )?;
        let t = Instant::now();
        let child = push_cli(ctx, &cli, &fp, &pkg, r#"{"timeout":120}"#)?;
        // The router reboots once the slot is written.
        vm.wait_exit(&mut log, 180)?;
        drop(vm);
        let mut vm = ctx.boot("push/trial-b", false, &[])?;
        vm.expect(&mut log, &["trial boot of slot b"], 120)?;
        vm.expect_all(
            &mut log,
            &[
                "ready:",
                "maintenance shell",
                "trial boot of slot b confirmed",
            ],
            120,
        )?;
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let _ = writeln!(log, "{stderr}");
        check(
            out.status.success(),
            format!("corerouter-cli upload: {stderr}"),
        )?;
        let v: Value =
            serde_json::from_slice(&out.stdout).map_err(|e| format!("upload output: {e}"))?;
        let tm = &v["times"];
        n.put(
            "push over TLS (QEMU user network): send",
            format!(
                "{} s for {:.1} MiB ({} MiB/s)",
                tm["send_s"],
                tm["bytes"].as_f64().unwrap_or(0.0) / 1048576.0,
                tm["mib_per_s"]
            ),
        );
        n.put(
            "push: upload start → slot written and read back",
            format!("{} s", tm["done_s"]),
        );
        n.put(
            "push: whole cycle (send → B confirmed, CLI clock)",
            format!("{:.1} s", t.elapsed().as_secs_f64()),
        );
        check(
            v["last"]["result"] == "confirmed" && v["last"]["slot"] == "b",
            format!("push result: {v}"),
        )?;
        let p = vm.print_until(&mut log, 30, |v| v["primary"] == "b")?;
        check(
            slot(&p, "b")["version"] == version.as_str(),
            "slot B version after the push",
        )?;
        let id = vm.ok(&mut log, "system.identity.get", "{}")?;
        check(
            id.to_string().contains("push-kept"),
            format!("/config not kept: identity {id}"),
        )?;
        let fp2 = shell_line(
            &mut vm,
            &mut log,
            "grep -o 'SHA256:[0-9A-F:]*' /var/log/corerouter-daemon.log | tail -n 1",
        )?;
        check(fp2 == fp, format!("certificate changed: {fp} → {fp2}"))?;

        // A bad package pushed the same way: back to B by itself.
        let squashfs = broken_squashfs(ctx)?;
        let bad = ctx.work.join("push-broken.crpkg");
        package(ctx, &bad, "-push-broken", Some(&squashfs), None)?;
        let child = push_cli(ctx, &cli, &fp, &bad, r#"{"timeout":30}"#)?;
        vm.wait_exit(&mut log, 180)?;
        drop(vm);
        let mut vm = ctx.boot("push/trial-a-broken", false, &[])?;
        vm.expect(&mut log, &["trial boot of slot a"], 120)?;
        vm.expect(&mut log, &["not confirmed in 30 s"], 90)?;
        vm.wait_exit(&mut log, 60)?;
        drop(vm);
        let mut vm = ctx.boot("push/back-on-b", false, &[])?;
        vm.expect(
            &mut log,
            &["back on slot b after the trial of slot a failed"],
            120,
        )?;
        vm.expect_all(&mut log, &["ready:", "maintenance shell"], 120)?;
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        let _ = writeln!(log, "{stderr}");
        check(
            !out.status.success() && stderr.contains("not kept"),
            format!("bad push should fail: {stderr}"),
        )?;
        let p = vm.print_until(&mut log, 30, |v| v["running"] == "b")?;
        check(
            p["last"]["result"] == "rolled-back" && p["primary"] == "b",
            format!("after the bad push: {p}"),
        )?;
        let id = vm.ok(&mut log, "system.identity.get", "{}")?;
        check(
            id.to_string().contains("push-kept"),
            "identity lost after the rollback",
        )?;
        vm.poweroff(&mut log)?;
        Ok(())
    })();
    ctx.fwd = None;
    r
}

/// One update and its trial, confirmed. `next` is the slot it goes to.
fn update_and_confirm(
    ctx: &mut Ctx,
    log: &mut std::fs::File,
    mut vm: Vm,
    next: &str,
    name: &str,
) -> Result<Value, String> {
    vm.ok(
        log,
        "system.package.update",
        r#"{"path":"/dev/vdb","timeout":120}"#,
    )?;
    vm.wait_exit(log, 120)?;
    drop(vm);
    let mut vm = ctx.boot(name, false, &[])?;
    vm.expect_all(log, &["ready:", "maintenance shell"], 120)?;
    let v = vm.print_until(log, 60, |v| v["primary"] == next)?;
    check(
        v["running"] == next && slot(&v, next)["verity"] == Value::Bool(true),
        format!("{name}: {v}"),
    )?;
    vm.poweroff(log)?;
    Ok(v)
}

/// G1.6g: the same disk, on each firmware in turn.
fn scenario_cross(ctx: &mut Ctx, n: &mut Numbers) -> Result<(), String> {
    let first = ctx.fw;
    let (a, b) = (Firmware::Ovmf, Firmware::SeaBios);
    let r = (|| {
        ctx.fw = a;
        let pkg_b = ctx.work.join("cross-b.crpkg");
        let pkg_c = ctx.work.join("cross-c.crpkg");
        package(ctx, &pkg_b, "-b", None, None)?;
        package(ctx, &pkg_c, "-c", None, None)?;
        let mut log = ctx.log.try_clone().map_err(|e| e.to_string())?;
        let vm = fresh(ctx, n, "cross", &[&pkg_b])?;
        update_and_confirm(ctx, &mut log, vm, "b", "cross/uefi-trial-b")?;
        // To a BIOS: the slot and the order UEFI left.
        ctx.fw = b;
        let mut vm = ctx.boot("cross/bios", false, &[&pkg_c])?;
        vm.expect_all(&mut log, &["ready:", "maintenance shell"], 120)?;
        let v = vm.print_until(&mut log, 30, |v| v["running"] == "b")?;
        check(
            v["firmware"] == "bios"
                && v["primary"] == "b"
                && slot(&v, "b")["verity"] == Value::Bool(true),
            format!("moved to BIOS: {v}"),
        )?;
        let v = update_and_confirm(ctx, &mut log, vm, "a", "cross/bios-trial-a")?;
        let hash = slot(&v, "a")["cmdline"].as_str().unwrap_or("").to_owned();
        // Back on the old NVRAM: its order, and slot A's entry put right.
        ctx.fw = a;
        let mut vm = ctx.boot("cross/uefi", false, &[])?;
        vm.expect_all(&mut log, &["ready:", "maintenance shell"], 120)?;
        let v = vm.print_until(&mut log, 30, |v| {
            slot(v, "a")["cmdline"].as_str() == Some(hash.as_str())
        })?;
        check(
            v["firmware"] == "uefi" && v["running"] == "b",
            format!("back on UEFI: {v}"),
        )?;
        vm.poweroff(&mut log)?;
        Ok(())
    })();
    ctx.fw = first;
    r
}

/// G1.6g: the power goes during an update (141 ms, **measured**) and around
/// the moment GRUB erases `next=`. The next boot comes up on a verified slot.
/// A torn block is the lab's (`bios_power_cut_around_grubenv`): a kill cannot
/// aim at one sector.
fn scenario_cut(ctx: &mut Ctx, n: &mut Numbers) -> Result<(), String> {
    let pkg = ctx.work.join("cut.crpkg");
    package(ctx, &pkg, "-b", None, None)?;
    let mut log = ctx.log.try_clone().map_err(|e| e.to_string())?;
    let mut landed = Vec::new();
    for (i, (update_ms, grub_ms)) in [
        (Some(20), None),
        (Some(60), None),
        (Some(100), None),
        (None, Some(100)),
        (None, Some(200)),
        (None, Some(300)),
    ]
    .into_iter()
    .enumerate()
    {
        let mut vm = fresh(ctx, n, "cut", &[&pkg])?;
        vm.ok(
            &mut log,
            "system.package.update",
            r#"{"path":"/dev/vdb","timeout":120}"#,
        )?;
        if let Some(ms) = update_ms {
            std::thread::sleep(Duration::from_millis(ms));
            drop(vm);
        } else {
            vm.wait_exit(&mut log, 120)?;
            drop(vm);
            let vm = ctx.boot(&format!("cut/{i}-grub"), false, &[])?;
            std::thread::sleep(Duration::from_millis(grub_ms.unwrap_or(0)));
            drop(vm);
        }
        let mut vm = ctx.boot(&format!("cut/{i}-after"), false, &[])?;
        vm.expect_all(&mut log, &["ready:", "maintenance shell"], 120)?;
        let v = vm.print_until(&mut log, 30, |v| v["running"].is_string())?;
        let on = v["running"].as_str().unwrap_or("").to_owned();
        check(
            slot(&v, &on)["verity"] == Value::Bool(true),
            format!("cut {i}: {v}"),
        )?;
        landed.push(on);
        vm.poweroff(&mut log)?;
    }
    n.put(
        "power cuts: the slot each next boot came up on",
        landed.join(" "),
    );
    Ok(())
}

/// G1.6g: Proxmox's controllers on its default board. The kernel needs each
/// driver and SeaBIOS must read the disk through each one; `megasas` is out:
/// QEMU's device fails the reads of SeaBIOS (`docs/os-image.md`).
fn scenario_controllers(ctx: &mut Ctx, n: &mut Numbers) -> Result<(), String> {
    let mut log = ctx.log.try_clone().map_err(|e| e.to_string())?;
    for (name, dev) in [
        ("virtio-blk", "-device virtio-blk-pci,drive=d"),
        (
            "virtio-scsi",
            "-device virtio-scsi-pci,id=s -device scsi-hd,drive=d,bus=s.0",
        ),
        (
            "lsi53c895a",
            "-device lsi53c895a,id=s -device scsi-hd,drive=d,bus=s.0",
        ),
        (
            "pvscsi",
            "-device pvscsi,id=s -device scsi-hd,drive=d,bus=s.0",
        ),
        ("ide", "-device ide-hd,drive=d,bus=ide.0"),
    ] {
        // A disk per controller: each boot ends with a cut, with no shell to
        // power off from.
        new_disk(ctx)?;
        let mut cmd = qemu_board("pc", ctx.kvm, Firmware::SeaBios, &ctx.work.join("vars.fd"));
        cmd.arg("-drive").arg(format!(
            "file={},if=none,id=d,format=qcow2",
            ctx.work.join("disk.qcow2").display()
        ));
        cmd.args(dev.split_whitespace());
        let mut vm = start(&mut ctx.log, &format!("controllers/{name}"), cmd)?;
        let r = vm.expect_all(&mut log, &["ready:"], 120)?;
        n.put(
            &format!("{name} on pc: kernel → daemon ready"),
            ready_s(r.first().map_or("", String::as_str)),
        );
    }
    Ok(())
}

/// `cargo xtask os ab-test [--tcg] [--firmware ovmf|seabios] [--scenario update|reflash|push|no-confirm|bad-signature|bad-param|cross|cut|controllers|to-ram]`.
pub fn ab_test(root: &Path, images: &Path, args: &[String]) -> Result<(), String> {
    let mut tcg = false;
    let mut only: Option<String> = None;
    let mut fw = Firmware::Ovmf;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--tcg" => tcg = true,
            "--firmware" => fw = Firmware::parse(it.next().map(String::as_str))?,
            "--scenario" => only = Some(it.next().ok_or("--scenario needs a name")?.clone()),
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    check(
        images.join("disk.img").exists(),
        "disk.img missing: run `cargo xtask os build` first",
    )?;
    check(
        Path::new(OVMF_CODE).exists(),
        format!("{OVMF_CODE} missing (package ovmf)"),
    )?;
    let work = super::out_dir(root)?.join("ab-test");
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let log_path = work.join("console.log");
    let log = std::fs::File::create(&log_path).map_err(|e| e.to_string())?;
    let mut ctx = Ctx {
        tool: tool(root)?,
        root: root.to_owned(),
        work: work.clone(),
        images: images.to_owned(),
        kvm: !tcg && super::kvm_usable(),
        fw,
        log,
        fwd: None,
    };
    let mut n = Numbers(Vec::new());
    type Scenario = fn(&mut Ctx, &mut Numbers) -> Result<(), String>;
    let all: [(&str, Scenario); 11] = [
        ("update", scenario_update),
        ("reflash", scenario_reflash),
        ("push", scenario_push),
        ("no-confirm", scenario_no_confirm),
        ("bad-signature", scenario_bad_signature),
        ("bad-param", scenario_bad_param),
        // G1.6zx: panics in UEFI variables, and a full NVRAM.
        ("crash", scenario_crash),
        ("cross", scenario_cross),
        ("cut", scenario_cut),
        ("controllers", scenario_controllers),
        // G1.6zn: the system in RAM, and the system disk pulled out.
        ("to-ram", super::to_ram::scenario),
    ];
    let t = Instant::now();
    let mut passed = Vec::new();
    for (name, f) in all {
        if only.as_deref().is_some_and(|o| o != name) {
            continue;
        }
        // What is about GRUB's files and the old board runs with SeaBIOS.
        if fw == Firmware::Ovmf && matches!(name, "cut" | "controllers") {
            continue;
        }
        // Boot entries in NVRAM are UEFI's.
        if fw == Firmware::SeaBios && matches!(name, "reflash" | "crash") {
            continue;
        }
        eprintln!(
            "\n== ab-test {name} ({}, {}) ==",
            if ctx.kvm { "KVM" } else { "TCG" },
            fw.name()
        );
        let ts = Instant::now();
        f(&mut ctx, &mut n)
            .map_err(|e| format!("{name}: {e} (console in {})", log_path.display()))?;
        eprintln!("   ok in {:.1} s", ts.elapsed().as_secs_f64());
        passed.push(name);
    }
    check(!passed.is_empty(), "no such scenario")?;
    eprintln!(
        "\nab-test ok: {} in {:.1} s",
        passed.join(", "),
        t.elapsed().as_secs_f64()
    );
    for (k, v) in &n.0 {
        eprintln!("  {k}: {v}");
    }
    let _ = std::fs::remove_file(work.join("disk.qcow2"));
    Ok(())
}
