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
//! either, a development key generated once in `os/out/keys/` (ignored by
//! git, never in the image). The image only carries the public key.

// `serde_json::Value` indexing (`v["slots"]`) gives `Null` for a missing
// key and never panics; the lint cannot tell it from slice indexing.
#![allow(clippy::indexing_slicing)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
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

/// The signing key and the public-key directory (`corerouter-image key`).
pub fn ensure_key(
    root: &Path,
    tool: &Path,
    given: Option<&Path>,
) -> Result<(PathBuf, PathBuf), String> {
    let keys = root.join("os/out/keys");
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
    let keys = ctx.root.join("os/out/keys").to_string_lossy().into_owned();
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

struct Ctx {
    root: PathBuf,
    tool: PathBuf,
    work: PathBuf,
    images: PathBuf,
    kvm: bool,
    log: std::fs::File,
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
}

const SHELL_APPEND: &str = "ip=10.0.2.15::10.0.2.2:255.255.255.0::eth0:off corerouter.shell=ttyS0";

/// The QEMU machine every image test boots: q35, 2 vCPUs, 1 GiB, serial
/// console on stdio, OVMF with the NVRAM in `vars`, no reboot (a guest
/// reboot ends the run).
pub(super) fn qemu_base(kvm: bool, vars: &Path) -> Command {
    let mut cmd = Command::new("qemu-system-x86_64");
    let accel = if kvm {
        "q35,accel=kvm"
    } else {
        "q35,accel=tcg"
    };
    cmd.args(["-machine", accel, "-cpu", if kvm { "host" } else { "max" }]);
    cmd.args([
        "-smp", "2", "-m", "1024", "-display", "none", "-monitor", "none",
    ]);
    cmd.args(["-serial", "stdio", "-no-reboot"]);
    cmd.arg("-drive")
        .arg(format!("if=pflash,format=raw,readonly=on,file={OVMF_CODE}"));
    cmd.arg("-drive")
        .arg(format!("if=pflash,format=raw,file={}", vars.display()));
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
    std::thread::Builder::new()
        .name("qemu-serial".into())
        .spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
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
    })
}

impl Ctx {
    fn boot(&mut self, name: &str, first: bool, extra: &[&Path]) -> Result<Vm, String> {
        let mut cmd = qemu_base(self.kvm, &self.work.join("vars.fd"));
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
            // The factory boot: OVMF loads the kernel QEMU hands it, with the
            // test's platform arguments; the image provisions its boot
            // entries (carrying those arguments) and later boots go through
            // the firmware's boot manager.
            cmd.arg("-kernel").arg(self.images.join("bzImage"));
            cmd.arg("-append").arg(SHELL_APPEND);
        }
        start(&mut self.log, name, cmd)
    }
}

impl Vm {
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
fn fresh(ctx: &mut Ctx, n: &mut Numbers, scenario: &str, extra: &[&Path]) -> Result<Vm, String> {
    let disk = ctx.work.join("disk.qcow2");
    let _ = std::fs::remove_file(&disk);
    let st = Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2", "-F", "raw", "-b"])
        .arg(ctx.images.join("disk.img"))
        .arg(&disk)
        .status()
        .map_err(|e| format!("qemu-img: {e}"))?;
    check(st.success(), "qemu-img create failed")?;
    fresh_vars(&ctx.work.join("vars.fd"))?;
    let mut log = ctx.log.try_clone().map_err(|e| e.to_string())?;
    let mut vm = ctx.boot(&format!("{scenario}/factory"), true, &[])?;
    let r = vm.expect_all(&mut log, &["ready:", "maintenance shell"], 120)?;
    if scenario == "update" {
        n.put(
            "boot without dm-verity (fallback path): kernel → daemon ready",
            ready_s(r.first().map_or("", String::as_str)),
        );
    }
    vm.print_until(&mut log, 30, |v| !slot(v, "a")["boot_entry"].is_null())?;
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
    Ok(vm)
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
    vm.expect(&mut log, &["trial boot of slot b"], 120)?;
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
    vm.poweroff(&mut log)?;
    Ok(())
}

/// A shell command's output line on the guest's console.
fn shell_line(vm: &mut Vm, log: &mut std::fs::File, cmd: &str) -> Result<String, String> {
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
    let st = Command::new(crate::cargo_bin())
        .args(["build", "-q", "--release", "-p", "corerouter-cli"])
        .current_dir(&ctx.root)
        .status()
        .map_err(|e| format!("cargo: {e}"))?;
    check(st.success(), "cargo build -p corerouter-cli failed")?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let cli = exe
        .parent()
        .and_then(Path::parent)
        .map(|t| t.join("release/corerouter-cli"))
        .ok_or("no target directory")?;
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

/// `cargo xtask os ab-test [--tcg] [--scenario update|push|no-confirm|bad-signature|bad-param]`.
pub fn ab_test(root: &Path, images: &Path, args: &[String]) -> Result<(), String> {
    let mut tcg = false;
    let mut only: Option<String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--tcg" => tcg = true,
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
    let work = root.join("os/out/ab-test");
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let log_path = work.join("console.log");
    let log = std::fs::File::create(&log_path).map_err(|e| e.to_string())?;
    let mut ctx = Ctx {
        tool: tool(root)?,
        root: root.to_owned(),
        work: work.clone(),
        images: images.to_owned(),
        kvm: !tcg && super::kvm_usable(),
        log,
        fwd: None,
    };
    let mut n = Numbers(Vec::new());
    type Scenario = fn(&mut Ctx, &mut Numbers) -> Result<(), String>;
    let all: [(&str, Scenario); 5] = [
        ("update", scenario_update),
        ("push", scenario_push),
        ("no-confirm", scenario_no_confirm),
        ("bad-signature", scenario_bad_signature),
        ("bad-param", scenario_bad_param),
    ];
    let t = Instant::now();
    let mut passed = Vec::new();
    for (name, f) in all {
        if only.as_deref().is_some_and(|o| o != name) {
            continue;
        }
        eprintln!(
            "\n== ab-test {name} ({}) ==",
            if ctx.kvm { "KVM" } else { "TCG" }
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
