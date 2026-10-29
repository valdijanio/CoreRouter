//! System › Packages (G1.6b): the A/B image's service.
//!
//! On its own thread. The session lock is taken only to take the queued
//! job, to hand over status and progress (O(1) each) and, during a trial,
//! to read the links once a second; the slot write, the read-back check
//! and the boot variables run with the lock released.
//!
//! - **Image** (`--backend linux` under `corerouter-init`): the platform of
//!   the disk (`corerouter_sysupdate::ab::discover`). On start it creates
//!   missing boot entries; during a trial boot with `confirm=auto` it
//!   confirms once the daemon has been up for [`GRACE`] and every
//!   management interface runs again. Init reboots into the previous slot
//!   if that does not happen in time.
//! - **Virtual lab** (`--backend virtual --config-dir`): the same code on
//!   `<config-dir>/lab-image/` (sparse files, a directory for the boot
//!   variables), with the firmware's reboot simulated: a lab update boots
//!   its trial on the spot, and an unconfirmed trial rolls back at its
//!   deadline.
//! - Anywhere else (a development machine with `--backend linux`): off, and
//!   it says why. It never writes a host's boot variables or disks.
//!
//! G1.6e: an upload job reads the chunks the control channel queues
//! (`system.package.upload.chunk`) as a stream and installs (or checks) it
//! like a file: header and signature first, then straight to the slot.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use corerouter_engine::package::{self, Job, JobKind};
use corerouter_engine::{Shared, lock};
use corerouter_sysupdate::SlotId;
use corerouter_sysupdate::ab::{Opts, Platform};
use corerouter_sysupdate::package::load_keys;
use corerouter_sysupdate::state::{Confirm, Reason, State};
use corerouter_sysupdate::upload::ChunkReader;
use serde_json::{Value, json};

const TICK: Duration = Duration::from_millis(250);
/// Status is re-read this often (a few small files and two signature
/// checks: ~0.2 ms, **medido** in the lab test).
const STATUS_EVERY: Duration = Duration::from_secs(2);
/// A trial is confirmed only after the daemon has been up this long (it
/// did not crash on its configuration). Flatcar waits ~2 min; ours is short
/// because the deadline (default 300 s) bounds the risk anyway.
const GRACE: Duration = Duration::from_secs(10);
/// Between a slot-changing job's result and the reboot.
const REBOOT_PAUSE: Duration = Duration::from_secs(2);
/// An upload with no chunk for this long is dropped (the client is gone).
const UPLOAD_STALL: Duration = Duration::from_secs(60);
const KEYS_DIR: &str = "/etc/corerouter/image-keys";
const ESP_MOUNT: &str = "/run/corerouter/esp";
/// Lab slots (sparse files).
const LAB_SLOT: u64 = 256 << 20;
const TUNING_KEYS: &[&str] = &[
    "isolcpus",
    "nohz_full",
    "intel_idle.max_cstate",
    "processor.max_cstate",
    "pcie_aspm",
    "iommu",
    "mitigations",
];

pub(crate) const SERVICE: super::Service = super::Service {
    name: "package",
    flags: &[super::Flag {
        name: "--image-keys",
        value: Some("<dir>"),
        help: "Ed25519 public keys trusted for system packages (default /etc/corerouter/image-keys)",
    }],
    topic: "system",
    enable: "always on (System › Packages)",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let keys_dir = PathBuf::from(ctx.flag("--image-keys").unwrap_or(KEYS_DIR));
    let config_dir = ctx.config_dir.clone();
    let lab = lock(&session).backend().starts_with("virtual lab");
    Ok(Box::new(move |health: &super::Health| {
        let mut svc = Svc::new(&session, &keys_dir, config_dir.as_deref(), lab);
        if let Some(e) = &svc.off {
            health.disabled(Some(e));
        }
        while health.sleep(TICK) {
            health.beat();
            svc.tick(&session, health);
        }
        Ok(())
    }))
}

struct Svc {
    platform: Option<Platform>,
    off: Option<String>,
    started: Instant,
    /// Unix time of the boot (deadline of a trial = boot + timeout).
    boot_unix: u64,
    status_at: Option<Instant>,
    healthy_since: Option<Instant>,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn uptime_s() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split('.').next()?.trim().parse().ok())
        .unwrap_or(0)
}

impl Svc {
    fn new(session: &Shared, keys_dir: &Path, config: Option<&Path>, lab: bool) -> Svc {
        let made = match (lab, config) {
            (true, Some(c)) => Platform::lab(&c.join("lab-image"), c, load_keys(keys_dir), LAB_SLOT),
            (true, None) => Err("virtual lab without --config-dir: nowhere to keep the lab image".into()),
            (false, Some(c)) => discover(c, keys_dir),
            (false, None) => Err("no --config-dir: no configuration to keep across an update".into()),
        };
        let made = made.and_then(|mut p| {
            if p.lab.is_some() {
                p.lab_seed(env!("CARGO_PKG_VERSION"), 1)?;
            }
            Ok(p)
        });
        let (platform, off) = match made {
            Ok(p) => (Some(p), None),
            Err(e) => (None, Some(e)),
        };
        if let Some(e) = &off {
            package::feed_status(&mut lock(session), json!({"supported": false, "reason": e}));
        }
        let boot_unix = if lab { now_unix() } else { now_unix().saturating_sub(uptime_s()) };
        Svc {
            platform,
            off,
            started: Instant::now(),
            boot_unix,
            status_at: None,
            healthy_since: None,
        }
    }

    fn tick(&mut self, session: &Shared, health: &super::Health) {
        let Some(p) = self.platform.as_mut() else { return };
        if self.status_at.is_none() {
            match p.provision(TUNING_KEYS) {
                Ok(log) => log.iter().for_each(|l| {
                    log::info!("package: {l}");
                    health.event(l);
                }),
                Err(e) => health.error(format!("boot entries: {e}")),
            }
        }
        let job = package::take_job(&mut lock(session));
        if let Some(job) = job {
            self.run(session, health, job);
            self.status_at = None;
        }
        self.trial(session, health);
        if self.status_at.is_none_or(|t| t.elapsed() >= STATUS_EVERY) {
            self.feed(session);
        }
    }

    fn feed(&mut self, session: &Shared) {
        let Some(p) = self.platform.as_ref() else { return };
        let (st, _) = State::load(&p.state_dir());
        let mut v = p.status(&st);
        if let (Some(t), Some(trial)) = (&st.trial, v.get_mut("trial").and_then(Value::as_object_mut))
            && p.running() == Some(t.slot)
        {
            let deadline = self.boot_unix + t.timeout_s;
            trial.insert("deadline_unix".into(), json!(deadline));
            // The engine refines it with its clock when it has one (the lab's
            // has none): at most STATUS_EVERY old.
            trial.insert("remaining_s".into(), json!(deadline.saturating_sub(now_unix())));
        }
        package::feed_status(&mut lock(session), v);
        self.status_at = Some(Instant::now());
    }

    /// During a trial boot: confirm (auto) once healthy; in the lab, play
    /// init's deadline.
    fn trial(&mut self, session: &Shared, health: &super::Health) {
        let Some(p) = self.platform.as_mut() else { return };
        let (st, _) = State::load(&p.state_dir());
        let Some(t) = st.trial else {
            self.healthy_since = None;
            return;
        };
        if p.running() != Some(t.slot) {
            return;
        }
        if p.lab.is_some() && now_unix() >= self.boot_unix + t.timeout_s {
            health.event(format!("lab: trial of slot {} not confirmed in {} s: rebooting", t.slot.as_str(), t.timeout_s));
            if let Err(e) = p.lab_reboot() {
                health.error(e);
            }
            self.status_at = None;
            return;
        }
        if t.confirm != Confirm::Auto || self.started.elapsed() < GRACE {
            return;
        }
        let rows = lock(session).execute("interface.list", &json!({})).unwrap_or(Value::Null);
        let up = |name: &str| {
            rows.as_array().is_some_and(|r| {
                r.iter().any(|i| i.get("name").and_then(Value::as_str) == Some(name) && i.get("running") == Some(&json!(true)))
            })
        };
        let down: Vec<&String> = t.mgmt.iter().filter(|m| !up(m)).collect();
        if !down.is_empty() {
            self.healthy_since = None;
            return;
        }
        let since = *self.healthy_since.get_or_insert_with(Instant::now);
        if since.elapsed() < Duration::from_secs(2) {
            return;
        }
        let detail = if t.mgmt.is_empty() {
            "daemon up".to_owned()
        } else {
            format!("daemon up; management interfaces running: {}", t.mgmt.join(", "))
        };
        match p.confirm(now_unix(), &detail) {
            Ok(o) => {
                log::info!("package: slot {} ({}) confirmed: {detail}", o.slot.as_str(), o.version);
                health.event(format!("slot {} confirmed", o.slot.as_str()));
            }
            Err(e) => health.error(format!("confirm: {e}")),
        }
        self.status_at = None;
    }

    fn run(&mut self, session: &Shared, health: &super::Health, job: Job) {
        let id = job.id;
        let kind = job.kind.name();
        let out = self.work(session, &job);
        match &out {
            Ok(_) => health.event(format!("{kind} done")),
            Err(e) => {
                log::warn!("package: {kind}: {e}");
                health.error(format!("{kind}: {e}"));
            }
        }
        let ok = out.is_ok();
        package::finish(&mut lock(session), id, kind, out);
        if ok && job.kind.arms_trial() && job.reboot {
            self.feed(session);
            self.reboot(session, health);
        }
    }

    fn work(&mut self, session: &Shared, job: &Job) -> Result<Value, String> {
        let p = self.platform.as_ref().ok_or("A/B updates are off")?;
        let threads = std::thread::available_parallelism().map(|n| n.get().min(8)).unwrap_or(1);
        let opts = |reason: Reason, drill: bool| Opts {
            reason,
            confirm: if job.confirm == "manual" { Confirm::Manual } else { Confirm::Auto },
            timeout_s: job.timeout_s,
            tuning: job.tuning.clone(),
            mgmt: job.mgmt.clone(),
            now: now_unix(),
            pipelined: true,
            threads,
            config_format: job.config_format,
            drill,
        };
        let phase = if matches!(job.kind, JobKind::Upload { .. }) { "receiving and writing" } else { "writing" };
        let mut last = Instant::now();
        let mut progress = |done: u64, total: u64| {
            if last.elapsed() >= Duration::from_millis(100) || done == total {
                last = Instant::now();
                package::feed_progress(&mut lock(session), phase, done, total);
            }
        };
        let rep = match &job.kind {
            JobKind::Update { path } => p.install(Path::new(path), false, &opts(Reason::Update, false), &mut progress)?,
            JobKind::Downgrade { path: Some(path) } => {
                p.install(Path::new(path), true, &opts(Reason::Downgrade, false), &mut progress)?
            }
            JobKind::Downgrade { path: None } => p.switch_back(&opts(Reason::Downgrade, false))?,
            JobKind::BootParams { drill } => p.clone_running(&opts(Reason::BootParams, *drill), &mut progress)?,
            JobKind::Confirm => {
                let o = p.confirm(now_unix(), "confirmed by an operator")?;
                return Ok(json!({"slot": o.slot.as_str(), "version": o.version}));
            }
            JobKind::Cancel => {
                p.cancel()?;
                return Ok(json!({}));
            }
            JobKind::Check { path } => return check(p, Path::new(path)),
            JobKind::Upload { size, downgrade, check } => {
                let rx = package::take_upload(&mut lock(session), job.id).ok_or("upload: its stream is gone (aborted)")?;
                let mut src = ChunkReader::new(rx, *size, UPLOAD_STALL);
                let t = Instant::now();
                if *check {
                    package::feed_progress(&mut lock(session), "receiving and checking", 0, *size);
                    return corerouter_sysupdate::upload::check(&mut src, Some(*size), &p.keys);
                }
                let reason = if *downgrade { Reason::Downgrade } else { Reason::Update };
                let rep = p.install_from(&mut src, Some(*size), *downgrade, &opts(reason, false), &mut progress)?;
                log::info!(
                    "package: upload of {size} bytes in {} ms, {} ms of it waiting for the network",
                    t.elapsed().as_millis(),
                    src.waited.as_millis()
                );
                let mut v = rep.json();
                if let Some(o) = v.as_object_mut() {
                    o.insert("network_wait_ms".into(), json!(src.waited.as_millis() as u64));
                }
                return Ok(v);
            }
            JobKind::Scrub { slot } => {
                let s = SlotId::parse(slot).ok_or("slot must be a or b")?;
                return p.scrub(s, threads);
            }
        };
        log::info!(
            "package: {} {} into slot {}: wrote {} bytes in {} ms, read back and verified in {} ms",
            job.kind.name(),
            rep.version,
            rep.slot.map(SlotId::as_str).unwrap_or("?"),
            rep.bytes,
            rep.write_ms,
            rep.verify_ms
        );
        Ok(rep.json())
    }

    fn reboot(&mut self, session: &Shared, health: &super::Health) {
        let Some(p) = self.platform.as_mut() else { return };
        if p.lab.is_some() {
            match p.lab_reboot() {
                Ok((_, log)) => log.iter().for_each(|l| health.event(l)),
                Err(e) => health.error(e),
            }
            self.boot_unix = now_unix();
            self.started = Instant::now();
            self.feed(session);
            return;
        }
        // A moment for whoever asked (an upload's client polls every
        // 100 ms) to read the result before the connection goes.
        std::thread::sleep(REBOOT_PAUSE);
        log::warn!("package: rebooting into the trial slot");
        reboot_image();
    }
}

/// A package's header, signature and payload hashes, without installing.
fn check(p: &Platform, path: &Path) -> Result<Value, String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let exact = f.metadata().ok().filter(|m| m.is_file()).map(|m| m.len());
    corerouter_sysupdate::upload::check(&mut f, exact, &p.keys)
}

#[cfg(target_os = "linux")]
fn discover(config: &Path, keys: &Path) -> Result<Platform, String> {
    corerouter_sysupdate::ab::discover(config, keys, Path::new(ESP_MOUNT))
}

#[cfg(not(target_os = "linux"))]
fn discover(_: &Path, _: &Path) -> Result<Platform, String> {
    let _ = ESP_MOUNT;
    Err("A/B updates run on the CoreRouter image (Linux) only".into())
}

/// Asks PID 1 (corerouter-init) for a clean reboot: it stops this daemon,
/// syncs and unmounts `/config`.
#[cfg(target_os = "linux")]
fn reboot_image() {
    if let Err(e) = rustix::process::kill_process(rustix::process::Pid::INIT, rustix::process::Signal::TERM) {
        log::error!("package: cannot ask init to reboot: {e}");
    }
}

#[cfg(not(target_os = "linux"))]
fn reboot_image() {}
