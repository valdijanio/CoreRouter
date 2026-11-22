//! System › Packages (G1.6b): the A/B image's state as the daemon's
//! `package` service last read it, and the one job it is asked to run.
//!
//! Writing a slot takes seconds of disk I/O: the commands only queue a job
//! (one at a time, "busy" otherwise) and the service runs it with the
//! session lock released, feeding progress and the result back here. The
//! engine never touches a disk or a boot variable itself (it also runs in
//! the browser).
//!
//! A package sent over the control channel (G1.6e) is a job too: its
//! chunks go into a bounded queue ([`UPLOAD_QUEUE`] chunks) that the service
//! reads as a stream and writes to the inactive slot as they arrive. A full
//! queue answers `busy` (the client resends); nothing waits under the lock.

use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};

use serde_json::{Value, json};

use crate::Session;

/// Chunks in flight between the control channel and the slot write: with
/// [`UPLOAD_CHUNK`], at most 8 MiB of a package is in RAM at a time.
pub const UPLOAD_QUEUE: usize = 8;
/// Largest chunk (decoded); the client's default.
pub const UPLOAD_CHUNK: usize = 1 << 20;

/// What the service is asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobKind {
    /// Install the package at `path` into the inactive slot.
    Update { path: String },
    /// Install an older package, or (no `path`) boot the other slot.
    Downgrade { path: Option<String> },
    /// Tuning › Boot (G1.26h): the running image on the inactive slot with
    /// the configured parameters; `drill`: a parameter that does not boot.
    BootParams { drill: bool },
    Confirm,
    Cancel,
    /// Read a package and check its signature, without installing it.
    Check { path: String },
    /// Re-read slot `slot` and check it against its signed root hash.
    Scrub { slot: String },
    /// A package of `size` bytes sent over the control channel: installed
    /// (`downgrade`: an older one), or only checked (`check`).
    Upload {
        size: u64,
        downgrade: bool,
        check: bool,
    },
    /// A package the router fetches itself over HTTP(S) (G1.6e, like
    /// RouterOS `/system package update install`): streamed to the slot.
    /// Remove these configuration snapshots (G1.6u; the command picked
    /// them, the service checks the trial again).
    SnapshotRemove { names: Vec<String> },
    Download {
        url: String,
        /// Check the server's certificate (`ssl-verify`); the package is
        /// signed either way.
        verify: bool,
        downgrade: bool,
        check: bool,
    },
}

impl JobKind {
    pub fn name(&self) -> &'static str {
        match self {
            JobKind::Update { .. } => "update",
            JobKind::Downgrade { .. } => "downgrade",
            JobKind::BootParams { .. } => "boot-params",
            JobKind::Confirm => "confirm",
            JobKind::Cancel => "cancel",
            JobKind::Check { .. } => "check",
            JobKind::Scrub { .. } => "scrub",
            JobKind::Upload { check: true, .. } => "upload-check",
            JobKind::Upload { .. } => "upload",
            JobKind::Download { check: true, .. } => "download-check",
            JobKind::Download { .. } => "download",
            JobKind::SnapshotRemove { .. } => "snapshot-remove",
        }
    }

    /// Does it end in a reboot into a trial slot?
    /// Installs another image (or boots the other slot): the jobs that
    /// save an automatic checkpoint first (G0.33b).
    pub fn replaces_image(&self) -> bool {
        matches!(
            self,
            JobKind::Update { .. }
                | JobKind::Downgrade { .. }
                | JobKind::Upload { check: false, .. }
                | JobKind::Download { check: false, .. }
        )
    }

    /// The command that queued it, for the checkpoint's comment.
    pub fn describe(&self) -> String {
        match self {
            JobKind::Update { path } => format!("system.package.update {path}"),
            JobKind::Downgrade { path: Some(path) } => format!("system.package.downgrade {path}"),
            JobKind::Downgrade { path: None } => "system.package.downgrade".to_owned(),
            JobKind::Upload { downgrade: true, .. } => "system.package.upload (downgrade)".to_owned(),
            JobKind::Upload { .. } => "system.package.upload".to_owned(),
            JobKind::Download { url, .. } => {
                // A user:password@ in the URL stays out of the comment.
                let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
                let host = rest.split('/').next().unwrap_or("");
                let rest = match host.rsplit_once('@') {
                    Some((_, after)) => rest.replacen(host, after, 1),
                    None => rest.to_owned(),
                };
                let url: String = format!("{scheme}://{rest}").chars().take(200).collect();
                format!("system.package.download {url}")
            }
            other => format!("system.package {}", other.name()),
        }
    }

    pub fn arms_trial(&self) -> bool {
        matches!(
            self,
            JobKind::Update { .. }
                | JobKind::Downgrade { .. }
                | JobKind::BootParams { .. }
                | JobKind::Upload { check: false, .. }
                | JobKind::Download { check: false, .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub id: u64,
    pub kind: JobKind,
    /// `auto` or `manual`.
    pub confirm: String,
    pub timeout_s: u64,
    pub reboot: bool,
    /// [`reachable_ports`] when the job was queued ("management reachable"
    /// after the reboot means each of these runs with an address again).
    pub mgmt: Vec<String>,
    /// `system.tuning.boot` of the running configuration.
    pub tuning: Vec<(String, String)>,
    /// `format_version` of the configuration this build writes.
    pub config_format: u32,
}

/// Runtime state (`s.ext::<Packages>()`), never saved.
#[derive(Debug, Default)]
pub struct Packages {
    /// The last status the service read (`supported: false` and a
    /// `reason` off the image).
    pub status: Option<Value>,
    pub queued: Option<Job>,
    /// The job being run: id, kind, phase, bytes done and total.
    pub running: Option<(u64, &'static str, String, u64, u64)>,
    /// The last job's outcome: `{id, kind, ok, result | error}`.
    pub result: Option<Value>,
    pub next_id: u64,
    /// The upload in progress (G1.6e).
    pub upload: Option<Upload>,
}

/// An upload's receiving end in the engine: the chunks go to `tx`, the
/// service reads the other end (taken with [`take_upload`]).
#[derive(Debug)]
pub struct Upload {
    /// The job it belongs to (the client names it in every chunk).
    pub job: u64,
    pub size: u64,
    pub received: u64,
    /// `None` once every byte was handed over (end of stream).
    pub tx: Option<SyncSender<Vec<u8>>>,
    /// Until the service takes it.
    pub rx: Option<Receiver<Vec<u8>>>,
}

/// What [`push_chunk`] did with a chunk.
#[derive(Debug, PartialEq, Eq)]
pub enum Pushed {
    Queued,
    /// The queue is full (the disk is behind): send the same chunk again.
    Busy,
}

impl Upload {
    pub fn new(job: u64, size: u64) -> Upload {
        let (tx, rx) = sync_channel(UPLOAD_QUEUE);
        Upload {
            job,
            size,
            received: 0,
            tx: Some(tx),
            rx: Some(rx),
        }
    }
}

/// Hands one chunk to the service. `Err`: the upload is over (the service
/// stopped reading: the job failed or was aborted).
pub fn push_chunk(up: &mut Upload, data: Vec<u8>) -> Result<Pushed, String> {
    let n = data.len() as u64;
    let tx = up.tx.as_ref().ok_or("every byte was already received")?;
    match tx.try_send(data) {
        Ok(()) => {
            up.received += n;
            if up.received >= up.size {
                up.tx = None; // end of stream
            }
            Ok(Pushed::Queued)
        }
        Err(TrySendError::Full(_)) => Ok(Pushed::Busy),
        Err(TrySendError::Disconnected(_)) => {
            up.tx = None;
            Err("the package service stopped reading this upload".into())
        }
    }
}

/// The service takes the upload's stream with its job.
pub fn take_upload(s: &mut Session, job: u64) -> Option<Receiver<Vec<u8>>> {
    let p = s.ext_mut::<Packages>()?;
    p.upload.as_mut().filter(|u| u.job == job)?.rx.take()
}

impl Packages {
    pub fn busy(&self) -> Option<String> {
        if let Some(j) = &self.queued {
            return Some(format!("job {} ({}) is queued", j.id, j.kind.name()));
        }
        self.running
            .as_ref()
            .map(|(id, kind, phase, ..)| format!("job {id} ({kind}) is running: {phase}"))
    }
}

/// The service takes the queued job (O(1) under the session lock).
pub fn take_job(s: &mut Session) -> Option<Job> {
    let p = s.ext_mut::<Packages>()?;
    let job = p.queued.take()?;
    p.running = Some((job.id, job.kind.name(), "starting".into(), 0, 0));
    Some(job)
}

pub fn feed_status(s: &mut Session, status: Value) {
    if let Some(p) = s.ext_mut::<Packages>() {
        p.status = Some(status);
    }
}

pub fn feed_progress(s: &mut Session, phase: &str, done: u64, total: u64) {
    if let Some(p) = s.ext_mut::<Packages>()
        && let Some(r) = p.running.as_mut()
    {
        r.2 = phase.to_owned();
        r.3 = done;
        r.4 = total;
    }
}

pub fn finish(s: &mut Session, id: u64, kind: &str, out: std::result::Result<Value, String>) {
    if let Some(p) = s.ext_mut::<Packages>() {
        p.running = None;
        if p.upload.as_ref().is_some_and(|u| u.job == id) {
            p.upload = None;
        }
        p.result = Some(match out {
            Ok(v) => json!({"id": id, "kind": kind, "ok": true, "result": v}),
            Err(e) => json!({"id": id, "kind": kind, "ok": false, "error": e}),
        });
    }
}

/// The status, or what a session without the service sees (the GUI over a
/// daemon without it, tests).
pub fn status(s: &Session) -> Value {
    s.ext::<Packages>()
        .and_then(|p| p.status.clone())
        .unwrap_or_else(|| {
            json!({"supported": false, "reason": "the package service has not reported (daemon without it, or still starting)"})
        })
}

/// Interfaces running now with an address the operator can reach the router
/// at: a static one, a DHCP lease, a DHCPv6 address or a PPPoE client
/// session (the addresses of [`Session::effective`]).
///
/// The update records them before the reboot and the trial is confirmed
/// automatically only when all of them carry an address again. G1.6ba: it
/// counted only the static addresses, so a router managed over a DHCP lease
/// (the notebook's ether2, dev.701) recorded no port, and a new image that
/// broke the DHCP client was confirmed anyway, the slot kept with the router
/// unreachable. The fallback address of a DHCP client (G4.7c) does not
/// count: it says the lease was not obtained.
pub fn reachable_ports(s: &mut Session) -> Vec<String> {
    let live = s.hal_mut().poll();
    let fallback: Vec<_> = s
        .dhcp
        .runners
        .values()
        .filter_map(|r| r.fallback.as_ref())
        .collect();
    let with_addr: std::collections::BTreeSet<String> = s
        .effective(s.store().running())
        .ip
        .addresses
        .iter()
        .filter(|a| !a.disabled && !fallback.contains(a))
        .map(|a| a.interface.to_string())
        .collect();
    live.iter()
        .filter(|l| l.running && with_addr.contains(&l.name.to_string()))
        .map(|l| l.name.to_string())
        .collect()
}
