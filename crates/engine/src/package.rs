//! System › Packages (G1.6b): the A/B image's state as the daemon's
//! `package` service last read it, and the one job it is asked to run.
//!
//! Writing a slot takes seconds of disk I/O: the commands only queue a job
//! (one at a time, "busy" otherwise) and the service runs it with the
//! session lock released, feeding progress and the result back here. The
//! engine never touches a disk or a boot variable itself (it also runs in
//! the browser).

use serde_json::{Value, json};

use crate::Session;

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
        }
    }

    /// Does it end in a reboot into a trial slot?
    pub fn arms_trial(&self) -> bool {
        matches!(
            self,
            JobKind::Update { .. } | JobKind::Downgrade { .. } | JobKind::BootParams { .. }
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
    /// Interfaces running with an address now ("management reachable"
    /// after the reboot means these run again).
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
