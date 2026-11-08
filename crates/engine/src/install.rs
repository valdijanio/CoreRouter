//! System › Install to disk (G1.6y): the state between `system.install.*` and
//! the daemon's `install` service, which reads the disks and writes the image
//! outside the session lock. Never saved.
//!
//! What it takes to erase a disk depends on what it holds: an empty disk asks
//! for its name, a disk with data or with a CoreRouter also for a code that
//! only the console shows, or for the power button pressed three times.
//! Someone who reaches the live image over the network with the blank admin
//! password can thus install on an empty disk, never erase data.

use serde_json::{Value, json};

use crate::Session;

/// What a disk holds, as it decides the confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holds {
    Empty,
    Data,
    CoreRouter,
}

impl Holds {
    pub fn as_str(self) -> &'static str {
        match self {
            Holds::Empty => "empty",
            Holds::Data => "data",
            Holds::CoreRouter => "corerouter",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disk {
    pub name: String,
    pub bytes: u64,
    pub model: String,
    pub serial: String,
    pub bus: String,
    pub removable: bool,
    pub holds: Holds,
    /// Its partitions, in words.
    pub detail: String,
    pub config_keepable: bool,
    pub refused: Option<String>,
}

impl Disk {
    fn json(&self) -> Value {
        json!({
            "name": self.name,
            "bytes": self.bytes,
            "model": self.model,
            "serial": self.serial,
            "bus": self.bus,
            "removable": self.removable,
            "holds": self.holds.as_str(),
            "detail": self.detail,
            "config_keepable": self.config_keepable,
            "refused": self.refused,
            "confirm": if self.holds == Holds::Empty { "name" } else { "name+code" },
        })
    }
}

/// The medium the image comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediumInfo {
    pub device: String,
    pub version: String,
    pub commit: String,
    pub channel: String,
    pub signed_by: String,
    pub min_disk: u64,
}

/// How long a code lives and how many wrong ones it takes.
pub const CHALLENGE_SECS: u32 = 300;
pub const CHALLENGE_ATTEMPTS: u32 = 3;
/// Six of these: 31^6 ≈ 887 million, no 0/O, 1/I/L to misread on a console.
const CODE_ALPHABET: &[u8; 31] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
const CODE_LEN: usize = 6;

/// A confirmation waiting for the console or the button.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub disk: String,
    pub serial: String,
    pub code: String,
    pub attempts_left: u32,
    /// The power button was pressed three times: no code needed.
    pub presence: bool,
    pub remaining_s: u32,
    /// Who asked ("tcp 192.0.2.7:50412"), shown on the console.
    pub by: String,
    /// The service already put it on the consoles.
    pub shown: bool,
}

/// The install the service must carry out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub disk: String,
    pub serial: String,
    pub bytes: u64,
    /// What it held when confirmed: the service looks again before writing.
    pub holds: Holds,
    pub keep_config: bool,
    pub by: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    pub disk: String,
    pub phase: &'static str,
    pub done: u64,
    pub total: u64,
}

#[derive(Debug, Default)]
pub struct Install {
    /// `None` without the service (lab, browser), `Err` on an installed system.
    pub support: Option<Result<(), String>>,
    pub medium: Option<MediumInfo>,
    pub disks: Vec<Disk>,
    pub scanned: bool,
    pub rescan: bool,
    pub challenge: Option<Challenge>,
    pub job: Option<Job>,
    pub running: Option<Progress>,
    pub result: Option<Value>,
}

impl Install {
    /// Installing or installed: nothing else may start.
    pub fn busy(&self) -> Option<String> {
        if let Some(r) = &self.running {
            return Some(format!("installing on {}", r.disk));
        }
        if let Some(j) = &self.job {
            return Some(format!("installing on {}", j.disk));
        }
        if self.result.as_ref().and_then(|r| r.get("ok")).and_then(Value::as_bool) == Some(true) {
            return Some("already installed: reboot (system.reboot)".into());
        }
        None
    }

    pub fn status(&self) -> Value {
        let (supported, reason) = match &self.support {
            Some(Ok(())) => (true, None),
            Some(Err(why)) => (false, Some(why.clone())),
            None => (false, Some("no daemon to carry it out (virtual lab)".to_owned())),
        };
        json!({
            "supported": supported,
            "reason": reason,
            "scanned": self.scanned,
            "medium": self.medium.as_ref().map(|m| json!({
                "device": m.device,
                "version": m.version,
                "commit": m.commit,
                "channel": m.channel,
                "signed_by": m.signed_by,
                "min_disk": m.min_disk,
            })),
            "disks": self.disks.iter().map(Disk::json).collect::<Vec<_>>(),
            // Never the code.
            "challenge": self.challenge.as_ref().map(|c| json!({
                "disk": c.disk,
                "serial": c.serial,
                "attempts_left": c.attempts_left,
                "presence": c.presence,
                "remaining_s": c.remaining_s,
            })),
            "job": self.running.as_ref().map(|r| json!({
                "disk": r.disk, "phase": r.phase, "done": r.done, "total": r.total,
            })).or_else(|| self.job.as_ref().map(|j| json!({
                "disk": j.disk, "phase": "queued", "done": 0, "total": 0,
            }))),
            "result": self.result,
        })
    }
}

pub fn set_support(s: &mut Session, support: Result<(), String>) {
    if let Some(i) = s.ext_mut::<Install>() {
        i.support = Some(support);
    }
}

/// A new look at the disks. Disks of an open challenge may go: `run` compares.
pub fn set_scan(s: &mut Session, medium: Option<MediumInfo>, disks: Vec<Disk>) {
    if let Some(i) = s.ext_mut::<Install>() {
        i.medium = medium;
        i.disks = disks;
        i.scanned = true;
    }
}

pub fn take_rescan(s: &mut Session) -> bool {
    s.ext_mut::<Install>().is_some_and(|i| std::mem::take(&mut i.rescan))
}

/// The job to run, now shown as running.
pub fn take_job(s: &mut Session) -> Option<Job> {
    let i = s.ext_mut::<Install>()?;
    let job = i.job.take()?;
    i.running = Some(Progress {
        disk: job.disk.clone(),
        phase: "checking",
        done: 0,
        total: 0,
    });
    Some(job)
}

pub fn set_progress(s: &mut Session, phase: &'static str, done: u64, total: u64) {
    if let Some(r) = s.ext_mut::<Install>().and_then(|i| i.running.as_mut()) {
        r.phase = phase;
        r.done = done;
        r.total = total;
    }
}

/// The install ended; `Err` leaves the live image as it was, to try again.
pub fn finish(s: &mut Session, result: Result<Value, String>) {
    if let Some(i) = s.ext_mut::<Install>() {
        i.running = None;
        i.rescan = true;
        i.result = Some(match result {
            Ok(mut v) => {
                if let Some(o) = v.as_object_mut() {
                    o.insert("ok".into(), Value::Bool(true));
                }
                v
            }
            Err(e) => json!({"ok": false, "error": e}),
        });
    }
}

pub(crate) fn challenge_open(s: &Session) -> bool {
    s.ext::<Install>().is_some_and(|i| i.challenge.is_some())
}

/// A challenge not yet on the consoles; the service shows it once.
pub fn take_announcement(s: &mut Session) -> Option<Challenge> {
    let c = s.ext_mut::<Install>()?.challenge.as_mut()?;
    if c.shown {
        return None;
    }
    c.shown = true;
    Some(c.clone())
}

/// The service's clock: nothing left ends the challenge.
pub fn set_remaining(s: &mut Session, remaining: u32) {
    if let Some(i) = s.ext_mut::<Install>() {
        if remaining == 0 {
            i.challenge = None;
        } else if let Some(c) = i.challenge.as_mut() {
            c.remaining_s = remaining;
        }
    }
}

/// Three presses of the power button.
pub fn set_presence(s: &mut Session) {
    if let Some(c) = s.ext_mut::<Install>().and_then(|i| i.challenge.as_mut()) {
        c.presence = true;
    }
}

pub(crate) fn new_code() -> Result<String, String> {
    let mut raw = [0u8; CODE_LEN];
    crate::auth::random_bytes(&mut raw)?;
    Ok(raw
        .iter()
        .filter_map(|b| CODE_ALPHABET.get(usize::from(*b) % CODE_ALPHABET.len()))
        .map(|&b| char::from(b))
        .collect())
}
