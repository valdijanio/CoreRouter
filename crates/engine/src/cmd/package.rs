//! /system package (G1.6b): the A/B image. Like RouterOS `/system package
//! update`, an update installs and reboots; unlike it, the new image boots
//! once on trial (UEFI `BootNext`) and becomes the default only when it is
//! confirmed — by the daemon once it is up and the management interfaces
//! run again (`confirm=auto`), or by an operator (`confirm=manual`, like
//! Junos `commit confirmed`). Without confirmation in `timeout` seconds,
//! init reboots and the firmware boots the previous slot, with the
//! configuration it had. The work runs on the daemon's `package` service:
//! these commands queue it (`system.package.print` shows the progress).

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_u32, req_str};
use super::{CommandSpec, always};
use crate::package::{Job, JobKind, Packages, status};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "system.package.print", "Packages", ["System", "Packages"], None,
        "{} → {supported, reason?, lab, running, primary, fallback, slots: [{slot, state, running, primary, next, version, build, commit, channel, kernel, verified, verity, signed_by, boot_entry, cmdline, size, rootfs_size, kernel_size}], trial: {slot, from, version, reason, confirm, timeout_s, remaining_s?} | null, last, snapshots, keys, job: {id, kind, phase, done, total} | null, result}",
        always, print),
    cmd!(
        "system.package.update",
        "Install and Reboot",
        [],
        None,
        "{path: string (package file on the router), confirm?: auto|manual, timeout?: u32 (30..3600 s, default 300), reboot?: bool (default yes)} → {job, kind}",
        always,
        update
    ),
    cmd!(
        "system.package.downgrade",
        "Downgrade",
        [],
        None,
        "{path?: string (older package; without it the other slot boots), confirm?: auto|manual, timeout?: u32 (30..3600 s), reboot?: bool} → {job, kind}",
        always,
        downgrade
    ),
    cmd!(
        "system.package.confirm",
        "Confirm Update",
        [],
        None,
        "{} → {job, kind}",
        always,
        confirm
    ),
    cmd!(
        "system.package.cancel",
        "Cancel Update",
        [],
        None,
        "{} → {job, kind}",
        always,
        cancel
    ),
    cmd!(
        "system.package.check",
        "Check Package",
        [],
        None,
        "{path: string} → {job, kind}",
        always,
        check
    ),
    cmd!(
        "system.package.scrub",
        "Scrub Slot",
        [],
        None,
        "{slot: a|b} → {job, kind}",
        always,
        scrub
    ),
];

pub const TIMEOUT_DEFAULT: u64 = 300;
const TIMEOUT_MIN: u32 = 30;
const TIMEOUT_MAX: u32 = 3600;
const MAX_PATH: usize = 4096;

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let mut v = status(s);
    let now = s.hal_mut().now_unix();
    if let (Some(trial), Some(now)) = (v.get_mut("trial").and_then(Value::as_object_mut), now)
        && let Some(deadline) = trial.get("deadline_unix").and_then(Value::as_u64)
    {
        trial.insert("remaining_s".into(), json!(deadline.saturating_sub(now)));
    }
    let p = s.ext::<Packages>();
    let job = p.and_then(|p| {
        p.running
            .as_ref()
            .map(|(id, kind, phase, done, total)| {
                json!({"id": id, "kind": kind, "phase": phase, "done": done, "total": total})
            })
            .or_else(|| {
                p.queued
                    .as_ref()
                    .map(|j| json!({"id": j.id, "kind": j.kind.name(), "phase": "queued", "done": 0, "total": 0}))
            })
    });
    let result = p.and_then(|p| p.result.clone());
    if let Some(o) = v.as_object_mut() {
        o.insert("job".into(), job.unwrap_or(Value::Null));
        o.insert("result".into(), result.unwrap_or(Value::Null));
    }
    Ok(v)
}

fn path(p: &Value, key: &str) -> Result<Option<String>> {
    let Some(raw) = opt_str(p, key)? else {
        return Ok(None);
    };
    let clip: String = raw.chars().take(64).collect();
    if raw.len() > MAX_PATH || !raw.starts_with('/') || raw.contains('\0') {
        return Err(EngineError::bad(
            key,
            format!("'{clip}' is not an absolute path on the router"),
        ));
    }
    if raw.split('/').any(|c| c == "..") {
        return Err(EngineError::bad(key, format!("'{clip}': no '..' in the path")));
    }
    Ok(Some(raw.to_owned()))
}

fn confirm_mode(p: &Value) -> Result<String> {
    match opt_str(p, "confirm")? {
        None | Some("auto") => Ok("auto".into()),
        Some("manual") => Ok("manual".into()),
        Some(_) => Err(EngineError::bad("confirm", "must be auto or manual")),
    }
}

fn timeout(p: &Value) -> Result<u64> {
    match opt_u32(p, "timeout")? {
        None => Ok(TIMEOUT_DEFAULT),
        Some(t) if (TIMEOUT_MIN..=TIMEOUT_MAX).contains(&t) => Ok(u64::from(t)),
        Some(t) => Err(EngineError::bad(
            "timeout",
            format!("{t} s: between {TIMEOUT_MIN} and {TIMEOUT_MAX} seconds"),
        )),
    }
}

/// Interfaces running now and carrying an enabled address.
fn mgmt(s: &mut Session) -> Vec<String> {
    let live = s.hal_mut().poll();
    let with_addr: BTreeSet<String> = s
        .store()
        .running()
        .ip
        .addresses
        .iter()
        .filter(|a| !a.disabled)
        .map(|a| a.interface.to_string())
        .collect();
    live.iter()
        .filter(|l| l.running && with_addr.contains(&l.name.to_string()))
        .map(|l| l.name.to_string())
        .collect()
}

/// Not now: another job, a pending trial (the command is fine, the moment
/// is not).
fn conflict(reason: impl Into<String>) -> EngineError {
    EngineError::Disabled {
        id: "system.package".into(),
        reason: reason.into(),
    }
}

fn supported(s: &Session) -> Result<()> {
    let st = status(s);
    if st.get("supported").and_then(Value::as_bool) == Some(true) {
        return Ok(());
    }
    let why = st
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("A/B updates are not available here");
    Err(EngineError::bad("path", why.to_owned()))
}

/// Queues `kind`; the slot-changing jobs need the A/B image and no other
/// job nor trial in the way.
pub(crate) fn queue(s: &mut Session, kind: JobKind, p: &Value) -> Result<Value> {
    supported(s)?;
    let confirm = confirm_mode(p)?;
    let timeout_s = timeout(p)?;
    let reboot = opt_bool(p, "reboot")?.unwrap_or(true);
    if let Some(busy) = s.ext::<Packages>().and_then(Packages::busy) {
        return Err(conflict(format!("busy: {busy}")));
    }
    if kind.arms_trial()
        && let Some(t) = status(s).get("trial").filter(|t| !t.is_null())
    {
        return Err(conflict(format!(
            "a trial boot of slot {} is pending: confirm or cancel it first",
            t.get("slot").and_then(Value::as_str).unwrap_or("?")
        )));
    }
    let mgmt = if kind.arms_trial() { mgmt(s) } else { Vec::new() };
    let tuning: Vec<(String, String)> = s
        .store()
        .running()
        .system
        .tuning
        .boot
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let p = s
        .ext_mut::<Packages>()
        .ok_or_else(|| EngineError::Internal("package state".into()))?;
    p.next_id += 1;
    let id = p.next_id;
    let name = kind.name();
    p.queued = Some(Job {
        id,
        kind,
        confirm,
        timeout_s,
        reboot,
        mgmt,
        tuning,
        config_format: corerouter_model::FORMAT_VERSION,
    });
    Ok(json!({"job": id, "kind": name}))
}

fn update(s: &mut Session, p: &Value) -> Result<Value> {
    let path = path(p, "path")?.ok_or_else(|| EngineError::bad("path", "required"))?;
    queue(s, JobKind::Update { path }, p)
}

fn downgrade(s: &mut Session, p: &Value) -> Result<Value> {
    let path = path(p, "path")?;
    queue(s, JobKind::Downgrade { path }, p)
}

fn confirm(s: &mut Session, p: &Value) -> Result<Value> {
    let st = status(s);
    let trial = st.get("trial").filter(|t| !t.is_null()).ok_or_else(|| {
        conflict("no trial boot to confirm")
    })?;
    if trial.get("slot") != st.get("running") {
        return Err(conflict(
            "the trial slot has not booted yet: confirm after the reboot (or cancel)",
        ));
    }
    queue(s, JobKind::Confirm, p)
}

fn cancel(s: &mut Session, p: &Value) -> Result<Value> {
    queue(s, JobKind::Cancel, p)
}

fn check(s: &mut Session, p: &Value) -> Result<Value> {
    let path = path(p, "path")?.ok_or_else(|| EngineError::bad("path", "required"))?;
    queue(s, JobKind::Check { path }, p)
}

fn scrub(s: &mut Session, p: &Value) -> Result<Value> {
    let slot = req_str(p, "slot")?;
    if !matches!(slot, "a" | "b") {
        return Err(EngineError::bad("slot", "must be a or b"));
    }
    queue(s, JobKind::Scrub { slot: slot.into() }, p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::{feed_status, finish, take_job};

    fn ab(s: &mut Session) {
        feed_status(
            s,
            json!({"supported": true, "running": "a", "trial": null, "slots": []}),
        );
    }

    #[test]
    fn update_queues_one_job() {
        let mut s = Session::virtual_lab();
        // No service: refused with the reason.
        let e = s
            .execute("system.package.update", &json!({"path": "/tmp/x.crpkg"}))
            .unwrap_err();
        assert!(e.to_string().contains("not reported"), "{e}");
        ab(&mut s);
        let out = s
            .execute(
                "system.package.update",
                &json!({"path": "/tmp/x.crpkg", "timeout": 60, "confirm": "manual"}),
            )
            .unwrap();
        assert_eq!(out["kind"], "update");
        let busy = s
            .execute("system.package.check", &json!({"path": "/tmp/y"}))
            .unwrap_err();
        assert!(busy.to_string().contains("busy"), "{busy}");
        let v = s.execute("system.package.print", &json!({})).unwrap();
        assert_eq!(v["job"]["phase"], "queued");
        let job = take_job(&mut s).unwrap();
        assert_eq!(job.kind, JobKind::Update { path: "/tmp/x.crpkg".into() });
        assert_eq!((job.timeout_s, job.confirm.as_str(), job.reboot), (60, "manual", true));
        finish(&mut s, job.id, "update", Err("bad signature".into()));
        let v = s.execute("system.package.print", &json!({})).unwrap();
        assert_eq!(v["result"]["error"], "bad signature");
        assert_eq!(v["job"], Value::Null);
    }

    #[test]
    fn validation() {
        let mut s = Session::virtual_lab();
        ab(&mut s);
        let mut err = |id: &str, p: Value| s.execute(id, &p).unwrap_err().to_string();
        assert!(err("system.package.update", json!({"path": "x.crpkg"})).contains("absolute"));
        assert!(err("system.package.update", json!({"path": "/a/../etc/shadow"})).contains(".."));
        assert!(err("system.package.update", json!({"path": "/x", "timeout": 5})).contains("between"));
        assert!(err("system.package.update", json!({"path": "/x", "confirm": "later"})).contains("auto or manual"));
        assert!(err("system.package.scrub", json!({"slot": "c"})).contains("a or b"));
        assert!(err("system.package.confirm", json!({})).contains("no trial"));
        assert!(err("system.package.update", json!({"path": "/x", "bogus": 1})).contains("bogus"));
    }

    #[test]
    fn trial_blocks_a_second_update_and_confirm_needs_the_reboot() {
        let mut s = Session::virtual_lab();
        feed_status(
            &mut s,
            json!({"supported": true, "running": "a", "trial": {"slot": "b"}}),
        );
        let e = s
            .execute("system.package.downgrade", &json!({}))
            .unwrap_err();
        assert!(e.to_string().contains("pending"), "{e}");
        assert!(s.execute("system.package.confirm", &json!({})).unwrap_err().to_string().contains("not booted"));
        // Cancel is allowed (it is what clears the armed trial).
        assert_eq!(s.execute("system.package.cancel", &json!({})).unwrap()["kind"], "cancel");
        take_job(&mut s);
        feed_status(
            &mut s,
            json!({"supported": true, "running": "b", "trial": {"slot": "b", "deadline_unix": u64::MAX}}),
        );
        finish(&mut s, 1, "cancel", Ok(json!({})));
        assert_eq!(s.execute("system.package.confirm", &json!({})).unwrap()["kind"], "confirm");
        // The journal recorded who asked; the configuration did not change.
        let rev = s.store().current_revision();
        assert_eq!(s.store().current_revision(), rev);
    }
}
