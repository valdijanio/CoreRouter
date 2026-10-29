//! /system package (G1.6b): the A/B image. Like RouterOS `/system package
//! update`, an update installs and reboots; unlike it, the new image boots
//! once on trial (UEFI `BootNext`) and becomes the default only when it is
//! confirmed — by the daemon once it is up and the management interfaces
//! run again (`confirm=auto`), or by an operator (`confirm=manual`, like
//! Junos `commit confirmed`). Without confirmation in `timeout` seconds,
//! init reboots and the firmware boots the previous slot, with the
//! configuration it had. The work runs on the daemon's `package` service:
//! these commands queue it (`system.package.print` shows the progress).
//!
//! G1.6e: `system.package.upload.*` sends the package over the control
//! channel instead of naming a file on the router: `start` declares its
//! size and queues the job, `chunk` carries it in order (base64, ≤ 4 MiB
//! each), and the service writes it to the inactive slot as it arrives
//! (signature checked before the first byte is written, hashes and the
//! verity tree before the slot is activated). `abort` stops it; a client
//! that disappears is dropped after 60 s without a chunk.

use std::collections::BTreeSet;

use base64::Engine as _;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_u32, req_str};
use super::{CommandSpec, always};
use crate::package::{Job, JobKind, Packages, Pushed, UPLOAD_CHUNK, Upload, push_chunk, status};
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
        "system.package.upload.start",
        "Upload Package",
        [],
        None,
        "{size: u64 (bytes of the .crpkg), check?: bool (only check it, default no), downgrade?: bool (an older package), confirm?: auto|manual, timeout?: u32 (30..3600 s, default 300), reboot?: bool (default yes)} → {job, kind, upload, chunk}",
        always,
        upload_start
    ),
    cmd!(query "system.package.upload.chunk", "Upload Chunk", [], None,
        "{upload: u64 (the job from upload.start), offset: u64 (bytes sent before this chunk), data: string (base64, ≤ 4 MiB decoded)} → {received, size, busy}",
        always, upload_chunk),
    cmd!(
        "system.package.upload.abort",
        "Abort Upload",
        [],
        None,
        "{upload?: u64} → {job, aborted}",
        always,
        upload_abort
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
/// The largest package the format allows (kernel 128 MiB, rootfs 4 GiB,
/// header): the slot's own size is checked by the service.
pub const MAX_UPLOAD: u64 = (4 << 30) + (128 << 20) + (1 << 20);
/// Largest chunk the engine takes (decoded): 4 MiB is a 5.6 MB line, well
/// under the control channel's 16 MiB.
pub const MAX_CHUNK: usize = 4 * UPLOAD_CHUNK;

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

fn req_u64(p: &Value, key: &str) -> Result<u64> {
    opt_u64(p, key)?.ok_or_else(|| EngineError::bad(key, "is required"))
}

fn opt_u64(p: &Value, key: &str) -> Result<Option<u64>> {
    match p.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| EngineError::bad(key, "must be a non-negative integer")),
    }
}

fn upload_start(s: &mut Session, p: &Value) -> Result<Value> {
    let size = req_u64(p, "size")?;
    if size == 0 || size > MAX_UPLOAD {
        return Err(EngineError::bad(
            "size",
            format!("{size} bytes: a package is 1..={MAX_UPLOAD} bytes"),
        ));
    }
    let check = opt_bool(p, "check")?.unwrap_or(false);
    let downgrade = opt_bool(p, "downgrade")?.unwrap_or(false);
    let kind = JobKind::Upload {
        size,
        downgrade,
        check,
    };
    let mut out = queue(s, kind, p)?;
    let job = out.get("job").and_then(Value::as_u64).unwrap_or(0);
    let pk = s
        .ext_mut::<Packages>()
        .ok_or_else(|| EngineError::Internal("package state".into()))?;
    pk.upload = Some(Upload::new(job, size));
    if let Some(o) = out.as_object_mut() {
        o.insert("upload".into(), json!(job));
        o.insert("chunk".into(), json!(UPLOAD_CHUNK));
    }
    Ok(out)
}

fn upload_chunk(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_u64(p, "upload")?;
    let offset = req_u64(p, "offset")?;
    let text = req_str(p, "data")?;
    if text.len() > MAX_CHUNK.div_ceil(3) * 4 {
        return Err(EngineError::bad(
            "data",
            format!("{} characters: a chunk is at most {MAX_CHUNK} bytes", text.len()),
        ));
    }
    let up = s
        .ext_mut::<Packages>()
        .and_then(|pk| pk.upload.as_mut())
        .filter(|u| u.job == id)
        .ok_or_else(|| conflict(format!("no upload {id} in progress (finished, aborted or never started)")))?;
    if offset != up.received {
        return Err(EngineError::bad(
            "offset",
            format!("{offset}: upload {id} has received {} bytes; send from there", up.received),
        ));
    }
    let data = base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|e| EngineError::bad("data", format!("not base64: {e}")))?;
    if data.is_empty() || up.received + data.len() as u64 > up.size {
        return Err(EngineError::bad(
            "data",
            format!(
                "{} bytes at {offset}: the upload declared {} bytes",
                data.len(),
                up.size
            ),
        ));
    }
    let pushed = push_chunk(up, data).map_err(conflict)?;
    Ok(json!({"received": up.received, "size": up.size, "busy": pushed == Pushed::Busy}))
}

fn upload_abort(s: &mut Session, p: &Value) -> Result<Value> {
    let want = opt_u64(p, "upload")?;
    let pk = s
        .ext_mut::<Packages>()
        .ok_or_else(|| EngineError::Internal("package state".into()))?;
    let up = pk
        .upload
        .take_if(|u| want.is_none_or(|w| w == u.job))
        .ok_or_else(|| conflict("no upload in progress"))?;
    // Not taken yet: the job goes with it. Taken: the service sees the
    // stream end early and fails the job ("upload aborted").
    if pk.queued.as_ref().is_some_and(|j| j.id == up.job) {
        let kind = pk.queued.take().map_or("upload", |j| j.kind.name());
        crate::package::finish(s, up.job, kind, Err("upload aborted".into()));
    }
    Ok(json!({"job": up.job, "aborted": true}))
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

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    #[test]
    fn upload_streams_chunks_in_order_through_a_bounded_queue() {
        let mut s = Session::virtual_lab();
        ab(&mut s);
        let out = s
            .execute("system.package.upload.start", &json!({"size": 14, "confirm": "manual"}))
            .unwrap();
        let id = out["upload"].as_u64().unwrap();
        assert_eq!(out["kind"], "upload");
        // Another job meanwhile: busy.
        assert!(s.execute("system.package.check", &json!({"path": "/x"})).unwrap_err().to_string().contains("busy"));
        let chunk = |s: &mut Session, off: u64, data: &[u8]| {
            s.execute("system.package.upload.chunk", &json!({"upload": id, "offset": off, "data": b64(data)}))
        };
        let r = chunk(&mut s, 0, b"abcd").unwrap();
        assert_eq!((r["received"].as_u64(), r["busy"].as_bool()), (Some(4), Some(false)));
        // Out of order, past the declared size, other upload, not base64.
        assert!(chunk(&mut s, 0, b"x").unwrap_err().to_string().contains("received 4"));
        assert!(chunk(&mut s, 4, b"0123456789a").unwrap_err().to_string().contains("declared 14"));
        let e = s.execute("system.package.upload.chunk", &json!({"upload": id + 1, "offset": 4, "data": "AA=="})).unwrap_err();
        assert!(e.to_string().contains("no upload"), "{e}");
        let e = s.execute("system.package.upload.chunk", &json!({"upload": id, "offset": 4, "data": "!!"})).unwrap_err();
        assert!(e.to_string().contains("base64"), "{e}");
        // The service takes the job and its stream.
        let job = take_job(&mut s).unwrap();
        assert_eq!(job.kind, JobKind::Upload { size: 14, downgrade: false, check: false });
        assert!(job.kind.arms_trial());
        let rx = crate::package::take_upload(&mut s, job.id).unwrap();
        // Queue full: the same chunk comes back busy, nothing is lost.
        for i in 1..crate::package::UPLOAD_QUEUE as u64 {
            chunk(&mut s, 4 + (i - 1), b"e").unwrap();
        }
        let off = 4 + crate::package::UPLOAD_QUEUE as u64 - 1;
        let r = chunk(&mut s, off, b"f").unwrap();
        assert_eq!(r["busy"], true);
        assert_eq!(r["received"].as_u64(), Some(off));
        let got: Vec<Vec<u8>> = rx.try_iter().collect();
        assert_eq!(got.len(), crate::package::UPLOAD_QUEUE);
        assert_eq!(got[0], b"abcd");
        chunk(&mut s, off, b"f").unwrap();
        // The last bytes end the stream.
        let r = chunk(&mut s, off + 1, b"gh").unwrap();
        assert_eq!(r["received"].as_u64(), Some(14));
        assert_eq!(rx.try_iter().count(), 2);
        assert!(rx.recv().is_err(), "sender dropped: end of stream");
        finish(&mut s, job.id, "upload", Ok(json!({"slot": "b"})));
        assert!(chunk(&mut s, 14, b"h").unwrap_err().to_string().contains("no upload"));
    }

    #[test]
    fn upload_validation_and_abort() {
        let mut s = Session::virtual_lab();
        // Off the image: refused with the reason, nothing queued.
        let e = s.execute("system.package.upload.start", &json!({"size": 10})).unwrap_err();
        assert!(e.to_string().contains("not reported"), "{e}");
        ab(&mut s);
        let mut err = |p: Value| s.execute("system.package.upload.start", &p).unwrap_err().to_string();
        assert!(err(json!({"size": 0})).contains("1..="));
        assert!(err(json!({"size": MAX_UPLOAD + 1})).contains("1..="));
        assert!(err(json!({"size": -1})).contains("non-negative"));
        assert!(err(json!({})).contains("required"));
        assert!(err(json!({"size": 5, "timeout": 1})).contains("between"));
        // Abort before the service took it: the job goes too.
        let id = s.execute("system.package.upload.start", &json!({"size": 5, "check": true})).unwrap()["upload"]
            .as_u64()
            .unwrap();
        assert_eq!(s.execute("system.package.upload.abort", &json!({})).unwrap()["job"].as_u64(), Some(id));
        assert!(take_job(&mut s).is_none());
        let v = s.execute("system.package.print", &json!({})).unwrap();
        assert_eq!(v["result"]["error"], "upload aborted");
        assert!(s.execute("system.package.upload.abort", &json!({})).unwrap_err().to_string().contains("no upload"));
        // Abort while the service reads: its stream ends early.
        let id = s.execute("system.package.upload.start", &json!({"size": 5})).unwrap()["upload"].as_u64().unwrap();
        let job = take_job(&mut s).unwrap();
        let rx = crate::package::take_upload(&mut s, job.id).unwrap();
        s.execute("system.package.upload.abort", &json!({"upload": id})).unwrap();
        assert!(rx.recv().is_err());
        // A chunk too large is refused before decoding.
        let big = "A".repeat(MAX_CHUNK / 3 * 4 + 8);
        let e = s.execute("system.package.upload.chunk", &json!({"upload": id, "offset": 0, "data": big})).unwrap_err();
        assert!(e.to_string().contains("at most"), "{e}");
    }
}
