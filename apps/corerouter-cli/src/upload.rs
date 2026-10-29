//! `corerouter-cli upload <file.crpkg>` (G1.6e): sends an update package
//! over the control channel (`system.package.upload.*`), shows the
//! progress, and with `--wait` waits for the router to reboot into the new
//! slot and confirm it. Prints how long each step took.

use std::io::Read;
use std::time::{Duration, Instant};

use base64::Engine as _;
use corerouter_mcp::Backend;
use serde_json::{Value, json};

/// How long `--wait` waits for the router to come back and confirm.
const WAIT_LIMIT: Duration = Duration::from_secs(900);
const POLL: Duration = Duration::from_millis(500);

pub struct Opts {
    pub file: String,
    /// `system.package.upload.start` parameters (check, downgrade, confirm,
    /// timeout, reboot).
    pub params: Value,
    pub wait: bool,
}

fn exec(b: &mut dyn Backend, id: &str, params: Value) -> Result<Value, String> {
    b.call(
        "engine.execute",
        json!({"command": id, "params": params, "via": "cli"}),
    )
}

fn mib(n: u64) -> f64 {
    n as f64 / (1u64 << 20) as f64
}

/// The job's outcome once the service finished it, or `None` while it runs.
fn outcome(print: &Value, job: u64) -> Option<Value> {
    let r = print.get("result")?;
    (r.get("id").and_then(Value::as_u64) == Some(job)).then(|| r.clone())
}

pub fn run(b: &mut dyn Backend, o: &Opts) -> Result<Value, String> {
    let t0 = Instant::now();
    let mut f = std::fs::File::open(&o.file).map_err(|e| format!("{}: {e}", o.file))?;
    let size = f.metadata().map_err(|e| format!("{}: {e}", o.file))?.len();
    let mut start = o.params.clone();
    if let Some(m) = start.as_object_mut() {
        m.insert("size".into(), json!(size));
    } else {
        start = json!({"size": size});
    }
    let check = start.get("check").and_then(Value::as_bool) == Some(true);
    let reboot = start.get("reboot").and_then(Value::as_bool) != Some(false);
    let before = exec(b, "system.package.print", json!({}))?;
    let started = exec(b, "system.package.upload.start", start)?;
    let job = started
        .get("upload")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("upload.start answered without an upload id: {started}"))?;
    let chunk = started
        .get("chunk")
        .and_then(Value::as_u64)
        .unwrap_or(1 << 20)
        .clamp(64 << 10, 4 << 20) as usize;
    eprintln!(
        "upload {job}: {} ({:.1} MiB) in chunks of {} KiB",
        o.file,
        mib(size),
        chunk >> 10
    );

    let mut buf = vec![0u8; chunk];
    let mut sent = 0u64;
    let mut busy = 0u32;
    let mut shown = Instant::now();
    while sent < size {
        let n = (size - sent).min(chunk as u64) as usize;
        let part = buf.get_mut(..n).ok_or("chunk buffer")?;
        f.read_exact(part).map_err(|e| format!("{}: {e}", o.file))?;
        let data = base64::engine::general_purpose::STANDARD.encode(&*part);
        loop {
            let r = exec(
                b,
                "system.package.upload.chunk",
                json!({"upload": job, "offset": sent, "data": data}),
            );
            let r = match r {
                Ok(r) => r,
                Err(e) => {
                    // The service gave up (bad signature, slot too small…):
                    // its reason is in the job result.
                    let why = exec(b, "system.package.print", json!({}))
                        .ok()
                        .and_then(|p| outcome(&p, job))
                        .and_then(|r| r.get("error").and_then(Value::as_str).map(str::to_owned));
                    return Err(why.unwrap_or(e));
                }
            };
            if r.get("busy").and_then(Value::as_bool) == Some(true) {
                busy += 1;
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            break;
        }
        sent += n as u64;
        if shown.elapsed() >= Duration::from_millis(500) || sent == size {
            shown = Instant::now();
            eprintln!("  sent {:.1} / {:.1} MiB", mib(sent), mib(size));
        }
    }
    let t_sent = t0.elapsed();
    // The service finishes writing the last chunks and reads the slot back.
    let result = loop {
        let p = exec(b, "system.package.print", json!({}))?;
        if let Some(r) = outcome(&p, job) {
            break r;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let t_done = t0.elapsed();
    if result.get("ok").and_then(Value::as_bool) != Some(true) {
        let e = result
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("upload failed");
        return Err(format!("upload {job}: {e}"));
    }
    let r = result.get("result").cloned().unwrap_or(Value::Null);
    let secs = t_sent.as_secs_f64().max(0.001);
    eprintln!(
        "sent in {:.2} s ({:.0} MiB/s, {busy} busy retries); {} in {:.2} s",
        secs,
        mib(size) / secs,
        if check {
            "checked"
        } else {
            "written and verified"
        },
        t_done.as_secs_f64()
    );
    let mut times = json!({
        "bytes": size,
        "send_s": round(t_sent),
        "done_s": round(t_done),
        "mib_per_s": (mib(size) / secs * 10.0).round() / 10.0,
        "busy_retries": busy,
    });
    if check || !reboot || !o.wait {
        return Ok(json!({"job": job, "result": r, "times": times}));
    }
    let slot = r
        .get("slot")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_owned();
    eprintln!("rebooting into slot {slot} (trial); waiting for it to come back and confirm…");
    let (back, confirmed, last) = wait(b, &slot, before.get("last"))?;
    if let Some(t) = times.as_object_mut() {
        t.insert("reboot_to_answer_s".into(), json!(round(back)));
        t.insert("reboot_to_confirmed_s".into(), json!(round(confirmed)));
        t.insert("total_s".into(), json!(round(t0.elapsed())));
    }
    eprintln!(
        "back after {:.1} s, slot {slot} confirmed after {:.1} s; {:.1} s in all",
        back.as_secs_f64(),
        confirmed.as_secs_f64(),
        t0.elapsed().as_secs_f64()
    );
    Ok(json!({"job": job, "result": r, "last": last, "times": times}))
}

fn round(d: Duration) -> f64 {
    (d.as_secs_f64() * 100.0).round() / 100.0
}

/// Polls until the router answers again from `slot` and the trial ended:
/// (time to the first answer, time to confirmation, the outcome). A trial
/// that rolls back is an error.
fn wait(
    b: &mut dyn Backend,
    slot: &str,
    last_before: Option<&Value>,
) -> Result<(Duration, Duration, Value), String> {
    let t = Instant::now();
    let mut back = None;
    let mut said = String::new();
    while t.elapsed() < WAIT_LIMIT {
        std::thread::sleep(POLL);
        let p = match exec(b, "system.package.print", json!({})) {
            Ok(p) => p,
            Err(e) => {
                if said != e {
                    log::info!("waiting: {e}");
                    said = e;
                }
                continue;
            }
        };
        let running = p.get("running").and_then(Value::as_str);
        if running == Some(slot) && back.is_none() {
            back = Some(t.elapsed());
            eprintln!(
                "  answering from slot {slot} after {:.1} s",
                t.elapsed().as_secs_f64()
            );
        }
        let trial = p.get("trial").filter(|v| !v.is_null());
        let last = p.get("last").cloned().unwrap_or(Value::Null);
        if trial.is_some() || Some(&last) == last_before {
            continue;
        }
        let result = last.get("result").and_then(Value::as_str).unwrap_or("");
        if result == "confirmed" && last.get("slot").and_then(Value::as_str) == Some(slot) {
            return Ok((back.unwrap_or(t.elapsed()), t.elapsed(), last));
        }
        return Err(format!(
            "slot {slot} was not kept ({result}): {}",
            last.get("detail")
                .and_then(Value::as_str)
                .unwrap_or("see system.package.print")
        ));
    }
    Err(format!(
        "slot {slot}: no confirmation in {} s",
        WAIT_LIMIT.as_secs()
    ))
}
