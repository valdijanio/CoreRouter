//! G6.8 DNS Lookup › Watch (`tool.dns.watch`): the same query again and
//! again, like `dnsping` (dnsdiag) — latency over time with the spikes
//! marked, and the answer, flagged when it changes. A task: it runs until
//! Stop (or `count` queries).
//!
//! Events (kind `dns-watch`):
//! - `{kind: "watch", n, at, t_ms, ms?, rcode?, stage?, ttl?, data, changed,
//!   spike, error?, timeout}` per query (`at`: Unix seconds, 3 decimals;
//!   `data` as `compare` compares it, so TTLs and order never count as a
//!   change);
//! - the summary: `{mode: "watch", sent, answered, loss_pct, min_ms, avg_ms,
//!   p50_ms, p95_ms, max_ms, changes, spikes}`.

use std::sync::Arc;
use std::time::Duration;

use corerouter_proto_dns::dig::{self, Ask};
use serde_json::{Value, json};

use crate::dns::DnsBackend;
use crate::dns_lookup::{LookupServer, bytes_for, compared, is_timeout};
use crate::tasks::TaskCtx;
use crate::tools::stats::{Outcome, Stats};

/// Fewest answers before a spike can be told (the median needs a few).
const SPIKE_AFTER: usize = 5;
/// A spike: at least this many times the median so far…
const SPIKE_FACTOR: f64 = 3.0;
/// …and at least this much above it (a 1 ms → 4 ms jump is no spike).
const SPIKE_MIN_MS: f64 = 20.0;

/// A watch, checked.
#[derive(Debug, Clone)]
pub(crate) struct Watch {
    pub ask: Ask,
    pub to: LookupServer,
    pub tcp: bool,
    pub interval: Duration,
    /// 0: until stopped.
    pub count: u64,
    /// Unix seconds when it started (the session's clock; `None`: unknown).
    pub started_unix: Option<u64>,
}

/// Whether `ms` is a spike against the answers so far (`sorted`).
pub(crate) fn is_spike(sorted: &[f64], ms: f64) -> bool {
    if sorted.len() < SPIKE_AFTER {
        return false;
    }
    let median = sorted.get(sorted.len() / 2).copied().unwrap_or(0.0);
    ms >= median * SPIKE_FACTOR && ms >= median + SPIKE_MIN_MS
}

/// Runs `w` (the task's body).
pub(crate) fn run(ctx: &TaskCtx, backend: &Arc<dyn DnsBackend>, w: &Watch) -> Result<(), String> {
    let mut stats = Stats::default();
    // Latencies so far, sorted (the spike's median); bounded like `Stats`.
    let mut sorted: Vec<f64> = Vec::new();
    let mut last: Option<Vec<String>> = None;
    let (mut changes, mut spikes) = (0u64, 0u64);
    let mut n = 0u64;
    ctx.emit(json!({"kind": "begin", "mode": "watch"}));
    let start = ctx.now();
    loop {
        if ctx.stopped() || (w.count > 0 && n >= w.count) {
            break;
        }
        n += 1;
        let t = ctx.now().saturating_sub(start);
        let at = w
            .started_unix
            .map(|u| ((u as f64 + t.as_secs_f64()) * 1000.0).round() / 1000.0);
        let q = bytes_for(&w.ask, &w.to)?;
        stats.sent += 1;
        let got = backend
            .exchange(&w.to, &q, w.tcp)
            .and_then(|x| dig::decode(&x.bytes).map(|r| (r, x)));
        let ev = match got {
            Ok((r, x)) => {
                let ms = x.ms as f64;
                let spike = is_spike(&sorted, ms);
                stats.record(Outcome::Ok, Some(ms));
                let pos = sorted.partition_point(|v| *v < ms);
                sorted.insert(pos, ms);
                if sorted.len() > 4096 {
                    // Keep the middle: drop one from each end.
                    sorted.remove(0);
                    sorted.pop();
                }
                let data = compared(&r);
                let changed = last.as_ref().is_some_and(|l| *l != data);
                last = Some(data.clone());
                changes += u64::from(changed);
                spikes += u64::from(spike);
                let ttl = r.answer.iter().map(|x| x.ttl).min();
                json!({"kind": "watch", "n": n, "at": at, "t_ms": t.as_millis() as u64,
                    "ms": x.ms, "rcode": r.status, "stage": x.stage, "ttl": ttl, "data": data,
                    "changed": changed, "spike": spike, "timeout": false})
            }
            Err(e) => {
                let e: String = e.chars().take(300).collect();
                let timeout = is_timeout(&e);
                stats.record(if timeout { Outcome::Timeout } else { Outcome::Error }, None);
                json!({"kind": "watch", "n": n, "at": at, "t_ms": t.as_millis() as u64,
                    "ms": null, "rcode": null, "data": [], "changed": false, "spike": false,
                    "error": e, "timeout": timeout})
            }
        };
        ctx.emit(ev);
        ctx.summary(summary(&stats, changes, spikes));
        let next = w.interval.saturating_mul(u32::try_from(n).unwrap_or(u32::MAX));
        let wait = next.saturating_sub(ctx.now().saturating_sub(start));
        if !ctx.sleep(wait) {
            break;
        }
    }
    ctx.summary(summary(&stats, changes, spikes));
    Ok(())
}

fn summary(stats: &Stats, changes: u64, spikes: u64) -> Value {
    let s = stats.to_json();
    let pick = |k: &str| s.get(k).cloned().unwrap_or(Value::Null);
    json!({"mode": "watch", "sent": stats.sent, "answered": stats.received,
        "loss_pct": pick("loss_pct"), "min_ms": pick("min_ms"), "avg_ms": pick("avg_ms"),
        "p50_ms": pick("p50_ms"), "p95_ms": pick("p95_ms"), "max_ms": pick("max_ms"),
        "changes": changes, "spikes": spikes})
}

/// `HH:MM:SS` (UTC) of Unix seconds.
fn clock(at: f64) -> String {
    let secs = at.max(0.0) as u64 % 86_400;
    format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Null) | None => String::new(),
        Some(x) => x.to_string(),
    }
}

/// Terminal row of a watch event: `N TIME MS STATUS STAGE TTL ANSWER`.
pub fn text_line(ev: &Value) -> String {
    if ev.get("kind").and_then(Value::as_str) == Some("begin") {
        return header();
    }
    let time = ev.get("at").and_then(Value::as_f64).map_or_else(
        || format!("+{:.1}s", ev.get("t_ms").and_then(Value::as_u64).unwrap_or(0) as f64 / 1000.0),
        clock,
    );
    let ms = ev.get("ms").and_then(Value::as_u64).map_or("-".into(), |m| format!("{m}ms"));
    let status = if ev["timeout"] == true {
        "timeout".to_owned()
    } else if ev.get("error").is_some() {
        "error".to_owned()
    } else {
        s(ev, "rcode")
    };
    let data: Vec<String> = ev
        .get("data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let mut flags = String::new();
    if ev["changed"] == true {
        flags.push_str(" changed");
    }
    if ev["spike"] == true {
        flags.push_str(" spike");
    }
    let answer = match ev.get("error").and_then(Value::as_str) {
        Some(e) => e.to_owned(),
        None => data.join(", "),
    };
    format!(
        "{:>5} {:<8} {:>7} {:<9} {:<9} {:>6}  {}{}",
        s(ev, "n"),
        time,
        ms,
        status,
        s(ev, "stage"),
        s(ev, "ttl"),
        answer,
        flags
    )
    .trim_end()
    .to_owned()
}

/// Column header of the terminal rows.
pub fn header() -> String {
    format!("{:>5} {:<8} {:>7} {:<9} {:<9} {:>6}  ANSWER", "N", "TIME", "MS", "STATUS", "STAGE", "TTL")
}

/// The closing line.
pub fn summary_lines(summary: &Value) -> Vec<String> {
    vec![format!(
        ";; sent={} answered={} loss={}% min/avg/p95/max={}/{}/{}/{} ms changes={} spikes={}",
        s(summary, "sent"),
        s(summary, "answered"),
        s(summary, "loss_pct"),
        s(summary, "min_ms"),
        s(summary, "avg_ms"),
        s(summary, "p95_ms"),
        s(summary, "max_ms"),
        s(summary, "changes"),
        s(summary, "spikes"),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spikes_need_a_median_and_a_real_jump() {
        let v = [10.0, 11.0, 12.0, 12.0, 13.0];
        assert!(!is_spike(&v[..4], 500.0), "too few answers");
        assert!(is_spike(&v, 40.0));
        assert!(!is_spike(&v, 30.0), "under 3x");
        let fast = [1.0, 1.0, 1.0, 1.0, 1.0];
        assert!(!is_spike(&fast, 5.0), "1 ms to 5 ms is no spike");
    }

    #[test]
    fn terminal_rows() {
        let ev = json!({"kind": "watch", "n": 3, "at": 3723.5, "ms": 12, "rcode": "NOERROR",
            "stage": "cache", "ttl": 290, "data": ["A 192.0.2.7"], "changed": true, "spike": false});
        assert_eq!(text_line(&ev), "    3 01:02:03    12ms NOERROR   cache        290  A 192.0.2.7 changed");
        let ev = json!({"kind": "watch", "n": 4, "at": null, "t_ms": 4000, "ms": null,
            "error": "timeout (no answer in 3000 ms)", "timeout": true, "data": []});
        assert!(text_line(&ev).contains("+4.0s"), "{}", text_line(&ev));
    }
}
