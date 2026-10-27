//! One queue seen live (G4.9g): `queue.simple.stats` of the "Queue <name>"
//! modal, and the queues' traffic history (`/tool graphing`).
//!
//! - **Stats** look up one queue and its counters, never the whole plan:
//!   the counters are a hash map by key ([`crate::queue::QueueStats`],
//!   filled by the `queue` service once a second), a session's come from
//!   its backend by id. What needs more than one reading — packets and
//!   drops per second, the burst average, how long the queue has been at
//!   its limit, the delay's p95 — comes from a short ring kept only for the
//!   queues being watched ([`QueueWatch`]): a call is a sample (at most one
//!   a second), so the modal's 1 Hz poll feeds it and nothing runs for a
//!   queue nobody looks at. A watch nobody asked for [`IDLE`] seconds is
//!   dropped; at most [`MAX_WATCHED`] at once ("busy" past it).
//! - **History** is a `queue:<name>` series of [`crate::graph`] for the
//!   fixed queues with `graph` on and the dynamic ones the operator marked
//!   (`system.graph.set queue_include`) or all of them (`dynamic_queues`),
//!   under the graphing memory cap. Sampled on the `queue` service's round
//!   ([`Session::queue_graph_sample`]), from the counters it just read.

use std::collections::{HashMap, HashSet, VecDeque};

use corerouter_hal::queue::QueueCounters;
use corerouter_model::ItemId;
use corerouter_model::ppp::ActiveSession;
use corerouter_model::queue::{Target, rate_text, targets_text};
use serde_json::{Value, json};

use crate::graph::{GraphDb, QUEUE, queue_key};
use crate::queue::{Limit, Queue, QueueStats, dhcp_dynamic, session_queue};
use crate::{EngineError, Result, Session};

/// Queues watched at once (two GUIs with a few modals each); past it a
/// new one is refused as busy.
pub const MAX_WATCHED: usize = 64;
/// Seconds without a call before a watch is dropped.
pub const IDLE: u64 = 30;
/// Seconds of samples a watch keeps: the modal's longest window (15 min).
pub const RING: usize = 900;
/// "At the limit": at or above this share of max-limit, percent…
pub const AT_LIMIT_PCT: u64 = 95;
/// …for at least this many seconds in a row.
pub const AT_LIMIT_SECS: u64 = 10;
/// Seconds the delay's p95 looks back.
pub const P95_WINDOW: u64 = 300;
/// A dynamic queue is looked up again after this many seconds (a session's
/// rate may change by CoA without a new config revision).
const RESOLVE_EVERY: u64 = 10;

/// One second of a watched queue, both directions (`[up, down]`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Sample {
    t: u64,
    rate: [u64; 2],
    pps: [u64; 2],
    drops: [u64; 2],
    queued: [u64; 2],
}

#[derive(Debug, Clone)]
struct Watch {
    asked: u64,
    resolved_at: u64,
    rev: u32,
    queue: Queue,
    interface: Option<String>,
    samples: VecDeque<Sample>,
    last: Option<(u64, QueueCounters)>,
}

/// The queues being watched, by the id the caller gave.
#[derive(Debug, Default)]
pub struct QueueWatch {
    by_id: HashMap<String, Watch>,
}

impl QueueWatch {
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

/// A PPP session's counters as a queue's: `rx` is what the subscriber
/// sent (upload).
pub fn session_counters(a: &ActiveSession) -> QueueCounters {
    QueueCounters {
        bytes: [a.rx_bytes, a.tx_bytes],
        packets: [a.rx_packets, a.tx_packets],
        dropped: [0, a.drops],
        queued_us: [0, a.queue_us],
        rate_bps: [a.rx_bps, a.tx_bps],
        pcq_queues: 0,
    }
}

/// `<pppoe-ana>` → (`pppoe`, `ana`); `<ipoe-x>` likewise.
fn session_name(name: &str) -> Option<(&str, &str)> {
    let inner = name.strip_prefix('<')?.strip_suffix('>')?;
    inner
        .strip_prefix("pppoe-")
        .map(|l| ("pppoe", l))
        .or_else(|| inner.strip_prefix("ipoe-").map(|l| ("ipoe", l)))
}

fn shown(raw: &str) -> String {
    crate::logging::cut(raw, 64)
}

/// The queue `raw` names (`*hex`, `ppp:<id>`, `dhcp:<address>` or a name)
/// in the running config, and the interface it sits behind when known.
fn resolve(s: &Session, raw: &str) -> Result<(Queue, Option<String>)> {
    let cfg = s.store().running();
    let not_found = || EngineError::bad("id", format!("no queue '{}'", shown(raw)));
    let fixed = |i: usize| {
        cfg.queue
            .simple
            .get(i)
            .map(|q| (Queue::fixed(q, &cfg.queue), interface_of(&q.target)))
            .ok_or_else(not_found)
    };
    if raw.starts_with('*') {
        let id: ItemId = raw.parse().map_err(|e| EngineError::bad("id", format!("{e}")))?;
        return cfg.queue.simple.position(id).ok_or_else(not_found).and_then(fixed);
    }
    let session = |a: ActiveSession| session_queue(cfg, &a).map(|q| (q, Some(a.interface.clone())));
    if let Some(id) = raw.strip_prefix("ppp:") {
        return s.ppp_backend().and_then(|b| b.session(id)).and_then(session).ok_or_else(not_found);
    }
    if raw.starts_with("dhcp:") || raw.starts_with("dhcp-ds<") {
        return dhcp_dynamic(s)
            .into_iter()
            .find(|q| q.key == raw || q.name == raw)
            .map(|q| (q, None))
            .ok_or_else(not_found);
    }
    if let Some(i) = cfg.queue.simple.position_of(raw) {
        return fixed(i);
    }
    if let Some((service, login)) = session_name(raw) {
        let keep = |a: &ActiveSession| a.name == login && (a.service == "ipoe") == (service == "ipoe") && a.rate_limit.is_some();
        return s
            .ppp_backend()
            .and_then(|b| b.active_page(&keep, 1).1.into_iter().next())
            .and_then(session)
            .ok_or_else(not_found);
    }
    Err(not_found())
}

/// An interface target, if the queue has one.
fn interface_of(targets: &[Target]) -> Option<String> {
    targets.iter().find_map(|t| match t {
        Target::Interface(n) => Some(n.to_string()),
        Target::Prefix(_) => None,
    })
}

/// The counters of `q` now; `None` when nothing counts it.
fn counters_of(s: &Session, q: &Queue) -> Option<QueueCounters> {
    match q.key.strip_prefix("ppp:") {
        Some(id) => s.ppp_backend().and_then(|b| b.session(id)).map(|a| session_counters(&a)),
        None => s.queue_counters(&q.key),
    }
}

/// The burst of one direction, as RouterOS runs it: allowed while the
/// average over `burst-time` is under `burst-threshold`, up to
/// `burst-limit`. The average here is the samples' (one a second while
/// watched): `known_s` says how much of the window they cover yet.
fn burst(l: &Limit, samples: &VecDeque<Sample>, dir: usize, now: u64) -> Value {
    if l.burst_limit == 0 {
        return json!({"state": "off"});
    }
    let threshold = if l.burst_threshold == 0 { l.max_limit } else { l.burst_threshold };
    let window = u64::from(l.burst_time_ms.max(1000)).div_ceil(1000);
    let recent = || samples.iter().rev().take_while(|x| now.saturating_sub(x.t) < window);
    let inside: Vec<u64> = recent().filter_map(|x| x.rate.get(dir).copied()).collect();
    // Seconds the samples cover (a poll that missed a second leaves a
    // hole, not a shorter window).
    let known = recent().last().map_or(0, |x| now.saturating_sub(x.t) + 1);
    let rate = samples.back().and_then(|x| x.rate.get(dir).copied()).unwrap_or(0);
    let avg = if inside.is_empty() { 0 } else { inside.iter().sum::<u64>() / inside.len() as u64 };
    let allowed = avg < threshold;
    let state = match (allowed, rate > l.max_limit) {
        (true, true) => "bursting",
        (true, false) => "ready",
        (false, _) => "spent",
    };
    let mut v = json!({
        "state": state,
        "average_bps": avg,
        "threshold_bps": threshold,
        "limit_bps": l.burst_limit,
        "window_s": window,
        "known_s": known,
    });
    // While bursting at `rate`, the average climbs ~(rate − avg)/window a
    // second: it meets the threshold after (threshold − avg) × window /
    // (rate − avg) seconds (from idle: threshold/rate × window, RouterOS's
    // own example). Estimated, the data plane keeps the exact clock.
    if state == "bursting"
        && rate > avg
        && let Some(o) = v.as_object_mut()
    {
        let left = (threshold - avg) as f64 * window as f64 / (rate - avg) as f64;
        o.insert("left_s".into(), json!(left.round() as u64));
    }
    v
}

/// The p95 of what a packet waited over the last [`P95_WINDOW`] seconds,
/// microseconds.
fn p95(samples: &VecDeque<Sample>, dir: usize, now: u64) -> u64 {
    let mut v: Vec<u64> = samples
        .iter()
        .filter(|x| now.saturating_sub(x.t) < P95_WINDOW)
        .filter_map(|x| x.queued.get(dir).copied())
        .collect();
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    let i = (v.len() * 95).div_ceil(100).saturating_sub(1);
    v.get(i).copied().unwrap_or(0)
}

/// Seconds in a row (up to now) at [`AT_LIMIT_PCT`] of `limit` or above.
fn at_limit(samples: &VecDeque<Sample>, dir: usize, limit: u64) -> u64 {
    if limit == 0 {
        return 0;
    }
    let mut run = samples
        .iter()
        .rev()
        .take_while(|x| x.rate.get(dir).is_some_and(|r| r.saturating_mul(100) >= limit.saturating_mul(AT_LIMIT_PCT)));
    match (run.next(), run.last()) {
        (Some(a), Some(b)) => a.t.saturating_sub(b.t) + 1,
        (Some(_), None) => 1,
        _ => 0,
    }
}

impl Session {
    /// `queue.simple.stats`: one queue's counters, and what its watch
    /// knows. `recent`: the watch's samples too (a modal opened again gets
    /// its graph at once).
    pub fn queue_stats(&mut self, raw: &str, recent: bool) -> Result<Value> {
        let raw = raw.trim();
        let now = self.now().unwrap_or(0);
        let rev = self.store().current_revision();
        let (fresh, cached) = match self.ext::<QueueWatch>().and_then(|w| w.by_id.get(raw)) {
            Some(w) => {
                let dynamic = w.queue.origin.dynamic();
                let stale = w.rev != rev || (dynamic && now.saturating_sub(w.resolved_at) >= RESOLVE_EVERY);
                (stale, true)
            }
            None => (true, false),
        };
        let resolved = if fresh { Some(resolve(self, raw)?) } else { None };
        // The watches, aged; a new one only if there is room.
        {
            let w = self.ext_mut::<QueueWatch>().ok_or_else(|| EngineError::Internal("queue watch".into()))?;
            w.by_id.retain(|_, x| now.saturating_sub(x.asked) < IDLE);
            if !cached && w.by_id.len() >= MAX_WATCHED {
                return Err(EngineError::bad("id", format!("busy: {MAX_WATCHED} queues are watched already, close a Queue window")));
            }
        }
        let (queue, interface) = match resolved {
            Some(r) => r,
            None => {
                let w = self.ext::<QueueWatch>().and_then(|w| w.by_id.get(raw));
                match w {
                    Some(w) => (w.queue.clone(), w.interface.clone()),
                    None => resolve(self, raw)?,
                }
            }
        };
        let counters = counters_of(self, &queue);
        let w = self
            .ext_mut::<QueueWatch>()
            .ok_or_else(|| EngineError::Internal("queue watch".into()))?
            .by_id
            .entry(raw.to_owned())
            .or_insert_with(|| Watch {
                asked: now,
                resolved_at: now,
                rev,
                queue: queue.clone(),
                interface: interface.clone(),
                samples: VecDeque::new(),
                last: None,
            });
        w.asked = now;
        if fresh {
            if w.queue.key != queue.key {
                // Another queue under the same name: start over.
                w.samples.clear();
                w.last = None;
            }
            w.queue = queue.clone();
            w.interface = interface.clone();
            w.resolved_at = now;
            w.rev = rev;
        }
        if let Some(c) = counters {
            match w.last {
                Some((t, p)) if now > t => {
                    let dt = now - t;
                    let per = |[a0, a1]: [u64; 2], [b0, b1]: [u64; 2]| [a0.saturating_sub(b0) / dt, a1.saturating_sub(b1) / dt];
                    w.samples.push_back(Sample {
                        t: now,
                        rate: c.rate_bps,
                        pps: per(c.packets, p.packets),
                        drops: per(c.dropped, p.dropped),
                        queued: c.queued_us,
                    });
                    while w.samples.len() > RING {
                        w.samples.pop_front();
                    }
                    w.last = Some((now, c));
                }
                Some(_) => {}
                None => w.last = Some((now, c)),
            }
        }
        let w = w.clone();
        Ok(self.stats_json(&w, counters.unwrap_or_default(), counters.is_some(), recent, now))
    }

    fn stats_json(&self, w: &Watch, c: QueueCounters, counted: bool, recent: bool, now: u64) -> Value {
        let q = &w.queue;
        let pair = |f: &dyn Fn(&Limit) -> u64| [f(&q.upload), f(&q.download)];
        let last = w.samples.back().copied().unwrap_or_default();
        let fresh = w.samples.back().is_some_and(|x| now.saturating_sub(x.t) <= 2);
        let per_s = |v: [u64; 2]| if fresh { json!(v) } else { Value::Null };
        let limits = pair(&|l| l.max_limit);
        let [lim_up, lim_down] = limits;
        let at = [at_limit(&w.samples, 0, lim_up), at_limit(&w.samples, 1, lim_down)];
        let graphing = &self.store().running().system.graphing;
        let marked = match q.origin {
            crate::queue::Origin::Fixed => q.graph,
            _ => graphing.dynamic_queues || graphing.queue_include.contains(&q.name),
        };
        let series = queue_key(&q.name);
        let db = self.ext::<GraphDb>();
        let kept = series.as_ref().is_some_and(|k| db.is_some_and(|d| d.get(k).is_some()));
        let refused = marked && !kept && db.is_some_and(|d| d.refused_queues() > 0);
        let stats = self.ext::<QueueStats>();
        let ppp = q.origin.session();
        let p95s = [0, 1].map(|d| p95(&w.samples, d, now));
        let at_now = at.map(|s| s >= AT_LIMIT_SECS);
        let address = q.targets.iter().find_map(|t| match t {
            Target::Prefix(n) => Some(n.to_string()),
            Target::Interface(_) => None,
        });
        let mut v = json!({
            "id": q.key,
            "name": q.name,
            "origin": q.origin.as_str(),
            "dynamic": q.origin.dynamic(),
            "disabled": q.disabled,
            "target": targets_text(&q.targets),
            "address": address,
            "interface": w.interface,
            "queue": q.queue_names.to_string(),
            "max_limit": limits,
            "max_limit_text": format!("{}/{}", rate_text(q.upload.max_limit), rate_text(q.download.max_limit)),
            "burst_limit": pair(&|l| l.burst_limit),
            "time": now,
            "counted": counted,
            "running": ppp || stats.is_some_and(|x| x.running),
            "rate_bps": c.rate_bps,
            "bytes": c.bytes,
            "packets": c.packets,
            "dropped": c.dropped,
            "queued_us": c.queued_us,
            "pcq_queues": c.pcq_queues,
            "pps": per_s(last.pps),
            "drops_ps": per_s(last.drops),
            "queued_p95_us": p95s,
            "at_limit_s": at,
            "at_limit": at_now,
            "burst": [burst(&q.upload, &w.samples, 0, now), burst(&q.download, &w.samples, 1, now)],
            "samples": w.samples.len(),
            "graph": marked,
            "series": series,
            "kept": kept,
            "refused": refused,
        });
        if let Some(o) = v.as_object_mut() {
            if !ppp && let Some(n) = stats.and_then(|x| x.note.clone()) {
                o.insert("note".into(), json!(n));
            }
            if recent {
                let rows: Vec<Value> = w
                    .samples
                    .iter()
                    .map(|x| json!([x.t, x.rate[0], x.rate[1], x.queued[1], x.drops[0].saturating_add(x.drops[1])]))
                    .collect();
                o.insert("recent".into(), json!(rows));
            }
        }
        v
    }

    /// The `queue` service's second for the history (G4.9g): every queue
    /// graphing keeps, with the counters just read (`dhcp`: the DHCP
    /// queues come from the round). The fixed queues kept are listed again
    /// only when the running config changes.
    pub fn queue_graph_sample(&mut self) {
        let cfg = self.store().running().system.graphing.clone();
        let Some(now) = self.now() else { return };
        let has_queue_series = self.ext::<GraphDb>().is_some_and(|d| d.keys().any(|k| k.starts_with(QUEUE)));
        if !(cfg.enabled && cfg.queues) && !has_queue_series {
            return;
        }
        let rev = self.store().current_revision();
        if self.ext::<KeptQueues>().is_none_or(|k| k.rev != Some(rev)) {
            let fixed: Vec<(String, String)> = self
                .store()
                .running()
                .queue
                .simple
                .iter()
                .filter(|q| cfg.keeps_queue(&q.name, Some(q.graph)))
                .filter_map(|q| Some((queue_key(&q.name)?, q.id.to_string())))
                .collect();
            if let Some(k) = self.ext_mut::<KeptQueues>() {
                k.rev = Some(rev);
                k.fixed = fixed;
            }
        }
        // The history is taken out of the session while the kept list and
        // the counters are borrowed from it.
        let mut db = self.ext_mut::<GraphDb>().map(std::mem::take).unwrap_or_default();
        let mut dynamic: Vec<(String, QueueCounters)> = Vec::new();
        let mut kept: Vec<(&str, QueueCounters)> = Vec::new();
        if cfg.enabled && cfg.queues {
            let by_key = self.ext::<QueueStats>().map(|s| &s.by_key);
            let counted = |key: &str| by_key.and_then(|m| m.get(key)).copied().unwrap_or_default();
            let wanted = |name: &str| cfg.keeps_queue(name, None);
            let dhcp = self.ext::<crate::queue::ShaperRuntime>().map_or(&[][..], |r| r.dhcp_queues());
            dynamic.extend(
                dhcp.iter()
                    .filter(|q| wanted(&q.name))
                    .filter_map(|q| Some((queue_key(&q.name)?, counted(&q.key)))),
            );
            if (cfg.dynamic_queues || !cfg.queue_include.is_empty())
                && let Some(b) = self.ppp_backend()
            {
                let marked: HashSet<(&str, &str)> = cfg.queue_include.iter().filter_map(|n| session_name(n)).collect();
                let all = cfg.dynamic_queues;
                let keep = |a: &ActiveSession| {
                    a.rate_limit.is_some()
                        && (all || marked.contains(&(if a.service == "ipoe" { "ipoe" } else { "pppoe" }, a.name.as_str())))
                };
                let room = crate::graph::MAX_SERIES.saturating_sub(dynamic.len());
                for a in b.active_page(&keep, room).1 {
                    let name = if a.service == "ipoe" { format!("<ipoe-{}>", a.name) } else { format!("<pppoe-{}>", a.name) };
                    if let Some(series) = queue_key(&name) {
                        dynamic.push((series, session_counters(&a)));
                    }
                }
            }
            if let Some(k) = self.ext::<KeptQueues>() {
                kept.extend(k.fixed.iter().map(|(series, key)| (series.as_str(), counted(key))));
            }
            kept.extend(dynamic.iter().map(|(s, c)| (s.as_str(), *c)));
        }
        let log = db.sample_queues(now, &cfg, &kept);
        drop(kept);
        if let Some(slot) = self.ext_mut::<GraphDb>() {
            *slot = db;
        }
        for (warning, line) in log {
            let level = if warning { "warning" } else { "info" };
            self.log_event(&["system", level], "graphing", line, Value::Null);
        }
    }
}

/// The fixed queues graphing keeps, as of a running revision.
#[derive(Debug, Default)]
struct KeptQueues {
    rev: Option<u32>,
    /// (series key, queue key).
    fixed: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples(rates: &[(u64, u64)]) -> VecDeque<Sample> {
        rates
            .iter()
            .map(|(t, r)| Sample {
                t: *t,
                rate: [*r, *r],
                ..Sample::default()
            })
            .collect()
    }

    fn limit(max: u64, burst: u64, thr: u64, time_ms: u32) -> Limit {
        let mut l = Limit::of_rate_limit(&"1M/1M".parse().unwrap(), true, corerouter_model::queue::QueueType::new("x", corerouter_model::queue::Kind::Pfifo));
        l.max_limit = max;
        l.burst_limit = burst;
        l.burst_threshold = thr;
        l.burst_time_ms = time_ms;
        l
    }

    #[test]
    fn burst_states_and_time_left() {
        let l = limit(2_000_000, 4_000_000, 3_000_000, 16_000);
        // 14 s idle, then 4M: the average (4M/15) is under the threshold.
        let mut rates: Vec<(u64, u64)> = (100..115).map(|t| (t, 0)).collect();
        rates.push((115, 4_000_000));
        let b = burst(&l, &samples(&rates), 1, 115);
        assert_eq!(b["state"], "bursting", "{b}");
        assert_eq!(b["average_bps"], 4_000_000 / 16);
        assert_eq!(b["known_s"], 16);
        // (3M − 250k) × 16 / (4M − 250k) = 11.7 s.
        assert_eq!(b["left_s"], 12);
        // The average past the threshold: spent, back to max-limit.
        let s = samples(&(0..16).map(|i| (200 + i, 3_500_000)).collect::<Vec<_>>());
        assert_eq!(burst(&l, &s, 1, 215)["state"], "spent");
        let s = samples(&[(300, 100_000)]);
        let b = burst(&l, &s, 1, 300);
        assert_eq!(b["state"], "ready");
        assert_eq!(b["known_s"], 1, "warming up: one second of sixteen");
        assert_eq!(burst(&limit(2_000_000, 0, 0, 0), &s, 1, 300)["state"], "off");
        // Threshold 0 is the max-limit (RouterOS).
        assert_eq!(burst(&limit(2_000_000, 4_000_000, 0, 8_000), &s, 1, 300)["threshold_bps"], 2_000_000);
    }

    #[test]
    fn p95_and_at_limit() {
        let mut s: VecDeque<Sample> = (0..100u64).map(|i| Sample { t: i, queued: [0, i * 10], ..Sample::default() }).collect();
        assert_eq!(p95(&s, 1, 99), 940);
        assert_eq!(p95(&VecDeque::new(), 1, 0), 0);
        for (i, x) in s.iter_mut().enumerate() {
            x.rate = [0, if i >= 80 { 960 } else { 500 }];
        }
        assert_eq!(at_limit(&s, 1, 1000), 20);
        assert_eq!(at_limit(&s, 1, 0), 0, "no limit, never at it");
        assert_eq!(at_limit(&s, 0, 1000), 0);
    }

    #[test]
    fn session_names() {
        assert_eq!(session_name("<pppoe-ana>"), Some(("pppoe", "ana")));
        assert_eq!(session_name("<ipoe-02:00>"), Some(("ipoe", "02:00")));
        assert_eq!(session_name("queue1"), None);
    }
}
