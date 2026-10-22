//! `tool.mtr.start`: continuous traceroute (MTR). Every round sends one
//! probe per TTL (1..=max_hops, at once); routers answer "TTL exceeded",
//! the destination answers the echo. Each hop keeps its own statistics
//! (loss, last / average / best / worst / standard deviation), so a lossy
//! or slow link shows up at the hop where it starts. Once the destination
//! (or an "unreachable") answers at hop N, later rounds stop at N.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::ops::ControlFlow;
use std::time::Duration;

use corerouter_hal::probe::{Probe, ProbeError, Prober, ReplyKind, SocketOptions, overhead};
use serde_json::{Value, json};

use super::stats::{Outcome, Stats};
use super::{Target, ms, wait_replies};
use crate::tasks::TaskCtx;

/// Addresses remembered per hop (a hop can answer from several when the
/// path load-balances).
const MAX_HOSTS: usize = 4;

#[derive(Debug, Clone)]
pub struct MtrJob {
    pub target: Target,
    /// Rounds; 0 = until stopped.
    pub count: u32,
    pub interval: Duration,
    pub timeout: Duration,
    pub max_hops: u8,
    pub size: u16,
    pub options: SocketOptions,
}

#[derive(Default)]
struct Hop {
    hosts: Vec<IpAddr>,
    stats: Stats,
    /// Last non-echo answer that is not "TTL exceeded" (unreachable…).
    note: Option<String>,
}

struct InFlight {
    hop: u8,
    round: u32,
    sent: Duration,
}

pub fn run(job: MtrJob, prober: &dyn Prober, ctx: &TaskCtx) -> Result<(), String> {
    let v6 = job.options.src.map(|a| a.is_ipv6());
    let dst = job.target.resolve(prober, v6)?;
    let size = job.size.max(overhead(dst));
    let mut sock = prober.open(&job.options).map_err(|e| e.to_string())?;
    let describe = prober.describe();
    let mut hops: BTreeMap<u8, Hop> = BTreeMap::new();
    // Hop of the destination (or of the router that said "unreachable").
    let mut last: u8 = job.max_hops.max(1);
    let mut reached = false;
    let mut flights: BTreeMap<u16, InFlight> = BTreeMap::new();
    let mut wire: u16 = 0;
    let mut round: u32 = 0;
    let mut next = Duration::ZERO;

    let summary = |hops: &BTreeMap<u8, Hop>, last: u8, reached: bool, round: u32| {
        let rows: Vec<Value> = hops
            .range(1..=last)
            .map(|(n, h)| {
                let mut v = h.stats.to_json();
                if let Value::Object(o) = &mut v {
                    o.insert("hop".into(), json!(n));
                    o.insert(
                        "hosts".into(),
                        json!(h.hosts.iter().map(ToString::to_string).collect::<Vec<_>>()),
                    );
                    o.insert(
                        "host".into(),
                        json!(h.hosts.first().map(ToString::to_string)),
                    );
                    o.insert("note".into(), json!(h.note));
                    // MTR names.
                    o.insert(
                        "best_ms".into(),
                        o.get("min_ms").cloned().unwrap_or(Value::Null),
                    );
                    o.insert(
                        "worst_ms".into(),
                        o.get("max_ms").cloned().unwrap_or(Value::Null),
                    );
                }
                v
            })
            .collect();
        json!({
            "host": job.target.input,
            "address": dst.to_string(),
            "prober": describe,
            "rounds": round,
            "reached": reached,
            "max_hops": job.max_hops,
            "hops": rows,
        })
    };
    ctx.summary(summary(&hops, last, reached, round));

    loop {
        let more = job.count == 0 || round < job.count;
        if !more && flights.is_empty() {
            break;
        }
        let now = ctx.now();
        let mut changed = false;
        if more && now >= next {
            round = round.saturating_add(1);
            for ttl in 1..=last {
                wire = wire.wrapping_add(1);
                let hop = hops.entry(ttl).or_default();
                hop.stats.sent += 1;
                let probe = Probe {
                    dst,
                    seq: wire,
                    ttl: Some(ttl),
                    size,
                };
                match sock.send(&probe) {
                    Ok(()) => {
                        flights.insert(
                            wire,
                            InFlight {
                                hop: ttl,
                                round,
                                sent: ctx.now(),
                            },
                        );
                    }
                    Err(ProbeError::Unreachable(why)) => {
                        hop.stats.record(Outcome::Unreachable, None);
                        hop.note = Some(why);
                    }
                    Err(ProbeError::TooBig(_)) => hop.stats.record(Outcome::TooBig, None),
                    Err(e) => return Err(e.to_string()),
                }
            }
            changed = true;
            next = next.saturating_add(job.interval);
            if next < now {
                next = now.saturating_add(job.interval);
            }
        }
        let now = ctx.now();
        let expired: Vec<u16> = flights
            .iter()
            .filter(|(_, f)| now.saturating_sub(f.sent) >= job.timeout)
            .map(|(w, _)| *w)
            .collect();
        for w in expired {
            if let Some(f) = flights.remove(&w)
                && let Some(h) = hops.get_mut(&f.hop)
            {
                h.stats.record(Outcome::Timeout, None);
                if f.hop <= last {
                    ctx.emit(json!({"round": f.round, "hop": f.hop, "status": "timeout"}));
                }
                changed = true;
            }
        }
        if changed {
            ctx.summary(summary(&hops, last, reached, round));
        }
        let more = job.count == 0 || round < job.count;
        if !more && flights.is_empty() {
            break;
        }
        let mut until = now.saturating_add(Duration::from_millis(250));
        if more {
            until = until.min(next);
        }
        if let Some(first) = flights.values().map(|f| f.sent).min() {
            until = until.min(first.saturating_add(job.timeout));
        }
        let mut got = false;
        let alive = wait_replies(sock.as_mut(), ctx, until, |r, _| {
            let Some(f) = flights.remove(&r.seq) else {
                return ControlFlow::Continue(());
            };
            let h = hops.entry(f.hop).or_default();
            let rtt = ms(r.rtt);
            let (status, end) = match &r.kind {
                ReplyKind::Echo => ("ok", true),
                ReplyKind::TtlExceeded => ("ttl-exceeded", false),
                ReplyKind::Unreachable(why) => {
                    h.note = Some(why.clone());
                    ("unreachable", true)
                }
                ReplyKind::TooBig { .. } => {
                    h.note = Some("fragmentation needed".into());
                    ("too-big", false)
                }
            };
            // An answer from the hop is what MTR counts, whatever it says.
            h.stats.record(Outcome::Ok, Some(rtt));
            if !h.hosts.contains(&r.from) && h.hosts.len() < MAX_HOSTS {
                h.hosts.push(r.from);
            }
            if end && f.hop < last {
                last = f.hop;
            }
            if r.kind == ReplyKind::Echo {
                reached = true;
            }
            if f.hop <= last {
                ctx.emit(json!({
                    "round": f.round, "hop": f.hop, "address": r.from.to_string(),
                    "rtt_ms": rtt, "status": status,
                }));
            }
            got = true;
            ControlFlow::Continue(())
        })?;
        if got {
            // Probes past the end will never be answered: forget them.
            flights.retain(|_, f| f.hop <= last);
            ctx.summary(summary(&hops, last, reached, round));
        }
        if !alive {
            break;
        }
    }
    ctx.summary(summary(&hops, last, reached, round));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::{Clock, TaskCell};
    use corerouter_hal::SimProber;
    use std::cell::Cell;

    struct Fake(Cell<Duration>);

    impl Clock for Fake {
        fn elapsed(&self) -> Duration {
            self.0.get()
        }
        fn sleep(&self, d: Duration) {
            self.0.set(self.0.get() + d);
        }
    }

    fn mtr(host: &str, rounds: u32) -> (Result<(), String>, Vec<Value>, Value) {
        let cell = TaskCell::for_test();
        let clock = Fake(Cell::new(Duration::ZERO));
        let ctx = TaskCtx::new(&cell, &clock);
        let job = MtrJob {
            target: Target {
                input: host.into(),
                addr: host.parse().ok(),
            },
            count: rounds,
            interval: Duration::from_secs(1),
            timeout: Duration::from_millis(800),
            max_hops: 30,
            size: 56,
            options: SocketOptions::default(),
        };
        let r = run(job, &SimProber::default(), &ctx);
        let (events, summary) = cell.snapshot();
        (r, events, summary)
    }

    #[test]
    fn walks_the_path_and_stops_at_the_destination() {
        let dst: IpAddr = "8.8.8.8".parse().unwrap();
        let path = SimProber::default().path(dst);
        let (r, _, s) = mtr("8.8.8.8", 5);
        r.unwrap();
        assert_eq!(s["reached"], true);
        let hops = s["hops"].as_array().unwrap();
        assert_eq!(hops.len(), usize::from(path.hops));
        let last = hops.last().unwrap();
        assert_eq!(last["host"], "8.8.8.8");
        assert_eq!(last["loss_pct"], 0.0);
        assert!(last["best_ms"].as_f64().unwrap() <= last["worst_ms"].as_f64().unwrap());
        // Routers answer from their own addresses (or stay silent: 100 % loss).
        for h in &hops[..hops.len() - 1] {
            let n = h["hop"].as_u64().unwrap() as u8;
            if h["received"].as_u64().unwrap() > 0 {
                assert_eq!(h["host"], SimProber::router(dst, n).to_string());
            } else {
                assert_eq!(h["loss_pct"], 100.0);
            }
        }
        // Round 1 asked up to 30; once the end is known only up to it.
        assert_eq!(hops[0]["sent"], 5);
    }

    #[test]
    fn lossy_path_and_unreachable_and_ipv6() {
        let (_, _, s) = mtr("198.51.100.20", 20);
        let last = s["hops"].as_array().unwrap().last().unwrap().clone();
        assert!(last["loss_pct"].as_f64().unwrap() > 0.0, "{last}");
        let (_, _, s) = mtr("192.0.2.5", 3);
        let hops = s["hops"].as_array().unwrap();
        assert_eq!(hops.len(), 3, "ends at the router that said unreachable");
        assert_eq!(hops[2]["note"], "host unreachable");
        assert_eq!(s["reached"], false);
        let (_, events, s) = mtr("2001:4860::8888", 2);
        assert_eq!(s["reached"], true);
        assert!(events.iter().any(|e| e["status"] == "ttl-exceeded"));
    }

    #[test]
    fn black_hole_never_reaches() {
        let (r, _, s) = mtr("203.0.113.7", 2);
        r.unwrap();
        assert_eq!(s["reached"], false);
        assert_eq!(s["hops"].as_array().unwrap().len(), 30);
    }
}
