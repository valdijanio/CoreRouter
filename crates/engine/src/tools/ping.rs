//! `tool.ping.start`: ICMP echo to one or more targets at a fixed interval.
//!
//! Every `interval` one probe goes to each target (like RouterOS, a probe
//! does not wait for the previous reply); a probe without an answer after
//! `timeout` is a timeout. Each answer is an event, and the summary holds
//! the statistics of every target (see [`super::stats`]).

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::ops::ControlFlow;
use std::time::Duration;

use corerouter_hal::probe::{Probe, ProbeError, Prober, Reply, ReplyKind, SocketOptions, overhead};
use serde_json::{Value, json};

use super::stats::{Outcome, Stats};
use super::{Target, ms, wait_replies};
use crate::tasks::TaskCtx;

/// Everything `tool.ping.start` validated.
#[derive(Debug, Clone)]
pub struct PingJob {
    pub targets: Vec<Target>,
    /// 0: until stopped.
    pub count: u32,
    pub interval: Duration,
    pub timeout: Duration,
    /// Whole IP packet; raised to the family's minimum per target.
    pub size: u16,
    pub ttl: Option<u8>,
    pub options: SocketOptions,
}

struct Live {
    input: String,
    addr: Option<IpAddr>,
    size: u16,
    /// Ping sequence number of the next probe (per target, from 0).
    next: u32,
    error: Option<String>,
    stats: Stats,
}

struct InFlight {
    target: usize,
    n: u32,
    sent: Duration,
}

/// Wire sequence numbers recently finished, to spot duplicates.
const RECENT_DONE: usize = 512;

pub fn run(job: PingJob, prober: &dyn Prober, ctx: &TaskCtx) -> Result<(), String> {
    let v6 = job.options.src.map(|a| a.is_ipv6());
    let mut live: Vec<Live> = job
        .targets
        .iter()
        .map(|t| {
            let (addr, error) = match t.resolve(prober, v6) {
                Ok(a) => (Some(a), None),
                Err(e) => (None, Some(e)),
            };
            Live {
                input: t.input.clone(),
                size: addr.map_or(job.size, |a| job.size.max(overhead(a))),
                addr,
                next: 0,
                error,
                stats: Stats::default(),
            }
        })
        .collect();
    for (i, t) in live.iter().enumerate() {
        if let Some(e) = &t.error {
            ctx.emit(json!({"target": i, "host": t.input, "status": "error", "detail": e}));
        }
    }
    let describe = prober.describe();
    let summary = |live: &[Live]| summary(&describe, &job, live);
    ctx.summary(summary(&live));
    if live.iter().all(|t| t.addr.is_none()) {
        return Err(live
            .iter()
            .find_map(|t| t.error.clone())
            .unwrap_or_else(|| "no target".into()));
    }
    let mut sock = prober.open(&job.options).map_err(|e| e.to_string())?;

    let mut flights: BTreeMap<u16, InFlight> = BTreeMap::new();
    let mut done: VecDeque<u16> = VecDeque::new();
    let mut wire: u16 = 0;
    let mut next_send = Duration::ZERO;
    let mut rounds: u32 = 0;
    loop {
        let more = job.count == 0 || rounds < job.count;
        if !more && flights.is_empty() {
            break;
        }
        let now = ctx.now();
        let mut changed = false;
        if more && now >= next_send {
            for (i, t) in live.iter_mut().enumerate() {
                let Some(addr) = t.addr else { continue };
                wire = wire.wrapping_add(1);
                let n = t.next;
                t.next = t.next.saturating_add(1);
                t.stats.sent += 1;
                let probe = Probe {
                    dst: addr,
                    seq: wire,
                    ttl: job.ttl,
                    size: t.size,
                };
                match sock.send(&probe) {
                    Ok(()) => {
                        flights.insert(
                            wire,
                            InFlight {
                                target: i,
                                n,
                                sent: ctx.now(),
                            },
                        );
                    }
                    Err(e) => {
                        let outcome = match &e {
                            ProbeError::TooBig(_) => Outcome::TooBig,
                            ProbeError::Unreachable(_) => Outcome::Unreachable,
                            _ => Outcome::Error,
                        };
                        t.stats.record(outcome, None);
                        ctx.emit(event(i, t, n, outcome, None, Some(e.to_string())));
                    }
                }
            }
            rounds = rounds.saturating_add(1);
            changed = true;
            next_send = next_send.saturating_add(job.interval);
            // Fell behind (a slow resolver, a suspended VM): no burst.
            if next_send < now {
                next_send = now.saturating_add(job.interval);
            }
        }
        // Timeouts.
        let now = ctx.now();
        let expired: Vec<u16> = flights
            .iter()
            .filter(|(_, f)| now.saturating_sub(f.sent) >= job.timeout)
            .map(|(w, _)| *w)
            .collect();
        for w in expired {
            if let Some(f) = flights.remove(&w)
                && let Some(t) = live.get_mut(f.target)
            {
                t.stats.record(Outcome::Timeout, None);
                ctx.emit(event(f.target, t, f.n, Outcome::Timeout, None, None));
                remember(&mut done, w);
                changed = true;
            }
        }
        if changed {
            ctx.summary(summary(&live));
        }
        let more = job.count == 0 || rounds < job.count;
        if !more && flights.is_empty() {
            break;
        }
        let mut until = now.saturating_add(Duration::from_millis(250));
        if more {
            until = until.min(next_send);
        }
        if let Some(first) = flights.values().map(|f| f.sent).min() {
            until = until.min(first.saturating_add(job.timeout));
        }
        let mut got = false;
        let alive = wait_replies(sock.as_mut(), ctx, until, |reply, _| {
            got |= on_reply(&reply, &mut flights, &mut done, &mut live, ctx);
            ControlFlow::Continue(())
        })?;
        if got {
            ctx.summary(summary(&live));
        }
        if !alive {
            break;
        }
    }
    ctx.summary(summary(&live));
    Ok(())
}

fn remember(done: &mut VecDeque<u16>, wire: u16) {
    done.push_back(wire);
    if done.len() > RECENT_DONE {
        done.pop_front();
    }
}

/// Book one reply; `true` if it changed the statistics.
fn on_reply(
    reply: &Reply,
    flights: &mut BTreeMap<u16, InFlight>,
    done: &mut VecDeque<u16>,
    live: &mut [Live],
    ctx: &TaskCtx,
) -> bool {
    let Some(f) = flights.remove(&reply.seq) else {
        // A second echo for a finished probe is a duplicate; a late error
        // or a stray reply is ignored.
        if reply.kind == ReplyKind::Echo
            && done.contains(&reply.seq)
            && let Some(t) = live.iter_mut().find(|t| t.addr == Some(reply.from))
        {
            t.stats.duplicates += 1;
            return true;
        }
        return false;
    };
    remember(done, reply.seq);
    let Some(t) = live.get_mut(f.target) else {
        return false;
    };
    let (outcome, detail) = match &reply.kind {
        ReplyKind::Echo => (Outcome::Ok, None),
        ReplyKind::Reached(how) => (Outcome::Ok, Some(how.clone())),
        ReplyKind::TtlExceeded => (Outcome::TtlExceeded, Some("TTL exceeded".to_owned())),
        ReplyKind::Unreachable(why) => (Outcome::Unreachable, Some(why.clone())),
        ReplyKind::TooBig { mtu } => (
            Outcome::TooBig,
            Some(match mtu {
                Some(m) => format!("fragmentation needed (mtu {m})"),
                None => "fragmentation needed".to_owned(),
            }),
        ),
    };
    let rtt = ms(reply.rtt);
    t.stats.record(outcome, Some(rtt));
    let mut ev = event(f.target, t, f.n, outcome, Some(reply), detail);
    if let Value::Object(o) = &mut ev {
        o.insert("rtt_ms".into(), json!(rtt));
    }
    ctx.emit(ev);
    true
}

fn event(
    target: usize,
    t: &Live,
    n: u32,
    outcome: Outcome,
    reply: Option<&Reply>,
    detail: Option<String>,
) -> Value {
    let mut ev = json!({
        "target": target,
        "host": t.input,
        "address": t.addr.map(|a| a.to_string()),
        "icmp_seq": n,
        "status": outcome.status(),
        "size": reply.and_then(|r| r.size).unwrap_or(t.size),
    });
    if let Value::Object(o) = &mut ev {
        if let Some(r) = reply {
            o.insert("ttl".into(), json!(r.ttl));
            if Some(r.from) != t.addr {
                o.insert("from".into(), json!(r.from.to_string()));
            }
        }
        if let Some(d) = detail {
            o.insert("detail".into(), json!(d));
        }
    }
    ev
}

fn summary(prober: &str, job: &PingJob, live: &[Live]) -> Value {
    let targets: Vec<Value> = live
        .iter()
        .map(|t| {
            let mut v = t.stats.to_json();
            if let Value::Object(o) = &mut v {
                o.insert("host".into(), json!(t.input));
                o.insert("address".into(), json!(t.addr.map(|a| a.to_string())));
                o.insert("size".into(), json!(t.size));
                o.insert("error".into(), json!(t.error));
            }
            v
        })
        .collect();
    json!({
        "prober": prober,
        "count": job.count,
        "interval_ms": ms(job.interval),
        "timeout_ms": ms(job.timeout),
        "targets": targets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::{Clock, TaskCell};
    use corerouter_hal::SimProber;
    use std::cell::Cell;

    /// Virtual time: sleeping advances it, nothing really waits.
    pub(crate) struct Fake(Cell<Duration>);

    impl Clock for Fake {
        fn elapsed(&self) -> Duration {
            self.0.get()
        }
        fn sleep(&self, d: Duration) {
            self.0.set(self.0.get() + d);
        }
    }

    fn job(targets: &[&str], count: u32) -> PingJob {
        PingJob {
            targets: targets
                .iter()
                .map(|t| Target {
                    input: (*t).to_owned(),
                    addr: t.parse().ok(),
                })
                .collect(),
            count,
            interval: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            size: 56,
            ttl: None,
            options: SocketOptions::default(),
        }
    }

    fn run_sim(job: PingJob) -> (Result<(), String>, Vec<Value>, Value, Duration) {
        let cell = TaskCell::for_test();
        let clock = Fake(Cell::new(Duration::ZERO));
        let ctx = TaskCtx::new(&cell, &clock);
        let r = run(job, &SimProber::default(), &ctx);
        let (events, summary) = cell.snapshot();
        (r, events, summary, clock.0.get())
    }

    #[test]
    fn two_targets_each_get_their_own_statistics() {
        let (r, events, summary, took) = run_sim(job(&["127.0.0.1", "198.51.100.7"], 20));
        r.unwrap();
        assert_eq!(events.len(), 40);
        let t = &summary["targets"];
        assert_eq!(t[0]["sent"], 20);
        assert_eq!(t[0]["received"], 20);
        assert_eq!(t[0]["loss_pct"], 0.0);
        assert!(t[0]["max_ms"].as_f64().unwrap() < 1.0);
        assert_eq!(t[1]["sent"], 20);
        let lost = t[1]["loss_pct"].as_f64().unwrap();
        assert!(lost > 0.0 && lost < 60.0, "lossy target lost {lost}%");
        assert!(t[1]["avg_ms"].as_f64().unwrap() > 20.0);
        // 20 rounds a second apart, the last one waits its timeout.
        assert!(took >= Duration::from_secs(19) && took <= Duration::from_secs(21));
        let first = &events[0];
        assert_eq!(first["status"], "ok");
        assert_eq!(first["icmp_seq"], 0);
        assert!(first["rtt_ms"].is_number());
    }

    #[test]
    fn black_hole_times_out_and_unreachable_says_who() {
        let (r, events, summary, _) = run_sim(job(&["203.0.113.5", "192.0.2.9"], 3));
        r.unwrap();
        let of = |i: u64| events.iter().filter(move |e| e["target"] == i);
        assert!(of(0).all(|e| e["status"] == "timeout"));
        assert!(of(1).all(|e| e["status"] == "unreachable" && e["from"].is_string()));
        assert_eq!(summary["targets"][0]["loss_pct"], 100.0);
        assert_eq!(summary["targets"][1]["unreachable"], 3);
    }

    #[test]
    fn names_resolve_and_bad_names_fail_alone() {
        let (r, events, summary, _) = run_sim(job(&["example.com", "no.invalid"], 2));
        r.unwrap();
        assert!(
            summary["targets"][0]["address"]
                .as_str()
                .unwrap()
                .starts_with("198.1")
        );
        assert!(
            summary["targets"][1]["error"]
                .as_str()
                .unwrap()
                .contains("resolved")
        );
        assert_eq!(events.iter().filter(|e| e["status"] == "error").count(), 1);
        let (r, _, _, _) = run_sim(job(&["only.invalid"], 2));
        assert!(r.unwrap_err().contains("resolved"));
    }

    #[test]
    fn ttl_and_df_answers() {
        let mut j = job(&["8.8.8.8"], 2);
        j.ttl = Some(1);
        let (_, events, _, _) = run_sim(j);
        assert!(events.iter().all(|e| e["status"] == "ttl-exceeded"));
        let mut j = job(&["198.51.100.1", "8.8.4.4"], 1);
        j.size = 1450;
        j.options.dont_fragment = true;
        let (_, events, _, _) = run_sim(j);
        assert_eq!(events[0]["status"], "too-big");
        assert!(events[0]["detail"].as_str().unwrap().contains("1400"));
        let mut j = job(&["8.8.4.4"], 1);
        j.size = 1600;
        j.options.dont_fragment = true;
        let (_, events, _, _) = run_sim(j);
        assert_eq!(events[0]["status"], "too-big");
    }

    #[test]
    fn ipv6_sizes_start_at_48() {
        let (_, events, summary, _) = run_sim(job(&["::1"], 1));
        assert_eq!(events[0]["status"], "ok");
        assert_eq!(summary["targets"][0]["size"], 56);
        let mut j = job(&["::1"], 1);
        j.size = 28;
        let (_, _, summary, _) = run_sim(j);
        assert_eq!(summary["targets"][0]["size"], 48);
    }
}
