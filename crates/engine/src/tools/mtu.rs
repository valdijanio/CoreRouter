//! `tool.ping.mtu`: path MTU discovery by binary search with DF set.
//!
//! Sizes are whole IP packets. The smallest size must get an answer (else
//! the host is unreachable, not "small MTU"); the largest that gets an echo
//! reply is the path MTU. A "fragmentation needed" / "packet too big" that
//! names the next-hop MTU narrows the search at once. A probe lost
//! `retries` times counts as too big (a path that drops big packets
//! silently — a PMTU black hole — looks exactly like that).

use std::net::IpAddr;
use std::ops::ControlFlow;
use std::time::Duration;

use corerouter_hal::probe::{
    Probe, ProbeError, ProbeSocket, Prober, ReplyKind, SocketOptions, overhead,
};
use serde_json::{Value, json};

use super::{Target, ms, wait_replies};
use crate::tasks::TaskCtx;

#[derive(Debug, Clone)]
pub struct MtuJob {
    pub target: Target,
    /// Largest size tried (whole IP packet).
    pub max: u16,
    pub timeout: Duration,
    /// Attempts per size before calling it lost.
    pub retries: u8,
    pub options: SocketOptions,
}

#[derive(Debug, Clone, PartialEq)]
enum Try {
    Pass(f64),
    TooBig(Option<u16>),
    Lost,
    Unreachable(String),
}

struct Search<'a> {
    sock: Box<dyn ProbeSocket>,
    ctx: &'a TaskCtx<'a>,
    addr: IpAddr,
    seq: u16,
    probes: u32,
    timeout: Duration,
    retries: u8,
}

impl Search<'_> {
    /// `None`: stopped.
    fn attempt(&mut self, size: u16) -> Result<Option<Try>, String> {
        for _ in 0..self.retries.max(1) {
            self.seq = self.seq.wrapping_add(1);
            self.probes += 1;
            let seq = self.seq;
            let sent = self.ctx.now();
            let probe = Probe {
                dst: self.addr,
                seq,
                ttl: None,
                size,
            };
            match self.sock.send(&probe) {
                Ok(()) => {}
                Err(ProbeError::TooBig(m)) => return Ok(Some(Try::TooBig(m))),
                Err(ProbeError::Unreachable(why)) => return Ok(Some(Try::Unreachable(why))),
                Err(e) => return Err(e.to_string()),
            }
            let mut got: Option<Try> = None;
            let until = sent.saturating_add(self.timeout);
            let alive = wait_replies(self.sock.as_mut(), self.ctx, until, |r, _| {
                if r.seq != seq {
                    return ControlFlow::Continue(());
                }
                got = Some(match r.kind {
                    ReplyKind::Echo => Try::Pass(ms(r.rtt)),
                    ReplyKind::TooBig { mtu } => Try::TooBig(mtu),
                    ReplyKind::Unreachable(why) => Try::Unreachable(why),
                    ReplyKind::TtlExceeded => Try::Unreachable("TTL exceeded".into()),
                });
                ControlFlow::Break(())
            })?;
            if !alive {
                return Ok(None);
            }
            if got.is_some() {
                return Ok(got);
            }
        }
        Ok(Some(Try::Lost))
    }

    /// Try `size` and report it as an event.
    fn probe(&mut self, size: u16) -> Result<Option<Try>, String> {
        let Some(t) = self.attempt(size)? else {
            return Ok(None);
        };
        let mut ev = json!({ "size": size, "payload": size.saturating_sub(overhead(self.addr)) });
        if let Value::Object(o) = &mut ev {
            let (status, extra) = match &t {
                Try::Pass(rtt) => ("ok", Some(("rtt_ms", json!(rtt)))),
                Try::TooBig(m) => ("too-big", m.map(|m| ("mtu", json!(m)))),
                Try::Lost => ("timeout", None),
                Try::Unreachable(why) => ("unreachable", Some(("detail", json!(why)))),
            };
            o.insert("status".into(), json!(status));
            if let Some((k, v)) = extra {
                o.insert(k.into(), v);
            }
        }
        self.ctx.emit(ev);
        Ok(Some(t))
    }
}

pub fn run(job: MtuJob, prober: &dyn Prober, ctx: &TaskCtx) -> Result<(), String> {
    let v6 = job.options.src.map(|a| a.is_ipv6());
    let addr = job.target.resolve(prober, v6)?;
    let min = overhead(addr);
    let max = job.max.max(min);
    let mut options = job.options.clone();
    options.dont_fragment = true;
    let mut s = Search {
        sock: prober.open(&options).map_err(|e| e.to_string())?,
        ctx,
        addr,
        seq: 0,
        probes: 0,
        timeout: job.timeout,
        retries: job.retries,
    };
    let base = json!({
        "host": job.target.input,
        "address": addr.to_string(),
        "prober": prober.describe(),
        "max_size": max,
    });
    let report = |good: Option<u16>, bad: u16, state: &str, probes: u32| {
        let mut v = base.clone();
        if let Value::Object(o) = &mut v {
            o.insert("state".into(), json!(state));
            o.insert("mtu".into(), json!(good));
            o.insert("payload".into(), json!(good.map(|g| g.saturating_sub(min))));
            o.insert(
                "smallest_failing".into(),
                json!((bad <= max).then_some(bad)),
            );
            o.insert("probes".into(), json!(probes));
        }
        v
    };
    ctx.summary(report(None, max.saturating_add(1), "searching", 0));

    match s.probe(min)? {
        None => return Ok(()),
        Some(Try::Pass(_)) => {}
        Some(Try::Unreachable(why)) => return Err(format!("{addr} is unreachable: {why}")),
        Some(other) => {
            return Err(format!(
                "no answer from {addr} even at the smallest size ({min} bytes): {}",
                match other {
                    Try::TooBig(_) => "too big",
                    _ => "timeout",
                }
            ));
        }
    }
    let mut good = min;
    // Smallest size known to fail; `max + 1` = none yet.
    let mut bad = max.saturating_add(1);
    let mut next = Some(max);
    while good.saturating_add(1) < bad {
        let size = next
            .take()
            .filter(|n| *n > good && *n < bad)
            .unwrap_or(good + (bad - good) / 2);
        let Some(t) = s.probe(size)? else {
            ctx.summary(report(Some(good), bad, "stopped", s.probes));
            return Ok(());
        };
        match t {
            Try::Pass(_) => good = size,
            Try::TooBig(m) => {
                bad = size;
                // The router named the next-hop MTU: everything above it fails.
                if let Some(m) = m.filter(|m| *m > good && *m < size) {
                    bad = m.saturating_add(1);
                    next = Some(m);
                }
            }
            Try::Lost => bad = size,
            Try::Unreachable(why) => return Err(format!("{addr} became unreachable: {why}")),
        }
        ctx.summary(report(Some(good), bad, "searching", s.probes));
    }
    ctx.summary(report(Some(good), bad, "done", s.probes));
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

    fn mtu(host: &str, max: u16) -> (Result<(), String>, Vec<Value>, Value) {
        let cell = TaskCell::for_test();
        let clock = Fake(Cell::new(Duration::ZERO));
        let ctx = TaskCtx::new(&cell, &clock);
        let job = MtuJob {
            target: Target {
                input: host.into(),
                addr: host.parse().ok(),
            },
            max,
            timeout: Duration::from_millis(500),
            retries: 2,
            options: SocketOptions::default(),
        };
        let r = run(job, &SimProber::default(), &ctx);
        let (events, summary) = cell.snapshot();
        (r, events, summary)
    }

    #[test]
    fn finds_the_tunnel_mtu() {
        let (r, events, s) = mtu("198.51.100.20", 1500);
        // The lossy path loses some probes; retries cover most of it.
        r.unwrap();
        assert_eq!(s["state"], "done");
        let found = s["mtu"].as_u64().unwrap();
        assert!(found <= 1400, "found {found}");
        assert_eq!(s["payload"], found - 28);
        assert!(events.len() < 20);
    }

    #[test]
    fn a_clean_path_passes_at_the_maximum() {
        let (r, events, s) = mtu("8.8.8.8", 1500);
        r.unwrap();
        assert_eq!(s["mtu"], 1500);
        assert_eq!(events.len(), 2, "smallest, then the maximum");
        // Above the local link MTU: binary search down to 1500.
        let (_, _, s) = mtu("8.8.8.8", 9000);
        assert_eq!(s["mtu"], 1500);
        assert_eq!(s["smallest_failing"], 1501);
        let (_, _, s) = mtu("::1", 9000);
        assert_eq!(s["mtu"], 9000);
        assert_eq!(s["payload"], 9000 - 48);
    }

    #[test]
    fn unreachable_and_silent_hosts_fail() {
        assert!(
            mtu("192.0.2.1", 1500)
                .0
                .unwrap_err()
                .contains("unreachable")
        );
        assert!(
            mtu("203.0.113.1", 1500)
                .0
                .unwrap_err()
                .contains("no answer")
        );
    }
}
