//! `tool.mtr.start`: continuous traceroute (MTR). Every round sends one
//! probe per TTL (1..=max_hops, at once); routers answer "TTL exceeded",
//! the destination answers the echo. Each hop keeps its own statistics
//! (loss, last / average / best / worst / standard deviation), so a lossy
//! or slow link shows up at the hop where it starts. Once the destination
//! (or an "unreachable") answers at hop N, later rounds stop at N.
//!
//! G6.3b: every hop address also gets, when it arrives, its reverse name
//! (`use_dns`, on by default like `mtr`), its origin AS (`as_lookup`, like
//! `mtr -z`) and the MPLS labels it reported (RFC 4950, like `mtr -e`).
//! Lookups never wait: the prober answers `Pending` and is asked again on
//! the next pass, so the IP shows at once and the name joins it later.
//! Private, CGNAT, link-local and loopback addresses are marked and never
//! looked up: RFC 6598 §4 says reverse queries for shared space "MUST NOT
//! be forwarded to the global DNS", and RFC 6303 §3 keeps the RFC 1918 and
//! ULA reverse zones local.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::ops::ControlFlow;
use std::time::Duration;

use corerouter_hal::probe::{
    AsInfo, Lookup, MplsLabel, Probe, ProbeError, Prober, ReplyKind, SocketOptions, overhead,
};
use serde_json::{Value, json};

use super::stats::{Outcome, Stats};
use super::{Target, ms, wait_replies};
use crate::tasks::TaskCtx;

/// A run with a round count waits at most this long, after its last
/// round, for names and AS numbers still on their way.
const LOOKUP_GRACE: Duration = Duration::from_secs(3);

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
    /// Reverse names of the hops (PTR).
    pub use_dns: bool,
    /// Origin AS of the hops (Team Cymru over DNS).
    pub as_lookup: bool,
}

/// What kind of address `ip` is, when it is not a public one: such
/// addresses mean nothing outside their network, so they are not looked up.
pub fn address_scope(ip: IpAddr) -> Option<&'static str> {
    match ip.to_canonical() {
        IpAddr::V4(v) => {
            let [a, b, ..] = v.octets();
            if v.is_loopback() {
                Some("loopback")
            } else if v.is_private() {
                // RFC 1918 §3: 10/8, 172.16/12, 192.168/16.
                Some("private")
            } else if a == 100 && (64..128).contains(&b) {
                // RFC 6598 §7: 100.64.0.0/10, shared address space (CGNAT).
                Some("cgnat")
            } else if v.is_link_local() {
                // RFC 3927: 169.254/16.
                Some("link-local")
            } else {
                None
            }
        }
        IpAddr::V6(v) => {
            let first = v.segments().first().copied().unwrap_or(0);
            if v.is_loopback() {
                Some("loopback")
            } else if first & 0xfe00 == 0xfc00 {
                // RFC 4193 §3: unique local addresses, fc00::/7.
                Some("private")
            } else if first & 0xffc0 == 0xfe80 {
                // RFC 4291 §2.5.6: fe80::/10.
                Some("link-local")
            } else {
                None
            }
        }
    }
}

/// One address seen at a hop, and what is known about it.
struct Host {
    ip: IpAddr,
    scope: Option<&'static str>,
    name: Lookup<Option<String>>,
    asn: Lookup<Option<AsInfo>>,
    /// Labels of its last answer that carried any.
    mpls: Vec<MplsLabel>,
}

impl Host {
    fn new(ip: IpAddr, job: &MtrJob) -> Self {
        let scope = address_scope(ip);
        let public = scope.is_none();
        Self {
            ip,
            scope,
            name: if job.use_dns && public {
                Lookup::Pending
            } else {
                Lookup::Done(None)
            },
            asn: if job.as_lookup && public {
                Lookup::Pending
            } else {
                Lookup::Done(None)
            },
            mpls: Vec::new(),
        }
    }

    /// Asks again for what is still pending; `true` if something arrived.
    fn refresh(&mut self, prober: &dyn Prober) -> bool {
        let mut changed = false;
        if self.name == Lookup::Pending {
            self.name = prober.reverse_name(self.ip);
            changed |= self.name != Lookup::Pending;
        }
        if self.asn == Lookup::Pending {
            self.asn = prober.origin_as(self.ip);
            changed |= self.asn != Lookup::Pending;
        }
        changed
    }

    fn name(&self) -> Option<&str> {
        match &self.name {
            Lookup::Done(Some(n)) => Some(n),
            _ => None,
        }
    }

    fn asn(&self) -> Option<&AsInfo> {
        match &self.asn {
            Lookup::Done(Some(a)) => Some(a),
            _ => None,
        }
    }

    fn to_json(&self) -> Value {
        let asn = self.asn();
        json!({
            "address": self.ip.to_string(),
            "name": self.name(),
            "name_pending": self.name == Lookup::Pending,
            "asn": asn.map(|a| a.asn),
            "as_name": asn.and_then(|a| a.name.clone()),
            "as_prefix": asn.and_then(|a| a.prefix.clone()),
            "scope": self.scope,
            "mpls": self.mpls,
            "mpls_text": mpls_text(&self.mpls),
        })
    }
}

/// "L=24017" or "L=16005/24003" (top first), `None` without labels.
pub fn mpls_text(labels: &[MplsLabel]) -> Option<String> {
    (!labels.is_empty()).then(|| {
        let l: Vec<String> = labels.iter().map(|l| l.label.to_string()).collect();
        format!("L={}", l.join("/"))
    })
}

#[derive(Default)]
struct Hop {
    hosts: Vec<Host>,
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
                        json!(
                            h.hosts
                                .iter()
                                .map(|x| x.ip.to_string())
                                .collect::<Vec<_>>()
                        ),
                    );
                    let first = h.hosts.first();
                    o.insert("host".into(), json!(first.map(|x| x.ip.to_string())));
                    if let Some(Value::Object(f)) = first.map(Host::to_json) {
                        for k in ["name", "asn", "as_name", "scope", "mpls_text"] {
                            o.insert(k.into(), f.get(k).cloned().unwrap_or(Value::Null));
                        }
                    }
                    o.insert(
                        "hosts_info".into(),
                        Value::Array(h.hosts.iter().map(Host::to_json).collect()),
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
            "use_dns": job.use_dns,
            "as_lookup": job.as_lookup,
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
        for h in hops.values_mut() {
            for x in &mut h.hosts {
                changed |= x.refresh(prober);
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
            let known = h.hosts.len();
            match h.hosts.iter_mut().find(|x| x.ip == r.from) {
                Some(x) if !r.mpls.is_empty() => x.mpls.clone_from(&r.mpls),
                Some(_) => {}
                None if known < MAX_HOSTS => {
                    let mut x = Host::new(r.from, &job);
                    x.mpls.clone_from(&r.mpls);
                    // Asked at once: a cached name shows with the address.
                    x.refresh(prober);
                    h.hosts.push(x);
                }
                None => {}
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
                    "rtt_ms": rtt, "status": status, "mpls": mpls_text(&r.mpls),
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
    let grace = ctx.now().saturating_add(LOOKUP_GRACE);
    let pending = |hops: &BTreeMap<u8, Hop>| {
        hops.values()
            .flat_map(|h| &h.hosts)
            .any(|x| x.name == Lookup::Pending || x.asn == Lookup::Pending)
    };
    while pending(&hops) && ctx.now() < grace && ctx.sleep(Duration::from_millis(100)) {
        let mut changed = false;
        for x in hops.values_mut().flat_map(|h| &mut h.hosts) {
            changed |= x.refresh(prober);
        }
        if changed {
            ctx.summary(summary(&hops, last, reached, round));
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
        mtr_with(host, rounds, &SimProber::default())
    }

    fn mtr_with(
        host: &str,
        rounds: u32,
        prober: &dyn Prober,
    ) -> (Result<(), String>, Vec<Value>, Value) {
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
            use_dns: true,
            as_lookup: true,
        };
        let r = run(job, prober, &ctx);
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

    /// A simulated network whose names take `delay` calls to arrive.
    struct Slow {
        sim: SimProber,
        delay: u32,
        calls: std::sync::Mutex<std::collections::BTreeMap<IpAddr, u32>>,
    }

    impl Prober for Slow {
        fn describe(&self) -> String {
            "slow names".into()
        }
        fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, ProbeError> {
            self.sim.resolve(name)
        }
        fn open(
            &self,
            o: &SocketOptions,
        ) -> Result<Box<dyn corerouter_hal::probe::ProbeSocket>, ProbeError> {
            self.sim.open(o)
        }
        fn reverse_name(&self, ip: IpAddr) -> Lookup<Option<String>> {
            let mut c = self.calls.lock().unwrap();
            let n = c.entry(ip).or_default();
            *n += 1;
            if *n <= self.delay {
                Lookup::Pending
            } else {
                Lookup::Done(Some(format!("late-{ip}.example")))
            }
        }
    }

    #[test]
    fn scopes_follow_the_rfcs() {
        let s = |a: &str| address_scope(a.parse().unwrap());
        // RFC 1918 §3.
        for a in ["10.1.2.3", "172.16.0.1", "172.31.255.254", "192.168.88.1"] {
            assert_eq!(s(a), Some("private"), "{a}");
        }
        assert_eq!(s("172.32.0.1"), None);
        assert_eq!(s("192.169.0.1"), None);
        // RFC 6598 §7: exactly 100.64.0.0/10.
        assert_eq!(s("100.64.0.1"), Some("cgnat"));
        assert_eq!(s("100.127.255.254"), Some("cgnat"));
        assert_eq!(s("100.63.255.255"), None);
        assert_eq!(s("100.128.0.1"), None);
        assert_eq!(s("169.254.1.1"), Some("link-local"));
        assert_eq!(s("127.0.0.1"), Some("loopback"));
        assert_eq!(s("fd00::1"), Some("private"));
        assert_eq!(s("fe80::1"), Some("link-local"));
        assert_eq!(s("::ffff:10.0.0.1"), Some("private"));
        assert_eq!(s("8.8.8.8"), None);
        assert_eq!(s("2001:4860::8888"), None);
    }

    #[test]
    fn hops_get_names_as_numbers_scopes_and_labels() {
        let (r, events, s) = mtr("198.51.100.20", 4);
        r.unwrap();
        let hops = s["hops"].as_array().unwrap();
        // Hop 1 is private, hop 2 CGNAT: marked, never looked up.
        let h1 = &hops[0];
        if !h1["host"].is_null() {
            assert_eq!(h1["scope"], "private");
            assert!(h1["name"].is_null() && h1["asn"].is_null());
        }
        assert!(hops.iter().any(|h| h["scope"] == "cgnat" && h["asn"].is_null()));
        // Public routers: names (most of them), AS and MPLS on the lossy
        // 6-hop path (hops 3 and 4).
        assert!(hops.iter().any(|h| h["name"].as_str().is_some_and(|n| n.ends_with(".sim-transit.example"))), "{s}");
        assert!(hops.iter().any(|h| h["asn"] == 64_500 && h["as_name"] == "SIM-ACCESS"));
        assert!(hops.iter().any(|h| h["mpls_text"].as_str().is_some_and(|t| t.starts_with("L="))), "{s}");
        assert!(events.iter().any(|e| e["mpls"].is_string()));
        let last = hops.last().unwrap();
        assert_eq!(last["name"], "host-198-51-100-20.sim-dest.example");
        assert_eq!(last["asn"], 64_999);
    }

    #[test]
    fn names_arrive_later_without_holding_up_the_probes() {
        let slow = Slow {
            sim: SimProber::default(),
            delay: 3,
            calls: Default::default(),
        };
        let (r, _, s) = mtr_with("8.8.8.8", 1, &slow);
        r.unwrap();
        let last = s["hops"].as_array().unwrap().last().unwrap().clone();
        // One round, the measurement done at once; the name came during
        // the grace wait after it.
        assert_eq!(last["sent"], 1);
        assert_eq!(last["received"], 1);
        assert_eq!(last["name"], "late-8.8.8.8.example");
        // A name that never comes does not hang the task.
        let never = Slow {
            sim: SimProber::default(),
            delay: u32::MAX,
            calls: Default::default(),
        };
        let (r, _, s) = mtr_with("8.8.8.8", 1, &never);
        r.unwrap();
        let last = s["hops"].as_array().unwrap().last().unwrap().clone();
        assert!(last["name"].is_null());
        assert_eq!(last["hosts_info"][0]["name_pending"], true);
    }
}
