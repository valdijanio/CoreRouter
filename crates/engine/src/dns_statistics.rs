//! The LAN forwarder as the engine sees it (G4.1e): its statistics, which
//! the daemon registers with [`Session::set_dns_statistics`] (without a
//! daemon nothing counts and `ip.dns.statistics.print` shows zeros), and
//! the networks `allowed_from` stands for now, DHCP-learned and pool
//! addresses included.
//!
//! G4.1h: once a second (the clock's tick) the counters are read into a
//! ring of the last [`RING`] seconds: the window's "now" values (queries
//! per second, the time to answer, each upstream's timeouts) are the
//! difference between two readings, and so is the `dns` graph series. What
//! the resolver counts since the daemon started (the upstreams, the cache's
//! evictions) is shown since the last reset by keeping a base at reset.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;

use corerouter_model::Config;
use corerouter_proto_dns::histogram::Hist;
use corerouter_proto_dns::resolver::ServerStats;
use corerouter_proto_dns::server::{Counters, Statistics, allowed_networks};
use ipnet::IpNet;

use crate::Session;
use crate::graph::GraphDb;
use crate::graph::dns::DNS_SOURCES;

/// Seconds of readings kept (a minute, and the one before it).
pub const RING: usize = 61;

/// What one second's reading keeps.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Reading {
    /// Unix time.
    pub t: u64,
    pub queries: u64,
    pub cache: u64,
    /// Answered by the cache, an upstream or stale (needed the resolver).
    pub resolved: u64,
    pub servfail: u64,
    /// Refused for `max_concurrent_queries` (the limit was hit).
    pub busy: u64,
    pub latency: Hist,
    pub in_flight: u64,
    pub socket_drops: u64,
    /// The cache's evictions (since the daemon started).
    pub evicted: u64,
    /// Each upstream as the resolver counts it (since the daemon started).
    pub upstreams: Vec<(IpAddr, ServerStats)>,
}

impl Reading {
    fn of(t: u64, c: &Counters, upstreams: Vec<(IpAddr, ServerStats)>, evicted: u64) -> Self {
        let got = |k: &str| c.answered.get(k).copied().unwrap_or(0);
        Self {
            t,
            queries: c.queries,
            cache: got("cache"),
            resolved: got("cache") + got("upstream") + got("stale"),
            servfail: c.rcodes.get("servfail").copied().unwrap_or(0),
            busy: got("busy"),
            latency: c.latency,
            in_flight: c.in_flight,
            socket_drops: c.socket_drops,
            evicted,
            upstreams,
        }
    }
}

/// What happened between two readings.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Window {
    pub secs: u64,
    pub queries: u64,
    pub cache: u64,
    pub resolved: u64,
    pub servfail: u64,
    pub busy: u64,
    pub latency: Hist,
    pub socket_drops: u64,
    pub evicted: u64,
    /// Per upstream: the difference of its counters and histogram.
    pub upstreams: Vec<(IpAddr, ServerStats)>,
}

/// `new - old` of every counter; a counter that went down (a reset in
/// between) counts from zero.
pub fn window(old: &Reading, new: &Reading) -> Window {
    let d = |a: u64, b: u64| if a >= b { a - b } else { a };
    Window {
        secs: new.t.saturating_sub(old.t),
        queries: d(new.queries, old.queries),
        cache: d(new.cache, old.cache),
        resolved: d(new.resolved, old.resolved),
        servfail: d(new.servfail, old.servfail),
        busy: d(new.busy, old.busy),
        latency: if new.queries >= old.queries { new.latency.since(&old.latency) } else { new.latency },
        socket_drops: d(new.socket_drops, old.socket_drops),
        evicted: d(new.evicted, old.evicted),
        upstreams: new
            .upstreams
            .iter()
            .map(|(ip, n)| {
                let base = old.upstreams.iter().find(|(o, _)| o == ip).map(|(_, s)| *s).unwrap_or_default();
                (*ip, minus(n, &base))
            })
            .collect(),
    }
}

/// `now - base` of a server's counters and histogram (the rest as now).
pub fn minus(now: &ServerStats, base: &ServerStats) -> ServerStats {
    let d = |a: u64, b: u64| if a >= b { a - b } else { a };
    ServerStats {
        answers: d(now.answers, base.answers),
        failures: d(now.failures, base.failures),
        timeouts: d(now.timeouts, base.timeouts),
        servfails: d(now.servfails, base.servfails),
        truncated: d(now.truncated, base.truncated),
        rtt: now.rtt.since(&base.rtt),
        ..*now
    }
}

#[derive(Default)]
struct DnsStatsRuntime {
    stats: Option<Arc<Statistics>>,
    /// Unix time counting started (registration or the last reset).
    since: Option<u64>,
    /// The last [`RING`] seconds, oldest first.
    ring: VecDeque<Reading>,
    /// What the resolver had counted at the last reset: per server, and
    /// the cache's evictions and expiries.
    upstream_base: Vec<(IpAddr, ServerStats)>,
    cache_base: (u64, u64),
}

impl Session {
    /// The daemon's forwarder counts into `stats`.
    pub fn set_dns_statistics(&mut self, stats: Arc<Statistics>) {
        let now = self.hal_now();
        let base = self.dns_resolver_counts();
        if let Some(rt) = self.ext_mut::<DnsStatsRuntime>() {
            rt.stats = Some(stats);
            rt.since = now;
            rt.ring.clear();
            (rt.upstream_base, rt.cache_base) = base;
        }
    }

    /// The forwarder's statistics and since when they count.
    pub fn dns_statistics(&self) -> Option<(Arc<Statistics>, Option<u64>)> {
        let rt = self.ext::<DnsStatsRuntime>()?;
        Some((rt.stats.clone()?, rt.since))
    }

    /// The readings of the last seconds, oldest first (empty before the
    /// first tick).
    pub fn dns_readings(&self) -> Vec<Reading> {
        self.ext::<DnsStatsRuntime>()
            .map(|rt| rt.ring.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// What the resolver had counted at the last reset (servers, and the
    /// cache's evictions and expiries).
    pub fn dns_bases(&self) -> (Vec<(IpAddr, ServerStats)>, (u64, u64)) {
        self.ext::<DnsStatsRuntime>()
            .map(|rt| (rt.upstream_base.clone(), rt.cache_base))
            .unwrap_or_default()
    }

    /// Back to zero; false without a forwarder.
    pub(crate) fn dns_statistics_reset(&mut self) -> bool {
        let now = self.hal_now();
        let base = self.dns_resolver_counts();
        let Some(rt) = self.ext_mut::<DnsStatsRuntime>() else {
            return false;
        };
        let Some(stats) = &rt.stats else {
            return false;
        };
        stats.reset();
        rt.since = now;
        rt.ring.clear();
        (rt.upstream_base, rt.cache_base) = base;
        true
    }

    /// The resolver's counts now: per server, and the cache's (evicted,
    /// expired).
    fn dns_resolver_counts(&self) -> (Vec<(IpAddr, ServerStats)>, (u64, u64)) {
        let Some(b) = self.dns_backend() else {
            return (Vec::new(), (0, 0));
        };
        let cache = b.cache_stats().map_or((0, 0), |c| (c.evicted, c.expired));
        (b.server_stats(), cache)
    }

    /// One second (G4.1h): a reading of the counters into the ring, and a
    /// point of the `dns` graph series. Nothing without a forwarder.
    pub(crate) fn dns_tick(&mut self) {
        let Some(now) = self.now() else { return };
        let Some((stats, _)) = self.dns_statistics() else {
            if let Some(db) = self.ext_mut::<GraphDb>() {
                let cfg = corerouter_model::graphing::Graphing::default();
                db.sample_dns(now, &cfg, None);
            }
            return;
        };
        let counters = stats.totals();
        let (upstreams, evicted) = match self.dns_backend() {
            Some(b) => (b.server_stats(), b.cache_stats().map_or(0, |c| c.evicted)),
            None => (Vec::new(), 0),
        };
        let reading = Reading::of(now, &counters, upstreams, evicted);
        let point = self
            .ext::<DnsStatsRuntime>()
            .and_then(|rt| rt.ring.back())
            .filter(|prev| now > prev.t && now - prev.t <= crate::graph::HEARTBEAT)
            .map(|prev| point(&window(prev, &reading), reading.in_flight));
        if let Some(rt) = self.ext_mut::<DnsStatsRuntime>() {
            // Registered before the clock had a time (the daemon's first
            // second): counting started at the first tick.
            rt.since.get_or_insert(now);
            if rt.ring.back().is_some_and(|p| p.t >= now) {
                // Two ticks in one second: the first stays.
                return;
            }
            rt.ring.push_back(reading);
            while rt.ring.len() > RING {
                rt.ring.pop_front();
            }
        }
        let cfg = &self.store().running().system.graphing;
        if !cfg.enabled {
            return;
        }
        let cfg = cfg.clone();
        if let (Some(v), Some(db)) = (point, self.ext_mut::<GraphDb>()) {
            db.sample_dns(now, &cfg, Some(v));
        }
    }

    /// What `allowed_from` of `cfg` stands for now: the interface lists'
    /// static addresses, the ones DHCP clients learned (RouterOS flag D)
    /// and the IPv6 addresses taken from a delegated pool, once it has a
    /// prefix. A LAN whose address comes from DHCP or a pool is then
    /// allowed without listing its prefix by hand.
    pub fn dns_allowed_networks(&self, cfg: &Config) -> Vec<IpNet> {
        match self.effective(cfg) {
            Cow::Borrowed(c) => allowed_networks(c),
            Cow::Owned(mut c) => {
                // The pools' addresses that stay are resolved: whole now.
                for a in &mut c.ip.addresses {
                    a.from_pool = None;
                }
                allowed_networks(&c)
            }
        }
    }
}

/// `part` of `whole` in percent; `None` when `whole` is zero.
pub fn percent(part: u64, whole: u64) -> Option<f64> {
    (whole > 0).then(|| part as f64 * 100.0 / whole as f64)
}

/// A graph point (in [`DNS_SOURCES`] order) from one second's window;
/// unknown (NaN) where nothing was counted.
fn point(w: &Window, in_flight: u64) -> [f32; DNS_SOURCES.len()] {
    let secs = w.secs.max(1) as f32;
    let or_nan = |v: Option<f64>| v.map_or(f32::NAN, |v| v as f32);
    let ms = |q: f64| w.latency.quantile_us(q).map(|us| us as f64 / 1000.0);
    [
        w.queries as f32 / secs,
        or_nan(percent(w.cache, w.resolved)),
        or_nan(percent(w.servfail, w.queries)),
        or_nan(ms(0.5)),
        or_nan(ms(0.99)),
        in_flight as f32,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reading(t: u64, queries: u64, cache: u64, resolved: u64) -> Reading {
        Reading {
            t,
            queries,
            cache,
            resolved,
            ..Reading::default()
        }
    }

    #[test]
    fn windows_and_points() {
        let a = reading(100, 1000, 300, 400);
        let mut b = reading(101, 1200, 450, 600);
        b.latency.add_us(80);
        b.servfail = 10;
        let w = window(&a, &b);
        assert_eq!((w.secs, w.queries, w.cache, w.resolved, w.servfail), (1, 200, 150, 200, 10));
        let p = point(&w, 3);
        assert_eq!(p[0], 200.0);
        assert_eq!(p[1], 75.0);
        assert_eq!(p[2], 5.0);
        assert!(p[3] <= 0.1, "{}", p[3]);
        assert_eq!(p[5], 3.0);
        // A reset in between: the counters went down, the window counts from zero.
        let c = reading(102, 50, 10, 20);
        let w = window(&b, &c);
        assert_eq!((w.queries, w.cache), (50, 10));
        // Nothing asked: unknown, not zero.
        let w = window(&c, &reading(103, 50, 10, 20));
        assert!(point(&w, 0)[1].is_nan());
    }

    #[test]
    fn server_counts_since_a_base() {
        let mut base = ServerStats { answers: 10, timeouts: 2, ..ServerStats::default() };
        base.rtt.add_ms(5);
        let mut now = ServerStats { answers: 25, timeouts: 3, srtt_ms: Some(7), ..ServerStats::default() };
        now.rtt = base.rtt;
        now.rtt.add_ms(40);
        let d = minus(&now, &base);
        assert_eq!((d.answers, d.timeouts, d.srtt_ms), (15, 1, Some(7)));
        assert_eq!(d.rtt.total(), 1);
        // The daemon restarted (counts below the base): from zero.
        let d = minus(&ServerStats { answers: 4, ..ServerStats::default() }, &base);
        assert_eq!(d.answers, 4);
    }
}
