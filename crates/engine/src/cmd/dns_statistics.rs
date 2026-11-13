//! /ip dns statistics (G4.1e, G4.1h): what the LAN forwarder did with the
//! queries since the last reset. RouterOS v7 has no such menu (only the
//! adlist's `match-count`); the names follow its `print`/`reset` style and
//! the counters Unbound (`unbound-control stats`, its histogram), PowerDNS
//! Recursor (`rec_control get-all`, `top-remotes`) and dnsdist keep.
//!
//! G4.1h adds what an operator reads first when DNS is slow or failing:
//! the time to answer (histogram, median, 99th percentile), the queries
//! waiting for an upstream and how often `max_concurrent_queries` was hit,
//! UDP/TCP over IPv4/IPv6, truncated replies, the kernel's drops on the
//! sockets, malformed messages, the extended error each failure stands for
//! (RFC 8914), each upstream's timeouts, SERVFAIL, TC and round trips, the
//! cache's evictions and types, the "now" values of the last minute and
//! the warnings the engine draws from them (the window only shows them).

use std::net::IpAddr;

use corerouter_proto_dns::histogram::{EDGES_US, Hist, RANGES};
use corerouter_proto_dns::resolver::ServerStats;
use corerouter_proto_dns::server::{Snapshot, ede_name, type_name};
use serde_json::{Map, Value, json};

use super::args::opt_u32;
use super::{CommandSpec, always};
use crate::dns_statistics::{Reading, Window, minus, percent, window};
use crate::{EngineError, Result, Session};

/// Clients listed by default, and at most.
const TOP: u32 = 10;
const MAX_TOP: u32 = 100;
/// Always shown, even at zero (the stages every forwarder has).
const ANSWERED: [&str; 6] = ["cache", "static", "upstream", "stale", "refused", "limit"];
/// Seconds the "now" queries per second average over.
const NOW_SECS: u64 = 10;
/// Warnings: an upstream whose timeouts pass this share of what it was
/// asked in the last minute (and at least [`MIN_EVENTS`] of them)…
const TIMEOUT_WARN_PERCENT: f64 = 5.0;
/// …SERVFAIL past this share of the queries of the last minute (with at
/// least [`MIN_QUERIES`] queries)…
const SERVFAIL_WARN_PERCENT: f64 = 5.0;
const MIN_QUERIES: u64 = 20;
const MIN_EVENTS: u64 = 3;
/// …cache evictions in the last minute past this many.
const EVICT_WARN: u64 = 10;
/// An upstream is `slow` when its 95th percentile passes this (ms).
const SLOW_MS: u64 = 500;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "ip.dns.statistics.print", "DNS Statistics", [], None,
        "{top?: int 1..100 (clients listed, default 10)} → {resolver: router|simulated, allow_remote_requests, since (unix time counting started), elapsed_secs, queries, udp, tcp, transport: {udp4, udp6, tcp4, tcp6, truncated, socket_drops}, malformed, answered: {cache, static, upstream, stale, refused, limit, busy, malformed, …}, cache_hit_percent, rcodes: {noerror, nxdomain, servfail, refused, formerr, notimp, dropped, …}, ede: [{code, name, replies}] (RFC 8914, most first), types: [{type, queries}], latency: {p50_ms, p90_ms, p99_ms, buckets: [{below_us (null: the last, open), replies}], ranges: [{range (ms), replies}]} (since the reset), in_flight, in_flight_peak, max_concurrent_queries, limit_hits, now: {window_secs, queries_per_sec, cache_hit_percent, servfail_percent, latency_p50_ms, latency_p99_ms, evictions}|null (the last minute; null before the first readings), cache: {entries, used_bytes, max_bytes, evicted, expired, stale_served, types: [{type, entries}]}|null, clients: [{address, queries, refused, error}], clients_tracked, clients_replaced, upstreams: [{server, via (udp|dot|doh), answers, answers_per_sec, srtt_ms, rtt_p50_ms, rtt_p95_ms, timeouts, timeouts_percent, servfails, servfail_percent, truncated, failures, down, state (up|slow|down), state_secs, rtt_ranges: [6 counts, ms ranges as latency.ranges]}], rtt_ranges: [{range, replies}] (all upstreams), warnings: [{key (upstream_down|upstream_timeouts|servfail_high|limit_reached|cache_evicting|socket_drops), severity (warning|error), text, args}]}",
        always, print),
    cmd!(
        "ip.dns.statistics.reset",
        "Reset Statistics",
        [],
        None,
        "{} → {reset: bool (false: no forwarder counting)}",
        always,
        reset
    ),
];

fn print(s: &mut Session, p: &Value) -> Result<Value> {
    let top = opt_u32(p, "top")?.unwrap_or(TOP);
    if !(1..=MAX_TOP).contains(&top) {
        return Err(EngineError::bad("top", format!("must be 1..{MAX_TOP}")));
    }
    let (snap, since, resolver) = match s.dns_statistics() {
        Some((st, since)) => (
            st.snapshot(usize::try_from(top).unwrap_or(10)),
            since,
            "router",
        ),
        None => (Snapshot::default(), None, "simulated"),
    };
    let mut out = render(&snap);
    let backend = s.dns_backend();
    let servers = backend.as_ref().map(|b| b.server_stats()).unwrap_or_default();
    let cache = backend.as_ref().and_then(|b| b.cache_stats());
    let clock = backend.as_ref().and_then(|b| b.clock_ms());
    let (bases, (evicted_base, expired_base)) = s.dns_bases();
    let readings = s.dns_readings();
    let minute = last(&readings, 60);
    let dns = &s.store().running().ip.dns;
    let max_queries = dns.max_concurrent_queries;
    let Some(o) = out.as_object_mut() else {
        return Ok(out);
    };
    o.insert("resolver".into(), json!(resolver));
    o.insert("allow_remote_requests".into(), json!(dns.allow_remote_requests));
    o.insert("since".into(), json!(since));
    let elapsed = since.zip(s.hal_now()).map(|(a, b)| b.saturating_sub(a));
    o.insert("elapsed_secs".into(), json!(elapsed));
    o.insert("max_concurrent_queries".into(), json!(max_queries));
    o.insert("now".into(), now(&readings, minute.as_ref()));
    let stale = snap.counters.answered.get("stale").copied().unwrap_or(0);
    o.insert(
        "cache".into(),
        cache.map_or(Value::Null, |c| {
            json!({
                "entries": c.entries,
                "used_bytes": c.used_bytes,
                "max_bytes": c.budget_bytes,
                "evicted": c.evicted.saturating_sub(evicted_base),
                "expired": c.expired.saturating_sub(expired_base),
                "stale_served": stale,
                "types": c.by_type.iter().map(|(t, n)| json!({"type": type_name(*t), "entries": n})).collect::<Vec<_>>(),
            })
        }),
    );
    // Each server the resolver knows, since the last reset, with what it
    // measured (the answers here are the clients' queries it served).
    let mut ups: Vec<Value> = Vec::new();
    let mut all_rtt = Hist::default();
    let mut warnings: Vec<Value> = Vec::new();
    for (ip, st) in &servers {
        let base = bases.iter().find(|(b, _)| b == ip).map(|(_, b)| *b).unwrap_or_default();
        let d = minus(st, &base);
        all_rtt.merge(&d.rtt);
        let recent = minute.as_ref().and_then(|w| w.upstreams.iter().find(|(u, _)| u == ip)).map(|(_, r)| *r);
        let row = upstream(*ip, st, &d, recent.as_ref(), minute.as_ref().map_or(0, |w| w.secs), clock, &snap);
        if let Some(w) = upstream_warning(*ip, &row, recent.as_ref()) {
            warnings.push(w);
        }
        ups.push(row);
    }
    for (ip, n) in &snap.counters.upstreams {
        if !servers.iter().any(|(s, _)| s == ip) {
            ups.push(json!({"server": ip, "via": "udp", "answers": n, "srtt_ms": null,
                "failures": 0, "down": false, "state": "up", "state_secs": null}));
        }
    }
    o.insert("upstreams".into(), Value::Array(ups));
    o.insert("rtt_ranges".into(), ranges(&all_rtt));
    if let Some(w) = &minute {
        warnings.extend(minute_warnings(w, max_queries));
    }
    o.insert("warnings".into(), Value::Array(warnings));
    Ok(out)
}

/// The window over the last `secs` seconds of `readings` (the newest
/// against the oldest within reach); `None` with fewer than two.
fn last(readings: &[Reading], secs: u64) -> Option<Window> {
    let new = readings.last()?;
    let old = readings
        .iter()
        .find(|r| new.t.saturating_sub(r.t) <= secs)
        .filter(|r| r.t < new.t)?;
    Some(window(old, new))
}

/// The "now" values: queries per second over [`NOW_SECS`], the rest over
/// the last minute.
fn now(readings: &[Reading], minute: Option<&Window>) -> Value {
    let Some(m) = minute else { return Value::Null };
    let qps = last(readings, NOW_SECS).map(|w| w.queries as f64 / w.secs.max(1) as f64);
    let ms = |q: f64| m.latency.quantile_us(q).map(us_to_ms);
    json!({
        "window_secs": m.secs,
        "queries_per_sec": qps.map(round1),
        "cache_hit_percent": percent(m.cache, m.resolved).map(round1),
        "servfail_percent": percent(m.servfail, m.queries).map(round1),
        "latency_p50_ms": ms(0.5),
        "latency_p99_ms": ms(0.99),
        "evictions": m.evicted,
    })
}

fn us_to_ms(us: u64) -> f64 {
    (us as f64 / 10.0).round() / 100.0
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

/// One upstream's row: counts since the reset (`d`), the rate and the
/// state from the last minute (`recent`, over `secs`).
fn upstream(
    ip: IpAddr,
    st: &ServerStats,
    d: &ServerStats,
    recent: Option<&ServerStats>,
    secs: u64,
    clock: Option<u64>,
    snap: &Snapshot,
) -> Value {
    let asked = d.answers + d.failures;
    // The minute's round trips when it had answers, else since the reset.
    let rtt = recent.filter(|r| r.rtt.total() > 0).map_or(d.rtt, |r| r.rtt);
    let p = |q: f64| rtt.quantile_us(q).map(us_to_ms);
    let p95 = rtt.quantile_us(0.95);
    let recent_asked = recent.map_or(0, |r| r.answers + r.failures);
    let recent_timeouts = recent.map_or(0, |r| r.timeouts);
    let down = st.down_until_ms > 0;
    let slow = p95.is_some_and(|us| us >= SLOW_MS * 1000)
        || percent(recent_timeouts, recent_asked).is_some_and(|p| p >= TIMEOUT_WARN_PERCENT * 2.0);
    let state = if down {
        "down"
    } else if slow {
        "slow"
    } else {
        "up"
    };
    let state_secs = clock
        .filter(|_| st.changed_ms > 0)
        .map(|c| c.saturating_sub(st.changed_ms) / 1000);
    json!({
        "server": ip,
        "via": st.via.as_str(),
        "answers": snap.counters.upstreams.get(&ip).copied().unwrap_or(d.answers),
        "answers_per_sec": recent.filter(|_| secs > 0).map(|r| round1(r.answers as f64 / secs as f64)),
        "srtt_ms": st.srtt_ms,
        "rtt_p50_ms": p(0.5),
        "rtt_p95_ms": p(0.95),
        "timeouts": d.timeouts,
        "timeouts_percent": percent(d.timeouts, asked).map(round1),
        "servfails": d.servfails,
        "servfail_percent": percent(d.servfails, asked).map(round1),
        "truncated": d.truncated,
        "failures": d.failures,
        "down": down,
        "state": state,
        "state_secs": state_secs,
        "rtt_ranges": d.rtt.ranges(),
    })
}

fn warning(key: &str, severity: &str, text: String, args: Value) -> Value {
    json!({"key": key, "severity": severity, "text": text, "args": args})
}

/// An upstream down, or timing out in the last minute.
fn upstream_warning(ip: IpAddr, row: &Value, recent: Option<&ServerStats>) -> Option<Value> {
    if row.get("down").and_then(Value::as_bool) == Some(true) {
        return Some(warning(
            "upstream_down",
            "error",
            format!("Upstream {ip} is down: it failed and is asked last for a minute"),
            json!({"server": ip.to_string()}),
        ));
    }
    let r = recent?;
    let asked = r.answers + r.failures;
    let p = percent(r.timeouts, asked)?;
    (r.timeouts >= MIN_EVENTS && p >= TIMEOUT_WARN_PERCENT).then(|| {
        let p = format!("{:.0}", p);
        warning(
            "upstream_timeouts",
            "warning",
            format!("Upstream {ip}: {p} % of the queries timed out in the last minute"),
            json!({"server": ip.to_string(), "percent": p}),
        )
    })
}

/// SERVFAIL, the concurrency limit, the cache and the sockets in the last
/// minute.
fn minute_warnings(w: &Window, max_queries: u32) -> Vec<Value> {
    let mut out = Vec::new();
    if let Some(p) = percent(w.servfail, w.queries).filter(|p| w.queries >= MIN_QUERIES && *p >= SERVFAIL_WARN_PERCENT) {
        let p = format!("{p:.0}");
        out.push(warning(
            "servfail_high",
            "warning",
            format!("{p} % of the replies in the last minute were SERVFAIL"),
            json!({"percent": p}),
        ));
    }
    if w.busy > 0 {
        out.push(warning(
            "limit_reached",
            "warning",
            format!(
                "Max Concurrent Queries ({max_queries}) was reached: {} queries got SERVFAIL in the last minute",
                w.busy
            ),
            json!({"count": w.busy.to_string(), "max": max_queries.to_string()}),
        ));
    }
    if w.evicted >= EVICT_WARN {
        out.push(warning(
            "cache_evicting",
            "warning",
            format!("The cache is full: {} answers still valid were evicted in the last minute", w.evicted),
            json!({"count": w.evicted.to_string()}),
        ));
    }
    if w.socket_drops > 0 {
        out.push(warning(
            "socket_drops",
            "warning",
            format!("The kernel dropped {} queries on the UDP sockets in the last minute", w.socket_drops),
            json!({"count": w.socket_drops.to_string()}),
        ));
    }
    out
}

fn ranges(h: &Hist) -> Value {
    Value::Array(
        RANGES
            .iter()
            .zip(h.ranges())
            .map(|((name, _), n)| json!({"range": name, "replies": n}))
            .collect(),
    )
}

/// The counters as `print` shows them.
fn render(snap: &Snapshot) -> Value {
    let c = &snap.counters;
    let mut answered = Map::new();
    for k in ANSWERED {
        answered.insert(k.into(), json!(c.answered.get(k).copied().unwrap_or(0)));
    }
    for (k, n) in &c.answered {
        answered.insert((*k).into(), json!(n));
    }
    let got = |k: &str| c.answered.get(k).copied().unwrap_or(0);
    // Of the queries that needed the resolver, how many the cache served.
    let resolved = got("cache") + got("upstream") + got("stale");
    let hit = (got("cache") * 100).checked_div(resolved);
    let types = snap.types();
    let mut ede: Vec<(u16, u64)> = c.ede.iter().map(|(k, n)| (*k, *n)).collect();
    ede.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let lat = &c.latency;
    let ms = |q: f64| lat.quantile_us(q).map(us_to_ms);
    let buckets: Vec<Value> = lat
        .0
        .iter()
        .enumerate()
        .map(|(i, n)| json!({"below_us": EDGES_US.get(i), "replies": n}))
        .collect();
    json!({
        "queries": c.queries,
        "udp": c.udp,
        "tcp": c.tcp,
        "transport": {"udp4": c.udp4, "udp6": c.udp6, "tcp4": c.tcp4, "tcp6": c.tcp6,
            "truncated": c.truncated, "socket_drops": c.socket_drops},
        "malformed": c.malformed,
        "answered": answered,
        "cache_hit_percent": hit,
        "rcodes": c.rcodes,
        "ede": ede.iter().map(|(code, n)| json!({"code": code, "name": ede_name(*code).unwrap_or("other"), "replies": n})).collect::<Vec<_>>(),
        "types": types.iter().map(|(t, n)| json!({"type": t, "queries": n})).collect::<Vec<_>>(),
        "latency": {"p50_ms": ms(0.5), "p90_ms": ms(0.9), "p99_ms": ms(0.99), "buckets": buckets, "ranges": ranges(lat)},
        "in_flight": c.in_flight,
        "in_flight_peak": c.in_flight_peak,
        "limit_hits": got("busy"),
        "clients": snap.top_clients.iter().map(|(ip, st)| json!({"address": ip,
            "queries": st.queries, "refused": st.refused, "error": st.error})).collect::<Vec<_>>(),
        "clients_tracked": snap.clients_tracked,
        "clients_replaced": c.clients_replaced,
    })
}

fn reset(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(json!({"reset": s.dns_statistics_reset()}))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;

    use corerouter_proto_dns::resolver::{Resolver, Settings};
    use corerouter_proto_dns::server::{Forwarder, Start, Statistics};
    use super::*;

    const A: u16 = 1;
    const AAAA: u16 = 28;

    /// A query in wire format (RFC 1035 §4.1): header, one question, IN.
    fn ask(name: &str, qtype: u16) -> Vec<u8> {
        let mut m = vec![0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.trim_end_matches('.').split('.') {
            m.push(u8::try_from(label.len()).unwrap());
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&qtype.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m
    }

    /// A forwarder with one static entry, counting into the session's
    /// statistics as the daemon wires it.
    fn wired(s: &mut Session) -> Forwarder {
        s.execute("ip.dns.static.add", &json!({"name": "nas.lan", "address": "192.168.88.2"}))
            .unwrap();
        let cfg = s.store().running().clone();
        let f = Forwarder::new(Arc::new(Resolver::new(Settings::new(&cfg.ip.dns, &[]))));
        f.configure(Arc::new(cfg), vec!["192.168.88.0/24".parse().unwrap()]);
        s.set_dns_statistics(f.state::<Statistics>());
        f
    }

    fn send(f: &Forwarder, from: [u8; 4], name: &str, t: u16) {
        match f.start(&ask(name, t), IpAddr::from(from), false, 1000) {
            Start::Done(_) => {}
            // Needs an upstream (none configured): SERVFAIL, still counted.
            Start::Pending(p) => drop(f.fail(*p)),
        }
    }

    #[test]
    fn counts_and_resets() {
        let mut s = Session::virtual_lab();
        let f = wired(&mut s);
        for _ in 0..3 {
            send(&f, [192, 168, 88, 10], "nas.lan.", A);
        }
        send(&f, [192, 168, 88, 11], "nas.lan.", AAAA);
        send(&f, [203, 0, 113, 9], "nas.lan.", A);
        let out = s.execute("ip.dns.statistics.print", &json!({"top": 2})).unwrap();
        assert_eq!(out["resolver"], "router");
        assert_eq!(out["queries"], 5);
        assert_eq!(out["udp"], 5);
        assert_eq!(out["answered"]["static"], 3);
        assert_eq!(out["answered"]["refused"], 1, "outside allowed_from");
        assert_eq!(out["answered"]["busy"], 1, "AAAA went upstream: no room");
        assert_eq!(out["answered"]["cache"], 0, "always listed");
        assert_eq!(out["rcodes"]["noerror"], 3);
        assert_eq!(out["rcodes"]["refused"], 1);
        assert_eq!(out["types"][0], json!({"type": "A", "queries": 4}));
        let clients = out["clients"].as_array().unwrap();
        assert_eq!(clients.len(), 2, "top 2 of 3");
        assert_eq!(clients[0], json!({"address": "192.168.88.10", "queries": 3,
            "refused": 0, "error": 0}));
        assert_eq!(out["clients_tracked"], 3);
        assert_eq!(s.execute("ip.dns.statistics.reset", &json!({})).unwrap()["reset"], true);
        let out = s.execute("ip.dns.statistics.print", &json!({})).unwrap();
        assert_eq!(out["queries"], 0);
        assert_eq!(out["clients"], json!([]));
        assert_eq!(out["cache_hit_percent"], Value::Null);
    }

    #[test]
    fn without_a_daemon_all_zero() {
        let mut s = Session::virtual_lab();
        let out = s.execute("ip.dns.statistics.print", &json!({})).unwrap();
        assert_eq!(out["resolver"], "simulated");
        assert_eq!(out["queries"], 0);
        assert_eq!(out["answered"]["upstream"], 0);
        assert_eq!(s.execute("ip.dns.statistics.reset", &json!({})).unwrap()["reset"], false);
    }

    #[test]
    fn bad_top_is_refused() {
        let mut s = Session::virtual_lab();
        for p in [json!({"top": 0}), json!({"top": 101}), json!({"top": "x"}),
            json!({"tpo": 3})]
        {
            assert!(s.execute("ip.dns.statistics.print", &p).is_err(), "{p}");
        }
    }

    /// A resolver with one upstream that timed out a lot, and a full cache.
    struct Lab {
        up: std::sync::Mutex<ServerStats>,
        evicted: std::sync::Mutex<u64>,
    }

    impl crate::dns::DnsBackend for Lab {
        fn lookup(&self, _: &str) -> std::result::Result<Vec<IpAddr>, corerouter_proto_dns::resolver::ResolveError> {
            Ok(Vec::new())
        }
        fn cache_rows(&self) -> Vec<corerouter_model::dns::CacheRow> {
            Vec::new()
        }
        fn cache_used_bytes(&self) -> usize {
            0
        }
        fn flush(&self) {}
        fn server_stats(&self) -> Vec<(IpAddr, ServerStats)> {
            vec![([192, 0, 2, 53].into(), *self.up.lock().unwrap())]
        }
        fn cache_stats(&self) -> Option<corerouter_proto_dns::cache::CacheStats> {
            Some(corerouter_proto_dns::cache::CacheStats {
                entries: 2,
                used_bytes: 1500,
                budget_bytes: 2048,
                evicted: *self.evicted.lock().unwrap(),
                expired: 1,
                by_type: vec![(1, 2)],
            })
        }
        fn clock_ms(&self) -> Option<u64> {
            Some(90_000)
        }
    }

    #[test]
    fn upstreams_cache_now_and_warnings() {
        let mut s = Session::virtual_lab();
        let f = wired(&mut s);
        let lab = Arc::new(Lab {
            up: std::sync::Mutex::new(ServerStats { answers: 100, ..ServerStats::default() }),
            evicted: std::sync::Mutex::new(5),
        });
        s.set_dns_backend(lab.clone());
        // Counted since the reset: what the resolver had before is the base.
        assert!(s.execute("ip.dns.statistics.reset", &json!({})).unwrap()["reset"] == true);
        let t0 = 1_800_000_000;
        s.tick(t0);
        for _ in 0..30 {
            send(&f, [192, 168, 88, 10], "nas.lan.", A);
        }
        // Over max_concurrent_queries: SERVFAIL (busy).
        send(&f, [192, 168, 88, 10], "www.example.", A);
        send(&f, [203, 0, 113, 9], "nas.lan.", A);
        f.statistics().answered_in(70);
        f.statistics().answered_in(25_000);
        f.statistics().set_in_flight(4);
        {
            let mut up = lab.up.lock().unwrap();
            up.answers += 20;
            up.failures += 10;
            up.timeouts += 10;
            up.down_until_ms = 0;
            for _ in 0..20 {
                up.rtt.add_ms(30);
            }
            up.via = corerouter_proto_dns::resolver::Via::Tls;
        }
        *lab.evicted.lock().unwrap() += 40;
        s.tick(t0 + 1);
        // The next second closes the graph's slot of the first.
        s.tick(t0 + 2);
        let out = s.execute("ip.dns.statistics.print", &json!({})).unwrap();
        assert!(out["since"].is_u64(), "counting has a start: {}", out["since"]);
        assert_eq!(out["queries"], 32);
        assert_eq!(out["transport"]["udp4"], 32);
        assert_eq!(out["limit_hits"], 1);
        assert_eq!(out["in_flight_peak"], 4);
        assert_eq!(out["latency"]["ranges"][0], json!({"range": "<1", "replies": 1}));
        assert_eq!(out["latency"]["ranges"][2], json!({"range": "10-100", "replies": 1}));
        assert!(out["latency"]["p99_ms"].as_f64().unwrap() >= 20.0);
        assert_eq!(out["ede"], json!([{"code": 18, "name": "Prohibited", "replies": 1}]));
        let now = &out["now"];
        assert_eq!(now["window_secs"], 2);
        assert_eq!(now["queries_per_sec"], 16.0);
        assert_eq!(now["evictions"], 40);
        let cache = &out["cache"];
        assert_eq!(cache["evicted"], 40, "5 were before the reset");
        assert_eq!(cache["types"][0], json!({"type": "A", "entries": 2}));
        let up = &out["upstreams"][0];
        assert_eq!(up["server"], "192.0.2.53");
        assert_eq!(up["via"], "dot");
        assert_eq!((up["answers"].clone(), up["timeouts"].clone()), (json!(20), json!(10)));
        assert_eq!(up["timeouts_percent"], 33.3);
        assert_eq!(up["state"], "slow", "a third timed out");
        assert_eq!(up["rtt_ranges"][2], 20, "10-100 ms");
        assert_eq!(out["rtt_ranges"][2]["replies"], 20);
        let keys: Vec<&str> = out["warnings"].as_array().unwrap().iter().map(|w| w["key"].as_str().unwrap()).collect();
        for k in ["upstream_timeouts", "limit_reached", "cache_evicting"] {
            assert!(keys.contains(&k), "{k} in {keys:?}");
        }
        assert!(!keys.contains(&"servfail_high"), "1 of 32 is under 5 %");
        // The DNS series of the graphs: one point a second.
        let g = s.execute("system.graph.query", &json!({"series": "dns", "range": "hour"})).unwrap();
        let st = &g["series"][0]["stats"];
        assert_eq!(st["queries"]["max"], 32.0, "{g}");
        assert_eq!(st["queries"]["max_at"], t0 + 1);
        assert_eq!(st["in_flight"]["current"], 4.0);
        let print = s.execute("system.graph.print", &json!({})).unwrap();
        assert!(print["series"].as_array().unwrap().iter().any(|r| r["series"] == "dns"));
        // Down: an error, whatever the minute says.
        lab.up.lock().unwrap().down_until_ms = 1;
        lab.up.lock().unwrap().changed_ms = 30_000;
        let out = s.execute("ip.dns.statistics.print", &json!({})).unwrap();
        assert_eq!(out["upstreams"][0]["state"], "down");
        assert_eq!(out["upstreams"][0]["state_secs"], 60);
        assert_eq!(out["warnings"][0]["key"], "upstream_down");
        assert_eq!(out["warnings"][0]["severity"], "error");
    }

    #[test]
    fn reset_in_a_transaction_leaves_the_config() {
        let mut s = Session::virtual_lab();
        let f = wired(&mut s);
        send(&f, [192, 168, 88, 10], "nas.lan.", A);
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        let before = s.store().candidate().clone();
        s.execute("ip.dns.statistics.reset", &json!({})).unwrap();
        assert_eq!(*s.store().candidate(), before, "counters are not config");
        assert!(
            s.execute("config.discard", &json!({})).is_err(),
            "nothing pending to roll back"
        );
        let out = s.execute("ip.dns.statistics.print", &json!({})).unwrap();
        assert_eq!(out["queries"], 0, "a reset is not rolled back");
    }
}
