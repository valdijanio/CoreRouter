//! /ip dns statistics (G4.1e): what the LAN forwarder did with the queries
//! since the last reset. RouterOS v7 has no such menu (only the adlist's
//! `match-count`); the names follow its `print`/`reset` style and the
//! counters Unbound (`unbound-control stats`) and PowerDNS Recursor
//! (`rec_control get-all`, `top-remotes`) keep.

use corerouter_proto_dns::server::Snapshot;
use serde_json::{Map, Value, json};

use super::args::opt_u32;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

/// Clients listed by default, and at most.
const TOP: u32 = 10;
const MAX_TOP: u32 = 100;
/// Always shown, even at zero (the stages every forwarder has).
const ANSWERED: [&str; 6] = ["cache", "static", "upstream", "stale", "refused", "limit"];

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "ip.dns.statistics.print", "DNS Statistics", [], None,
        "{top?: int 1..100 (clients listed, default 10)} → {resolver: router|simulated, allow_remote_requests, since (unix time counting started), elapsed_secs, queries, udp, tcp, answered: {cache, static, upstream, stale, refused, limit, …}, cache_hit_percent, rcodes: {noerror, nxdomain, servfail, refused, dropped, …}, types: [{type, queries}], clients: [{address, queries, refused, error}], clients_tracked, clients_replaced, upstreams: [{server, answers, srtt_ms, failures, down}]}",
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
    let servers = s
        .dns_backend()
        .map(|b| b.server_stats())
        .unwrap_or_default();
    if let Some(o) = out.as_object_mut() {
        o.insert("resolver".into(), json!(resolver));
        o.insert(
            "allow_remote_requests".into(),
            json!(s.store().running().ip.dns.allow_remote_requests),
        );
        o.insert("since".into(), json!(since));
        let elapsed = since.zip(s.hal_now()).map(|(a, b)| b.saturating_sub(a));
        o.insert("elapsed_secs".into(), json!(elapsed));
        // Each server the resolver knows, with what it measured (the
        // answers here are the clients' queries it served).
        let mut ups: Vec<Value> = Vec::new();
        for (ip, st) in &servers {
            ups.push(json!({"server": ip, "answers": snap.counters.upstreams.get(ip).copied().unwrap_or(0),
                "srtt_ms": st.srtt_ms, "failures": st.failures, "down": st.down_until_ms > 0}));
        }
        for (ip, n) in &snap.counters.upstreams {
            if !servers.iter().any(|(s, _)| s == ip) {
                ups.push(json!({"server": ip, "answers": n, "srtt_ms": null,
                    "failures": 0, "down": false}));
            }
        }
        o.insert("upstreams".into(), Value::Array(ups));
    }
    Ok(out)
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
    json!({
        "queries": c.queries,
        "udp": c.udp,
        "tcp": c.tcp,
        "answered": answered,
        "cache_hit_percent": hit,
        "rcodes": c.rcodes,
        "types": types.iter().map(|(t, n)| json!({"type": t, "queries": n})).collect::<Vec<_>>(),
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
