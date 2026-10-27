//! /routing route for BGP (G3.2c, G3.3): the routes each connection
//! received and advertised, paged and searched like `ip.route.page`
//! (G1.27c), with the RPKI state of each; "Why this route?" for a prefix;
//! and the flap history of each session.
//!
//! Reading bgpd is a job on the runner, never a wait under the lock
//! (`crate::bgp_rib`): the first look answers `loading`, and the window
//! (or an agent) asks again; every later page comes from memory.

use corerouter_model::bgp_rib::{BgpPath, Direction};
use corerouter_model::rpki::RpkiState;
use corerouter_proto_bgp::decision::{Step, Verdict};
use corerouter_proto_bgp::rib::{AsPathPattern, Match, Query};
use corerouter_proto_bgp::rpki::origin_as;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_u32, req_str};
use super::{CommandSpec, always};
use crate::bgp_rib::{Load, lock};
use crate::{EngineError, Result, Session};

/// Rows of one page at most (as `ip.route.page`; the window asks for 500).
pub const MAX_LIMIT: u32 = 5_000;
const DEFAULT_LIMIT: u32 = 500;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "routing.bgp.route.list", "BGP Routes", ["Routing", "BGP"], None,
        "{connection: string, direction?: string (received | advertised; default received), prefix?: cidr | ip, match?: string (exact | longer | orlonger | covering; default orlonger, covering for an address), as_path?: string (AS numbers in order, ^ and $ anchor: \"^64500\", \"13335$\"), community?: string (a:b, a:b:c or a well-known name), rpki?: string (valid | invalid | unknown | unverified), filtered?: bool (refused by the inbound policy), offset?: u32, limit?: u32 (1..=5000, default 500), refresh?: bool (read bgpd again)} → {state: loading | ready | failed, error?, connection, direction, pre_policy (received before the inbound policy, refused ones flagged), load_ms?, age_secs?, total (rows that match), offset, rows: [{prefix, best, filtered, rpki, origin_as?, as_path, origin, next_hop?, med?, local_pref?, weight, communities, large_communities}], summary: {total, ipv4, ipv6, best, filtered, rpki: {valid, invalid, unknown, unverified}}, warnings} (loading: ask again in a moment)",
        always, list),
    cmd!(query "routing.bgp.route.explain", "Why This Route", ["Routing", "BGP"], None,
        "{prefix: cidr | ip (an address: its longest match), instance?: string (default \"default\")} → {state: loading | ready | failed, error?, prefix, best? (index), agrees (our comparison picks the daemon's best), paths: [{index, peer, connection?, best, valid, multipath, stale, peer_kind (local | external | internal | confed-external), as_path, origin, med?, local_pref?, weight, next_hop?, igp_metric?, router_id?, originator_id?, cluster_list_len, communities, large_communities, rpki, origin_as?, selection_reason? (the daemon's), lost_at?: {step, rule, winner_value, loser_value}, won_at?, unexplained}], steps: [{step, rule}] (the order compared)} (loading: ask again; an answer is kept 30 s)",
        always, explain),
    cmd!(query "routing.bgp.route.summary", "BGP Route Tables", [], None,
        "{} → [{connection, direction, state: loading | ready | failed, age_secs?, total?, filtered?, rpki?: {valid, invalid, unknown, unverified}}] (the tables read so far: the share of each RPKI state per session)",
        always, summary),
    cmd!(query "routing.bgp.session.history", "BGP Session History", ["Routing", "BGP"], None,
        "{connection?: string} → [{connection?, remote_address, at, event: down | up | flap (down and up between two samples), state, reason?, uptime_secs? (how long it had been up)}] (newest first; 64 per session, kept until restart)",
        always, history),
];

fn page_args(p: &Value) -> Result<(usize, usize)> {
    let offset = opt_u32(p, "offset")?.unwrap_or(0);
    let limit = opt_u32(p, "limit")?.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 || limit > MAX_LIMIT {
        return Err(EngineError::bad("limit", format!("must be 1..={MAX_LIMIT}")));
    }
    Ok((
        usize::try_from(offset).unwrap_or(usize::MAX),
        usize::try_from(limit).unwrap_or(usize::MAX),
    ))
}

fn query_of(p: &Value) -> Result<Query> {
    let mut q = Query::default();
    if let Some(raw) = opt_str(p, "prefix")? {
        let t = raw.trim();
        let shown = crate::logging::cut(t, 64);
        let (net, default) = match t.parse::<ipnet::IpNet>() {
            Ok(n) => (n, Match::OrLonger),
            Err(_) => {
                let a: std::net::IpAddr = t
                    .parse()
                    .map_err(|_| EngineError::bad("prefix", format!("{shown:?} is not a prefix or an address")))?;
                (ipnet::IpNet::from(a), Match::Covering)
            }
        };
        let m = match opt_str(p, "match")? {
            Some(m) => Match::parse(m)
                .ok_or_else(|| EngineError::bad("match", "exact, longer, orlonger or covering"))?,
            None => default,
        };
        q.prefix = Some((net, m));
    } else if p.get("match").is_some() {
        return Err(EngineError::bad("match", "needs a prefix"));
    }
    if let Some(a) = opt_str(p, "as_path")? {
        if a.len() > 512 {
            return Err(EngineError::bad("as_path", "at most 512 characters"));
        }
        q.as_path = Some(AsPathPattern::parse(a).map_err(|e| EngineError::bad("as_path", e))?);
    }
    if let Some(c) = opt_str(p, "community")? {
        let c = c.trim();
        if c.is_empty() || c.len() > 64 || !c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'-') {
            return Err(EngineError::bad("community", "a:b, a:b:c or a well-known name (no-export…)"));
        }
        q.community = Some(c.to_owned());
    }
    if let Some(r) = opt_str(p, "rpki")? {
        q.rpki = Some(
            RpkiState::parse(r).ok_or_else(|| EngineError::bad("rpki", "valid, invalid, unknown or unverified"))?,
        );
    }
    q.filtered = opt_bool(p, "filtered")?;
    Ok(q)
}

fn rpki_json(n: [u64; 4]) -> Value {
    json!({"valid": n[0], "invalid": n[1], "unknown": n[2], "unverified": n[3]})
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let connection = req_str(p, "connection")?.to_owned();
    let direction = match opt_str(p, "direction")? {
        Some(d) => Direction::parse(d).ok_or_else(|| EngineError::bad("direction", "received or advertised"))?,
        None => Direction::Received,
    };
    let q = query_of(p)?;
    let (offset, limit) = page_args(p)?;
    let refresh = opt_bool(p, "refresh")?.unwrap_or(false);
    let local_as = s.bgp_target(&connection)?.local_as;
    let slot = s.bgp_table(&connection, direction, refresh)?;
    let now = s.now();
    let sl = lock(&slot);
    let head = json!({
        "connection": connection,
        "direction": direction.name(),
        "load_ms": sl.ms,
        "age_secs": sl.finished.zip(now).map(|(f, n)| n.saturating_sub(f)),
        "offset": offset,
    });
    let mut out = match &sl.load {
        Load::Loading => json!({"state": "loading", "total": 0, "rows": [], "summary": null, "pre_policy": null, "warnings": []}),
        Load::Failed(e) => json!({"state": "failed", "error": e, "total": 0, "rows": [], "summary": null, "pre_policy": null, "warnings": []}),
        Load::Ready(ix) => {
            let (total, page) = ix.search(&q, offset, limit);
            let rows: Vec<Value> = page
                .iter()
                .filter_map(|&i| ix.route(i))
                .map(|(r, a, state)| {
                    let a = a.cloned().unwrap_or_default();
                    json!({
                        "prefix": r.prefix.to_string(),
                        "best": r.best(),
                        "filtered": r.filtered(),
                        "rpki": state.name(),
                        "origin_as": origin_as(&a.as_path, local_as),
                        "as_path": a.as_path,
                        "origin": a.origin.name(),
                        "next_hop": a.next_hop.map(|h| h.to_string()),
                        "med": a.med,
                        "local_pref": a.local_pref,
                        "weight": a.weight,
                        "communities": a.communities,
                        "large_communities": a.large_communities,
                    })
                })
                .collect();
            let sm = ix.summary;
            json!({
                "state": "ready",
                "total": total,
                "rows": rows,
                "pre_policy": ix.rib.pre_policy,
                "warnings": ix.rib.warnings,
                "summary": {
                    "total": sm.total, "ipv4": sm.ipv4, "ipv6": sm.ipv6, "best": sm.best,
                    "filtered": sm.filtered, "rpki": rpki_json(sm.rpki),
                },
            })
        }
    };
    if let (Some(o), Some(h)) = (out.as_object_mut(), head.as_object()) {
        for (k, v) in h {
            o.insert(k.clone(), v.clone());
        }
    }
    Ok(out)
}

fn verdict_json(v: &Verdict) -> Value {
    json!({"step": v.step.key(), "rule": v.step.rule(), "winner_value": v.winner_value, "loser_value": v.loser_value})
}

fn path_json(i: usize, x: &BgpPath, s: &Session, local_as: Option<u32>, prefix: Option<ipnet::IpNet>) -> Value {
    let origin = origin_as(&x.as_path, local_as);
    let rpki = match (s.vrps(), prefix) {
        (Some(t), Some(n)) => t.validate(n.network(), n.prefix_len(), origin).name().to_owned(),
        (None, _) => x.rpki.clone().unwrap_or_else(|| RpkiState::Unverified.name().to_owned()),
        _ => RpkiState::Unverified.name().to_owned(),
    };
    let connection = s
        .store()
        .running()
        .routing
        .bgp_connections
        .values()
        .find(|c| c.remote_address.to_string() == x.peer)
        .map(|c| c.name.clone());
    json!({
        "index": i,
        "peer": x.peer,
        "connection": connection,
        "best": x.best,
        "valid": x.valid,
        "multipath": x.multipath,
        "stale": x.stale,
        "peer_kind": x.peer_kind,
        "as_path": x.as_path,
        "origin": x.origin.name(),
        "med": x.med,
        "local_pref": x.local_pref,
        "weight": x.weight,
        "next_hop": x.next_hop,
        "igp_metric": x.igp_metric,
        "router_id": x.peer_router_id.map(|r| r.to_string()),
        "originator_id": x.originator_id.map(|r| r.to_string()),
        "cluster_list_len": x.cluster_list_len,
        "communities": x.communities,
        "large_communities": x.large_communities,
        "rpki": rpki,
        "origin_as": origin,
        "selection_reason": x.selection_reason,
        "last_update": x.last_update,
    })
}

fn explain(s: &mut Session, p: &Value) -> Result<Value> {
    let raw = req_str(p, "prefix")?.trim().to_owned();
    let shown = crate::logging::cut(&raw, 64);
    let normalized = match raw.parse::<ipnet::IpNet>() {
        Ok(n) => n.trunc().to_string(),
        Err(_) => raw
            .parse::<std::net::IpAddr>()
            .map_err(|_| EngineError::bad("prefix", format!("{shown:?} is not a prefix or an address")))?
            .to_string(),
    };
    let instance = opt_str(p, "instance")?
        .unwrap_or(corerouter_proto_bgp::DEFAULT_INSTANCE)
        .to_owned();
    if !s.store().running().routing.bgp.contains_key(&instance) {
        return Err(EngineError::bad(
            "instance",
            format!("no BGP instance {:?} (routing.bgp.instance.list)", crate::logging::cut(&instance, 64)),
        ));
    }
    let slot = s.bgp_explain(&instance, &normalized)?;
    let sl = lock(&slot);
    let steps: Vec<Value> = Step::ALL
        .iter()
        .filter(|st| !matches!(st, Step::Equal))
        .map(|st| json!({"step": st.key(), "rule": st.rule()}))
        .collect();
    Ok(match &sl.load {
        Load::Loading => json!({"state": "loading", "prefix": normalized, "paths": [], "steps": steps}),
        Load::Failed(e) => json!({"state": "failed", "error": e, "prefix": normalized, "paths": [], "steps": steps}),
        Load::Ready(x) => {
            let shown_prefix = if x.prefix.prefix.is_empty() { normalized.clone() } else { x.prefix.prefix.clone() };
            let net = shown_prefix.parse::<ipnet::IpNet>().ok();
            let paths: Vec<Value> = x
                .prefix
                .paths
                .iter()
                .enumerate()
                .map(|(i, path)| {
                    let mut v = path_json(i, path, s, x.prefix.local_as, net);
                    if let (Some(o), Some(row)) = (v.as_object_mut(), x.explanation.rows.get(i)) {
                        o.insert("lost_at".into(), row.lost_at.as_ref().map_or(Value::Null, verdict_json));
                        o.insert("won_at".into(), row.won_at.as_ref().map_or(Value::Null, verdict_json));
                        o.insert("unexplained".into(), json!(row.unexplained));
                    }
                    v
                })
                .collect();
            json!({
                "state": "ready",
                "prefix": shown_prefix,
                "best": x.explanation.best,
                "agrees": x.explanation.agrees,
                "paths": paths,
                "steps": steps,
                "load_ms": sl.ms,
            })
        }
    })
}

fn summary(s: &mut Session, _: &Value) -> Result<Value> {
    let now = s.now();
    let mut rows: Vec<(String, &'static str, Value)> = s
        .bgp_tables()
        .into_iter()
        .map(|((connection, direction), slot)| {
            let sl = lock(&slot);
            let mut v = json!({
                "connection": connection,
                "direction": direction.name(),
                "age_secs": sl.finished.zip(now).map(|(f, n)| n.saturating_sub(f)),
            });
            if let Some(o) = v.as_object_mut() {
                match &sl.load {
                    Load::Loading => {
                        o.insert("state".into(), json!("loading"));
                    }
                    Load::Failed(e) => {
                        o.insert("state".into(), json!("failed"));
                        o.insert("error".into(), json!(e));
                    }
                    Load::Ready(ix) => {
                        o.insert("state".into(), json!("ready"));
                        o.insert("total".into(), json!(ix.summary.total));
                        o.insert("filtered".into(), json!(ix.summary.filtered));
                        o.insert("rpki".into(), rpki_json(ix.summary.rpki));
                    }
                }
            }
            (connection, direction.name(), v)
        })
        .collect();
    rows.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
    Ok(Value::Array(rows.into_iter().map(|r| r.2).collect()))
}

fn history(s: &mut Session, p: &Value) -> Result<Value> {
    let connection = opt_str(p, "connection")?;
    let rows: Vec<Value> = s
        .bgp_history()
        .map(|h| h.list(connection))
        .unwrap_or_default()
        .into_iter()
        .map(|(conn, addr, e)| {
            let mut v = serde_json::to_value(&e).unwrap_or_else(|_| json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("connection".into(), json!(conn));
                o.insert("remote_address".into(), json!(addr));
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use corerouter_hal::HalError;
    use corerouter_hal::VirtualHal;
    use corerouter_hal::routing::{RoutingDaemon, RoutingReader};
    use corerouter_model::Config;
    use corerouter_model::bgp_rib::{AsSegment, BgpAttrs, BgpPrefix, BgpRib, BgpRoute, PeerKind, SegmentKind};
    use corerouter_model::routing_state::{BgpSession, RoutingStatus};
    use corerouter_proto_bgp::rpki::{Vrp, VrpTable};

    use super::*;
    use crate::tasks::{Clock, Job, Runner};

    /// Runs each job at once, on the caller's thread.
    struct Inline;
    struct NoClock;
    impl Clock for NoClock {
        fn elapsed(&self) -> std::time::Duration {
            std::time::Duration::from_millis(3)
        }
        fn sleep(&self, _: std::time::Duration) {}
    }
    impl Runner for Inline {
        fn spawn(&self, _: &str, job: Job) -> std::result::Result<(), String> {
            job(&NoClock);
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct Fake {
        reads: Arc<Mutex<usize>>,
    }

    impl RoutingDaemon for Fake {
        fn describe(&self) -> String {
            "fake".into()
        }
        fn apply(&mut self, _: &Config, _: &Config) -> std::result::Result<(), HalError> {
            Ok(())
        }
        fn reader(&self) -> Box<dyn RoutingReader> {
            Box::new(self.clone())
        }
    }

    fn path(peer: &str, lp: u32, best: bool) -> BgpPath {
        BgpPath {
            peer: peer.into(),
            peer_router_id: peer.parse().ok(),
            peer_kind: PeerKind::Internal,
            segments: vec![AsSegment { kind: SegmentKind::Sequence, asns: vec![64502, 64502] }],
            as_path: "64502 64502".into(),
            local_pref: Some(lp),
            valid: true,
            next_hop_reachable: true,
            best,
            selection_reason: best.then(|| "Local Pref".into()),
            ..BgpPath::default()
        }
    }

    impl RoutingReader for Fake {
        fn bgp_sessions(&mut self, _: &Config) -> std::result::Result<Vec<BgpSession>, HalError> {
            Ok(Vec::new())
        }
        fn version(&mut self) -> std::result::Result<String, HalError> {
            Ok("fake".into())
        }
        fn bgp_routes(&mut self, _: &str, neighbor: &str, d: Direction) -> std::result::Result<BgpRib, HalError> {
            *self.reads.lock().unwrap() += 1;
            if neighbor == "192.0.2.99" {
                return Err(HalError::Io("bgpd went away".into()));
            }
            let attrs = vec![
                BgpAttrs { as_path: "64502 13335".into(), local_pref: Some(200), ..BgpAttrs::default() },
                BgpAttrs { as_path: "64502 64666".into(), communities: vec!["65000:100".into()], ..BgpAttrs::default() },
            ];
            let mut routes = Vec::new();
            for i in 0..1_000u32 {
                routes.push(BgpRoute {
                    prefix: format!("10.{}.{}.0/24", i / 256, i % 256).parse().unwrap(),
                    attrs: i % 2,
                    flags: if i % 10 == 0 { BgpRoute::FILTERED } else { BgpRoute::BEST },
                });
            }
            Ok(BgpRib { routes, attrs, pre_policy: d == Direction::Received, warnings: vec![] })
        }
        fn bgp_prefix(&mut self, _: &str, prefix: &str) -> std::result::Result<BgpPrefix, HalError> {
            Ok(BgpPrefix {
                prefix: if prefix.contains('/') { prefix.into() } else { "10.20.1.0/24".into() },
                paths: vec![path("198.51.100.18", 200, true), path("198.51.100.22", 100, false)],
                default_local_pref: Some(100),
                local_as: Some(65000),
            })
        }
    }

    fn session(fake: &Fake) -> Session {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        s.set_runner(Arc::new(Inline));
        let _ = s.attach_routing(Box::new(fake.clone()));
        s.execute("routing.bgp.instance.set", &json!({"asn": 65000, "router_id": "10.0.0.1"})).unwrap();
        s.execute("routing.bgp.connection.add", &json!({"name": "rr1", "remote_address": "198.51.100.18", "remote_as": 65000})).unwrap();
        s.execute("routing.bgp.connection.add", &json!({"name": "gone", "remote_address": "192.0.2.99", "remote_as": 65000})).unwrap();
        s
    }

    #[test]
    fn routes_are_read_once_then_paged_and_searched() {
        let fake = Fake::default();
        let mut s = session(&fake);
        let t = VrpTable::build(&[Vrp::new("10.0.0.0".parse().unwrap(), 8, 24, 13335).unwrap()]);
        s.set_rpki_table(Some(Arc::new(t)));
        let r = s.execute("routing.bgp.route.list", &json!({"connection": "rr1", "limit": 10})).unwrap();
        assert_eq!(r["state"], "ready", "{r}");
        assert_eq!((r["total"].as_u64(), r["rows"].as_array().unwrap().len()), (Some(1_000), 10));
        assert_eq!(r["summary"]["rpki"], json!({"valid": 500, "invalid": 500, "unknown": 0, "unverified": 0}));
        assert_eq!(r["summary"]["filtered"], 100);
        assert_eq!(r["rows"][0]["prefix"], "10.0.0.0/24");
        assert_eq!(r["rows"][0]["rpki"], "valid");
        assert_eq!(r["rows"][1]["origin_as"], 64666);
        let r = s
            .execute("routing.bgp.route.list", &json!({"connection": "rr1", "prefix": "10.1.0.0/16", "rpki": "invalid", "offset": 2, "limit": 5}))
            .unwrap();
        assert_eq!(r["total"], 128);
        assert_eq!(r["rows"][0]["prefix"], "10.1.5.0/24");
        let r = s.execute("routing.bgp.route.list", &json!({"connection": "rr1", "community": "65000:100", "filtered": false})).unwrap();
        assert_eq!(r["total"], 500);
        let r = s.execute("routing.bgp.route.list", &json!({"connection": "rr1", "as_path": "13335$"})).unwrap();
        assert_eq!(r["total"], 500);
        let r = s.execute("routing.bgp.route.list", &json!({"connection": "rr1", "prefix": "10.0.3.7"})).unwrap();
        assert_eq!(r["rows"][0]["prefix"], "10.0.3.0/24");
        assert_eq!(*fake.reads.lock().unwrap(), 1, "pages come from memory");
        let sm = s.execute("routing.bgp.route.summary", &json!({})).unwrap();
        assert_eq!((sm[0]["connection"].as_str(), sm[0]["rpki"]["invalid"].as_u64()), (Some("rr1"), Some(500)));
        s.execute("routing.bgp.route.list", &json!({"connection": "rr1", "refresh": true})).unwrap();
        assert_eq!(*fake.reads.lock().unwrap(), 2);
        let r = s.execute("routing.bgp.route.list", &json!({"connection": "rr1", "direction": "advertised"})).unwrap();
        assert_eq!(r["pre_policy"], false);
        // Errors: a failed read is an answer, bad params are refused.
        let r = s.execute("routing.bgp.route.list", &json!({"connection": "gone"})).unwrap();
        assert_eq!(r["state"], "failed");
        assert!(r["error"].as_str().unwrap().contains("bgpd went away"));
        for bad in [
            json!({"connection": "nope"}),
            json!({"connection": "rr1", "direction": "sideways"}),
            json!({"connection": "rr1", "limit": 0}),
            json!({"connection": "rr1", "match": "exact"}),
            json!({"connection": "rr1", "as_path": "a b"}),
            json!({"connection": "rr1", "community": "x y"}),
            json!({"connection": "rr1", "rpki": "maybe"}),
        ] {
            assert!(s.execute("routing.bgp.route.list", &bad).is_err(), "{bad}");
        }
    }

    /// Takes jobs and never runs them: reads stay `loading`.
    struct Never;
    impl Runner for Never {
        fn spawn(&self, _: &str, _: Job) -> std::result::Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn reads_in_flight_are_bounded() {
        let fake = Fake::default();
        let mut s = session(&fake);
        s.set_runner(Arc::new(Never));
        for (c, d) in [("rr1", "received"), ("rr1", "advertised")] {
            let r = s.execute("routing.bgp.route.list", &json!({"connection": c, "direction": d})).unwrap();
            assert_eq!(r["state"], "loading");
        }
        // The same table again is the read in flight, not a new one.
        let r = s.execute("routing.bgp.route.list", &json!({"connection": "rr1"})).unwrap();
        assert_eq!(r["state"], "loading");
        let e = s.execute("routing.bgp.route.list", &json!({"connection": "gone"})).unwrap_err();
        assert!(e.to_string().contains("busy"), "{e}");
    }

    #[test]
    fn explain_names_the_step() {
        let fake = Fake::default();
        let mut s = session(&fake);
        let r = s.execute("routing.bgp.route.explain", &json!({"prefix": "10.20.1.5"})).unwrap();
        assert_eq!(r["state"], "ready", "{r}");
        assert_eq!(r["prefix"], "10.20.1.0/24");
        assert_eq!((r["best"].as_u64(), r["agrees"].as_bool()), (Some(0), Some(true)));
        assert_eq!(r["paths"][0]["connection"], "rr1");
        assert_eq!(r["paths"][1]["lost_at"]["step"], "local-pref");
        assert_eq!(r["paths"][1]["lost_at"]["winner_value"], "200");
        assert_eq!(r["paths"][0]["won_at"]["step"], "local-pref");
        assert_eq!(r["paths"][0]["rpki"], "unverified");
        assert!(s.execute("routing.bgp.route.explain", &json!({"prefix": "nope"})).is_err());
        assert!(s.execute("routing.bgp.route.explain", &json!({"prefix": "10.0.0.0/8", "instance": "x"})).is_err());
    }

    #[test]
    fn without_a_daemon_it_says_so() {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        s.execute("routing.bgp.instance.set", &json!({"asn": 65000, "router_id": "10.0.0.1"})).unwrap();
        s.execute("routing.bgp.connection.add", &json!({"name": "rr1", "remote_address": "198.51.100.18", "remote_as": 65000})).unwrap();
        let e = s.execute("routing.bgp.route.list", &json!({"connection": "rr1"})).unwrap_err();
        assert!(e.to_string().contains("background jobs"), "{e}");
        s.set_runner(Arc::new(Inline));
        let e = s.execute("routing.bgp.route.explain", &json!({"prefix": "10.0.0.0/8"})).unwrap_err();
        assert!(e.to_string().contains("no routing daemon"), "{e}");
    }

    #[test]
    fn history_from_samples() {
        let fake = Fake::default();
        let mut s = session(&fake);
        let one = |up: bool| RoutingStatus {
            backend: "fake".into(),
            updated: Some(1),
            error: None,
            bgp_sessions: vec![BgpSession {
                instance: "default".into(),
                remote_address: "198.51.100.18".into(),
                connection: Some("rr1".into()),
                state: if up { "established" } else { "idle" }.into(),
                established: up,
                uptime_secs: Some(50),
                last_error: (!up).then(|| "Cease/Administrative Reset".into()),
                ..BgpSession::default()
            }],
        };
        s.set_routing_status(one(true));
        s.set_routing_status(one(false));
        let h = s.execute("routing.bgp.session.history", &json!({"connection": "rr1"})).unwrap();
        assert_eq!(h[0]["event"], "down");
        assert_eq!(h[0]["reason"], "Cease/Administrative Reset");
        assert_eq!(h[0]["uptime_secs"], 50);
    }
}
