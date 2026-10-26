//! G4.3cd: routes to subscribers through the BNG (`pppoe_bng.rs`) with
//! real `proto-pppoe` clients in memory: from the secret and from RADIUS
//! (repeated `Framed-Route`/`Framed-IPv6-Route`), installed after the
//! session (XDP LPM or a kernel route via `bng0`), refused with the reason
//! when they would take someone else's block, changed by CoA without a
//! reconnect, and gone with the session (a block left behind is a
//! blackhole).
#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use corerouter_engine::framed::FramedTable;
use corerouter_engine::ppp::PppBackend;
use corerouter_engine::radius::{AaaBackend, AcctSource, AuthDone, SessionOwner};
use corerouter_hal::pppoe::PppoeOp;
use corerouter_model::framed_route::{FramedRoute, RouteOrigin};
use corerouter_model::radius::{
    AcctRequest, AcctStatus, Attribute, AuthOutcome, AuthReply, AuthRequest, CoaKind, CoaOutcome,
    CoaRequest, CoaSelector, RadiusStatus,
};
use corerouter_proto_pppoe::client::Client;

use super::pppoe_bng::{Effect, Owner};
use super::pppoe_bng_tests::{BNG_MAC, IFINDEX, Lab, server, snap};

/// RADIUS answering from a table: user → reply attributes.
#[derive(Default)]
struct RouteAaa {
    replies: Vec<(String, Vec<Attribute>)>,
    accts: Mutex<Vec<AcctRequest>>,
}

impl AaaBackend for RouteAaa {
    fn authenticate(&self, req: AuthRequest, done: AuthDone) {
        let mut reply = AuthReply::failed(AuthOutcome::Reject, "");
        reply.message = None;
        if let Some((_, attrs)) = self.replies.iter().find(|(u, _)| *u == req.user) {
            reply.outcome = AuthOutcome::Accept;
            reply.attributes = attrs.clone();
        }
        done(reply);
    }

    fn account(&self, req: AcctRequest, _: Option<Arc<dyn AcctSource>>) -> Result<(), String> {
        self.accts.lock().unwrap().push(req);
        Ok(())
    }

    fn register_owner(&self, _: Arc<dyn SessionOwner>) {}

    fn status(&self) -> RadiusStatus {
        RadiusStatus::default()
    }
}

fn a(name: &str, value: &str) -> Attribute {
    Attribute::new(name, value)
}

/// `n` RADIUS users `r0..` answered from `replies`, CPEs speaking PAP.
fn radius_lab(replies: Vec<(String, Vec<Attribute>)>, xdp: bool) -> (Lab, Arc<RouteAaa>) {
    let n = replies.len();
    let aaa = Arc::new(RouteAaa { replies, ..RouteAaa::default() });
    let mut s = snap(0, server(serde_json::json!({"authentication": ["pap"]})), 100);
    let mut cfg = corerouter_model::Config::default();
    cfg.ip.pools = s.pools.clone();
    s.forbidden = Arc::new(corerouter_engine::framed::Forbidden::of(&cfg));
    s.ppp.aaa.use_radius = true;
    s.aaa = Some(aaa.clone());
    let mut lab = Lab::new(n, s, |i| (format!("r{i}"), "x".into()));
    for i in 0..n {
        let mut cfg = lab.clients[i].config().clone();
        cfg.auth = corerouter_proto_pppoe::layers::AuthSet::new(&[corerouter_proto_pppoe::lcp::AuthProto::Pap]);
        lab.clients[i] = Client::new(cfg, [i as u8 + 9; 32]);
    }
    lab.bng.xdp = xdp;
    (lab, aaa)
}

fn table(lab: &Lab) -> FramedTable {
    lab.bng.shared.lock().unwrap().framed.clone()
}

fn holder(lab: &Lab, ip: &str) -> Option<String> {
    table(lab).holder_of(ip.parse::<IpAddr>().unwrap()).map(|(_, h)| h.user)
}

fn ipv4(octets: [u8; 4], dst: Ipv4Addr) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0];
    p.extend_from_slice(&octets);
    p.extend_from_slice(&dst.octets());
    p
}

/// A session frame from client 0 (MAC 02:10:00:00:00:01) with `pkt`.
fn from_client(sid: u16, pkt: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&BNG_MAC);
    f.extend_from_slice(&[0x02, 0x10, 0, 0, 0, 1]);
    f.extend_from_slice(&[0x88, 0x64, 0x11, 0x00]);
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(&(pkt.len() as u16 + 2).to_be_bytes());
    f.extend_from_slice(&[0x00, 0x21]);
    f.extend_from_slice(pkt);
    f
}

#[test]
fn secret_routes_ride_the_slow_path_and_leave_with_the_session() {
    let mut s = snap(1, server(serde_json::json!({})), 10);
    s.ppp.secrets.get_mut(0).unwrap().routes = FramedRoute::parse_list("203.0.113.8/29,2001:db8:100::/48").unwrap();
    let mut lab = Lab::new(1, s, |_| ("u0".into(), "p0".into()));
    lab.start(0..1);
    lab.run(100, 50);
    assert_eq!(lab.ups(), 1);
    let act = lab.backend().active().pop().unwrap();
    assert_eq!(act.routes.len(), 1, "{:?}", act.routes);
    assert_eq!((act.routes[0].route.as_str(), act.routes[0].origin), ("203.0.113.8/29", RouteOrigin::Secret));
    let blocks: Vec<_> = lab.bng.effects.iter().filter_map(|e| match e { Effect::Block { dst, add } => Some((dst.to_string(), *add)), _ => None }).collect();
    assert_eq!(blocks, [("203.0.113.8/29".to_owned(), true)]);
    // IPv6 needs the XDP data plane (no IPv6 slow path, G4.3l): refused,
    // and "Why?" says so.
    let why = lab.backend().active().pop().unwrap();
    assert!(why.refused_routes.iter().any(|r| r.contains("2001:db8:100::/48") && r.contains("XDP")), "{why:?}");
    assert!(lab.bng.effects.iter().any(|e| matches!(e, Effect::Log { error: true, text } if text.contains("rota recusada"))));
    // Downstream to a host of the block: encapsulated for the subscriber.
    let host = Ipv4Addr::new(203, 0, 113, 10);
    lab.bng.frames.clear();
    lab.bng.data_down(&ipv4([8, 8, 8, 8], host));
    let (_, f) = lab.bng.frames.pop().expect("to the subscriber");
    assert_eq!(&f[..6], &[0x02, 0x10, 0, 0, 0, 1]);
    // Upstream from a host of the block: the subscriber's; outside: spoofed.
    lab.bng.upstream.clear();
    lab.bng.frame(lab.now, IFINDEX, &from_client(act.session_id, &ipv4([203, 0, 113, 10], Ipv4Addr::new(8, 8, 8, 8))));
    lab.bng.frame(lab.now, IFINDEX, &from_client(act.session_id, &ipv4([203, 0, 113, 20], Ipv4Addr::new(8, 8, 8, 8))));
    assert_eq!(lab.bng.upstream.len(), 1);
    assert_eq!(holder(&lab, "203.0.113.12").as_deref(), Some("u0"));
    // Logout: the route goes with the session, nothing left behind.
    lab.bng.effects.clear();
    lab.backend().terminate(std::slice::from_ref(&act.id));
    lab.bng.requests(lab.now);
    lab.run(50, 50);
    assert!(lab.bng.effects.iter().any(|e| matches!(e, Effect::Block { add: false, dst } if dst.to_string() == "203.0.113.8/29")));
    assert!(table(&lab).is_empty());
    lab.bng.frames.clear();
    lab.bng.data_down(&ipv4([8, 8, 8, 8], host));
    assert!(lab.bng.frames.is_empty());
}

#[test]
fn radius_routes_reach_the_xdp_lpm_and_two_subscribers_never_share_a_block() {
    let (mut lab, aaa) = radius_lab(
        vec![
            (
                "r0".into(),
                vec![
                    a("Framed-Route", "203.0.113.8/29 0.0.0.0 1"),
                    a("Framed-Route", "198.51.100.0/30"),
                    a("Framed-IPv6-Prefix", "2001:db8:1:1::/64"),
                    a("Framed-IPv6-Route", "2001:db8:100::/48 :: 1"),
                    a("Framed-IPv6-Prefix", "2001:db8:9::/56"),
                ],
            ),
            (
                "r1".into(),
                vec![a("Framed-Route", "203.0.113.12/30"), a("Framed-Route", "192.0.2.0/29"), a("Framed-Route", "127.0.0.0/8")],
            ),
        ],
        true,
    );
    lab.start(0..1);
    lab.run(100, 50);
    lab.start(1..2);
    lab.run(100, 50);
    assert_eq!(lab.ups(), 2);
    // Each route right after its session's Upsert, at the same index.
    let mut idx_of_session = None;
    let mut r0 = Vec::new();
    for e in &lab.bng.effects {
        match e {
            Effect::Xdp(PppoeOp::Upsert(i, _)) if idx_of_session.is_none() => idx_of_session = Some(*i),
            Effect::Xdp(PppoeOp::Route { dst, idx, add: true }) if Some(*idx) == idx_of_session => r0.push(dst.to_string()),
            _ => {}
        }
    }
    assert_eq!(r0, ["203.0.113.8/29", "198.51.100.0/30", "2001:db8:100::/48", "2001:db8:9::/56"]);
    let active = lab.backend().active();
    let row = |u: &str| active.iter().find(|x| x.name == u).unwrap().routes.clone();
    let origins: Vec<RouteOrigin> = row("r0").iter().map(|r| r.origin).collect();
    assert_eq!(origins, [RouteOrigin::FramedRoute, RouteOrigin::FramedRoute, RouteOrigin::FramedIpv6Route, RouteOrigin::FramedIpv6Prefix]);
    // r1: the block inside r0's is refused (r0 keeps it), the special one
    // too; the free one is installed.
    assert_eq!(row("r1").iter().map(|r| r.route.as_str()).collect::<Vec<_>>(), ["192.0.2.0/29"]);
    let why = lab.backend().active().into_iter().find(|x| x.name == "r1").unwrap();
    assert!(why.refused_routes.iter().any(|r| r.contains("já roteado para r0")), "{why:?}");
    assert!(why.refused_routes.iter().any(|r| r.contains("127.0.0.0/8")), "{why:?}");
    assert_eq!(holder(&lab, "203.0.113.13").as_deref(), Some("r0"));
    // Accounting-Start carries the routes installed (RFC 2866 §5.13).
    {
        let accts = aaa.accts.lock().unwrap();
        let start = accts.iter().find(|r| r.status == AcctStatus::Start && r.user == "r0").unwrap();
        let fr: Vec<&str> = start.attributes.iter().filter(|a| a.name == "Framed-Route").map(|a| a.value.as_str()).collect();
        assert_eq!(fr, ["203.0.113.8/29", "198.51.100.0/30"]);
    }
    // r0 leaves: its routes are removed before its session, and the block
    // is free for r1's next login.
    let id = active.iter().find(|x| x.name == "r0").unwrap().id.clone();
    lab.bng.effects.clear();
    lab.backend().terminate(&[id]);
    lab.bng.requests(lab.now);
    lab.run(50, 50);
    let ops: Vec<String> = lab.bng.effects.iter().filter_map(|e| match e {
        Effect::Xdp(PppoeOp::Route { dst, add: false, .. }) => Some(format!("-{dst}")),
        Effect::Xdp(PppoeOp::Remove(_)) => Some("remove".into()),
        _ => None,
    }).collect();
    assert_eq!(ops, ["-203.0.113.8/29", "-198.51.100.0/30", "-2001:db8:100::/48", "-2001:db8:9::/56", "remove"]);
    assert_eq!(holder(&lab, "203.0.113.13"), None);
    assert_eq!(holder(&lab, "192.0.2.3").as_deref(), Some("r1"));
}

#[test]
fn coa_swaps_routes_live_and_refuses_bad_ones_whole() {
    let (mut lab, _) = radius_lab(
        vec![
            ("r0".into(), vec![a("Framed-Route", "203.0.113.8/29")]),
            ("r1".into(), vec![a("Framed-Route", "192.0.2.0/29")]),
        ],
        true,
    );
    lab.start(0..2);
    lab.run(100, 50);
    assert_eq!(lab.ups(), 2);
    let owner = Owner(lab.bng.shared.clone());
    let coa = |routes: &[(&str, &str)]| CoaRequest {
        kind: CoaKind::Coa,
        from: "127.0.0.1:3799".parse().unwrap(),
        selector: CoaSelector { user_name: Some("r0".into()), ..CoaSelector::default() },
        changes: routes.iter().map(|(n, v)| a(n, v)).collect(),
        authorize_only: false,
        packet: Vec::new(),
    };
    // Invalid in any way: NAK 407, nothing changes (RFC 5176 §3.5).
    for bad in [
        vec![("Framed-Route", "127.0.0.0/8")],
        vec![("Framed-Route", "10.0.0.1/24")],
        vec![("Framed-Route", "192.0.2.0/28")],
        vec![("Framed-Route", "100.64.0.0/29")],
        vec![("Framed-Route", "203.0.113.64/29"), ("Framed-Route", "203.0.113.64/30")],
        vec![("Framed-IPv6-Route", "fe80::/64")],
    ] {
        assert_eq!(owner.handle(&coa(&bad)), CoaOutcome::Nak(407), "{bad:?}");
    }
    lab.bng.effects.clear();
    lab.bng.requests(lab.now);
    assert!(lab.bng.effects.is_empty(), "{:?}", lab.bng.effects);
    // Keep one, add one: only the new one is installed.
    assert_eq!(owner.handle(&coa(&[("Framed-Route", "203.0.113.8/29"), ("Framed-Route", "203.0.113.32/29")])), CoaOutcome::Ack);
    lab.bng.requests(lab.now);
    let ops = |lab: &Lab| -> Vec<String> {
        lab.bng.effects.iter().filter_map(|e| match e {
            Effect::Xdp(PppoeOp::Route { dst, add, .. }) => Some(format!("{}{dst}", if *add { "+" } else { "-" })),
            _ => None,
        }).collect()
    };
    assert_eq!(ops(&lab), ["+203.0.113.32/29"]);
    // Replace both: the new block first, then the old ones go.
    lab.bng.effects.clear();
    assert_eq!(owner.handle(&coa(&[("Framed-Route", "203.0.113.64/29")])), CoaOutcome::Ack);
    lab.bng.requests(lab.now);
    assert_eq!(ops(&lab), ["+203.0.113.64/29", "-203.0.113.8/29", "-203.0.113.32/29"]);
    assert_eq!(holder(&lab, "203.0.113.9"), None);
    assert_eq!(holder(&lab, "203.0.113.65").as_deref(), Some("r0"));
    let row = lab.backend().active().into_iter().find(|x| x.name == "r0").unwrap();
    assert_eq!(row.routes.iter().map(|r| r.route.as_str()).collect::<Vec<_>>(), ["203.0.113.64/29"]);
    // An empty Framed-Route clears the IPv4 routes.
    lab.bng.effects.clear();
    assert_eq!(owner.handle(&coa(&[("Framed-Route", "")])), CoaOutcome::Ack);
    lab.bng.requests(lab.now);
    assert_eq!(ops(&lab), ["-203.0.113.64/29"]);
    lab.run(20, 50);
    assert_eq!(lab.ups(), 2, "a CoA never reconnects");
    assert!(lab.bng.effects.iter().any(|e| matches!(e, Effect::Log { text, .. } if text.contains("rotas trocadas por CoA"))));
}
