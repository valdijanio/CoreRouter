//! Tests of the BNG (`pppoe_bng.rs`) with real `proto-pppoe` clients in
//! memory: no sockets, a fake clock, so 10 000 subscribers take seconds.
//! The namespace test (`tests/netns_pppoe.rs`) runs the same over a veth.
#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use corerouter_engine::ppp::PppBackend;
use corerouter_engine::radius::{AaaBackend, AcctSource, AuthDone, SessionOwner};
use corerouter_hal::pppoe::PppoeOp;
use corerouter_model::ItemId;
use corerouter_model::ip_pool::{IpPool, IpPools};
use corerouter_model::ppp::{AddrOrPool, Ppp, PppProfile, PppSecret, PppoeServer, Stage};
use corerouter_model::radius::{
    AcctRequest, AcctStatus, Attribute, AuthOutcome, AuthReply, AuthRequest, CoaKind, CoaOutcome,
    CoaRequest, CoaSelector, RadiusStatus,
};
use corerouter_proto_pppoe::client::{Client, ClientConfig, ClientEvent, ClientOutput, ClientPhase};
use corerouter_proto_pppoe::wire::Mac;

use super::pppoe_bng::{Backend, Bng, Effect, Owner, PortInfo, Snapshot};

const IFINDEX: u32 = 7;
const BNG_MAC: [u8; 6] = [0x02, 0xBB, 0, 0, 0, 1];

fn server(json: serde_json::Value) -> PppoeServer {
    let mut base = serde_json::json!({"id": "*1", "name": "pppoe-ether2", "interface": "ether2", "padi_limit": 0, "mac_padi_limit": 0, "new_session_rate": 0});
    if let (Some(b), Some(extra)) = (base.as_object_mut(), json.as_object()) {
        for (k, v) in extra {
            b.insert(k.clone(), v.clone());
        }
    }
    serde_json::from_value(base).unwrap()
}

fn pools(size: u32) -> IpPools {
    let start = u32::from(Ipv4Addr::new(100, 64, 0, 1));
    IpPools {
        pools: vec![IpPool {
            id: ItemId(1),
            name: "clientes".into(),
            ranges: vec![
                corerouter_model::ip_pool::PoolRange::new(Ipv4Addr::from(start), Ipv4Addr::from(start + size - 1)).unwrap(),
            ],
            next_pool: None,
            comment: String::new(),
        }],
        next_id: 1,
    }
}

fn ppp(users: usize, srv: PppoeServer) -> Ppp {
    let mut p = Ppp::default();
    p.profiles.push(PppProfile {
        id: ItemId(2),
        name: "default".into(),
        remote_address: Some(AddrOrPool::Pool("clientes".into())),
        dns_server: vec![Ipv4Addr::new(1, 1, 1, 1)],
        rate_limit: Some("10M/50M".into()),
        ..PppProfile::default()
    });
    let secrets: Vec<PppSecret> = (0..users)
        .map(|i| PppSecret {
            id: ItemId(10 + i as u32),
            name: format!("u{i}"),
            password: format!("p{i}"),
            profile: "default".into(),
            ..PppSecret::default()
        })
        .collect();
    p.secrets = corerouter_model::cow::CowArc::new(secrets);
    p.pppoe_servers.push(srv);
    p
}

/// N clients and the BNG, a fake clock and a perfect wire.
struct Lab {
    bng: Bng,
    clients: Vec<Client>,
    by_mac: HashMap<[u8; 6], usize>,
    now: u64,
    up: Vec<bool>,
    downs: Vec<usize>,
}

impl Lab {
    fn new(n: usize, snap: Snapshot, auth: impl Fn(usize) -> (String, String)) -> Self {
        let mut bng = Bng::new([7; 32]);
        let ports = HashMap::from([("pppoe-ether2".to_owned(), PortInfo { ifindex: IFINDEX, mac: BNG_MAC })]);
        bng.configure(0, snap, &ports);
        let mut clients = Vec::new();
        let mut by_mac = HashMap::new();
        for i in 0..n {
            let (user, password) = auth(i);
            let mac = [0x02, 0x10, (i >> 16) as u8, (i >> 8) as u8, i as u8, 0x01];
            let cfg = ClientConfig {
                mac: Mac(mac),
                ifindex: IFINDEX,
                username: user.into_bytes(),
                password,
                discovery_timeout_ms: 1000,
                discovery_attempts: 10,
                keepalive_interval_ms: 0,
                ..ClientConfig::default()
            };
            let mut seed = [3u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            clients.push(Client::new(cfg, seed));
            by_mac.insert(mac, i);
        }
        let up = vec![false; n];
        let downs = vec![0; n];
        Self { bng, clients, by_mac, now: 0, up, downs }
    }

    fn start(&mut self, range: std::ops::Range<usize>) {
        let mut out = ClientOutput::new();
        for i in range {
            self.clients[i].start(self.now, &mut out);
            self.feed(&mut out);
        }
    }

    fn feed(&mut self, out: &mut ClientOutput) {
        let frames: Vec<Vec<u8>> = out.frames().map(|(_, f)| f.to_vec()).collect();
        out.clear();
        for f in frames {
            self.bng.frame(self.now, IFINDEX, &f);
        }
    }

    /// Deliver until quiet, then advance the clock by `step` ms, `rounds` times.
    fn run(&mut self, rounds: usize, step: u64) {
        let mut out = ClientOutput::new();
        for _ in 0..rounds {
            for _ in 0..50 {
                self.bng.radius(self.now);
                let frames: Vec<(u32, Vec<u8>)> = std::mem::take(&mut self.bng.frames);
                if frames.is_empty() {
                    break;
                }
                for (_, f) in frames {
                    let mut dst = [0u8; 6];
                    dst.copy_from_slice(&f[..6]);
                    let targets: Vec<usize> = if dst == [0xff; 6] {
                        (0..self.clients.len()).collect()
                    } else {
                        self.by_mac.get(&dst).copied().into_iter().collect()
                    };
                    for c in targets {
                        self.clients[c].handle_frame(self.now, &f, &mut out);
                        self.events(c, &mut out);
                        self.feed(&mut out);
                    }
                }
            }
            self.now += step;
            self.bng.timers(self.now);
            if self.now % 1000 < step {
                self.bng.tick(self.now, &[]);
            }
            for c in 0..self.clients.len() {
                if self.clients[c].next_deadline().is_some_and(|d| d <= self.now) {
                    self.clients[c].handle_timers(self.now, &mut out);
                    self.events(c, &mut out);
                    self.feed(&mut out);
                }
            }
        }
    }

    fn events(&mut self, c: usize, out: &mut ClientOutput) {
        for ev in out.events.drain(..) {
            match ev {
                ClientEvent::Up { .. } => self.up[c] = true,
                ClientEvent::Down { .. } => {
                    self.up[c] = false;
                    self.downs[c] += 1;
                }
            }
        }
    }

    fn ups(&self) -> usize {
        self.up.iter().filter(|u| **u).count()
    }

    fn backend(&self) -> Backend {
        Backend(self.bng.shared.clone())
    }
}

fn snap(users: usize, srv: PppoeServer, pool: u32) -> Snapshot {
    Snapshot { ppp: ppp(users, srv), pools: pools(pool), aaa: None, unix_base: 1_700_000_000 }
}

fn mass(n: usize) {
    let mut lab = Lab::new(n, snap(n, server(serde_json::json!({})), 65_000), |i| (format!("u{i}"), format!("p{i}")));
    lab.start(0..n);
    lab.run(400, 50);
    assert_eq!(lab.ups(), n, "every subscriber reaches Opened");
    lab.bng.check().unwrap();
    let active = lab.backend().active();
    assert_eq!(active.len(), n);
    let ips: std::collections::HashSet<_> = active.iter().filter_map(|a| a.address).collect();
    assert_eq!(ips.len(), n, "one address each");
    assert!(active.iter().all(|a| a.rate_limit.as_deref() == Some("10M/50M")));
    // Slow path (no XDP in the lab): one route per subscriber.
    let routes = lab.bng.effects.iter().filter(|e| matches!(e, Effect::Route { add: true, .. })).count();
    assert_eq!(routes, n);
}

#[test]
fn one_session_reaches_opened() {
    mass(1);
}

#[test]
fn a_hundred_sessions_reach_opened() {
    mass(100);
}

#[test]
fn ten_thousand_sessions_reach_opened() {
    mass(10_000);
}

#[test]
fn xdp_slots_follow_the_sessions() {
    let mut lab = Lab::new(50, snap(50, server(serde_json::json!({})), 1000), |i| (format!("u{i}"), format!("p{i}")));
    lab.bng.xdp = true;
    lab.start(0..50);
    lab.run(200, 50);
    assert_eq!(lab.ups(), 50);
    let ups: Vec<u32> = lab
        .bng
        .effects
        .iter()
        .filter_map(|e| match e {
            Effect::Xdp(PppoeOp::Upsert(i, s)) => {
                assert_eq!(s.down.rate_bps, 50_000_000, "tx = download");
                assert_eq!(s.up.rate_bps, 10_000_000, "rx = upload");
                assert!(s.fast_down && s.ipv4.is_some());
                Some(*i)
            }
            _ => None,
        })
        .collect();
    assert_eq!(ups.len(), 50);
    assert_eq!(ups.iter().collect::<std::collections::HashSet<_>>().len(), 50);
    lab.bng.effects.clear();
    let ids: Vec<String> = lab.backend().active().into_iter().map(|a| a.id).collect();
    assert_eq!(lab.backend().terminate(&ids), 50);
    lab.bng.requests(lab.now);
    lab.run(100, 50);
    let removed = lab.bng.effects.iter().filter(|e| matches!(e, Effect::Xdp(PppoeOp::Remove(_)))).count();
    assert_eq!(removed, 50, "every map entry goes");
    assert!(lab.backend().active().is_empty());
    assert_eq!(lab.ups(), 0);
}

#[test]
fn wrong_password_is_explained_by_why() {
    let mut lab = Lab::new(2, snap(2, server(serde_json::json!({})), 100), |i| {
        (format!("u{i}"), if i == 1 { "errada".into() } else { format!("p{i}") })
    });
    lab.start(0..2);
    lab.run(200, 50);
    assert_eq!(lab.ups(), 1);
    let w = lab.backend().why(Some("u1"), None);
    assert_eq!(w.last_stage, Some(Stage::Auth));
    let last = w.last.unwrap();
    assert_eq!(last.event, "failed");
    assert_eq!(last.reason, "auth-failed");
    assert_eq!(last.reply_message.as_deref(), Some("wrong password"));
    assert!(last.hint.contains("senha"));
    assert!(w.attempts.iter().any(|(s, n)| *s == Stage::Padi && *n >= 1));
    // By MAC too.
    let by_mac = lab.backend().why(None, Some(corerouter_model::MacAddr([0x02, 0x10, 0, 0, 1, 1])));
    assert_eq!(by_mac.last_stage, Some(Stage::Auth));
}

#[test]
fn pool_exhaustion_fails_at_ncp() {
    let mut lab = Lab::new(5, snap(5, server(serde_json::json!({})), 3), |i| (format!("u{i}"), format!("p{i}")));
    lab.start(0..5);
    lab.run(400, 50);
    assert_eq!(lab.ups(), 3, "three addresses, three subscribers");
    let failed: Vec<_> = lab.backend().history().into_iter().filter(|h| h.event == "failed").collect();
    assert!(!failed.is_empty());
    assert!(failed.iter().all(|h| h.reason == "ncp-failed" && h.stage == Some(Stage::Ncp)), "{failed:?}");
}

#[test]
fn coa_changes_the_rate_live_and_disconnect_ends() {
    let mut lab = Lab::new(3, snap(3, server(serde_json::json!({})), 100), |i| (format!("u{i}"), format!("p{i}")));
    lab.bng.xdp = true;
    lab.start(0..3);
    lab.run(200, 50);
    assert_eq!(lab.ups(), 3);
    lab.bng.effects.clear();
    let owner = Owner(lab.bng.shared.clone());
    let coa = |kind, user: &str, changes: Vec<Attribute>| CoaRequest {
        kind,
        from: "127.0.0.1:3799".parse().unwrap(),
        selector: CoaSelector { user_name: Some(user.into()), ..CoaSelector::default() },
        changes,
        authorize_only: false,
        packet: Vec::new(),
    };
    assert_eq!(owner.handle(&coa(CoaKind::Coa, "u0", vec![Attribute::new("Mikrotik-Rate-Limit", "20M/100M")])), CoaOutcome::Ack);
    assert_eq!(owner.handle(&coa(CoaKind::Coa, "nobody", vec![])), CoaOutcome::NotMine);
    assert_eq!(owner.handle(&coa(CoaKind::Coa, "u0", vec![Attribute::new("Mikrotik-Rate-Limit", "fast")])), CoaOutcome::Nak(407));
    lab.bng.requests(lab.now);
    let new_rate = lab.bng.effects.iter().find_map(|e| match e {
        Effect::Xdp(PppoeOp::Upsert(_, s)) => Some(s.down.rate_bps),
        _ => None,
    });
    assert_eq!(new_rate, Some(100_000_000));
    let u0 = lab.backend().active().into_iter().find(|a| a.name == "u0").unwrap();
    assert_eq!(u0.rate_limit.as_deref(), Some("20M/100M"));
    assert_eq!(lab.ups(), 3, "a CoA does not reconnect");
    assert_eq!(owner.handle(&coa(CoaKind::Disconnect, "u1", vec![])), CoaOutcome::Ack);
    lab.bng.requests(lab.now);
    lab.run(100, 50);
    assert!(lab.backend().active().iter().all(|a| a.name != "u1"));
    let h = lab.backend().history().into_iter().rev().find(|h| h.name == "u1").unwrap();
    assert_eq!((h.event.as_str(), h.reason.as_str()), ("down", "admin"));
}

#[test]
fn mass_reconnect_after_cpe_reboots_is_spread_by_the_rate() {
    let n = 2000;
    let srv = server(serde_json::json!({"new_session_rate": 500}));
    let mut lab = Lab::new(n, snap(n, srv, 65_000), |i| (format!("u{i}"), format!("p{i}")));
    lab.start(0..n);
    // The CPEs back off (RFC 2516 §5: PADR again after 1, 2, 4… s): 2000
    // over 500/s take more than 4 s.
    lab.run(1500, 50);
    assert_eq!(lab.ups(), n);
    assert!(lab.backend().stats().throttled > 0, "2000 at once over 500/s");
    // Every CPE reboots without PADT: one-session-per-host replaces each.
    for c in 0..n {
        // A fresh client with the same MAC and login: no PADT was sent.
        let cfg = lab.clients[c].config().clone();
        let mut seed = [9u8; 32];
        seed[..8].copy_from_slice(&(c as u64).to_le_bytes());
        lab.clients[c] = Client::new(cfg, seed);
        lab.up[c] = false;
        let mut out = ClientOutput::new();
        lab.clients[c].start(lab.now, &mut out);
        lab.feed(&mut out);
    }
    // The rate paces the wave: a token per PADI, 500 in the bucket, so the
    // last of 2000 cannot be in before (2000 − 500) / 500 = 3 s.
    let t0 = lab.now;
    let mut rounds = 0;
    while lab.ups() < n && rounds < 1500 {
        lab.run(1, 50);
        rounds += 1;
    }
    let took = lab.now - t0;
    eprintln!("reconnect of {n} at 500/s: {took} ms");
    assert!(took >= 3000, "the rate paced the reconnect: {took} ms");
    lab.run(100, 50);
    assert_eq!(lab.ups(), n, "all back");
    assert_eq!(lab.backend().active().len(), n, "nothing duplicated");
    lab.bng.check().unwrap();
    let replaced = lab.backend().history().iter().filter(|h| h.reason == "replaced").count();
    assert_eq!(replaced, n);
}

#[test]
fn only_one_caller_id_and_disabled_are_enforced() {
    let mut s = snap(3, server(serde_json::json!({})), 100);
    s.ppp.profiles[0].only_one = corerouter_model::ppp::Tri::Yes;
    let mut secrets: Vec<PppSecret> = s.ppp.secrets.to_vec();
    secrets[1].caller_id = Some(corerouter_model::MacAddr([9; 6]));
    secrets[2].disabled = true;
    s.ppp.secrets = corerouter_model::cow::CowArc::new(secrets);
    // Clients 0 and 3 are both u0.
    let mut lab = Lab::new(4, s, |i| if i == 3 { ("u0".into(), "p0".into()) } else { (format!("u{i}"), format!("p{i}")) });
    lab.start(0..1);
    lab.run(100, 50);
    lab.start(1..4);
    lab.run(200, 50);
    assert_eq!(lab.ups(), 1);
    let msg = |u: &str| lab.backend().why(Some(u), None).last.and_then(|l| l.reply_message);
    assert_eq!(msg("u1").as_deref(), Some("caller-id mismatch"));
    assert_eq!(msg("u2").as_deref(), Some("secret disabled"));
    let h = lab.backend().history();
    assert!(h.iter().any(|h| h.name == "u0" && h.reply_message.as_deref().is_some_and(|m| m.starts_with("only-one"))));
}

#[test]
fn slow_path_carries_ipv4_both_ways() {
    let mut lab = Lab::new(1, snap(1, server(serde_json::json!({})), 10), |_| ("u0".into(), "p0".into()));
    lab.start(0..1);
    lab.run(100, 50);
    let a = lab.backend().active().pop().unwrap();
    let ip = a.address.unwrap();
    // Upstream: an IPv4 packet from the subscriber's address.
    let mut pkt = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0];
    pkt.extend_from_slice(&ip.octets());
    pkt.extend_from_slice(&[8, 8, 8, 8]);
    let mut f = Vec::new();
    f.extend_from_slice(&BNG_MAC);
    f.extend_from_slice(&[0x02, 0x10, 0, 0, 0, 1]);
    f.extend_from_slice(&[0x88, 0x64, 0x11, 0x00]);
    f.extend_from_slice(&a.session_id.to_be_bytes());
    f.extend_from_slice(&(pkt.len() as u16 + 2).to_be_bytes());
    f.extend_from_slice(&[0x00, 0x21]);
    f.extend_from_slice(&pkt);
    lab.bng.frame(lab.now, IFINDEX, &f);
    assert_eq!(lab.bng.upstream, vec![pkt.clone()]);
    // A spoofed source is dropped (anti-spoofing like the XDP).
    let mut spoof = f.clone();
    let at = spoof.len() - 8;
    spoof[at] = 10;
    lab.bng.frame(lab.now, IFINDEX, &spoof);
    assert_eq!(lab.bng.upstream.len(), 1);
    // Downstream: to the subscriber's address.
    let mut back = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 8, 8, 8, 8];
    back.extend_from_slice(&ip.octets());
    lab.bng.data_down(&back);
    let (ifindex, frame) = lab.bng.frames.pop().unwrap();
    assert_eq!(ifindex, IFINDEX);
    assert_eq!(&frame[..6], &[0x02, 0x10, 0, 0, 0, 1]);
    assert_eq!(&frame[12..14], &[0x88, 0x64]);
    assert_eq!(&frame[22..], &back[..]);
    lab.bng.tick(lab.now, &[]);
    let a = lab.backend().active().pop().unwrap();
    assert_eq!((a.rx_packets, a.tx_packets), (1, 1));
    assert_eq!(lab.backend().who(ip).as_deref(), Some("u0"));
}

/// A RADIUS service that answers at once from a table.
#[derive(Default)]
struct FakeAaa {
    accts: Mutex<Vec<AcctRequest>>,
}

impl AaaBackend for FakeAaa {
    fn authenticate(&self, req: AuthRequest, done: AuthDone) {
        let ok = matches!(&req.credentials, corerouter_model::radius::Credentials::Chap { .. } | corerouter_model::radius::Credentials::MsChapV2 { .. } | corerouter_model::radius::Credentials::Pap { .. })
            && req.user.starts_with("r");
        let mut reply = AuthReply::failed(if ok { AuthOutcome::Accept } else { AuthOutcome::Reject }, "");
        reply.message = None;
        if ok {
            reply.attributes = vec![
                Attribute::new("Framed-IP-Address", "100.65.0.9"),
                Attribute::new("Mikrotik-Rate-Limit", "5M/25M"),
            ];
        } else {
            reply.attributes = vec![Attribute::new("Reply-Message", "Inadimplente")];
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

#[test]
fn radius_users_get_framed_ip_rate_and_accounting() {
    let aaa = Arc::new(FakeAaa::default());
    let mut s = snap(0, server(serde_json::json!({"authentication": ["pap"]})), 10);
    s.ppp.aaa.use_radius = true;
    s.aaa = Some(aaa.clone());
    let mut lab = Lab::new(2, s, |i| (if i == 0 { "radius-user".into() } else { "bloqueado".into() }, "x".into()));
    lab.clients[0] = {
        let mut cfg = lab.clients[0].config().clone();
        cfg.auth = corerouter_proto_pppoe::layers::AuthSet::new(&[corerouter_proto_pppoe::lcp::AuthProto::Pap]);
        Client::new(cfg, [5; 32])
    };
    lab.clients[1] = {
        let mut cfg = lab.clients[1].config().clone();
        cfg.auth = corerouter_proto_pppoe::layers::AuthSet::new(&[corerouter_proto_pppoe::lcp::AuthProto::Pap]);
        Client::new(cfg, [6; 32])
    };
    lab.start(0..2);
    lab.run(200, 50);
    assert_eq!(lab.ups(), 1);
    let a = lab.backend().active().pop().unwrap();
    assert_eq!(a.address, Some(Ipv4Addr::new(100, 65, 0, 9)));
    assert_eq!(a.rate_limit.as_deref(), Some("5M/25M"));
    assert!(a.radius);
    let w = lab.backend().why(Some("bloqueado"), None);
    assert_eq!(w.last.unwrap().reply_message.as_deref(), Some("Inadimplente"));
    lab.backend().terminate(std::slice::from_ref(&a.id));
    lab.bng.requests(lab.now);
    lab.run(100, 50);
    let accts = aaa.accts.lock().unwrap();
    let kinds: Vec<AcctStatus> = accts.iter().map(|r| r.status).collect();
    assert_eq!(kinds, [AcctStatus::Start, AcctStatus::Stop]);
    assert_eq!(accts[1].terminate_cause, Some(6), "Admin-Reset (RFC 2866 §5.10)");
    assert_eq!(accts[0].session_id, accts[1].session_id);
    let _ = ClientPhase::Idle;
}
