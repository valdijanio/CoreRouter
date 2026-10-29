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

pub(super) const IFINDEX: u32 = 7;
pub(super) const BNG_MAC: [u8; 6] = [0x02, 0xBB, 0, 0, 0, 1];

pub(super) fn server(json: serde_json::Value) -> PppoeServer {
    let mut base = serde_json::json!({"id": "*1", "name": "pppoe-ether2", "interface": "ether2", "padi_limit": 0, "mac_padi_limit": 0, "new_session_rate": 0});
    if let (Some(b), Some(extra)) = (base.as_object_mut(), json.as_object()) {
        for (k, v) in extra {
            b.insert(k.clone(), v.clone());
        }
    }
    serde_json::from_value(base).unwrap()
}

pub(super) fn pools_of(size: u32) -> IpPools {
    pools(size)
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

pub(super) fn ppp(users: usize, srv: PppoeServer) -> Ppp {
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
            password: format!("p{i}").into(),
            profile: "default".into(),
            ..PppSecret::default()
        })
        .collect();
    p.secrets = corerouter_model::ppp_secrets::Secrets::new(secrets);
    p.pppoe_servers.push(srv);
    p
}

/// N clients and the BNG, a fake clock and a perfect wire.
pub(super) struct Lab {
    pub(super) bng: Bng,
    pub(super) clients: Vec<Client>,
    by_mac: HashMap<[u8; 6], usize>,
    pub(super) now: u64,
    pub(super) up: Vec<bool>,
    downs: Vec<usize>,
    /// IPv6 packets (PPP protocol 0x0057) each client received (G4.3e).
    v6: Vec<Vec<Vec<u8>>>,
}

impl Lab {
    pub(super) fn new(n: usize, snap: Snapshot, auth: impl Fn(usize) -> (String, String)) -> Self {
        Self::with(n, snap, auth, |_, _| {})
    }

    /// [`Lab::new`] with each client's config edited by `tweak`.
    fn with(
        n: usize,
        snap: Snapshot,
        auth: impl Fn(usize) -> (String, String),
        tweak: impl Fn(usize, &mut ClientConfig),
    ) -> Self {
        let mut bng = Bng::new([7; 32]);
        let ports = HashMap::from([("pppoe-ether2".to_owned(), PortInfo { ifindex: IFINDEX, mac: BNG_MAC })]);
        bng.configure(0, snap, &ports);
        let mut clients = Vec::new();
        let mut by_mac = HashMap::new();
        for i in 0..n {
            let (user, password) = auth(i);
            let mac = [0x02, 0x10, (i >> 16) as u8, (i >> 8) as u8, i as u8, 0x01];
            let mut cfg = ClientConfig {
                mac: Mac(mac),
                ifindex: IFINDEX,
                username: user.into_bytes(),
                password,
                discovery_timeout_ms: 1000,
                discovery_attempts: 10,
                discovery_jitter_pct: 25,
                keepalive_interval_ms: 0,
                ..ClientConfig::default()
            };
            tweak(i, &mut cfg);
            let mut seed = [3u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            clients.push(Client::new(cfg, seed));
            by_mac.insert(mac, i);
        }
        let up = vec![false; n];
        let downs = vec![0; n];
        let v6 = vec![Vec::new(); n];
        Self { bng, clients, by_mac, now: 0, up, downs, v6 }
    }

    pub(super) fn start(&mut self, range: std::ops::Range<usize>) {
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
    pub(super) fn run(&mut self, rounds: usize, step: u64) {
        let mut out = ClientOutput::new();
        for _ in 0..rounds {
            // G4.3hh: like the worker, a takeover a chunk per round, then
            // its bookkeeping.
            if self.bng.ha_adopting() {
                self.bng.ha_adopt_step(self.now);
            } else if self.bng.ha_later() {
                self.bng.ha_adopt_rest(self.now);
            }
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
                        // IPv6 to the client (any tags): kept for the test.
                        if let Ok(sf) = corerouter_proto_pppoe::ppp::parse_session(&f)
                            && sf.protocol == 0x0057
                        {
                            self.v6[c].push(sf.info.to_vec());
                            continue;
                        }
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

    pub(super) fn ups(&self) -> usize {
        self.up.iter().filter(|u| **u).count()
    }

    pub(super) fn backend(&self) -> Backend {
        Backend(self.bng.shared.clone())
    }
}

pub(super) fn snap(users: usize, srv: PppoeServer, pool: u32) -> Snapshot {
    Snapshot { ppp: ppp(users, srv), pools: pools(pool), aaa: None, unix_base: 1_700_000_000, ..Snapshot::default() }
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

/// G4.3n: the passwords are sealed in the config; the BNG opens them with
/// the session's key, and a box of another key is a refused login.
#[test]
fn sealed_passwords_log_in_with_the_key_only() {
    let key = std::sync::Arc::new(corerouter_engine::sealing::SealKey::from_bytes(&[3; 32]));
    let mut sn = snap(2, server(serde_json::json!({})), 100);
    for x in sn.ppp.secrets.iter_mut() {
        x.password = key.seal(x.password.stored()).unwrap();
    }
    sn.seal = Some(key);
    let mut lab = Lab::new(2, sn.clone(), |i| (format!("u{i}"), format!("p{i}")));
    lab.start(0..2);
    lab.run(200, 50);
    assert_eq!(lab.ups(), 2, "sealed passwords open");
    sn.seal = Some(std::sync::Arc::new(corerouter_engine::sealing::SealKey::from_bytes(&[4; 32])));
    let mut lab = Lab::new(1, sn, |i| (format!("u{i}"), format!("p{i}")));
    lab.start(0..1);
    lab.run(200, 50);
    assert_eq!(lab.ups(), 0);
    let last = lab.backend().why(Some("u0"), None).last.unwrap();
    assert!(last.reply_message.unwrap_or_default().contains("cannot be opened"));
}

#[test]
fn pool_exhaustion_fails_at_ncp() {
    let mut lab = Lab::new(5, snap(5, server(serde_json::json!({})), 3), |i| (format!("u{i}"), format!("p{i}")));
    lab.start(0..5);
    // Without an IPv4 address the session still waits for IPv6CP (an
    // IPv6-only subscriber is fine, G4.3e); this CPE never answers it, so
    // the session fails when IPv6CP gives up (RFC 1661 §4.6 Max-Configure,
    // 10 × 3 s).
    lab.run(800, 50);
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
    // The arrears notice: the billing moves u2 into a list, live.
    lab.bng.effects.clear();
    assert_eq!(owner.handle(&coa(CoaKind::Coa, "u2", vec![Attribute::new("Mikrotik-Address-List", "inadimplentes")])), CoaOutcome::Ack);
    assert_eq!(owner.handle(&coa(CoaKind::Coa, "u2", vec![Attribute::new("Mikrotik-Address-List", "not a list")])), CoaOutcome::Nak(407));
    lab.bng.requests(lab.now);
    assert!(
        lab.bng.effects.iter().any(|e| matches!(e, Effect::AddressList { list, add: true, .. } if list == "inadimplentes")),
        "{:?}",
        lab.bng.effects
    );
    assert_eq!(owner.handle(&coa(CoaKind::Disconnect, "u1", vec![])), CoaOutcome::Ack);
    lab.bng.requests(lab.now);
    lab.run(100, 50);
    assert!(lab.backend().active().iter().all(|a| a.name != "u1"));
    let h = lab.backend().history().into_iter().rev().find(|h| h.name == "u1").unwrap();
    assert_eq!((h.event.as_str(), h.reason.as_str()), ("down", "admin"));
}

/// G4.3hk: the session shows the CoA's rate when the ACK leaves (RFC 5176
/// §3: the ACK says the change was made), not only after the worker's next
/// turn: under load that turn came after the RADIUS server (and the netns
/// test) read the session back.
#[test]
fn coa_rate_is_on_the_session_when_the_ack_leaves() {
    let mut lab = Lab::new(2, snap(2, server(serde_json::json!({})), 100), |i| (format!("u{i}"), format!("p{i}")));
    lab.start(0..2);
    lab.run(200, 50);
    assert_eq!(lab.ups(), 2);
    let owner = Owner(lab.bng.shared.clone());
    let req = CoaRequest {
        kind: CoaKind::Coa,
        from: "127.0.0.1:3799".parse().unwrap(),
        selector: CoaSelector { user_name: Some("u0".into()), ..CoaSelector::default() },
        changes: vec![Attribute::new("Mikrotik-Rate-Limit", "9M/9M")],
        authorize_only: false,
        packet: Vec::new(),
    };
    assert_eq!(owner.handle(&req), CoaOutcome::Ack);
    // No worker turn yet.
    let rate = |lab: &Lab| lab.backend().active().into_iter().find(|a| a.name == "u0").and_then(|a| a.rate_limit);
    assert_eq!(rate(&lab).as_deref(), Some("9M/9M"));
    lab.bng.requests(lab.now);
    assert_eq!(rate(&lab).as_deref(), Some("9M/9M"));
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
    s.ppp.secrets = corerouter_model::ppp_secrets::Secrets::new(secrets);
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
    lab.now += 1000;
    lab.bng.tick(lab.now, &[]);
    let a = lab.backend().active().pop().unwrap();
    assert_eq!((a.rx_packets, a.tx_packets), (1, 1));
    assert!(a.rx_bps > 0 && a.tx_bps > 0, "the rates of the last second: {a:?}");
    assert_eq!(lab.backend().who(ip).as_deref(), Some("u0"));
}

/// G4.3ha: the Class every RADIUS login of [`FakeAaa`] gets (binary: a NUL
/// and 0xff, which no text form keeps).
pub(super) const FAKE_CLASS: &[u8] = &[0x00, 0xff, b'p', b'l', b'a', b'n', b'o', 0x00];

/// A RADIUS service that answers at once from a table.
#[derive(Default)]
pub(super) struct FakeAaa {
    pub(super) accts: Mutex<Vec<AcctRequest>>,
    asked: Mutex<Vec<AuthRequest>>,
}

impl AaaBackend for FakeAaa {
    fn authenticate(&self, req: AuthRequest, done: AuthDone) {
        self.asked.lock().unwrap().push(req.clone());
        let ok = matches!(&req.credentials, corerouter_model::radius::Credentials::Chap { .. } | corerouter_model::radius::Credentials::MsChapV2 { .. } | corerouter_model::radius::Credentials::Pap { .. })
            && req.user.starts_with("r");
        let mut reply = AuthReply::failed(if ok { AuthOutcome::Accept } else { AuthOutcome::Reject }, "");
        reply.message = None;
        if ok {
            reply.attributes = vec![
                // One address per login: `r3` gets .12, `radius-user` .9.
                Attribute::new(
                    "Framed-IP-Address",
                    format!("100.65.0.{}", 9 + req.user.trim_start_matches(|c: char| !c.is_ascii_digit()).parse::<u8>().unwrap_or(0)),
                ),
                Attribute::new("Mikrotik-Rate-Limit", "5M/25M"),
            ];
            // The Class is read from the packet, as it came (RFC 2865 §5.25).
            let mut b = corerouter_proto_radius::packet::Builder::new(corerouter_proto_radius::packet::Code::AccessAccept, 1);
            corerouter_proto_radius::packet::PushAttr::push(&mut b, corerouter_proto_radius::packet::attr::CLASS, FAKE_CLASS).unwrap();
            reply.packet = b.into_unsigned();
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
    // G4.3ha: the Accept's Class in the Start and the Stop, byte for byte.
    assert!(accts.iter().all(|r| r.class == [FAKE_CLASS.to_vec()]), "{accts:?}");
    let _ = ClientPhase::Idle;
}

#[test]
fn a_session_that_fails_before_login_is_explained_by_its_mac() {
    // The server offers only MS-CHAPv2; the CPE speaks only PAP: LCP never
    // agrees (RFC 1661 §4.6 Max-Failure), no login is ever seen.
    let mut lab = Lab::new(1, snap(1, server(serde_json::json!({"authentication": ["mschap2"]})), 10), |_| ("u0".into(), "p0".into()));
    lab.clients[0] = {
        let mut cfg = lab.clients[0].config().clone();
        cfg.auth = corerouter_proto_pppoe::layers::AuthSet::new(&[corerouter_proto_pppoe::lcp::AuthProto::Pap]);
        Client::new(cfg, [8; 32])
    };
    lab.start(0..1);
    lab.run(1500, 50);
    assert_eq!(lab.ups(), 0);
    let w = lab.backend().why(None, Some(corerouter_model::MacAddr([0x02, 0x10, 0, 0, 0, 1])));
    let last = w.last.expect("the MAC has a last failure");
    assert_eq!(last.event, "failed");
    assert_eq!(last.stage, Some(Stage::Lcp), "{last:?}");
    assert_eq!(last.reason, "auth-protocol");
    assert!(last.hint.contains("métodos de autenticação"), "{last:?}");
}

// ---- G4.3e: dual stack ------------------------------------------------------

fn pools6() -> Vec<corerouter_model::dhcp6_server::Ipv6Pool> {
    let p = |name: &str, prefix: &str, len: u8| corerouter_model::dhcp6_server::Ipv6Pool {
        id: ItemId(1),
        name: name.into(),
        prefix: prefix.parse().unwrap(),
        prefix_length: len,
        comment: String::new(),
    };
    vec![p("wan6", "2001:db8:100::/48", 64), p("pd6", "2001:db8:8000::/40", 56)]
}

fn dual(n: usize) -> Snapshot {
    let mut s = snap(n, server(serde_json::json!({})), 65_000);
    s.pools6 = pools6();
    s.iid_key = Some([0x43; 32]);
    let pr = &mut s.ppp.profiles[0];
    pr.remote_ipv6_prefix_pool = Some("wan6".into());
    pr.dhcpv6_pd_pool = Some("pd6".into());
    pr.dns_server_ipv6 = vec!["2001:db8::53".parse().unwrap()];
    s
}

fn v6_clients(lab: &mut Lab) {
    for i in 0..lab.clients.len() {
        let mut cfg = lab.clients[i].config().clone();
        cfg.ipv6 = true;
        let mut seed = [4u8; 32];
        seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
        lab.clients[i] = Client::new(cfg, seed);
    }
}

/// A PPPoE session frame with an IPv6 packet from client `c`.
fn v6_frame(lab: &Lab, c: usize, packet: &[u8]) -> Vec<u8> {
    let cl = &lab.clients[c];
    let mut f = Vec::new();
    f.extend_from_slice(&BNG_MAC);
    f.extend_from_slice(&cl.config().mac.0);
    f.extend_from_slice(&[0x88, 0x64, 0x11, 0x00]);
    f.extend_from_slice(&cl.session_id().to_be_bytes());
    f.extend_from_slice(&((packet.len() + 2) as u16).to_be_bytes());
    f.extend_from_slice(&[0x00, 0x57]);
    f.extend_from_slice(packet);
    f
}

fn solicit(c: usize) -> Vec<u8> {
    use corerouter_proto_dhcp::v6::{IaReq, Outgoing, msg};
    let duid = [0, 3, 0, 1, 2, 0x10, (c >> 16) as u8, (c >> 8) as u8, c as u8, 1];
    Outgoing {
        kind: msg::SOLICIT,
        xid: c as u32 & 0xff_ffff,
        client_id: &duid,
        server_id: None,
        elapsed_cs: 0,
        rapid_commit: true,
        ia_na: Some(IaReq { iaid: 1, ..IaReq::default() }),
        ia_pd: Some(IaReq { iaid: 2, ..IaReq::default() }),
        oro: &[23],
    }
    .encode()
}

#[test]
fn dual_stack_sessions_get_a_64_a_delegated_prefix_and_dns() {
    use corerouter_proto_pppoe::nd;
    let n = 1000;
    let mut lab = Lab::new(n, dual(n), |i| (format!("u{i}"), format!("p{i}")));
    lab.bng.xdp = true;
    v6_clients(&mut lab);
    lab.start(0..n);
    lab.run(400, 50);
    assert_eq!(lab.ups(), n);
    lab.bng.check().unwrap();
    let active = lab.backend().active();
    let by_name: HashMap<String, _> = active.iter().map(|a| (a.name.clone(), a.clone())).collect();
    let p64: std::collections::HashSet<_> = active.iter().filter_map(|a| a.ipv6_prefix).collect();
    let pds: std::collections::HashSet<_> = active.iter().filter_map(|a| a.delegated_prefix).collect();
    assert_eq!((p64.len(), pds.len()), (n, n), "one /64 and one /56 each");
    assert!(pds.iter().all(|p| p.prefix_len() == 56));
    // XDP knows both prefixes of every session.
    let mut v6_slots = 0;
    for e in &lab.bng.effects {
        if let Effect::Xdp(PppoeOp::Upsert(_, s)) = e
            && s.ipv6_prefix.is_some()
            && s.delegated.is_some_and(|d| d.1 == 56)
        {
            v6_slots += 1;
        }
    }
    assert!(v6_slots >= n, "{v6_slots}");
    // Each client got an RA (RFC 4861 §6.2.4: at once) with its /64 and the RDNSS.
    for c in 0..n {
        let a = &by_name[&format!("u{c}")];
        let ra = lab.v6[c].iter().find_map(|p| nd::parse_ra(p).ok()).expect("an RA");
        let (_, peer) = lab.clients[c].ipv6_iids().unwrap();
        assert_eq!(ra.src, nd::link_local(peer), "from the BNG's IPv6CP identifier");
        assert_eq!(ra.prefixes[0].prefix, a.ipv6_prefix.unwrap().network());
        assert!(ra.prefixes[0].autonomous && ra.prefixes[0].on_link);
        assert_eq!(ra.rdnss, vec!["2001:db8::53".parse::<std::net::Ipv6Addr>().unwrap()]);
        assert!(ra.other, "O: DHCPv6 has a prefix");
        assert_eq!(a.link_local, Some(nd::link_local(lab.clients[c].ipv6_iids().unwrap().0)));
    }
    // DHCPv6-PD: a Solicit with Rapid Commit binds the session's /56.
    for v in lab.v6.iter_mut() {
        v.clear();
    }
    for c in 0..n {
        let (ours, _) = lab.clients[c].ipv6_iids().unwrap();
        let mut p = Vec::new();
        nd::udp6(&mut p, nd::link_local(ours), nd::ALL_DHCP, 546, 547, &solicit(c));
        let f = v6_frame(&lab, c, &p);
        lab.bng.frame(lab.now, IFINDEX, &f);
    }
    lab.run(2, 50);
    for c in 0..n {
        let a = lab.backend().active().into_iter().find(|a| a.name == format!("u{c}")).unwrap();
        assert!(a.delegated_bound);
        let reply = lab.v6[c].iter().find_map(|p| {
            let h = nd::parse_ipv6(p).ok()?;
            corerouter_proto_dhcp::v6::decode(h.payload.get(8..)?).ok()
        });
        let r = reply.expect("a DHCPv6 Reply");
        assert!(r.rapid_commit);
        assert_eq!(r.ia_pd[0].prefixes[0].prefix, a.delegated_prefix.unwrap());
        // IA_NA: the /64 + the subscriber's identifier (what SLAAC gives).
        let (ours, _) = lab.clients[c].ipv6_iids().unwrap();
        assert_eq!(r.ia_na[0].addrs[0].addr, nd::with_iid(a.ipv6_prefix.unwrap().network(), ours));
    }
    let st = lab.backend().stats();
    assert_eq!((st.ipv6_sessions, st.delegated), (n as u64, n as u64));
    // An RS gets a unicast RA, but only one in 3 s.
    lab.v6[0].clear();
    let (ours, _) = lab.clients[0].ipv6_iids().unwrap();
    let mut rs = Vec::new();
    nd::router_solicit(&mut rs, nd::link_local(ours));
    let f = v6_frame(&lab, 0, &rs);
    lab.now += 5000;
    lab.bng.frame(lab.now, IFINDEX, &f);
    lab.bng.frame(lab.now, IFINDEX, &f);
    lab.run(1, 10);
    let ras: Vec<_> = lab.v6[0].iter().filter_map(|p| nd::parse_ra(p).ok()).collect();
    assert_eq!(ras.len(), 1);
    assert_eq!(lab.backend().stats().ipv6_dropped, 1);
    // Everyone leaves: every prefix goes back.
    let ids: Vec<String> = lab.backend().active().into_iter().map(|a| a.id).collect();
    lab.backend().terminate(&ids);
    lab.bng.requests(lab.now);
    lab.run(100, 50);
    assert!(lab.backend().active().is_empty());
    lab.bng.check().unwrap();
}

#[test]
fn periodic_ras_are_spread_between_min_and_max() {
    use corerouter_proto_pppoe::nd;
    let n = 200;
    let mut lab = Lab::new(n, dual(n), |i| (format!("u{i}"), format!("p{i}")));
    v6_clients(&mut lab);
    lab.start(0..n);
    lab.run(200, 50);
    assert_eq!(lab.ups(), n);
    for v in lab.v6.iter_mut() {
        v.clear();
    }
    // 20 minutes later every session has had its 3 initial RAs (≤ 16 s
    // apart, RFC 4861 §6.2.4) and one or two more (200–600 s).
    lab.run(1200, 1000);
    for c in 0..n {
        let ras = lab.v6[c].iter().filter(|p| nd::parse_ra(p).is_ok()).count();
        assert!((3..=8).contains(&ras), "client {c}: {ras} RAs");
    }
}

#[test]
fn use_ipv6_no_leaves_the_session_on_ipv4() {
    let n = 5;
    let mut s = dual(n);
    s.ppp.profiles[0].use_ipv6 = corerouter_model::ppp::UseIpv6::No;
    let mut lab = Lab::new(n, s, |i| (format!("u{i}"), format!("p{i}")));
    v6_clients(&mut lab);
    lab.start(0..n);
    lab.run(200, 50);
    assert_eq!(lab.ups(), n);
    for a in lab.backend().active() {
        assert!(a.address.is_some() && a.link_local.is_none() && a.ipv6_prefix.is_none(), "{a:?}");
    }
    assert!(lab.v6.iter().all(Vec::is_empty));
    lab.bng.check().unwrap();
}

/// RADIUS gives the prefixes (RFC 3162/4818): they win over the profile,
/// and the accounting names them from the Start (RouterOS does not).
#[test]
fn radius_prefixes_win_and_reach_the_accounting() {
    struct V6Aaa(FakeAaa);
    impl AaaBackend for V6Aaa {
        fn authenticate(&self, req: AuthRequest, done: AuthDone) {
            let mut reply = AuthReply::failed(AuthOutcome::Accept, "");
            reply.message = None;
            reply.attributes = vec![
                Attribute::new("Framed-IPv6-Prefix", "2001:db8:aaaa:1::/64"),
                Attribute::new("Delegated-IPv6-Prefix", "2001:db8:bbbb::/48"),
                Attribute::new("DNS-Server-IPv6-Address", "2001:db8::99"),
            ];
            let _ = req;
            done(reply);
        }
        fn account(&self, req: AcctRequest, s: Option<Arc<dyn AcctSource>>) -> Result<(), String> {
            self.0.account(req, s)
        }
        fn register_owner(&self, _: Arc<dyn SessionOwner>) {}
        fn status(&self) -> RadiusStatus {
            RadiusStatus::default()
        }
    }
    let aaa = Arc::new(V6Aaa(FakeAaa::default()));
    let mut s = dual(0);
    s.ppp.aaa.use_radius = true;
    s.aaa = Some(aaa.clone());
    let mut lab = Lab::new(2, s, |i| (format!("r{i}"), "x".into()));
    v6_clients(&mut lab);
    for i in 0..2 {
        let mut cfg = lab.clients[i].config().clone();
        cfg.auth = corerouter_proto_pppoe::layers::AuthSet::new(&[corerouter_proto_pppoe::lcp::AuthProto::Pap]);
        lab.clients[i] = Client::new(cfg, [9 + i as u8; 32]);
    }
    lab.start(0..2);
    lab.run(200, 50);
    assert_eq!(lab.ups(), 2);
    let active = lab.backend().active();
    // The same fixed prefixes for two sessions: the second one cannot have
    // them (one owner per prefix) and says so in the log.
    let with: Vec<_> = active.iter().filter(|a| a.ipv6_prefix == Some("2001:db8:aaaa:1::/64".parse().unwrap())).collect();
    assert_eq!(with.len(), 1);
    assert_eq!(with[0].delegated_prefix, Some("2001:db8:bbbb::/48".parse().unwrap()));
    let logs: Vec<String> = lab.bng.effects.iter().filter_map(|e| match e {
        Effect::Log { error: true, text } => Some(text.clone()),
        _ => None,
    }).collect();
    assert!(logs.iter().any(|t| t.contains("já está em uso")), "{logs:?}");
    let ra = lab.v6.iter().flatten().find_map(|p| corerouter_proto_pppoe::nd::parse_ra(p).ok()).unwrap();
    assert!(ra.rdnss.contains(&"2001:db8::99".parse().unwrap()));
    let accts = aaa.0.accts.lock().unwrap();
    let start = accts.iter().find(|r| r.status == AcctStatus::Start && r.attributes.iter().any(|a| a.value == "2001:db8:aaaa:1::/64")).expect("a Start with the /64");
    assert!(start.attributes.iter().any(|a| a.name == "Delegated-IPv6-Prefix" && a.value == "2001:db8:bbbb::/48"));
    assert!(start.attributes.iter().any(|a| a.name == "Framed-Interface-Id"));
}

/// G4.3g: four workers on one port, frames handed out by the client's MAC
/// as the driver does. Every subscriber comes up, no SESSION_ID or address
/// is given twice, and the load spreads.
#[test]
fn workers_split_one_port_without_collisions() {
    let n = 4000;
    let lanes = 4u16;
    let s = snap(n, server(serde_json::json!({})), 65_000);
    let ports = HashMap::from([("pppoe-ether2".to_owned(), PortInfo { ifindex: IFINDEX, mac: BNG_MAC })]);
    let mut bngs = vec![Bng::first_of([7; 32], lanes)];
    for l in 1..lanes {
        let b = bngs[0].sibling([7 + l as u8; 32], l, lanes);
        bngs.push(b);
    }
    for b in &mut bngs {
        b.configure(0, s.clone(), &ports);
    }
    // The clients of a lab (its own BNG is not used).
    let mut lab = Lab::new(n, s.clone(), |i| (format!("u{i}"), format!("p{i}")));
    let mut out = ClientOutput::new();
    for c in &mut lab.clients {
        c.start(0, &mut out);
    }
    let mut wire: Vec<Vec<u8>> = out.frames().map(|(_, f)| f.to_vec()).collect();
    out.clear();
    let mut per_lane = vec![0usize; usize::from(lanes)];
    while !wire.is_empty() {
        for f in wire.drain(..) {
            let lane = Bng::lane_of(&f, lanes);
            per_lane[usize::from(lane)] += 1;
            bngs[usize::from(lane)].frame(0, IFINDEX, &f);
        }
        for b in &mut bngs {
            b.effects.clear();
            for (_, f) in b.frames.drain(..) {
                let mut dst = [0u8; 6];
                dst.copy_from_slice(&f[..6]);
                if let Some(&c) = lab.by_mac.get(&dst) {
                    lab.clients[c].handle_frame(0, &f, &mut out);
                    lab.events(c, &mut out);
                    wire.extend(out.frames().map(|(_, f)| f.to_vec()));
                    out.clear();
                }
            }
        }
    }
    assert_eq!(lab.ups(), n, "every subscriber up");
    for b in &bngs {
        b.check().unwrap();
    }
    let active = Backend(bngs[0].shared.clone()).active();
    assert_eq!(active.len(), n);
    let ips: std::collections::HashSet<_> = active.iter().filter_map(|a| a.address).collect();
    assert_eq!(ips.len(), n, "one address each across the workers");
    let ids: std::collections::HashSet<_> = active.iter().map(|a| a.session_id).collect();
    assert_eq!(ids.len(), n, "one SESSION_ID each on the port");
    for (l, frames) in per_lane.iter().enumerate() {
        let share = *frames as f64 / per_lane.iter().sum::<usize>() as f64;
        assert!((0.15..0.35).contains(&share), "lane {l} got {share:.2} of the frames");
    }
    // ppp.active.remove of one session: only its worker takes it.
    let id = active[0].id.clone();
    Backend(bngs[0].shared.clone()).terminate(std::slice::from_ref(&id));
    for b in &mut bngs {
        b.requests(0);
    }
    let frames: usize = bngs.iter().map(|b| b.frames.len()).sum();
    assert!(frames >= 1, "the owner sent the Terminate-Request");
}

/// A RADIUS server of fixed capacity on the lab's clock (G4.3g): one FIFO
/// for authentication and accounting, `cap` requests a second, at most
/// two seconds of work queued (the rest is lost), and the client gives up
/// on a login after 8 s (`Retry::ACCESS` MRD) while the server may still
/// work on it. The shape of a MK-Auth/IXC in a mass reconnect. Accounting
/// waits in the client while [`AUTH_BUSY`] logins are out, as
/// `radius_aaa` holds it.
struct SlowAaa {
    cap: f64,
    st: Mutex<SlowState>,
}

#[derive(Default)]
struct SlowState {
    queue: std::collections::VecDeque<(Option<AuthDone>, u64)>,
    /// Accounting the client holds back; logins sent and unanswered.
    held: u64,
    logins: u64,
    lost: Vec<(AuthDone, u64)>,
    tokens: f64,
    at: u64,
    now: u64,
    timeouts: u64,
    served: u64,
}

const GIVE_UP_MS: u64 = 8000;
/// `radius_aaa::AUTH_BUSY`.
const AUTH_BUSY: u64 = 64;

impl SlowAaa {
    fn new(cap: f64) -> Self {
        Self { cap, st: Mutex::new(SlowState::default()) }
    }

    fn push(&self, done: Option<AuthDone>) {
        let mut st = self.st.lock().unwrap();
        let now = st.now;
        if done.is_none() && st.logins >= AUTH_BUSY {
            st.held += 1;
            return;
        }
        if done.is_some() {
            st.logins += 1;
        }
        if st.queue.len() as f64 >= 2.0 * self.cap {
            if let Some(d) = done {
                st.lost.push((d, now));
            }
            return;
        }
        st.queue.push_back((done, now));
    }

    /// Advance the server to `now`, answering what it can.
    fn pump(&self, now: u64) {
        let mut answers: Vec<(AuthDone, AuthReply)> = Vec::new();
        {
            let mut st = self.st.lock().unwrap();
            let dt = now.saturating_sub(st.at) as f64 / 1000.0;
            st.at = now;
            st.now = now;
            st.tokens = (st.tokens + dt * self.cap).min(self.cap / 10.0);
            // The client gives up on what waited too long (queued or lost).
            for (d, enq) in st.queue.iter_mut() {
                if now.saturating_sub(*enq) >= GIVE_UP_MS
                    && let Some(done) = d.take()
                {
                    answers.push((done, AuthReply::failed(AuthOutcome::Timeout, "no answer")));
                }
            }
            let lost = std::mem::take(&mut st.lost);
            for (d, enq) in lost {
                if now.saturating_sub(enq) >= GIVE_UP_MS {
                    answers.push((d, AuthReply::failed(AuthOutcome::Timeout, "no answer")));
                } else {
                    st.lost.push((d, enq));
                }
            }
            st.timeouts += answers.len() as u64;
            if st.logins < AUTH_BUSY {
                while st.held > 0 && (st.queue.len() as f64) < 2.0 * self.cap {
                    st.held -= 1;
                    st.queue.push_back((None, now));
                }
            }
            while st.tokens >= 1.0 {
                let Some((d, _)) = st.queue.pop_front() else { break };
                st.tokens -= 1.0;
                st.served += 1;
                if let Some(d) = d {
                    let mut r = AuthReply::failed(AuthOutcome::Accept, "");
                    r.message = None;
                    answers.push((d, r));
                }
            }
        }
        self.st.lock().unwrap().logins -= answers.len() as u64;
        for (d, r) in answers {
            d(r);
        }
    }
}

impl AaaBackend for SlowAaa {
    fn authenticate(&self, _: AuthRequest, done: AuthDone) {
        self.push(Some(done));
    }

    fn account(&self, _: AcctRequest, _: Option<Arc<dyn AcctSource>>) -> Result<(), String> {
        self.push(None);
        Ok(())
    }

    fn register_owner(&self, _: Arc<dyn SessionOwner>) {}

    fn status(&self) -> RadiusStatus {
        RadiusStatus::default()
    }
}

/// The wave's RADIUS, on the lab's clock.
trait WaveAaa: AaaBackend {
    fn pump(&self, now: u64);
    /// Requests the client gave up on (MRC/MRD), and retransmissions.
    fn counts(&self) -> (u64, u64);
    /// One line of state, for `WAVE_TRACE`.
    fn trace(&self) -> String {
        String::new()
    }
}

impl WaveAaa for SlowAaa {
    fn pump(&self, now: u64) {
        SlowAaa::pump(self, now);
    }

    fn counts(&self) -> (u64, u64) {
        (self.st.lock().unwrap().timeouts, 0)
    }
}

/// The wave's RADIUS with the real client in front (G4.3g, VM round 4:
/// the simple model above has no retransmissions): `proto_radius::Client`
/// as `radius_aaa` runs it (adaptive RTO, MRD, a server dead after three
/// failures, accounting held while [`AUTH_BUSY`] logins are out,
/// cancelled logins dropped), against `TestServer` behind the lab's queue:
/// `cap` requests a second, at most two seconds of work held, a copy of a
/// request it holds dropped (RFC 5080 §2.2.2, as FreeRADIUS).
struct RealAaa {
    cap: f64,
    st: Mutex<RealState>,
}

struct RealState {
    client: corerouter_proto_radius::client::Client,
    server: corerouter_proto_radius::testserver::TestServer,
    logins: HashMap<corerouter_proto_radius::client::RequestId, (AuthDone, Option<Arc<std::sync::atomic::AtomicBool>>)>,
    held: std::collections::VecDeque<(String, u64)>,
    queue: std::collections::VecDeque<(corerouter_proto_radius::client::SocketKey, std::net::SocketAddr, Vec<u8>)>,
    holding: std::collections::HashSet<(u16, u8, [u8; 16])>,
    tokens: f64,
    at: u64,
    now: u64,
}

const AUTH_ADDR: &str = "192.0.2.1:1812";
const ACCT_ADDR: &str = "192.0.2.1:1813";

impl RealAaa {
    fn new(cap: f64, users: usize) -> Self {
        use corerouter_proto_radius::client::{Client as Radius, ClientConfig as RadiusConfig, ServerConfig};
        let mut server = corerouter_proto_radius::testserver::TestServer::new(b"lab", 7);
        for i in 0..users {
            server.add_user(&format!("r{i}"), "x", corerouter_proto_radius::packet::AttrList::new());
        }
        let client = Radius::new(
            RadiusConfig { require_message_authenticator: false, ..RadiusConfig::default() },
            vec![
                ServerConfig::auth(AUTH_ADDR.parse().unwrap(), b"lab"),
                ServerConfig::acct(ACCT_ADDR.parse().unwrap(), b"lab"),
            ],
            [3; 32],
        );
        Self {
            cap,
            st: Mutex::new(RealState {
                client,
                server,
                logins: HashMap::new(),
                held: Default::default(),
                queue: Default::default(),
                holding: Default::default(),
                tokens: 0.0,
                at: 0,
                now: 0,
            }),
        }
    }

    fn login(&self, req: AuthRequest, done: AuthDone, cancel: Option<Arc<std::sync::atomic::AtomicBool>>) {
        let mut st = self.st.lock().unwrap();
        let now = st.now;
        let mut l = corerouter_proto_radius::packet::AttrList::new();
        corerouter_proto_radius::packet::PushAttr::push_text(&mut l, corerouter_proto_radius::packet::attr::USER_NAME, &req.user).unwrap();
        match st.client.access(l, Some(b"x"), now) {
            Ok(id) => {
                st.logins.insert(id, (done, cancel));
            }
            Err(e) => {
                drop(st);
                done(AuthReply::failed(AuthOutcome::Error, e.to_string()));
            }
        }
    }

    fn send_acct(st: &mut RealState, session: &str, event: u64, now: u64) {
        let r = corerouter_proto_radius::acct::Record::new(corerouter_proto_radius::acct::StatusType::Start, session);
        let _ = st.client.accounting_at(r.encode().unwrap(), None, event, now);
    }
}

impl AaaBackend for RealAaa {
    fn authenticate(&self, req: AuthRequest, done: AuthDone) {
        self.login(req, done, None);
    }

    fn authenticate_until(&self, req: AuthRequest, done: AuthDone, cancel: Arc<std::sync::atomic::AtomicBool>) {
        self.login(req, done, Some(cancel));
    }

    fn account(&self, req: AcctRequest, _: Option<Arc<dyn AcctSource>>) -> Result<(), String> {
        let mut st = self.st.lock().unwrap();
        let now = st.now;
        if st.logins.len() >= AUTH_BUSY as usize {
            st.held.push_back((req.session_id, now));
        } else {
            Self::send_acct(&mut st, &req.session_id, now, now);
        }
        Ok(())
    }

    fn register_owner(&self, _: Arc<dyn SessionOwner>) {}

    fn status(&self) -> RadiusStatus {
        RadiusStatus::default()
    }
}

impl WaveAaa for RealAaa {
    fn pump(&self, now: u64) {
        use corerouter_proto_radius::client::Event;
        let mut answers: Vec<(AuthDone, AuthReply)> = Vec::new();
        {
            let mut st = self.st.lock().unwrap();
            let st = &mut *st;
            st.now = now;
            // Called-off logins leave the client (radius_aaa's sweep).
            let off: Vec<_> = st
                .logins
                .iter()
                .filter(|(_, (_, c))| c.as_ref().is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)))
                .map(|(id, _)| *id)
                .collect();
            for id in off {
                st.client.cancel(id);
                if let Some((done, _)) = st.logins.remove(&id) {
                    answers.push((done, AuthReply::failed(AuthOutcome::Error, "cancelled")));
                }
            }
            // Accounting held behind the logins (radius_aaa::release_acct).
            while let Some((sid, at)) = st.held.front().cloned() {
                if st.logins.len() >= AUTH_BUSY as usize && now.saturating_sub(at) < 60_000 {
                    break;
                }
                st.held.pop_front();
                Self::send_acct(st, &sid, at, now);
            }
            st.client.handle_timeout(now);
            let mut buf = Vec::new();
            let bound = (self.cap * 2.0) as usize;
            while let Some(t) = st.client.poll_transmit(&mut buf) {
                let (Some(id), Some(a)) = (buf.get(1).copied(), buf.get(4..20)) else { continue };
                let key = (t.from.socket * 2 + t.from.server as u16, id, <[u8; 16]>::try_from(a).unwrap());
                if st.queue.len() >= bound || !st.holding.insert(key) {
                    continue;
                }
                st.queue.push_back((t.from, t.dest, buf.clone()));
            }
            let dt = now.saturating_sub(st.at) as f64 / 1000.0;
            st.at = now;
            st.tokens = (st.tokens + dt * self.cap).min(self.cap / 10.0);
            while st.tokens >= 1.0 {
                let Some((from, _dest, data)) = st.queue.pop_front() else { break };
                st.tokens -= 1.0;
                if let (Some(id), Some(a)) = (data.get(1).copied(), data.get(4..20)) {
                    st.holding.remove(&(from.socket * 2 + from.server as u16, id, <[u8; 16]>::try_from(a).unwrap()));
                }
                let me: std::net::SocketAddr = format!("10.0.0.1:{}", 20_000 + from.socket + 1000 * from.server as u16).parse().unwrap();
                let dest: std::net::SocketAddr = if from.server == 0 { AUTH_ADDR } else { ACCT_ADDR }.parse().unwrap();
                if let Some(r) = st.server.handle(me, &data, now) {
                    let _ = st.client.handle_input(from, dest, &r.bytes, now);
                }
            }
            st.server.accounting.clear();
            while let Some(e) = st.client.poll_event() {
                match e {
                    Event::Response { request, .. } => {
                        if let Some((done, _)) = st.logins.remove(&request) {
                            let mut r = AuthReply::failed(AuthOutcome::Accept, "");
                            r.message = None;
                            answers.push((done, r));
                        }
                    }
                    Event::Failed { request, .. } => {
                        if let Some((done, _)) = st.logins.remove(&request) {
                            answers.push((done, AuthReply::failed(AuthOutcome::Timeout, "no answer")));
                        }
                    }
                    _ => {}
                }
            }
        }
        for (d, r) in answers {
            d(r);
        }
    }

    fn trace(&self) -> String {
        let st = self.st.lock().unwrap();
        let s = |i| st.client.stats(i).map(|s| (s.timeouts, s.resends, s.rto_ms)).unwrap_or_default();
        format!(
            "logins out {}, accounting held {}, server queue {}; auth (timeouts, resends, rto) {:?}, acct {:?}",
            st.logins.len(),
            st.held.len(),
            st.queue.len(),
            s(0),
            s(1)
        )
    }

    fn counts(&self) -> (u64, u64) {
        let st = self.st.lock().unwrap();
        (0..2).filter_map(|i| st.client.stats(i)).fold((0, 0), |(t, r), s| (t + s.timeouts, r + s.resends))
    }
}

/// `n` CPEs at once against a `cap`/s RADIUS with `rate` (a number or
/// "auto"): seconds until all are up (None: not in `limit_s`) and the
/// logins the client gave up on.
fn wave(n: usize, cap: f64, rate: serde_json::Value, limit_s: u64) -> (Option<f64>, u64) {
    let r = wave_with(Arc::new(SlowAaa::new(cap)), n, rate, limit_s);
    (r.0, r.1)
}

/// [`wave`] against `aaa`: also the retransmissions.
fn wave_with<A: WaveAaa + 'static>(aaa: Arc<A>, n: usize, rate: serde_json::Value, limit_s: u64) -> (Option<f64>, u64, u64) {
    let mut srv = server(serde_json::json!({}));
    match rate.as_str() {
        Some("auto") => srv.new_session_rate_auto = true,
        _ => srv.new_session_rate = rate.as_u64().unwrap_or(0) as u32,
    }
    let mut s = snap(0, srv, 65_000);
    s.ppp.aaa.use_radius = true;
    s.aaa = Some(aaa.clone());
    let mut lab = Lab::new(n, s, |i| (format!("r{i}"), "x".into()));
    let fresh = |lab: &Lab, c: usize, k: u64| {
        let mut cfg = lab.clients[c].config().clone();
        cfg.discovery_attempts = u8::MAX;
        // CHAP, as BNG Blaster (an Accept with no MS-CHAP2-Success cannot
        // finish an MS-CHAPv2 login).
        cfg.auth = corerouter_proto_pppoe::layers::AuthSet::new(&[corerouter_proto_pppoe::lcp::AuthProto::ChapMd5]);
        let mut seed = [8u8; 32];
        seed[..8].copy_from_slice(&(c as u64).to_le_bytes());
        seed[8..16].copy_from_slice(&k.to_le_bytes());
        Client::new(cfg, seed)
    };
    for c in 0..n {
        lab.clients[c] = fresh(&lab, c, 0);
    }
    // A power cut: the CPEs boot within 5 s of each other; one whose login
    // failed tries again 1–3 s later, as a real one (and BNG Blaster) does.
    let hash = |c: usize, k: u64| (c as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(k.wrapping_mul(0xbf58_476d_1ce4_e5b9)) >> 33;
    let mut next: Vec<Option<u64>> = (0..n).map(|c| Some(hash(c, 0) % 5000)).collect();
    let mut tries = vec![0u64; n];
    let t0 = lab.now;
    while lab.now - t0 < limit_s * 1000 {
        let now = lab.now;
        let mut out = ClientOutput::new();
        for c in 0..n {
            if next[c].is_some_and(|t| t0 + t <= now) {
                next[c] = None;
                tries[c] += 1;
                lab.clients[c] = fresh(&lab, c, tries[c]);
                lab.clients[c].start(now, &mut out);
                lab.feed(&mut out);
            } else if next[c].is_none() && matches!(lab.clients[c].phase(), ClientPhase::Closed(_)) {
                next[c] = Some(now - t0 + 1000 + hash(c, tries[c]) % 2000);
            }
        }
        lab.run(1, 50);
        aaa.pump(lab.now);
        if std::env::var_os("WAVE_TRACE").is_some() && (lab.now - t0) % 1000 < 50 {
            let st = lab.backend().stats();
            eprintln!("t={:>5} up={:>6} rate={:>5} {:?} | {}", lab.now - t0, lab.ups(), st.admission_rate, st.admission_reason, aaa.trace());
        }
        if lab.ups() == n {
            let (t, r) = aaa.counts();
            return (Some((lab.now - t0) as f64 / 1000.0), t, r);
        }
    }
    let (t, r) = aaa.counts();
    eprintln!("wave {rate}: {} of {n} up; stats {:?}", lab.ups(), lab.backend().stats());
    (None, t, r)
}

/// Slow layer (G0.30, `slow_`): 6000 CPEs on the lab clock, ~13 s in a dev build.
#[test]
fn slow_mass_reconnect_against_a_slow_radius() {
    // 6000 CPEs after a power cut, a 300/s RADIUS shared by
    // authentication and accounting; the logins go first (the accounting
    // waits behind them), ~20 s for all.
    let (n, cap) = (6000, 300.0);
    let ideal = n as f64 / cap;
    let off = wave(n, cap, serde_json::json!(0), 300);
    let over = wave(n, cap, serde_json::json!(200), 300);
    let fixed = wave(n, cap, serde_json::json!(100), 300);
    let auto = wave(n, cap, serde_json::json!("auto"), 300);
    eprintln!(
        "wave of {n} against {cap}/s (ideal {ideal:.0} s): off {off:?}, fixed 200 {over:?}, fixed 100 {fixed:?}, auto {auto:?}"
    );
    let (t, timeouts) = (auto.0.expect("auto brings every CPE back"), auto.1);
    assert!(t <= ideal * 1.35, "auto close to the server's capacity: {t} s for an ideal {ideal} s");
    assert!(timeouts * 20 < off.1.max(1), "auto spares the server: {timeouts} timeouts against {} with no limit", off.1);
    assert!(fixed.0.is_some_and(|f| f > t), "a fixed limit under the capacity is slower: {fixed:?}");
}


/// The VM's third round in the lab's model (G4.3g): a 3000/s RADIUS, with
/// 60 000 CPEs (one port's SESSION_IDs and the lab's pool stop at 65 000;
/// the VM had 100 000). By hand, release: `cargo test --release -p
/// corerouter-daemon --bin corerouter-daemon wave_of_the_vm_round --
/// --ignored --nocapture`.
#[test]
#[ignore = "a minute of CPU; by hand in release"]
fn wave_of_the_vm_round() {
    let (n, cap) = (60_000, 3000.0);
    let off = wave(n, cap, serde_json::json!(0), 600);
    let fixed = wave(n, cap, serde_json::json!(2000), 600);
    let auto = wave(n, cap, serde_json::json!("auto"), 600);
    eprintln!("wave of {n} against {cap}/s: off {off:?}, fixed 2000 {fixed:?}, auto {auto:?}");
    let (t, timeouts) = (auto.0.expect("auto brings every CPE back"), auto.1);
    assert!(off.0.is_none_or(|o| t <= o), "auto no slower than no limit: {t} s against {off:?}");
    assert!(timeouts <= off.1, "and with fewer timeouts: {timeouts} against {}", off.1);
}

/// [`wave_of_the_vm_round`] with the real RADIUS client in front of the
/// server ([`RealAaa`]): retransmissions, adaptive RTO, MRD. By hand,
/// release: `cargo test --release -p corerouter-daemon --bin
/// corerouter-daemon wave_with_the_real_client -- --ignored --nocapture`.
#[test]
#[ignore = "a minute of CPU; by hand in release"]
fn wave_with_the_real_client() {
    let (n, cap) = (60_000, 3000.0);
    let run = |rate: serde_json::Value| wave_with(Arc::new(RealAaa::new(cap, n)), n, rate, 600);
    let off = run(serde_json::json!(0));
    let fixed = run(serde_json::json!(2000));
    let auto = run(serde_json::json!("auto"));
    eprintln!(
        "real client, wave of {n} against {cap}/s (up in s, timeouts, resends): off {off:?}, fixed 2000 {fixed:?}, auto {auto:?}"
    );
    // Before the client's timers were fixed (a finished request's timer
    // fired on the next one in its slot): auto 25.3 s, 429 timeouts, 66 205
    // resends; now 20.1 s, 0, 0.
    let t = auto.0.expect("auto brings every CPE back");
    assert!(off.0.is_none_or(|o| t <= o * 1.05), "auto no slower than no limit: {t} s against {off:?}");
    assert!(fixed.0.is_none_or(|f| t <= f), "nor than fixed 2000: {fixed:?}");
    assert_eq!(auto.1, 0, "no login timed out: {auto:?}");
    assert!(auto.2 * 10 <= off.2.max(10), "and next to no copies: {auto:?} against {off:?}");
}

/// `new_session_rate=auto` with the real RADIUS client: a wave of 6000
/// against a 300/s server comes up at the server's pace, with no login
/// timed out and next to no copies sent.
#[test]
fn auto_keeps_the_real_client_from_resending() {
    let (n, cap) = (6000, 300.0);
    let (t, timeouts, resends) = wave_with(Arc::new(RealAaa::new(cap, n)), n, serde_json::json!("auto"), 300);
    let t = t.expect("auto brings every CPE back");
    assert!(t <= n as f64 / cap * 1.35, "{t} s for an ideal {} s", n as f64 / cap);
    assert_eq!(timeouts, 0);
    assert!(resends <= n as u64 / 100, "{resends} copies for {n} logins");
}

/// G4.3k: one port, three Service-Names: each session gets its row's
/// profile (a secret left on `default` too), the name shows in Active and
/// goes to RADIUS as Called-Station-Id; a drop row gets no session.
#[test]
fn service_names_choose_the_profile_and_drop_rows_get_nothing() {
    let srv = server(serde_json::json!({"services": [
        {"name": "internet"},
        {"name": "iptv", "profile": "tv"},
        {"name": "bloqueado", "action": "drop"},
        {"name": "any", "action": "drop"},
    ]}));
    let mut s = snap(30, srv, 1000);
    s.ppp.profiles.push(PppProfile {
        id: ItemId(3),
        name: "tv".into(),
        remote_address: Some(AddrOrPool::Pool("clientes".into())),
        rate_limit: Some("5M/20M".into()),
        ..PppProfile::default()
    });
    let names = ["internet", "iptv", "", "bloqueado", "outro"];
    let mut lab = Lab::with(30, s, |i| (format!("u{i}"), format!("p{i}")), |i, c| {
        c.service_name = names[i % names.len()].as_bytes().to_vec();
        c.discovery_attempts = 3;
    });
    lab.start(0..30);
    lab.run(600, 50);
    assert_eq!(lab.ups(), 18, "internet, iptv and the empty name");
    lab.bng.check().unwrap();
    for a in lab.backend().active() {
        let i: usize = a.name[1..].parse().unwrap();
        let want = names[i % names.len()];
        assert_eq!(a.service_name.as_deref(), Some(want), "{a:?}");
        let (profile, rate) = if want == "iptv" { ("tv", "5M/20M") } else { ("default", "10M/50M") };
        assert_eq!((a.profile.as_str(), a.rate_limit.as_deref()), (profile, Some(rate)), "{a:?}");
    }
}

/// G3.9g: the PADO's AC-Name is `/system identity`, as RouterOS sends it;
/// a RouterOS CPE with `ac-name=<identity>` only takes that PADO. With no
/// identity in the snapshot it stays "CoreRouter".
#[test]
fn pado_ac_name_is_the_system_identity() {
    for (identity, want) in [("bng-sp1", "bng-sp1"), ("", "CoreRouter")] {
        let mut s = snap(1, server(serde_json::json!({})), 10);
        s.identity = identity.into();
        let mut lab = Lab::new(1, s, |i| (format!("u{i}"), format!("p{i}")));
        lab.start(0..1);
        let names: Vec<Vec<u8>> = lab
            .bng
            .frames
            .iter()
            .filter_map(|(_, f)| corerouter_proto_pppoe::discovery::parse(f).ok())
            .filter_map(|d| d.tags.ac_name.map(<[u8]>::to_vec))
            .collect();
        assert_eq!(names, vec![want.as_bytes().to_vec()], "identity {identity:?}");
        lab.run(100, 50);
        assert_eq!(lab.ups(), 1, "the client takes the PADO and comes up");
    }
}

/// G4.3l: QinQ (802.1ad 100-101 outside, any C-tag inside), one session
/// per line (TR-101 1:1): the second CPE on a line gets nothing; RADIUS
/// gets the line in NAS-Port-Id (`ether2:<s>-<c>`) and the TR-101 ids;
/// the slow path answers inside both tags.
#[test]
fn qinq_lines_one_session_each_with_tr101_to_radius() {
    use corerouter_proto_pppoe::eth::Vlans;
    let aaa = Arc::new(FakeAaa::default());
    let srv = server(serde_json::json!({
        "authentication": ["pap"], "vlan_mode": "stacked", "outer_vlan_range": ["100-101"],
        "accept_untagged": false, "max_sessions_per_vlan": 1
    }));
    let mut s = snap(0, srv, 10);
    s.ppp.aaa.use_radius = true;
    s.ppp.aaa.accounting = true;
    s.aaa = Some(aaa.clone());
    // Clients 0..3 on lines (100,10) (101,11) (100,12); client 3 on line (100,10) too.
    let line = |i: usize| match i {
        3 => Vlans::qinq(100, 10),
        i => Vlans::qinq(100 + (i % 2) as u16, 10 + i as u16),
    };
    let mut lab = Lab::with(4, s, |i| (format!("r{i}"), "x".into()), |i, c| {
        c.vlans = line(i);
        c.auth = corerouter_proto_pppoe::layers::AuthSet::new(&[corerouter_proto_pppoe::lcp::AuthProto::Pap]);
        c.circuit_id = Some(format!("olt1 pon 0/1/{i}").into_bytes());
        c.remote_id = Some(format!("cliente-{i}").into_bytes());
        c.discovery_attempts = 3;
    });
    lab.start(0..4);
    lab.run(400, 50);
    assert_eq!(lab.ups(), 3, "one session per line");
    assert!(lab.up[0] ^ lab.up[3], "line (100,10) has one of its two CPEs");
    let active = lab.backend().active();
    for a in &active {
        let i: usize = a.name[1..].parse().unwrap();
        let v = line(i);
        assert_eq!((a.vlan, a.inner_vlan), (Some(v.outer), Some(v.inner)), "{a:?}");
        assert_eq!(a.circuit_id.as_deref(), Some(format!("olt1 pon 0/1/{i}").as_str()));
    }
    let asked = aaa.asked.lock().unwrap().clone();
    let a0 = asked.iter().find(|r| r.user == "r1").unwrap();
    assert_eq!(a0.nas_port_id.as_deref(), Some("ether2:101-11"));
    let has = |attrs: &[Attribute], k: &str, v: &str| attrs.iter().any(|a| a.name == k && a.value == v);
    assert!(has(&a0.attributes, "ADSL-Agent-Circuit-Id", "olt1 pon 0/1/1"), "{:?}", a0.attributes);
    assert!(has(&a0.attributes, "ADSL-Agent-Remote-Id", "cliente-1"));
    let accts = aaa.accts.lock().unwrap().clone();
    let start = accts.iter().find(|r| r.user == "r1").unwrap();
    assert!(has(&start.attributes, "NAS-Port-Id", "ether2:101-11"), "{:?}", start.attributes);
    assert!(has(&start.attributes, "ADSL-Agent-Circuit-Id", "olt1 pon 0/1/1"));
    // Downstream on the slow path: back inside 802.1ad 101 + 802.1Q 11.
    let r1 = active.iter().find(|a| a.name == "r1").unwrap();
    let ip = r1.address.unwrap();
    let mut back = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 8, 8, 8, 8];
    back.extend_from_slice(&ip.octets());
    lab.bng.frames.clear();
    lab.bng.data_down(&back);
    let (_, f) = lab.bng.frames.pop().unwrap();
    assert_eq!(&f[12..22], &[0x88, 0xa8, 0, 101, 0x81, 0x00, 0, 11, 0x88, 0x64]);
    assert_eq!(&f[30..], &back[..]);
    lab.bng.check().unwrap();
}

/// G4.3l: IPv6 on the slow path, inside two tags. A packet from the
/// session's /64 or delegated prefix goes up to the stack; a spoofed one
/// does not; a link-local one stays with the control plane; the kernel's
/// packet to the prefix comes back inside the line's tags. The prefixes'
/// routes to `bng0` come and go with the session.
#[test]
fn ipv6_on_the_slow_path_inside_qinq() {
    use corerouter_proto_pppoe::eth::Vlans;
    let mut s = dual(1);
    s.ppp.pppoe_servers[0] = server(serde_json::json!({"vlan_mode": "stacked", "outer_vlan_range": ["300"], "accept_untagged": false}));
    let mut lab = Lab::with(1, s, |i| (format!("u{i}"), format!("p{i}")), |_, c| {
        c.vlans = Vlans::qinq(300, 42);
        c.ipv6 = true;
    });
    lab.start(0..1);
    lab.run(200, 50);
    assert_eq!(lab.ups(), 1);
    let a = lab.backend().active().pop().unwrap();
    let (p64, pd) = (a.ipv6_prefix.unwrap(), a.delegated_prefix.unwrap());
    let route6 = |lab: &Lab, add: bool| -> Vec<ipnet::Ipv6Net> {
        lab.bng.effects.iter().filter_map(|e| match e { Effect::Route6 { net, add: a } if *a == add => Some(*net), _ => None }).collect()
    };
    let mut added = route6(&lab, true);
    added.sort();
    let mut want = vec![p64, pd];
    want.sort();
    assert_eq!(added, want, "the /64 and the delegated prefix to bng0");
    let pkt = |src: std::net::Ipv6Addr, dst: std::net::Ipv6Addr| {
        let mut p = vec![0x60, 0, 0, 0, 0, 8, 58, 64];
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(&[128, 0, 0, 0, 0, 1, 0, 1]);
        p
    };
    let host = |n: ipnet::Ipv6Net, last: u8| {
        let mut o = n.network().octets();
        o[15] = last;
        std::net::Ipv6Addr::from(o)
    };
    let frame = |lab: &Lab, p: &[u8]| {
        let mut f = Vec::new();
        corerouter_proto_pppoe::eth::put_header(&mut f, Mac(BNG_MAC), lab.clients[0].config().mac, Vlans::qinq(300, 42), 0x8864);
        f.extend_from_slice(&[0x11, 0x00]);
        f.extend_from_slice(&lab.clients[0].session_id().to_be_bytes());
        f.extend_from_slice(&((p.len() + 2) as u16).to_be_bytes());
        f.extend_from_slice(&[0x00, 0x57]);
        f.extend_from_slice(p);
        f
    };
    let far: std::net::Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
    lab.bng.upstream.clear();
    // From the /64 and from the delegated prefix: up.
    for src in [host(p64, 1), host(pd, 9)] {
        let p = pkt(src, far);
        lab.bng.frame(lab.now, IFINDEX, &frame(&lab, &p));
        assert_eq!(lab.bng.upstream.pop(), Some(p));
    }
    // Spoofed source, and the right source on another line's tags: dropped.
    lab.bng.frame(lab.now, IFINDEX, &frame(&lab, &pkt("2001:db8:9999::1".parse().unwrap(), far)));
    let mut other = frame(&lab, &pkt(host(p64, 1), far));
    other[19] = 43;
    lab.bng.frame(lab.now, IFINDEX, &other);
    assert!(lab.bng.upstream.is_empty());
    // Downstream to the delegated prefix: inside both tags, PPP 0x0057.
    let back = pkt(far, host(pd, 0x77));
    lab.bng.frames.clear();
    lab.bng.data_down(&back);
    let (_, f) = lab.bng.frames.pop().expect("encapsulated");
    assert_eq!(&f[12..22], &[0x88, 0xa8, 0x01, 0x2c, 0x81, 0x00, 0, 42, 0x88, 0x64]);
    assert_eq!(&f[28..30], &[0x00, 0x57]);
    assert_eq!(&f[30..], &back[..]);
    // Not a subscriber's: nothing.
    lab.bng.data_down(&pkt(far, "2001:db8:7777::1".parse().unwrap()));
    assert!(lab.bng.frames.is_empty());
    // The session ends: its routes go.
    lab.bng.effects.clear();
    lab.backend().terminate(std::slice::from_ref(&a.id));
    lab.bng.requests(lab.now);
    lab.run(100, 50);
    let mut gone = route6(&lab, false);
    gone.sort();
    assert_eq!(gone, want);
    lab.bng.data_down(&back);
    assert!(lab.bng.frames.iter().all(|(_, f)| f.get(28..30) != Some(&[0x00, 0x57])), "no session, no frame");
}
