//! Mass simulations: many subscribers against the BNG in memory, with a
//! fake clock and a hostile network. Every test ends by cross-checking the
//! server's indexes, the address pool and the client/server views
//! (`Lab::check`): unique SESSION_IDs, one session per subscriber, no lease
//! or session left behind.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use corerouter_proto_pppoe::client::ClientPhase;
use corerouter_proto_pppoe::lab::{Lab, LabConfig};
use corerouter_proto_pppoe::lcp::AuthProto;
use std::time::Instant;

fn run(cfg: LabConfig, secs: u64) -> Lab {
    let mut l = Lab::new(cfg);
    l.start_all();
    l.run_until(secs * 1000);
    l
}

fn closed(l: &Lab) -> usize {
    l.clients
        .iter()
        .filter(|c| matches!(c.phase(), ClientPhase::Closed(_)))
        .count()
}

/// Ends every client with a PADT and checks nothing is left on the BNG.
fn teardown(l: &mut Lab) {
    let t0 = l.now;
    l.cfg.reconnect = false;
    for i in 0..l.clients.len() {
        l.abort(i);
    }
    l.run_until(t0 + 60_000);
    assert_eq!(l.server_sessions(), 0, "sessions leaked after PADT");
    assert_eq!(l.leases(), 0, "addresses leaked");
    l.check().unwrap();
}

/// Sessions may only die of keepalive on a lossy network (two echoes lost
/// in a row); anything else is a protocol bug.
fn only_keepalive_deaths(l: &Lab) {
    for (reason, n) in &l.stats.server_reasons {
        assert!(
            reason == "Keepalive",
            "{n} sessions ended with {reason}: {:?}",
            l.stats
        );
    }
}

#[test]
fn hundred_thousand_dual_stack_sessions_reach_opened_on_a_lossy_network() {
    let t = Instant::now();
    let n: usize = std::env::var("SIM_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let mut l = run(
        LabConfig {
            clients: n,
            shards: 2,
            loss_ppm: 5_000,
            dup_ppm: 2_000,
            reorder_ppm: 10_000,
            start_spread_ms: 20_000,
            auth_cycle: vec![AuthProto::Pap, AuthProto::ChapMd5],
            seed: 100_000,
            // G4.3e: IPv6CP on every session, each asking the BNG for its
            // identifier (stable and opaque, RFC 8064).
            ipv6: true,
            ipv6_zero_iid: true,
            server: ServerConfig {
                ipv6_iid_key: Some([0x43; 32]),
                ..ServerConfig::default()
            },
            trace: std::env::var("SIM_TRACE")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .map(corerouter_proto_pppoe::lab::client_mac),
            ..LabConfig::default()
        },
        120,
    );
    eprintln!("odd downs: {:?}", l.stats.odd_downs);
    only_keepalive_deaths(&l);
    // The network heals; clients that lost a session to keepalive come back.
    l.cfg.loss_ppm = 0;
    l.cfg.dup_ppm = 0;
    l.cfg.reorder_ppm = 0;
    l.run_until(180_000);
    let up = l.clients_up();
    eprintln!(
        "{n} clients: {up} up, {:?}, {:?} wall",
        l.stats,
        t.elapsed()
    );
    assert_eq!(up, n);
    eprintln!(
        "server sessions {} up-map {} leases {}",
        l.server_sessions(),
        l.up.len(),
        l.leases()
    );
    assert_eq!(l.server_sessions(), n);
    assert_eq!(l.up.len(), n);
    assert_eq!(l.leases(), n);
    // Every session is dual-stack, and no two subscribers share a
    // link-local identifier.
    let iids: std::collections::HashSet<[u8; 8]> =
        l.up.keys()
            .filter_map(|k| l.servers[k.0].session(k.1)?.ipv6_iid)
            .collect();
    assert_eq!(iids.len(), n, "one IPv6CP identifier per session");
    only_keepalive_deaths(&l);
    l.check().unwrap();
    teardown(&mut l);
}

use corerouter_proto_pppoe::discovery::{self, Code, DiscoveryWriter, tag};
use corerouter_proto_pppoe::eth::Vlans;
use corerouter_proto_pppoe::lab::{Dice, ac_mac, client_mac};
use corerouter_proto_pppoe::server::ServerConfig;
use corerouter_proto_pppoe::wire::Mac;

/// Runs a lossy phase, heals the network and checks everyone is back.
fn settle_and_check(l: &mut Lab, n: usize) {
    l.cfg.loss_ppm = 0;
    l.cfg.dup_ppm = 0;
    l.cfg.reorder_ppm = 0;
    let t = l.now;
    l.run_until(t + 90_000);
    assert_eq!(l.clients_up(), n, "{:?}", l.stats);
    assert_eq!(l.server_sessions(), n);
    assert_eq!(l.leases(), n);
    l.check().unwrap();
}

#[test]
fn heavy_loss_duplication_and_reordering() {
    let n = 2000;
    let mut l = run(
        LabConfig {
            clients: n,
            loss_ppm: 50_000,
            dup_ppm: 50_000,
            reorder_ppm: 100_000,
            jitter_ms: 50,
            auth_cycle: vec![
                AuthProto::Pap,
                AuthProto::ChapMd5,
                AuthProto::MsChapV1,
                AuthProto::MsChapV2,
            ],
            seed: std::env::var("SIM_SEED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(7),
            trace: std::env::var("SIM_TRACE")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .map(client_mac),
            ..LabConfig::default()
        },
        120,
    );
    eprintln!("heavy: {:?}", l.stats);
    // With 5 % loss a session may die of keepalive, time out in setup, or
    // be replaced when its host gives up waiting for a PADS and starts
    // over, but never on a protocol error.
    for reason in l.stats.server_reasons.keys() {
        assert!(
            [
                "Keepalive",
                "LcpFailed",
                "SetupTimeout",
                "AuthTimeout",
                "Replaced"
            ]
            .contains(&reason.as_str()),
            "{reason}: {:?}",
            l.stats
        );
    }
    settle_and_check(&mut l, n);
    teardown(&mut l);
}

#[test]
fn mschap2_at_scale_with_ipv6cp() {
    let n = 5000;
    let mut l = run(
        LabConfig {
            clients: n,
            loss_ppm: 5_000,
            dup_ppm: 2_000,
            reorder_ppm: 10_000,
            auth_cycle: vec![AuthProto::MsChapV2],
            ipv6: true,
            seed: 11,
            ..LabConfig::default()
        },
        60,
    );
    only_keepalive_deaths(&l);
    settle_and_check(&mut l, n);
    // IPv6CP came up next to IPCP on every session.
    let with_iid =
        l.up.keys()
            .filter(|(k, sid)| {
                l.servers[*k]
                    .session(*sid)
                    .is_some_and(|d| d.ipv6_iid.is_some())
            })
            .count();
    assert_eq!(with_iid, n);
    teardown(&mut l);
}

fn random_padi(d: &mut Dice) -> Vec<u8> {
    let r = d.roll().to_be_bytes();
    // Locally administered unicast, random.
    let mac = Mac([0x06, r[1], r[2], r[3], r[4], r[5]]);
    let mut b = Vec::new();
    let mut w = DiscoveryWriter::begin(&mut b, Mac::BROADCAST, mac, Vlans::NONE, Code::Padi, 0);
    w.tag(tag::SERVICE_NAME, b"");
    w.tag(tag::HOST_UNIQ, &r);
    w.finish().unwrap();
    b
}

#[test]
fn padi_flood_creates_no_state_and_legit_hosts_still_connect() {
    let n = 1000;
    let mut l = Lab::new(LabConfig {
        clients: n,
        server: ServerConfig {
            padi_limit: 2000,
            mac_padi_limit: 1,
            ..ServerConfig::default()
        },
        seed: 21,
        ..LabConfig::default()
    });
    let mut dice = Dice::new(99);
    l.start_all();
    // 200 000 PADIs from random MACs over 10 s, while the subscribers dial.
    for step in 0..100 {
        for _ in 0..2000 {
            l.inject(0, &random_padi(&mut dice));
        }
        l.run_until((step + 1) * 100);
    }
    l.run_until(90_000);
    let st = l.servers[0].stats().clone();
    eprintln!("flood: {st:?}");
    assert!(st.padi_limited > 150_000, "the global limit held");
    assert_eq!(l.clients_up(), n, "legit hosts got through by retrying");
    assert_eq!(l.server_sessions(), n, "a PADI never creates state");
    l.check().unwrap();
}

#[test]
fn padr_flood_with_forged_cookies_creates_nothing() {
    let mut l = Lab::new(LabConfig {
        clients: 0,
        seed: 22,
        ..LabConfig::default()
    });
    let mut dice = Dice::new(5);
    for _ in 0..100_000 {
        let r = dice.roll().to_be_bytes();
        let mut cookie = [0u8; 21];
        for (i, c) in cookie.iter_mut().enumerate() {
            *c = r[i % 8] ^ (i as u8);
        }
        let mut b = Vec::new();
        let mut w = DiscoveryWriter::begin(
            &mut b,
            ac_mac(0),
            Mac([0x06, r[0], r[1], r[2], r[3], r[4]]),
            Vlans::NONE,
            Code::Padr,
            0,
        );
        w.tag(tag::SERVICE_NAME, b"");
        w.tag(tag::AC_COOKIE, &cookie);
        w.finish().unwrap();
        l.inject(0, &b);
    }
    l.run_until(1000);
    assert_eq!(l.servers[0].stats().padr_bad_cookie, 100_000);
    assert_eq!(l.server_sessions(), 0);
    l.check().unwrap();
}

fn is_padr(f: &[u8]) -> bool {
    discovery::parse(f).is_ok_and(|d| d.code == Code::Padr)
}

#[test]
fn ac_cookie_replay_is_refused() {
    let mut l = run(
        LabConfig {
            clients: 1,
            tap: Some(is_padr),
            reconnect: false,
            seed: 23,
            ..LabConfig::default()
        },
        3,
    );
    assert_eq!(l.clients_up(), 1);
    let padr = l.tapped[0].clone();
    // The same PADR again within the cookie's lifetime: a copy of the
    // request, so the same SID back and no new session.
    l.inject(0, &padr);
    l.run_until(l.now + 10);
    assert_eq!(l.server_sessions(), 1);
    // From another MAC: the cookie is bound to the first one.
    let mut stolen = padr.clone();
    stolen[6..12].copy_from_slice(&client_mac(77).0);
    l.inject(0, &stolen);
    l.run_until(l.now + 10);
    assert_eq!(
        l.servers[0].stats().padr_bad_cookie,
        1,
        "stolen cookie refused"
    );
    // After the cookie timeout the copy still names the live session (we
    // checked those bytes when we made it): same SID, nothing new.
    l.run_until(l.now + 10_000);
    l.inject(0, &padr);
    l.run_until(l.now + 10);
    assert_eq!(l.server_sessions(), 1);
    assert!(l.servers[0].stats().padr_duplicate >= 2);
    assert_eq!(l.clients_up(), 1, "the real session is untouched");
    // Once that session is gone, the expired cookie opens nothing.
    l.abort(0);
    l.run_until(l.now + 1000);
    assert_eq!(l.server_sessions(), 0);
    l.inject(0, &padr);
    l.run_until(l.now + 10);
    assert_eq!(l.servers[0].stats().padr_bad_cookie, 2);
    assert_eq!(l.server_sessions(), 0);
    l.check().unwrap();
}

#[test]
fn authentication_failures_at_scale_leave_nothing_behind() {
    let n = 10_000;
    let l = run(
        LabConfig {
            clients: n,
            bad_password_every: 10,
            reconnect: false,
            auth_cycle: vec![AuthProto::Pap, AuthProto::ChapMd5, AuthProto::MsChapV2],
            seed: 24,
            ..LabConfig::default()
        },
        60,
    );
    assert_eq!(l.clients_up(), n - n / 10);
    assert_eq!(l.stats.auth_rejects, (n / 10) as u64);
    assert_eq!(l.server_sessions(), n - n / 10);
    assert_eq!(
        l.leases(),
        n - n / 10,
        "rejected subscribers got no address"
    );
    assert_eq!(closed(&l), n / 10);
    l.check().unwrap();
}

#[test]
fn mass_reconnect_after_an_outage() {
    let n = 20_000;
    let mut l = run(
        LabConfig {
            clients: n,
            shards: 1,
            start_spread_ms: 5000,
            seed: 25,
            ..LabConfig::default()
        },
        30,
    );
    assert_eq!(l.clients_up(), n);
    // The access network goes dark for 60 s: both ends' keepalives expire.
    l.cfg.loss_ppm = 1_000_000;
    let t = l.now;
    l.run_until(t + 60_000);
    assert_eq!(l.server_sessions(), 0, "every session timed out on the BNG");
    assert_eq!(l.leases(), 0);
    assert_eq!(l.clients_up(), 0);
    l.check().unwrap();
    // Light comes back: everyone dials at once.
    l.cfg.loss_ppm = 0;
    let t = l.now;
    l.run_until(t + 90_000);
    assert_eq!(l.clients_up(), n, "{:?}", l.stats);
    assert_eq!(l.server_sessions(), n);
    l.check().unwrap();
    teardown(&mut l);
}

#[test]
fn cpe_reboot_storm_replaces_sessions_one_per_host() {
    let n = 5000;
    let mut l = run(
        LabConfig {
            clients: n,
            seed: 26,
            ..LabConfig::default()
        },
        20,
    );
    assert_eq!(l.clients_up(), n);
    // Every CPE reboots at once, without a PADT.
    for i in 0..n {
        l.start(i);
    }
    let t = l.now;
    l.run_until(t + 60_000);
    assert_eq!(l.clients_up(), n);
    assert_eq!(l.server_sessions(), n, "old sessions replaced, not kept");
    assert_eq!(
        l.stats.server_reasons.get("Replaced").copied(),
        Some(n as u64)
    );
    l.check().unwrap();
}
