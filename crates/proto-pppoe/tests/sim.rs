//! Mass simulations: many subscribers against the BNG in memory, with a
//! fake clock and a hostile network. Every test ends by cross-checking the
//! server's indexes, the address pool and the client/server views
//! (`Lab::check`): unique SESSION_IDs, one session per subscriber, no lease
//! or session left behind.

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
fn hundred_thousand_sessions_reach_opened_on_a_lossy_network() {
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
    only_keepalive_deaths(&l);
    l.check().unwrap();
    teardown(&mut l);
}
