//! G4.3h hot standby: established sessions leave one `Server` and continue
//! on another (the other BNG of the pair), in the in-memory lab. The CPEs
//! must not notice: no PADT, no new login, keepalive answered with the
//! same Magic-Numbers, the same addresses; and the new server ends the
//! sessions cleanly later.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use corerouter_proto_pppoe::lab::{Lab, LabConfig, server_seed};
use corerouter_proto_pppoe::lcp::AuthProto;
use corerouter_proto_pppoe::server::ha::ImportError;
use corerouter_proto_pppoe::server::{Server, ServerOutput};

fn up(n: usize, f: impl FnOnce(&mut LabConfig)) -> Lab {
    let mut cfg = LabConfig {
        clients: n,
        shards: 2,
        auth_cycle: vec![AuthProto::MsChapV2, AuthProto::Pap, AuthProto::ChapMd5],
        ..LabConfig::default()
    };
    f(&mut cfg);
    let mut l = Lab::new(cfg);
    l.start_all();
    l.run_until(30_000);
    assert_eq!(l.clients_up(), n);
    l
}

/// Every shard's sessions move to a new server (another seed: another
/// node); returns how many moved.
fn take_over(l: &mut Lab) -> usize {
    let now = l.now;
    let mut moved = 0;
    for k in 0..l.servers.len() {
        let states = l.servers[k].export_all(now);
        let mut fresh = Server::new(
            l.servers[k].config().clone(),
            server_seed(l.cfg.seed + 99, k),
            now,
        );
        let mut out = ServerOutput::new();
        let r = fresh.import(now, &states, &mut out);
        assert!(r.iter().all(Result::is_ok), "{r:?}");
        assert!(
            out.frames().next().is_none(),
            "nothing sent: the CPE must not notice"
        );
        // Every field survives (the Magic-Numbers too: lab clients, like
        // pppd, only check that an Echo-Reply is not their own).
        assert_eq!(fresh.export_all(now), states);
        for st in &states {
            let old = l.servers[k].session(st.sid).unwrap();
            let new = fresh.session(st.sid).unwrap();
            assert_eq!(old, new, "same descriptor (XDP maps, accounting)");
        }
        moved += states.len();
        l.servers[k] = fresh;
    }
    moved
}

#[test]
fn established_sessions_continue_on_another_server_unnoticed() {
    let mut l = up(1000, |c| {
        c.ipv6 = true;
        c.reconnect = false;
    });
    let (ups, client_downs) = (l.stats.ups, l.stats.client_downs);
    assert_eq!(take_over(&mut l), 1000);
    // Two minutes: 12 keepalive rounds of 10 s on both ends.
    l.run_until(l.now + 120_000);
    assert_eq!(l.clients_up(), 1000);
    assert_eq!(l.stats.ups, ups, "no new login");
    assert_eq!(
        l.stats.client_downs, client_downs,
        "no CPE went down: {:?}",
        l.stats.client_reasons
    );
    assert_eq!(l.server_sessions(), 1000);
    l.check().unwrap();
    // The new server ends them as its own.
    for i in 0..1000 {
        l.close(i);
    }
    l.run_until(l.now + 30_000);
    assert_eq!(
        l.server_sessions(),
        0,
        "ups {} downs {} {:?}",
        l.stats.ups,
        l.stats.downs,
        l.stats.server_reasons
    );
}

#[test]
fn a_lossy_network_after_the_takeover_still_holds() {
    let mut l = up(300, |c| c.reconnect = true);
    take_over(&mut l);
    l.cfg.loss_ppm = 50_000;
    l.run_until(l.now + 60_000);
    l.cfg.loss_ppm = 0;
    l.run_until(l.now + 30_000);
    assert_eq!(l.clients_up(), 300);
    l.check().unwrap();
}

#[test]
fn a_busy_or_foreign_session_id_is_refused() {
    let l = up(10, |_| {});
    let now = l.now;
    let states = l.servers[0].export_all(now);
    let mut same = Server::new(l.servers[0].config().clone(), server_seed(7, 0), now);
    let mut out = ServerOutput::new();
    assert!(
        same.import(now, &states, &mut out)
            .iter()
            .all(Result::is_ok)
    );
    assert!(
        same.import(now, &states, &mut out)
            .iter()
            .all(|r| *r == Err(ImportError::Busy))
    );
    let mut cfg = l.servers[0].config().clone();
    cfg.sid_lane = (1, 2);
    let mut other = Server::new(cfg, server_seed(8, 0), now);
    let r = other.import(now, &states, &mut out);
    let odd = states.iter().filter(|s| s.sid % 2 == 1).count();
    assert_eq!(
        r.iter().filter(|r| r.is_ok()).count(),
        odd,
        "only its lane's SIDs"
    );
    assert!(r.contains(&Err(ImportError::NotOurs)));
}
