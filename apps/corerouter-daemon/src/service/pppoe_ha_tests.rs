//! G4.3h hot standby at the BNG level (`pppoe_bng/ha.rs`), with the
//! in-memory lab of `pppoe_bng_tests.rs`: one worker publishes its
//! sessions, another (the other node of the pair) adopts them, and the
//! subscribers go on with the new one without noticing.
#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use corerouter_engine::ppp::PppBackend;
use corerouter_proto_ha::record::SessionRecord;

use super::pppoe_bng::ha::{HaChange, TAKEOVER, TAKEOVER_GEN};
use super::pppoe_bng::{Bng, HA_ACTIVE, PortInfo, Snapshot};
use super::pppoe_bng_tests::{BNG_MAC, IFINDEX, Lab, server, snap};

fn hot(n: usize) -> Snapshot {
    let mut s = snap(n, server(serde_json::json!({})), 65_000);
    s.ppp.redundancy.enabled = true;
    s.ppp.redundancy.mode = corerouter_model::ppp_redundancy::HaMode::HotStandby;
    s.ppp.redundancy.secret = "segredo-do-par-123".into();
    s
}

fn records(changes: &[HaChange]) -> Vec<SessionRecord> {
    changes
        .iter()
        .filter_map(|c| match c {
            HaChange::Up(_, v) => SessionRecord::decode(v).ok(),
            _ => None,
        })
        .collect()
}

#[test]
fn the_other_node_adopts_every_session_and_the_subscribers_stay_up() {
    HA_ACTIVE.store(true, Ordering::Release);
    let n = 200;
    let mut lab = Lab::new(n, hot(n), |i| (format!("u{i}"), format!("p{i}")));
    lab.start(0..n);
    lab.run(400, 50);
    assert_eq!(lab.ups(), n);
    let before = lab.backend().active();
    let now = lab.now;
    let published = records(&lab.bng.ha_take(now));
    assert_eq!(published.len(), n, "one record per session up");
    assert!(published.iter().all(|r| !r.acct_session_id.is_empty() && r.ipv4.is_some()));

    // The other node: same config, its own port index.
    let mut other = Bng::new([9; 32]);
    let ports = HashMap::from([("pppoe-ether2".to_owned(), PortInfo { ifindex: IFINDEX, mac: BNG_MAC })]);
    other.configure(now, hot(n), &ports);
    *TAKEOVER.lock().unwrap() = Some(Arc::new(published.clone()));
    TAKEOVER_GEN.fetch_add(1, Ordering::AcqRel);
    assert!(other.ha_pending());
    let done = other.ha_adopt_pending(now);
    assert_eq!((done.sessions, done.skipped), (n, 0));
    assert!(!other.ha_pending(), "adopted once");
    assert!(other.frames.is_empty(), "nothing sent to the subscribers");

    // The subscribers now talk to the other node: two minutes of its
    // keepalive (5 s), nobody falls (a PADT from it would end them).
    lab.bng = other;
    lab.run(2400, 50);
    assert_eq!(lab.ups(), n, "no subscriber noticed");
    lab.bng.check().unwrap();
    let after = lab.backend().active();
    // Its keepalive got answers for two minutes (it ends a silent session
    // after 10 s), and it sent no PADT.
    assert_eq!(after.len(), n);
    assert_eq!(lab.backend().stats().padt_tx, 0);
    let key = |a: &corerouter_model::ppp::ActiveSession| (a.name.clone(), a.address, a.session_id);
    let mut x: Vec<_> = before.iter().map(key).collect();
    let mut y: Vec<_> = after.iter().map(key).collect();
    x.sort();
    y.sort();
    assert_eq!(x, y, "same logins, addresses and SESSION_IDs");
    // It publishes them as its own (the new active's stream).
    let again = records(&lab.bng.ha_take(lab.now));
    assert_eq!(again.len(), n);
    let ids = |v: &[SessionRecord]| {
        let mut k: Vec<_> = v.iter().map(|r| (r.key(), r.acct_session_id.clone())).collect();
        k.sort();
        k
    };
    assert_eq!(ids(&again), ids(&published), "same keys, same Acct-Session-Id");
    HA_ACTIVE.store(false, Ordering::Release);
}

#[test]
fn sessions_of_another_server_are_skipped_and_counted() {
    let n = 5;
    let mut lab = Lab::new(n, hot(n), |i| (format!("u{i}"), format!("p{i}")));
    lab.start(0..n);
    lab.run(400, 50);
    let mut recs = records(&lab.bng.ha_take(lab.now));
    for r in &mut recs {
        r.server = "pppoe-outro".into();
    }
    let mut other = Bng::new([9; 32]);
    let ports = HashMap::from([("pppoe-ether2".to_owned(), PortInfo { ifindex: IFINDEX, mac: BNG_MAC })]);
    other.configure(lab.now, hot(n), &ports);
    let refs: Vec<&SessionRecord> = recs.iter().collect();
    let done = other.adopt(lab.now, &refs);
    assert_eq!((done.sessions, done.skipped), (0, n));
}
