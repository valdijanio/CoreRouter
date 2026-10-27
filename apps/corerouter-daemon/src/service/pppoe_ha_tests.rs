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

/// The tests share the pair's globals (`HA_ACTIVE`, the takeover hand-off):
/// one at a time, this node active.
fn pair_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let g = LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    HA_ACTIVE.store(true, Ordering::Release);
    g
}

/// A worker created after another test's takeover would wait for it.
fn no_takeover_pending(b: &mut Bng, now: u64) {
    *TAKEOVER.lock().unwrap() = None;
    TAKEOVER_GEN.fetch_add(1, Ordering::AcqRel);
    b.ha_adopt_pending(now);
    assert!(!b.ha_pending());
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
    let _g = pair_lock();
    let n = 200;
    let mut lab = Lab::new(n, hot(n), |i| (format!("u{i}"), format!("p{i}")));
    no_takeover_pending(&mut lab.bng, 0);
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
}

#[test]
fn sessions_of_another_server_are_skipped_and_counted() {
    let _g = pair_lock();
    let n = 5;
    let mut lab = Lab::new(n, hot(n), |i| (format!("u{i}"), format!("p{i}")));
    no_takeover_pending(&mut lab.bng, 0);
    lab.start(0..n);
    lab.run(400, 50);
    let mut recs = records(&lab.bng.ha_take(lab.now));
    assert_eq!(recs.len(), n);
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

/// G4.3ha: a RADIUS session's Class (RFC 2865 §5.25) goes in its record,
/// and the node that takes it over echoes it, byte for byte, in its
/// Interim and its Stop, with the same Acct-Session-Id.
#[test]
fn the_class_of_a_radius_session_survives_a_takeover() {
    use super::pppoe_bng_tests::{FAKE_CLASS, FakeAaa};
    use corerouter_model::radius::AcctStatus;
    let radius_snap = |aaa: &Arc<FakeAaa>| {
        // PAP: the in-memory RADIUS has no MS-CHAP2-Success to give.
        let mut s = snap(0, server(serde_json::json!({"authentication": ["pap"]})), 10);
        s.ppp.redundancy.enabled = true;
        s.ppp.redundancy.mode = corerouter_model::ppp_redundancy::HaMode::HotStandby;
        s.ppp.redundancy.secret = "segredo-do-par-123".into();
        s.ppp.aaa.use_radius = true;
        s.aaa = Some(aaa.clone());
        s
    };
    let _g = pair_lock();
    let a_aaa = Arc::new(FakeAaa::default());
    let n = 3;
    let mut lab = Lab::new(n, radius_snap(&a_aaa), |i| (format!("r{i}"), "x".into()));
    no_takeover_pending(&mut lab.bng, 0);
    for i in 0..n {
        let mut cfg = lab.clients[i].config().clone();
        cfg.auth = corerouter_proto_pppoe::layers::AuthSet::new(&[corerouter_proto_pppoe::lcp::AuthProto::Pap]);
        lab.clients[i] = corerouter_proto_pppoe::client::Client::new(cfg, [5 + i as u8; 32]);
    }
    lab.start(0..n);
    lab.run(400, 50);
    assert_eq!(lab.ups(), n);
    let published = records(&lab.bng.ha_take(lab.now));
    assert_eq!(published.len(), n);
    for r in &published {
        assert_eq!(r.class.len(), 1);
        assert_eq!(&*r.class[0], FAKE_CLASS, "the record carries the Class");
        // What it costs on the sync link: one TLV (type, length u16, value).
        let mut bare = r.clone();
        bare.class.clear();
        let (with, without) = (r.to_bytes().unwrap().len(), bare.to_bytes().unwrap().len());
        assert_eq!(with - without, 3 + FAKE_CLASS.len(), "{with} B against {without} B");
    }
    let starts: Vec<_> = a_aaa.accts.lock().unwrap().clone();
    assert!(starts.iter().all(|r| r.status == AcctStatus::Start && r.class == [FAKE_CLASS.to_vec()]));

    let c_aaa = Arc::new(FakeAaa::default());
    let mut other = Bng::new([9; 32]);
    let ports = HashMap::from([("pppoe-ether2".to_owned(), PortInfo { ifindex: IFINDEX, mac: BNG_MAC })]);
    other.configure(lab.now, radius_snap(&c_aaa), &ports);
    no_takeover_pending(&mut other, lab.now);
    let refs: Vec<&SessionRecord> = published.iter().collect();
    assert_eq!(other.adopt(lab.now, &refs).sessions, n);
    lab.bng = other;
    lab.run(100, 50);
    let ids: Vec<String> = lab.backend().active().iter().map(|a| a.id.clone()).collect();
    lab.backend().terminate(&ids);
    lab.bng.requests(lab.now);
    lab.run(100, 50);
    let accts = c_aaa.accts.lock().unwrap().clone();
    let kinds = |s: AcctStatus| accts.iter().filter(|r| r.status == s).count();
    assert_eq!((kinds(AcctStatus::Start), kinds(AcctStatus::InterimUpdate), kinds(AcctStatus::Stop)), (0, n, n));
    assert!(accts.iter().all(|r| r.class == [FAKE_CLASS.to_vec()]), "{accts:?}");
    let mut a: Vec<_> = starts.iter().map(|r| r.session_id.clone()).collect();
    let mut b: Vec<_> = accts.iter().filter(|r| r.status == AcctStatus::Stop).map(|r| r.session_id.clone()).collect();
    a.sort();
    b.sort();
    assert_eq!(a, b, "the same Acct-Session-Id from the Start to the Stop");
}

#[test]
fn the_class_limit_is_the_records() {
    assert_eq!(corerouter_engine::radius::MAX_CLASS, corerouter_proto_ha::record::MAX_CLASS);
}
