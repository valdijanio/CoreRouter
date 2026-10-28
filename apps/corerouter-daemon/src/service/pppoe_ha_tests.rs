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
use super::pppoe_bng::{Backend, Bng, HA_ACTIVE, PortInfo, Snapshot};
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
    let done = other.ha_adopt_pending(now).expect("one chunk adopts 200");
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

/// G4.3hh profiling: `n` records over two servers, adopted by `lanes`
/// workers in parallel like the daemon's.
fn synth(n: usize, lanes: u16) -> (Snapshot, Vec<SessionRecord>) {
    let mut s = hot(n);
    s.pools = super::pppoe_bng_tests::pools_of(200_000);
    let mut second = s.ppp.pppoe_servers[0].clone();
    second.name = "pppoe-ether3".into();
    second.id = corerouter_model::ItemId(2);
    second.interface = "ether3".parse().unwrap();
    s.ppp.pppoe_servers.push(second);
    let mut lab = Lab::new(1, hot(1), |i| (format!("u{i}"), format!("p{i}")));
    no_takeover_pending(&mut lab.bng, 0);
    lab.start(0..1);
    lab.run(400, 50);
    let t = records(&lab.bng.ha_take(lab.now)).remove(0);
    let mut next_sid: HashMap<(usize, u16), u16> = HashMap::new();
    let base = u32::from(std::net::Ipv4Addr::new(100, 64, 0, 1));
    let recs = (0..n)
        .map(|i| {
            let mut r = t.clone();
            r.client_mac = [0x02, 0x10, (i >> 16) as u8, (i >> 8) as u8, i as u8, 0x01];
            let lane = super::pppoe_bng::ha::mac_lane(r.client_mac, lanes);
            let srv = i % 2;
            let sid = next_sid.entry((srv, lane)).or_insert(lane);
            *sid += lanes;
            r.sid = *sid;
            r.server = if srv == 0 { "pppoe-ether2".into() } else { "pppoe-ether3".into() };
            r.ipv4 = Some(std::net::Ipv4Addr::from(base + i as u32));
            r.username = format!("u{i}").into_bytes().into();
            r.acct_session_id = format!("{i:08x}").into();
            r
        })
        .collect();
    (s, recs)
}

#[test]
#[ignore = "profiling: cargo test --release -p corerouter-daemon adopt_profile -- --ignored --nocapture"]
fn adopt_profile() {
    let _g = pair_lock();
    let n: usize = std::env::var("ADOPT_N").ok().and_then(|v| v.parse().ok()).unwrap_or(100_000);
    let lanes: u16 = std::env::var("ADOPT_LANES").ok().and_then(|v| v.parse().ok()).unwrap_or(8);
    let (s, recs) = synth(n, lanes);
    let ports = HashMap::from([
        ("pppoe-ether2".to_owned(), PortInfo { ifindex: IFINDEX, mac: BNG_MAC }),
        ("pppoe-ether3".to_owned(), PortInfo { ifindex: IFINDEX + 1, mac: BNG_MAC }),
    ]);
    let mut bngs = vec![Bng::first_of([9; 32], lanes)];
    for lane in 1..lanes {
        let b = bngs[0].sibling([9; 32], lane, lanes);
        bngs.push(b);
    }
    for b in &mut bngs {
        b.configure(0, s.clone(), &ports);
        no_takeover_pending(b, 0);
    }
    let shared = bngs[0].shared.clone();
    *TAKEOVER.lock().unwrap() = Some(Arc::new(recs));
    TAKEOVER_GEN.fetch_add(1, Ordering::AcqRel);
    let t0 = std::time::Instant::now();
    let handles: Vec<_> = bngs
        .into_iter()
        .map(|mut b| {
            std::thread::spawn(move || {
                let t = std::time::Instant::now();
                let mut d = b.ha_adopt_pending(1000);
                let answering = t.elapsed();
                while d.is_none() {
                    d = b.ha_adopt_step(1000);
                }
                let d = d.unwrap();
                let serving = t.elapsed();
                while b.ha_later() {
                    b.ha_adopt_rest(1000);
                }
                (d, answering, serving, t.elapsed(), b)
            })
        })
        .collect();
    let mut total = 0;
    for h in handles {
        let (d, answering, serving, all, b) = h.join().unwrap();
        eprintln!("worker: {} adopted, {} skipped: answering after {answering:?}, all adopted after {serving:?}, bookkeeping done after {all:?} ({} effects)", d.sessions, d.skipped, b.effects.len());
        total += d.sessions;
        b.check().unwrap();
    }
    eprintln!("{total} of {n} adopted by {lanes} workers in {:?}", t0.elapsed());
    assert_eq!(total, n);
    assert_eq!(Backend(shared).active().len(), n, "every session in the active table");
}

/// G4.3hh: the worker answers after the first phase of a takeover; the
/// bookkeeping (active table, history, Interim) follows a chunk per round.
/// A session that ends in between still gets its row first: its Stop
/// carries the counters it came with, and no Interim goes for it.
#[test]
fn a_session_that_ends_before_its_bookkeeping_keeps_its_counters() {
    use super::pppoe_bng_tests::FakeAaa;
    use corerouter_model::radius::AcctStatus;
    let radius_snap = |aaa: &Arc<FakeAaa>| {
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
    let mut published = records(&lab.bng.ha_take(lab.now));
    for r in &mut published {
        r.counters.rx_bytes = 123_456;
        r.counters.tx_bytes = 654_321;
    }
    let c_aaa = Arc::new(FakeAaa::default());
    let mut other = Bng::new([9; 32]);
    let ports = HashMap::from([("pppoe-ether2".to_owned(), PortInfo { ifindex: IFINDEX, mac: BNG_MAC })]);
    other.configure(lab.now, radius_snap(&c_aaa), &ports);
    no_takeover_pending(&mut other, lab.now);
    let refs: Vec<&SessionRecord> = published.iter().collect();
    assert_eq!(other.adopt(lab.now, &refs).sessions, n);
    // First phase only: serving, nothing in the table yet, no Interim.
    assert!(other.ha_later());
    assert!(Backend(other.shared.clone()).active().is_empty());
    assert!(c_aaa.accts.lock().unwrap().is_empty());
    // Subscriber 0 hangs up now (PADT to the new node).
    let mut out = corerouter_proto_pppoe::client::ClientOutput::new();
    lab.clients[0].abort(&mut out);
    for (_, f) in out.frames() {
        other.frame(lab.now, IFINDEX, f);
    }
    lab.bng = other;
    lab.run(100, 50);
    assert!(!lab.bng.ha_later(), "the bookkeeping is done");
    let accts = c_aaa.accts.lock().unwrap().clone();
    let stops: Vec<_> = accts.iter().filter(|r| r.status == AcctStatus::Stop).collect();
    assert_eq!(stops.len(), 1, "{accts:?}");
    let c = stops[0].counters.as_ref().unwrap();
    assert_eq!((c.input_octets, c.output_octets), (123_456, 654_321), "the counters it came with");
    let interims = accts.iter().filter(|r| r.status == AcctStatus::InterimUpdate).count();
    assert_eq!(interims, n - 1, "an Interim for each session still up, none for the one gone");
    let active = lab.backend().active();
    assert_eq!(active.len(), n - 1);
    assert!(active.iter().all(|a| a.rx_bytes == 123_456));
    lab.bng.check().unwrap();
}

/// G4.3hh: a takeover bigger than one chunk. The worker answers after the
/// first; an upstream packet of a session still waiting adopts it on the
/// spot and goes up (no PADT); the next rounds adopt the rest.
#[test]
fn a_frame_of_a_session_not_adopted_yet_adopts_it_on_the_spot() {
    let _g = pair_lock();
    let n = 1300;
    let mut lab = Lab::new(n, hot(n), |i| (format!("u{i}"), format!("p{i}")));
    no_takeover_pending(&mut lab.bng, 0);
    lab.start(0..n);
    lab.run(400, 50);
    assert_eq!(lab.ups(), n);
    let now = lab.now;
    let published = records(&lab.bng.ha_take(now));
    let mut other = Bng::new([9; 32]);
    let ports = HashMap::from([("pppoe-ether2".to_owned(), PortInfo { ifindex: IFINDEX, mac: BNG_MAC })]);
    other.configure(now, hot(n), &ports);
    *TAKEOVER.lock().unwrap() = Some(Arc::new(published.clone()));
    TAKEOVER_GEN.fetch_add(1, Ordering::AcqRel);
    assert!(other.ha_adopt_pending(now).is_none(), "one chunk, more to go");
    assert!(other.serving(), "it answers already");
    assert!(other.ha_adopting());
    // The chunks take the records from the end: the first is still waiting.
    let r = &published[0];
    let ip = r.ipv4.unwrap();
    let mut pkt = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0];
    pkt.extend_from_slice(&ip.octets());
    pkt.extend_from_slice(&[8, 8, 8, 8]);
    let mut f = Vec::new();
    f.extend_from_slice(&BNG_MAC);
    f.extend_from_slice(&r.client_mac);
    f.extend_from_slice(&[0x88, 0x64, 0x11, 0x00]);
    f.extend_from_slice(&r.sid.to_be_bytes());
    f.extend_from_slice(&(pkt.len() as u16 + 2).to_be_bytes());
    f.extend_from_slice(&[0x00, 0x21]);
    f.extend_from_slice(&pkt);
    other.frame(now, IFINDEX, &f);
    assert_eq!(other.upstream, vec![pkt], "adopted and forwarded");
    assert!(other.frames.is_empty(), "no PADT, nothing to the subscriber");
    let mut done = None;
    for _ in 0..10 {
        if done.is_none() {
            done = other.ha_adopt_step(now);
        }
    }
    let done = done.expect("the rest in the next chunk");
    assert_eq!((done.sessions, done.skipped), (n, 0), "the one on demand counted once");
    assert!(!other.ha_adopting());
    lab.bng = other;
    lab.run(2400, 50);
    assert_eq!(lab.ups(), n, "no subscriber noticed");
    assert_eq!(lab.backend().stats().padt_tx, 0);
    assert_eq!(lab.backend().active().len(), n);
    lab.bng.check().unwrap();
}
