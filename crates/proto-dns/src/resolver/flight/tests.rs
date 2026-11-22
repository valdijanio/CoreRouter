//! G4.1o: equal lookups in flight make one query upstream (RFC 5452 §5),
//! with real threads and a server that takes its time.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_model::dns::Dns;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;

use super::super::{ResolveError, Resolver, Settings, Source, Transport, TransportError};
use super::{Flights, Role};
use crate::message::parse_name;
use crate::message::tests::{a, reply};

/// A server that answers after `delay` (or fails), counting the queries.
struct Slow {
    asked: Arc<AtomicUsize>,
    delay: Duration,
    fail: bool,
    epoch: Instant,
}

impl Transport for Slow {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap()
    }

    fn exchange(
        &mut self,
        _server: SocketAddr,
        query: &[u8],
        _tcp: bool,
        _wait_ms: u64,
        accept: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<Vec<u8>, TransportError> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        thread::sleep(self.delay);
        if self.fail {
            return Err(TransportError::Timeout);
        }
        let owner = Message::from_vec(query).unwrap().queries[0]
            .name()
            .to_ascii();
        let b = reply(
            query,
            ResponseCode::NoError,
            vec![a(&owner, 300, [198, 51, 100, 7])],
            None,
        );
        assert!(accept(&b));
        Ok(b)
    }
}

fn resolver() -> Arc<Resolver> {
    let dns = Dns {
        servers: vec!["192.0.2.1".parse::<IpAddr>().unwrap()],
        query_server_timeout_ms: 2000,
        ..Dns::default()
    };
    Arc::new(Resolver::new(Settings::new(&dns, &[])))
}

/// `n` threads ask `names[i % len]` at once (a barrier, then the lookup).
fn ask_together(
    r: &Arc<Resolver>,
    n: usize,
    names: &[(&'static str, RecordType)],
    fail: bool,
) -> (usize, Vec<Result<super::super::Resolved, ResolveError>>) {
    let asked = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(n));
    let epoch = Instant::now();
    let handles: Vec<_> = (0..n)
        .map(|i| {
            let (r, asked, barrier) = (r.clone(), asked.clone(), barrier.clone());
            let (name, rtype) = names[i % names.len()];
            thread::spawn(move || {
                let mut t = Slow {
                    asked,
                    delay: Duration::from_millis(300),
                    fail,
                    epoch,
                };
                let qn = parse_name(name).unwrap();
                barrier.wait();
                r.resolve(&mut t, &qn, rtype, None)
            })
        })
        .collect();
    let out = handles.into_iter().map(|h| h.join().unwrap()).collect();
    (asked.load(Ordering::SeqCst), out)
}

#[test]
fn ten_equal_lookups_make_one_query() {
    let r = resolver();
    let (asked, out) = ask_together(&r, 10, &[("popular.example", RecordType::A)], false);
    assert_eq!(asked, 1, "RFC 5452 §5: one query for the ten");
    for o in &out {
        let got = o.as_ref().unwrap();
        assert_eq!(
            got.answer.addresses(),
            vec!["198.51.100.7".parse::<IpAddr>().unwrap()]
        );
        assert!(matches!(got.source, Source::Server(_)), "{:?}", got.source);
    }
    assert_eq!(r.flights.len(), 0, "the flight is gone");
    // Cached now: no flight, no query.
    let (asked, _) = ask_together(&r, 4, &[("popular.example", RecordType::A)], false);
    assert_eq!(asked, 0);
}

#[test]
fn a_failure_is_shared_and_held_once() {
    let r = resolver();
    let (asked, out) = ask_together(&r, 8, &[("dead.example", RecordType::A)], true);
    // One lookup: its three queries to the one server (RFC 9520 §3.1,
    // G4.1u); the seven followers add none.
    assert_eq!(asked, 3, "the followers do not ask again");
    for o in out {
        assert!(matches!(o, Err(ResolveError::Failed { .. })), "{o:?}");
    }
    assert_eq!(r.flights.len(), 0);
}

#[test]
fn other_names_and_types_are_their_own_flights() {
    let r = resolver();
    let names = [
        ("one.example", RecordType::A),
        ("one.example", RecordType::AAAA),
        ("two.example", RecordType::A),
    ];
    let (asked, out) = ask_together(&r, 9, &names, false);
    assert_eq!(asked, 3, "one per name and type");
    assert!(out.iter().all(Result::is_ok));
}

#[test]
fn a_follower_gives_up_at_its_deadline() {
    let flights = Arc::new(Flights::default());
    let key = || ("x.example".to_owned(), RecordType::A, None);
    let Role::Lead(_lead) = flights.join(key(), 10) else {
        panic!("first one leads");
    };
    let Role::Follow(f) = flights.join(key(), 10) else {
        panic!("second one follows");
    };
    let t = std::cell::Cell::new(0u64);
    // The clock moves 40 ms per look; the leader never answers.
    let now = || {
        t.set(t.get() + 40);
        t.get()
    };
    assert!(f.wait(100, &now).is_none());
}

#[test]
fn a_leader_that_unwinds_frees_its_followers() {
    let flights = Arc::new(Flights::default());
    let key = || ("x.example".to_owned(), RecordType::A, None);
    let Role::Lead(lead) = flights.join(key(), 10) else {
        panic!("first one leads");
    };
    let Role::Follow(f) = flights.join(key(), 10) else {
        panic!("second one follows");
    };
    drop(lead);
    let got = f.wait(u64::MAX, &|| 0).expect("published on drop");
    assert!(matches!(got, Err(ResolveError::Failed { .. })), "{got:?}");
    assert_eq!(flights.len(), 0);
    // A new lookup leads a new flight.
    assert!(matches!(flights.join(key(), 10), Role::Lead(_)));
}

/// G4.1t: a follower leaves a callback instead of a blocked thread; it
/// takes no slot, and the leaders are bounded.
#[test]
fn callbacks_take_no_slot_and_leaders_are_bounded() {
    let flights = Arc::new(Flights::default());
    let key = |n: &str| (n.to_owned(), RecordType::A, None);
    let Role::Lead(lead) = flights.join(key("a.example"), 2) else {
        panic!("leads");
    };
    let got = Arc::new(std::sync::Mutex::new(Vec::new()));
    for _ in 0..100 {
        let Role::Follow(f) = flights.join(key("a.example"), 2) else {
            panic!("follows: no slot needed");
        };
        let got = got.clone();
        f.then(Box::new(move |r| got.lock().unwrap().push(r.is_err())));
    }
    assert_eq!(flights.counts(), (1, 100));
    let Role::Lead(_b) = flights.join(key("b.example"), 2) else {
        panic!("a second leader fits");
    };
    assert!(
        matches!(flights.join(key("c.example"), 2), Role::Busy),
        "max 2 leaders"
    );
    lead.finish(&Err(ResolveError::NoServers));
    assert_eq!(got.lock().unwrap().len(), 100, "every callback ran once");
    assert_eq!(flights.counts(), (1, 0));
}

/// A follower that comes after the result is out gets it at once.
#[test]
fn a_late_callback_runs_now() {
    let flights = Arc::new(Flights::default());
    let key = || ("x.example".to_owned(), RecordType::A, None);
    let Role::Lead(lead) = flights.join(key(), 10) else {
        panic!()
    };
    let Role::Follow(f) = flights.join(key(), 10) else {
        panic!()
    };
    lead.finish(&Err(ResolveError::NoServers));
    let ran = Arc::new(AtomicUsize::new(0));
    let r2 = ran.clone();
    f.then(Box::new(move |_| {
        r2.fetch_add(1, Ordering::SeqCst);
    }));
    assert_eq!(ran.load(Ordering::SeqCst), 1);
    assert_eq!(flights.counts(), (0, 0));
}
