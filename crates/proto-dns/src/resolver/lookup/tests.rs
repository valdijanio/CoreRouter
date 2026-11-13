//! G4.1t: the lookup state machine driven as the daemon's event loop
//! drives it: several exchanges, the clock moved by hand, no transport.

use std::net::IpAddr;

use corerouter_model::dns::Dns;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;

use super::super::{Begin, ResolveError, Resolver, Settings, Source};
use super::{Exchange, Lookup, Way};
use crate::message::parse_name;
use crate::message::tests::{a, reply};

fn resolver(servers: &[&str], total_ms: u32) -> Resolver {
    let dns = Dns {
        servers: servers.iter().map(|s| s.parse().unwrap()).collect(),
        query_server_timeout_ms: 2000,
        query_total_timeout_ms: total_ms,
        max_concurrent_queries: 2,
        ..Dns::default()
    };
    Resolver::new(Settings::new(&dns, &[]))
}

fn lead(r: &Resolver, name: &str) -> Box<Lookup> {
    match r.begin(&parse_name(name).unwrap(), RecordType::A, None, 0) {
        Begin::Lead(l) => l,
        other => panic!("expected a new lookup, got {other:?}"),
    }
}

fn answer(x: &Exchange, ip: [u8; 4]) -> Vec<u8> {
    let owner = Message::from_vec(&x.query).unwrap().queries[0]
        .name()
        .to_ascii();
    reply(
        &x.query,
        ResponseCode::NoError,
        vec![a(&owner, 300, ip)],
        None,
    )
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn a_silent_server_times_out_on_tick_and_the_next_answers() {
    let r = resolver(&["192.0.2.1", "192.0.2.2"], 10_000);
    let mut l = lead(&r, "www.example");
    let first = l.start(0);
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].server.ip(), ip("192.0.2.1"));
    assert_eq!(first[0].way, Way::Udp);
    assert_eq!(l.wake_at(), Some(2000), "query_server_timeout");
    // Nothing before the wait is over.
    assert!(l.tick(1999).is_empty());
    let second = l.tick(2000);
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].server.ip(), ip("192.0.2.2"));
    assert_ne!(second[0].token, first[0].token);
    // A reply for the first exchange now is too late: it moved on.
    assert!(
        l.reply(first[0].token, &answer(&first[0], [6, 6, 6, 6]), 2001)
            .is_empty()
    );
    assert!(!l.done());
    assert!(
        l.reply(second[0].token, &answer(&second[0], [192, 0, 2, 80]), 2010)
            .is_empty()
    );
    assert!(l.done());
    let got = r.complete(*l, 2010).unwrap();
    assert_eq!(got.source, Source::Server(ip("192.0.2.2")));
    assert_eq!(got.answer.addresses(), vec![ip("192.0.2.80")]);
    // The first server is counted as a timeout, the second answered in 10 ms.
    let stats: std::collections::BTreeMap<_, _> = r.server_stats().into_iter().collect();
    assert_eq!(stats[&ip("192.0.2.1")].timeouts, 1);
    assert_eq!(stats[&ip("192.0.2.2")].srtt_ms, Some(10));
}

#[test]
fn a_stray_reply_is_skipped_rfc5452() {
    let r = resolver(&["192.0.2.1"], 10_000);
    let mut l = lead(&r, "www.example");
    let x = l.start(0).remove(0);
    let mut forged = Message::from_vec(&answer(&x, [6, 6, 6, 6])).unwrap();
    forged.metadata.id = x.id.wrapping_add(1);
    let forged = forged.to_vec().unwrap();
    assert!(!l.accepts(x.token, &forged));
    assert!(l.reply(x.token, &forged, 5).is_empty());
    assert!(
        !l.done(),
        "RFC 5452 §9.1: still waiting for the real answer"
    );
    let real = answer(&x, [192, 0, 2, 9]);
    assert!(l.accepts(x.token, &real));
    l.reply(x.token, &real, 6);
    assert!(l.done());
}

#[test]
fn truncated_goes_to_tcp_of_the_same_server_rfc7766() {
    let r = resolver(&["192.0.2.1"], 10_000);
    let mut l = lead(&r, "big.example");
    let x = l.start(0).remove(0);
    let mut m = Message::from_vec(&reply(&x.query, ResponseCode::NoError, vec![], None)).unwrap();
    m.metadata.truncation = true;
    let tcp = l.reply(x.token, &m.to_vec().unwrap(), 3);
    assert_eq!(tcp.len(), 1);
    assert_eq!(tcp[0].way, Way::Tcp);
    assert_eq!(tcp[0].server, x.server);
    l.reply(tcp[0].token, &answer(&tcp[0], [192, 0, 2, 7]), 9);
    let got = r.complete(*l, 9).unwrap();
    assert_eq!(got.source, Source::Server(ip("192.0.2.1")));
    let stats = r.server_stats();
    assert_eq!(stats[0].1.truncated, 1);
    assert_eq!(
        stats[0].1.srtt_ms,
        Some(9),
        "the RTT counts from the UDP query"
    );
}

#[test]
fn servfail_moves_on_and_the_total_timeout_ends_it() {
    let r = resolver(&["192.0.2.1", "192.0.2.2", "192.0.2.3"], 3000);
    let mut l = lead(&r, "dead.example");
    let x = l.start(0).remove(0);
    let next = l.reply(
        x.token,
        &reply(&x.query, ResponseCode::ServFail, vec![], None),
        10,
    );
    assert_eq!(next[0].server.ip(), ip("192.0.2.2"));
    // The second waits 2 s, the third only what is left of the 3 s.
    let third = l.tick(2010);
    assert_eq!(third[0].server.ip(), ip("192.0.2.3"));
    assert_eq!(third[0].wait_ms, 990);
    assert!(l.tick(3000).is_empty());
    assert!(l.done());
    let err = r.complete(*l, 3000).unwrap_err();
    let ResolveError::Failed { why, .. } = err else {
        panic!("{err:?}")
    };
    assert!(
        why.contains("SERVFAIL") || why.contains("server failure"),
        "{why}"
    );
    assert!(why.contains("query_total_timeout reached"), "{why}");
}

/// The equal lookups wait for the leader without a slot; a third name past
/// `max_concurrent_queries` (2 here) is refused.
#[test]
fn followers_wait_on_the_leader_and_the_limit_counts_leaders() {
    let r = resolver(&["192.0.2.1"], 10_000);
    let mut one = lead(&r, "one.example");
    let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    for _ in 0..5 {
        match r.begin(&parse_name("one.example").unwrap(), RecordType::A, None, 0) {
            Begin::Follow(f) => {
                let got = got.clone();
                f.then(Box::new(move |res| got.lock().unwrap().push(res)));
            }
            other => panic!("{other:?}"),
        }
    }
    let _two = lead(&r, "two.example");
    assert!(matches!(
        r.begin(
            &parse_name("three.example").unwrap(),
            RecordType::A,
            None,
            0
        ),
        Begin::Now(Err(ResolveError::Busy))
    ));
    assert_eq!(r.in_flight(), (2, 5));
    let x = one.start(0).remove(0);
    one.reply(x.token, &answer(&x, [192, 0, 2, 1]), 4);
    r.complete(*one, 4).unwrap();
    let got = got.lock().unwrap();
    assert_eq!(got.len(), 5);
    assert!(
        got.iter()
            .all(|g| g.as_ref().unwrap().answer.addresses() == vec![ip("192.0.2.1")])
    );
    // Cached now: no lookup.
    assert!(matches!(
        r.begin(&parse_name("one.example").unwrap(), RecordType::A, None, 5),
        Begin::Now(Ok(_))
    ));
}

/// A lookup dropped unfinished (its loop closing) frees its followers.
#[test]
fn a_dropped_lookup_fails_its_followers() {
    let r = resolver(&["192.0.2.1"], 10_000);
    let l = lead(&r, "gone.example");
    let Begin::Follow(f) = r.begin(&parse_name("gone.example").unwrap(), RecordType::A, None, 0)
    else {
        panic!()
    };
    drop(l);
    assert!(f.wait(u64::MAX, &|| 0).unwrap().is_err());
    assert_eq!(r.in_flight(), (0, 0));
}
