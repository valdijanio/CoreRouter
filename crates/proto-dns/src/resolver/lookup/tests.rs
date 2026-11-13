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
    // G4.1u: never measured, so Unbound's 376 ms, not query_server_timeout.
    assert_eq!(l.wake_at(), Some(376));
    assert!(l.tick(375).is_empty());
    let second = l.tick(376);
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].server.ip(), ip("192.0.2.2"));
    assert_ne!(second[0].token, first[0].token);
    assert_eq!(second[0].wait_ms, 376);
    assert!(
        l.reply(second[0].token, &answer(&second[0], [192, 0, 2, 80]), 386)
            .is_empty()
    );
    assert!(l.done());
    let got = r.complete(*l, 386).unwrap();
    assert_eq!(got.source, Source::Server(ip("192.0.2.2")));
    assert_eq!(got.answer.addresses(), vec![ip("192.0.2.80")]);
    let stats: std::collections::BTreeMap<_, _> = r.server_stats().into_iter().collect();
    let a = stats[&ip("192.0.2.1")];
    assert_eq!(a.timeouts, 1);
    assert_eq!(a.rto_ms, 752, "RFC 6298 §5.5: doubled");
    assert_eq!(a.down_until_ms, 0, "one lost datagram is not down");
    let b = stats[&ip("192.0.2.2")];
    // RFC 6298 §2.2: SRTT = R, RTTVAR = R/2, RTO = SRTT + 4·RTTVAR (≥ 50).
    assert_eq!((b.srtt_ms, b.rttvar_ms, b.rto_ms), (Some(10), 5, 50));
}

/// G4.1u: an answer to a query past its wait still counts (it was only
/// slow); the lookup ends there.
#[test]
fn a_late_answer_to_an_expired_query_is_taken() {
    let r = resolver(&["192.0.2.1", "192.0.2.2"], 10_000);
    let mut l = lead(&r, "late.example");
    let first = l.start(0).remove(0);
    let second = l.tick(376).remove(0);
    assert!(l.waiting().any(|t| t == first.token), "still listening");
    assert!(
        l.reply(first.token, &answer(&first, [192, 0, 2, 1]), 500)
            .is_empty()
    );
    assert!(l.done());
    assert!(l.waiting().next().is_none());
    let got = r.complete(*l, 500).unwrap();
    assert_eq!(got.source, Source::Server(ip("192.0.2.1")));
    let _ = second;
}

/// G4.1u: one server that loses datagrams is asked three times (RFC 9520
/// §3.1: no more), at its RTO, twice that, then the whole
/// query_server_timeout.
#[test]
fn three_tries_to_one_server_with_backoff_rfc9520() {
    let r = resolver(&["192.0.2.1"], 10_000);
    let mut l = lead(&r, "lossy.example");
    let a = l.start(0).remove(0);
    assert_eq!(a.wait_ms, 376);
    let b = l.tick(376).remove(0);
    assert_eq!(b.server, a.server);
    assert_ne!(b.id, a.id, "a fresh id for each try");
    assert_eq!(b.wait_ms, 752);
    let c = l.tick(376 + 752).remove(0);
    assert_eq!(c.wait_ms, 2000, "the last try waits it all");
    assert!(l.tick(376 + 752 + 1999).is_empty());
    assert!(!l.done());
    assert!(l.tick(376 + 752 + 2000).is_empty());
    assert!(l.done(), "no fourth query");
    let err = r.complete(*l, 3128).unwrap_err();
    assert!(matches!(err, ResolveError::Failed { .. }));
    let s = r.server_stats()[0].1;
    assert_eq!(s.timeouts, 3);
    assert!(s.down_until_ms > 0, "three timeouts in a row: down");
}

/// G4.1u: the RTO comes from what the server measured.
#[test]
fn the_rto_follows_the_server() {
    let r = resolver(&["192.0.2.1"], 10_000);
    for i in 0..8u64 {
        let mut l = lead(&r, &format!("n{i}.example"));
        let x = l.start(i * 1000).remove(0);
        l.reply(x.token, &answer(&x, [192, 0, 2, 1]), i * 1000 + 20);
        r.complete(*l, i * 1000 + 20).unwrap();
    }
    let s = r.server_stats()[0].1;
    assert_eq!(s.srtt_ms, Some(20));
    assert!(s.rto_ms >= 50 && s.rto_ms < 100, "{}", s.rto_ms);
    let mut l = lead(&r, "next.example");
    let x = l.start(10_000).remove(0);
    assert_eq!(x.wait_ms, s.rto_ms, "a server known to answer in 20 ms");
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
    // Looked at late (2010 ms): the second expired long ago (its RTO); the
    // third, the last try, gets only what is left of the 3 s.
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

/// G4.1v (RFC 8767 §5): the client response timer. A lookup still out
/// answers with the stale entry; the equal lookups waiting and the ones
/// that join later get it at once, no new lookup starts, and the lookup's
/// own result later only refreshes the cache.
#[test]
fn stale_goes_out_early_and_the_lookup_goes_on() {
    let dns = Dns {
        servers: vec![ip("192.0.2.1")],
        serve_stale_secs: 86_400,
        ..Dns::default()
    };
    let r = Resolver::new(Settings::new(&dns, &[]));
    // Cached with TTL 1 s, then expired.
    let mut l = lead(&r, "old.example");
    let x = l.start(0).remove(0);
    let owner = Message::from_vec(&x.query).unwrap().queries[0]
        .name()
        .to_ascii();
    let one = reply(
        &x.query,
        ResponseCode::NoError,
        vec![a(&owner, 1, [192, 0, 2, 1])],
        None,
    );
    l.reply(x.token, &one, 5);
    r.complete(*l, 5).unwrap();
    let qn = parse_name("old.example").unwrap();
    let Begin::Lead(mut l) = r.begin(&qn, RecordType::A, None, 10_000) else {
        panic!("expired: a new lookup")
    };
    assert!(l.serves_stale());
    let x = l.start(10_000).remove(0);
    let Begin::Follow(before) = r.begin(&qn, RecordType::A, None, 10_100) else {
        panic!()
    };
    let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let g = got.clone();
    before.then(Box::new(move |res| g.lock().unwrap().push(res)));
    let stale = r
        .answer_stale(&l, 10_000 + super::super::STALE_CLIENT_MS)
        .unwrap();
    assert_eq!(stale.source, Source::Stale);
    assert_eq!(stale.answer.ttl, Some(30), "RFC 8767 §4: TTL 30 s");
    assert_eq!(got.lock().unwrap().len(), 1, "the follower got it too");
    // A lookup now still follows the one in flight, and gets stale at once.
    let Begin::Follow(after) = r.begin(&qn, RecordType::A, None, 11_900) else {
        panic!("no second lookup upstream")
    };
    assert_eq!(after.wait(0, &|| 0).unwrap().unwrap().source, Source::Stale);
    // The server answers at last: the cache is fresh again.
    let fresh = reply(
        &x.query,
        ResponseCode::NoError,
        vec![a(&owner, 300, [192, 0, 2, 2])],
        None,
    );
    l.reply(x.token, &fresh, 12_000);
    r.complete(*l, 12_000).unwrap();
    assert_eq!(r.in_flight(), (0, 0));
    match r.begin(&qn, RecordType::A, None, 12_001) {
        Begin::Now(Ok(hit)) => {
            assert_eq!(hit.source, Source::Cache);
            assert_eq!(hit.answer.addresses(), vec![ip("192.0.2.2")]);
        }
        other => panic!("{other:?}"),
    }
}

/// Nothing stale in the cache: the client keeps waiting.
#[test]
fn no_stale_entry_no_early_answer() {
    let dns = Dns {
        servers: vec![ip("192.0.2.1")],
        serve_stale_secs: 86_400,
        ..Dns::default()
    };
    let r = Resolver::new(Settings::new(&dns, &[]));
    let mut l = lead(&r, "never.example");
    l.start(0);
    assert!(r.answer_stale(&l, 1800).is_none());
    assert!(!l.done());
}
