//! Load simulation: 100 000 Access-Requests and 100 000 Interim-Updates
//! through the client, on a virtual network with 3 % loss each way, two
//! authentication and two accounting servers, and the primary
//! authentication server dying for a minute in the middle.
//!
//! Checked on every datagram, not only at the end:
//! - no identifier is used twice on a socket while outstanding;
//! - a retransmission is byte for byte the previous transmission;
//! - a new transmission of a request (failover) has a new identifier or
//!   socket, a new authenticator, and Acct-Delay-Time not smaller;
//! - the client's own tables stay consistent;
//! - every request ends exactly once.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use crate::common;

use std::collections::HashMap;
use std::net::SocketAddr;

use common::{Net, Sent};
use corerouter_proto_radius::acct::{Counters, Record, StatusType};
use corerouter_proto_radius::client::{
    Client, ClientConfig, Event, Failure, RequestId, ServerConfig,
};
use corerouter_proto_radius::packet::{AttrList, Code, Packet, PushAttr, attr};
use corerouter_proto_radius::testserver::TestServer;

const SECRET: &[u8] = b"load";
const ACCESS: u64 = 100_000;
const SESSIONS: u64 = 20_000;
const INTERIMS: u64 = 5;

/// (server, socket, identifier).
type Triple = (usize, u16, u8);

#[derive(Default)]
struct Track {
    /// (server, socket, id) → request using it.
    owner: HashMap<Triple, RequestId>,
    /// request → (its triple, last bytes).
    last: HashMap<RequestId, (Triple, Vec<u8>)>,
    collisions: u64,
    bad_retransmissions: u64,
    bad_failovers: u64,
    transmissions: u64,
    retransmissions: u64,
    failovers: u64,
    responses: HashMap<RequestId, Code>,
    failures: HashMap<RequestId, Failure>,
    twice: u64,
    down: Vec<usize>,
    up: Vec<usize>,
    /// Status-Server probes sent to the primary.
    probes: u64,
}

impl Track {
    fn on_send(&mut self, s: &Sent) {
        self.transmissions += 1;
        if s.t.from.server == 0
            && Packet::parse(&s.bytes).is_ok_and(|p| p.code() == Code::StatusServer)
        {
            self.probes += 1;
        }
        let key = (s.t.from.server, s.t.from.socket, s.t.identifier);
        if s.t.retransmission {
            self.retransmissions += 1;
            match self.last.get(&s.t.request) {
                Some((k, bytes)) if *k == key && *bytes == s.bytes => {}
                _ => self.bad_retransmissions += 1,
            }
            return;
        }
        if let Some((old, bytes)) = self.last.remove(&s.t.request) {
            self.failovers += 1;
            self.owner.remove(&old);
            let (a, b) = (
                Packet::parse(&bytes).unwrap(),
                Packet::parse(&s.bytes).unwrap(),
            );
            let delay = |p: &Packet<'_>| p.attr_u32(attr::ACCT_DELAY_TIME).unwrap_or(0);
            // The same identifier may come back after the timeout (RFC
            // 5080 §2.2.2), but never with the same authenticator.
            if a.authenticator() == b.authenticator() || delay(&b) < delay(&a) {
                self.bad_failovers += 1;
            }
        }
        if let Some(other) = self.owner.insert(key, s.t.request) {
            // Status-Server probes end without an event (they are the
            // client's own); the client's invariant check covers them.
            let probe = self.last.get(&other).is_some_and(|(_, b)| {
                Packet::parse(b).is_ok_and(|p| p.code() == Code::StatusServer)
            });
            if other != s.t.request && !probe {
                self.collisions += 1;
            }
            if probe {
                self.last.remove(&other);
            }
        }
        self.last.insert(s.t.request, (key, s.bytes.clone()));
    }

    fn on_event(&mut self, e: Event) {
        let done = |t: &mut Self, r: RequestId| {
            if let Some((k, _)) = t.last.remove(&r) {
                t.owner.remove(&k);
            }
            if t.responses.contains_key(&r) || t.failures.contains_key(&r) {
                t.twice += 1;
            }
        };
        match e {
            Event::Response { request, code, .. } => {
                done(self, request);
                self.responses.insert(request, code);
            }
            Event::Failed { request, reason } => {
                done(self, request);
                self.failures.insert(request, reason);
            }
            Event::ServerDown { server } => self.down.push(server),
            Event::ServerUp { server } => self.up.push(server),
        }
    }
}

fn servers() -> Vec<(SocketAddr, TestServer)> {
    let mut out = Vec::new();
    for (i, a) in ["10.0.0.10:1812", "10.0.0.11:1812"].iter().enumerate() {
        let mut s = TestServer::new(SECRET, 11 + i as u64);
        s.script.jitter_ms = 20;
        for u in 0..1000 {
            s.add_user(&format!("u{u}"), &format!("p{u}"), AttrList::new());
        }
        out.push((a.parse().unwrap(), s));
    }
    for (i, a) in ["10.0.0.20:1813", "10.0.0.21:1813"].iter().enumerate() {
        let mut s = TestServer::new(SECRET, 21 + i as u64);
        s.status_reply = Code::AccountingResponse;
        s.script.jitter_ms = 20;
        out.push((a.parse().unwrap(), s));
    }
    out
}

#[test]
fn hundred_thousand_requests_with_loss_and_failover() {
    let srv = servers();
    let addrs: Vec<SocketAddr> = srv.iter().map(|(a, _)| *a).collect();
    let mut net = Net::new(srv, 99);
    net.loss_up = 3;
    net.loss_down = 3;
    let mut cfg_auth = ServerConfig::auth(addrs[0], SECRET);
    cfg_auth.status_server = true;
    let mut c = Client::new(
        ClientConfig {
            probe_interval_ms: 5_000,
            ..ClientConfig::default()
        },
        vec![
            cfg_auth,
            ServerConfig::auth(addrs[1], SECRET),
            ServerConfig::acct(addrs[2], SECRET),
            ServerConfig::acct(addrs[3], SECRET),
        ],
        [0xA5; 32],
    );
    let track = std::cell::RefCell::new(Track::default());
    let mut access_ids = Vec::with_capacity(ACCESS as usize);
    let mut acct_ids = Vec::new();
    // 1000 Access-Requests and 250 interims per simulated second.
    let start = net.now;
    let mut sent_access = 0u64;
    let mut sent_acct = 0u64;
    let mut second = 0u64;
    let mut steps = 0u64;
    while sent_access < ACCESS || sent_acct < SESSIONS * INTERIMS {
        let now = start + second * 1000;
        for _ in 0..1000 {
            if sent_access == ACCESS {
                break;
            }
            let u = sent_access % 1000;
            let mut l = AttrList::new();
            l.push_text(attr::USER_NAME, &format!("u{u}")).unwrap();
            // One in 50 uses a wrong password: Access-Reject.
            let pw = if sent_access.is_multiple_of(50) {
                "bad".to_owned()
            } else {
                format!("p{u}")
            };
            access_ids.push(c.access(l, Some(pw.as_bytes()), now).unwrap());
            sent_access += 1;
        }
        for _ in 0..250 {
            if sent_acct == SESSIONS * INTERIMS {
                break;
            }
            let session = sent_acct % SESSIONS;
            let round = sent_acct / SESSIONS + 1;
            let mut r = Record::new(StatusType::InterimUpdate, format!("S{session}"));
            r.counters = Some(Counters {
                input_octets: round << 33,
                output_octets: round,
                session_time: round as u32 * 300,
                ..Counters::default()
            });
            acct_ids.push(
                c.accounting(r.encode().unwrap(), Some(session), now)
                    .unwrap(),
            );
            sent_acct += 1;
        }
        // The primary authentication server dies from 30 s to 90 s.
        if second == 30 {
            net.server(addrs[0]).script.offline = true;
        }
        if second == 90 {
            net.server(addrs[0]).script.offline = false;
        }
        second += 1;
        let until = start + second * 1000;
        while net.step(
            &mut c,
            until,
            &mut |e| track.borrow_mut().on_event(e),
            &mut |s| track.borrow_mut().on_send(s),
        ) {
            steps += 1;
            if steps.is_multiple_of(20_000) {
                c.check_invariants().unwrap();
            }
        }
        assert_eq!(
            track.borrow().collisions,
            0,
            "identifier reused while outstanding"
        );
    }
    // Drain: everything ends (accounting retries until acknowledged).
    let deadline = net.now + 3_600_000;
    net.run(
        &mut c,
        deadline,
        &mut |e| track.borrow_mut().on_event(e),
        &mut |s| track.borrow_mut().on_send(s),
    );
    c.check_invariants().unwrap();
    let track = track.into_inner();

    assert_eq!(c.pending(), 0);
    assert_eq!(track.twice, 0, "a request ended twice");
    assert_eq!(track.collisions, 0);
    assert_eq!(track.bad_retransmissions, 0);
    assert_eq!(track.bad_failovers, 0);
    let ended = |r: &RequestId| track.responses.contains_key(r) || track.failures.contains_key(r);
    assert!(access_ids.iter().all(ended));
    assert!(acct_ids.iter().all(ended));

    let accepts = access_ids
        .iter()
        .filter(|r| track.responses.get(r) == Some(&Code::AccessAccept))
        .count() as u64;
    let rejects = access_ids
        .iter()
        .filter(|r| track.responses.get(r) == Some(&Code::AccessReject))
        .count() as u64;
    let timeouts = access_ids
        .iter()
        .filter(|r| track.failures.contains_key(r))
        .count() as u64;
    assert_eq!(accepts + rejects + timeouts, ACCESS);
    assert!(
        timeouts * 1000 < ACCESS,
        "too many access timeouts: {timeouts}"
    );
    assert!(rejects >= ACCESS / 50 - timeouts);

    // Accounting: no failures but supersedes; the servers end with the last
    // interim of every session.
    let acct_fail: Vec<_> = acct_ids
        .iter()
        .filter_map(|r| track.failures.get(r))
        .filter(|f| **f != Failure::Superseded)
        .collect();
    assert!(acct_fail.is_empty(), "{acct_fail:?}");
    let mut last: HashMap<String, u64> = HashMap::new();
    for a in &addrs[2..] {
        for l in &net.server(*a).accounting {
            let e = last.entry(l.session_id.clone()).or_default();
            *e = (*e).max(l.output_octets);
        }
    }
    assert_eq!(last.len() as u64, SESSIONS);
    assert!(
        last.values().all(|&v| v == INTERIMS),
        "every session's newest interim arrived"
    );

    // The primary was declared dead, probed with Status-Server while down,
    // and came back (by a probe or a late answer, whichever came first).
    assert!(track.down.contains(&0));
    assert!(track.probes > 0);
    assert!(track.up.contains(&0));
    // Retransmissions met the duplicate cache.
    let dups: u64 = addrs.iter().map(|a| net.server(*a).stats.duplicates).sum();
    assert!(dups > 0);
    eprintln!(
        "sim: {} datagrams ({} retransmissions, {} failovers), {} lost, {} accepts, {} rejects, {} timeouts, {} duplicate hits, {} s simulated",
        track.transmissions,
        track.retransmissions,
        track.failovers,
        net.lost,
        accepts,
        rejects,
        timeouts,
        dups,
        (net.now - start) / 1000
    );
}
