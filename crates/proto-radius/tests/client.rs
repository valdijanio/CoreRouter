//! Client against the test server on a virtual network: authentication
//! methods, Blast-RADIUS protection, failover, dead-server detection,
//! Status-Server, accounting retries and superseding, socket growth.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

mod common;

use std::net::SocketAddr;

use common::{Net, Sent};
use corerouter_proto_radius::acct::{Counters, Record, StatusType};
use corerouter_proto_radius::client::{
    Client, ClientConfig, Event, Failure, RequestId, Retry, ServerConfig,
};
use corerouter_proto_radius::crypto;
use corerouter_proto_radius::dict::{mikrotik, vendor};
use corerouter_proto_radius::mschap::{self, VENDOR_MICROSOFT, vsa as ms};
use corerouter_proto_radius::packet::{AttrList, Code, Packet, PushAttr, attr};
use corerouter_proto_radius::rate_limit::RateLimit;
use corerouter_proto_radius::testserver::TestServer;

const SECRET: &[u8] = b"lab-secret";

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn auth_server(a: &str) -> (SocketAddr, TestServer) {
    let mut s = TestServer::new(SECRET, 7);
    let mut reply = AttrList::new();
    reply
        .push_vsa(vendor::MIKROTIK, mikrotik::RATE_LIMIT, b"10M/50M")
        .unwrap();
    reply
        .push_ipv4(attr::FRAMED_IP_ADDRESS, [100, 64, 0, 10].into())
        .unwrap();
    s.add_user("ana", "segredo", reply);
    s.add_user("bia", "outra", AttrList::new());
    (addr(a), s)
}

fn user(name: &str) -> AttrList {
    let mut l = AttrList::new();
    l.push_text(attr::USER_NAME, name).unwrap();
    l.push_text(attr::NAS_IDENTIFIER, "bng1").unwrap();
    l
}

#[derive(Default)]
struct Log {
    events: Vec<Event>,
    sent: Vec<(u64, RequestId, u8, bool, Vec<u8>)>,
}

impl Log {
    /// Run the network for `for_ms` more milliseconds.
    fn run(&mut self, net: &mut Net, c: &mut Client, for_ms: u64) {
        let until = net.now + for_ms;
        let (events, sent) = (&mut self.events, &mut self.sent);
        net.run(c, until, &mut |e| events.push(e), &mut |s: &Sent| {
            sent.push((
                s.at,
                s.t.request,
                s.t.identifier,
                s.t.retransmission,
                s.bytes.clone(),
            ))
        });
    }

    fn response(&self, r: RequestId) -> Option<(Code, Vec<u8>, [u8; 16])> {
        self.events.iter().find_map(|e| match e {
            Event::Response {
                request,
                code,
                packet,
                request_authenticator,
                ..
            } if *request == r => Some((*code, packet.clone(), *request_authenticator)),
            _ => None,
        })
    }

    fn failure(&self, r: RequestId) -> Option<Failure> {
        self.events.iter().find_map(|e| match e {
            Event::Failed { request, reason } if *request == r => Some(*reason),
            _ => None,
        })
    }
}

fn client(servers: Vec<ServerConfig>) -> Client {
    Client::new(ClientConfig::default(), servers, [42; 32])
}

#[test]
fn pap_accept_carries_the_rate_limit_and_reject_is_reported() {
    let (a, s) = auth_server("10.0.0.10:1812");
    let mut net = Net::new(vec![(a, s)], 1);
    let mut c = client(vec![ServerConfig::auth(a, SECRET)]);
    let ok = c.access(user("ana"), Some(b"segredo"), net.now).unwrap();
    let bad = c.access(user("ana"), Some(b"errada"), net.now).unwrap();
    let mut log = Log::default();
    log.run(&mut net, &mut c, 60_000);
    let (code, bytes, _) = log.response(ok).unwrap();
    assert_eq!(code, Code::AccessAccept);
    let p = Packet::parse(&bytes).unwrap();
    let rl: RateLimit = std::str::from_utf8(p.vsa(vendor::MIKROTIK, mikrotik::RATE_LIMIT).unwrap())
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!((rl.rate.rx, rl.rate.tx), (10_000_000, 50_000_000));
    assert_eq!(log.response(bad).unwrap().0, Code::AccessReject);
    let st = c.stats(0).unwrap();
    assert_eq!(
        (st.accepts, st.rejects, st.resends, st.bad_replies),
        (1, 1, 0, 0)
    );
    assert_eq!(c.pending(), 0);
    c.check_invariants().unwrap();
}

#[test]
fn chap_and_mschapv2_through_the_client() {
    let (a, s) = auth_server("10.0.0.10:1812");
    let mut net = Net::new(vec![(a, s)], 1);
    let mut c = client(vec![ServerConfig::auth(a, SECRET)]);
    let mut chap = user("bia");
    let challenge = [0x33u8; 16];
    let mut v = vec![17];
    v.extend_from_slice(&crypto::chap_response(17, b"outra", &challenge));
    chap.push(attr::CHAP_PASSWORD, &v).unwrap();
    chap.push(attr::CHAP_CHALLENGE, &challenge).unwrap();
    let r1 = c.access(chap, None, net.now).unwrap();

    let auth = [0x44u8; 16];
    let peer = [0x55u8; 16];
    let pw = mschap::utf16le("segredo");
    let nt = mschap::generate_nt_response(&auth, &peer, b"ana", &pw);
    let mut m = user("ana");
    m.push_vsa(VENDOR_MICROSOFT, ms::MS_CHAP_CHALLENGE, &auth)
        .unwrap();
    let resp = mschap::Chap2Response {
        ident: 9,
        flags: 0,
        peer_challenge: peer,
        nt_response: nt,
    };
    m.push_vsa(VENDOR_MICROSOFT, ms::MS_CHAP2_RESPONSE, &resp.encode())
        .unwrap();
    let r2 = c.access(m, None, net.now).unwrap();
    let mut log = Log::default();
    log.run(&mut net, &mut c, 60_000);
    assert_eq!(log.response(r1).unwrap().0, Code::AccessAccept);
    let (code, bytes, ra) = log.response(r2).unwrap();
    assert_eq!(code, Code::AccessAccept);
    let p = Packet::parse(&bytes).unwrap();
    // The NAS checks the server's authenticator response before telling
    // the peer it succeeded, and decrypts the MPPE keys.
    let digest = mschap::authenticator_response(&pw, &nt, &peer, &auth, b"ana");
    assert_eq!(
        p.vsa(311, ms::MS_CHAP2_SUCCESS).unwrap()[1..],
        *mschap::authenticator_response_string(&digest).as_bytes()
    );
    let recv =
        crypto::salt_decrypt(p.vsa(311, ms::MS_MPPE_RECV_KEY).unwrap(), SECRET, &ra).unwrap();
    assert_eq!(recv, mschap::mppe_keys(&pw, &nt).recv);
}

/// Blast-RADIUS (CVE-2024-3596): an Access-Accept without
/// Message-Authenticator is discarded by default, so the request fails;
/// with the check off (an old server) it is accepted.
#[test]
fn replies_without_message_authenticator_are_discarded() {
    for require in [true, false] {
        let (a, mut s) = auth_server("10.0.0.10:1812");
        s.script.omit_message_authenticator = true;
        let mut net = Net::new(vec![(a, s)], 1);
        let mut c = Client::new(
            ClientConfig {
                require_message_authenticator: require,
                ..ClientConfig::default()
            },
            vec![ServerConfig::auth(a, SECRET)],
            [1; 32],
        );
        let r = c.access(user("ana"), Some(b"segredo"), net.now).unwrap();
        let mut log = Log::default();
        log.run(&mut net, &mut c, 120_000);
        if require {
            assert_eq!(log.failure(r), Some(Failure::Timeout));
            assert_eq!(c.stats(0).unwrap().bad_replies, 3);
        } else {
            assert_eq!(log.response(r).unwrap().0, Code::AccessAccept);
        }
    }
}

#[test]
fn wrong_secret_replies_count_as_bad_replies() {
    let (a, mut s) = auth_server("10.0.0.10:1812");
    s.script.reply_secret = Some(b"other".to_vec());
    let mut net = Net::new(vec![(a, s)], 1);
    let mut c = client(vec![ServerConfig::auth(a, SECRET)]);
    let r = c.access(user("ana"), Some(b"segredo"), net.now).unwrap();
    let mut log = Log::default();
    log.run(&mut net, &mut c, 120_000);
    assert_eq!(log.failure(r), Some(Failure::Timeout));
    assert_eq!(c.stats(0).unwrap().bad_replies, 3);
}

/// RFC 5080 §2.2.1: retransmissions to the same server are identical,
/// spaced by a doubling RT with ±10 % jitter; then failover with a new
/// identifier and authenticator.
#[test]
fn retransmission_backoff_then_failover() {
    let (a, mut sa) = auth_server("10.0.0.10:1812");
    sa.script.offline = true;
    let (b, sb) = auth_server("10.0.0.11:1812");
    let mut net = Net::new(vec![(a, sa), (b, sb)], 1);
    let mut c = client(vec![
        ServerConfig::auth(a, SECRET),
        ServerConfig::auth(b, SECRET),
    ]);
    let r = c.access(user("ana"), Some(b"segredo"), net.now).unwrap();
    let mut log = Log::default();
    log.run(&mut net, &mut c, 120_000);
    assert_eq!(log.response(r).unwrap().0, Code::AccessAccept);
    let sent: Vec<_> = log.sent.iter().filter(|s| s.1 == r).collect();
    assert_eq!(sent.len(), 4, "3 to the first server, 1 to the second");
    assert_eq!(sent[1].4, sent[0].4);
    assert_eq!(sent[2].4, sent[0].4);
    assert!(sent[1].3 && sent[2].3 && !sent[3].3);
    let (g1, g2) = (sent[1].0 - sent[0].0, sent[2].0 - sent[1].0);
    assert!((990..=1210).contains(&g1), "RT1 = IRT ± 10 %: {g1}");
    assert!(
        g2 >= 2 * g1 - g1 / 10 - 1 && g2 <= 2 * g1 + g1 / 10 + 1,
        "RT2 ≈ 2·RT1: {g1} {g2}"
    );
    let (p0, p3) = (
        Packet::parse(&sent[0].4).unwrap(),
        Packet::parse(&sent[3].4).unwrap(),
    );
    assert_ne!(p0.authenticator(), p3.authenticator());
    // The password is hidden again with the new authenticator.
    assert_eq!(
        crypto::unhide_user_password(
            p3.attr(attr::USER_PASSWORD).unwrap(),
            SECRET,
            &p3.authenticator()
        )
        .unwrap(),
        b"segredo"
    );
    assert_eq!(c.stats(0).unwrap().timeouts, 1);
}

/// After `dead_after` failed exchanges the primary is skipped; Status-Server
/// probes bring it back when it answers again (RFC 5997).
#[test]
fn dead_server_is_skipped_and_status_server_revives_it() {
    let (a, mut sa) = auth_server("10.0.0.10:1812");
    sa.script.offline = true;
    let (b, sb) = auth_server("10.0.0.11:1812");
    let mut net = Net::new(vec![(a, sa), (b, sb)], 1);
    let mut cfg_a = ServerConfig::auth(a, SECRET);
    cfg_a.status_server = true;
    let mut c = Client::new(
        ClientConfig {
            dead_after: 2,
            probe_interval_ms: 5_000,
            ..ClientConfig::default()
        },
        vec![cfg_a, ServerConfig::auth(b, SECRET)],
        [3; 32],
    );
    let mut log = Log::default();
    for _ in 0..3 {
        c.access(user("ana"), Some(b"segredo"), net.now).unwrap();
        log.run(&mut net, &mut c, 20_000);
    }
    assert!(!c.is_alive(0));
    assert!(log.events.contains(&Event::ServerDown { server: 0 }));
    // The first two failed over; the third went straight to the secondary.
    assert_eq!(c.stats(0).unwrap().requests, 2);
    assert_eq!(c.stats(1).unwrap().requests, 3);
    net.server(a).script.offline = false;
    log.run(&mut net, &mut c, 20_000);
    assert!(c.is_alive(0));
    assert!(log.events.contains(&Event::ServerUp { server: 0 }));
    assert!(net.server(a).stats.status >= 1);
    c.check_invariants().unwrap();
}

/// Without Status-Server a dead server comes back after `dead_time_ms`.
#[test]
fn dead_time_without_status_server() {
    let (a, mut sa) = auth_server("10.0.0.10:1812");
    sa.script.offline = true;
    let (b, sb) = auth_server("10.0.0.11:1812");
    let mut net = Net::new(vec![(a, sa), (b, sb)], 1);
    let mut c = Client::new(
        ClientConfig {
            dead_after: 1,
            dead_time_ms: 10_000,
            ..ClientConfig::default()
        },
        vec![ServerConfig::auth(a, SECRET), ServerConfig::auth(b, SECRET)],
        [3; 32],
    );
    let mut log = Log::default();
    c.access(user("ana"), Some(b"segredo"), net.now).unwrap();
    // 1.1 + 2.2 + 4.4 s of retransmissions (RFC 5080 §2.2.1), then dead.
    log.run(&mut net, &mut c, 9_000);
    assert!(!c.is_alive(0));
    log.run(&mut net, &mut c, 30_000);
    assert!(c.is_alive(0));
}

/// Accounting: Acct-Delay-Time grows per server attempt (RFC 2866 §5.2),
/// a new interim supersedes a pending one, and with every server down the
/// request goes round again until acknowledged.
#[test]
fn accounting_delay_time_supersede_and_rounds() {
    let mut sa = TestServer::new(SECRET, 1);
    sa.status_reply = Code::AccountingResponse;
    sa.script.offline = true;
    let a = addr("10.0.0.20:1813");
    let mut net = Net::new(vec![(a, sa)], 1);
    let mut c = client(vec![ServerConfig::acct(a, SECRET)]);
    let rec = |n: u64| {
        let mut r = Record::new(StatusType::InterimUpdate, "S-1");
        r.counters = Some(Counters {
            input_octets: n,
            ..Counters::default()
        });
        r.encode().unwrap()
    };
    let first = c.accounting(rec(1), Some(1), net.now).unwrap();
    let mut log = Log::default();
    log.run(&mut net, &mut c, 100_000);
    let second = c.accounting(rec(2), Some(1), net.now).unwrap();
    assert_eq!(c.pending(), 1);
    drop_events(&mut c, &mut log);
    assert_eq!(log.failure(first), Some(Failure::Superseded));
    // Two rounds with one server: more than 5 transmissions, the delay
    // grows from round to round.
    log.run(&mut net, &mut c, 200_000);
    let delays: Vec<u32> = log
        .sent
        .iter()
        .filter(|s| s.1 == second && !s.3)
        .map(|s| {
            Packet::parse(&s.4)
                .unwrap()
                .attr_u32(attr::ACCT_DELAY_TIME)
                .unwrap()
        })
        .collect();
    assert!(delays.len() >= 3, "{delays:?}");
    assert!(delays.windows(2).all(|w| w[1] > w[0]), "{delays:?}");
    // The server comes back: acknowledged, logged once with the newest
    // counters.
    net.server(a).script.offline = false;
    log.run(&mut net, &mut c, 200_000);
    assert_eq!(log.response(second).unwrap().0, Code::AccountingResponse);
    let logged = &net.server(a).accounting;
    assert_eq!(logged.len(), 1);
    assert_eq!(logged[0].input_octets, 2);
    assert!(logged[0].delay_time > 100);
}

fn drop_events(c: &mut Client, log: &mut Log) {
    while let Some(e) = c.poll_event() {
        log.events.push(e);
    }
}

/// Accounting with an age limit gives up.
#[test]
fn accounting_age_limit() {
    let mut sa = TestServer::new(SECRET, 1);
    sa.script.offline = true;
    let a = addr("10.0.0.20:1813");
    let mut net = Net::new(vec![(a, sa)], 1);
    let mut c = Client::new(
        ClientConfig {
            accounting_max_age_ms: 60_000,
            ..ClientConfig::default()
        },
        vec![ServerConfig::acct(a, SECRET)],
        [5; 32],
    );
    let r = c
        .accounting(
            Record::new(StatusType::AccountingOn, "").encode().unwrap(),
            None,
            net.now,
        )
        .unwrap();
    let mut log = Log::default();
    log.run(&mut net, &mut c, 300_000);
    assert_eq!(log.failure(r), Some(Failure::Timeout));
}

/// More than 256 requests in flight to one server open more sockets; past
/// `max_sockets` requests queue and go out as identifiers free up.
#[test]
fn identifiers_grow_sockets_then_queue() {
    let (a, mut s) = auth_server("10.0.0.10:1812");
    s.script.delay_ms = 50;
    let mut net = Net::new(vec![(a, s)], 1);
    let mut c = Client::new(
        ClientConfig {
            max_sockets: 2,
            ..ClientConfig::default()
        },
        vec![ServerConfig::auth(a, SECRET)],
        [9; 32],
    );
    let ids: Vec<_> = (0..1000)
        .map(|_| c.access(user("ana"), Some(b"segredo"), net.now).unwrap())
        .collect();
    assert_eq!(c.stats(0).unwrap().sockets, 2);
    assert_eq!(c.stats(0).unwrap().in_flight, 512);
    c.check_invariants().unwrap();
    let mut log = Log::default();
    log.run(&mut net, &mut c, 60_000);
    assert!(
        ids.iter()
            .all(|r| log.response(*r).is_some_and(|x| x.0 == Code::AccessAccept))
    );
    assert_eq!(c.pending(), 0);
    c.check_invariants().unwrap();
}

#[test]
fn back_pressure_and_cancel() {
    let (a, _) = auth_server("10.0.0.10:1812");
    let mut c = Client::new(
        ClientConfig {
            max_pending: 2,
            ..ClientConfig::default()
        },
        vec![ServerConfig::auth(a, SECRET)],
        [9; 32],
    );
    let r = c.access(user("ana"), None, 0).unwrap();
    c.access(user("ana"), None, 0).unwrap();
    assert!(c.access(user("ana"), None, 0).is_err());
    c.cancel(r);
    assert_eq!(
        c.poll_event(),
        Some(Event::Failed {
            request: r,
            reason: Failure::Cancelled
        })
    );
    assert!(c.access(user("ana"), None, 0).is_ok());
    assert!(
        c.accounting(AttrList::new(), None, 0).is_err(),
        "no accounting server"
    );
    assert!(c.access(user("ana"), Some(&[b'x'; 129]), 0).is_err());
    c.check_invariants().unwrap();
}

#[test]
fn unsolicited_and_spoofed_replies_are_ignored() {
    let (a, _) = auth_server("10.0.0.10:1812");
    let mut c = client(vec![ServerConfig::auth(a, SECRET)]);
    let r = c.access(user("ana"), Some(b"segredo"), 0).unwrap();
    let mut buf = Vec::new();
    let t = c.poll_transmit(&mut buf).unwrap();
    assert_eq!(t.request, r);
    // From another address.
    let spoof = addr("10.0.0.99:1812");
    assert!(c.handle_input(t.from, spoof, &buf, 1).is_err());
    // Right address, unknown identifier.
    let mut b =
        corerouter_proto_radius::Builder::new(Code::AccessAccept, t.identifier.wrapping_add(1));
    b.message_authenticator().unwrap();
    let bytes = crypto::sign_response(b, &[0; 16], SECRET);
    assert!(c.handle_input(t.from, a, &bytes, 1).is_err());
    // Garbage.
    assert!(c.handle_input(t.from, a, &[0xff; 3], 1).is_err());
    assert_eq!(c.pending(), 1);
    let st = c.stats(0).unwrap();
    assert_eq!((st.unsolicited, st.bad_replies), (2, 1));
    // A late duplicate after the answer is unsolicited too (RFC 5080
    // §2.2.2: "Any later responses MUST be silently discarded").
    let req = Packet::parse(&buf).unwrap();
    let mut b = corerouter_proto_radius::Builder::new(Code::AccessReject, t.identifier);
    b.message_authenticator().unwrap();
    let reject = crypto::sign_response(b, &req.authenticator(), SECRET);
    assert!(c.handle_input(t.from, a, &reject, 2).is_ok());
    assert!(c.handle_input(t.from, a, &reject, 3).is_err());
    let _ = Retry::ACCESS;
}

/// G4.3g: a server slowing down as a queue grows, from 0.8 s to 1.6 s
/// (past the 1.1 s IRT). The adaptive first timeout (SRTT + 4·RTTVAR, RFC
/// 6298, from answers to single transmissions) keeps ahead of it: no copies
/// of what the server is still working on.
#[test]
fn slowing_server_gets_an_adaptive_first_timeout() {
    let (a, sa) = auth_server("10.0.0.10:1812");
    let mut net = Net::new(vec![(a, sa)], 1);
    let mut c = client(vec![ServerConfig::auth(a, SECRET)]);
    let mut log = Log::default();
    for delay in (800..=1600).step_by(50) {
        net.server(a).script.delay_ms = delay;
        for _ in 0..8 {
            let r = c.access(user("ana"), Some(b"segredo"), net.now).unwrap();
            log.run(&mut net, &mut c, 10_000);
            assert_eq!(log.response(r).unwrap().0, Code::AccessAccept);
        }
    }
    let st = c.stats(0).unwrap();
    assert_eq!(st.resends, 0, "the timeout kept ahead of the server");
    assert!(
        (1600..=4400).contains(&st.rto_ms),
        "SRTT + 4·RTTVAR within MRT: {}",
        st.rto_ms
    );
}

/// G4.3g: the timer of an answered request must not fire on the next
/// request that takes its slot. Logins one after another, each answered in
/// 100 ms, far inside the 1.1 s timeout: not one is sent twice.
#[test]
fn an_answered_request_leaves_no_timer_behind() {
    let (a, sa) = auth_server("10.0.0.10:1812");
    let mut net = Net::new(vec![(a, sa)], 1);
    net.server(a).script.delay_ms = 100;
    let mut c = client(vec![ServerConfig::auth(a, SECRET)]);
    let mut log = Log::default();
    for _ in 0..40 {
        let r = c.access(user("ana"), Some(b"segredo"), net.now).unwrap();
        log.run(&mut net, &mut c, 150);
        assert_eq!(log.response(r).unwrap().0, Code::AccessAccept);
    }
    assert_eq!(c.stats(0).unwrap().resends, 0, "a copy before its timeout");
}
