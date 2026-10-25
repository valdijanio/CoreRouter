//! Tests of the RADIUS AAA driver (`radius_aaa.rs`) against the pure-Rust
//! test server of `proto-radius` on real UDP sockets in 127.0.0.1 (no
//! root): failover, retransmission and timeout, 10 000 authentications at
//! once, accounting, interim jitter, CoA/Disconnect.
#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::radius::{AaaBackend, AcctSource, SessionOwner};
use corerouter_model::ItemId;
use corerouter_model::radius::{
    AaaService, AcctCounters, AcctRequest, AcctStatus, AuthOutcome, AuthReply, AuthRequest,
    CoaKind, CoaOutcome, CoaRequest, RadiusIncoming, RadiusServer, ServerState,
};
use corerouter_proto_radius::dynauth::{self, RequestKind};
use corerouter_proto_radius::packet::{AttrList, Code, Packet, PushAttr, attr};
use corerouter_proto_radius::testserver::TestServer;

use super::radius_aaa::{self, AaaConfig, Aaa, Interims};

/// A server socket with room for a burst (net.core.rmem_max caps it).
fn big_socket() -> UdpSocket {
    let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
    let _ = s.set_recv_buffer_size(4 << 20);
    s.bind(&"127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap().into()).unwrap();
    s.into()
}

const SECRET: &str = "segredo-radius";

/// A test RADIUS server on two UDP ports (authentication, accounting),
/// with its script changeable while it runs.
struct TestRadius {
    auth: SocketAddr,
    acct: SocketAddr,
    srv: Arc<Mutex<TestServer>>,
    stop: Arc<AtomicBool>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl TestRadius {
    fn start(seed: u64) -> Self {
        let mut s = TestServer::new(SECRET.as_bytes(), seed);
        let mut reply = AttrList::new();
        reply.push_vsa(14988, 8, b"10M/20M").unwrap();
        reply.push_ipv4(attr::FRAMED_IP_ADDRESS, "100.64.0.10".parse().unwrap()).unwrap();
        s.add_user("ana", "segredo", reply);
        for i in 0..10 {
            s.add_user(&format!("u{i}"), "pw", AttrList::new());
        }
        let srv = Arc::new(Mutex::new(s));
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        let mut addrs = Vec::new();
        for _ in 0..2 {
            let sock = big_socket();
            sock.set_read_timeout(Some(Duration::from_millis(2))).unwrap();
            addrs.push(sock.local_addr().unwrap());
            let (srv, stop) = (srv.clone(), stop.clone());
            threads.push(thread::spawn(move || {
                let t0 = Instant::now();
                let mut later: VecDeque<(u64, SocketAddr, Vec<u8>)> = VecDeque::new();
                let mut buf = [0u8; 4096];
                while !stop.load(Ordering::Relaxed) {
                    let now = t0.elapsed().as_millis() as u64;
                    while later.front().is_some_and(|(t, _, _)| *t <= now) {
                        let (_, to, b) = later.pop_front().unwrap();
                        let _ = sock.send_to(&b, to);
                    }
                    let Ok((n, from)) = sock.recv_from(&mut buf) else {
                        continue;
                    };
                    let r = srv.lock().unwrap().handle(from, &buf[..n], now);
                    if let Some(r) = r {
                        if r.at_ms <= now {
                            let _ = sock.send_to(&r.bytes, r.to);
                        } else {
                            later.push_back((r.at_ms, r.to, r.bytes));
                        }
                    }
                }
            }));
        }
        Self {
            auth: addrs[0],
            acct: addrs[1],
            srv,
            stop,
            threads,
        }
    }

    fn entry(&self, id: u32) -> RadiusServer {
        let mut e = RadiusServer::new(ItemId(id), self.auth.ip());
        e.authentication_port = self.auth.port();
        e.accounting_port = self.acct.port();
        e.secret = SECRET.into();
        e.service = vec![AaaService::Ppp];
        e
    }
}

impl Drop for TestRadius {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

struct Running {
    aaa: Aaa,
    h: Option<thread::JoinHandle<()>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.aaa.stop();
        if let Some(h) = self.h.take() {
            let _ = h.join();
        }
    }
}

fn start(servers: Vec<RadiusServer>) -> Running {
    start_with(AaaConfig {
        servers,
        nas_identifier: "cr-test".into(),
        ..AaaConfig::default()
    })
}

fn start_with(cfg: AaaConfig) -> Running {
    let (aaa, h) = radius_aaa::spawn(cfg).unwrap();
    Running { aaa, h: Some(h) }
}

fn auth(aaa: &Aaa, user: &str, pw: &str) -> AuthReply {
    let (tx, rx) = mpsc::channel();
    aaa.authenticate(
        AuthRequest::pap(AaaService::Ppp, user, pw),
        Box::new(move |r| {
            let _ = tx.send(r);
        }),
    );
    rx.recv_timeout(Duration::from_secs(30)).expect("no answer")
}

/// The monitor after the driver published (every 100 ms).
fn monitor(aaa: &Aaa) -> corerouter_model::radius::RadiusStatus {
    thread::sleep(Duration::from_millis(300));
    aaa.status()
}

#[test]
fn accept_reject_and_reply_attributes() {
    let srv = TestRadius::start(1);
    let r = start(vec![srv.entry(1)]);
    let ok = auth(&r.aaa, "ana", "segredo");
    assert_eq!(ok.outcome, AuthOutcome::Accept, "{ok:?}");
    assert_eq!(ok.server, Some(ItemId(1)));
    assert_eq!(ok.attr("Mikrotik-Rate-Limit"), Some("10M/20M"), "{:?}", ok.attributes);
    assert_eq!(ok.attr("Framed-IP-Address"), Some("100.64.0.10"));
    assert!(ok.rtt_ms.is_some());
    assert!(!ok.packet.is_empty());
    let no = auth(&r.aaa, "ana", "errada");
    assert_eq!(no.outcome, AuthOutcome::Reject);
    // A service without servers: an error at once, nothing sent.
    let (tx, rx) = mpsc::channel();
    r.aaa.authenticate(
        AuthRequest::pap(AaaService::Login, "ana", "segredo"),
        Box::new(move |x| tx.send(x).unwrap()),
    );
    let e = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(e.outcome, AuthOutcome::Error);
    let m = monitor(&r.aaa);
    assert_eq!(m.servers[0].state, ServerState::Up);
    assert_eq!((m.servers[0].accepts, m.servers[0].rejects), (1, 1));
    let logs = r.aaa.take_logs();
    assert!(logs.iter().any(|l| l.message.contains("recusado")), "{logs:?}");
}

#[test]
fn retransmits_and_times_out() {
    let srv = TestRadius::start(2);
    let mut e = srv.entry(1);
    e.timeout = 100;
    let r = start(vec![e]);
    // The first transmission is lost: the retransmission is answered.
    srv.srv.lock().unwrap().script.drop_next = 1;
    assert_eq!(auth(&r.aaa, "ana", "segredo").outcome, AuthOutcome::Accept);
    assert_eq!(monitor(&r.aaa).servers[0].resends, 1);
    // A dead server: every transmission (100 + 200 + 400 ms), then Timeout.
    srv.srv.lock().unwrap().script.offline = true;
    let t = Instant::now();
    let x = auth(&r.aaa, "ana", "segredo");
    assert_eq!(x.outcome, AuthOutcome::Timeout, "{x:?}");
    assert!(t.elapsed() >= Duration::from_millis(600), "{:?}", t.elapsed());
    let m = monitor(&r.aaa);
    assert_eq!(m.servers[0].timeouts, 1);
    assert_eq!(m.servers[0].resends, 3);
}

#[test]
fn fails_over_when_the_primary_drops() {
    let a = TestRadius::start(3);
    let b = TestRadius::start(4);
    let mut ea = a.entry(1);
    ea.timeout = 100;
    ea.status_server = true;
    let mut eb = b.entry(2);
    eb.timeout = 100;
    let r = start(vec![ea, eb]);
    assert_eq!(auth(&r.aaa, "ana", "segredo").server, Some(ItemId(1)));
    a.srv.lock().unwrap().script.offline = true;
    // Three at once fail on A together: A is marked down, B answers all.
    let (tx, rx) = mpsc::channel();
    for _ in 0..5 {
        let tx = tx.clone();
        r.aaa.authenticate(
            AuthRequest::pap(AaaService::Ppp, "ana", "segredo"),
            Box::new(move |x| tx.send(x).unwrap()),
        );
    }
    for _ in 0..5 {
        let x = rx.recv_timeout(Duration::from_secs(20)).unwrap();
        assert_eq!((x.outcome, x.server), (AuthOutcome::Accept, Some(ItemId(2))), "{x:?}");
    }
    let m = monitor(&r.aaa);
    assert_eq!(m.servers[0].state, ServerState::Probing, "{m:?}");
    assert_eq!(m.servers[1].state, ServerState::Up);
    assert!(m.servers[0].timeouts >= 3);
    // Down: the next request goes straight to B, without waiting on A.
    let t = Instant::now();
    assert_eq!(auth(&r.aaa, "ana", "segredo").server, Some(ItemId(2)));
    assert!(t.elapsed() < Duration::from_millis(500), "{:?}", t.elapsed());
    let logs = r.aaa.take_logs();
    assert!(logs.iter().any(|l| l.message.contains("fora do ar")), "{logs:?}");
}

#[test]
fn ten_thousand_at_once_without_identifier_collisions() {
    const N: usize = 10_000;
    let srv = TestRadius::start(5);
    let mut e = srv.entry(1);
    // Room for the debug build to answer without retransmissions.
    e.timeout = 5000;
    let r = start(vec![e]);
    let (tx, rx) = mpsc::channel();
    let t = Instant::now();
    for i in 0..N {
        let tx = tx.clone();
        r.aaa.authenticate(
            AuthRequest::pap(AaaService::Ppp, format!("u{}", i % 10), "pw"),
            Box::new(move |x| tx.send(x.outcome).unwrap()),
        );
    }
    let mut accepts = 0;
    for _ in 0..N {
        match rx.recv_timeout(Duration::from_secs(60)).unwrap() {
            AuthOutcome::Accept => accepts += 1,
            o => panic!("{o:?}"),
        }
    }
    let secs = t.elapsed().as_secs_f64();
    eprintln!("{N} authentications in {secs:.2} s ({:.0}/s, debug build)", N as f64 / secs);
    assert_eq!(accepts, N);
    let m = monitor(&r.aaa);
    let s = &m.servers[0];
    // 256 identifiers per socket: more sockets under load.
    assert!(s.sockets > 1, "{s:?}");
    assert_eq!((s.bad_replies, s.unsolicited, s.pending), (0, 0, 0), "{s:?}");
    // An identifier reused while its request is pending would bring a reply
    // signed over another authenticator: a bad reply, then a timeout. The
    // burst overflows the server's socket buffer, so some requests are
    // retransmitted (the same bytes, RFC 5080 §2.2.1), never renumbered.
    let stats = srv.srv.lock().unwrap().stats;
    eprintln!("resends {}, server {stats:?}", s.resends);
    assert!(stats.accepts as usize >= N, "{stats:?}");
}

struct Counting(AtomicU32);

impl AcctSource for Counting {
    fn counters(&self) -> Option<AcctCounters> {
        let n = self.0.fetch_add(1, Ordering::Relaxed);
        Some(AcctCounters {
            input_octets: 5_000_000_000 + u64::from(n),
            output_octets: 7,
            ..AcctCounters::default()
        })
    }
}

fn acct(status: AcctStatus, session: &str) -> AcctRequest {
    AcctRequest {
        service: AaaService::Ppp,
        status,
        session_id: session.into(),
        user: "ana".into(),
        counters: (status != AcctStatus::Start).then(|| AcctCounters {
            input_octets: 5_000_000_000,
            output_octets: 1,
            ..AcctCounters::default()
        }),
        terminate_cause: (status == AcctStatus::Stop).then_some(1),
        interim_secs: None,
        attributes: Vec::new(),
    }
}

#[test]
fn accounting_reaches_the_server_and_can_be_off() {
    let srv = TestRadius::start(6);
    let r = start(vec![srv.entry(1)]);
    r.aaa.account(acct(AcctStatus::Start, "S-1"), None).unwrap();
    r.aaa.account(acct(AcctStatus::Stop, "S-1"), None).unwrap();
    let t = Instant::now();
    while srv.srv.lock().unwrap().accounting.len() < 2 {
        assert!(t.elapsed() < Duration::from_secs(10), "accounting not received");
        thread::sleep(Duration::from_millis(10));
    }
    let log = srv.srv.lock().unwrap().accounting.clone();
    assert_eq!((log[0].status, log[1].status), (1, 2));
    assert_eq!(log[1].session_id, "S-1");
    // 64-bit counters through Gigawords (RFC 2869 §5.1).
    assert_eq!(log[1].input_octets, 5_000_000_000);
    assert_eq!(monitor(&r.aaa).servers[0].acct_responses, 2);
    // /ppp aaa accounting=no: PPP accounting is not sent.
    let mut cfg = AaaConfig {
        servers: vec![srv.entry(1)],
        ..AaaConfig::default()
    };
    cfg.ppp.accounting = false;
    r.aaa.reload(cfg);
    thread::sleep(Duration::from_millis(100));
    r.aaa.account(acct(AcctStatus::Start, "S-2"), None).unwrap();
    thread::sleep(Duration::from_millis(500));
    assert_eq!(srv.srv.lock().unwrap().accounting.len(), 2);
}

#[test]
fn interims_are_spread_over_the_jitter_window() {
    // 10 000 sessions start in the same millisecond (an OLT came back).
    const N: u64 = 10_000;
    let mut iv = Interims::default();
    let src: Arc<dyn AcctSource> = Arc::new(Counting(AtomicU32::new(0)));
    let mut first = Vec::new();
    for i in 0..N {
        let due = iv
            .add(acct(AcctStatus::Start, &format!("PPP-{i}")), src.clone(), 300, 20, 0)
            .unwrap();
        first.push(due);
    }
    // Never later than the interval; at most 20 % earlier.
    assert!(first.iter().all(|t| (240_000..=300_000).contains(t)));
    // Flat: ten 6-second buckets, each within ±15 % of N/10.
    let mut buckets = [0u64; 10];
    for t in &first {
        buckets[(((t - 240_000) / 6000) as usize).min(9)] += 1;
    }
    for b in buckets {
        assert!((850..=1150).contains(&b), "{buckets:?}");
    }
    assert!(iv.due(239_999).is_empty());
    let sent = iv.due(300_000);
    assert_eq!(sent.len() as u64, N);
    assert!(sent.iter().all(|r| r.status == AcctStatus::InterimUpdate && r.counters.is_some()));
    // The second round keeps each session's offset: one interval later.
    let next = iv.next_due().unwrap();
    assert!((540_000..=600_000).contains(&next), "{next}");
    // A Stop ends the schedule.
    for i in 0..N {
        iv.remove(&format!("PPP-{i}"));
    }
    assert_eq!(iv.len(), 0);
    assert!(iv.due(u64::MAX).is_empty());
}

#[derive(Default)]
struct Owner {
    calls: Mutex<Vec<CoaRequest>>,
}

impl SessionOwner for Owner {
    fn name(&self) -> &str {
        "ppp"
    }
    fn handle(&self, req: &CoaRequest) -> CoaOutcome {
        self.calls.lock().unwrap().push(req.clone());
        if req.selector.acct_session_id.as_deref() == Some("PPP-1") {
            CoaOutcome::Ack
        } else {
            CoaOutcome::NotMine
        }
    }
}

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn incoming(port: u16) -> AaaConfig {
    let mut e = RadiusServer::new(ItemId(1), "127.0.0.1".parse().unwrap());
    e.secret = SECRET.into();
    e.service = vec![AaaService::Ppp];
    e.authentication_port = 1;
    e.accounting_port = 2;
    AaaConfig {
        servers: vec![e],
        incoming: RadiusIncoming {
            accept: true,
            port,
            ..RadiusIncoming::default()
        },
        ..AaaConfig::default()
    }
}

/// Send `req` from `from` to the NAS; the reply, if any, within 500 ms.
fn send(from: &UdpSocket, port: u16, req: &[u8]) -> Option<Vec<u8>> {
    from.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    from.send_to(req, ("127.0.0.1", port)).unwrap();
    let mut buf = [0u8; 4096];
    from.recv_from(&mut buf).ok().map(|(n, _)| buf[..n].to_vec())
}

fn coa(kind: RequestKind, id: u8, session: &str, ts: u32) -> Vec<u8> {
    let mut l = AttrList::new();
    l.push_text(attr::ACCT_SESSION_ID, session).unwrap();
    l.push_u32(attr::EVENT_TIMESTAMP, ts).unwrap();
    if kind == RequestKind::Coa {
        l.push_vsa(14988, 8, b"30M/60M").unwrap();
    }
    dynauth::build_request(kind, id, &l, SECRET.as_bytes(), true)
}

fn unix_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

fn wait_listening(aaa: &Aaa) {
    let t = Instant::now();
    while aaa.status().incoming.listening.is_none() {
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", aaa.status().incoming);
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn coa_accepted_replayed_unknown_and_not_found() {
    let port = free_port();
    let r = start_with(incoming(port));
    let owner = Arc::new(Owner::default());
    r.aaa.register_owner(owner.clone());
    wait_listening(&r.aaa);
    let dac = UdpSocket::bind("127.0.0.1:0").unwrap();
    // Accepted: CoA-ACK, the owner got the change decoded.
    let req = coa(RequestKind::Coa, 1, "PPP-1", unix_now());
    let ack = send(&dac, port, &req).expect("no CoA-ACK");
    assert_eq!(Packet::parse(&ack).unwrap().code(), Code::CoaAck);
    {
        let calls = owner.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].kind, CoaKind::Coa);
        assert_eq!(calls[0].changes[0].name, "Mikrotik-Rate-Limit");
        assert_eq!(calls[0].changes[0].value, "30M/60M");
    }
    // The same request again (a retransmission): the same answer, from the
    // cache, without applying it twice (RFC 5176 §2.3).
    assert_eq!(send(&dac, port, &req).as_deref(), Some(ack.as_slice()));
    assert_eq!(owner.calls.lock().unwrap().len(), 1);
    // Replayed later with an old Event-Timestamp: dropped (§6.3 window).
    let old = coa(RequestKind::Coa, 2, "PPP-1", unix_now() - 3600);
    assert_eq!(send(&dac, port, &old), None);
    // From an address that is no /radius entry: dropped, no reply.
    let stranger = UdpSocket::bind("127.0.0.2:0").unwrap();
    assert_eq!(send(&stranger, port, &coa(RequestKind::Coa, 3, "PPP-1", unix_now())), None);
    assert_eq!(owner.calls.lock().unwrap().len(), 1);
    // A session nobody owns: NAK 503.
    let nak = send(&dac, port, &coa(RequestKind::Disconnect, 4, "PPP-9", unix_now())).unwrap();
    let p = Packet::parse(&nak).unwrap();
    assert_eq!(p.code(), Code::DisconnectNak);
    assert_eq!(p.attr_u32(attr::ERROR_CAUSE), Some(503));
    let m = monitor(&r.aaa).incoming;
    assert_eq!((m.requests, m.acks, m.naks, m.owners), (2, 1, 1, 1), "{m:?}");
    assert!(m.dropped >= 2 && m.duplicates >= 1, "{m:?}");
}

#[test]
fn without_an_owner_every_request_is_nak_503() {
    let port = free_port();
    let r = start_with(incoming(port));
    wait_listening(&r.aaa);
    let dac = UdpSocket::bind("127.0.0.1:0").unwrap();
    let nak = send(&dac, port, &coa(RequestKind::Coa, 9, "PPP-1", unix_now())).unwrap();
    let p = Packet::parse(&nak).unwrap();
    assert_eq!(p.code(), Code::CoaNak);
    assert_eq!(p.attr_u32(attr::ERROR_CAUSE), Some(503));
    // accept=no closes the port.
    let mut cfg = incoming(port);
    cfg.incoming.accept = false;
    r.aaa.reload(cfg);
    let t = Instant::now();
    while r.aaa.status().incoming.listening.is_some() {
        assert!(t.elapsed() < Duration::from_secs(5));
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_reload_keeps_pending_requests() {
    let srv = TestRadius::start(7);
    let r = start(vec![srv.entry(1)]);
    srv.srv.lock().unwrap().script.delay_ms = 300;
    let (tx, rx) = mpsc::channel();
    r.aaa.authenticate(
        AuthRequest::pap(AaaService::Ppp, "ana", "segredo"),
        Box::new(move |x| tx.send(x).unwrap()),
    );
    thread::sleep(Duration::from_millis(50));
    // A new timeout builds a new lane; the old one finishes its request.
    let mut e = srv.entry(1);
    e.timeout = 2000;
    r.aaa.reload(AaaConfig {
        servers: vec![e],
        ..AaaConfig::default()
    });
    let x = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(x.outcome, AuthOutcome::Accept, "{x:?}");
    // The counters of the old lane are kept.
    thread::sleep(Duration::from_millis(200));
    assert_eq!(monitor(&r.aaa).servers[0].accepts, 1);
    let _: IpAddr = srv.auth.ip();
}

/// G4.3e: the IPv6 accounting attributes of the BNG go out as RFC 3162
/// §2.2/§2.3 say and read back as the same text.
#[test]
fn rfc3162_prefix_and_interface_id_round_trip() {
    let dict = corerouter_proto_radius::dict::Dictionary::builtin();
    let mut l = AttrList::new();
    for (name, value) in [
        ("Delegated-IPv6-Prefix", "2001:db8:8800::/56"),
        ("Framed-IPv6-Prefix", "2001:db8:0:5::/64"),
        ("Framed-Interface-Id", "0x0211223344556677"),
    ] {
        radius_aaa::encode_attr(&dict, &mut l, &corerouter_model::radius::Attribute::new(name, value)).unwrap();
    }
    // /56 → 7 significant octets after reserved and length.
    let first = l.iter().next().unwrap();
    assert_eq!(first.value.len(), 2 + 7);
    assert_eq!(&first.value[..2], &[0, 56]);
    let back = radius_aaa::decode_list(&dict, &l);
    let text: Vec<(String, String)> = back.into_iter().map(|a| (a.name, a.value)).collect();
    assert!(
        text.contains(&("Delegated-IPv6-Prefix".into(), "2001:db8:8800::/56".into())),
        "{text:?}"
    );
    assert!(text.contains(&("Framed-IPv6-Prefix".into(), "2001:db8:0:5::/64".into())));
    assert!(
        text.contains(&("Framed-Interface-Id".into(), "0x0211223344556677".into())),
        "{text:?}"
    );
    for bad in [
        ("Framed-IPv6-Prefix", "2001:db8::"),
        ("Framed-IPv6-Prefix", "2001:db8::/129"),
        ("Framed-Interface-Id", "0x12"),
    ] {
        assert!(
            radius_aaa::encode_attr(&dict, &mut l, &corerouter_model::radius::Attribute::new(bad.0, bad.1)).is_err(),
            "{bad:?}"
        );
    }
}

/// G4.3g: a login called off (its session ended) leaves the client: no
/// more retransmissions to a server that does not answer, and the caller
/// hears of it at once instead of after every timeout.
#[test]
fn a_called_off_login_stops_being_retransmitted() {
    let srv = TestRadius::start(3);
    srv.srv.lock().unwrap().script.offline = true;
    let mut e = srv.entry(1);
    e.timeout = 1000;
    let r = start(vec![e]);
    let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    let t = Instant::now();
    r.aaa.authenticate_until(
        AuthRequest::pap(AaaService::Ppp, "ana", "segredo"),
        Box::new(move |x| tx.send(x).unwrap()),
        cancel.clone(),
    );
    std::thread::sleep(Duration::from_millis(300));
    cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    let x = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(x.outcome, AuthOutcome::Error, "{x:?}");
    assert!(x.message.as_deref().unwrap_or("").contains("cancelled"), "{x:?}");
    assert!(t.elapsed() < Duration::from_millis(1000), "before the first retransmission: {:?}", t.elapsed());
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(monitor(&r.aaa).servers[0].resends, 0, "nothing sent again");
    // Called off before it is even taken: never sent.
    let gone = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let (tx, rx) = mpsc::channel();
    r.aaa.authenticate_until(AuthRequest::pap(AaaService::Ppp, "bia", "x"), Box::new(move |x| tx.send(x).unwrap()), gone);
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap().outcome, AuthOutcome::Error);
}

/// G4.3g: while many logins wait for the server, an Accounting-Start
/// waits behind them, and goes once they are answered, with the time it
/// waited in Acct-Delay-Time (RFC 2866 §5.2).
#[test]
fn accounting_waits_behind_a_wave_of_logins() {
    let srv = TestRadius::start(9);
    srv.srv.lock().unwrap().script.delay_ms = 1500;
    let r = start(vec![srv.entry(1)]);
    let (tx, rx) = mpsc::channel();
    for _ in 0..100 {
        let tx = tx.clone();
        r.aaa.authenticate(AuthRequest::pap(AaaService::Ppp, "ana", "segredo"), Box::new(move |x| tx.send(x).unwrap()));
    }
    // The next sweep sees the wave.
    thread::sleep(Duration::from_millis(400));
    r.aaa.account(acct(AcctStatus::Start, "S-W"), None).unwrap();
    thread::sleep(Duration::from_millis(600));
    assert!(srv.srv.lock().unwrap().accounting.is_empty(), "held while the logins wait");
    for _ in 0..100 {
        assert_eq!(rx.recv_timeout(Duration::from_secs(10)).unwrap().outcome, AuthOutcome::Accept);
    }
    let t = Instant::now();
    while srv.srv.lock().unwrap().accounting.is_empty() {
        assert!(t.elapsed() < Duration::from_secs(10), "released after the wave");
        thread::sleep(Duration::from_millis(20));
    }
    let a = srv.srv.lock().unwrap().accounting[0].clone();
    assert_eq!(a.session_id, "S-W");
    assert!(a.delay_time >= 1, "Acct-Delay-Time counts the wait: {}", a.delay_time);
}
