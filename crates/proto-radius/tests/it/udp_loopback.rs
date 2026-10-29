//! Real UDP on 127.0.0.1 (no root): the client against the test server in
//! a thread, and a CoA/Disconnect round trip to the Dynamic Authorization
//! Server. Shows the sans-IO pieces driven by real sockets, the way the
//! daemon (G4.3d) will.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use corerouter_proto_radius::client::{Client, ClientConfig, Event, ServerConfig, SocketKey};
use corerouter_proto_radius::crypto;
use corerouter_proto_radius::dynauth::{
    self, DynAuthClient, DynAuthConfig, DynAuthServer, Incoming, Outcome, RequestKind, SessionView,
};
use corerouter_proto_radius::packet::{AttrList, Code, Packet, PushAttr, attr};
use corerouter_proto_radius::testserver::TestServer;

const SECRET: &[u8] = b"udp-secret";

fn spawn_server(stop: Arc<AtomicBool>) -> (SocketAddr, std::thread::JoinHandle<TestServer>) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let addr = sock.local_addr().unwrap();
    let h = std::thread::spawn(move || {
        let mut s = TestServer::new(SECRET, 3);
        s.add_user("ana", "segredo", AttrList::new());
        let t0 = Instant::now();
        let mut buf = [0u8; 4096];
        while !stop.load(Ordering::Relaxed) {
            let Ok((n, from)) = sock.recv_from(&mut buf) else {
                continue;
            };
            if let Some(r) = s.handle(from, &buf[..n], t0.elapsed().as_millis() as u64) {
                sock.send_to(&r.bytes, r.to).unwrap();
            }
        }
        s
    });
    (addr, h)
}

#[test]
fn client_over_udp_loopback() {
    let stop = Arc::new(AtomicBool::new(false));
    let (addr, h) = spawn_server(stop.clone());
    let mut c = Client::new(
        ClientConfig::default(),
        vec![ServerConfig::auth(addr, SECRET)],
        [7; 32],
    );
    let t0 = Instant::now();
    let now = || t0.elapsed().as_millis() as u64;
    const N: usize = 2000;
    for i in 0..N {
        let mut l = AttrList::new();
        l.push_text(attr::USER_NAME, "ana").unwrap();
        let pw: &[u8] = if i % 10 == 0 { b"nope" } else { b"segredo" };
        c.access(l, Some(pw), now()).unwrap();
    }
    let mut sockets: HashMap<SocketKey, UdpSocket> = HashMap::new();
    let (mut accepts, mut rejects, mut failed) = (0, 0, 0);
    let mut buf = Vec::new();
    let mut rx = [0u8; 4096];
    while accepts + rejects + failed < N {
        assert!(t0.elapsed() < Duration::from_secs(30), "stuck");
        while let Some(t) = c.poll_transmit(&mut buf) {
            let s = sockets.entry(t.from).or_insert_with(|| {
                let s = UdpSocket::bind("127.0.0.1:0").unwrap();
                s.set_nonblocking(true).unwrap();
                s
            });
            s.send_to(&buf, t.dest).unwrap();
        }
        let mut got = false;
        for (k, s) in &sockets {
            while let Ok((n, from)) = s.recv_from(&mut rx) {
                got = true;
                let _ = c.handle_input(*k, from, &rx[..n], now());
            }
        }
        if !got {
            std::thread::sleep(Duration::from_millis(1));
        }
        c.handle_timeout(now());
        while let Some(e) = c.poll_event() {
            match e {
                Event::Response {
                    code: Code::AccessAccept,
                    ..
                } => accepts += 1,
                Event::Response {
                    code: Code::AccessReject,
                    ..
                } => rejects += 1,
                Event::Failed { .. } => failed += 1,
                _ => {}
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    let server = h.join().unwrap();
    assert_eq!((accepts, rejects, failed), (N - N / 10, N / 10, 0));
    // 2000 in flight need 8 sockets of 256 identifiers.
    assert!(sockets.len() >= 8);
    assert_eq!(server.stats.accepts as usize, N - N / 10);
    c.check_invariants().unwrap();
}

#[test]
fn coa_and_disconnect_over_udp_loopback() {
    let nas = UdpSocket::bind("127.0.0.1:0").unwrap();
    nas.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let dac = UdpSocket::bind("127.0.0.1:0").unwrap();
    dac.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut srv = DynAuthServer::new(DynAuthConfig {
        clients: vec![DynAuthClient {
            addr: dac.local_addr().unwrap().ip(),
            secret: SECRET.to_vec(),
        }],
        require_event_timestamp: true,
        ..DynAuthConfig::default()
    });
    let now_unix = 1_800_000_000;
    let sessions = [("PPP-1", "ana"), ("PPP-2", "bia")];
    let mut rate = HashMap::new();
    let mut alive = vec![true, true];
    for (id, kind) in [(1u8, RequestKind::Coa), (2, RequestKind::Disconnect)] {
        let mut l = AttrList::new();
        l.push_text(attr::ACCT_SESSION_ID, "PPP-2").unwrap();
        l.push_u32(attr::EVENT_TIMESTAMP, now_unix).unwrap();
        if kind == RequestKind::Coa {
            l.push_vsa(14988, 8, b"30M/60M").unwrap();
        }
        let req = dynauth::build_request(kind, id, &l, SECRET, true);
        dac.send_to(&req, nas.local_addr().unwrap()).unwrap();
        let mut buf = [0u8; 4096];
        let (n, from) = nas.recv_from(&mut buf).unwrap();
        let Ok(Incoming::Request(r)) = srv.handle(from, &buf[..n], now_unix, 0) else {
            panic!("expected a request");
        };
        assert_eq!(r.precheck, None);
        let views = sessions.iter().map(|(s, u)| SessionView {
            acct_session_id: Some(s),
            user_name: Some(u),
            ..SessionView::default()
        });
        let hit = r.selector.select(views);
        assert_eq!(hit, vec![1]);
        match kind {
            RequestKind::Coa => {
                for a in r.changes.iter() {
                    rate.insert(hit[0], a.value.to_vec());
                }
            }
            RequestKind::Disconnect => alive[hit[0]] = false,
        }
        let resp = srv.respond(&r, Outcome::Ack, &AttrList::new(), now_unix);
        nas.send_to(&resp, from).unwrap();
        let (n, _) = dac.recv_from(&mut buf).unwrap();
        let p = Packet::parse(&buf[..n]).unwrap();
        let want = if kind == RequestKind::Coa {
            Code::CoaAck
        } else {
            Code::DisconnectAck
        };
        assert_eq!(p.code(), want);
        let ra = Packet::parse(&req).unwrap().authenticator();
        assert!(crypto::verify_response(&p, &ra, SECRET));
    }
    assert!(rate.contains_key(&1));
    assert_eq!(alive, vec![true, false]);
}
