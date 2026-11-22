//! G4.1b: the daemon answers the LAN on the real port 53, inside a
//! throwaway network namespace (no root, nothing reaches the host):
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_dns_server
//! ```
//!
//! A dummy interface `lan0` has the router's LAN addresses 10.53.0.1 and
//! 10.53.0.3 and a client's, 10.53.0.2. A test upstream written here sits
//! on `127.0.0.2:53` (the forwarder holds `0.0.0.0:53`; both use
//! SO_REUSEADDR, and the more specific socket gets its packets). Checked:
//! REFUSED outside `allowed_from`, answers inside it, the reply's source is
//! the address the query went to (IP_PKTINFO), static entries with PTR,
//! TCP, the per-client limit, and serve-stale with the upstream gone.
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use common::*;
use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde_json::{Value, json};

const PORT: &str = "7995";

fn run(command: &str, params: Value) -> Result<Value, String> {
    common::client(&format!("127.0.0.1:{PORT}"), common::token_of(None)).and_then(|mut c| {
        c.call(
            "engine.execute",
            json!({"command": command, "params": params}),
        )
    })
}

/// The upstream: A queries get 198.51.100.7 (TTL 1 for `short.*`, else
/// 300); silent while `down`. Returns (queries seen, down switch).
fn upstream() -> (Arc<AtomicUsize>, Arc<AtomicBool>) {
    let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
    s.set_reuse_address(true).unwrap();
    s.bind(&SocketAddr::from(([127, 0, 0, 2], 53)).into())
        .unwrap();
    let sock: UdpSocket = s.into();
    let count = Arc::new(AtomicUsize::new(0));
    let down = Arc::new(AtomicBool::new(false));
    let (c, d) = (count.clone(), down.clone());
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            c.fetch_add(1, Ordering::Relaxed);
            if d.load(Ordering::Relaxed) {
                continue;
            }
            let Ok(q) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let Some(qq) = q.queries.first().cloned() else {
                continue;
            };
            let mut m = Message::response(q.metadata.id, OpCode::Query);
            m.metadata.recursion_available = true;
            m.add_query(qq.clone());
            if qq.query_type() == RecordType::A {
                let ttl = if qq.name().to_ascii().starts_with("short.") {
                    1
                } else {
                    300
                };
                m.add_answer(Record::from_rdata(
                    qq.name().clone(),
                    ttl,
                    RData::A(A::new(198, 51, 100, 7)),
                ));
            }
            let _ = sock.send_to(&m.to_vec().unwrap(), from);
        }
    });
    (count, down)
}

fn query(name: &str, t: RecordType) -> Vec<u8> {
    let mut m = Message::query();
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), t));
    m.to_vec().unwrap()
}

/// Asks `server`:53 from `client` over UDP; the reply and where it came
/// from, or `None` after 700 ms.
fn ask_from(client: [u8; 4], server: [u8; 4], q: &[u8]) -> Option<(Message, SocketAddr)> {
    let s = UdpSocket::bind(SocketAddr::from((client, 0))).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(700)))
        .unwrap();
    s.send_to(q, SocketAddr::from((server, 53))).unwrap();
    let mut buf = [0u8; 4096];
    let (n, from) = s.recv_from(&mut buf).ok()?;
    Some((Message::from_vec(&buf[..n]).unwrap(), from))
}

fn answers(m: &Message) -> Vec<String> {
    m.answers.iter().map(|r| r.data.to_string()).collect()
}

#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn the_lan_is_served_and_outsiders_refused() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    ip(None, &["link", "add", "lan0", "type", "dummy"]);
    ip(None, &["link", "set", "lan0", "up"]);
    for a in ["10.53.0.1/24", "10.53.0.2/24", "10.53.0.3/24"] {
        ip(None, &["addr", "add", a, "dev", "lan0"]);
    }
    let (count, down) = upstream();

    let dir = std::env::temp_dir().join(format!("g41b-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let log = std::fs::File::create(std::env::temp_dir().join("g41b-netns.log")).unwrap();
    let mut c = Command::new(DAEMON);
    c.args([
        "--no-discovery",
        "--dns-lab-any",
        "--control",
        PORT,
        "--config-dir",
    ])
    .arg(&dir)
    .arg("--token-file")
    .arg(common::token_file(None, &dir))
    .env("RUST_LOG", "info")
    .stdout(Stdio::null())
    .stderr(log);
    let _daemon = Kill(c.spawn().unwrap());
    wait_for("the daemon", || run("interface.list", json!({})).is_ok());

    run(
        "ip.dns.set",
        json!({"servers": ["127.0.0.2"], "allow_remote_requests": true}),
    )
    .unwrap();
    run(
        "ip.dns.static.add",
        json!({"name": "nas.lan", "address": "10.53.0.20"}),
    )
    .unwrap();
    const CLIENT: [u8; 4] = [10, 53, 0, 2];
    const ROUTER: [u8; 4] = [10, 53, 0, 1];
    let a = query("www.example.com.", RecordType::A);
    wait_for("the listener", || ask_from(CLIENT, ROUTER, &a).is_some());

    // allowed_from is the (empty) LAN list: REFUSED, nothing asked upstream.
    let (m, _) = ask_from(CLIENT, ROUTER, &a).unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::Refused);
    assert_eq!(count.load(Ordering::Relaxed), 0);

    run("ip.dns.set", json!({"allowed_from": "10.53.0.0/24"})).unwrap();
    wait_for("allowed_from", || {
        ask_from(CLIENT, ROUTER, &a)
            .is_some_and(|(m, _)| m.metadata.response_code == ResponseCode::NoError)
    });
    let (m, from) = ask_from(CLIENT, ROUTER, &a).unwrap();
    assert_eq!(answers(&m), ["198.51.100.7"]);
    assert_eq!(from, SocketAddr::from((ROUTER, 53)));
    // Asked on the second address, answered from it (IP_PKTINFO).
    let (_, from) = ask_from(CLIENT, [10, 53, 0, 3], &a).unwrap();
    assert_eq!(from, SocketAddr::from(([10, 53, 0, 3], 53)));
    assert_eq!(count.load(Ordering::Relaxed), 1, "the rest from the cache");

    // Static entry and its automatic PTR.
    let (m, _) = ask_from(CLIENT, ROUTER, &query("nas.lan.", RecordType::A)).unwrap();
    assert_eq!(answers(&m), ["10.53.0.20"]);
    assert!(m.metadata.authoritative);
    let (m, _) = ask_from(
        CLIENT,
        ROUTER,
        &query("20.0.53.10.in-addr.arpa.", RecordType::PTR),
    )
    .unwrap();
    assert_eq!(answers(&m), ["nas.lan."]);

    // TCP.
    let mut s = TcpStream::connect(SocketAddr::from((ROUTER, 53))).unwrap();
    let mut framed = u16::try_from(a.len()).unwrap().to_be_bytes().to_vec();
    framed.extend_from_slice(&a);
    s.write_all(&framed).unwrap();
    let mut head = [0u8; 2];
    s.read_exact(&mut head).unwrap();
    let mut msg = vec![0u8; usize::from(u16::from_be_bytes(head))];
    s.read_exact(&mut msg).unwrap();
    assert_eq!(answers(&Message::from_vec(&msg).unwrap()), ["198.51.100.7"]);

    // Serve stale: a TTL of 1 s, then the upstream goes quiet.
    let short = query("short.example.com.", RecordType::A);
    ask_from(CLIENT, ROUTER, &short).unwrap();
    down.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(1500));
    run(
        "ip.dns.set",
        json!({"query_server_timeout_ms": 300, "query_total_timeout_ms": 300}),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    let s = UdpSocket::bind(SocketAddr::from((CLIENT, 0))).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    s.send_to(&short, SocketAddr::from((ROUTER, 53))).unwrap();
    let mut buf = [0u8; 1500];
    let n = s.recv(&mut buf).unwrap();
    let m = Message::from_vec(&buf[..n]).unwrap();
    assert_eq!(answers(&m), ["198.51.100.7"], "stale answer (RFC 8767)");
    assert_eq!(m.answers[0].ttl, 30);
    let cache = run("ip.dns.cache.print", json!({"name": "short"})).unwrap();
    assert_eq!(cache[0]["stale"], true, "{cache}");

    // Per-client limit: 5/s with a burst of 10, the rest dropped.
    run("ip.dns.set", json!({"max_queries_per_client": 5})).unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    let s = UdpSocket::bind(SocketAddr::from((CLIENT, 0))).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    for _ in 0..30 {
        s.send_to(&a, SocketAddr::from((ROUTER, 53))).unwrap();
    }
    let mut got = 0;
    while s.recv(&mut buf).is_ok() {
        got += 1;
    }
    assert!((10..=12).contains(&got), "{got} answers");
}
