//! G4.1zf end to end: the real daemon (virtual lab, loopback) answers DNS
//! over TLS (RFC 7858) with the `/certificate` it made, pipelined and out of
//! order; bytes that are not TLS get no DNS answer (§3.1); the counters
//! move; `_dns.resolver.arpa` SVCB over UDP names the service (RFC 9462).
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_control::Client;
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use serde_json::{Value, json};

const DAEMON: &str = env!("CARGO_BIN_EXE_corerouter-daemon");

struct Daemon {
    child: Child,
    control: String,
    dns_port: u16,
    token_file: std::path::PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.token_file);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start() -> Daemon {
    let port = free_port();
    let dns_port = free_port();
    let token_file =
        std::env::temp_dir().join(format!("cr-dot-{}-{port}.token", std::process::id()));
    let child = Command::new(DAEMON)
        .args(["--control", &port.to_string()])
        .args(["--dns-port", &dns_port.to_string()])
        .arg("--token-file")
        .arg(&token_file)
        .arg("--no-discovery")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let d = Daemon {
        child,
        control: format!("127.0.0.1:{port}"),
        dns_port,
        token_file,
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(&d.control).is_err() || !d.token_file.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        thread::sleep(Duration::from_millis(50));
    }
    d
}

fn call(d: &Daemon, command: &str, params: Value) -> Value {
    let token = std::fs::read_to_string(&d.token_file).unwrap();
    let mut c = Client::connect(&d.control, Duration::from_secs(2)).unwrap();
    c.set_token(Some(token.trim().to_owned()));
    c.call(
        "engine.execute",
        json!({"command": command, "params": params}),
    )
    .unwrap()
}

fn query(id: u16, name: &str, t: RecordType) -> Vec<u8> {
    let mut m = Message::query();
    m.metadata.id = id;
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), t));
    m.to_vec().unwrap()
}

fn read_framed(s: &mut impl Read) -> Message {
    let mut len = [0u8; 2];
    s.read_exact(&mut len).unwrap();
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
    s.read_exact(&mut buf).unwrap();
    Message::from_vec(&buf).unwrap()
}

/// A TLS client to the router, once it listens.
fn connect(port: u16) -> corerouter_control::tls::ClientStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(tcp) = TcpStream::connect(("127.0.0.1", port)) {
            tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            if let Ok((s, _)) = corerouter_control::tls::connect(tcp, None) {
                return s;
            }
        }
        assert!(
            Instant::now() < deadline,
            "DNS over TLS never answered on {port}"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn dns_over_tls_answers_pipelined_queries_and_nothing_in_clear() {
    let d = start();
    let dot = free_port();
    call(
        &d,
        "ip.dns.set",
        json!({"allow_remote_requests": true, "servers": ["192.0.2.53"]}),
    );
    call(
        &d,
        "ip.dns.static.add",
        json!({"name": "router.lan", "address": "192.168.88.1"}),
    );
    call(
        &d,
        "ip.dns.static.add",
        json!({"name": "nas.lan", "address": "192.168.88.2"}),
    );
    let r = call(
        &d,
        "ip.dns.encrypted-service.set",
        json!({"dot": true, "dot_port": dot}),
    );
    assert_eq!(r["certificate"], "dns-server", "{r}");

    // Three queries in one write (RFC 7766 §6.2.1.1: pipelined); answers
    // matched by id.
    let mut s = connect(dot);
    let mut burst = Vec::new();
    for (id, name) in [(1u16, "router.lan."), (2, "nas.lan."), (3, "x.invalid.")] {
        let q = query(id, name, RecordType::A);
        burst.extend_from_slice(&u16::try_from(q.len()).unwrap().to_be_bytes());
        burst.extend_from_slice(&q);
    }
    s.write_all(&burst).unwrap();
    let mut got: Vec<(u16, ResponseCode, Vec<String>)> = (0..3)
        .map(|_| {
            let m = read_framed(&mut s);
            let addrs = m
                .answers
                .iter()
                .filter_map(|r| match &r.data {
                    RData::A(a) => Some(a.0.to_string()),
                    _ => None,
                })
                .collect();
            (m.metadata.id, m.metadata.response_code, addrs)
        })
        .collect();
    got.sort_by_key(|g| g.0);
    assert_eq!(
        got[0],
        (1, ResponseCode::NoError, vec!["192.168.88.1".to_owned()])
    );
    assert_eq!(
        got[1],
        (2, ResponseCode::NoError, vec!["192.168.88.2".to_owned()])
    );
    assert_eq!(got[2].1, ResponseCode::NXDomain);
    // The same connection keeps answering (RFC 7858 §3.4).
    let q = query(4, "router.lan.", RecordType::A);
    let mut framed = u16::try_from(q.len()).unwrap().to_be_bytes().to_vec();
    framed.extend_from_slice(&q);
    s.write_all(&framed).unwrap();
    assert_eq!(read_framed(&mut s).metadata.id, 4);

    // Out of order (RFC 7766 §7): a miss (the upstream never answers) and
    // then a static name; the static answer does not wait for the miss.
    call(
        &d,
        "ip.dns.set",
        json!({"query_server_timeout_ms": 400, "query_total_timeout_ms": 800}),
    );
    thread::sleep(Duration::from_millis(1500));
    let mut burst = Vec::new();
    for (id, name) in [(5u16, "slow.example."), (6, "router.lan.")] {
        let q = query(id, name, RecordType::A);
        burst.extend_from_slice(&u16::try_from(q.len()).unwrap().to_be_bytes());
        burst.extend_from_slice(&q);
    }
    s.write_all(&burst).unwrap();
    let first = read_framed(&mut s);
    let second = read_framed(&mut s);
    assert_eq!(first.metadata.id, 6, "the cache/static answer first");
    assert_eq!(
        (second.metadata.id, second.metadata.response_code),
        (5, ResponseCode::ServFail)
    );

    // Plain DNS on the TLS port never gets a DNS answer (RFC 7858 §3.1).
    let mut plain = TcpStream::connect(("127.0.0.1", dot)).unwrap();
    plain
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    plain.write_all(&framed).unwrap();
    let mut back = Vec::new();
    let _ = plain.read_to_end(&mut back);
    assert!(
        Message::from_vec(back.get(2..).unwrap_or_default()).is_err(),
        "a DNS answer in clear: {back:?}"
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    let g = loop {
        let g = call(&d, "ip.dns.encrypted-service.get", json!({}));
        if g["queries"].as_u64() >= Some(4) && g["handshake_failures"].as_u64() >= Some(1) {
            break g;
        }
        assert!(Instant::now() < deadline, "{g}");
        thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(g["status"], "listening", "{g}");
    assert!(g["handshakes"].as_u64() >= Some(1), "{g}");
    assert!(
        g["fingerprint"].as_str().unwrap().starts_with("SHA256:"),
        "{g}"
    );

    // DDR over plain UDP 53 names it (RFC 9462 §4), port included.
    let u = UdpSocket::bind("127.0.0.1:0").unwrap();
    u.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    u.send_to(
        &query(9, "_dns.resolver.arpa.", RecordType::SVCB),
        ("127.0.0.1", d.dns_port),
    )
    .unwrap();
    let mut buf = [0u8; 2048];
    let n = u.recv(&mut buf).unwrap();
    let m = Message::from_vec(&buf[..n]).unwrap();
    let RData::SVCB(svcb) = &m.answers[0].data else {
        panic!("{m:?}")
    };
    let text = format!("{svcb}");
    assert!(
        text.contains("alpn=dot") || text.contains("alpn=\"dot\""),
        "{text}"
    );
    assert!(text.contains(&format!("port={dot}")), "{text}");
}

/// An idle connection goes after `idle_timeout_secs` (with close_notify);
/// one address holds at most a quarter of `max_sessions`.
#[test]
fn idle_connections_close_and_one_address_is_capped() {
    let d = start();
    let dot = free_port();
    call(&d, "ip.dns.set", json!({"allow_remote_requests": true}));
    call(
        &d,
        "ip.dns.static.add",
        json!({"name": "router.lan", "address": "192.168.88.1"}),
    );
    call(
        &d,
        "ip.dns.encrypted-service.set",
        json!({"dot": true, "dot_port": dot, "idle_timeout_secs": 1, "max_sessions": 4}),
    );
    let mut s = connect(dot);
    let q = query(1, "router.lan.", RecordType::A);
    let mut framed = u16::try_from(q.len()).unwrap().to_be_bytes().to_vec();
    framed.extend_from_slice(&q);
    s.write_all(&framed).unwrap();
    assert_eq!(read_framed(&mut s).metadata.id, 1);
    // A second connection from the same address: over its quarter (1).
    let tcp = TcpStream::connect(("127.0.0.1", dot)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    assert!(
        corerouter_control::tls::connect(tcp, None).is_err(),
        "the second one is closed at accept"
    );
    // Idle for over a second: closed by the router, cleanly.
    let t = Instant::now();
    let mut rest = Vec::new();
    let _ = s.read_to_end(&mut rest);
    assert!(
        t.elapsed() < Duration::from_secs(4),
        "closed after the idle time, {:?}",
        t.elapsed()
    );
    let g = call(&d, "ip.dns.encrypted-service.get", json!({}));
    assert!(g["over_limit"].as_u64() >= Some(1), "{g}");
    // Its place is free again.
    let mut s = connect(dot);
    s.write_all(&framed).unwrap();
    assert_eq!(read_framed(&mut s).metadata.id, 1);
}
