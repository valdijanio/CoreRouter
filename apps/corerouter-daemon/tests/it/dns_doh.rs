//! G4.1zf end to end: the real daemon (virtual lab, loopback) answers DNS
//! over HTTPS (RFC 8484) on HTTP/1.1 and HTTP/2 (by ALPN), GET and POST,
//! with the HTTP errors of a wrong path or media type; DDR names both
//! services.
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
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use corerouter_control::Client;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
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
        std::env::temp_dir().join(format!("cr-doh-{}-{port}.token", std::process::id()));
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

#[derive(Debug)]
struct AnyCert;

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            m,
            c,
            d,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A TLS client offering `alpn`, once the router listens.
fn connect(port: u16, alpn: &[u8]) -> StreamOwned<ClientConnection, TcpStream> {
    let mut cfg =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert))
            .with_no_client_auth();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    let cfg = Arc::new(cfg);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(tcp) = TcpStream::connect(("127.0.0.1", port)) {
            tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let conn = ClientConnection::new(
                cfg.clone(),
                ServerName::IpAddress(std::net::Ipv4Addr::LOCALHOST.into()),
            )
            .unwrap();
            let mut s = StreamOwned::new(conn, tcp);
            if s.flush().is_ok() && s.conn.complete_io(&mut s.sock).is_ok() {
                return s;
            }
        }
        assert!(
            Instant::now() < deadline,
            "DNS over HTTPS never answered on {port}"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

/// One HTTP/1.1 exchange: (status, headers, body).
fn h1(s: &mut StreamOwned<ClientConnection, TcpStream>, request: &[u8]) -> (u16, String, Vec<u8>) {
    s.write_all(request).unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = s.read(&mut chunk).unwrap();
        assert!(n > 0, "closed early: {}", String::from_utf8_lossy(&buf));
        buf.extend_from_slice(&chunk[..n]);
        let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
            continue;
        };
        let head = String::from_utf8_lossy(&buf[..end]).to_string();
        let len: usize = head
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(|v| v.trim().parse().unwrap())
            })
            .unwrap();
        if buf.len() >= end + 4 + len {
            let status = head[9..12].parse().unwrap();
            return (status, head, buf[end + 4..end + 4 + len].to_vec());
        }
    }
}

fn frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream: u32, p: &[u8]) {
    out.extend_from_slice(&u32::try_from(p.len()).unwrap().to_be_bytes()[1..]);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(p);
}

/// An HPACK literal without indexing, new name (RFC 7541 §6.2.2).
fn literal(out: &mut Vec<u8>, name: &str, value: &str) {
    out.push(0);
    out.push(u8::try_from(name.len()).unwrap());
    out.extend_from_slice(name.as_bytes());
    out.push(u8::try_from(value.len()).unwrap());
    out.extend_from_slice(value.as_bytes());
}

#[test]
fn dns_over_https_answers_http1_and_http2() {
    let d = start();
    let doh = free_port();
    call(&d, "ip.dns.set", json!({"allow_remote_requests": true}));
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
        json!({"doh": true, "doh_port": doh, "dot": true, "dot_port": free_port()}),
    );
    assert_eq!(r["certificate"], "dns-server", "{r}");

    // HTTP/1.1: POST, then GET on the same connection (RFC 8484 §4.1).
    let mut s = connect(doh, b"http/1.1");
    let q = query(0, "router.lan.", RecordType::A);
    let mut post = format!("POST /dns-query HTTP/1.1\r\nHost: r\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", q.len()).into_bytes();
    post.extend_from_slice(&q);
    let (status, head, body) = h1(&mut s, &post);
    assert_eq!(status, 200, "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("content-type: application/dns-message"),
        "{head}"
    );
    assert!(
        head.contains("cache-control: max-age=86400"),
        "the static entry's TTL: {head}"
    );
    assert_eq!(Message::from_vec(&body).unwrap().answers.len(), 1);
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(query(
        0,
        "nas.lan.",
        RecordType::A,
    ));
    let (status, _, body) = h1(
        &mut s,
        format!("GET /dns-query?dns={b64} HTTP/1.1\r\nHost: r\r\n\r\n").as_bytes(),
    );
    assert_eq!(status, 200);
    let m = Message::from_vec(&body).unwrap();
    let RData::A(a) = &m.answers[0].data else {
        panic!()
    };
    assert_eq!(a.0.to_string(), "192.168.88.2");
    let (status, _, _) = h1(&mut s, b"GET /other HTTP/1.1\r\nHost: r\r\n\r\n");
    assert_eq!(status, 404);
    let (status, _, _) = h1(&mut s, b"POST /dns-query HTTP/1.1\r\nHost: r\r\nContent-Type: text/plain\r\nContent-Length: 1\r\n\r\nx");
    assert_eq!(status, 415);

    // HTTP/2: two streams at once, answered by stream.
    let mut s = connect(doh, b"h2");
    assert_eq!(s.conn.alpn_protocol(), Some(&b"h2"[..]));
    let mut b = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
    frame(&mut b, 0x4, 0, 0, &[]);
    for (id, name) in [(1u32, "router.lan."), (3, "nas.lan.")] {
        let b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(query(0, name, RecordType::A));
        let mut block = vec![0x82, 0x87]; // :method GET, :scheme https
        literal(&mut block, ":authority", "127.0.0.1");
        literal(&mut block, ":path", &format!("/dns-query?dns={b64}"));
        frame(&mut b, 0x1, 0x4 | 0x1, id, &block);
    }
    s.write_all(&b).unwrap();
    let mut got: Vec<(u32, u8, Vec<u8>)> = Vec::new();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while got.iter().filter(|g| g.1 == 0x0).count() < 2 {
        let n = s.read(&mut chunk).unwrap();
        assert!(n > 0);
        buf.extend_from_slice(&chunk[..n]);
        while buf.len() >= 9 {
            let len = usize::from(buf[0]) << 16 | usize::from(buf[1]) << 8 | usize::from(buf[2]);
            if buf.len() < 9 + len {
                break;
            }
            let id = u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]);
            got.push((id, buf[3], buf[9..9 + len].to_vec()));
            buf.drain(..9 + len);
        }
    }
    for id in [1u32, 3] {
        let headers = got.iter().find(|g| g.0 == id && g.1 == 0x1).unwrap();
        assert_eq!(headers.2[0], 0x88, ":status 200 (static index 8)");
        let data = got.iter().find(|g| g.0 == id && g.1 == 0x0).unwrap();
        let m = Message::from_vec(&data.2).unwrap();
        let RData::A(a) = &m.answers[0].data else {
            panic!()
        };
        let want = if id == 1 {
            "192.168.88.1"
        } else {
            "192.168.88.2"
        };
        assert_eq!(a.0.to_string(), want);
    }

    // The counters are published every second.
    let deadline = Instant::now() + Duration::from_secs(5);
    let g = loop {
        let g = call(&d, "ip.dns.encrypted-service.get", json!({}));
        if g["doh_queries"].as_u64() >= Some(4) {
            break g;
        }
        assert!(Instant::now() < deadline, "{g}");
        thread::sleep(Duration::from_millis(100));
    };
    assert!(g["doh_errors"].as_u64() >= Some(2), "{g}");
    assert!(g["http2"].as_u64() >= Some(1), "{g}");
    assert!(
        g["url"].as_str().unwrap().ends_with("/dns-query{?dns}"),
        "{g}"
    );

    // DDR: DoH first (h2, dohpath), then DoT.
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
    assert_eq!(m.answers.len(), 2);
    let RData::SVCB(first) = &m.answers[0].data else {
        panic!("{m:?}")
    };
    let text = format!("{first}");
    assert!(
        text.contains("h2")
            && text.contains(&format!("port={doh}"))
            && text.contains("/dns-query{?dns}"),
        "{text}"
    );
}
