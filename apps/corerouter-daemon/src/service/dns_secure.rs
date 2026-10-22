//! Encrypted upstream DNS (G4.1d): DNS over TLS (RFC 7858) and DNS over
//! HTTPS (RFC 8484), the sockets behind `Transport::exchange_secure`.
//!
//! - DoT: a TLS stream to port 853, each message with its 2-byte length
//!   (RFC 7858 §3.3, as RFC 1035 §4.2.2 over TCP).
//! - DoH: `POST <path>` with `application/dns-message` (RFC 8484 §4.1),
//!   HTTP/1.1 over our client (`https.rs`). RFC 8484 §5.2 recommends
//!   HTTP/2; the public servers answer HTTP/1.1, and keeping the
//!   connection open (below) removes most of the difference.
//! - Connections are reused (RFC 7858 §3.4 SHOULD): a few idle ones per
//!   server, dropped after [`IDLE`]. A reused one the server closed in the
//!   meantime is retried once on a fresh connection (§3.4: both sides MUST
//!   handle a close).
//! - The certificate is checked unless `verify` is off (RFC 8310 §8.1:
//!   the chain and the name in subjectAltName); there is no fall back to
//!   plain DNS either way (§5: strict never falls back).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use corerouter_proto_dns::encrypted::{Proto, SecureServer};
use corerouter_proto_dns::resolver::TransportError;

use super::https::{self, Stream, Url};

/// An idle connection older than this is closed, not reused (servers
/// close theirs after 10–30 s; RFC 7766 §6.2.3 suggests seconds).
const IDLE: Duration = Duration::from_secs(20);
/// Idle connections kept per server.
const KEEP: usize = 4;
/// Largest DNS message (RFC 8484 §6, RFC 1035 §4.2.2).
const MAX_MESSAGE: usize = 65_535;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    addr: SocketAddr,
    proto: Proto,
    name: String,
    verify: bool,
}

type Pool = Mutex<HashMap<Key, Vec<(Stream, Instant)>>>;

fn pool() -> &'static Pool {
    static POOL: OnceLock<Pool> = OnceLock::new();
    POOL.get_or_init(Pool::default)
}

fn take(key: &Key) -> Option<Stream> {
    let mut p = pool().lock().unwrap_or_else(|e| e.into_inner());
    let list = p.get_mut(key)?;
    list.retain(|(_, at)| at.elapsed() < IDLE);
    list.pop().map(|(s, _)| s)
}

fn give_back(key: Key, s: Stream) {
    let mut p = pool().lock().unwrap_or_else(|e| e.into_inner());
    // Servers gone from the config leave no sockets behind for long.
    p.retain(|_, list| {
        list.retain(|(_, at)| at.elapsed() < IDLE);
        !list.is_empty()
    });
    let list = p.entry(key).or_default();
    if list.len() < KEEP {
        list.push((s, Instant::now()));
    }
}

fn io(e: &str) -> TransportError {
    if e.contains("timed out") || e.contains("WouldBlock") || e.contains("Resource temporarily") {
        TransportError::Timeout
    } else {
        TransportError::Io(e.chars().take(200).collect())
    }
}

/// One query to `via` at `addr`.
pub(crate) fn exchange(
    addr: SocketAddr,
    via: &SecureServer,
    query: &[u8],
    wait_ms: u64,
) -> Result<Vec<u8>, TransportError> {
    let deadline = Instant::now() + Duration::from_millis(wait_ms);
    let key = Key {
        addr,
        proto: via.proto,
        name: via.auth_name.clone(),
        verify: via.verify,
    };
    if let Some(s) = take(&key) {
        match once(s, &key, via, query, deadline) {
            Ok(r) => return Ok(r),
            // A stale connection: try a fresh one, if there is time left.
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => {}
        }
    }
    let s = https::connect(addr, true, &via.auth_name, via.verify, deadline).map_err(|e| io(&e))?;
    once(s, &key, via, query, deadline)
}

fn once(
    mut s: Stream,
    key: &Key,
    via: &SecureServer,
    query: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, TransportError> {
    let (reply, reuse) = match via.proto {
        Proto::Tls => (dot(&mut s, query, deadline)?, true),
        Proto::Https => doh(&mut s, via, query, deadline)?,
    };
    if reuse {
        give_back(key.clone(), s);
    }
    Ok(reply)
}

/// RFC 7858 §3.3: the 2-byte length, then the message.
fn dot(s: &mut Stream, query: &[u8], deadline: Instant) -> Result<Vec<u8>, TransportError> {
    s.deadline(deadline).map_err(|e| io(&e))?;
    let len = u16::try_from(query.len()).map_err(|_| TransportError::Io("query too long".into()))?;
    let mut framed = len.to_be_bytes().to_vec();
    framed.extend_from_slice(query);
    s.write_all(&framed).map_err(|e| io(&e.to_string()))?;
    s.flush().map_err(|e| io(&e.to_string()))?;
    let mut head = [0u8; 2];
    s.read_exact(&mut head).map_err(|e| io(&e.to_string()))?;
    let mut msg = vec![0u8; usize::from(u16::from_be_bytes(head))];
    s.read_exact(&mut msg).map_err(|e| io(&e.to_string()))?;
    Ok(msg)
}

/// RFC 8484 §4.1: POST, the message as the body.
fn doh(
    s: &mut Stream,
    via: &SecureServer,
    query: &[u8],
    deadline: Instant,
) -> Result<(Vec<u8>, bool), TransportError> {
    let url = Url {
        tls: true,
        host: via.host.clone(),
        port: via.port,
        path: via.path.clone(),
    };
    let r = https::exchange(
        s,
        "POST",
        &url,
        &[
            ("Content-Type", "application/dns-message"),
            ("Accept", "application/dns-message"),
        ],
        query,
        MAX_MESSAGE,
        deadline,
    )
    .map_err(|e| io(&e))?;
    if r.status != 200 {
        return Err(TransportError::Io(format!("HTTP {}", r.status)));
    }
    // RFC 8484 §4.2: anything else is not a DNS answer.
    let ok = r
        .content_type
        .as_deref()
        .is_some_and(|t| t.to_ascii_lowercase().starts_with("application/dns-message"));
    if !ok {
        return Err(TransportError::Io(format!(
            "not application/dns-message: {}",
            r.content_type.unwrap_or_default()
        )));
    }
    Ok((r.body, r.keep_alive))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use hickory_proto::op::{Message, OpCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, Record};
    use rustls::StreamOwned;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    /// The answer a test server gives: A 192.0.2.99 for whatever was asked.
    pub(crate) fn answer(query: &[u8]) -> Vec<u8> {
        let q = Message::from_vec(query).unwrap();
        let mut m = Message::response(q.metadata.id, OpCode::Query);
        m.metadata.recursion_available = true;
        m.add_queries(q.queries.clone());
        m.add_answer(Record::from_rdata(
            q.queries[0].name().clone(),
            300,
            RData::A(A::new(192, 0, 2, 99)),
        ));
        m.to_vec().unwrap()
    }

    /// A DoT (`doh == false`) or DoH server on localhost with a self-signed
    /// certificate for `localhost`; counts connections.
    pub(crate) fn server(doh: bool) -> (u16, Arc<AtomicUsize>) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert = CertificateDer::from(ck.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
        let config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .unwrap(),
        );
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let conns = Arc::new(AtomicUsize::new(0));
        let count = conns.clone();
        thread::spawn(move || {
            for tcp in l.incoming() {
                let Ok(tcp) = tcp else { return };
                count.fetch_add(1, Ordering::SeqCst);
                let config = config.clone();
                thread::spawn(move || {
                    let conn = rustls::ServerConnection::new(config).unwrap();
                    let mut s = StreamOwned::new(conn, tcp);
                    loop {
                        let query = if doh {
                            let mut head = Vec::new();
                            let mut b = [0u8; 1];
                            while !head.ends_with(b"\r\n\r\n") {
                                if s.read(&mut b).unwrap_or(0) == 0 {
                                    return;
                                }
                                head.push(b[0]);
                            }
                            let text = String::from_utf8_lossy(&head).to_lowercase();
                            assert!(text.starts_with("post /dns-query http/1.1"), "{text}");
                            assert!(text.contains("content-type: application/dns-message"));
                            let len: usize = text
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length: "))
                                .unwrap()
                                .trim()
                                .parse()
                                .unwrap();
                            let mut body = vec![0u8; len];
                            s.read_exact(&mut body).unwrap();
                            body
                        } else {
                            let mut head = [0u8; 2];
                            if s.read_exact(&mut head).is_err() {
                                return;
                            }
                            let mut q = vec![0u8; usize::from(u16::from_be_bytes(head))];
                            s.read_exact(&mut q).unwrap();
                            q
                        };
                        let a = answer(&query);
                        let out = if doh {
                            let mut r = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                                a.len()
                            )
                            .into_bytes();
                            r.extend_from_slice(&a);
                            r
                        } else {
                            let mut r = u16::try_from(a.len()).unwrap().to_be_bytes().to_vec();
                            r.extend_from_slice(&a);
                            r
                        };
                        if s.write_all(&out).is_err() || s.flush().is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (port, conns)
    }

    fn ask(url: &str, port: u16, verify: bool) -> Result<Message, TransportError> {
        let via = SecureServer::parse(url, verify).unwrap();
        let q = corerouter_proto_dns::encrypted::query(
            &hickory_proto::rr::Name::from_ascii("www.example.").unwrap(),
            hickory_proto::rr::RecordType::A,
            1232,
        )
        .unwrap();
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        exchange(addr, &via, &q, 3000).map(|b| Message::from_vec(&b).unwrap())
    }

    #[test]
    fn dot_and_doh_answer_and_reuse_the_connection() {
        for (doh, url) in [(false, "tls://127.0.0.1#localhost"), (true, "https://localhost/dns-query")] {
            let (port, conns) = server(doh);
            let url = url.replacen("1#", &format!("1:{port}#"), 1).replacen("localhost/", &format!("localhost:{port}/"), 1);
            // Self-signed: refused when verified (RFC 8310 strict), never
            // sent in the clear instead.
            let err = ask(&url, port, true).unwrap_err();
            assert!(err.to_string().to_lowercase().contains("cert"), "{err}");
            for _ in 0..3 {
                let m = ask(&url, port, false).unwrap();
                assert_eq!(m.metadata.id, 0);
                assert_eq!(m.answers[0].data.to_string(), "192.0.2.99");
            }
            // One refused handshake, then one connection for three queries.
            assert_eq!(conns.load(Ordering::SeqCst), 2, "{url}");
        }
    }

    #[test]
    fn the_router_resolves_through_use_doh_server() {
        use corerouter_engine::dns::DnsBackend;
        use corerouter_model::dns::Dns;
        use corerouter_proto_dns::resolver::Settings;
        for doh in [false, true] {
            let (port, _) = server(doh);
            let url = if doh {
                format!("https://127.0.0.1:{port}/dns-query")
            } else {
                format!("tls://127.0.0.1:{port}")
            };
            let dns = super::super::dns::RouterDns::new();
            let d = Dns {
                use_doh_server: url.clone(),
                verify_doh_cert: false,
                ..Dns::default()
            };
            dns.resolver.configure(Settings::new(&d, &[]), dns.now_ms());
            assert_eq!(
                dns.lookup("www.example").unwrap()[0],
                "192.0.2.99".parse::<std::net::IpAddr>().unwrap(),
                "{url}"
            );
        }
    }
}
