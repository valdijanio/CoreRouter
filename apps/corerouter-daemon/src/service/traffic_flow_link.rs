//! Traffic Flow (G4.4j): the connection to one stream collector — IPFIX
//! over TCP (RFC 7011 §10.4), SCTP (§10.2) or TLS on TCP (§11) — on a
//! thread of its own (`tf-send-<id>`).
//!
//! The exporter thread encodes and hands the messages over
//! ([`Link::push`]); it never waits for a network: connecting, the TLS
//! handshake, encryption, a slow or dead collector all happen here. One
//! thread per collector, so each one's encryption runs on its own core and
//! one collector's trouble never delays another's.
//!
//! - The queue between them is bounded in bytes ([`QUEUE_BYTES`]); what
//!   does not fit is dropped and counted (RFC 7011 §10.2.1/§10.4.1: account
//!   for dropped export data). Dropped messages leave their gap in the
//!   sequence numbers, as §10.2.2 asks.
//! - On every new connection the templates go first (RFC 7011 §8.1), in a
//!   message without data records that carries the sequence number of the
//!   message after it ([`corerouter_proto_flow::export::set_sequence`]);
//!   the exporter is told to send the options records again.
//! - A message that failed halfway is sent again whole on the next
//!   connection (a stream collector reads whole messages by their length).
//! - SCTP: one IPFIX message per SCTP message on stream 0 (§10.2.6 allows
//!   any stream; templates and data share it), the association closed by
//!   SHUTDOWN when the collector goes away (§10.2.4). Kernel SCTP through
//!   `socket2`, no `unsafe`.
//! - TLS: rustls, TLS 1.2 or 1.3 (RFC 7011 §11.1 names 1.1, which RFC 8996
//!   deprecated), the collector's certificate checked against the target's
//!   CA and name, this router's certificate shown (mutual authentication,
//!   §11.3).

use std::collections::VecDeque;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use corerouter_model::traffic_flow::{FlowTarget, FlowTransport};
use corerouter_proto_flow::export::{sequence, set_sequence};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Messages waiting for one collector, in bytes (about 6 000 full
/// messages; 8 MiB as for TCP before).
pub(crate) const QUEUE_BYTES: usize = 8 << 20;
/// Wait between connection attempts.
const RECONNECT: Duration = Duration::from_secs(2);
/// Connecting and the TLS handshake give up after this.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// A write that blocks this long counts as a dead connection.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// IANA protocol number of SCTP.
const IPPROTO_SCTP: i32 = 132;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LinkStats {
    pub connected: bool,
    pub messages: u64,
    pub bytes: u64,
    /// Messages dropped for a full queue.
    pub dropped: u64,
    pub errors: u64,
    pub queue: u64,
    pub connects: u64,
    pub last_error: Option<String>,
}

struct Shared {
    queue: VecDeque<Vec<u8>>,
    bytes: usize,
    /// The template sets (no data records) the exporter last made.
    templates: Option<Vec<u8>>,
    stats: LinkStats,
    /// Set by the sender on a new connection; the exporter clears it when
    /// it schedules the options records again.
    reconnected: bool,
}

/// One stream collector's queue and sender thread; dropping it stops the
/// thread and closes the connection.
pub(crate) struct Link {
    shared: Arc<(Mutex<Shared>, Condvar)>,
    stop: Arc<AtomicBool>,
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Link {
    /// Start the sender of `cfg` (already validated by the engine).
    pub(crate) fn start(cfg: FlowTarget) -> Result<Self, String> {
        let tls = match cfg.transport {
            FlowTransport::Tls => Some(tls_config(&cfg)?),
            _ => None,
        };
        let shared = Arc::new((
            Mutex::new(Shared {
                queue: VecDeque::new(),
                bytes: 0,
                templates: None,
                stats: LinkStats::default(),
                reconnected: false,
            }),
            Condvar::new(),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let (sh, st) = (shared.clone(), stop.clone());
        std::thread::Builder::new()
            .name(format!("tf-send-{}", cfg.id.0))
            .spawn(move || send_loop(&cfg, tls.as_ref(), &sh, &st))
            .map_err(|e| format!("cannot start the sender: {e}"))?;
        Ok(Self { shared, stop })
    }

    /// Queue `msgs`; what does not fit is dropped and counted. `templates`
    /// is the template-only message for a new connection.
    pub(crate) fn push(&self, msgs: Vec<Vec<u8>>, templates: impl FnOnce() -> Vec<u8>) {
        let (m, cv) = &*self.shared;
        let mut sh = guard(m);
        if sh.templates.is_none() {
            sh.templates = Some(templates());
        }
        for msg in msgs {
            if sh.bytes + msg.len() > QUEUE_BYTES {
                sh.stats.dropped += 1;
                continue;
            }
            sh.bytes += msg.len();
            sh.queue.push_back(msg);
        }
        sh.stats.queue = sh.queue.len() as u64;
        drop(sh);
        cv.notify_one();
    }

    /// New templates (the exporter's set changed).
    pub(crate) fn set_templates(&self, t: Vec<u8>) {
        guard(&self.shared.0).templates = Some(t);
    }

    pub(crate) fn stats(&self) -> LinkStats {
        guard(&self.shared.0).stats.clone()
    }

    /// Whether the sender connected again since the last call.
    pub(crate) fn take_reconnected(&self) -> bool {
        std::mem::take(&mut guard(&self.shared.0).reconnected)
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.shared.1.notify_all();
    }
}

fn tls_config(cfg: &FlowTarget) -> Result<Arc<rustls::ClientConfig>, String> {
    let client = (!cfg.certificate.is_empty()).then_some((cfg.certificate.as_str(), cfg.private_key.as_str()));
    super::https::custom_tls_config(true, &cfg.ca_certificate, client)
}

/// The collector's name for the certificate check: `server_name`, or its
/// address (an IP SAN).
fn server_name(cfg: &FlowTarget) -> Result<ServerName<'static>, String> {
    if cfg.server_name.is_empty() {
        Ok(ServerName::IpAddress(cfg.dst_address.into()))
    } else {
        ServerName::try_from(cfg.server_name.clone()).map_err(|e| format!("server_name: {e}"))
    }
}

enum Conn {
    Tcp(TcpStream),
    Sctp(Socket),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Conn {
    /// One whole message.
    fn send(&mut self, msg: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.write_all(msg),
            Self::Tls(s) => s.write_all(msg).and_then(|()| s.flush()),
            // One send is one SCTP message: all of it or an error.
            Self::Sctp(s) => match s.send(msg)? {
                n if n == msg.len() => Ok(()),
                n => Err(std::io::Error::other(format!("SCTP sent {n} of {} bytes", msg.len()))),
            },
        }
    }
}

/// A socket of `kind` bound to `src` (when given) and connected to `dst`.
fn connect_socket(dst: SocketAddr, src: Option<IpAddr>, sctp: bool) -> std::io::Result<Socket> {
    let proto = if sctp { Protocol::from(IPPROTO_SCTP) } else { Protocol::TCP };
    let s = Socket::new(Domain::for_address(dst), Type::STREAM, Some(proto))?;
    if let Some(ip) = src {
        // `src_address`, over TCP too (G4.4j; std cannot bind a client).
        s.bind(&SockAddr::from(SocketAddr::new(ip, 0)))?;
    }
    s.connect_timeout(&SockAddr::from(dst), CONNECT_TIMEOUT)?;
    s.set_write_timeout(Some(WRITE_TIMEOUT))?;
    if !sctp {
        s.set_tcp_nodelay(true)?;
    }
    Ok(s)
}

fn connect(cfg: &FlowTarget, tls: Option<&Arc<rustls::ClientConfig>>) -> Result<Conn, String> {
    let dst = SocketAddr::new(cfg.dst_address, cfg.port);
    let what = cfg.transport.as_str().to_uppercase();
    let sock = connect_socket(dst, cfg.src_address, cfg.transport == FlowTransport::Sctp)
        .map_err(|e| format!("{what} connect to {dst}: {e}"))?;
    match (cfg.transport, tls) {
        (FlowTransport::Sctp, _) => Ok(Conn::Sctp(sock)),
        (FlowTransport::Tls, Some(tls)) => {
            let tcp: TcpStream = sock.into();
            let _ = tcp.set_read_timeout(Some(CONNECT_TIMEOUT));
            let mut c = ClientConnection::new(tls.clone(), server_name(cfg)?)
                .map_err(|e| format!("TLS: {e}"))?;
            let mut tcp = tcp;
            // The handshake now, so a refused certificate shows as such
            // instead of as a failed first write.
            while c.is_handshaking() {
                c.complete_io(&mut tcp).map_err(|e| format!("TLS handshake with {dst}: {e}"))?;
            }
            Ok(Conn::Tls(Box::new(StreamOwned::new(c, tcp))))
        }
        _ => Ok(Conn::Tcp(sock.into())),
    }
}

/// The sender thread: connect when needed, then send what the queue holds.
fn send_loop(cfg: &FlowTarget, tls: Option<&Arc<rustls::ClientConfig>>, shared: &(Mutex<Shared>, Condvar), stop: &AtomicBool) {
    let (m, cv) = shared;
    let mut conn: Option<Conn> = None;
    // The message being sent: out of the queue, kept until it went whole.
    let mut pending: Option<Vec<u8>> = None;
    let mut next_try = Instant::now();
    while !stop.load(Ordering::Acquire) {
        if conn.is_none() {
            let wait = next_try.saturating_duration_since(Instant::now());
            if !wait.is_zero() {
                let sh = guard(m);
                let _ = cv.wait_timeout(sh, wait);
                continue;
            }
            next_try = Instant::now() + RECONNECT;
            match connect(cfg, tls) {
                Ok(mut c) => {
                    // RFC 7011 §8.1: the templates first, numbered as the
                    // message they precede.
                    let first = {
                        let mut sh = guard(m);
                        sh.stats.connects += 1;
                        sh.reconnected = true;
                        let seq = pending.as_deref().or(sh.queue.front().map(Vec::as_slice)).and_then(sequence);
                        sh.templates.clone().map(|mut t| {
                            if let Some(seq) = seq {
                                set_sequence(&mut t, seq);
                            }
                            t
                        })
                    };
                    match first.map_or(Ok(()), |t| c.send(&t)) {
                        Ok(()) => {
                            let mut sh = guard(m);
                            sh.stats.connected = true;
                            sh.stats.last_error = None;
                            conn = Some(c);
                        }
                        Err(e) => fail(m, format!("send to {}:{}: {e}", cfg.dst_address, cfg.port)),
                    }
                }
                Err(e) => fail(m, e),
            }
            continue;
        }
        // Wait for a message (or the stop).
        if pending.is_none() {
            let mut sh = guard(m);
            while sh.queue.is_empty() && !stop.load(Ordering::Acquire) {
                sh = cv.wait_timeout(sh, Duration::from_millis(500)).map_or_else(|e| e.into_inner().0, |r| r.0);
            }
            pending = sh.queue.pop_front();
            if let Some(p) = &pending {
                sh.bytes = sh.bytes.saturating_sub(p.len());
            }
            sh.stats.queue = sh.queue.len() as u64;
        }
        let (Some(msg), Some(c)) = (pending.as_deref(), conn.as_mut()) else { continue };
        match c.send(msg) {
            Ok(()) => {
                let mut sh = guard(m);
                sh.stats.messages += 1;
                sh.stats.bytes += msg.len() as u64;
                pending = None;
            }
            Err(e) => {
                // Kept: sent again whole on the next connection.
                conn = None;
                fail(m, format!("send to {}:{}: {e}", cfg.dst_address, cfg.port));
            }
        }
    }
}

fn fail(m: &Mutex<Shared>, e: String) {
    let mut sh = guard(m);
    sh.stats.connected = false;
    sh.stats.errors += 1;
    sh.stats.last_error = Some(e);
}

/// The unspecified address of `dst`'s family (a UDP socket's bind).
pub(crate) fn any_of(dst: IpAddr) -> IpAddr {
    if dst.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    }
}
