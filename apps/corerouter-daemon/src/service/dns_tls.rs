//! DNS over TLS (RFC 7858) and DNS over HTTPS (RFC 8484) for the LAN
//! (G4.1zf): `ip.dns.encrypted-service dot=yes` / `doh=yes` with
//! `allow_remote_requests`. The queries go down the same chain as UDP/TCP
//! 53 (`dns_server::Answer`): ACL, limits, statics, adlists, zones, cache,
//! upstream.
//!
//! Why an event loop and not a thread per connection like TCP 53: Android's
//! automatic Private DNS moves every phone of the LAN to port 853 as soon as
//! it answers, and keeps the connection while it is busy (it closes it
//! after 20 s idle); a provider whose CPEs hand out the router's address
//! sees tens of thousands. A connection here is its rustls state and a
//! socket (~8 KiB in all with 2000 open, **medido**), not a thread.
//!
//! - "dns-tls": every second follows the running config (on/off, ports,
//!   path, certificate: a new one serves the next connections), opens and
//!   closes the loops, publishes [`EncryptedStatus`].
//! - "dns-tls-N": up to four event loops (`mio`); loop 0 also accepts on
//!   both ports and hands the connections out in turn. A peer that may not
//!   ask (`dns_server::may_connect`) is closed at accept, before any TLS.
//! - DoT: each message with its 2-byte length (RFC 7858 §3.3), pipelined:
//!   up to [`MAX_IN_FLIGHT`] at once, cache hits answered at once and
//!   misses when their worker is done, so answers go out of order (RFC 7766
//!   §6.2.1.1, §7). The idle timer restarts only on a whole message
//!   (§6.2.3); a message must arrive whole within [`MESSAGE`].
//! - DoH: ALPN `h2` gets HTTP/2 (`http2::server`: up to 100 streams,
//!   answered in any order), anything else HTTP/1.1, one request at a time
//!   (`dns_doh`). GET and POST on `doh_path` (RFC 8484 §4.1).
//! - Over `max_sessions`, the connection of this loop idle the longest
//!   gives its place (RFC 7766 §6.2.3 allows closing at once under load;
//!   the stalled-connection lesson of G4.1w); one address holds at most a
//!   quarter of the places (CGNAT and CPEs: loose, §6.2.2).
//! - TLS 1.2 and 1.3 (rustls: AEAD with forward secrecy only, RFC 9325),
//!   no 0-RTT (§3.10; RFC 8470), ALPN `dot` on DoT and `h2`/`http/1.1` on
//!   DoH (§3.8), stateless tickets rotated by rustls (RFC 8310 §9), the
//!   whole chain sent (`identity_from_pem`), `close_notify` on close (RFC
//!   7858 §3.4). Bytes that are not TLS never get a DNS answer (§3.1).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::{Shared, lock};
use corerouter_model::dns_encrypted::EncryptedStatus;
use corerouter_model::service::Listen;
use mio::net::{TcpListener, TcpStream};
use mio::{Events, Interest, Poll, Token, Waker};
use rustls::{ServerConfig, ServerConnection};

use super::dns_doh::{self, Doh};
use super::dns_server::{self, Answer, Server};
use super::http2::server as h2;

/// How often the follow thread looks at the config.
const TICK: Duration = if cfg!(test) { Duration::from_millis(50) } else { Duration::from_secs(1) };
/// A loop's longest sleep: the stop signal and the timers are looked at
/// this often.
const POLL: Duration = Duration::from_millis(250);
/// The TLS handshake, from accept to done.
const HANDSHAKE: Duration = Duration::from_secs(10);
/// A message (or an HTTP request), from its first byte to its last.
const MESSAGE: Duration = Duration::from_secs(10);
/// DoT queries of one connection waiting for an answer; more are read once
/// some are answered (TCP pushes back on the client meanwhile).
const MAX_IN_FLIGHT: usize = 64;
/// Plaintext waiting to be framed (two messages and a bit).
const MAX_INBOX: usize = 2 * (2 + 65_535) + 4096;
/// Answers rustls holds for a client that does not read; past it, closed.
const MAX_OUTBOX: usize = 256 * 1024;
/// Loop 0's listeners take tokens below this; the waker is next.
const LISTENERS: usize = 8;
const WAKE: Token = Token(LISTENERS);
const FIRST_CONN: usize = LISTENERS + 1;

/// Which service a listener (and its connections) is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Dot,
    Doh,
}

/// What the loops share.
struct Shared2 {
    srv: Arc<Server>,
    /// The TLS configurations of the next connections (DoT, DoH: they
    /// differ in ALPN).
    tls: Mutex<(Arc<ServerConfig>, Arc<ServerConfig>)>,
    doh_path: Mutex<String>,
    idle: AtomicU64,
    max_sessions: AtomicUsize,
    sessions: AtomicUsize,
    per_source: Mutex<HashMap<IpAddr, usize>>,
    epoch: AtomicU64,
    stats: Stats,
}

#[derive(Default)]
struct Stats {
    accepted: AtomicU64,
    handshakes: AtomicU64,
    resumed: AtomicU64,
    handshake_failures: AtomicU64,
    queries: AtomicU64,
    doh_queries: AtomicU64,
    doh_errors: AtomicU64,
    http2: AtomicU64,
    refused: AtomicU64,
    over_limit: AtomicU64,
}

fn n(a: &AtomicU64) -> u64 {
    a.load(Ordering::Relaxed)
}

fn bump(a: &AtomicU64) {
    a.fetch_add(1, Ordering::Relaxed);
}

/// A connection's places (all, and its address's), given back on drop.
struct Place {
    sh: Arc<Shared2>,
    ip: IpAddr,
}

impl Place {
    fn take(sh: &Arc<Shared2>, ip: IpAddr) -> Option<Self> {
        let max = sh.max_sessions.load(Ordering::Relaxed);
        let mut per = sh.per_source.lock().unwrap_or_else(PoisonError::into_inner);
        let mine = per.entry(ip).or_insert(0);
        if *mine >= (max / 4).max(1) {
            return None;
        }
        *mine += 1;
        sh.sessions.fetch_add(1, Ordering::AcqRel);
        Some(Self { sh: sh.clone(), ip })
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        self.sh.sessions.fetch_sub(1, Ordering::AcqRel);
        let mut per = self.sh.per_source.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(c) = per.get_mut(&self.ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                per.remove(&self.ip);
            }
        }
    }
}

/// What reaches a loop from elsewhere.
enum Mail {
    /// A connection loop 0 accepted for this loop.
    Conn(TcpStream, IpAddr, Place, Kind),
    /// A miss answered: (connection, its generation, the HTTP/2 stream or
    /// 0, the reply).
    Reply(usize, u64, u32, Option<Vec<u8>>),
}

struct Inbox {
    tx: Sender<Mail>,
    waker: Arc<Waker>,
}

impl Inbox {
    fn send(&self, m: Mail) {
        if self.tx.send(m).is_ok() {
            let _ = self.waker.wake();
        }
    }
}

/// What a connection speaks once its handshake is done.
enum Proto {
    /// Not decided yet (handshaking).
    Tls,
    Dot,
    H2(Box<h2::Server>),
    /// HTTP/1.1: one request at a time; `close` after its answer.
    H1 { busy: bool, close: bool },
}

struct Conn {
    sock: TcpStream,
    tls: ServerConnection,
    peer: IpAddr,
    kind: Kind,
    proto: Proto,
    /// Tells a reply for this connection from one for an older one that
    /// had the same token.
    generation: u64,
    inbox: Vec<u8>,
    in_flight: usize,
    opened: Instant,
    /// The last whole message or request (or the handshake's end).
    last: Instant,
    partial_since: Option<Instant>,
    writable: bool,
    /// Close once what is queued is sent (HTTP/1.1 `close`, GOAWAY).
    closing: bool,
    _place: Place,
}

/// What a connection does after an event.
#[derive(PartialEq, Eq)]
enum Fate {
    Keep,
    Close,
}

impl Conn {
    fn handshaken(&self) -> bool {
        !matches!(self.proto, Proto::Tls)
    }

    /// Reads what the socket has into rustls, and the plaintext out.
    fn read(&mut self, sh: &Shared2) -> Fate {
        loop {
            match self.tls.read_tls(&mut self.sock) {
                Ok(0) => return Fate::Close,
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Fate::Close,
            }
            if self.tls.process_new_packets().is_err() {
                // The alert goes out; not TLS never gets a DNS answer
                // (RFC 7858 §3.1).
                let _ = self.flush();
                if !self.handshaken() {
                    bump(&sh.stats.handshake_failures);
                }
                return Fate::Close;
            }
        }
        if !self.handshaken() && !self.tls.is_handshaking() {
            self.last = Instant::now();
            bump(&sh.stats.handshakes);
            if self.tls.handshake_kind() == Some(rustls::HandshakeKind::Resumed) {
                bump(&sh.stats.resumed);
            }
            self.proto = match (self.kind, self.tls.alpn_protocol()) {
                (Kind::Dot, _) => Proto::Dot,
                (Kind::Doh, Some(b"h2")) => {
                    bump(&sh.stats.http2);
                    Proto::H2(Box::default())
                }
                (Kind::Doh, _) => Proto::H1 { busy: false, close: false },
            };
        }
        let mut chunk = [0u8; 4096];
        loop {
            match self.tls.reader().read(&mut chunk) {
                Ok(0) => return Fate::Close, // close_notify
                Ok(k) => {
                    self.inbox.extend_from_slice(chunk.get(..k).unwrap_or_default());
                    if self.inbox.len() > MAX_INBOX {
                        return Fate::Close;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Fate::Keep,
                Err(_) => return Fate::Close,
            }
        }
    }

    /// Plaintext to the client.
    fn send(&mut self, bytes: &[u8]) -> Fate {
        if bytes.is_empty() {
            return Fate::Keep;
        }
        match self.tls.writer().write_all(bytes) {
            Ok(()) => Fate::Keep,
            // Over MAX_OUTBOX: a client that does not read its answers.
            Err(_) => Fate::Close,
        }
    }

    /// One framed DoT answer, in one write (RFC 7858 §3.3).
    fn dot_answer(&mut self, reply: &[u8]) -> Fate {
        let Ok(len) = u16::try_from(reply.len()) else {
            return Fate::Close;
        };
        let mut framed = Vec::with_capacity(reply.len() + 2);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(reply);
        self.send(&framed)
    }

    /// The DoH answer of `stream` (0: HTTP/1.1): 200 with the message, or
    /// the HTTP error (a reply the chain refused to give: 400).
    fn doh_answer(&mut self, sh: &Shared2, stream: u32, reply: Result<Vec<u8>, (u16, &'static str)>) -> Fate {
        let (status, body, headers) = match reply {
            Ok(r) => {
                let h = dns_doh::answer_headers(&r);
                (200u16, r, h.to_vec())
            }
            Err((status, why)) => {
                bump(&sh.stats.doh_errors);
                (status, why.as_bytes().to_vec(), vec![("content-type", "text/plain".to_owned())])
            }
        };
        let refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        match &mut self.proto {
            Proto::H2(s) => {
                s.respond(stream, status, &refs, &body);
                let out = s.take_out();
                self.send(&out)
            }
            Proto::H1 { busy, close } => {
                *busy = false;
                let out = dns_doh::h1_response(status, &refs, &body, *close);
                if *close {
                    self.closing = true;
                }
                self.send(&out)
            }
            Proto::Dot | Proto::Tls => Fate::Close,
        }
    }

    /// Sends what rustls has; remembers whether the socket must say when
    /// it can take more.
    fn flush(&mut self) -> Fate {
        while self.tls.wants_write() {
            match self.tls.write_tls(&mut self.sock) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    self.writable = true;
                    return Fate::Keep;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Fate::Close,
            }
        }
        self.writable = false;
        if self.closing { Fate::Close } else { Fate::Keep }
    }

    /// One query to the chain; `stream` names it when it comes back.
    fn ask(&mut self, sh: &Shared2, me: usize, inbox: &Arc<Inbox>, msg: &[u8], stream: u32) -> Option<Option<Vec<u8>>> {
        let now = Instant::now();
        let (tx, generation) = (inbox.clone(), self.generation);
        let then: dns_server::Then = Box::new(move |reply| tx.send(Mail::Reply(me, generation, stream, reply)));
        match Answer::ask(&sh.srv, msg, self.peer, now, then) {
            Answer::Now(r) => Some(r),
            Answer::Later => {
                self.in_flight += 1;
                None
            }
        }
    }

    /// What came in, served as the connection's protocol says.
    fn serve(&mut self, sh: &Shared2, me: usize, inbox: &Arc<Inbox>) -> Fate {
        match self.proto {
            Proto::Tls => Fate::Keep,
            Proto::Dot => self.serve_dot(sh, me, inbox),
            Proto::H2(_) => self.serve_h2(sh, me, inbox),
            Proto::H1 { .. } => self.serve_h1(sh, me, inbox),
        }
    }

    /// The whole DoT messages in the inbox go to the chain, while fewer
    /// than [`MAX_IN_FLIGHT`] wait.
    fn serve_dot(&mut self, sh: &Shared2, me: usize, inbox: &Arc<Inbox>) -> Fate {
        while self.in_flight < MAX_IN_FLIGHT {
            let (Some(hi), Some(lo)) = (self.inbox.first().copied(), self.inbox.get(1).copied()) else {
                break;
            };
            let len = usize::from(u16::from_be_bytes([hi, lo]));
            let Some(msg) = self.inbox.get(2..2 + len).map(<[u8]>::to_vec) else {
                self.partial_since.get_or_insert_with(Instant::now);
                break;
            };
            self.inbox.drain(..2 + len);
            let now = Instant::now();
            self.last = now;
            self.partial_since = (!self.inbox.is_empty()).then_some(now);
            bump(&sh.stats.queries);
            match self.ask(sh, me, inbox, &msg, 0) {
                Some(Some(r)) => {
                    if self.dot_answer(&r) == Fate::Close {
                        return Fate::Close;
                    }
                }
                // Junk or over the per-client limit: the connection ends.
                Some(None) => return Fate::Close,
                None => {}
            }
        }
        Fate::Keep
    }

    /// One DoH request: the chain, or its HTTP error at once.
    fn doh_request(&mut self, sh: &Shared2, me: usize, inbox: &Arc<Inbox>, stream: u32, what: Doh) -> Fate {
        self.last = Instant::now();
        match what {
            Doh::Reject(status, why) => self.doh_answer(sh, stream, Err((status, why))),
            Doh::Query(msg) => {
                bump(&sh.stats.doh_queries);
                match self.ask(sh, me, inbox, &msg, stream) {
                    Some(Some(r)) => self.doh_answer(sh, stream, Ok(r)),
                    // Junk the chain would not answer: 400 (§4.2.1: only a
                    // DNS answer is a 2xx).
                    Some(None) => self.doh_answer(sh, stream, Err((400, "not a DNS query"))),
                    None => Fate::Keep,
                }
            }
        }
    }

    fn serve_h2(&mut self, sh: &Shared2, me: usize, inbox: &Arc<Inbox>) -> Fate {
        let bytes = std::mem::take(&mut self.inbox);
        let Proto::H2(s) = &mut self.proto else { return Fate::Close };
        let got = s.receive(&bytes);
        let out = s.take_out();
        if self.send(&out) == Fate::Close {
            return Fate::Close;
        }
        let requests = match got {
            Ok(r) => r,
            Err(_) => {
                // GOAWAY is queued: out, then closed.
                self.closing = true;
                return Fate::Keep;
            }
        };
        let path = sh.doh_path.lock().unwrap_or_else(PoisonError::into_inner).clone();
        for r in requests {
            let what = dns_doh::parse(&r.method, &r.path, r.content_type.as_deref(), &r.body, r.too_big, &path);
            if self.doh_request(sh, me, inbox, r.stream, what) == Fate::Close {
                return Fate::Close;
            }
        }
        Fate::Keep
    }

    fn serve_h1(&mut self, sh: &Shared2, me: usize, inbox: &Arc<Inbox>) -> Fate {
        let Proto::H1 { busy, .. } = self.proto else { return Fate::Close };
        if busy || self.inbox.is_empty() {
            return Fate::Keep;
        }
        match dns_doh::h1_request(&self.inbox) {
            Ok(None) => {
                self.partial_since.get_or_insert_with(Instant::now);
                Fate::Keep
            }
            Err(status) => {
                if let Proto::H1 { close, .. } = &mut self.proto {
                    *close = true;
                }
                self.inbox.clear();
                self.doh_answer(sh, 0, Err((status, "bad request")))
            }
            Ok(Some((req, used))) => {
                self.inbox.drain(..used);
                self.partial_since = None;
                if let Proto::H1 { busy, close } = &mut self.proto {
                    *busy = true;
                    *close = req.close;
                }
                let path = sh.doh_path.lock().unwrap_or_else(PoisonError::into_inner).clone();
                let what = dns_doh::parse(&req.method, &req.path, req.content_type.as_deref(), &req.body, req.too_big, &path);
                self.doh_request(sh, me, inbox, 0, what)
            }
        }
    }

    fn interest(&self) -> Interest {
        if self.writable { Interest::READABLE | Interest::WRITABLE } else { Interest::READABLE }
    }

    /// `close_notify` (RFC 7858 §3.4: the client keeps the TIME-WAIT), and
    /// GOAWAY first on HTTP/2; best effort.
    fn close(mut self) {
        if let Proto::H2(s) = &mut self.proto {
            s.goaway(h2::NO_ERROR);
            let out = s.take_out();
            let _ = self.tls.writer().write_all(&out);
        }
        self.tls.send_close_notify();
        self.closing = false;
        let _ = self.flush();
        let _ = self.sock.shutdown(std::net::Shutdown::Both);
    }
}

/// One event loop.
struct Loop {
    sh: Arc<Shared2>,
    poll: Poll,
    inbox: Arc<Inbox>,
    rx: Receiver<Mail>,
    conns: HashMap<usize, Conn>,
    next: usize,
    generation: u64,
}

impl Loop {
    fn new(sh: Arc<Shared2>) -> std::io::Result<Self> {
        let poll = Poll::new()?;
        let waker = Arc::new(Waker::new(poll.registry(), WAKE)?);
        let (tx, rx) = channel();
        Ok(Self { sh, poll, inbox: Arc::new(Inbox { tx, waker }), rx, conns: HashMap::new(), next: FIRST_CONN, generation: 0 })
    }

    fn add(&mut self, mut sock: TcpStream, peer: IpAddr, place: Place, kind: Kind) {
        let cfg = {
            let tls = self.sh.tls.lock().unwrap_or_else(PoisonError::into_inner);
            match kind {
                Kind::Dot => tls.0.clone(),
                Kind::Doh => tls.1.clone(),
            }
        };
        let Ok(mut tls) = ServerConnection::new(cfg) else {
            return;
        };
        tls.set_buffer_limit(Some(MAX_OUTBOX));
        let _ = sock.set_nodelay(true);
        let id = self.next;
        self.next = self.next.wrapping_add(1).max(FIRST_CONN);
        if self.poll.registry().register(&mut sock, Token(id), Interest::READABLE).is_err() {
            return;
        }
        self.generation = self.generation.wrapping_add(1);
        let now = Instant::now();
        self.conns.insert(
            id,
            Conn {
                sock,
                tls,
                peer,
                kind,
                proto: Proto::Tls,
                generation: self.generation,
                inbox: Vec::new(),
                in_flight: 0,
                opened: now,
                last: now,
                partial_since: None,
                writable: false,
                closing: false,
                _place: place,
            },
        );
    }

    fn drop_conn(&mut self, id: usize) {
        if let Some(mut c) = self.conns.remove(&id) {
            let _ = self.poll.registry().deregister(&mut c.sock);
            c.close();
        }
    }

    /// After anything happened to `id`: serve what came, send, re-arm.
    fn settle(&mut self, id: usize, fate: Fate) {
        let (sh, inbox) = (self.sh.clone(), self.inbox.clone());
        let fate = match (fate, self.conns.get_mut(&id)) {
            (Fate::Keep, Some(c)) => {
                if c.serve(&sh, id, &inbox) == Fate::Keep { c.flush() } else { Fate::Close }
            }
            (_, None) => return,
            (f, Some(_)) => f,
        };
        if fate == Fate::Close {
            self.drop_conn(id);
            return;
        }
        if let Some(c) = self.conns.get_mut(&id) {
            let interest = c.interest();
            if self.poll.registry().reregister(&mut c.sock, Token(id), interest).is_err() {
                self.drop_conn(id);
            }
        }
    }

    /// The connection idle the longest, to make room (no query waiting).
    fn evict_one(&mut self) -> bool {
        let oldest = self.conns.iter().filter(|(_, c)| c.in_flight == 0).min_by_key(|(_, c)| c.last).map(|(id, _)| *id);
        match oldest {
            Some(id) => {
                self.drop_conn(id);
                true
            }
            None => false,
        }
    }

    fn mail(&mut self) {
        while let Ok(m) = self.rx.try_recv() {
            match m {
                Mail::Conn(sock, peer, place, kind) => self.add(sock, peer, place, kind),
                Mail::Reply(id, generation, stream, reply) => {
                    let sh = self.sh.clone();
                    let Some(c) = self.conns.get_mut(&id).filter(|c| c.generation == generation) else {
                        continue;
                    };
                    c.in_flight = c.in_flight.saturating_sub(1);
                    let fate = match (&c.proto, reply) {
                        (Proto::Dot, Some(r)) => c.dot_answer(&r),
                        (Proto::Dot | Proto::Tls, None) => Fate::Close,
                        (_, Some(r)) => c.doh_answer(&sh, stream, Ok(r)),
                        (_, None) => c.doh_answer(&sh, stream, Err((400, "not a DNS query"))),
                    };
                    self.settle(id, fate);
                }
            }
        }
    }

    /// Handshakes, messages and idle connections past their time.
    fn timers(&mut self) {
        let idle = Duration::from_secs(self.sh.idle.load(Ordering::Relaxed));
        let now = Instant::now();
        let late: Vec<(usize, bool)> = self
            .conns
            .iter()
            .filter_map(|(id, c)| {
                let handshake = !c.handshaken() && now.duration_since(c.opened) > HANDSHAKE;
                let message = c.partial_since.is_some_and(|t| now.duration_since(t) > MESSAGE);
                let waiting = c.in_flight > 0 || matches!(&c.proto, Proto::H2(s) if s.waiting() > 0);
                let quiet = !waiting && now.duration_since(c.last) > idle;
                (handshake || message || quiet).then_some((*id, handshake))
            })
            .collect();
        for (id, handshake) in late {
            if handshake {
                bump(&self.sh.stats.handshake_failures);
            }
            self.drop_conn(id);
        }
    }

    fn run(mut self, listeners: Vec<(std::net::TcpListener, Kind)>, others: Vec<Arc<Inbox>>, epoch: u64) {
        let mut ls: Vec<(TcpListener, Kind)> = Vec::new();
        for (i, (l, kind)) in listeners.into_iter().take(LISTENERS).enumerate() {
            let mut l = TcpListener::from_std(l);
            if self.poll.registry().register(&mut l, Token(i), Interest::READABLE).is_ok() {
                ls.push((l, kind));
            }
        }
        let mut turn = 0usize;
        let mut events = Events::with_capacity(256);
        let mut swept = Instant::now();
        while self.sh.epoch.load(Ordering::Acquire) == epoch {
            if let Err(e) = self.poll.poll(&mut events, Some(POLL))
                && e.kind() != std::io::ErrorKind::Interrupted
            {
                log::warn!("DNS over TLS/HTTPS: poll: {e}");
                thread::sleep(POLL);
            }
            for ev in &events {
                let Token(t) = ev.token();
                if t < LISTENERS {
                    if let Some((l, kind)) = ls.get(t) {
                        turn = self.accept(l, *kind, &others, turn);
                    }
                } else if t != WAKE.0 {
                    let fate = match self.conns.get_mut(&t) {
                        Some(c) if ev.is_readable() || ev.is_read_closed() || ev.is_error() => c.read(&self.sh),
                        Some(_) => Fate::Keep,
                        None => continue,
                    };
                    self.settle(t, fate);
                }
            }
            self.mail();
            if swept.elapsed() >= POLL {
                swept = Instant::now();
                self.timers();
            }
        }
        let ids: Vec<usize> = self.conns.keys().copied().collect();
        for id in ids {
            self.drop_conn(id);
        }
    }

    /// Takes every waiting connection off `l`; hands each to the next loop
    /// in turn (this one included). The new value of the turn.
    fn accept(&mut self, l: &TcpListener, kind: Kind, others: &[Arc<Inbox>], mut turn: usize) -> usize {
        loop {
            let (sock, at) = match l.accept() {
                Ok(got) => got,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return turn,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    log::debug!("DNS over TLS/HTTPS: accept: {e}");
                    return turn;
                }
            };
            let peer = at.ip().to_canonical();
            if !dns_server::may_connect(&self.sh.srv, peer) {
                bump(&self.sh.stats.refused);
                continue;
            }
            bump(&self.sh.stats.accepted);
            let max = self.sh.max_sessions.load(Ordering::Relaxed);
            if self.sh.sessions.load(Ordering::Acquire) >= max && !self.evict_one() {
                bump(&self.sh.stats.over_limit);
                continue;
            }
            let Some(place) = Place::take(&self.sh, peer) else {
                bump(&self.sh.stats.over_limit);
                continue;
            };
            turn = turn.wrapping_add(1);
            match others.get(turn % (others.len() + 1)) {
                Some(other) => other.send(Mail::Conn(sock, peer, place, kind)),
                None => self.add(sock, peer, place, kind),
            }
        }
    }
}

/// The TLS configurations from a `/certificate`: its chain and key,
/// stateless tickets (RFC 8310 §9), no early data; ALPN `dot` (RFC 7858 /
/// IANA) for DoT, `h2` then `http/1.1` for DoH. The fingerprint served.
fn tls_configs(cert: &str, key: &str) -> Result<Configs, String> {
    let id = corerouter_control::tls::identity_from_pem(cert.as_bytes(), key.as_bytes())?;
    let mut dot = (*id.config).clone();
    dot.ticketer = rustls::crypto::ring::Ticketer::new().map_err(|e| format!("session tickets: {e}"))?;
    dot.max_early_data_size = 0;
    let mut doh = dot.clone();
    dot.alpn_protocols = vec![b"dot".to_vec()];
    doh.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(((Arc::new(dot), Arc::new(doh)), id.fingerprint))
}

/// The TLS configurations of DoT and DoH, and the fingerprint served.
type Configs = ((Arc<ServerConfig>, Arc<ServerConfig>), String);

/// What the follow thread wants now.
#[derive(Clone, PartialEq, Eq)]
struct Want {
    dot: Option<u16>,
    doh: Option<u16>,
    doh_path: String,
    certificate: String,
    /// The PEM, so a certificate replaced under the same name is seen.
    pem: Option<String>,
}

impl Want {
    fn on(&self) -> bool {
        self.dot.is_some() || self.doh.is_some()
    }
}

fn want(session: &Shared) -> (Want, u64, usize) {
    let s = lock(session);
    let running = s.store().running();
    let e = &running.ip.dns.encrypted_service;
    let lan = running.ip.dns.allow_remote_requests;
    let w = Want {
        dot: (lan && e.dot).then_some(e.dot_port),
        doh: (lan && e.doh).then_some(e.doh_port),
        doh_path: e.doh_path.clone(),
        certificate: e.certificate.clone(),
        pem: running.system.certificates.get(&e.certificate).map(|c| c.certificate.clone()),
    };
    let max = usize::try_from(e.max_sessions).unwrap_or(usize::MAX);
    (w, u64::from(e.idle_timeout_secs), max)
}

fn open(sh: &Arc<Shared2>, ports: &[(u16, Kind)], lab: bool, epoch: u64) -> Result<Vec<(SocketAddr, Kind)>, String> {
    let mut listeners = Vec::new();
    let mut at = Vec::new();
    for &(port, kind) in ports {
        for ip in dns_server::listen_ips(lab) {
            let addr = SocketAddr::new(ip, port);
            let l = bind(addr).map_err(|e| format!("cannot listen on {addr}: {e}"))?;
            at.push((l.local_addr().unwrap_or(addr), kind));
            listeners.push((l, kind));
        }
    }
    let loops = dns_server::udp_threads();
    let mut built = Vec::new();
    for _ in 0..loops {
        built.push(Loop::new(sh.clone()).map_err(|e| format!("event loop: {e}"))?);
    }
    let mut built = built.into_iter();
    let first = built.next().ok_or("no event loop")?;
    let rest: Vec<Loop> = built.collect();
    let others: Vec<Arc<Inbox>> = rest.iter().map(|l| l.inbox.clone()).collect();
    for (i, l) in rest.into_iter().enumerate() {
        thread::Builder::new()
            .name(format!("dns-tls-{}", i + 1))
            .spawn(move || l.run(Vec::new(), Vec::new(), epoch))
            .map_err(|e| format!("thread: {e}"))?;
    }
    thread::Builder::new()
        .name("dns-tls-0".into())
        .spawn(move || first.run(listeners, others, epoch))
        .map_err(|e| format!("thread: {e}"))?;
    Ok(at)
}

/// A listening socket of one family (IPv6 only on `::`, as TCP 53).
fn bind(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
    let s = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    s.set_reuse_address(true)?;
    if addr.is_ipv6() {
        s.set_only_v6(true)?;
    }
    s.bind(&addr.into())?;
    s.listen(1024)?;
    s.set_nonblocking(true)?;
    Ok(s.into())
}

fn status(sh: &Shared2, st: &mut EncryptedStatus) {
    st.sessions = u64::try_from(sh.sessions.load(Ordering::Relaxed)).unwrap_or(u64::MAX);
    st.accepted = n(&sh.stats.accepted);
    st.handshakes = n(&sh.stats.handshakes);
    st.resumed = n(&sh.stats.resumed);
    st.handshake_failures = n(&sh.stats.handshake_failures);
    st.queries = n(&sh.stats.queries);
    st.doh_queries = n(&sh.stats.doh_queries);
    st.doh_errors = n(&sh.stats.doh_errors);
    st.http2 = n(&sh.stats.http2);
    st.refused = n(&sh.stats.refused);
    st.over_limit = n(&sh.stats.over_limit);
}

fn publish(session: &Shared, st: &EncryptedStatus) {
    let mut s = lock(session);
    if s.ext::<EncryptedStatus>() != Some(st)
        && let Some(slot) = s.ext_mut::<EncryptedStatus>()
    {
        *slot = st.clone();
    }
}

fn served(session: &Shared, name: &str) -> Result<Configs, String> {
    let pair = corerouter_engine::x509::served(&mut lock(session), name)?;
    let (c, k) = pair.ok_or("no certificate")?;
    tls_configs(&c, &k).map_err(|e| format!("certificate {name}: {e}"))
}

/// Follows the config: opens, closes and re-keys the service.
fn follow(session: &Shared, srv: Arc<Server>, health: &super::Health, lab: bool) {
    let mut sh: Option<Arc<Shared2>> = None;
    let mut last: Option<Want> = None;
    let mut st = EncryptedStatus { status: "stopped".into(), ..EncryptedStatus::default() };
    let mut retry_at: Option<Instant> = None;
    while !health.stopping() {
        health.beat();
        let (w, idle, max) = want(session);
        if let Some(s) = &sh {
            s.idle.store(idle, Ordering::Relaxed);
            s.max_sessions.store(max, Ordering::Relaxed);
            w.doh_path.clone_into(&mut s.doh_path.lock().unwrap_or_else(PoisonError::into_inner));
        }
        let changed = last.as_ref() != Some(&w);
        let reopen = last.as_ref().is_none_or(|l| l.dot != w.dot || l.doh != w.doh);
        if changed {
            if reopen {
                if let Some(s) = sh.take() {
                    s.epoch.fetch_add(1, Ordering::AcqRel);
                    st = EncryptedStatus { status: "stopped".into(), ..EncryptedStatus::default() };
                    health.listen(Vec::new());
                }
            } else if let Some(s) = &sh {
                // A new certificate serves the next connections; the open
                // ones keep theirs.
                match served(session, &w.certificate) {
                    Ok((c, fp)) => {
                        *s.tls.lock().unwrap_or_else(PoisonError::into_inner) = c;
                        st.fingerprint = Some(fp);
                        st.last_error = None;
                    }
                    Err(e) => {
                        health.error(&e);
                        st.last_error = Some(e);
                    }
                }
            }
            last = Some(w.clone());
            retry_at = None;
        }
        let due = retry_at.is_none_or(|t| Instant::now() >= t);
        if w.on() && sh.is_none() && due {
            match served(session, &w.certificate) {
                Err(e) => {
                    st.status = "error".into();
                    health.error(&e);
                    st.last_error = Some(e);
                    retry_at = Some(Instant::now() + Duration::from_secs(10));
                }
                Ok((tls, fp)) => {
                    let s = Arc::new(Shared2 {
                        srv: srv.clone(),
                        tls: Mutex::new(tls),
                        doh_path: Mutex::new(w.doh_path.clone()),
                        idle: AtomicU64::new(idle),
                        max_sessions: AtomicUsize::new(max),
                        sessions: AtomicUsize::new(0),
                        per_source: Mutex::new(HashMap::new()),
                        epoch: AtomicU64::new(0),
                        stats: Stats::default(),
                    });
                    let ports: Vec<(u16, Kind)> = [(w.dot, Kind::Dot), (w.doh, Kind::Doh)]
                        .into_iter()
                        .filter_map(|(p, k)| p.map(|p| (p, k)))
                        .collect();
                    match open(&s, &ports, lab, 0) {
                        Ok(at) => {
                            let ports_text: Vec<String> = ports.iter().map(|(p, k)| format!("{} {p}", if *k == Kind::Dot { "DoT" } else { "DoH" })).collect();
                            log::info!("DNS over TLS/HTTPS: answering the LAN ({})", ports_text.join(", "));
                            health.event(format!("encrypted DNS: {}", ports_text.join(", ")));
                            health.listen(at.iter().map(|(a, k)| Listen::new(if *k == Kind::Dot { "tls" } else { "https" }, *a)).collect());
                            health.clear_error();
                            st = EncryptedStatus {
                                status: "listening".into(),
                                listening: at.iter().map(|(a, _)| a.to_string()).collect(),
                                fingerprint: Some(fp),
                                ..EncryptedStatus::default()
                            };
                            sh = Some(s);
                        }
                        Err(e) => {
                            s.epoch.fetch_add(1, Ordering::AcqRel);
                            log::error!("DNS over TLS/HTTPS: {e}; retrying in 10 s");
                            health.error(format!("{e}; retrying in 10 s"));
                            st.status = "error".into();
                            st.last_error = Some(e);
                            retry_at = Some(Instant::now() + Duration::from_secs(10));
                        }
                    }
                }
            }
        }
        if let Some(s) = &sh {
            status(s, &mut st);
        }
        health.disabled((!w.on()).then_some("ip.dns encrypted-service dot=no doh=no (or allow_remote_requests=no)"));
        publish(session, &st);
        health.sleep(TICK);
    }
    if let Some(s) = sh {
        s.epoch.fetch_add(1, Ordering::AcqRel);
    }
    publish(session, &EncryptedStatus { status: "stopped".into(), ..EncryptedStatus::default() });
}

pub(crate) const SERVICE: super::Service = super::Service {
    name: "dns-tls",
    flags: &[super::Flag {
        name: "--dot-lab-any",
        value: None,
        help: "virtual lab: DNS over TLS and HTTPS listen on every address\n(default: loopback only, as the LAN forwarder)",
    }],
    topic: "dns",
    enable: "ip.dns.encrypted-service.set dot=yes (or doh=yes)",
    depends: &["dns-server"],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let any = ctx.flag("--dot-lab-any").is_some();
    Ok(Box::new(move |health: &super::Health| {
        let Some(srv) = dns_server::server() else {
            return Err("the LAN forwarder is not running".into());
        };
        let lab = !any && dns_server::is_lab(&session);
        follow(&session, srv, health, lab);
        Ok(())
    }))
}
