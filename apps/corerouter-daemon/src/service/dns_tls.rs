//! DNS over TLS for the LAN (G4.1zf, RFC 7858): `ip.dns.encrypted-service
//! dot=yes` with `allow_remote_requests`. The queries go down the same chain
//! as UDP/TCP 53 (`dns_server::Answer`): ACL, limits, statics, adlists,
//! zones, cache, upstream.
//!
//! Why an event loop and not a thread per connection like TCP 53: Android's
//! automatic Private DNS moves every phone of the LAN to port 853 as soon as
//! it answers, and keeps the connection while it is busy (it closes it
//! after 20 s idle); a provider whose CPEs hand out the router's address
//! sees tens of thousands. A connection here is its rustls state (~5 KiB
//! idle, **medido**) and a socket, not a thread.
//!
//! - "dns-tls": every second follows the running config (on/off, port,
//!   certificate: a new one serves the next connections), opens and closes
//!   the loops, publishes [`EncryptedStatus`].
//! - "dns-tls-N": up to four event loops (`mio`); loop 0 also accepts and
//!   hands the connections out in turn. A peer that may not ask
//!   (`dns_server::may_connect`) is closed at accept, before any TLS.
//! - Per connection: the TLS handshake within [`HANDSHAKE`]; then each
//!   message with its 2-byte length (RFC 7858 §3.3, RFC 1035 §4.2.2),
//!   pipelined: up to [`MAX_IN_FLIGHT`] queries at once, cache hits
//!   answered at once and misses when their worker is done, so the
//!   answers go out of order (RFC 7766 §6.2.1.1, §7). The idle timer only
//!   restarts on a whole message (§6.2.3: a slow drip does not keep a
//!   connection); a message must arrive whole within [`MESSAGE`].
//! - Over `max_sessions`, the connection of this loop idle the longest
//!   gives its place (RFC 7766 §6.2.3 allows closing at once under load;
//!   the stalled-connection lesson of G4.1w); one address holds at most a
//!   quarter of the places (CGNAT and CPEs: loose, §6.2.2).
//! - TLS 1.2 and 1.3 (rustls: AEAD with forward secrecy only, RFC 9325),
//!   no 0-RTT (§3.10), ALPN `dot` when the client offers one (§3.8),
//!   resumption with stateless tickets rotated by rustls (RFC 8310 §9),
//!   the whole chain sent (`identity_from_pem`), `close_notify` on close
//!   (RFC 7858 §3.4). Bytes that are not TLS never get a DNS answer
//!   (§3.1): the handshake fails and the connection closes.

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

use super::dns_server::{self, Answer, Server};

/// How often the follow thread looks at the config.
const TICK: Duration = if cfg!(test) { Duration::from_millis(50) } else { Duration::from_secs(1) };
/// A loop's longest sleep: the stop signal and the timers are looked at
/// this often.
const POLL: Duration = Duration::from_millis(250);
/// The TLS handshake, from accept to done.
const HANDSHAKE: Duration = Duration::from_secs(10);
/// A message, from its first byte to its last.
const MESSAGE: Duration = Duration::from_secs(10);
/// Queries of one connection waiting for an answer; more are read once
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

/// What the loops share.
struct Shared2 {
    srv: Arc<Server>,
    /// The TLS configuration of the next connections.
    tls: Mutex<Arc<ServerConfig>>,
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
    Conn(TcpStream, IpAddr, Place),
    /// A miss answered: (connection, its generation, the reply).
    Reply(usize, u64, Option<Vec<u8>>),
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

struct Conn {
    sock: TcpStream,
    tls: ServerConnection,
    peer: IpAddr,
    /// Tells a reply for this connection from one for an older one that
    /// had the same token.
    generation: u64,
    inbox: Vec<u8>,
    in_flight: usize,
    opened: Instant,
    /// The last whole message (or the handshake's end).
    last: Instant,
    partial_since: Option<Instant>,
    handshaken: bool,
    writable: bool,
    _place: Place,
}

/// What a connection does after an event.
#[derive(PartialEq, Eq)]
enum Fate {
    Keep,
    Close,
}

impl Conn {
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
            if let Err(_e) = self.tls.process_new_packets() {
                // The alert goes out; not TLS never gets a DNS answer
                // (RFC 7858 §3.1).
                let _ = self.flush();
                if !self.handshaken {
                    bump(&sh.stats.handshake_failures);
                }
                return Fate::Close;
            }
        }
        if !self.handshaken && !self.tls.is_handshaking() {
            self.handshaken = true;
            self.last = Instant::now();
            bump(&sh.stats.handshakes);
            if self.tls.handshake_kind() == Some(rustls::HandshakeKind::Resumed) {
                bump(&sh.stats.resumed);
            }
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

    /// One framed answer, in one write (RFC 7858 §3.3).
    fn answer(&mut self, reply: &[u8]) -> Fate {
        let Ok(len) = u16::try_from(reply.len()) else {
            return Fate::Close;
        };
        let mut framed = Vec::with_capacity(reply.len() + 2);
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(reply);
        match self.tls.writer().write_all(&framed) {
            Ok(()) => Fate::Keep,
            // Over MAX_OUTBOX: a client that does not read its answers.
            Err(_) => Fate::Close,
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
        Fate::Keep
    }

    /// The whole messages in the inbox go to the chain, while fewer than
    /// [`MAX_IN_FLIGHT`] wait.
    fn serve(&mut self, sh: &Shared2, me: usize, inbox: &Arc<Inbox>) -> Fate {
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
            let (tx, generation) = (inbox.clone(), self.generation);
            let then: dns_server::Then = Box::new(move |reply| tx.send(Mail::Reply(me, generation, reply)));
            match Answer::ask(&sh.srv, &msg, self.peer, now, then) {
                Answer::Now(Some(r)) => {
                    if self.answer(&r) == Fate::Close {
                        return Fate::Close;
                    }
                }
                // Junk or over the per-client limit: the connection ends.
                Answer::Now(None) => return Fate::Close,
                Answer::Later => self.in_flight += 1,
            }
        }
        Fate::Keep
    }

    fn interest(&self) -> Interest {
        if self.writable { Interest::READABLE | Interest::WRITABLE } else { Interest::READABLE }
    }

    /// `close_notify` (RFC 7858 §3.4: the client keeps the TIME-WAIT), best
    /// effort.
    fn close(mut self) {
        self.tls.send_close_notify();
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

    fn add(&mut self, mut sock: TcpStream, peer: IpAddr, place: Place) {
        let cfg = self.sh.tls.lock().unwrap_or_else(PoisonError::into_inner).clone();
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
                generation: self.generation,
                inbox: Vec::new(),
                in_flight: 0,
                opened: now,
                last: now,
                partial_since: None,
                handshaken: false,
                writable: false,
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
                let served = if c.handshaken { c.serve(&sh, id, &inbox) } else { Fate::Keep };
                if served == Fate::Keep { c.flush() } else { Fate::Close }
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
                Mail::Conn(sock, peer, place) => self.add(sock, peer, place),
                Mail::Reply(id, generation, reply) => {
                    let Some(c) = self.conns.get_mut(&id).filter(|c| c.generation == generation) else {
                        continue;
                    };
                    c.in_flight = c.in_flight.saturating_sub(1);
                    let fate = match reply {
                        Some(r) => c.answer(&r),
                        None => Fate::Close,
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
                let handshake = !c.handshaken && now.duration_since(c.opened) > HANDSHAKE;
                let message = c.partial_since.is_some_and(|t| now.duration_since(t) > MESSAGE);
                let quiet = c.in_flight == 0 && now.duration_since(c.last) > idle;
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

    fn run(mut self, listeners: Vec<std::net::TcpListener>, others: Vec<Arc<Inbox>>, epoch: u64) {
        let mut ls: Vec<TcpListener> = Vec::new();
        for (i, l) in listeners.into_iter().take(LISTENERS).enumerate() {
            let mut l = TcpListener::from_std(l);
            if self.poll.registry().register(&mut l, Token(i), Interest::READABLE).is_ok() {
                ls.push(l);
            }
        }
        let mut turn = 0usize;
        let mut events = Events::with_capacity(256);
        let mut swept = Instant::now();
        while self.sh.epoch.load(Ordering::Acquire) == epoch {
            if let Err(e) = self.poll.poll(&mut events, Some(POLL))
                && e.kind() != std::io::ErrorKind::Interrupted
            {
                log::warn!("DNS over TLS: poll: {e}");
                thread::sleep(POLL);
            }
            for ev in &events {
                let Token(t) = ev.token();
                if t < LISTENERS {
                    if let Some(l) = ls.get(t) {
                        turn = self.accept(l, &others, turn);
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
    fn accept(&mut self, l: &TcpListener, others: &[Arc<Inbox>], mut turn: usize) -> usize {
        loop {
            let (sock, at) = match l.accept() {
                Ok(got) => got,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return turn,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    log::debug!("DNS over TLS: accept: {e}");
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
                Some(other) => other.send(Mail::Conn(sock, peer, place)),
                None => self.add(sock, peer, place),
            }
        }
    }
}

/// The TLS configuration from a `/certificate`: its chain and key, ALPN
/// `dot` (RFC 7858 / IANA), stateless tickets (RFC 8310 §9), no early data.
fn tls_config(cert: &str, key: &str) -> Result<(Arc<ServerConfig>, String), String> {
    let id = corerouter_control::tls::identity_from_pem(cert.as_bytes(), key.as_bytes())?;
    let mut cfg = (*id.config).clone();
    cfg.alpn_protocols = vec![b"dot".to_vec()];
    cfg.ticketer = rustls::crypto::ring::Ticketer::new().map_err(|e| format!("session tickets: {e}"))?;
    cfg.max_early_data_size = 0;
    Ok((Arc::new(cfg), id.fingerprint))
}

/// What the follow thread wants now.
#[derive(Clone, PartialEq, Eq)]
struct Want {
    on: bool,
    port: u16,
    certificate: String,
    /// The PEM, so a certificate replaced under the same name is seen.
    pem: Option<String>,
}

fn want(session: &Shared) -> (Want, u64, usize) {
    let s = lock(session);
    let running = s.store().running();
    let e = &running.ip.dns.encrypted_service;
    let w = Want {
        on: e.dot && running.ip.dns.allow_remote_requests,
        port: e.dot_port,
        certificate: e.certificate.clone(),
        pem: running.system.certificates.get(&e.certificate).map(|c| c.certificate.clone()),
    };
    let max = usize::try_from(e.max_sessions).unwrap_or(usize::MAX);
    (w, u64::from(e.idle_timeout_secs), max)
}

fn open(sh: &Arc<Shared2>, port: u16, lab: bool, epoch: u64) -> Result<Vec<SocketAddr>, String> {
    let mut listeners = Vec::new();
    let mut at = Vec::new();
    for ip in dns_server::listen_ips(lab) {
        let addr = SocketAddr::new(ip, port);
        let l = bind(addr).map_err(|e| format!("cannot listen on {addr}: {e}"))?;
        at.push(l.local_addr().unwrap_or(addr));
        listeners.push(l);
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
        }
        let changed = last.as_ref() != Some(&w);
        // A new certificate serves the next connections; the open ones keep
        // theirs.
        let cfg = if changed && w.on {
            let pair = corerouter_engine::x509::served(&mut lock(session), &w.certificate);
            match pair.and_then(|p| p.ok_or_else(|| "no certificate".to_owned())).and_then(|(c, k)| tls_config(&c, &k)) {
                Ok(c) => Some(c),
                Err(e) => {
                    st.status = "error".into();
                    st.last_error = Some(format!("certificate {}: {e}", w.certificate));
                    health.error(st.last_error.clone().unwrap_or_default());
                    None
                }
            }
        } else {
            None
        };
        let reopen = last.as_ref().is_none_or(|l| l.on != w.on || l.port != w.port);
        if changed {
            if let (Some((c, fp)), Some(s)) = (&cfg, &sh)
                && !reopen
            {
                *s.tls.lock().unwrap_or_else(PoisonError::into_inner) = c.clone();
                st.fingerprint = Some(fp.clone());
            }
            if reopen && let Some(s) = sh.take() {
                s.epoch.fetch_add(1, Ordering::AcqRel);
                st = EncryptedStatus { status: "stopped".into(), ..EncryptedStatus::default() };
                health.listen(Vec::new());
            }
            last = Some(w.clone());
            retry_at = None;
        }
        let due = retry_at.is_none_or(|t| Instant::now() >= t);
        if w.on && sh.is_none() && due {
            let tls = match cfg {
                Some(c) => Some(c),
                None => corerouter_engine::x509::served(&mut lock(session), &w.certificate)
                    .ok()
                    .flatten()
                    .and_then(|(c, k)| tls_config(&c, &k).ok()),
            };
            if let Some((tls, fp)) = tls {
                let s = Arc::new(Shared2 {
                    srv: srv.clone(),
                    tls: Mutex::new(tls),
                    idle: AtomicU64::new(idle),
                    max_sessions: AtomicUsize::new(max),
                    sessions: AtomicUsize::new(0),
                    per_source: Mutex::new(HashMap::new()),
                    epoch: AtomicU64::new(0),
                    stats: Stats::default(),
                });
                match open(&s, w.port, lab, 0) {
                    Ok(at) => {
                        log::info!("DNS over TLS: answering the LAN on port {}", w.port);
                        health.event(format!("DNS over TLS on port {}", w.port));
                        health.listen(at.iter().map(|a| Listen::new("tls", *a)).collect());
                        health.clear_error();
                        st = EncryptedStatus {
                            status: "listening".into(),
                            listening: at.iter().map(ToString::to_string).collect(),
                            fingerprint: Some(fp),
                            ..EncryptedStatus::default()
                        };
                        sh = Some(s);
                    }
                    Err(e) => {
                        s.epoch.fetch_add(1, Ordering::AcqRel);
                        log::error!("DNS over TLS: {e}; retrying in 10 s");
                        health.error(format!("{e}; retrying in 10 s"));
                        st.status = "error".into();
                        st.last_error = Some(e);
                        retry_at = Some(Instant::now() + Duration::from_secs(10));
                    }
                }
            }
        }
        if let Some(s) = &sh {
            status(s, &mut st);
        }
        health.disabled((!w.on).then_some("ip.dns encrypted-service dot=no (or allow_remote_requests=no)"));
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
        help: "virtual lab: DNS over TLS listens on every address\n(default: loopback only, as the LAN forwarder)",
    }],
    topic: "dns",
    enable: "ip.dns.encrypted-service.set dot=yes",
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
