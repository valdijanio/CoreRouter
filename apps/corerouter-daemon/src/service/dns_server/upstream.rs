//! G4.1t: the cache misses of the LAN forwarder, carried by event loops
//! ("dns-upstream-N", `mio`) instead of a thread blocked per query.
//!
//! Why: with a thread per query in flight the misses stopped at
//! `max_concurrent_queries` / RTT and a thousand in flight were a thousand
//! threads (VM: unique names at 20 000/s fell to 8 700/s, p50 573 ms;
//! `docs/dns-stress.md`, **medido**). Here a query in flight is a
//! [`Lookup`] (the resolver's state machine, ~1 KiB) in a slot, an id on a
//! socket and a timer.
//!
//! - **Sockets** (RFC 5452 §9.2): UDP, connected to one server (the kernel
//!   drops datagrams from anyone else, §9.1, and reports the server's ICMP
//!   port unreachable), bound to a kernel-chosen ephemeral port (random on
//!   Linux). A socket carries at most [`USES`] queries and lives at most
//!   [`AGE`], then a fresh one (a new port) takes over: with many queries
//!   outstanding, several ports are in use at once (§9.2 MUST), and a port
//!   an attacker may have learned stops being useful after a few queries.
//!   Ids are random over the full 16 bits (hickory's `Message::query`); one
//!   already outstanding on the socket opens another socket.
//! - **What still blocks** runs on the misses' pool (`pool.rs`, threads kept
//!   for the next job): a TCP retry after a truncated answer (RFC 7766 §5,
//!   rare) and the lookups with an encrypted upstream (DoT/DoH are blocking
//!   TLS streams here; their connection pool keeps one per query in flight,
//!   `dns_secure.rs`). A job's result comes back through the loop's inbox.
//! - **Bounds**: lookups in flight are at most `max_concurrent_queries`
//!   (the resolver refuses more: SERVFAIL "busy"); equal ones waiting for
//!   them (G4.1o) take no slot and are at most `MAX_WAITING`; the inbox
//!   holds at most those, so it needs no bound of its own.
//! - **Threads**: as many loops as UDP readers per family (half the CPUs,
//!   1–4); a lookup goes to the next loop in turn and stays there. Nothing
//!   is shared between loops but the resolver (its lock is held only
//!   around the cache and the statistics).

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_proto_dns::resolver::{Exchange, Lookup, TransportError, Waiter, Way};
use mio::net::UdpSocket;
use mio::{Events, Interest, Poll, Token, Waker};

use super::Server;

/// Queries one socket carries before a fresh one (a new port) takes over.
pub(super) const USES: u32 = 16;
/// A socket older than this takes no new query (a port in use for long at
/// a low rate).
const AGE: Duration = Duration::from_secs(2);
/// The loop wakes at least this often (shutdown, sockets to close).
const POLL: Duration = Duration::from_millis(250);
/// Largest message read (RFC 1035 §4.2.2).
const MAX_MESSAGE: usize = 65_535;
/// How often [`Run::close_idle`] looks.
const SWEEP: Duration = Duration::from_millis(100);
const WAKE: Token = Token(usize::MAX);

/// The loops of a server, started on the first miss.
#[derive(Default)]
pub(super) struct Loops {
    loops: OnceLock<Vec<Arc<Inbox>>>,
    next: AtomicUsize,
}

/// What other threads hand a loop.
struct Inbox {
    mail: Mutex<Vec<Mail>>,
    waker: Waker,
}

enum Mail {
    /// A lookup this loop now leads; `done` gets its result.
    Lead(Box<Lookup>, Waiter),
    /// A blocking exchange of slot `slot` came back.
    Stream {
        slot: usize,
        era: u32,
        token: u32,
        got: Result<Vec<u8>, TransportError>,
    },
}

impl Inbox {
    fn post(&self, m: Mail) {
        let first = {
            let mut mail = self.mail.lock().unwrap_or_else(PoisonError::into_inner);
            mail.push(m);
            mail.len() == 1
        };
        // One wake-up per batch: the loop takes the whole inbox.
        if first && let Err(e) = self.waker.wake() {
            log::debug!("DNS: waking an upstream loop: {e}");
        }
    }
}

impl Loops {
    /// Runs `lookup` (led by this server's forwarder); `done` gets its
    /// result, on a loop or pool thread.
    pub(super) fn lead(&self, srv: &Arc<Server>, lookup: Box<Lookup>, done: Waiter) {
        if lookup.needs_thread() {
            return blocking(srv, lookup, done);
        }
        let loops = self.loops.get_or_init(|| start(srv));
        let n = self.next.fetch_add(1, Ordering::Relaxed);
        match loops.get(n % loops.len().max(1)) {
            Some(inbox) => inbox.post(Mail::Lead(lookup, done)),
            // No loop could start: the old way, on a pooled thread.
            None => blocking(srv, lookup, done),
        }
    }
}

/// A lookup run with blocking exchanges on a pooled thread (encrypted
/// upstreams, or no loop).
fn blocking(srv: &Arc<Server>, mut lookup: Box<Lookup>, done: Waiter) {
    let s = srv.clone();
    let job = Box::new(move || {
        let mut t = s.dns.transport();
        s.fwd.resolver.drive(&mut t, &mut lookup);
        let r = s.fwd.resolver.complete(*lookup, s.dns.now_ms());
        s.fwd.count_in_flight();
        done(r);
    });
    if srv.misses.submit(job).is_err() {
        // The job (and its lookup) is dropped with the pool's queue: the
        // lookup's leader publishes a failure to its followers; `done` was
        // inside the job, so its client times out and asks again.
        log::warn!("DNS: no thread for an upstream lookup");
    }
}

fn start(srv: &Arc<Server>) -> Vec<Arc<Inbox>> {
    let mut out = Vec::new();
    for i in 0..super::udp_threads().max(1) {
        let poll = match Poll::new() {
            Ok(p) => p,
            Err(e) => {
                log::warn!("DNS: upstream loop: {e}");
                break;
            }
        };
        let waker = match Waker::new(poll.registry(), WAKE) {
            Ok(w) => w,
            Err(e) => {
                log::warn!("DNS: upstream loop: {e}");
                break;
            }
        };
        let inbox = Arc::new(Inbox {
            mail: Mutex::new(Vec::new()),
            waker,
        });
        let mut run = Run::new(srv.clone(), inbox.clone(), poll);
        match thread::Builder::new()
            .name(format!("dns-upstream-{i}"))
            .spawn(move || run.run())
        {
            Ok(_) => out.push(inbox),
            Err(e) => {
                log::warn!("DNS: upstream loop: {e}");
                break;
            }
        }
    }
    out
}

/// A lookup in a loop.
struct Entry {
    era: u32,
    lookup: Box<Lookup>,
    done: Waiter,
    /// Its UDP exchanges outstanding: token, socket, id.
    sent: Vec<(u32, usize, u16)>,
    /// The timer queued for it (no duplicates in the heap).
    timer: Option<u64>,
}

/// A UDP socket to one server.
struct Sock {
    udp: UdpSocket,
    server: SocketAddr,
    uses: u32,
    opened: Instant,
    /// Outstanding ids: slot, its generation, the exchange's token.
    waiting: HashMap<u16, (usize, u32, u32)>,
    /// Takes no new query; closed once nothing waits on it.
    retired: bool,
}

struct Run {
    srv: Arc<Server>,
    inbox: Arc<Inbox>,
    poll: Poll,
    slots: Vec<Option<Entry>>,
    eras: Vec<u32>,
    free: Vec<usize>,
    timers: BinaryHeap<Reverse<(u64, usize, u32)>>,
    socks: Vec<Option<Sock>>,
    free_socks: Vec<usize>,
    /// The socket taking new queries, per server.
    current: HashMap<SocketAddr, usize>,
    buf: Vec<u8>,
    /// The last look for sockets to close.
    swept: Instant,
}

impl Run {
    fn new(srv: Arc<Server>, inbox: Arc<Inbox>, poll: Poll) -> Self {
        Self {
            srv,
            inbox,
            poll,
            slots: Vec::new(),
            eras: Vec::new(),
            free: Vec::new(),
            timers: BinaryHeap::new(),
            socks: Vec::new(),
            free_socks: Vec::new(),
            current: HashMap::new(),
            buf: vec![0; MAX_MESSAGE],
            swept: Instant::now(),
        }
    }

    fn now(&self) -> u64 {
        self.srv.dns.now_ms()
    }

    fn run(&mut self) {
        let mut events = Events::with_capacity(256);
        while !self.srv.shutdown.is_closed() {
            let wait = self
                .timers
                .peek()
                .map(|Reverse((at, _, _))| Duration::from_millis(at.saturating_sub(self.now())))
                .map_or(POLL, |d| d.min(POLL));
            if let Err(e) = self.poll.poll(&mut events, Some(wait))
                && e.kind() != std::io::ErrorKind::Interrupted
            {
                log::warn!("DNS: upstream loop: {e}");
                thread::sleep(POLL);
            }
            for ev in &events {
                if ev.token() != WAKE {
                    self.readable(ev.token().0);
                }
            }
            let mail = std::mem::take(
                &mut *self.inbox.mail.lock().unwrap_or_else(PoisonError::into_inner),
            );
            for m in mail {
                self.mail(m);
            }
            self.timers_due();
            self.close_idle();
        }
        // Closing: every lookup still here fails to its client.
        for i in 0..self.slots.len() {
            if let Some(e) = self.slots.get_mut(i).and_then(Option::take) {
                let r = self.srv.fwd.resolver.complete(*e.lookup, self.now());
                (e.done)(r);
            }
        }
    }

    fn mail(&mut self, m: Mail) {
        match m {
            Mail::Lead(mut lookup, done) => {
                let now = self.now();
                let out = lookup.start(now);
                let slot = self.free.pop().unwrap_or_else(|| {
                    self.slots.push(None);
                    self.eras.push(0);
                    self.slots.len() - 1
                });
                let era = self.eras.get(slot).copied().unwrap_or(0);
                if let Some(s) = self.slots.get_mut(slot) {
                    *s = Some(Entry {
                        era,
                        lookup,
                        done,
                        sent: Vec::new(),
                        timer: None,
                    });
                }
                self.send(slot, out);
                self.settle(slot);
            }
            Mail::Stream { slot, era, token, got } => {
                let now = self.now();
                let Some(e) = self.entry(slot, era) else { return };
                let out = match got {
                    Ok(b) => e.lookup.reply(token, &b, now),
                    Err(err) => e.lookup.failed(token, err, now),
                };
                self.send(slot, out);
                self.settle(slot);
            }
        }
    }

    fn entry(&mut self, slot: usize, era: u32) -> Option<&mut Entry> {
        self.slots
            .get_mut(slot)
            .and_then(Option::as_mut)
            .filter(|e| e.era == era)
    }

    /// Sends the exchanges of `slot`.
    fn send(&mut self, slot: usize, out: Vec<Exchange>) {
        let Some(era) = self.slots.get(slot).and_then(Option::as_ref).map(|e| e.era) else {
            return;
        };
        for x in out {
            match x.way {
                Way::Udp => self.send_udp(slot, era, x),
                _ => self.send_stream(slot, era, x),
            }
        }
    }

    fn send_udp(&mut self, slot: usize, era: u32, x: Exchange) {
        let sent = match self.sock_for(x.server, x.id) {
            Ok(i) => match self.socks.get_mut(i).and_then(Option::as_mut) {
                Some(s) => match s.udp.send(&x.query) {
                    Ok(_) => {
                        s.waiting.insert(x.id, (slot, era, x.token));
                        Ok(i)
                    }
                    Err(e) => Err(e),
                },
                None => Err(std::io::Error::other("socket gone")),
            },
            Err(e) => Err(e),
        };
        let now = self.now();
        let Some(e) = self.entry(slot, era) else { return };
        match sent {
            Ok(i) => e.sent.push((x.token, i, x.id)),
            Err(err) => {
                let out = e.lookup.failed(x.token, TransportError::Io(err.to_string()), now);
                self.send(slot, out);
            }
        }
    }

    /// A TCP retry (or an encrypted exchange) on a pooled thread; the
    /// result comes back by mail.
    fn send_stream(&mut self, slot: usize, era: u32, x: Exchange) {
        let (srv, inbox) = (self.srv.clone(), self.inbox.clone());
        let job = Box::new(move || {
            use corerouter_proto_dns::resolver::Transport;
            let mut t = srv.dns.transport();
            let id = x.id.to_be_bytes();
            let got = match &x.way {
                Way::Secure(s) => t.exchange_secure(x.server, s, &x.query, x.wait_ms),
                _ => t.exchange(x.server, &x.query, true, x.wait_ms, &mut |b| {
                    b.get(..2) == Some(&id[..])
                }),
            };
            inbox.post(Mail::Stream {
                slot,
                era,
                token: x.token,
                got,
            });
        });
        if self.srv.misses.submit(job).is_err() {
            let now = self.now();
            if let Some(e) = self.entry(slot, era) {
                let out = e.lookup.failed(x.token, TransportError::Io("no thread".into()), now);
                self.send(slot, out);
            }
        }
    }

    /// The socket for a new query to `server` with `id`: the current one,
    /// or a fresh one (used up, too old, or `id` taken).
    fn sock_for(&mut self, server: SocketAddr, id: u16) -> std::io::Result<usize> {
        if let Some(&i) = self.current.get(&server)
            && let Some(s) = self.socks.get_mut(i).and_then(Option::as_mut)
        {
            if s.uses < USES && s.opened.elapsed() < AGE && !s.waiting.contains_key(&id) {
                s.uses += 1;
                return Ok(i);
            }
            s.retired = true;
        }
        let local: SocketAddr = if server.is_ipv4() {
            ([0, 0, 0, 0], 0).into()
        } else {
            ([0u16; 8], 0).into()
        };
        let mut udp = UdpSocket::bind(local)?;
        udp.connect(server)?;
        let i = self.free_socks.pop().unwrap_or_else(|| {
            self.socks.push(None);
            self.socks.len() - 1
        });
        self.poll
            .registry()
            .register(&mut udp, Token(i), Interest::READABLE)?;
        if let Some(s) = self.socks.get_mut(i) {
            *s = Some(Sock {
                udp,
                server,
                uses: 1,
                opened: Instant::now(),
                waiting: HashMap::new(),
                retired: false,
            });
        }
        self.current.insert(server, i);
        Ok(i)
    }

    /// Socket `i` has datagrams (or an error: the server's ICMP).
    fn readable(&mut self, i: usize) {
        loop {
            let Some(s) = self.socks.get_mut(i).and_then(Option::as_mut) else {
                return;
            };
            match s.udp.recv(&mut self.buf) {
                Ok(n) => {
                    let msg = self.buf.get(..n).unwrap_or_default().to_vec();
                    let Some(id) = msg
                        .get(..2)
                        .and_then(|b| <[u8; 2]>::try_from(b).ok())
                        .map(u16::from_be_bytes)
                    else {
                        continue;
                    };
                    let Some(&(slot, era, token)) = s.waiting.get(&id) else {
                        // Late (its lookup moved on) or forged: dropped.
                        continue;
                    };
                    let now = self.now();
                    let Some(e) = self.entry(slot, era) else { continue };
                    let out = e.lookup.reply(token, &msg, now);
                    self.send(slot, out);
                    self.settle(slot);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(err) => {
                    // ICMP unreachable from the server: every query waiting
                    // on this socket has failed.
                    let waiting: Vec<_> = s.waiting.values().copied().collect();
                    let now = self.now();
                    for (slot, era, token) in waiting {
                        if let Some(e) = self.entry(slot, era) {
                            let out = e.lookup.failed(token, TransportError::Io(err.to_string()), now);
                            self.send(slot, out);
                            self.settle(slot);
                        }
                    }
                    if let Some(s) = self.socks.get_mut(i).and_then(Option::as_mut) {
                        s.retired = true;
                    }
                    return;
                }
            }
        }
    }

    fn timers_due(&mut self) {
        let now = self.now();
        while let Some(&Reverse((at, slot, era))) = self.timers.peek() {
            if at > now {
                break;
            }
            self.timers.pop();
            let Some(e) = self.entry(slot, era) else { continue };
            if e.timer != Some(at) {
                continue;
            }
            e.timer = None;
            let out = e.lookup.tick(now);
            self.send(slot, out);
            self.settle(slot);
        }
    }

    /// After a step of `slot`: ids no longer waited for leave their
    /// sockets; a finished lookup completes and frees the slot; else its
    /// next timer is queued.
    fn settle(&mut self, slot: usize) {
        let Some(e) = self.slots.get_mut(slot).and_then(Option::as_mut) else {
            return;
        };
        let live: Vec<u32> = e.lookup.waiting().collect();
        let mut gone = Vec::new();
        e.sent.retain(|&(token, sock, id)| {
            let keep = live.contains(&token);
            if !keep {
                gone.push((sock, id));
            }
            keep
        });
        let finished = e.lookup.done();
        let next = e.lookup.wake_at();
        let era = e.era;
        if !finished && next.is_some() && e.timer != next {
            e.timer = next;
            if let Some(at) = next {
                self.timers.push(Reverse((at, slot, era)));
            }
        }
        for (sock, id) in gone {
            if let Some(s) = self.socks.get_mut(sock).and_then(Option::as_mut)
                && s.waiting.get(&id).is_some_and(|w| w.0 == slot && w.1 == era)
            {
                s.waiting.remove(&id);
            }
        }
        if !finished {
            return;
        }
        let Some(e) = self.slots.get_mut(slot).and_then(Option::take) else {
            return;
        };
        if let Some(g) = self.eras.get_mut(slot) {
            *g = g.wrapping_add(1);
        }
        self.free.push(slot);
        let r = self.srv.fwd.resolver.complete(*e.lookup, self.now());
        self.srv.fwd.count_in_flight();
        (e.done)(r);
    }

    /// Retired sockets with nothing waiting are closed (looked at every
    /// [`SWEEP`], not on every wake-up).
    fn close_idle(&mut self) {
        if self.swept.elapsed() < SWEEP {
            return;
        }
        self.swept = Instant::now();
        for i in 0..self.socks.len() {
            let Some(s) = self.socks.get_mut(i).and_then(Option::as_mut) else {
                continue;
            };
            let stale = s.uses >= USES || s.opened.elapsed() >= AGE;
            if (s.retired || stale) && s.waiting.is_empty() {
                if self.current.get(&s.server) == Some(&i) {
                    self.current.remove(&s.server);
                }
                if let Some(mut s) = self.socks.get_mut(i).and_then(Option::take) {
                    let _ = self.poll.registry().deregister(&mut s.udp);
                }
                self.free_socks.push(i);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::{Session, lock, shared};
    use corerouter_proto_dns::resolver::Settings;
    use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use serde_json::json;
    use std::collections::{HashSet, VecDeque};
    use std::net::{Ipv4Addr, UdpSocket as StdUdp};
    use std::sync::atomic::AtomicUsize;

    /// An upstream that answers every query `delay` after it came, from one
    /// thread (no thread per query on its side either); counts the queries.
    fn slow_server(delay: Duration) -> (u16, Arc<AtomicUsize>) {
        let udp = StdUdp::bind("127.0.0.1:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        udp.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        thread::spawn(move || {
            let mut due: VecDeque<(Instant, Vec<u8>, SocketAddr)> = VecDeque::new();
            let mut buf = [0u8; 1500];
            loop {
                if let Ok((n, from)) = udp.recv_from(&mut buf) {
                    c.fetch_add(1, Ordering::Relaxed);
                    let q = Message::from_vec(&buf[..n]).unwrap();
                    let mut m = Message::response(q.metadata.id, OpCode::Query);
                    m.metadata.response_code = ResponseCode::NoError;
                    m.add_queries(q.queries.clone());
                    m.add_answer(Record::from_rdata(
                        q.queries[0].name().clone(),
                        300,
                        RData::A(A(Ipv4Addr::new(198, 51, 100, 9))),
                    ));
                    due.push_back((Instant::now() + delay, m.to_vec().unwrap(), from));
                }
                while due.front().is_some_and(|d| d.0 <= Instant::now()) {
                    let (_, b, to) = due.pop_front().unwrap();
                    let _ = udp.send_to(&b, to);
                }
            }
        });
        (port, count)
    }

    fn query(id: u16, name: &str) -> Vec<u8> {
        let mut m = Message::query();
        m.metadata.id = id;
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        m.to_vec().unwrap()
    }

    /// A forwarder on a free port whose resolver asks `upstream`.
    fn forwarder(upstream: u16, max: u32) -> (Arc<Server>, u16, corerouter_control::Shutdown) {
        let session = shared(Session::virtual_lab());
        lock(&session)
            .execute(
                "ip.dns.set",
                &json!({"allow_remote_requests": true, "max_concurrent_queries": max}),
            )
            .unwrap();
        let dns = Arc::new(super::super::RouterDns::new());
        let mut s = Settings::default();
        s.servers = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
        s.port = upstream;
        s.max_queries = max;
        dns.resolver.configure(s, 0);
        let port = loop {
            let u = StdUdp::bind("127.0.0.1:0").unwrap();
            let p = u.local_addr().unwrap().port();
            drop(u);
            if std::net::TcpListener::bind(("127.0.0.1", p)).is_ok() {
                break p;
            }
        };
        let shutdown = corerouter_control::Shutdown::default();
        let srv = super::super::spawn(session, dns, port, shutdown.clone()).unwrap();
        (srv, port, shutdown)
    }

    use std::net::IpAddr;

    /// Sends `names` from one socket at once and collects the answers.
    fn ask_all(port: u16, names: &[String], within: Duration) -> HashSet<u16> {
        let c = StdUdp::bind("127.0.0.1:0").unwrap();
        c.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let end = Instant::now() + within;
        // The listener may not be up yet: the first name until it answers.
        let mut got = HashSet::new();
        while Instant::now() < end && got.is_empty() {
            c.send_to(&query(0, &names[0]), ("127.0.0.1", port)).unwrap();
            let mut buf = [0u8; 1500];
            if let Ok(n) = c.recv(&mut buf) {
                got.insert(Message::from_vec(&buf[..n]).unwrap().metadata.id);
            }
        }
        for (i, n) in names.iter().enumerate().skip(1) {
            c.send_to(&query(u16::try_from(i).unwrap(), n), ("127.0.0.1", port))
                .unwrap();
        }
        let mut buf = [0u8; 1500];
        while Instant::now() < end && got.len() < names.len() {
            if let Ok(n) = c.recv(&mut buf) {
                let m = Message::from_vec(&buf[..n]).unwrap();
                if m.metadata.response_code == ResponseCode::NoError && !m.answers.is_empty() {
                    got.insert(m.metadata.id);
                }
            }
        }
        got
    }

    /// G4.1t: 400 different names at once against an upstream that takes
    /// 300 ms each are all in flight together (with a thread per query
    /// this was 400 threads), answered in about one RTT; no pooled thread
    /// is used for plain UDP.
    #[test]
    fn many_misses_in_flight_without_a_thread_each() {
        let (up, asked) = slow_server(Duration::from_millis(300));
        let (srv, port, shutdown) = forwarder(up, 1000);
        let names: Vec<String> = (0..400).map(|i| format!("n{i}.wt.example.")).collect();
        let t0 = Instant::now();
        let got = ask_all(port, &names, Duration::from_secs(5));
        let took = t0.elapsed();
        assert_eq!(got.len(), 400, "every name answered");
        // One RTT for the first, one for the 399 in flight together.
        assert!(took < Duration::from_millis(1500), "{took:?}");
        assert_eq!(asked.load(Ordering::Relaxed), 400);
        assert_eq!(srv.misses.counts().0, 0, "no thread for a plain UDP miss");
        assert_eq!(srv.fwd.resolver.in_flight(), (0, 0));
        shutdown.close();
    }

    /// Past `max_concurrent_queries` lookups in flight: SERVFAIL at once
    /// ("busy"); equal names follow the one in flight and take no slot.
    #[test]
    fn the_limit_counts_lookups_and_equal_names_follow() {
        let (up, asked) = slow_server(Duration::from_millis(300));
        let (srv, port, shutdown) = forwarder(up, 10);
        // 50 times the same name: one query upstream, every one answered.
        let same: Vec<String> = (0..50).map(|_| "same.example.".to_owned()).collect();
        let got = ask_all(port, &same, Duration::from_secs(5));
        assert_eq!(got.len(), 50);
        assert!(asked.load(Ordering::Relaxed) <= 2, "{}", asked.load(Ordering::Relaxed));
        // 30 different names with room for 10.
        let names: Vec<String> = (0..30).map(|i| format!("d{i}.example.")).collect();
        let got = ask_all(port, &names, Duration::from_secs(3));
        assert!((10..=12).contains(&got.len()), "{}", got.len());
        let busy = srv.fwd.statistics().snapshot(10).counters.answered.get("busy").copied().unwrap_or(0);
        assert!(busy >= 18, "{busy}");
        shutdown.close();
    }

    /// The socket rotates: after [`USES`] queries a new port takes over
    /// (RFC 5452 §9.2: several ports at once).
    #[test]
    fn queries_use_several_source_ports() {
        let udp = StdUdp::bind("127.0.0.1:0").unwrap();
        let up = udp.local_addr().unwrap().port();
        udp.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let (_srv, port, shutdown) = forwarder(up, 1000);
        let names: Vec<String> = (0..64).map(|i| format!("p{i}.example.")).collect();
        let c = StdUdp::bind("127.0.0.1:0").unwrap();
        let mut buf = [0u8; 1500];
        // The listener is up once a query reaches the upstream.
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            c.send_to(&query(999, "warm.example."), ("127.0.0.1", port)).unwrap();
            if udp.recv_from(&mut buf).is_ok() {
                break;
            }
            assert!(Instant::now() < end, "the listener never came up");
        }
        for (i, n) in names.iter().enumerate() {
            c.send_to(&query(u16::try_from(i).unwrap(), n), ("127.0.0.1", port)).unwrap();
        }
        let mut ports = HashSet::new();
        let mut names_seen = HashSet::new();
        let end = Instant::now() + Duration::from_secs(3);
        while Instant::now() < end && names_seen.len() < 64 {
            if let Ok((n, from)) = udp.recv_from(&mut buf) {
                let q = Message::from_vec(&buf[..n]).unwrap();
                let name = q.queries[0].name().to_ascii();
                if name.starts_with('p') {
                    ports.insert(from.port());
                    names_seen.insert(name);
                }
            }
        }
        assert_eq!(names_seen.len(), 64);
        let want = 64 / usize::try_from(USES).unwrap();
        assert!(ports.len() >= want, "{} ports for 64 queries", ports.len());
        shutdown.close();
    }
}
