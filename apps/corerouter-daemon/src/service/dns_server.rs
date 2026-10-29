//! The LAN DNS forwarder (G4.1b, `/ip dns allow_remote_requests`): UDP and
//! TCP port 53, answered by the chain of `corerouter_proto_dns::server`
//! (ACL, per-client limit, static entries, the cache shared with the
//! router's resolver, upstream).
//!
//! Threads, like the rest of the daemon (no async runtime: a forwarder
//! spends its time in the cache, and the upstream waits are bounded by
//! `max_concurrent_queries`):
//!
//! - "dns-server": every second, copies the running config into the
//!   forwarder when it changed, and opens or closes the sockets as
//!   `allow_remote_requests` says.
//! - up to four UDP threads per family on one socket ([`udp_threads`]):
//!   each reads a query and runs the chain up to the cache; a cache hit is
//!   answered at once. A miss gets a thread of its
//!   own, at most `max_concurrent_queries` of them (more: SERVFAIL), so
//!   one slow upstream never holds the cache hits back.
//! - one TCP thread per family; a thread per connection, at most
//!   `max_concurrent_tcp_sessions` (a quarter of them per source), closed
//!   after 10 s idle (RFC 7766 §6.2.3). A peer that may not ask anything
//!   (not the router, not `allowed_from`, not a peer a zone names) is
//!   closed at accept, before it takes a slot; a message must arrive whole
//!   within 10 s of its first byte and a connection reads no new query
//!   after 2 minutes (a slow drip never holds a slot).
//! - "dns-update": RFC 2136 UPDATEs that came over UDP, applied off the
//!   listener (they wait for the session lock and a disk write).
//! - "dns-effects": applies what the chain asks of the rest of the router
//!   (a static entry's address list) under the session lock, off the
//!   answering threads; its queue is bounded (full: dropped, the next
//!   answer adds the address again).
//!
//! On Linux, UDP sockets read the destination address of each query (IP_PKTINFO /
//! IPV6_RECVPKTINFO) and answer from it: a router with several addresses
//! on the LAN would otherwise answer from another one, and the client drops
//! the reply (dnsmasq and Unbound do the same).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_control::Shutdown;
use corerouter_engine::{Shared, lock};
use corerouter_model::Config;
use corerouter_proto_dns::server::{Done, Effect, Forwarder, MAX_QUERY, Pending, Start, Statistics};
use corerouter_proto_dns::zone;
use super::dns::RouterDns;
use corerouter_model::service::Listen;
use sock::{Udp, bind_tcp};

/// RFC 1035 §4.2.1.
const DEFAULT_PORT: u16 = 53;
/// G0.30: 50 ms in the unit tests, which follow the config through it.
const TICK: Duration = if cfg!(test) {
    Duration::from_millis(50)
} else {
    Duration::from_secs(1)
};
/// How often the socket threads look at the stop signal.
const POLL: Duration = Duration::from_millis(250);
/// RFC 7766 §6.2.3: idle TCP connections are closed (a few seconds).
const TCP_IDLE: Duration = Duration::from_secs(10);
/// A message, from its first byte to its last (a peer sending one byte
/// every few seconds is not idle, and must not hold a slot for days).
const TCP_MESSAGE: Duration = if cfg!(test) {
    Duration::from_secs(2)
} else {
    Duration::from_secs(10)
};
/// No new query is read on a connection older than this.
const TCP_SESSION: Duration = Duration::from_secs(120);
/// Queries answered on one TCP connection before it is closed.
const TCP_MAX_QUERIES: usize = 1000;
/// Address-list effects waiting for the session lock; more are dropped
/// (each answer sends its addresses again).
const EFFECTS_QUEUE: usize = 4096;
/// UDP UPDATEs waiting for the updater; more are dropped (the client
/// retries, RFC 2136 §7.6).
const UPDATE_QUEUE: usize = 64;

/// A bounded count (queries or TCP sessions in flight).
#[derive(Default)]
struct Gate(AtomicUsize);

impl Gate {
    fn try_enter(&self, max: u32) -> bool {
        let max = usize::try_from(max).unwrap_or(usize::MAX);
        let mut cur = self.0.load(Ordering::Relaxed);
        loop {
            if cur >= max {
                return false;
            }
            match self
                .0
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(now) => cur = now,
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Which {
    Query,
    Tcp,
}

/// A TCP session's place per source: one source holds at most a quarter
/// of `max_concurrent_tcp_sessions` (at least one).
struct SourcePass {
    srv: Arc<Server>,
    ip: IpAddr,
}

impl SourcePass {
    fn enter(srv: &Arc<Server>, ip: IpAddr, max: u32) -> Option<Self> {
        let cap = (max / 4).max(1);
        let mut per = srv.tcp_sources.lock().unwrap_or_else(|e| e.into_inner());
        let n = per.entry(ip).or_insert(0);
        if *n >= cap {
            return None;
        }
        *n += 1;
        Some(Self {
            srv: srv.clone(),
            ip,
        })
    }
}

impl Drop for SourcePass {
    fn drop(&mut self) {
        let mut per = self.srv.tcp_sources.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = per.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                per.remove(&self.ip);
            }
        }
    }
}

/// An RFC 2136 UPDATE that came over UDP, for the "dns-update" thread.
struct UdpUpdate {
    packet: Vec<u8>,
    from: SocketAddr,
    local: Option<IpAddr>,
    sock: Arc<Udp>,
}

/// A place in a gate, given back when dropped (it can move to a thread).
struct Pass {
    srv: Arc<Server>,
    which: Which,
}

impl Pass {
    fn enter(srv: &Arc<Server>, which: Which, max: u32) -> Option<Self> {
        srv.gate(which).try_enter(max).then(|| Self {
            srv: srv.clone(),
            which,
        })
    }
}

impl Drop for Pass {
    fn drop(&mut self) {
        self.srv.gate(self.which).0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// What the socket threads share.
pub(crate) struct Server {
    fwd: Forwarder,
    dns: Arc<RouterDns>,
    queries: Gate,
    tcp: Gate,
    /// TCP sessions per source address.
    tcp_sources: Mutex<HashMap<IpAddr, u32>>,
    effects: SyncSender<Effect>,
    /// Effects dropped because the queue was full.
    effects_dropped: AtomicU64,
    updates: SyncSender<UdpUpdate>,
    /// Socket threads of an older epoch stop (the config turned the
    /// forwarder off, or the daemon is closing).
    epoch: AtomicU64,
    shutdown: Shutdown,
}

impl Server {
    fn gate(&self, which: Which) -> &Gate {
        match which {
            Which::Query => &self.queries,
            Which::Tcp => &self.tcp,
        }
    }

    fn alive(&self, epoch: u64) -> bool {
        !self.shutdown.is_closed() && self.epoch.load(Ordering::Acquire) == epoch
    }

    fn max_queries(&self) -> u32 {
        self.fwd.config().config.ip.dns.max_concurrent_queries
    }

    fn effects(&self, done: &mut Done) {
        if done.effects.is_empty() {
            return;
        }
        for e in done.effects.drain(..) {
            if let Err(TrySendError::Full(_)) = self.effects.try_send(e) {
                self.effects_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// The forwarder (its zones are served by `dns_zones`).
    pub(crate) fn forwarder(&self) -> &Forwarder {
        &self.fwd
    }

    /// The rest of the chain, on this (worker) thread.
    fn finish(&self, p: Pending) -> Done {
        let mut t = self.dns.transport();
        self.fwd.finish(p, &mut t)
    }
}

fn udp_loop(srv: Arc<Server>, sock: Arc<Udp>, epoch: u64) {
    let mut buf = vec![0u8; MAX_QUERY];
    while srv.alive(epoch) {
        let (n, from, local) = match sock.recv(&mut buf) {
            Ok(got) => got,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(e) => {
                log::debug!("DNS: UDP read: {e}");
                continue;
            }
        };
        let packet = buf.get(..n).unwrap_or_default();
        // RFC 2136 UPDATE: applied on its own thread (it waits for the
        // session lock and a disk write; queries must not).
        if is_update(packet) {
            let job = UdpUpdate {
                packet: packet.to_vec(),
                from,
                local,
                sock: sock.clone(),
            };
            if srv.updates.try_send(job).is_err() {
                log::debug!("DNS: UPDATE from {from} dropped: too many waiting");
            }
            continue;
        }
        // Zone transfers and NOTIFY (G4.1c), before the chain.
        if let Some(replies) = zone::xfr::intercept(&srv.fwd, packet, from.ip(), false) {
            for r in &replies {
                sock.send(r, from, local);
            }
            continue;
        }
        match srv.fwd.start(packet, from.ip(), false, srv.dns.now_ms()) {
            Start::Done(mut d) => {
                if let Some(r) = &d.reply {
                    sock.send(r, from, local);
                }
                srv.effects(&mut d);
            }
            Start::Pending(p) => {
                // RouterOS `max-concurrent-queries`: past it, SERVFAIL now
                // (the client tries its other server) instead of a queue.
                let Some(pass) = Pass::enter(&srv, Which::Query, srv.max_queries()) else {
                    let d = srv.fwd.fail(*p);
                    if let Some(r) = &d.reply {
                        sock.send(r, from, local);
                    }
                    continue;
                };
                let sock_w = sock.clone();
                let worker = move || {
                    let mut d = pass.srv.finish(*p);
                    if let Some(r) = &d.reply {
                        sock_w.send(r, from, local);
                    }
                    pass.srv.effects(&mut d);
                };
                if let Err(e) = thread::Builder::new().name("dns-query".into()).spawn(worker) {
                    // The query went down with the closure: SERVFAIL from
                    // its bytes, so the client tries elsewhere at once.
                    log::warn!("DNS: no thread for a query: {e}");
                    if let Some(r) = servfail(packet) {
                        sock.send(&r, from, local);
                    }
                }
            }
        }
    }
}

/// The opcode of `packet` is UPDATE (RFC 2136 §2.2: opcode 5, a query).
fn is_update(packet: &[u8]) -> bool {
    packet.get(2).is_some_and(|f| f & 0x80 == 0 && (f >> 3) & 0x0f == 5)
}

/// One UDP UPDATE on the "dns-update" thread, answered from there.
fn apply_updates_one(srv: &Server, u: UdpUpdate) {
    if let Some(replies) = zone::xfr::intercept(&srv.fwd, &u.packet, u.from.ip(), false) {
        for r in &replies {
            u.sock.send(r, u.from, u.local);
        }
    }
}

fn tcp_loop(srv: Arc<Server>, listener: TcpListener, epoch: u64) {
    while srv.alive(epoch) {
        let (stream, peer) = match listener.accept() {
            Ok(got) => got,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
                continue;
            }
            Err(e) => {
                log::debug!("DNS: TCP accept: {e}");
                thread::sleep(Duration::from_millis(20));
                continue;
            }
        };
        // Who may not ask anything never takes a slot (the chain's ACL
        // only runs on a whole message).
        if !zone::xfr::may_connect(&srv.fwd, peer.ip()) {
            continue;
        }
        let max = srv.fwd.config().config.ip.dns.max_concurrent_tcp_sessions;
        // Over the limits the connection just closes.
        let Some(source) = SourcePass::enter(&srv, peer.ip().to_canonical(), max) else {
            continue;
        };
        let Some(pass) = Pass::enter(&srv, Which::Tcp, max) else {
            continue;
        };
        let session = move || {
            let _source = source;
            tcp_session(&pass.srv, stream, epoch);
        };
        if let Err(e) = thread::Builder::new().name("dns-tcp".into()).spawn(session) {
            log::warn!("DNS: no thread for a TCP session: {e}");
        }
    }
}

/// Fills `buf` from `s` before `deadline` (the socket's timeout follows
/// what is left, so a byte now and then does not stretch it).
fn read_by(s: &mut TcpStream, buf: &mut [u8], deadline: Instant) -> std::io::Result<()> {
    let mut at = 0;
    while at < buf.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        s.set_read_timeout(Some(left))?;
        let Some(rest) = buf.get_mut(at..) else { break };
        match s.read(rest) {
            Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => at += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// One framed message: up to [`TCP_IDLE`] for its first byte, then
/// [`TCP_MESSAGE`] for the rest. The buffer grows as bytes come (a
/// length of 65 535 alone allocates nothing).
fn read_message(s: &mut TcpStream, session_end: Instant) -> Option<Vec<u8>> {
    let mut first = [0u8; 1];
    read_by(s, &mut first, (Instant::now() + TCP_IDLE).min(session_end)).ok()?;
    let deadline = Instant::now() + TCP_MESSAGE;
    let mut second = [0u8; 1];
    read_by(s, &mut second, deadline).ok()?;
    let len = usize::from(u16::from_be_bytes([first[0], second[0]]));
    let mut msg = Vec::new();
    let mut chunk = [0u8; 4096];
    while msg.len() < len {
        let want = (len - msg.len()).min(chunk.len());
        let part = chunk.get_mut(..want)?;
        read_by(s, part, deadline).ok()?;
        msg.extend_from_slice(part);
    }
    Some(msg)
}

/// RFC 1035 §4.2.2 / RFC 7766: 2-byte length, then the message; several
/// queries per connection, answered in order.
fn tcp_session(srv: &Arc<Server>, mut s: TcpStream, epoch: u64) {
    let Ok(peer) = s.peer_addr() else { return };
    let _ = s.set_nonblocking(false);
    let _ = s.set_write_timeout(Some(TCP_IDLE));
    let session_end = Instant::now() + TCP_SESSION;
    for _ in 0..TCP_MAX_QUERIES {
        if !srv.alive(epoch) || Instant::now() >= session_end {
            return;
        }
        let Some(msg) = read_message(&mut s, session_end) else {
            return;
        };
        // AXFR/IXFR (several messages) and NOTIFY (G4.1c), before the chain.
        if let Some(replies) = zone::xfr::intercept(&srv.fwd, &msg, peer.ip(), true) {
            for r in replies {
                let Ok(len) = u16::try_from(r.len()) else {
                    return;
                };
                let mut framed = len.to_be_bytes().to_vec();
                framed.extend(r);
                if s.write_all(&framed).is_err() {
                    return;
                }
            }
            continue;
        }
        let mut done = match srv.fwd.start(&msg, peer.ip(), true, srv.dns.now_ms()) {
            Start::Done(d) => d,
            Start::Pending(p) => match Pass::enter(srv, Which::Query, srv.max_queries()) {
                Some(_pass) => srv.finish(*p),
                None => srv.fwd.fail(*p),
            },
        };
        srv.effects(&mut done);
        let Some(reply) = done.reply else {
            // Refused by the limit or junk: the connection ends.
            return;
        };
        // An answer over 64 KiB cannot be framed: SERVFAIL, not silence.
        let reply = if reply.len() > usize::from(u16::MAX) {
            match servfail(&msg) {
                Some(r) => r,
                None => return,
            }
        } else {
            reply
        };
        let Ok(len) = u16::try_from(reply.len()) else {
            return;
        };
        let mut framed = len.to_be_bytes().to_vec();
        framed.extend(reply);
        if s.write_all(&framed).is_err() {
            return;
        }
    }
}

/// SERVFAIL for `query` (its id, opcode and question).
fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    use hickory_proto::op::{Message, ResponseCode};
    let q = Message::from_vec(query).ok()?;
    let mut r = Message::error_msg(q.metadata.id, q.metadata.op_code, ResponseCode::ServFail);
    r.add_queries(q.queries);
    r.to_vec().ok()
}

/// Where the forwarder listens: every address of the host, or only its
/// loopback when the daemon runs the virtual lab (its interfaces are not
/// the host's, so the host's LAN must not reach it; as CRDP, G5.4).
fn listen_ips(lab: bool) -> [IpAddr; 2] {
    if lab {
        [IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)]
    } else {
        [IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V6(Ipv6Addr::UNSPECIFIED)]
    }
}

/// Whether the session runs the virtual lab (`--backend virtual`).
fn is_lab(session: &Shared) -> bool {
    lock(session).backend().starts_with("virtual lab")
}

/// Readers of each UDP socket: half the cores, 1 to 4. One thread answered
/// at most ~340 000 cache hits a second at 100 % of a core with the other
/// cores free; the chain's locks (statistics, per-client limit, cache) let
/// several scale: 2 threads 577 000/s, 4 threads 964 000/s (G0.31,
/// **medido**). The kernel hands each datagram to one waiting reader.
fn udp_threads() -> usize {
    let cores = thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    (cores / 2).clamp(1, 4)
}

/// The sockets of one epoch, their threads counted in `health`; where
/// they listen.
fn open(
    srv: &Arc<Server>,
    port: u16,
    lab: bool,
    epoch: u64,
    health: &super::Health,
) -> Result<Vec<SocketAddr>, String> {
    let mut opened = Vec::new();
    for ip in listen_ips(lab) {
        let addr = SocketAddr::new(ip, port);
        let udp = match Udp::bind(addr) {
            Ok(u) => Arc::new(u),
            // A host without IPv6 still serves IPv4.
            Err(e) if ip.is_ipv6() => {
                log::info!("DNS: no IPv6 listener on {addr}: {e}");
                continue;
            }
            Err(e) => return Err(format!("UDP {addr}: {e}")),
        };
        let tcp = bind_tcp(addr).map_err(|e| format!("TCP {addr}: {e}"))?;
        opened.push((udp, tcp, addr));
    }
    let at = opened.iter().map(|(_, _, a)| *a).collect();
    for (udp, tcp, _) in opened {
        for _ in 0..udp_threads() {
            let s = srv.clone();
            let udp = udp.clone();
            health
                .spawn("dns-udp", move || udp_loop(s, udp, epoch))
                .map_err(|e| e.to_string())?;
        }
        let s = srv.clone();
        health
            .spawn("dns-tcp-accept", move || tcp_loop(s, tcp, epoch))
            .map_err(|e| e.to_string())?;
    }
    Ok(at)
}

fn apply_effects(session: &Shared, rx: &Receiver<Effect>) {
    while let Ok(e) = rx.recv() {
        match e {
            Effect::AddressList {
                list,
                address,
                timeout_secs,
            } => {
                if let Err(why) = lock(session).dns_address_list(&list, address, timeout_secs) {
                    log::warn!("DNS: address list {list}: {address} not added: {why}");
                }
            }
        }
    }
}

/// Starts the forwarder on `port`, outside the supervisor (tests): it
/// follows the config from then on.
#[cfg(test)]
pub(crate) fn spawn(
    session: Shared,
    dns: Arc<RouterDns>,
    port: u16,
    shutdown: Shutdown,
) -> std::io::Result<Arc<Server>> {
    let srv = prepare(&session, dns, shutdown.clone())?;
    let keep = srv.clone();
    let health = super::Health::new(shutdown);
    thread::Builder::new()
        .name("dns-server".into())
        .spawn(move || follow(&session, &keep, port, false, &health))?;
    Ok(srv)
}

/// The daemon's server: [`prepare`] with the zone service attached before
/// any socket opens, so the zones it answers for take UPDATE from the
/// first packet (`dns_zones::attach`).
fn make(
    session: &Shared,
    dns: Arc<RouterDns>,
    shutdown: &Shutdown,
) -> std::io::Result<(Arc<Server>, Arc<super::dns_zones::Zones>)> {
    let srv = prepare(session, dns, shutdown.clone())?;
    let zones = super::dns_zones::attach(session, &srv, shutdown);
    Ok((srv, zones))
}

/// The forwarder and its effects thread, registered in the session. One
/// for the daemon's life: a restart of the service keeps its lists and
/// counters (only the sockets and the follow loop are per run).
fn prepare(
    session: &Shared,
    dns: Arc<RouterDns>,
    shutdown: Shutdown,
) -> std::io::Result<Arc<Server>> {
    let (tx, rx) = sync_channel(EFFECTS_QUEUE);
    let (utx, urx) = sync_channel(UPDATE_QUEUE);
    let srv = Arc::new(Server {
        fwd: Forwarder::new(dns.resolver.clone()),
        dns,
        queries: Gate::default(),
        tcp: Gate::default(),
        tcp_sources: Mutex::new(HashMap::new()),
        effects: tx,
        effects_dropped: AtomicU64::new(0),
        updates: utx,
        epoch: AtomicU64::new(0),
        shutdown,
    });
    {
        let session = session.clone();
        thread::Builder::new()
            .name("dns-effects".into())
            .spawn(move || apply_effects(&session, &rx))?;
    }
    {
        // Weak: the server's last reference going away ends the thread
        // (its sender with it).
        let weak = Arc::downgrade(&srv);
        thread::Builder::new().name("dns-update".into()).spawn(move || {
            while let Ok(u) = urx.recv() {
                let Some(srv) = weak.upgrade() else { return };
                apply_updates_one(&srv, u);
            }
        })?;
    }
    // `ip.dns.statistics.print` reads what the chain counts.
    lock(session).set_dns_statistics(srv.fwd.state::<Statistics>());
    Ok(srv)
}

/// Copies the config in when it changes, or when what `allowed_from`
/// stands for does (a DHCP lease, a delegated prefix); opens and closes the
/// sockets.
/// `any`: listen on every address even in the virtual lab (`--dns-lab-any`).
fn follow(session: &Shared, srv: &Arc<Server>, port: u16, any: bool, health: &super::Health) {
    let mut last: Option<Config> = None;
    let mut last_allowed = Vec::new();
    let mut listening = false;
    let mut retry_at = 0u64;
    let lab = !any && is_lab(session);
    loop {
        if health.stopping() {
            srv.epoch.fetch_add(1, Ordering::AcqRel);
            return;
        }
        health.beat();
        let (changed, allowed) = {
            let s = lock(session);
            let running = s.store().running();
            let allowed = s.dns_allowed_networks(running);
            if last.as_ref() == Some(running) {
                (None, allowed)
            } else {
                (Some(running.clone()), allowed)
            }
        };
        if changed.is_some() || allowed != last_allowed {
            if let Some(cfg) = changed {
                last = Some(cfg);
            }
            if let Some(cfg) = &last {
                srv.fwd.configure(Arc::new(cfg.clone()), allowed.clone());
            }
            last_allowed = allowed;
        }
        let want = last.as_ref().is_some_and(|c| c.ip.dns.allow_remote_requests);
        let now = srv.dns.now_ms();
        if want && !listening && now >= retry_at {
            let epoch = srv.epoch.fetch_add(1, Ordering::AcqRel) + 1;
            match open(srv, port, lab, epoch, health) {
                Ok(at) => {
                    health.listen(at.iter().flat_map(|a| [Listen::new("udp", *a), Listen::new("tcp", *a)]).collect());
                    health.clear_error();
                    health.event(format!("answering the LAN on port {port}"));
                    listening = true;
                    log::info!("DNS: answering the LAN on port {port} (UDP, TCP)");
                }
                Err(e) => {
                    // Closes whatever this attempt opened.
                    srv.epoch.fetch_add(1, Ordering::AcqRel);
                    retry_at = now + 10_000;
                    log::error!("DNS: cannot answer the LAN: {e}; retrying in 10 s");
                    health.error(format!("cannot answer the LAN: {e}; retrying in 10 s"));
                }
            }
        } else if !want && listening {
            srv.epoch.fetch_add(1, Ordering::AcqRel);
            listening = false;
            health.listen(Vec::new());
            log::info!("DNS: no longer answering the LAN (allow_remote_requests off)");
        }
        health.disabled((!want).then_some("ip.dns allow_remote_requests=no"));
        health.sleep(TICK);
    }
}

pub(crate) const SERVICE: super::Service = super::Service {
    name: "dns-server",
    flags: &[
        super::Flag {
            name: "--dns-port",
            value: Some("<port>"),
            help: "port of the LAN DNS forwarder (default 53; on with\nip.dns.set allow_remote_requests=yes)",
        },
        super::Flag {
            name: "--dns-lab-any",
            value: None,
            help: "virtual lab: the LAN DNS forwarder listens on every address\n(default: loopback only; for a lab inside a network namespace)",
        },
    ],
    topic: "dns",
    enable: "ip.dns.set allow_remote_requests=yes",
    depends: &["dns-resolver"],
    start,
};

/// A bad `--dns-port` stops the daemon; the rest runs supervised, on the
/// resolver's cache (it depends on `dns-resolver`).
fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let port = match ctx.flag("--dns-port") {
        None => DEFAULT_PORT,
        Some(p) => p
            .parse()
            .map_err(|_| format!("--dns-port: '{p}' is not a port"))?,
    };
    let any = ctx.flag("--dns-lab-any").is_some();
    let session = ctx.session.clone();
    let shutdown = ctx.shutdown.clone();
    Ok(Box::new(move |health: &super::Health| {
        let srv = match SERVER.get() {
            Some(srv) => srv.clone(),
            None => {
                let dns = super::dns::router().ok_or("the DNS resolver is not running")?;
                let (srv, zones) = make(&session, dns, &shutdown)
                    .map_err(|e| format!("cannot start its threads: {e}"))?;
                super::dns_zones::publish(zones);
                SERVER.get_or_init(|| srv).clone()
            }
        };
        follow(&session, &srv, port, any, health);
        Ok(())
    }))
}

/// The forwarder, once started (the adlist loader fills its lists; the
/// zone service works on its zones).
static SERVER: OnceLock<Arc<Server>> = OnceLock::new();

/// G6.6 DNS Lookup with the router as the server: `query` down the chain
/// as a client on the router itself is answered, without a socket. The
/// reply's bytes (`None`: dropped) and the stage that answered; `None`
/// when the forwarder has not started.
pub(crate) fn ask(query: &[u8], tcp: bool) -> Option<(Option<Vec<u8>>, &'static str)> {
    let srv = SERVER.get()?;
    let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut done = match srv.fwd.start(query, client, tcp, srv.dns.now_ms()) {
        Start::Done(d) => d,
        Start::Pending(p) => srv.finish(*p),
    };
    srv.effects(&mut done);
    Some((done.reply, done.answered_by))
}

/// [`ask`] as a LAN client would be answered (G6.8): from `as_client`
/// (the router itself when `None`: then like [`ask`]), keeping each
/// stage's decision when `explain`. A simulated client sent nothing: its
/// query takes no limit token, counts in no statistics and touches no
/// address list.
pub(crate) fn ask_as(
    query: &[u8],
    tcp: bool,
    as_client: Option<IpAddr>,
    explain: bool,
) -> Option<corerouter_proto_dns::server::Done> {
    Some(SERVER.get()?.ask_as(query, tcp, as_client, explain))
}

impl Server {
    /// [`ask_as`] on this server.
    fn ask_as(
        &self,
        query: &[u8],
        tcp: bool,
        as_client: Option<IpAddr>,
        explain: bool,
    ) -> corerouter_proto_dns::server::Done {
        let how = corerouter_proto_dns::server::How {
            explain,
            simulated: as_client.is_some(),
        };
        let client = as_client.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let mut done = match self.fwd.start_as(query, client, tcp, self.dns.now_ms(), how) {
            Start::Done(d) => d,
            Start::Pending(p) => self.finish(*p),
        };
        if as_client.is_none() {
            self.effects(&mut done);
        }
        done
    }
}

/// The block lists the forwarder matches (G4.1d), once it started.
pub(crate) fn adlists() -> Option<Arc<corerouter_proto_dns::adlist::Adlists>> {
    SERVER.get().map(|s| s.fwd.state())
}

/// Linux: the destination address of each query (IP_PKTINFO /
/// IPV6_RECVPKTINFO), through `nix`.
#[cfg(target_os = "linux")]
mod sock {
    use std::io::{IoSlice, IoSliceMut};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
    use std::os::fd::{AsRawFd, OwnedFd};

    use nix::libc;
    use nix::sys::socket::{
        AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
        SockaddrIn, SockaddrIn6, SockaddrStorage, bind, recvmsg, sendmsg, setsockopt, socket,
        sockopt,
    };

    use super::POLL;

    /// Receive buffer of each UDP socket: with the default (`rmem_default`,
    /// 208 KiB) a burst of 4096 queries in flight lost 27 392 of them in
    /// 6 s, dropped by the kernel before a reader got them (G0.31,
    /// **medido**). `SO_RCVBUFFORCE` as root, else up to `rmem_max`.
    const RCVBUF: usize = 4 << 20;

    /// A UDP socket that knows each query's destination address.
    pub(super) struct Udp {
        sock: UdpSocket,
        v6: bool,
    }

    fn nix_io(e: nix::Error) -> std::io::Error {
        std::io::Error::from_raw_os_error(e as i32)
    }

    impl Udp {
        pub(super) fn bind(addr: SocketAddr) -> std::io::Result<Self> {
            let v6 = addr.is_ipv6();
            let family = if v6 {
                AddressFamily::Inet6
            } else {
                AddressFamily::Inet
            };
            let fd: OwnedFd = socket(family, SockType::Datagram, SockFlag::SOCK_CLOEXEC, None)
                .map_err(nix_io)?;
            setsockopt(&fd, sockopt::ReuseAddr, &true).map_err(nix_io)?;
            if setsockopt(&fd, sockopt::RcvBufForce, &RCVBUF).is_err() {
                let _ = setsockopt(&fd, sockopt::RcvBuf, &RCVBUF);
            }
            match addr {
                SocketAddr::V4(a) => {
                    setsockopt(&fd, sockopt::Ipv4PacketInfo, &true).map_err(nix_io)?;
                    bind(fd.as_raw_fd(), &SockaddrIn::from(a)).map_err(nix_io)?;
                }
                SocketAddr::V6(a) => {
                    // IPv4 has its own socket.
                    setsockopt(&fd, sockopt::Ipv6V6Only, &true).map_err(nix_io)?;
                    setsockopt(&fd, sockopt::Ipv6RecvPacketInfo, &true).map_err(nix_io)?;
                    bind(fd.as_raw_fd(), &SockaddrIn6::from(a)).map_err(nix_io)?;
                }
            }
            let sock = UdpSocket::from(fd);
            sock.set_read_timeout(Some(POLL))?;
            Ok(Self { sock, v6 })
        }

        /// One datagram: (length, client, the address it was sent to).
        pub(super) fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr, Option<IpAddr>)> {
            let mut cmsg = nix::cmsg_space!(libc::in6_pktinfo);
            let mut iov = [IoSliceMut::new(buf)];
            let msg = recvmsg::<SockaddrStorage>(
                self.sock.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg),
                MsgFlags::empty(),
            )
            .map_err(nix_io)?;
            let mut local = None;
            for c in msg.cmsgs().map_err(nix_io)? {
                match c {
                    ControlMessageOwned::Ipv4PacketInfo(i) => {
                        local = Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(i.ipi_addr.s_addr))));
                    }
                    ControlMessageOwned::Ipv6PacketInfo(i) => {
                        local = Some(IpAddr::V6(Ipv6Addr::from(i.ipi6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            let from = msg.address.as_ref().and_then(|a| {
                a.as_sockaddr_in()
                    .map(|v4| SocketAddr::from((v4.ip(), v4.port())))
                    .or_else(|| {
                        a.as_sockaddr_in6()
                            .map(|v6| SocketAddr::from((v6.ip(), v6.port())))
                    })
            });
            let from = from.ok_or_else(|| std::io::Error::other("datagram without a source"))?;
            Ok((msg.bytes, from, local))
        }

        /// Sends `bytes` to `to`, from `local` when known.
        pub(super) fn send(&self, bytes: &[u8], to: SocketAddr, local: Option<IpAddr>) {
            let iov = [IoSlice::new(bytes)];
            let sent = match (to, local) {
                (SocketAddr::V4(dst), Some(IpAddr::V4(src))) if !self.v6 => {
                    let info = libc::in_pktinfo {
                        ipi_ifindex: 0,
                        ipi_spec_dst: libc::in_addr {
                            s_addr: u32::from(src).to_be(),
                        },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    };
                    sendmsg(
                        self.sock.as_raw_fd(),
                        &iov,
                        &[ControlMessage::Ipv4PacketInfo(&info)],
                        MsgFlags::empty(),
                        Some(&SockaddrIn::from(dst)),
                    )
                }
                (SocketAddr::V6(dst), Some(IpAddr::V6(src))) if self.v6 => {
                    let info = libc::in6_pktinfo {
                        ipi6_addr: libc::in6_addr {
                            s6_addr: src.octets(),
                        },
                        ipi6_ifindex: 0,
                    };
                    sendmsg(
                        self.sock.as_raw_fd(),
                        &iov,
                        &[ControlMessage::Ipv6PacketInfo(&info)],
                        MsgFlags::empty(),
                        Some(&SockaddrIn6::from(dst)),
                    )
                }
                _ => self
                    .sock
                    .send_to(bytes, to)
                    .map_err(|e| nix::Error::from_raw(e.raw_os_error().unwrap_or(0))),
            };
            if let Err(e) = sent {
                log::debug!("DNS: reply to {to} not sent: {e}");
            }
        }
    }

    pub(super) fn bind_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
        let family = if addr.is_ipv6() {
            AddressFamily::Inet6
        } else {
            AddressFamily::Inet
        };
        let fd: OwnedFd =
            socket(family, SockType::Stream, SockFlag::SOCK_CLOEXEC, None).map_err(nix_io)?;
        setsockopt(&fd, sockopt::ReuseAddr, &true).map_err(nix_io)?;
        match addr {
            SocketAddr::V4(a) => bind(fd.as_raw_fd(), &SockaddrIn::from(a)).map_err(nix_io)?,
            SocketAddr::V6(a) => {
                setsockopt(&fd, sockopt::Ipv6V6Only, &true).map_err(nix_io)?;
                bind(fd.as_raw_fd(), &SockaddrIn6::from(a)).map_err(nix_io)?;
            }
        }
        let backlog = nix::sys::socket::Backlog::new(128).map_err(nix_io)?;
        nix::sys::socket::listen(&fd, backlog).map_err(nix_io)?;
        let l = TcpListener::from(fd);
        l.set_nonblocking(true)?;
        Ok(l)
    }
}

/// Elsewhere (the daemon on macOS/Windows runs the virtual lab): plain
/// `std::net`, answering from whatever address the system picks.
#[cfg(not(target_os = "linux"))]
mod sock {
    use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};

    use super::POLL;

    pub(super) struct Udp {
        sock: UdpSocket,
    }

    impl Udp {
        pub(super) fn bind(addr: SocketAddr) -> std::io::Result<Self> {
            let sock = UdpSocket::bind(addr)?;
            sock.set_read_timeout(Some(POLL))?;
            Ok(Self { sock })
        }

        pub(super) fn recv(
            &self,
            buf: &mut [u8],
        ) -> std::io::Result<(usize, SocketAddr, Option<IpAddr>)> {
            let (n, from) = self.sock.recv_from(buf)?;
            Ok((n, from, None))
        }

        pub(super) fn send(&self, bytes: &[u8], to: SocketAddr, _local: Option<IpAddr>) {
            if let Err(e) = self.sock.send_to(bytes, to) {
                log::debug!("DNS: reply to {to} not sent: {e}");
            }
        }
    }

    pub(super) fn bind_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
        let l = TcpListener::bind(addr)?;
        l.set_nonblocking(true)?;
        Ok(l)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};
    use corerouter_proto_dns::resolver::Settings;
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use serde_json::json;
    use std::net::UdpSocket;
    use std::time::Instant;

    fn free_port() -> u16 {
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        let p = u.local_addr().unwrap().port();
        let t = TcpListener::bind(("127.0.0.1", p));
        drop(u);
        if t.is_err() { free_port() } else { p }
    }

    fn query(name: &str, t: RecordType) -> Vec<u8> {
        let mut m = Message::query();
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), t));
        m.to_vec().unwrap()
    }

    /// A UDP query with a short wait (also used to see the listener is
    /// closed).
    fn udp(port: u16, q: &[u8]) -> Option<Message> {
        udp_within(port, q, Duration::from_millis(500))
    }

    fn udp_within(port: u16, q: &[u8], wait: Duration) -> Option<Message> {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(wait)).unwrap();
        s.send_to(q, ("127.0.0.1", port)).unwrap();
        let mut buf = [0u8; 4096];
        let (n, from) = s.recv_from(&mut buf).ok()?;
        assert_eq!(from, SocketAddr::from(([127, 0, 0, 1], port)), "answered from the address asked");
        Some(Message::from_vec(&buf[..n]).unwrap())
    }

    fn tcp(port: u16, q: &[u8]) -> Message {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut framed = u16::try_from(q.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(q);
        s.write_all(&framed).unwrap();
        let mut head = [0u8; 2];
        s.read_exact(&mut head).unwrap();
        let mut msg = vec![0u8; usize::from(u16::from_be_bytes(head))];
        s.read_exact(&mut msg).unwrap();
        Message::from_vec(&msg).unwrap()
    }

    fn wait(what: &str, mut ok: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !ok() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn the_virtual_lab_answers_only_on_the_loopback() {
        // audit-e2e: with `--backend virtual` the forwarder listened on
        // 0.0.0.0/[::], so the host's LAN reached the lab's resolver.
        assert!(is_lab(&shared(Session::virtual_lab())));
        assert!(listen_ips(true).iter().all(IpAddr::is_loopback));
        assert!(listen_ips(false).iter().all(IpAddr::is_unspecified));
    }

    #[test]
    fn answers_the_lan_over_udp_and_tcp() {
        let (up_port, count) =
            super::super::dns::tests::server(Ipv4Addr::new(192, 0, 2, 10), false);
        let dns = Arc::new(RouterDns::new());
        let st = Settings {
            servers: vec![IpAddr::from([127, 0, 0, 1])],
            port: up_port,
            // Generous: under a loaded full CI a 300 ms upstream timeout
            // made the resolver ask twice (the upstream count went to 2).
            server_timeout_ms: 3000,
            ..Settings::default()
        };
        dns.resolver.configure(st, 0);
        let session = shared(Session::virtual_lab());
        lock(&session)
            .execute(
                "ip.dns.static.add",
                &json!({"name": "vpn.lan", "type": "FWD", "forward_to": "127.0.0.1",
                    "address_list": "vpn"}),
            )
            .unwrap();
        lock(&session)
            .execute("ip.dns.static.add", &json!({"name": "nas.lan", "address": "192.168.88.2"}))
            .unwrap();
        let port = free_port();
        let shutdown = Shutdown::default();
        let srv = spawn(session.clone(), dns, port, shutdown.clone()).unwrap();
        thread::sleep(Duration::from_millis(1500));
        assert!(udp(port, &query("nas.lan.", RecordType::A)).is_none(), "off by default");

        lock(&session)
            .execute("ip.dns.set", &json!({"allow_remote_requests": true}))
            .unwrap();
        let mut got = None;
        wait("the listener", || {
            got = udp(port, &query("nas.lan.", RecordType::A));
            got.is_some()
        });
        let m = got.unwrap();
        assert_eq!(m.answers[0].data.to_string(), "192.168.88.2");
        assert_eq!(count.load(Ordering::Relaxed), 0, "static: upstream not asked");

        // Answers that wait for the upstream get a longer client wait
        // than the 500 ms of `udp` (the flaky part on a loaded machine).
        let slow = Duration::from_secs(5);
        let m = udp_within(port, &query("www.example.com.", RecordType::A), slow).unwrap();
        assert_eq!(m.answers[0].data.to_string(), "192.0.2.10");
        let m = tcp(port, &query("www.example.com.", RecordType::A));
        assert_eq!(m.answers[0].data.to_string(), "192.0.2.10");
        assert_eq!(count.load(Ordering::Relaxed), 1, "TCP answered from the cache");

        // FWD + address-list: the address lands in the firewall list.
        let m = udp_within(port, &query("vpn.lan.", RecordType::A), slow).unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::NoError);
        wait("the address list", || {
            let rows = lock(&session)
                .execute("ip.firewall.address-list.list", &json!({"list": "vpn"}))
                .unwrap();
            rows.as_array().is_some_and(|r| r.len() == 1)
        });
        // G4.1e: the chain counted all of it.
        let st = lock(&session)
            .execute("ip.dns.statistics.print", &json!({}))
            .unwrap();
        assert_eq!(st["resolver"], "router");
        assert_eq!(st["tcp"], 1);
        assert!(st["answered"]["static"].as_u64().unwrap() >= 1, "{st}");
        assert!(st["answered"]["upstream"].as_u64().unwrap() >= 1, "{st}");
        assert_eq!(st["answered"]["cache"], 1, "{st}");
        assert_eq!(st["clients"][0]["address"], "127.0.0.1");

        lock(&session)
            .execute("ip.dns.set", &json!({"allow_remote_requests": false}))
            .unwrap();
        wait("the listener to close", || {
            udp(port, &query("nas.lan.", RecordType::A)).is_none()
        });
        shutdown.close();
        drop(srv);
    }

    /// A forwarder answering the LAN on a free port; static `nas.lan`.
    fn lab() -> (Shared, Arc<Server>, u16, Shutdown) {
        let session = shared(Session::virtual_lab());
        lock(&session)
            .execute("ip.dns.static.add", &json!({"name": "nas.lan", "address": "192.168.88.2"}))
            .unwrap();
        lock(&session)
            .execute(
                "ip.dns.set",
                &json!({"allow_remote_requests": true, "max_concurrent_tcp_sessions": 4}),
            )
            .unwrap();
        let port = free_port();
        let shutdown = Shutdown::default();
        let srv = spawn(session.clone(), Arc::new(RouterDns::new()), port, shutdown.clone()).unwrap();
        wait("the listener", || udp(port, &query("nas.lan.", RecordType::A)).is_some());
        (session, srv, port, shutdown)
    }

    /// G3.9h: several readers share one UDP socket. Clients in parallel
    /// each get their own answer (the id they asked with), and turning the
    /// forwarder off stops every reader, not just one.
    #[test]
    fn parallel_clients_share_the_udp_readers() {
        let (session, srv, port, shutdown) = lab();
        assert!((1..=4).contains(&udp_threads()));
        thread::scope(|s| {
            for c in 0..8u16 {
                s.spawn(move || {
                    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
                    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                    for i in 0..50u16 {
                        let id = c * 1000 + i;
                        let mut m = Message::query();
                        m.metadata.id = id;
                        m.metadata.recursion_desired = true;
                        m.add_query(Query::query(Name::from_ascii("nas.lan.").unwrap(), RecordType::A));
                        sock.send_to(&m.to_vec().unwrap(), ("127.0.0.1", port)).unwrap();
                        let mut buf = [0u8; 512];
                        let n = sock.recv(&mut buf).unwrap();
                        let r = Message::from_vec(&buf[..n]).unwrap();
                        assert_eq!(r.metadata.id, id);
                        assert_eq!(r.answers[0].data.to_string(), "192.168.88.2");
                    }
                });
            }
        });
        lock(&session)
            .execute("ip.dns.set", &json!({"allow_remote_requests": false}))
            .unwrap();
        // Every reader is gone: no answer at all for a few polls in a row.
        wait("all readers to stop", || (0..4).all(|_| udp(port, &query("nas.lan.", RecordType::A)).is_none()));
        shutdown.close();
        drop(srv);
    }

    #[cfg(target_os = "linux")]
    /// Connects from source address `src` (any 127/8 address works on
    /// Linux loopback) and sends the first byte of a length.
    fn connect_from(src: [u8; 4], port: u16) -> TcpStream {
        use nix::sys::socket::{AddressFamily, SockFlag, SockType, SockaddrIn, bind, connect, socket};
        use std::os::fd::AsRawFd;
        let fd = socket(AddressFamily::Inet, SockType::Stream, SockFlag::SOCK_CLOEXEC, None).unwrap();
        bind(fd.as_raw_fd(), &SockaddrIn::new(src[0], src[1], src[2], src[3], 0)).unwrap();
        connect(fd.as_raw_fd(), &SockaddrIn::new(127, 0, 0, 1, port)).unwrap();
        let mut s = TcpStream::from(fd);
        s.write_all(&[0]).unwrap();
        s
    }

    /// RFC 7766 slots: one source cannot take them all, and a message that
    /// trickles in is cut at its deadline.
    #[cfg(target_os = "linux")]
    #[test]
    fn tcp_slots_survive_slow_and_greedy_peers() {
        let (_session, srv, port, shutdown) = lab();
        // 127.0.0.2 opens every slot there is and sends one byte each.
        let greedy: Vec<TcpStream> = (0..4).map(|_| connect_from([127, 0, 0, 2], port)).collect();
        thread::sleep(Duration::from_millis(300));
        // The LAN client still gets an answer over TCP.
        let m = tcp(port, &query("nas.lan.", RecordType::A));
        assert_eq!(m.answers[0].data.to_string(), "192.168.88.2");
        // A message trickling in one byte at a time is cut at its
        // deadline (TCP_MESSAGE, 2 s in tests), not kept alive by each byte.
        let mut slow = connect_from([127, 0, 0, 3], port);
        let t = Instant::now();
        let mut closed = false;
        while t.elapsed() < Duration::from_secs(6) {
            thread::sleep(Duration::from_millis(300));
            if slow.write_all(&[1]).is_err() {
                closed = true;
                break;
            }
        }
        assert!(closed, "the slow message was never cut");
        drop(greedy);
        shutdown.close();
        drop(srv);
    }

    /// G6.8: DNS Lookup asking as a LAN address, with each stage's
    /// decision. Outside allowed_from: REFUSED by the ACL and nothing
    /// counted; the router itself reaches the static entry.
    #[test]
    fn ask_as_a_client_goes_through_the_acl() {
        let (_session, srv, _port, shutdown) = lab();
        let before = srv.fwd.state::<corerouter_proto_dns::server::Statistics>().snapshot(10).counters.queries;
        let q = query("nas.lan.", RecordType::A);
        let d = srv.ask_as(&q, false, Some(IpAddr::from([203, 0, 113, 9])), true);
        assert_eq!(d.answered_by, "acl");
        let m = Message::from_vec(d.reply.as_deref().unwrap()).unwrap();
        assert_eq!(m.metadata.response_code, hickory_proto::op::ResponseCode::Refused);
        assert_eq!(d.explain[0].text(), "203.0.113.9 is not in allowed_from: REFUSED");
        let after = srv.fwd.state::<corerouter_proto_dns::server::Statistics>().snapshot(10).counters.queries;
        assert_eq!(after, before, "a simulated query is not counted");
        let d = srv.ask_as(&q, false, None, true);
        assert_eq!(d.answered_by, "static");
        let s = d.explain.iter().find(|x| x.stage == "static").unwrap();
        assert_eq!(s.text(), "static entry *1 (name=nas.lan) answers A");
        shutdown.close();
    }

    /// The effects queue is bounded: with the session lock held, a flood
    /// of address-list effects is dropped past the queue, not kept.
    #[test]
    fn effects_queue_is_bounded() {
        let (session, srv, _port, shutdown) = lab();
        let held = lock(&session);
        let mut d = Done {
            reply: None,
            effects: (0..100_000u32)
                .map(|i| Effect::AddressList {
                    list: "vpn".into(),
                    address: IpAddr::from(Ipv4Addr::from(i)),
                    timeout_secs: 60,
                })
                .collect(),
            answered_by: "test",
            explain: Vec::new(),
        };
        srv.effects(&mut d);
        let dropped = srv.effects_dropped.load(Ordering::Relaxed);
        assert!(dropped >= 100_000 - EFFECTS_QUEUE as u64 - 1, "{dropped} dropped");
        drop(held);
        shutdown.close();
    }

    /// The server the daemon starts takes a zone's UPDATE before any
    /// "dns-zones" thread ran: it got NOTIMP in that window while the zone
    /// already answered, and `nsupdate` failed under load (netns_dns_ddns,
    /// 2026-10-25). RFC 2136 §2.2: NOTIMP is for a server without UPDATE.
    #[test]
    fn the_daemons_server_takes_updates_before_the_zone_thread() {
        use hickory_proto::op::OpCode;
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
        use hickory_proto::rr::{RData, Record, TSigner};
        let session = shared(Session::virtual_lab());
        let key = lock(&session).execute("ip.dns.tsig-key.add", &json!({"name": "ddns"})).unwrap();
        let secret = corerouter_model::dns_tsig::base64_decode(key["secret"].as_str().unwrap()).unwrap();
        lock(&session)
            .execute("ip.dns.zone.add", &json!({"name": "lan.example", "update_keys": "ddns"}))
            .unwrap();
        let shutdown = Shutdown::default();
        // What `start` builds before `follow` opens the sockets; no zone thread.
        let (srv, _zones) = make(&session, Arc::new(RouterDns::new()), &shutdown).unwrap();
        srv.fwd.configure(Arc::new(lock(&session).store().running().clone()), Vec::new());

        let mut m = Message::query();
        m.metadata.op_code = OpCode::Update;
        m.add_query(Query::query(Name::from_ascii("lan.example.").unwrap(), RecordType::SOA));
        m.add_authority(Record::from_rdata(
            Name::from_ascii("pc.lan.example.").unwrap(),
            300,
            RData::A(A::new(192, 168, 88, 50)),
        ));
        let signer =
            TSigner::new(secret, TsigAlgorithm::HmacSha256, Name::from_ascii("ddns.").unwrap(), 300)
                .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (tsig, _) = signer.sign_message(&m, now).unwrap();
        m.set_signature(tsig);
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let replies = zone::xfr::intercept(&srv.fwd, &m.to_vec().unwrap(), client, false).unwrap();
        let r = Message::from_vec(replies.first().unwrap()).unwrap();
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert!(r.signature().is_some(), "RFC 8945 §5.3: signed answer");
        let rows = lock(&session)
            .execute("ip.dns.zone.record.print", &json!({"zone": "lan.example"}))
            .unwrap();
        assert_eq!(rows[0]["flags"], "D", "{rows}");
        shutdown.close();
    }
}
