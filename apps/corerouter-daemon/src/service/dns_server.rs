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
//! - one UDP thread per family: reads a query and runs the chain up to the
//!   cache; a cache hit is answered at once. A miss gets a thread of its
//!   own, at most `max_concurrent_queries` of them (more: SERVFAIL), so
//!   one slow upstream never holds the cache hits back.
//! - one TCP thread per family; a thread per connection, at most
//!   `max_concurrent_tcp_sessions`, closed after 10 s idle (RFC 7766 §6.2.3).
//! - "dns-effects": applies what the chain asks of the rest of the router
//!   (a static entry's address list) under the session lock, off the
//!   answering threads.
//!
//! On Linux, UDP sockets read the destination address of each query (IP_PKTINFO /
//! IPV6_RECVPKTINFO) and answer from it: a router with several addresses
//! on the LAN would otherwise answer from another one, and the client drops
//! the reply (dnsmasq and Unbound do the same).

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use corerouter_control::Shutdown;
use corerouter_engine::{Shared, lock};
use corerouter_model::Config;
use corerouter_proto_dns::server::{
    Done, Effect, Forwarder, MAX_QUERY, Pending, Start, allowed_networks,
};
use super::dns::RouterDns;
use sock::{Udp, bind_tcp};

/// RFC 1035 §4.2.1.
const DEFAULT_PORT: u16 = 53;
const TICK: Duration = Duration::from_secs(1);
/// How often the socket threads look at the stop signal.
const POLL: Duration = Duration::from_millis(250);
/// RFC 7766 §6.2.3: idle TCP connections are closed (a few seconds).
const TCP_IDLE: Duration = Duration::from_secs(10);
/// Queries answered on one TCP connection before it is closed.
const TCP_MAX_QUERIES: usize = 1000;

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
    effects: Mutex<Sender<Effect>>,
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
        let tx = self.effects.lock().unwrap_or_else(|e| e.into_inner());
        for e in done.effects.drain(..) {
            let _ = tx.send(e);
        }
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
                let sock = sock.clone();
                let worker = move || {
                    let mut d = pass.srv.finish(*p);
                    if let Some(r) = &d.reply {
                        sock.send(r, from, local);
                    }
                    pass.srv.effects(&mut d);
                };
                if let Err(e) = thread::Builder::new().name("dns-query".into()).spawn(worker) {
                    log::warn!("DNS: no thread for a query: {e}");
                }
            }
        }
    }
}

fn tcp_loop(srv: Arc<Server>, listener: TcpListener, epoch: u64) {
    while srv.alive(epoch) {
        let stream = match listener.accept() {
            Ok((s, _)) => s,
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
        let max = srv.fwd.config().config.ip.dns.max_concurrent_tcp_sessions;
        // Over the limit the connection just closes.
        let Some(pass) = Pass::enter(&srv, Which::Tcp, max) else {
            continue;
        };
        let session = move || tcp_session(&pass.srv, stream, epoch);
        if let Err(e) = thread::Builder::new().name("dns-tcp".into()).spawn(session) {
            log::warn!("DNS: no thread for a TCP session: {e}");
        }
    }
}

/// RFC 1035 §4.2.2 / RFC 7766: 2-byte length, then the message; several
/// queries per connection, answered in order.
fn tcp_session(srv: &Arc<Server>, mut s: TcpStream, epoch: u64) {
    let Ok(peer) = s.peer_addr() else { return };
    let _ = s.set_nonblocking(false);
    let _ = s.set_read_timeout(Some(TCP_IDLE));
    let _ = s.set_write_timeout(Some(TCP_IDLE));
    for _ in 0..TCP_MAX_QUERIES {
        if !srv.alive(epoch) {
            return;
        }
        let mut head = [0u8; 2];
        if s.read_exact(&mut head).is_err() {
            return;
        }
        let mut msg = vec![0u8; usize::from(u16::from_be_bytes(head))];
        if s.read_exact(&mut msg).is_err() {
            return;
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

/// The sockets of one epoch.
fn open(srv: &Arc<Server>, port: u16, epoch: u64) -> Result<(), String> {
    let mut opened = Vec::new();
    for ip in [IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V6(Ipv6Addr::UNSPECIFIED)] {
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
        opened.push((udp, tcp));
    }
    for (udp, tcp) in opened {
        let s = srv.clone();
        thread::Builder::new()
            .name("dns-udp".into())
            .spawn(move || udp_loop(s, udp, epoch))
            .map_err(|e| e.to_string())?;
        let s = srv.clone();
        thread::Builder::new()
            .name("dns-tcp-accept".into())
            .spawn(move || tcp_loop(s, tcp, epoch))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
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

/// Starts the forwarder on `port`: it follows the config from then on.
pub(crate) fn spawn(
    session: Shared,
    dns: Arc<RouterDns>,
    port: u16,
    shutdown: Shutdown,
) -> std::io::Result<Arc<Server>> {
    let (tx, rx) = channel();
    let srv = Arc::new(Server {
        fwd: Forwarder::new(dns.resolver.clone()),
        dns,
        queries: Gate::default(),
        tcp: Gate::default(),
        effects: Mutex::new(tx),
        epoch: AtomicU64::new(0),
        shutdown,
    });
    {
        let session = session.clone();
        thread::Builder::new()
            .name("dns-effects".into())
            .spawn(move || apply_effects(&session, &rx))?;
    }
    let keep = srv.clone();
    thread::Builder::new()
        .name("dns-server".into())
        .spawn(move || follow(&session, &keep, port))?;
    Ok(srv)
}

/// Copies the config in when it changes; opens and closes the sockets.
fn follow(session: &Shared, srv: &Arc<Server>, port: u16) {
    let mut last: Option<Config> = None;
    let mut listening = false;
    let mut retry_at = 0u64;
    loop {
        if srv.shutdown.is_closed() {
            srv.epoch.fetch_add(1, Ordering::AcqRel);
            return;
        }
        let changed = {
            let s = lock(session);
            let running = s.store().running();
            if last.as_ref() == Some(running) {
                None
            } else {
                Some(running.clone())
            }
        };
        if let Some(cfg) = changed {
            let allowed = allowed_networks(&cfg);
            srv.fwd.configure(Arc::new(cfg.clone()), allowed);
            last = Some(cfg);
        }
        let want = last.as_ref().is_some_and(|c| c.ip.dns.allow_remote_requests);
        let now = srv.dns.now_ms();
        if want && !listening && now >= retry_at {
            let epoch = srv.epoch.fetch_add(1, Ordering::AcqRel) + 1;
            match open(srv, port, epoch) {
                Ok(()) => {
                    listening = true;
                    log::info!("DNS: answering the LAN on port {port} (UDP, TCP)");
                }
                Err(e) => {
                    // Closes whatever this attempt opened.
                    srv.epoch.fetch_add(1, Ordering::AcqRel);
                    retry_at = now + 10_000;
                    log::error!("DNS: cannot answer the LAN: {e}; retrying in 10 s");
                }
            }
        } else if !want && listening {
            srv.epoch.fetch_add(1, Ordering::AcqRel);
            listening = false;
            log::info!("DNS: no longer answering the LAN (allow_remote_requests off)");
        }
        thread::sleep(TICK);
    }
}

pub(crate) const SERVICE: super::Service = super::Service {
    name: "dns server",
    flags: &[super::Flag {
        name: "--dns-port",
        value: Some("<port>"),
        help: "port of the LAN DNS forwarder (default 53; on with\nip.dns.set allow_remote_requests=yes)",
    }],
    start,
};

/// Without the resolver (its thread failed) there is nothing to forward to:
/// logged, not fatal.
fn start(ctx: &super::Ctx) -> Result<(), String> {
    let port = match ctx.flag("--dns-port") {
        None => DEFAULT_PORT,
        Some(p) => p
            .parse()
            .map_err(|_| format!("--dns-port: '{p}' is not a port"))?,
    };
    let Some(dns) = super::dns::router() else {
        log::error!("DNS server is off: the resolver did not start");
        return Ok(());
    };
    match spawn(ctx.session.clone(), dns, port, ctx.shutdown.clone()) {
        Ok(srv) => {
            let _ = SERVER.set(srv);
        }
        Err(e) => log::error!("DNS server is off: cannot start its threads: {e}"),
    }
    Ok(())
}

/// The forwarder, once started (the adlist loader fills its lists).
static SERVER: std::sync::OnceLock<Arc<Server>> = std::sync::OnceLock::new();

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

    fn udp(port: u16, q: &[u8]) -> Option<Message> {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
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
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ok() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn answers_the_lan_over_udp_and_tcp() {
        let (up_port, count) =
            super::super::dns::tests::server(Ipv4Addr::new(192, 0, 2, 10), false);
        let dns = Arc::new(RouterDns::new());
        let st = Settings {
            servers: vec![IpAddr::from([127, 0, 0, 1])],
            port: up_port,
            server_timeout_ms: 300,
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

        let m = udp(port, &query("www.example.com.", RecordType::A)).unwrap();
        assert_eq!(m.answers[0].data.to_string(), "192.0.2.10");
        let m = tcp(port, &query("www.example.com.", RecordType::A));
        assert_eq!(m.answers[0].data.to_string(), "192.0.2.10");
        assert_eq!(count.load(Ordering::Relaxed), 1, "TCP answered from the cache");

        // FWD + address-list: the address lands in the firewall list.
        let m = udp(port, &query("vpn.lan.", RecordType::A)).unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::NoError);
        wait("the address list", || {
            let rows = lock(&session)
                .execute("ip.firewall.address-list.list", &json!({"list": "vpn"}))
                .unwrap();
            rows.as_array().is_some_and(|r| r.len() == 1)
        });

        lock(&session)
            .execute("ip.dns.set", &json!({"allow_remote_requests": false}))
            .unwrap();
        wait("the listener to close", || {
            udp(port, &query("nas.lan.", RecordType::A)).is_none()
        });
        shutdown.close();
        drop(srv);
    }
}
