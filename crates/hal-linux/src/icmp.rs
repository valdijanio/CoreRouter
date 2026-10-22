//! Host ICMP for the diagnostic tools: [`HostProber`] implements
//! `corerouter_hal::probe::Prober` over the kernel's sockets.
//!
//! Two kinds of socket, tried in this order per address family:
//!
//! 1. **Ping socket** (`SOCK_DGRAM` + `IPPROTO_ICMP`/`ICMPV6`): no
//!    privilege, allowed when the process' group is inside
//!    `net.ipv4.ping_group_range` (per network namespace; it also covers
//!    IPv6). The kernel picks the echo identifier and hands this socket only
//!    its own replies; ICMP errors about our probes (TTL exceeded,
//!    unreachable, fragmentation needed) arrive on the error queue
//!    (`IP_RECVERR`), TTL / hop limit in a control message.
//! 2. **Raw socket** (`SOCK_RAW`): needs `CAP_NET_RAW` (the production
//!    daemon has it). Sees every ICMP packet of the host, so replies are
//!    matched by our identifier and the probe quoted inside ICMP errors.
//!
//! No `unsafe`: sockets and options come from `socket2`, `nix` (error queue,
//! control messages, poll) and `rustix` (`IP_MTU_DISCOVER`). Sizes are
//! whole IP packets. RTT is measured from `sendto` to the `recvmsg` that
//! returns the answer; `recv` waits on both families at once (`poll`) so
//! neither delays the other.

use std::collections::HashMap;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use corerouter_hal::probe::{
    Family, Probe, ProbeError, ProbeSocket, Prober, Reply, ReplyKind, SocketOptions, overhead,
};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{
    ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg, setsockopt, sockopt,
};
use rustix::net::sockopt::{
    Ipv4PathMtuDiscovery, Ipv6PathMtuDiscovery, set_ip_mtu_discover, set_ipv6_mtu_discover,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_UNREACH: u8 = 3;
const ICMP_ECHO: u8 = 8;
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP_FRAG_NEEDED: u8 = 4;
const ICMP6_UNREACH: u8 = 1;
const ICMP6_TOO_BIG: u8 = 2;
const ICMP6_TIME_EXCEEDED: u8 = 3;
const ICMP6_ECHO: u8 = 128;
const ICMP6_ECHO_REPLY: u8 = 129;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;
/// `SO_EE_ORIGIN_*` of `sock_extended_err`.
const ORIGIN_LOCAL: u8 = 1;
const ORIGIN_ICMP: u8 = 2;
const ORIGIN_ICMP6: u8 = 3;
/// Default TTL / hop limit when a probe names none.
const DEFAULT_TTL: u8 = 64;
/// Probes remembered for RTT and matching (older ones are forgotten).
const MAX_SENT: usize = 8192;
const SENT_TTL: Duration = Duration::from_secs(120);
/// Control messages (TTL, hop limit, extended error + offender) fit easily.
const CMSG_BUF: usize = 512;
/// Receive buffer: the largest IPv4 packet.
const BUF: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Unprivileged ping socket.
    Ping,
    /// Raw ICMP socket (`CAP_NET_RAW`).
    Raw,
}

impl Kind {
    fn ty(self) -> Type {
        match self {
            Kind::Ping => Type::DGRAM,
            Kind::Raw => Type::RAW,
        }
    }
}

/// Why no ICMP socket could be opened, with the fixes.
pub fn hint(e: &io::Error) -> String {
    format!(
        "cannot open an ICMP socket ({e}): give the daemon CAP_NET_RAW \
         (`setcap cap_net_raw+ep corerouter-daemon`) or allow ping sockets for its \
         group (`sysctl net.ipv4.ping_group_range=\"0 2147483647\"`)"
    )
}

fn open_raw(family: Family, kind: Kind) -> io::Result<Socket> {
    let (domain, proto) = match family {
        Family::V4 => (Domain::IPV4, Protocol::ICMPV4),
        Family::V6 => (Domain::IPV6, Protocol::ICMPV6),
    };
    Socket::new(domain, kind.ty(), Some(proto))
}

/// The host's ICMP. Built by [`HostProber::detect`], which fails (with the
/// reason) when neither kind of socket may be opened.
#[derive(Debug, Clone)]
pub struct HostProber {
    v4: Kind,
}

impl HostProber {
    /// Try a ping socket, then a raw one (IPv4 decides the description;
    /// IPv6 is tried the same way when first used).
    pub fn detect() -> Result<Self, String> {
        match open_raw(Family::V4, Kind::Ping) {
            Ok(_) => Ok(Self { v4: Kind::Ping }),
            Err(ping) => match open_raw(Family::V4, Kind::Raw) {
                Ok(_) => Ok(Self { v4: Kind::Raw }),
                Err(_) => Err(hint(&ping)),
            },
        }
    }

    /// Only `kind` sockets (tests).
    pub fn with_kind(kind: Kind) -> Self {
        Self { v4: kind }
    }

    pub fn kind(&self) -> Kind {
        self.v4
    }
}

impl Prober for HostProber {
    fn describe(&self) -> String {
        match self.v4 {
            Kind::Ping => "host ICMP (ping socket)".into(),
            Kind::Raw => "host ICMP (raw socket)".into(),
        }
    }

    /// Never the host's resolver (`/etc/resolv.conf` points at a
    /// `127.0.0.53` that the router's namespace and image do not have):
    /// names come from the router's own resolver (G4.1a, `ip.dns`), which
    /// the engine puts in front of this prober. Reaching here means it has
    /// no server to ask.
    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, ProbeError> {
        let shown: String = name.chars().take(64).collect();
        Err(ProbeError::Unavailable(format!(
            "cannot resolve '{shown}': no DNS server configured (ip.dns.set servers=…, \
             or a DHCP client with use_peer_dns)"
        )))
    }

    fn open(&self, options: &SocketOptions) -> Result<Box<dyn ProbeSocket>, ProbeError> {
        Ok(Box::new(HostSocket {
            options: options.clone(),
            prefer: self.v4,
            v4: None,
            v6: None,
            sent: HashMap::new(),
            buf: vec![0u8; BUF],
        }))
    }
}

/// One family's socket.
struct Side {
    sock: Socket,
    kind: Kind,
    family: Family,
    /// Echo identifier (raw sockets; the kernel sets it on ping sockets).
    ident: u16,
    ttl: Option<u8>,
}

struct Sent {
    at: Instant,
    dst: IpAddr,
}

struct HostSocket {
    options: SocketOptions,
    prefer: Kind,
    v4: Option<Result<Side, ProbeError>>,
    v6: Option<Result<Side, ProbeError>>,
    sent: HashMap<u16, Sent>,
    buf: Vec<u8>,
}

fn next_ident() -> u16 {
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let pid = std::process::id() as u16;
    pid.wrapping_add(NEXT.fetch_add(0x9e37, Ordering::Relaxed))
}

fn nix_io(e: Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

fn open_side(family: Family, prefer: Kind, o: &SocketOptions) -> Result<Side, ProbeError> {
    let order = match prefer {
        Kind::Ping => [Kind::Ping, Kind::Raw],
        Kind::Raw => [Kind::Raw, Kind::Ping],
    };
    let mut first: Option<io::Error> = None;
    for kind in order {
        match open_raw(family, kind) {
            Ok(sock) => {
                return configure(sock, kind, family, o)
                    .map_err(|e| ProbeError::Unavailable(format!("ICMP socket setup: {e}")));
            }
            Err(e) => {
                first.get_or_insert(e);
            }
        }
    }
    let e = first.unwrap_or_else(|| io::Error::other("no socket kind"));
    Err(ProbeError::Unavailable(match family {
        Family::V4 => hint(&e),
        Family::V6 => format!("IPv6: {}", hint(&e)),
    }))
}

fn configure(sock: Socket, kind: Kind, family: Family, o: &SocketOptions) -> io::Result<Side> {
    sock.set_nonblocking(true)?;
    if let Some(dev) = &o.device {
        sock.bind_device(Some(dev.as_bytes())).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("binding to {dev} needs CAP_NET_RAW and an existing device: {e}"),
            )
        })?;
    }
    match family {
        Family::V4 => {
            sock.set_tos_v4(u32::from(o.tos))?;
            let pmtu = if o.dont_fragment {
                Ipv4PathMtuDiscovery::DO
            } else {
                Ipv4PathMtuDiscovery::DONT
            };
            set_ip_mtu_discover(sock.as_fd(), pmtu)?;
            if kind == Kind::Ping {
                setsockopt(&sock, sockopt::Ipv4RecvErr, &true).map_err(nix_io)?;
                setsockopt(&sock, sockopt::Ipv4RecvTtl, &true).map_err(nix_io)?;
            }
        }
        Family::V6 => {
            sock.set_tclass_v6(u32::from(o.tos))?;
            if o.dont_fragment {
                set_ipv6_mtu_discover(sock.as_fd(), Ipv6PathMtuDiscovery::DO)?;
            }
            setsockopt(&sock, sockopt::Ipv6RecvHopLimit, &true).map_err(nix_io)?;
            if kind == Kind::Ping {
                setsockopt(&sock, sockopt::Ipv6RecvErr, &true).map_err(nix_io)?;
            }
        }
    }
    if let Some(src) = o.src.filter(|s| Family::of(*s) == family) {
        sock.bind(&SockAddr::from(SocketAddr::new(src, 0)))
            .map_err(|e| io::Error::new(e.kind(), format!("source {src}: {e}")))?;
    }
    Ok(Side {
        sock,
        kind,
        family,
        ident: next_ident(),
        ttl: None,
    })
}

/// RFC 1071 Internet checksum.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (pairs, rest) = data.as_chunks::<2>();
    for pair in pairs {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes(*pair)));
    }
    if let [last] = rest {
        sum = sum.wrapping_add(u32::from(*last) << 8);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Echo request: header + `payload` bytes of a counting pattern.
pub fn echo_request(family: Family, ident: u16, seq: u16, payload: usize) -> Vec<u8> {
    let ty = match family {
        Family::V4 => ICMP_ECHO,
        Family::V6 => ICMP6_ECHO,
    };
    let mut p = Vec::with_capacity(8 + payload);
    p.extend_from_slice(&[ty, 0, 0, 0]);
    p.extend_from_slice(&ident.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend((0..payload).map(|i| (i % 256) as u8));
    // ICMPv6 checksums cover a pseudo-header: the kernel fills them in.
    if family == Family::V4 {
        let c = checksum(&p).to_be_bytes();
        if let Some(slot) = p.get_mut(2..4) {
            slot.copy_from_slice(&c);
        }
    }
    p
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(at)?,
        *b.get(at + 1)?,
        *b.get(at + 2)?,
        *b.get(at + 3)?,
    ]))
}

fn unreach_v4(code: u8) -> String {
    match code {
        0 => "network unreachable",
        1 => "host unreachable",
        2 => "protocol unreachable",
        3 => "port unreachable",
        5 => "source route failed",
        6 | 7 => "destination unknown",
        9 | 10 | 13 => "administratively prohibited",
        _ => "destination unreachable",
    }
    .to_owned()
}

fn unreach_v6(code: u8) -> String {
    match code {
        0 => "no route to destination",
        1 => "administratively prohibited",
        2 => "beyond scope of source address",
        3 => "address unreachable",
        4 => "port unreachable",
        5 | 6 => "rejected by policy",
        _ => "destination unreachable",
    }
    .to_owned()
}

/// What a received ICMP message says, before RTT matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub seq: u16,
    /// Identifier of the echo it is about (raw sockets check it).
    pub ident: u16,
    pub kind: ReplyKind,
    pub size: Option<u16>,
    pub ttl: Option<u8>,
}

/// The echo header quoted inside an ICMP error: `(ident, seq)`.
fn quoted_v4(inner: &[u8]) -> Option<(u16, u16)> {
    let ihl = usize::from(*inner.first()? & 0x0f) * 4;
    if *inner.get(9)? != IPPROTO_ICMP {
        return None;
    }
    let echo = inner.get(ihl..)?;
    (*echo.first()? == ICMP_ECHO).then_some(())?;
    Some((be16(echo, 4)?, be16(echo, 6)?))
}

fn quoted_v6(inner: &[u8]) -> Option<(u16, u16)> {
    // No extension headers: our probes carry none.
    if *inner.get(6)? != IPPROTO_ICMPV6 {
        return None;
    }
    let echo = inner.get(40..)?;
    (*echo.first()? == ICMP6_ECHO).then_some(())?;
    Some((be16(echo, 4)?, be16(echo, 6)?))
}

/// A raw IPv4 packet (IP header included).
pub fn parse_raw_v4(pkt: &[u8]) -> Option<Parsed> {
    let ihl = usize::from(*pkt.first()? & 0x0f) * 4;
    if ihl < 20 || *pkt.get(9)? != IPPROTO_ICMP {
        return None;
    }
    let ttl = *pkt.get(8)?;
    let total = be16(pkt, 2)?;
    let icmp = pkt.get(ihl..)?;
    let (ty, code) = (*icmp.first()?, *icmp.get(1)?);
    let (ident, seq, kind) = match ty {
        ICMP_ECHO_REPLY => (be16(icmp, 4)?, be16(icmp, 6)?, ReplyKind::Echo),
        ICMP_TIME_EXCEEDED | ICMP_UNREACH => {
            let (ident, seq) = quoted_v4(icmp.get(8..)?)?;
            let kind = match (ty, code) {
                (ICMP_TIME_EXCEEDED, _) => ReplyKind::TtlExceeded,
                (_, ICMP_FRAG_NEEDED) => ReplyKind::TooBig {
                    mtu: be16(icmp, 6).filter(|m| *m > 0),
                },
                _ => ReplyKind::Unreachable(unreach_v4(code)),
            };
            (ident, seq, kind)
        }
        _ => return None,
    };
    Some(Parsed {
        seq,
        ident,
        kind,
        size: Some(total),
        ttl: Some(ttl),
    })
}

/// A raw ICMPv6 message (the kernel strips the IPv6 header).
pub fn parse_raw_v6(icmp: &[u8], hop_limit: Option<u8>) -> Option<Parsed> {
    let (ty, code) = (*icmp.first()?, *icmp.get(1)?);
    let (ident, seq, kind) = match ty {
        ICMP6_ECHO_REPLY => (be16(icmp, 4)?, be16(icmp, 6)?, ReplyKind::Echo),
        ICMP6_TIME_EXCEEDED | ICMP6_UNREACH | ICMP6_TOO_BIG => {
            let (ident, seq) = quoted_v6(icmp.get(8..)?)?;
            let kind = match ty {
                ICMP6_TIME_EXCEEDED => ReplyKind::TtlExceeded,
                ICMP6_TOO_BIG => ReplyKind::TooBig {
                    mtu: be32(icmp, 4).map(|m| u16::try_from(m).unwrap_or(u16::MAX)),
                },
                _ => ReplyKind::Unreachable(unreach_v6(code)),
            };
            (ident, seq, kind)
        }
        _ => return None,
    };
    Some(Parsed {
        seq,
        ident,
        kind,
        size: u16::try_from(icmp.len() + 40).ok(),
        ttl: hop_limit,
    })
}

fn to_ip(a: &SockaddrStorage) -> Option<IpAddr> {
    if let Some(v4) = a.as_sockaddr_in() {
        return Some(IpAddr::V4(v4.ip()));
    }
    a.as_sockaddr_in6().map(|v6| IpAddr::V6(v6.ip()))
}

fn ip_of_v4(sa: &nix::libc::sockaddr_in) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)))
}

fn ip_of_v6(sa: &nix::libc::sockaddr_in6) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr))
}

/// One message read off a socket.
enum Got {
    /// Nothing (more) to read now.
    Empty,
    /// Not about one of our probes; read on.
    Skip,
    Msg(Parsed, IpAddr),
}

/// What an error-queue entry says about a probe (`None`: not about one).
fn error_kind(ee: &nix::libc::sock_extended_err) -> Option<ReplyKind> {
    let mtu = u16::try_from(ee.ee_info).ok().filter(|m| *m > 0);
    Some(match (ee.ee_origin, ee.ee_type, ee.ee_code) {
        (ORIGIN_ICMP, ICMP_TIME_EXCEEDED, _) | (ORIGIN_ICMP6, ICMP6_TIME_EXCEEDED, _) => {
            ReplyKind::TtlExceeded
        }
        (ORIGIN_ICMP, ICMP_UNREACH, ICMP_FRAG_NEEDED) | (ORIGIN_ICMP6, ICMP6_TOO_BIG, _) => {
            ReplyKind::TooBig { mtu }
        }
        (ORIGIN_ICMP, ICMP_UNREACH, code) => ReplyKind::Unreachable(unreach_v4(code)),
        (ORIGIN_ICMP6, ICMP6_UNREACH, code) => ReplyKind::Unreachable(unreach_v6(code)),
        (ORIGIN_LOCAL, _, _) if ee.ee_errno == Errno::EMSGSIZE as u32 => ReplyKind::TooBig { mtu },
        (ORIGIN_LOCAL, _, _) => {
            let e = Errno::from_raw(i32::try_from(ee.ee_errno).unwrap_or(0));
            ReplyKind::Unreachable(e.desc().to_lowercase())
        }
        _ => return None,
    })
}

impl Side {
    /// One normal datagram, without waiting.
    fn read(&self, buf: &mut [u8]) -> io::Result<Got> {
        let mut cmsg = vec![0u8; CMSG_BUF];
        let (n, from, ttl) = {
            let mut iov = [IoSliceMut::new(buf)];
            let msg = match recvmsg::<SockaddrStorage>(
                self.sock.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg),
                MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(m) => m,
                Err(Errno::EAGAIN) => return Ok(Got::Empty),
                // A ping socket also reports an ICMP error here once (its
                // details are on the error queue, read separately).
                Err(
                    Errno::EHOSTUNREACH
                    | Errno::ENETUNREACH
                    | Errno::EMSGSIZE
                    | Errno::ECONNREFUSED
                    | Errno::EPROTO
                    | Errno::EACCES,
                ) => return Ok(Got::Skip),
                Err(e) => return Err(nix_io(e)),
            };
            let mut ttl = None;
            for c in msg.cmsgs().map_err(nix_io)? {
                match c {
                    ControlMessageOwned::Ipv4Ttl(t) => ttl = u8::try_from(t).ok(),
                    ControlMessageOwned::Ipv6HopLimit(t) => ttl = u8::try_from(t).ok(),
                    _ => {}
                }
            }
            (msg.bytes, msg.address.as_ref().and_then(to_ip), ttl)
        };
        let Some(from) = from else {
            return Ok(Got::Skip);
        };
        let data = buf.get(..n).unwrap_or_default();
        let parsed = match (self.kind, self.family) {
            (Kind::Raw, Family::V4) => parse_raw_v4(data).filter(|p| p.ident == self.ident),
            (Kind::Raw, Family::V6) => parse_raw_v6(data, ttl).filter(|p| p.ident == self.ident),
            // A ping socket receives only its own echo replies.
            (Kind::Ping, family) => {
                let reply = match family {
                    Family::V4 => ICMP_ECHO_REPLY,
                    Family::V6 => ICMP6_ECHO_REPLY,
                };
                (data.first() == Some(&reply))
                    .then(|| {
                        Some(Parsed {
                            seq: be16(data, 6)?,
                            ident: be16(data, 4)?,
                            kind: ReplyKind::Echo,
                            size: u16::try_from(n + usize::from(overhead(from)) - 8).ok(),
                            ttl,
                        })
                    })
                    .flatten()
            }
        };
        Ok(parsed.map_or(Got::Skip, |p| Got::Msg(p, from)))
    }

    /// One entry of a ping socket's error queue, without waiting.
    fn read_error(&self, buf: &mut [u8]) -> io::Result<Got> {
        if self.kind != Kind::Ping {
            return Ok(Got::Empty);
        }
        let mut cmsg = vec![0u8; CMSG_BUF];
        let (n, dst, found) = {
            let mut iov = [IoSliceMut::new(buf)];
            let msg = match recvmsg::<SockaddrStorage>(
                self.sock.as_raw_fd(),
                &mut iov,
                Some(&mut cmsg),
                MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(m) => m,
                Err(Errno::EAGAIN) => return Ok(Got::Empty),
                Err(e) => return Err(nix_io(e)),
            };
            let mut found = None;
            for c in msg.cmsgs().map_err(nix_io)? {
                let (ee, offender) = match c {
                    ControlMessageOwned::Ipv4RecvErr(ee, a) => (ee, a.as_ref().map(ip_of_v4)),
                    ControlMessageOwned::Ipv6RecvErr(ee, a) => (ee, a.as_ref().map(ip_of_v6)),
                    _ => continue,
                };
                if let Some(kind) = error_kind(&ee) {
                    found = Some((kind, offender));
                }
            }
            (msg.bytes, msg.address.as_ref().and_then(to_ip), found)
        };
        let Some((kind, offender)) = found else {
            return Ok(Got::Skip);
        };
        // The payload is the echo request we sent.
        let data = buf.get(..n).unwrap_or_default();
        let (Some(ident), Some(seq)) = (be16(data, 4), be16(data, 6)) else {
            return Ok(Got::Skip);
        };
        let Some(from) = offender.or(dst) else {
            return Ok(Got::Skip);
        };
        Ok(Got::Msg(
            Parsed {
                seq,
                ident,
                kind,
                size: None,
                ttl: None,
            },
            from,
        ))
    }
}

impl HostSocket {
    fn side(&mut self, family: Family) -> Result<&mut Side, ProbeError> {
        let slot = match family {
            Family::V4 => &mut self.v4,
            Family::V6 => &mut self.v6,
        };
        let opened = slot.get_or_insert_with(|| open_side(family, self.prefer, &self.options));
        opened.as_mut().map_err(|e| e.clone())
    }

    fn forget_old(&mut self) {
        if self.sent.len() < MAX_SENT {
            return;
        }
        let now = Instant::now();
        self.sent.retain(|_, s| now.duration_since(s.at) < SENT_TTL);
        if self.sent.len() >= MAX_SENT {
            self.sent.clear();
        }
    }

    /// Turn a parsed message into a reply to one of our probes.
    fn matched(&self, p: Parsed, from: IpAddr) -> Option<Reply> {
        let sent = self.sent.get(&p.seq)?;
        // An echo reply must come from where the probe went.
        if p.kind == ReplyKind::Echo && from != sent.dst {
            return None;
        }
        Some(Reply {
            seq: p.seq,
            from,
            kind: p.kind,
            size: p.size,
            ttl: p.ttl,
            rtt: sent.at.elapsed(),
        })
    }

    /// Everything readable now, first match wins.
    fn drain(&mut self) -> Result<Option<Reply>, ProbeError> {
        let io = |e: io::Error| ProbeError::Io(e.to_string());
        for family in [Family::V4, Family::V6] {
            loop {
                let slot = match family {
                    Family::V4 => &self.v4,
                    Family::V6 => &self.v6,
                };
                let Some(Ok(side)) = slot else { break };
                let mut got = side.read_error(&mut self.buf).map_err(io)?;
                if matches!(got, Got::Empty) {
                    got = side.read(&mut self.buf).map_err(io)?;
                }
                match got {
                    Got::Empty => break,
                    Got::Skip => {}
                    Got::Msg(p, from) => {
                        if let Some(r) = self.matched(p, from) {
                            return Ok(Some(r));
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}

impl ProbeSocket for HostSocket {
    fn send(&mut self, probe: &Probe) -> Result<(), ProbeError> {
        let family = Family::of(probe.dst);
        self.forget_old();
        let side = self.side(family)?;
        let ttl = probe.ttl.unwrap_or(DEFAULT_TTL);
        if side.ttl != Some(ttl) {
            let set = match family {
                Family::V4 => side.sock.set_ttl_v4(u32::from(ttl)),
                Family::V6 => side.sock.set_unicast_hops_v6(u32::from(ttl)),
            };
            set.map_err(|e| ProbeError::Io(format!("TTL {ttl}: {e}")))?;
            side.ttl = Some(ttl);
        }
        let payload = usize::from(probe.size.saturating_sub(overhead(probe.dst)));
        let packet = echo_request(family, side.ident, probe.seq, payload);
        let to = SockAddr::from(SocketAddr::new(probe.dst, 0));
        let at = Instant::now();
        match side.sock.send_to(&packet, &to) {
            Ok(_) => {}
            Err(e) => {
                return Err(match e.raw_os_error().map(Errno::from_raw) {
                    Some(Errno::EMSGSIZE) => ProbeError::TooBig(None),
                    Some(
                        Errno::ENETUNREACH
                        | Errno::EHOSTUNREACH
                        | Errno::ENETDOWN
                        | Errno::EHOSTDOWN,
                    ) => ProbeError::Unreachable(e.to_string()),
                    Some(Errno::EACCES | Errno::EPERM) => {
                        ProbeError::Unreachable(format!("not permitted (firewall?): {e}"))
                    }
                    _ => ProbeError::Io(e.to_string()),
                });
            }
        }
        self.sent.insert(probe.seq, Sent { at, dst: probe.dst });
        Ok(())
    }

    fn recv(&mut self, wait: Duration) -> Result<Option<Reply>, ProbeError> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(r) = self.drain()? {
                return Ok(Some(r));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            let timeout = PollTimeout::try_from(left).unwrap_or(PollTimeout::MAX);
            let mut fds: Vec<PollFd> = [&self.v4, &self.v6]
                .into_iter()
                .filter_map(|s| match s {
                    Some(Ok(side)) => Some(PollFd::new(side.sock.as_fd(), PollFlags::POLLIN)),
                    _ => None,
                })
                .collect();
            if fds.is_empty() {
                // Nothing open yet (every send failed): just wait.
                std::thread::sleep(left);
                return Ok(None);
            }
            match poll(&mut fds, timeout) {
                Ok(0) => return Ok(None),
                Ok(_) | Err(Errno::EINTR) => {}
                Err(e) => return Err(ProbeError::Io(format!("poll: {e}"))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_a_known_echo() {
        // ping -c1 style request: type 8, id 0x1234, seq 1, no payload.
        let p = echo_request(Family::V4, 0x1234, 1, 0);
        assert_eq!(checksum(&p), 0, "a packet with its checksum sums to zero");
        let p = echo_request(Family::V4, 7, 9, 57);
        assert_eq!(p.len(), 65);
        assert_eq!(checksum(&p), 0);
    }

    fn ipv4(proto: u8, ttl: u8, payload: &[u8]) -> Vec<u8> {
        let total = (20 + payload.len()) as u16;
        let mut h = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, ttl, proto, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        h[2..4].copy_from_slice(&total.to_be_bytes());
        h.extend_from_slice(payload);
        h
    }

    #[test]
    fn parses_raw_v4_replies_and_errors() {
        let mut reply = echo_request(Family::V4, 0x55, 3, 4);
        reply[0] = ICMP_ECHO_REPLY;
        let p = parse_raw_v4(&ipv4(1, 61, &reply)).unwrap();
        assert_eq!(
            (p.ident, p.seq, p.ttl, p.size),
            (0x55, 3, Some(61), Some(32))
        );
        assert_eq!(p.kind, ReplyKind::Echo);

        let quoted = ipv4(1, 1, &echo_request(Family::V4, 0x55, 4, 0));
        let mut te = vec![ICMP_TIME_EXCEEDED, 0, 0, 0, 0, 0, 0, 0];
        te.extend_from_slice(&quoted);
        let p = parse_raw_v4(&ipv4(1, 255, &te)).unwrap();
        assert_eq!((p.seq, p.kind.clone()), (4, ReplyKind::TtlExceeded));

        let mut fragn = vec![ICMP_UNREACH, ICMP_FRAG_NEEDED, 0, 0, 0, 0, 0x05, 0x78];
        fragn.extend_from_slice(&quoted);
        let p = parse_raw_v4(&ipv4(1, 255, &fragn)).unwrap();
        assert_eq!(p.kind, ReplyKind::TooBig { mtu: Some(1400) });

        // Our own echo request (loopback) and garbage are not replies.
        assert!(parse_raw_v4(&ipv4(1, 64, &echo_request(Family::V4, 1, 1, 0))).is_none());
        assert!(parse_raw_v4(&[0x45, 0]).is_none());
        assert!(parse_raw_v4(&ipv4(17, 64, &[0; 8])).is_none());
    }

    #[test]
    fn parses_raw_v6_replies_and_errors() {
        let mut reply = echo_request(Family::V6, 9, 2, 8);
        reply[0] = ICMP6_ECHO_REPLY;
        let p = parse_raw_v6(&reply, Some(64)).unwrap();
        assert_eq!((p.ident, p.seq, p.size), (9, 2, Some(56)));

        let mut inner = vec![0x60, 0, 0, 0, 0, 8, IPPROTO_ICMPV6, 1];
        inner.extend_from_slice(&[0; 32]);
        inner.extend_from_slice(&echo_request(Family::V6, 9, 5, 0));
        let mut big = vec![ICMP6_TOO_BIG, 0, 0, 0, 0, 0, 0x05, 0x00];
        big.extend_from_slice(&inner);
        let p = parse_raw_v6(&big, None).unwrap();
        assert_eq!((p.seq, p.kind), (5, ReplyKind::TooBig { mtu: Some(1280) }));
        let mut un = vec![ICMP6_UNREACH, 3, 0, 0, 0, 0, 0, 0];
        un.extend_from_slice(&inner);
        assert_eq!(
            parse_raw_v6(&un, None).unwrap().kind,
            ReplyKind::Unreachable("address unreachable".into())
        );
        assert!(parse_raw_v6(&[ICMP6_ECHO, 0, 0], None).is_none());
    }
}
