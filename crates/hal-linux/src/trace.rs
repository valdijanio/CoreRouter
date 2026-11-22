//! UDP and TCP SYN probes for traceroute (G6.4c), without a raw socket:
//! the kernel reports the ICMP errors a probe causes on the socket's error
//! queue (`IP_RECVERR` / `IPV6_RECVERR`, ip(7)), with the router that sent
//! them (`SO_EE_OFFENDER`) and the probe it quoted.
//!
//! **UDP** — one socket per family, bound once (so its source port never
//! changes). Classic traceroute sends to `port + seq`: every probe is a
//! flow of its own, and the error's original destination (msg_name) gives
//! the sequence back. Paris sends every probe to `port`, the same flow;
//! the sequence is the first payload word, which the router quotes when it
//! quotes more than the 8 bytes RFC 792 requires (RFC 1812 §4.3.2.3 asks
//! for as much as fits in 576). A router that quotes only 8 bytes leaves no
//! word: then the reply belongs to the one probe in flight — the engine
//! sends Paris UDP probes one at a time. The destination answers "port
//! unreachable": the end of the path.
//!
//! **TCP** — one socket per probe, a non-blocking `connect` with the TTL
//! set. A router's "time exceeded" ends the connect (`tcp_v4_err`: in
//! SYN_SENT the error is queued and the connection dropped); the
//! destination answers SYN-ACK (the connect completes: we reset it at once,
//! `SO_LINGER` 0) or RST (`ECONNREFUSED`). Paris binds every probe to the
//! same source port, so they go one at a time too. Like `traceroute
//! -T`'s `tcpconn` mode and mtr `--tcp`, the handshake is a full one: a
//! service at the destination sees a connection that is reset at once.

use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd};
use std::time::{Duration, Instant};

use corerouter_hal::probe::{
    Family, Probe, ProbeError, ProbeProto, ProbeSocket, Reply, ReplyKind, SocketOptions, overhead,
};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{
    ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg, setsockopt, sockopt,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::icmp::{
    CMSG_BUF, DEFAULT_TTL, ICMP_UNREACH, ICMP6_UNREACH, ORIGIN_ICMP, ORIGIN_ICMP6, error_kind,
    ip_of_v4, ip_of_v6, nix_io,
};

/// ICMP "port unreachable" codes (IPv4 3/3, IPv6 1/4).
const PORT_UNREACH_V4: u8 = 3;
const PORT_UNREACH_V6: u8 = 4;
/// Probes older than this are forgotten (their sockets closed).
const FORGET: Duration = Duration::from_secs(10);
/// Error-queue entries one `recv` reads at most.
const BUDGET: usize = 256;
/// Bytes of an error-queue entry kept (the quoted probe).
const BUF: usize = 2048;

fn domain(f: Family) -> Domain {
    match f {
        Family::V4 => Domain::IPV4,
        Family::V6 => Domain::IPV6,
    }
}

fn unspecified(f: Family) -> IpAddr {
    match f {
        Family::V4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        Family::V6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

/// Options common to every probe socket: non-blocking, device, TOS,
/// errors on the queue, the TTL.
fn prepare(sock: &Socket, family: Family, o: &SocketOptions, ttl: u8) -> io::Result<()> {
    sock.set_nonblocking(true)?;
    if let Some(dev) = &o.device {
        sock.bind_device(Some(dev.as_bytes()))
            .map_err(|e| io::Error::new(e.kind(), format!("binding to {dev}: {e}")))?;
    }
    match family {
        Family::V4 => {
            sock.set_tos_v4(u32::from(o.tos))?;
            setsockopt(sock, sockopt::Ipv4RecvErr, &true).map_err(nix_io)?;
            sock.set_ttl_v4(u32::from(ttl))?;
        }
        Family::V6 => {
            sock.set_tclass_v6(u32::from(o.tos))?;
            setsockopt(sock, sockopt::Ipv6RecvErr, &true).map_err(nix_io)?;
            sock.set_unicast_hops_v6(u32::from(ttl))?;
        }
    }
    Ok(())
}

fn be16(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(at)?, *d.get(at + 1)?]))
}

/// One error-queue entry: what it says, who said it, the original
/// destination (address and port) and the quoted payload.
struct Queued {
    kind: ReplyKind,
    from: Option<IpAddr>,
    dst: Option<SocketAddr>,
    data: Vec<u8>,
    port_unreachable: bool,
}

fn read_queue(sock: &Socket, buf: &mut [u8]) -> io::Result<Option<Queued>> {
    let mut cmsg = vec![0u8; CMSG_BUF];
    let mut iov = [IoSliceMut::new(buf)];
    let msg = match recvmsg::<SockaddrStorage>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg),
        MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT,
    ) {
        Ok(m) => m,
        Err(Errno::EAGAIN) => return Ok(None),
        Err(e) => return Err(nix_io(e)),
    };
    let mut found = None;
    for c in msg.cmsgs().map_err(nix_io)? {
        let (ee, offender) = match c {
            ControlMessageOwned::Ipv4RecvErr(ee, a) => (ee, a.as_ref().map(ip_of_v4)),
            ControlMessageOwned::Ipv6RecvErr(ee, a) => (ee, a.as_ref().map(ip_of_v6)),
            _ => continue,
        };
        let port = matches!(
            (ee.ee_origin, ee.ee_type, ee.ee_code),
            (ORIGIN_ICMP, ICMP_UNREACH, PORT_UNREACH_V4)
                | (ORIGIN_ICMP6, ICMP6_UNREACH, PORT_UNREACH_V6)
        );
        if let Some(kind) = error_kind(&ee) {
            found = Some((kind, offender, port));
        }
    }
    let dst = msg.address.as_ref().and_then(|a| {
        a.as_sockaddr_in()
            .map(|v| SocketAddr::new(IpAddr::V4(v.ip()), v.port()))
            .or_else(|| {
                a.as_sockaddr_in6()
                    .map(|v| SocketAddr::new(IpAddr::V6(v.ip()), v.port()))
            })
    });
    let n = msg.bytes;
    let Some((kind, from, port_unreachable)) = found else {
        return Ok(Some(Queued {
            kind: ReplyKind::Unreachable("unknown error".into()),
            from: None,
            dst: None,
            data: Vec::new(),
            port_unreachable: false,
        }));
    };
    Ok(Some(Queued {
        kind,
        from,
        dst,
        data: buf.get(..n).unwrap_or_default().to_vec(),
        port_unreachable,
    }))
}

struct Sent {
    at: Instant,
    dst: IpAddr,
}

struct UdpSide {
    sock: Socket,
    ttl: u8,
}

struct TcpProbe {
    seq: u16,
    sock: Socket,
    dst: IpAddr,
    at: Instant,
}

/// The socket `HostProber::open` hands out for UDP and TCP probes.
pub struct TraceSocket {
    options: SocketOptions,
    v4: Option<Result<UdpSide, ProbeError>>,
    v6: Option<Result<UdpSide, ProbeError>>,
    sent: std::collections::HashMap<u16, Sent>,
    tcp: Vec<TcpProbe>,
    /// Paris TCP: the source port every probe reuses (once known).
    tcp_port: Option<u16>,
    /// Answers found while doing something else (a TCP connect that
    /// completed at once).
    ready: Vec<Reply>,
    buf: Vec<u8>,
}

impl TraceSocket {
    pub fn new(options: SocketOptions) -> Self {
        Self {
            options,
            v4: None,
            v6: None,
            sent: std::collections::HashMap::new(),
            tcp: Vec::new(),
            tcp_port: None,
            ready: Vec::new(),
            buf: vec![0u8; BUF],
        }
    }

    fn udp_side(&mut self, family: Family) -> Result<&mut UdpSide, ProbeError> {
        let slot = match family {
            Family::V4 => &mut self.v4,
            Family::V6 => &mut self.v6,
        };
        let o = &self.options;
        let opened = slot.get_or_insert_with(|| {
            let open = || -> io::Result<UdpSide> {
                let sock = Socket::new(domain(family), Type::DGRAM, Some(Protocol::UDP))?;
                prepare(&sock, family, o, DEFAULT_TTL)?;
                let src = o
                    .src
                    .filter(|s| Family::of(*s) == family)
                    .unwrap_or_else(|| unspecified(family));
                // Bound once: the source port stays for every probe.
                sock.bind(&SockAddr::from(SocketAddr::new(src, 0)))?;
                Ok(UdpSide {
                    sock,
                    ttl: DEFAULT_TTL,
                })
            };
            open().map_err(|e| ProbeError::Unavailable(format!("UDP probe socket: {e}")))
        });
        opened.as_mut().map_err(|e| e.clone())
    }

    fn send_udp(&mut self, probe: &Probe, base: u16) -> Result<(), ProbeError> {
        let family = Family::of(probe.dst);
        let paris = self.options.paris;
        let side = self.udp_side(family)?;
        let ttl = probe.ttl.unwrap_or(DEFAULT_TTL);
        if side.ttl != ttl {
            let set = match family {
                Family::V4 => side.sock.set_ttl_v4(u32::from(ttl)),
                Family::V6 => side.sock.set_unicast_hops_v6(u32::from(ttl)),
            };
            set.map_err(|e| ProbeError::Io(format!("TTL {ttl}: {e}")))?;
            side.ttl = ttl;
        }
        // IPv4 28 / IPv6 48 bytes of headers (IP + UDP; ICMP's echo header
        // is 8 bytes too).
        let payload = usize::from(probe.size.saturating_sub(overhead(probe.dst))).max(2);
        let mut data: Vec<u8> = (0..payload).map(|i| (i % 256) as u8).collect();
        if let Some(w) = data.get_mut(0..2) {
            w.copy_from_slice(&probe.seq.to_be_bytes());
        }
        let port = if paris {
            base
        } else {
            // Classic: each probe its own port (and flow); never port 0.
            base.wrapping_add(probe.seq).max(1)
        };
        let to = SockAddr::from(SocketAddr::new(probe.dst, port));
        let at = Instant::now();
        let mut tries = 0;
        loop {
            match side.sock.send_to(&data, &to) {
                Ok(_) => break,
                // An earlier probe's ICMP error is reported once by the next
                // call (`sk_err`): its details are on the queue; send again.
                Err(e)
                    if tries == 0
                        && matches!(
                            e.raw_os_error().map(Errno::from_raw),
                            Some(
                                Errno::ECONNREFUSED
                                    | Errno::EHOSTUNREACH
                                    | Errno::ENETUNREACH
                                    | Errno::EPROTO
                            )
                        ) =>
                {
                    tries += 1;
                }
                Err(e) => {
                    return Err(match e.raw_os_error().map(Errno::from_raw) {
                        Some(Errno::EMSGSIZE) => ProbeError::TooBig(None),
                        Some(Errno::ENETUNREACH | Errno::EHOSTUNREACH | Errno::ENETDOWN) => {
                            ProbeError::Unreachable(e.to_string())
                        }
                        _ => ProbeError::Io(e.to_string()),
                    });
                }
            }
        }
        self.remember(probe.seq, Sent { at, dst: probe.dst });
        Ok(())
    }

    fn remember(&mut self, seq: u16, s: Sent) {
        let now = s.at;
        self.sent
            .retain(|_, x| now.saturating_duration_since(x.at) < FORGET);
        self.sent.insert(seq, s);
    }

    fn send_tcp(&mut self, probe: &Probe, port: u16) -> Result<(), ProbeError> {
        let family = Family::of(probe.dst);
        let ttl = probe.ttl.unwrap_or(DEFAULT_TTL);
        let paris = self.options.paris;
        if paris {
            // One at a time on the same source port: the previous probe is
            // answered or given up by now.
            self.close_tcp(|_| true);
        }
        let sock = Socket::new(domain(family), Type::STREAM, Some(Protocol::TCP))
            .map_err(|e| ProbeError::Unavailable(format!("TCP probe socket: {e}")))?;
        prepare(&sock, family, &self.options, ttl)
            .map_err(|e| ProbeError::Unavailable(format!("TCP probe socket: {e}")))?;
        let src = self
            .options
            .src
            .filter(|s| Family::of(*s) == family)
            .unwrap_or_else(|| unspecified(family));
        if paris {
            let _ = sock.set_reuse_address(true);
            sock.bind(&SockAddr::from(SocketAddr::new(
                src,
                self.tcp_port.unwrap_or(0),
            )))
            .map_err(|e| ProbeError::Io(format!("TCP source port: {e}")))?;
            if self.tcp_port.is_none() {
                self.tcp_port = sock
                    .local_addr()
                    .ok()
                    .and_then(|a| a.as_socket())
                    .map(|a| a.port());
            }
        } else if self.options.src.is_some() {
            sock.bind(&SockAddr::from(SocketAddr::new(src, 0)))
                .map_err(|e| ProbeError::Io(format!("TCP source: {e}")))?;
        }
        let at = Instant::now();
        let to = SockAddr::from(SocketAddr::new(probe.dst, port));
        match sock.connect(&to) {
            Ok(()) => {
                let _ = sock.set_linger(Some(Duration::ZERO));
                self.ready.push(reply(
                    probe.seq,
                    probe.dst,
                    ReplyKind::Reached("syn-ack".into()),
                    at,
                ));
                return Ok(());
            }
            Err(e) if e.raw_os_error() == Some(Errno::EINPROGRESS as i32) => {}
            Err(e) if e.raw_os_error() == Some(Errno::ECONNREFUSED as i32) => {
                self.ready.push(reply(
                    probe.seq,
                    probe.dst,
                    ReplyKind::Reached("rst".into()),
                    at,
                ));
                return Ok(());
            }
            Err(e) => {
                return Err(match e.raw_os_error().map(Errno::from_raw) {
                    Some(Errno::ENETUNREACH | Errno::EHOSTUNREACH | Errno::ENETDOWN) => {
                        ProbeError::Unreachable(e.to_string())
                    }
                    _ => ProbeError::Io(e.to_string()),
                });
            }
        }
        self.tcp.push(TcpProbe {
            seq: probe.seq,
            sock,
            dst: probe.dst,
            at,
        });
        Ok(())
    }

    /// Close the TCP probes `which` picks, with a reset (no TIME_WAIT, no
    /// FIN to a service).
    fn close_tcp(&mut self, which: impl Fn(&TcpProbe) -> bool) {
        self.tcp.retain(|p| {
            if which(p) {
                let _ = p.sock.set_linger(Some(Duration::ZERO));
                false
            } else {
                true
            }
        });
    }

    /// What the UDP sockets' error queues hold now.
    fn drain_udp(&mut self) -> io::Result<Option<Reply>> {
        let paris = self.options.paris;
        let base = match self.options.proto {
            ProbeProto::Udp { port } => port,
            _ => return Ok(None),
        };
        let mut budget = BUDGET;
        for side in [&self.v4, &self.v6] {
            let Some(Ok(side)) = side else { continue };
            while budget > 0 {
                budget -= 1;
                let Some(q) = read_queue(&side.sock, &mut self.buf)? else {
                    break;
                };
                let Some(dst) = q.dst else { continue };
                // Which probe: the port (classic), else the payload word
                // (Paris), else the only one in flight to that address.
                let seq = if paris {
                    be16(&q.data, 0)
                        .filter(|s| self.sent.contains_key(s))
                        .or_else(|| {
                            let mine: Vec<u16> = self
                                .sent
                                .iter()
                                .filter(|(_, x)| x.dst == dst.ip())
                                .map(|(s, _)| *s)
                                .collect();
                            match mine.as_slice() {
                                [only] => Some(*only),
                                _ => None,
                            }
                        })
                } else {
                    Some(dst.port().wrapping_sub(base))
                };
                let Some(seq) = seq else { continue };
                let Some(sent) = self.sent.remove(&seq) else {
                    continue;
                };
                if sent.dst != dst.ip() {
                    continue;
                }
                let from = q.from.unwrap_or(dst.ip());
                let kind = if q.port_unreachable && from == sent.dst {
                    ReplyKind::Reached("port unreachable".into())
                } else {
                    q.kind
                };
                return Ok(Some(reply(seq, from, kind, sent.at)));
            }
        }
        Ok(None)
    }

    /// TCP probes that have an answer now.
    fn drain_tcp(&mut self) -> io::Result<Option<Reply>> {
        let mut done: Option<(usize, Reply)> = None;
        for (i, p) in self.tcp.iter().enumerate() {
            if let Some(q) = read_queue(&p.sock, &mut self.buf)? {
                let from = q.from.unwrap_or(p.dst);
                done = Some((i, reply(p.seq, from, q.kind, p.at)));
                break;
            }
            match p.sock.take_error() {
                Ok(Some(e)) => {
                    let kind = match e.raw_os_error().map(Errno::from_raw) {
                        Some(Errno::ECONNREFUSED) => ReplyKind::Reached("rst".into()),
                        _ => ReplyKind::Unreachable(e.to_string().to_lowercase()),
                    };
                    let from = p.dst;
                    done = Some((i, reply(p.seq, from, kind, p.at)));
                    break;
                }
                Ok(None) => {
                    // Connected: the destination answered SYN-ACK.
                    if p.sock.peer_addr().is_ok() {
                        done = Some((
                            i,
                            reply(p.seq, p.dst, ReplyKind::Reached("syn-ack".into()), p.at),
                        ));
                        break;
                    }
                }
                Err(_) => {}
            }
        }
        if let Some((i, r)) = done {
            if i < self.tcp.len() {
                let p = self.tcp.remove(i);
                let _ = p.sock.set_linger(Some(Duration::ZERO));
            }
            return Ok(Some(r));
        }
        let now = Instant::now();
        self.close_tcp(|p| now.saturating_duration_since(p.at) > FORGET);
        Ok(None)
    }
}

fn reply(seq: u16, from: IpAddr, kind: ReplyKind, at: Instant) -> Reply {
    Reply {
        seq,
        from,
        kind,
        size: None,
        ttl: None,
        rtt: at.elapsed(),
        mpls: Vec::new(),
    }
}

impl ProbeSocket for TraceSocket {
    fn send(&mut self, probe: &Probe) -> Result<(), ProbeError> {
        match self.options.proto {
            ProbeProto::Udp { port } => self.send_udp(probe, port),
            ProbeProto::Tcp { port } => self.send_tcp(probe, port),
            ProbeProto::Icmp => Err(ProbeError::Unavailable("not an ICMP socket".into())),
        }
    }

    fn recv(&mut self, wait: Duration) -> Result<Option<Reply>, ProbeError> {
        let io = |e: io::Error| ProbeError::Io(e.to_string());
        let deadline = Instant::now() + wait;
        loop {
            if let Some(r) = self.ready.pop() {
                return Ok(Some(r));
            }
            let found = match self.options.proto {
                ProbeProto::Udp { .. } => self.drain_udp().map_err(io)?,
                ProbeProto::Tcp { .. } => self.drain_tcp().map_err(io)?,
                ProbeProto::Icmp => None,
            };
            if found.is_some() {
                return Ok(found);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            let timeout = PollTimeout::try_from(left).unwrap_or(PollTimeout::MAX);
            let mut fds: Vec<PollFd> = match self.options.proto {
                ProbeProto::Udp { .. } => [&self.v4, &self.v6]
                    .into_iter()
                    .filter_map(|s| match s {
                        Some(Ok(side)) => Some(PollFd::new(
                            side.sock.as_fd(),
                            PollFlags::POLLERR | PollFlags::POLLIN,
                        )),
                        _ => None,
                    })
                    .collect(),
                _ => self
                    .tcp
                    .iter()
                    .map(|p| PollFd::new(p.sock.as_fd(), PollFlags::POLLOUT | PollFlags::POLLERR))
                    .collect(),
            };
            if fds.is_empty() {
                std::thread::sleep(left);
                return Ok(None);
            }
            match poll(&mut fds, timeout) {
                Ok(0) => return Ok(None),
                Ok(_) | Err(Errno::EINTR) => {}
                Err(e) => return Err(ProbeError::Io(format!("poll: {e}"))),
            }
            drop(fds);
            // UDP: a datagram from the destination (an echo service) is not
            // a probe answer; drop it so poll does not spin.
            if let ProbeProto::Udp { .. } = self.options.proto {
                for side in [&self.v4, &self.v6].into_iter().flatten().flatten() {
                    let mut b = [0u8; 64];
                    for _ in 0..BUDGET {
                        if nix::sys::socket::recv(
                            side.sock.as_raw_fd(),
                            &mut b,
                            MsgFlags::MSG_DONTWAIT,
                        )
                        .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        }
    }
}
