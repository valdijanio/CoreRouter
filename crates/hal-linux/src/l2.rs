//! Neighbor-discovery I/O: LLDP frames over `AF_PACKET`, MNDP datagrams over
//! UDP. Bytes only: building and parsing LLDPDUs / MNDP packets is the job of
//! `proto-lldp` / `proto-mndp` (L2), glued by the daemon — this crate is L1
//! and cannot depend on them.
//!
//! No `unsafe`: sockets come from `socket2`; the `sockaddr_ll` an
//! `AF_PACKET` socket must be bound to is the one the kernel itself reports
//! for the interface through `getifaddrs` (nix), so it is never built by
//! hand. The LLDP group address 01:80:C2:00:00:0E is not in a NIC's default
//! multicast filter and `PACKET_ADD_MEMBERSHIP` has no safe binding, so an
//! LLDP port turns on `allmulticast` over rtnetlink while it is open (only if
//! it was off, and turns it back off when closed).
//!
//! Everything is non-blocking: the daemon calls [`LldpIo::recv`] /
//! [`MndpListener::recv`] from its loop and [`LldpIo::due`] tells it which
//! ports must transmit (one LLDPDU per port per interval).

use std::collections::BTreeMap;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use corerouter_model::IfName;
use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;
use nix::sys::socket::{
    ControlMessageOwned, LinkAddr, MsgFlags, SockaddrStorage, bind, recvfrom, recvmsg, send,
    setsockopt, sockopt,
};
use rtnetlink::LinkUnspec;
use socket2::{Domain, Protocol, Socket, Type};

/// EtherType of LLDP (802.1AB). Same value as `proto_lldp::ETHERTYPE`.
pub const LLDP_ETHERTYPE: u16 = 0x88CC;
/// Nearest-bridge group address LLDP is sent to.
pub const LLDP_MULTICAST: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E];
/// The three 802.1AB group addresses accepted on receive (nearest bridge,
/// nearest non-TPMR bridge, nearest customer bridge).
const LLDP_GROUPS: [[u8; 6]; 3] = [
    LLDP_MULTICAST,
    [0x01, 0x80, 0xC2, 0x00, 0x00, 0x03],
    [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00],
];
/// Ethernet header: destination, source, EtherType.
const ETH_HEADER_LEN: usize = 14;
/// Shortest Ethernet frame without FCS; shorter frames are zero-padded
/// (padding after the End TLV is ignored by LLDP receivers).
const ETH_MIN_FRAME: usize = 60;
/// Largest LLDPDU accepted (jumbo); same as `proto_lldp::MAX_LLDPDU_LEN`.
pub const MAX_LLDPDU_LEN: usize = 9216;
/// Largest MNDP datagram accepted; same as `proto_mndp::MAX_PACKET_LEN`.
pub const MAX_MNDP_LEN: usize = 2048;
/// Frames/datagrams read per socket per `recv` call, so a flood on one
/// interface cannot starve the daemon loop.
const RECV_BUDGET: usize = 64;
/// `PACKET_OUTGOING`: a copy of a frame this host sent. Ignored.
const PACKET_OUTGOING: u8 = 4;

/// One LLDP frame received on a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LldpFrame {
    pub interface: IfName,
    pub src_mac: [u8; 6],
    /// Ethernet payload: the LLDPDU (may carry trailing padding).
    pub lldpdu: Vec<u8>,
}

/// A receive buffer of `want` bytes: `SO_RCVBUFFORCE` first (with
/// CAP_NET_ADMIN it passes `net.core.rmem_max`), else `SO_RCVBUF` (capped
/// there). Returns what the kernel gave: it reports twice the size (the
/// other half is its bookkeeping), halved here. A burst after an outage
/// (PADIs, RADIUS answers) overflows a small buffer into retransmissions.
pub fn rcvbuf(fd: &impl std::os::fd::AsFd, want: usize) -> usize {
    use nix::sys::socket::{getsockopt, setsockopt, sockopt};
    if setsockopt(fd, sockopt::RcvBufForce, &want).is_err() {
        let _ = setsockopt(fd, sockopt::RcvBuf, &want);
    }
    getsockopt(fd, sockopt::RcvBuf).map_or(0, |v| v / 2)
}

pub(crate) fn io_err(e: nix::Error) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

/// What the kernel reports for one interface, read via `getifaddrs`.
pub(crate) struct IfInfo {
    pub(crate) link: LinkAddr,
    pub(crate) mac: [u8; 6],
    allmulti: bool,
}

pub(crate) fn if_info(name: &IfName) -> io::Result<IfInfo> {
    let found = getifaddrs()
        .map_err(io_err)?
        .filter(|a| a.interface_name == name.as_str())
        .find_map(|a| {
            let link = *a.address?.as_link_addr()?;
            Some(IfInfo {
                mac: link.addr()?,
                link,
                allmulti: a.flags.contains(InterfaceFlags::IFF_ALLMULTI),
            })
        });
    found.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no such interface: {name}"),
        )
    })
}

/// Turn `allmulticast` on/off on one interface over rtnetlink.
fn set_allmulti(ifindex: u32, on: bool) -> io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    rt.block_on(async {
        let (conn, handle, _) = rtnetlink::new_connection()?;
        let task = tokio::spawn(conn);
        let out = handle
            .link()
            .set(LinkUnspec::new_with_index(ifindex).allmulticast(on).build())
            .execute()
            .await
            .map_err(|e| io::Error::other(format!("allmulticast {on} on ifindex {ifindex}: {e}")));
        task.abort();
        out
    })
}

struct Port {
    sock: Socket,
    ifindex: u32,
    mac: [u8; 6],
    last_tx: Option<Instant>,
    /// We turned allmulticast on, so we turn it off on close.
    allmulti_by_us: bool,
}

impl Port {
    fn open(name: &IfName) -> io::Result<Self> {
        let info = if_info(name)?;
        let ifindex = u32::try_from(info.link.ifindex())
            .map_err(|_| io::Error::other(format!("{name}: interface index out of range")))?;
        let proto = Protocol::from(i32::from(LLDP_ETHERTYPE.to_be()));
        let sock = Socket::new(Domain::PACKET, Type::RAW, Some(proto))?;
        sock.set_nonblocking(true)?;
        // sll_protocol in the kernel's address is 0, which means "keep the
        // protocol the socket was created with" (LLDP only).
        bind(sock.as_raw_fd(), &info.link).map_err(io_err)?;
        let allmulti_by_us = !info.allmulti;
        if allmulti_by_us {
            set_allmulti(ifindex, true)?;
        }
        Ok(Self {
            sock,
            ifindex,
            mac: info.mac,
            last_tx: None,
            allmulti_by_us,
        })
    }
}

impl Drop for Port {
    fn drop(&mut self) {
        if self.allmulti_by_us
            && let Err(e) = set_allmulti(self.ifindex, false)
        {
            log::warn!("lldp: could not restore allmulticast off: {e}");
        }
    }
}

/// LLDP transmit/receive on the interfaces discovery is enabled on.
pub struct LldpIo {
    ports: BTreeMap<IfName, Port>,
    interval: Duration,
}

impl LldpIo {
    /// `interval`: time between two LLDPDUs on a port (802.1AB: 30 s).
    pub fn new(interval: Duration) -> Self {
        Self {
            ports: BTreeMap::new(),
            interval,
        }
    }

    /// Make the open ports exactly `names`: opens the new ones, closes the
    /// others. Returns the interfaces that could not be opened, with why
    /// (the rest are open regardless).
    pub fn set_interfaces(&mut self, names: &[IfName]) -> Vec<(IfName, io::Error)> {
        self.ports.retain(|n, _| names.contains(n));
        let mut failed = Vec::new();
        for name in names {
            if self.ports.contains_key(name) {
                continue;
            }
            match Port::open(name) {
                Ok(p) => {
                    self.ports.insert(name.clone(), p);
                }
                Err(e) => failed.push((name.clone(), e)),
            }
        }
        failed
    }

    /// Change the time between two LLDPDUs on a port (the operator's
    /// `interval_secs`); takes effect at the next [`LldpIo::due`].
    pub fn set_interval(&mut self, interval: Duration) {
        self.interval = interval;
    }

    /// Kernel interface index of an open port (for the Management Address
    /// TLV's ifIndex).
    pub fn ifindex(&self, name: &IfName) -> Option<u32> {
        self.ports.get(name).map(|p| p.ifindex)
    }

    /// Open ports and their MAC addresses (for the Chassis/Port ID).
    pub fn interfaces(&self) -> Vec<(IfName, [u8; 6])> {
        self.ports.iter().map(|(n, p)| (n.clone(), p.mac)).collect()
    }

    /// Ports that must send an LLDPDU at `now` (never sent, or the
    /// interval has passed since the last successful send).
    pub fn due(&self, now: Instant) -> Vec<IfName> {
        self.ports
            .iter()
            .filter(|(_, p)| {
                p.last_tx
                    .is_none_or(|t| now.saturating_duration_since(t) >= self.interval)
            })
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// Send one LLDPDU on `name` to 01:80:C2:00:00:0E. `now` is recorded as
    /// the last transmission (on success only).
    pub fn send(&mut self, name: &IfName, lldpdu: &[u8], now: Instant) -> io::Result<()> {
        let port = self.ports.get_mut(name).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("lldp is not open on {name}"),
            )
        })?;
        if lldpdu.len() > MAX_LLDPDU_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("LLDPDU of {} bytes is too long", lldpdu.len()),
            ));
        }
        let mut frame = Vec::with_capacity(ETH_HEADER_LEN.saturating_add(lldpdu.len()));
        frame.extend_from_slice(&LLDP_MULTICAST);
        frame.extend_from_slice(&port.mac);
        frame.extend_from_slice(&LLDP_ETHERTYPE.to_be_bytes());
        frame.extend_from_slice(lldpdu);
        if frame.len() < ETH_MIN_FRAME {
            frame.resize(ETH_MIN_FRAME, 0);
        }
        send(port.sock.as_raw_fd(), &frame, MsgFlags::empty()).map_err(io_err)?;
        port.last_tx = Some(now);
        Ok(())
    }

    /// Every LLDP frame waiting on the open ports (non-blocking; at most a
    /// fixed budget per port per call). Our own transmissions, frames to
    /// other destinations and runt frames are dropped.
    pub fn recv(&mut self) -> Vec<LldpFrame> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; ETH_HEADER_LEN.saturating_add(MAX_LLDPDU_LEN)];
        for (name, port) in &self.ports {
            for _ in 0..RECV_BUDGET {
                let (n, from) = match recvfrom::<LinkAddr>(port.sock.as_raw_fd(), &mut buf) {
                    Ok(r) => r,
                    Err(nix::Error::EAGAIN) => break,
                    Err(e) => {
                        log::debug!("lldp recv on {name}: {e}");
                        break;
                    }
                };
                if from.is_some_and(|a| a.pkttype() == PACKET_OUTGOING) {
                    continue;
                }
                if let Some(f) = parse_frame(name, buf.get(..n).unwrap_or(&[])) {
                    out.push(f);
                }
            }
        }
        out
    }
}

/// Split an Ethernet frame into an [`LldpFrame`], or `None` if it is not an
/// LLDP frame to one of the LLDP group addresses.
fn parse_frame(name: &IfName, frame: &[u8]) -> Option<LldpFrame> {
    let (dst, rest) = frame.split_first_chunk::<6>()?;
    let (src, rest) = rest.split_first_chunk::<6>()?;
    let (ty, payload) = rest.split_first_chunk::<2>()?;
    if u16::from_be_bytes(*ty) != LLDP_ETHERTYPE || !LLDP_GROUPS.contains(dst) {
        return None;
    }
    Some(LldpFrame {
        interface: name.clone(),
        src_mac: *src,
        lldpdu: payload.to_vec(),
    })
}

/// One UDP datagram received by the MNDP listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    /// Interface it arrived on (from `IP_PKTINFO`), when known.
    pub interface: Option<IfName>,
    pub src: SocketAddr,
    /// Destination address of the packet (from the packet info), when
    /// known: a broadcast or multicast for a real announcement.
    pub dst: Option<IpAddr>,
    pub payload: Vec<u8>,
}

/// Passive MNDP listener: UDP port 5678 on IPv4 (and IPv6 when available).
/// Receive only — it never sends anything.
pub struct MndpListener {
    sockets: Vec<Socket>,
}

impl MndpListener {
    /// Bind `0.0.0.0:port` (and `[::]:port`, IPv6-only, if the host has
    /// IPv6). `SO_REUSEADDR`, so several listeners can share the port and
    /// all get the broadcasts.
    pub fn bind(port: u16) -> io::Result<Self> {
        let v4 = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        v4.set_reuse_address(true)?;
        v4.set_nonblocking(true)?;
        setsockopt(&v4, sockopt::Ipv4PacketInfo, &true).map_err(io_err)?;
        v4.bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())?;
        let mut sockets = vec![v4];
        match Self::bind_v6(port) {
            Ok(s) => sockets.push(s),
            Err(e) => log::info!("mndp: no IPv6 listener ({e}); IPv4 only"),
        }
        Ok(Self { sockets })
    }

    fn bind_v6(port: u16) -> io::Result<Socket> {
        let s = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
        s.set_only_v6(true)?;
        s.set_reuse_address(true)?;
        s.set_nonblocking(true)?;
        setsockopt(&s, sockopt::Ipv6RecvPacketInfo, &true).map_err(io_err)?;
        s.bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())?;
        Ok(s)
    }

    /// Port actually bound (useful with port 0 in tests).
    pub fn local_port(&self) -> Option<u16> {
        let a = self.sockets.first()?.local_addr().ok()?;
        a.as_socket().map(|s| s.port())
    }

    /// Every datagram waiting (non-blocking, bounded per socket). Oversized
    /// datagrams (more than [`MAX_MNDP_LEN`]) are dropped.
    pub fn recv(&mut self) -> Vec<UdpDatagram> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; MAX_MNDP_LEN];
        for s in &self.sockets {
            for _ in 0..RECV_BUDGET {
                match recv_one(s, &mut buf) {
                    Ok(Some(d)) => out.push(d),
                    Ok(None) => {}
                    Err(nix::Error::EAGAIN) => break,
                    Err(e) => {
                        log::debug!("mndp recv: {e}");
                        break;
                    }
                }
            }
        }
        out
    }
}

/// One `recvmsg`; `Ok(None)` for a datagram that is dropped (truncated or
/// with no usable source).
fn recv_one(s: &Socket, buf: &mut [u8]) -> nix::Result<Option<UdpDatagram>> {
    let mut cmsg = nix::cmsg_space!(nix::libc::in6_pktinfo);
    let (n, truncated, src, ifindex, dst) = {
        let mut iov = [IoSliceMut::new(buf)];
        let msg = recvmsg::<SockaddrStorage>(
            s.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg),
            MsgFlags::MSG_DONTWAIT,
        )?;
        let mut ifindex = None;
        let mut dst = None;
        for c in msg.cmsgs()? {
            match c {
                ControlMessageOwned::Ipv4PacketInfo(pi) => {
                    ifindex = Some(pi.ipi_ifindex);
                    // ip(7): ipi_addr is the header's destination address.
                    dst = Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(pi.ipi_addr.s_addr))));
                }
                ControlMessageOwned::Ipv6PacketInfo(pi) => {
                    ifindex = i32::try_from(pi.ipi6_ifindex).ok();
                    dst = Some(IpAddr::V6(Ipv6Addr::from(pi.ipi6_addr.s6_addr)));
                }
                _ => {}
            }
        }
        let src = msg.address.and_then(|a| sock_addr(&a));
        let truncated = msg.flags.contains(MsgFlags::MSG_TRUNC);
        (msg.bytes, truncated, src, ifindex, dst)
    };
    let (Some(src), false) = (src, truncated) else {
        return Ok(None);
    };
    let interface = ifindex
        .and_then(|i| u32::try_from(i).ok())
        .and_then(|i| nix::net::if_::if_indextoname(i).ok())
        .and_then(|c| c.into_string().ok())
        .and_then(|s| s.parse::<IfName>().ok());
    Ok(Some(UdpDatagram {
        interface,
        src,
        dst,
        payload: buf.get(..n).unwrap_or(&[]).to_vec(),
    }))
}

fn sock_addr(a: &SockaddrStorage) -> Option<SocketAddr> {
    if let Some(v4) = a.as_sockaddr_in() {
        return Some(SocketAddrV4::from(*v4).into());
    }
    let v6 = a.as_sockaddr_in6()?;
    Some(SocketAddrV6::from(*v6).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth(name: &str) -> IfName {
        name.parse().unwrap()
    }

    #[test]
    fn parses_lldp_frames_only() {
        let src = [2, 0, 0, 0, 0, 1];
        let frame = [&LLDP_MULTICAST[..], &src, &[0x88, 0xCC], b"pdu"].concat();
        let f = parse_frame(&eth("ether1"), &frame).unwrap();
        assert_eq!(f.src_mac, src);
        assert_eq!(f.lldpdu, b"pdu");
        assert_eq!(f.interface, eth("ether1"));

        let unicast = [&src[..], &src, &[0x88, 0xCC], b"pdu"].concat();
        assert_eq!(parse_frame(&eth("ether1"), &unicast), None);
        let ipv4 = [&LLDP_MULTICAST[..], &src, &[0x08, 0x00], b"pdu"].concat();
        assert_eq!(parse_frame(&eth("ether1"), &ipv4), None);
        assert_eq!(parse_frame(&eth("ether1"), &[0; 13]), None);
    }

    #[test]
    fn no_ports_nothing_due() {
        let io = LldpIo::new(Duration::from_secs(30));
        assert!(io.due(Instant::now()).is_empty());
        assert!(io.interfaces().is_empty());
    }
}
