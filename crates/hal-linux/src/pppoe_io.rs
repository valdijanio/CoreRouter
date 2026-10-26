//! PPPoE access-port I/O for the daemon's BNG service (G4.3d): the
//! Discovery (0x8863) and session (0x8864) frames of one access interface
//! over `AF_PACKET`, and the slow path that carries subscriber traffic when
//! the XDP data plane (G4.3c) is not there (virtual lab, a NIC without
//! XDP, the unprivileged namespace tests).
//!
//! Bytes only: `proto-pppoe` (L2) parses them, the daemon glues the two.
//! No `unsafe`: sockets come from `socket2`, the address to bind from
//! `getifaddrs` (`l2::if_info`).
//!
//! **VLANs without `PACKET_AUXDATA`.** The kernel takes the outer tag off
//! a frame before a packet socket sees it (`skb_vlan_untag`, or the NIC)
//! and keeps it next to the frame; the tag is only readable through
//! `PACKET_AUXDATA`, a socket option with no safe binding. So a port opens
//! one socket per outer VLAN id ([`Listen`]), each with a classic BPF
//! filter that keeps only its VLAN and TPID (`SKF_AD_VLAN_TAG`,
//! `SKF_AD_VLAN_TPID`); the socket a frame came from says its outer tag,
//! which goes back in-band before `proto-pppoe` reads it. A second tag
//! (QinQ, G4.3l) is never taken off: it stays in the frame.
//!
//! The sockets are bound to every protocol (`ETH_P_ALL`): one bound to
//! 0x8863 gets its frames only after the kernel has cleared the tag (a
//! frame of VLAN 100 reached the untagged socket as untagged, and the VLAN
//! socket nothing — measured on veth, 2026-10-26, G4.3l), and a QinQ
//! frame is 0x8100 there, not 0x8863. The filter keeps the two PPPoE
//! EtherTypes and drops what the host sends.
//!
//! **Slow path.** Upstream, a subscriber's IPv4 or IPv6 packet (already
//! decapsulated and checked by the service) is sent through a raw socket
//! of its family (`IPPROTO_RAW`: the kernel routes it as the host's own, so
//! `forward` rules do not see it; the output and postrouting chains,
//! CGNAT included, do). Downstream, every subscriber address gets a /32
//! route (and every /64 and delegated IPv6 prefix, G4.3l) through a
//! `dummy` device (`bng0`, created if missing); the
//! service reads what the kernel sends there with a packet socket (the
//! dummy drops the frame, the tap sees it first) and encapsulates it to
//! the subscriber. The production path is XDP plus G4.3ca (a tc program
//! on `bng0`); this one is correct, not fast.

use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

use corerouter_model::IfName;
use nix::errno::Errno;
use nix::sys::socket::{ControlMessageOwned, LinkAddr, MsgFlags, bind, recvmsg, send};
use socket2::{Domain, Protocol, SockFilter, Socket, Type};

use crate::l2::{if_info, io_err};

pub const ETH_P_PPP_DISC: u16 = 0x8863;
pub const ETH_P_PPP_SES: u16 = 0x8864;
const ETH_P_ALL: u16 = 0x0003;
/// Sockets one port may open (one per outer VLAN id): a range of 1-4094 would be
/// 8188 descriptors; the XDP path is the answer for that.
pub const MAX_VLAN_IDS: usize = 512;
/// Largest frame read (jumbo PPPoE is RFC 4638: 1508 + tags).
const FRAME_MAX: usize = 9216;
/// Frames read from one socket per call, so one busy VLAN cannot starve
/// the rest.
const BUDGET: usize = 256;
const RCVBUF: usize = 4 << 20;
/// `PACKET_OUTGOING`.
const PACKET_OUTGOING: u8 = 4;

// Classic BPF (linux/filter.h).
const LD_W_ABS: u16 = 0x20;
const LD_H_ABS: u16 = 0x28;
const ALU_AND_K: u16 = 0x54;
const JEQ_K: u16 = 0x15;
const RET_K: u16 = 0x06;
const SKF_AD_OFF: u32 = 0xFFFF_F000;
const SKF_AD_VLAN_TAG: u32 = 44;
const SKF_AD_VLAN_TAG_PRESENT: u32 = 48;
const SKF_AD_PKTTYPE: u32 = 4;
const SKF_AD_VLAN_TPID: u32 = 60;
const TPID_8021Q: u16 = 0x8100;
const ACCEPT: u32 = 0x0004_0000;

/// One classic BPF instruction: code, jt, jf, k.
type Ins = (u16, u8, u8, u32);

/// What one socket of a port keeps (G4.3l): untagged PPPoE, PPPoE in one
/// 802.1Q VLAN, or PPPoE inside two tags whose outer one (the S-tag, this
/// TPID) is `outer` and whose inner one (802.1Q) stays in the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Listen {
    Untagged,
    Vlan(u16),
    Stacked { outer: u16, tpid: u16 },
}

/// The filter of one socket. The kernel takes the outer tag off before a
/// packet socket sees the frame (`skb_vlan_untag`) and keeps it next to the
/// frame, where the filter reads it (`SKF_AD_VLAN_TAG*`); a second tag
/// stays in the frame. The copies of what this host sends
/// (`PACKET_OUTGOING`) never reach the BNG: on an access port they are its
/// own PADOs, PADSs and session frames.
fn program(listen: Listen) -> Vec<Ins> {
    // Accept and drop are the last two instructions; jumps count to them.
    let mut p: Vec<Ins> = vec![
        (LD_W_ABS, 0, 0, SKF_AD_OFF + SKF_AD_PKTTYPE),
        (JEQ_K, DROP, 0, u32::from(PACKET_OUTGOING)),
        (LD_W_ABS, 0, 0, SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT),
    ];
    match listen {
        Listen::Untagged => p.push((JEQ_K, 0, DROP, 0)),
        Listen::Vlan(vid) | Listen::Stacked { outer: vid, .. } => {
            let tpid = match listen {
                Listen::Stacked { tpid, .. } => tpid,
                _ => TPID_8021Q,
            };
            p.extend([
                (JEQ_K, 0, DROP, 1),
                (LD_W_ABS, 0, 0, SKF_AD_OFF + SKF_AD_VLAN_TAG),
                (ALU_AND_K, 0, 0, 0x0FFF),
                (JEQ_K, 0, DROP, u32::from(vid)),
                (LD_W_ABS, 0, 0, SKF_AD_OFF + SKF_AD_VLAN_TPID),
                (JEQ_K, 0, DROP, u32::from(tpid)),
            ]);
        }
    }
    // The EtherType: at 12, or at 16 behind the inner 802.1Q tag.
    if matches!(listen, Listen::Stacked { .. }) {
        p.extend([
            (LD_H_ABS, 0, 0, 12),
            (JEQ_K, 0, DROP, u32::from(TPID_8021Q)),
            (LD_H_ABS, 0, 0, 16),
        ]);
    } else {
        p.push((LD_H_ABS, 0, 0, 12));
    }
    p.extend([
        (JEQ_K, TO_ACCEPT, 0, u32::from(ETH_P_PPP_DISC)),
        (JEQ_K, 0, DROP, u32::from(ETH_P_PPP_SES)),
        (RET_K, 0, 0, ACCEPT),
        (RET_K, 0, 0, 0),
    ]);
    resolve(p)
}

/// Jump placeholders of [`program`]: to the drop (last) and to the accept
/// (the one before), turned into offsets by [`resolve`].
const DROP: u8 = 0xFF;
const TO_ACCEPT: u8 = 0xFE;

fn resolve(mut p: Vec<Ins>) -> Vec<Ins> {
    let n = p.len();
    for (i, ins) in p.iter_mut().enumerate() {
        let to = |j: u8| -> u8 {
            let target = match j {
                DROP => n.saturating_sub(1),
                TO_ACCEPT => n.saturating_sub(2),
                j => return j,
            };
            u8::try_from(target.saturating_sub(i + 1)).unwrap_or(0)
        };
        ins.1 = to(ins.1);
        ins.2 = to(ins.2);
    }
    p
}

/// The filter of the slow path's tap on `bng0`: only what the host sends.
fn outgoing_only() -> Vec<Ins> {
    vec![
        (LD_W_ABS, 0, 0, SKF_AD_OFF + SKF_AD_PKTTYPE),
        (JEQ_K, 0, 1, u32::from(PACKET_OUTGOING)),
        (RET_K, 0, 0, ACCEPT),
        (RET_K, 0, 0, 0),
    ]
}

fn filter(p: &[Ins]) -> Vec<SockFilter> {
    p.iter()
        .map(|&(code, jt, jf, k)| SockFilter::new(code, jt, jf, k))
        .collect()
}

fn bound(link: &LinkAddr, protocol: u16, prog: &[Ins]) -> io::Result<Socket> {
    let proto = Protocol::from(i32::from(protocol.to_be()));
    let sock = Socket::new(Domain::PACKET, Type::RAW, Some(proto))?;
    sock.set_nonblocking(true)?;
    crate::l2::rcvbuf(&sock, RCVBUF);
    sock.attach_filter(&filter(prog))?;
    // The kernel's count of frames it dropped on this socket (buffer full),
    // with each frame read: `PppoePort::dropped`.
    let _ = nix::sys::socket::setsockopt(&sock, nix::sys::socket::sockopt::RxqOvfl, &1);
    bind(sock.as_raw_fd(), link).map_err(io_err)?;
    Ok(sock)
}

struct Side {
    sock: Socket,
    listen: Listen,
    /// Frames the kernel dropped on this socket so far (`SO_RXQ_OVFL`).
    dropped: u32,
}

/// The index and MAC of access port `name` (the IPoE service's XDP
/// sessions, G4.3f).
pub fn port_info(name: &IfName) -> io::Result<(u32, [u8; 6])> {
    let info = if_info(name)?;
    let ifindex = u32::try_from(info.link.ifindex())
        .map_err(|_| io::Error::other(format!("{name}: interface index out of range")))?;
    Ok((ifindex, info.mac))
}

/// The PPPoE sockets of one access interface.
pub struct PppoePort {
    name: IfName,
    ifindex: u32,
    mac: [u8; 6],
    sides: Vec<Side>,
    /// One socket to send on (bound, unfiltered sends work on any).
    tx: Socket,
    buf: Vec<u8>,
    next: usize,
}

impl PppoePort {
    /// Open `name` for PPPoE: untagged frames when `untagged`, and those of
    /// every VLAN id in `vlans` (at most [`MAX_VLAN_IDS`]).
    pub fn open(name: &IfName, vlans: &[u16], untagged: bool) -> io::Result<Self> {
        let listen: Vec<Listen> = untagged
            .then_some(Listen::Untagged)
            .into_iter()
            .chain(vlans.iter().map(|v| Listen::Vlan(*v)))
            .collect();
        Self::open_for(name, &listen)
    }

    /// Open `name` for PPPoE with one socket per [`Listen`] (at most
    /// [`MAX_VLAN_IDS`]).
    pub fn open_for(name: &IfName, listen: &[Listen]) -> io::Result<Self> {
        if listen.len() > MAX_VLAN_IDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} VLAN ids on {name}: at most {MAX_VLAN_IDS} (one socket each)",
                    listen.len()
                ),
            ));
        }
        let info = if_info(name)?;
        let ifindex = u32::try_from(info.link.ifindex())
            .map_err(|_| io::Error::other(format!("{name}: interface index out of range")))?;
        let mut sides = Vec::new();
        for &l in listen {
            sides.push(Side {
                sock: bound(&info.link, ETH_P_ALL, &program(l))?,
                listen: l,
                dropped: 0,
            });
        }
        // Sending needs no filter; a socket that reads nothing (protocol 0).
        let tx = Socket::new(Domain::PACKET, Type::RAW, None)?;
        tx.set_nonblocking(true)?;
        bind(tx.as_raw_fd(), &info.link).map_err(io_err)?;
        Ok(Self {
            name: name.clone(),
            ifindex,
            mac: info.mac,
            sides,
            tx,
            buf: vec![0u8; FRAME_MAX],
            next: 0,
        })
    }

    pub fn name(&self) -> &IfName {
        &self.name
    }

    /// Frames the kernel dropped on this port's sockets because their
    /// buffers were full (as of the last frame read from each).
    pub fn dropped(&self) -> u64 {
        self.sides.iter().map(|s| u64::from(s.dropped)).sum()
    }

    /// The smallest receive buffer the kernel gave this port's sockets, and
    /// the size asked for (`system.health.check` warns when short).
    pub fn rcvbuf(&self) -> (usize, usize) {
        use nix::sys::socket::{getsockopt, sockopt};
        let got = self
            .sides
            .iter()
            .filter_map(|s| getsockopt(&s.sock, sockopt::RcvBuf).ok())
            .map(|v| v / 2)
            .min()
            .unwrap_or(0);
        (got, RCVBUF)
    }

    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// For `poll`.
    pub fn fds(&self) -> Vec<BorrowedFd<'_>> {
        self.sides.iter().map(|s| s.sock.as_fd()).collect()
    }

    /// Every frame waiting (non-blocking, a budget per socket), each with
    /// its VLAN tag back in the frame. `f` gets the frame bytes.
    pub fn recv(&mut self, mut f: impl FnMut(&[u8])) -> io::Result<usize> {
        let n = self.sides.len();
        let first = self.next;
        self.next = (self.next + 1) % n.max(1);
        let mut total = 0;
        let mut framed = Vec::with_capacity(FRAME_MAX + 4);
        for k in 0..n {
            let Some(side) = self.sides.get_mut((first + k) % n) else {
                continue;
            };
            for _ in 0..BUDGET {
                let mut iov = [IoSliceMut::new(&mut self.buf)];
                let mut cmsg = nix::cmsg_space!(u32);
                let msg = match recvmsg::<LinkAddr>(
                    side.sock.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsg),
                    MsgFlags::MSG_DONTWAIT,
                ) {
                    Ok(m) => m,
                    Err(Errno::EAGAIN | Errno::EINTR) => break,
                    Err(e) => return Err(io_err(e)),
                };
                if let Ok(cmsgs) = msg.cmsgs() {
                    for c in cmsgs {
                        if let ControlMessageOwned::RxqOvfl(d) = c {
                            side.dropped = d;
                        }
                    }
                }
                let len = msg.bytes;
                let Some(frame) = self.buf.get(..len) else {
                    continue;
                };
                total += 1;
                let (tpid, vid) = match side.listen {
                    Listen::Untagged => {
                        f(frame);
                        continue;
                    }
                    Listen::Vlan(vid) => (TPID_8021Q, vid),
                    Listen::Stacked { outer, tpid } => (tpid, outer),
                };
                // dst, src, the outer tag back, then the rest (a QinQ
                // frame's inner tag is still there).
                let (Some(macs), Some(rest)) = (frame.get(..12), frame.get(12..)) else {
                    continue;
                };
                framed.clear();
                framed.extend_from_slice(macs);
                framed.extend_from_slice(&tpid.to_be_bytes());
                framed.extend_from_slice(&(vid & 0x0FFF).to_be_bytes());
                framed.extend_from_slice(rest);
                f(&framed);
            }
        }
        Ok(total)
    }

    /// Send one Ethernet frame (tags, if any, in the frame).
    pub fn send(&self, frame: &[u8]) -> io::Result<()> {
        send(self.tx.as_raw_fd(), frame, MsgFlags::empty())
            .map(|_| ())
            .map_err(io_err)
    }

    /// A sender of its own for another thread (the service's workers send
    /// while this one receives; G4.3g).
    pub fn sender(&self) -> io::Result<PortSender> {
        Ok(PortSender {
            ifindex: self.ifindex,
            tx: self.tx.try_clone()?,
        })
    }
}

/// The send side of a [`PppoePort`], for a worker thread.
pub struct PortSender {
    ifindex: u32,
    tx: Socket,
}

impl PortSender {
    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    pub fn send(&self, frame: &[u8]) -> io::Result<()> {
        send(self.tx.as_raw_fd(), frame, MsgFlags::empty())
            .map(|_| ())
            .map_err(io_err)
    }
}

/// Name of the slow path's device.
pub const SLOW_DEVICE: &str = "bng0";

/// The slow path (see the module docs).
pub struct SlowPath {
    raw: Socket,
    raw6: Socket,
    tap: Socket,
    ifindex: u32,
    buf: Vec<u8>,
}

impl SlowPath {
    /// Create (or reuse) `bng0`, bring it up and open the two sockets.
    pub fn open() -> io::Result<Self> {
        let name: IfName = SLOW_DEVICE
            .parse()
            .map_err(|e| io::Error::other(format!("{e}")))?;
        let ifindex = ensure_dummy(SLOW_DEVICE)?;
        let info = if_info(&name)?;
        let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(255)))?;
        raw.set_nonblocking(true)?;
        // IPPROTO_RAW on IPv6 sends the header as given (IPV6_HDRINCL).
        let raw6 = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::from(255)))?;
        raw6.set_nonblocking(true)?;
        let proto = Protocol::from(i32::from(ETH_P_ALL.to_be()));
        let tap = Socket::new(Domain::PACKET, Type::RAW, Some(proto))?;
        tap.set_nonblocking(true)?;
        crate::l2::rcvbuf(&tap, RCVBUF);
        tap.attach_filter(&filter(&outgoing_only()))?;
        bind(tap.as_raw_fd(), &info.link).map_err(io_err)?;
        Ok(Self {
            raw,
            raw6,
            tap,
            ifindex,
            buf: vec![0u8; FRAME_MAX],
        })
    }

    pub fn fd(&self) -> BorrowedFd<'_> {
        self.tap.as_fd()
    }

    /// Send a subscriber's IPv4 or IPv6 packet (header included) into the
    /// stack.
    pub fn inject(&self, packet: &[u8]) -> io::Result<()> {
        inject(&self.raw, &self.raw6, packet)
    }

    /// IPv4 and IPv6 packets the kernel routed to a subscriber (`bng0`),
    /// without their Ethernet header; `f` gets each.
    pub fn recv(&mut self, mut f: impl FnMut(&[u8])) -> io::Result<usize> {
        let mut total = 0;
        for _ in 0..BUDGET {
            let mut iov = [IoSliceMut::new(&mut self.buf)];
            let msg = match recvmsg::<LinkAddr>(
                self.tap.as_raw_fd(),
                &mut iov,
                None,
                MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(m) => m,
                Err(Errno::EAGAIN | Errno::EINTR) => break,
                Err(e) => return Err(io_err(e)),
            };
            let len = msg.bytes;
            let Some(frame) = self.buf.get(..len) else {
                continue;
            };
            // Ethernet II, IPv4 or IPv6 (G4.3l).
            if matches!(frame.get(12..14), Some([0x08, 0x00] | [0x86, 0xdd]))
                && let Some(ip) = frame.get(14..)
            {
                total += 1;
                f(ip);
            }
        }
        Ok(total)
    }

    /// Route `ip/32` to the subscribers' device.
    pub fn add_route(&self, ip: Ipv4Addr) -> io::Result<()> {
        route(self.ifindex, ip, true)
    }

    pub fn remove_route(&self, ip: Ipv4Addr) -> io::Result<()> {
        route(self.ifindex, ip, false)
    }

    /// The send side for a worker thread: its own raw socket and its own
    /// netlink connection, kept open (one connection per route cost a
    /// runtime and a socket each; G4.3g).
    pub fn sender(&self) -> io::Result<SlowTx> {
        let rt = runtime()?;
        let handle = rt.block_on(async {
            let (conn, handle, _) = rtnetlink::new_connection()?;
            tokio::spawn(conn);
            Ok::<_, io::Error>(handle)
        })?;
        Ok(SlowTx {
            raw: self.raw.try_clone()?,
            raw6: self.raw6.try_clone()?,
            ifindex: self.ifindex,
            rt,
            handle,
        })
    }
}

/// The send side of a [`SlowPath`]: inject upstream packets and keep the
/// `/32` routes to `bng0`.
pub struct SlowTx {
    raw: Socket,
    raw6: Socket,
    ifindex: u32,
    rt: tokio::runtime::Runtime,
    handle: rtnetlink::Handle,
}

impl SlowTx {
    pub fn inject(&self, packet: &[u8]) -> io::Result<()> {
        inject(&self.raw, &self.raw6, packet)
    }

    /// Add (`true`) or remove these IPv6 routes to `bng0` (a session's /64
    /// and delegated prefix, G4.3l), all in one round. The first error is
    /// returned; the rest still run.
    pub fn routes6(&self, ops: &[(Ipv6Addr, u8, bool)]) -> io::Result<()> {
        use rtnetlink::RouteMessageBuilder;
        if ops.is_empty() {
            return Ok(());
        }
        let ifindex = self.ifindex;
        self.rt.block_on(async {
            let calls = ops.iter().map(|&(net, len, add)| {
                let h = self.handle.clone();
                async move {
                    let msg = RouteMessageBuilder::<Ipv6Addr>::new()
                        .destination_prefix(net, len)
                        .output_interface(ifindex)
                        .build();
                    let out = if add {
                        h.route().add(msg).replace().execute().await
                    } else {
                        h.route().del(msg).execute().await
                    };
                    match out {
                        Ok(()) => Ok(()),
                        Err(rtnetlink::Error::NetlinkError(e)) if !add && e.raw_code() == -3 => {
                            Ok(())
                        }
                        Err(e) => Err(io::Error::other(format!(
                            "route {net}/{len} via {SLOW_DEVICE}: {e}"
                        ))),
                    }
                }
            });
            let results = futures_util::future::join_all(calls).await;
            results.into_iter().find(Result::is_err).unwrap_or(Ok(()))
        })
    }

    /// Add (`true`) or remove these `/32` routes, all in one round on the
    /// open connection. The first error is returned; the rest still run.
    pub fn routes(&self, ops: &[(Ipv4Addr, bool)]) -> io::Result<()> {
        let ops: Vec<(Ipv4Addr, u8, bool)> = ops.iter().map(|&(ip, add)| (ip, 32, add)).collect();
        self.prefixes(&ops)
    }

    /// Add (`true`) or remove routes `prefix/len` to `bng0` (a subscriber's
    /// /32, or a block routed to it, G4.3cd), in one round.
    pub fn prefixes(&self, ops: &[(Ipv4Addr, u8, bool)]) -> io::Result<()> {
        use rtnetlink::RouteMessageBuilder;
        if ops.is_empty() {
            return Ok(());
        }
        let ifindex = self.ifindex;
        self.rt.block_on(async {
            let calls = ops.iter().map(|&(ip, len, add)| {
                let h = self.handle.clone();
                async move {
                    let msg = RouteMessageBuilder::<Ipv4Addr>::new()
                        .destination_prefix(ip, len)
                        .output_interface(ifindex)
                        .build();
                    let out = if add {
                        h.route().add(msg).replace().execute().await
                    } else {
                        h.route().del(msg).execute().await
                    };
                    match out {
                        Ok(()) => Ok(()),
                        Err(rtnetlink::Error::NetlinkError(e)) if !add && e.raw_code() == -3 => {
                            Ok(())
                        }
                        Err(e) => Err(io::Error::other(format!(
                            "route {ip}/{len} via {SLOW_DEVICE}: {e}"
                        ))),
                    }
                }
            });
            let results = futures_util::future::join_all(calls).await;
            results.into_iter().find(Result::is_err).unwrap_or(Ok(()))
        })
    }
}

/// A subscriber's IPv4 or IPv6 packet (header included) into the stack.
fn inject(raw: &Socket, raw6: &Socket, packet: &[u8]) -> io::Result<()> {
    if packet.first().is_some_and(|b| b >> 4 == 6) {
        let dst = packet
            .get(24..40)
            .and_then(|d| <[u8; 16]>::try_from(d).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "short IPv6 packet"))?;
        let to = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(dst), 0, 0, 0));
        return raw6.send_to(packet, &to.into()).map(|_| ());
    }
    let Some(dst) = packet.get(16..20) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "short IPv4 packet",
        ));
    };
    let dst = Ipv4Addr::new(
        dst.first().copied().unwrap_or(0),
        dst.get(1).copied().unwrap_or(0),
        dst.get(2).copied().unwrap_or(0),
        dst.get(3).copied().unwrap_or(0),
    );
    let to = SocketAddr::V4(SocketAddrV4::new(dst, 0));
    raw.send_to(packet, &to.into()).map(|_| ())
}

fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
}

/// The index of dummy device `name`, created and set up if missing.
pub(crate) fn ensure_dummy(name: &str) -> io::Result<u32> {
    use futures_util::TryStreamExt;
    use rtnetlink::{LinkDummy, LinkMessageBuilder, LinkUnspec};
    let rt = runtime()?;
    rt.block_on(async {
        let (conn, handle, _) = rtnetlink::new_connection()?;
        let task = tokio::spawn(conn);
        let find = |h: rtnetlink::Handle| async move {
            let mut links = h.link().get().match_name(name.to_owned()).execute();
            links
                .try_next()
                .await
                .ok()
                .flatten()
                .map(|l| l.header.index)
        };
        let index = match find(handle.clone()).await {
            Some(i) => i,
            None => {
                handle
                    .link()
                    .add(LinkMessageBuilder::<LinkDummy>::new(name).build())
                    .execute()
                    .await
                    .map_err(|e| io::Error::other(format!("creating {name}: {e}")))?;
                find(handle.clone())
                    .await
                    .ok_or_else(|| io::Error::other(format!("{name} vanished after creation")))?
            }
        };
        handle
            .link()
            .set(LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await
            .map_err(|e| io::Error::other(format!("setting {name} up: {e}")))?;
        task.abort();
        Ok(index)
    })
}

fn route(ifindex: u32, ip: Ipv4Addr, add: bool) -> io::Result<()> {
    use rtnetlink::RouteMessageBuilder;
    let rt = runtime()?;
    rt.block_on(async {
        let (conn, handle, _) = rtnetlink::new_connection()?;
        let task = tokio::spawn(conn);
        let msg = RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(ip, 32)
            .output_interface(ifindex)
            .build();
        let out = if add {
            handle.route().add(msg).replace().execute().await
        } else {
            handle.route().del(msg).execute().await
        };
        task.abort();
        match out {
            Ok(()) => Ok(()),
            // Removing a route already gone is fine.
            Err(rtnetlink::Error::NetlinkError(e)) if !add && e.raw_code() == -3 => Ok(()),
            Err(e) => Err(io::Error::other(format!(
                "route {ip}/32 via {SLOW_DEVICE}: {e}"
            ))),
        }
    })
}

/// G4.3cd: routes of blocks to IPoE subscribers (`prefix/len via
/// subscriber`, the subscriber on a connected network), added (`true`) or
/// removed, in one round on one connection. The kernel forwards IPoE
/// downstream itself (no encapsulation), so a routed block needs this
/// route whether XDP polices the session or not. The first error is
/// returned; the rest still run. A route already gone is fine.
pub fn gateway_routes(ops: &[(Ipv4Addr, u8, Ipv4Addr, bool)]) -> io::Result<()> {
    use rtnetlink::RouteMessageBuilder;
    if ops.is_empty() {
        return Ok(());
    }
    let rt = runtime()?;
    rt.block_on(async {
        let (conn, handle, _) = rtnetlink::new_connection()?;
        let task = tokio::spawn(conn);
        let mut first = Ok(());
        for &(dst, len, via, add) in ops {
            let msg = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(dst, len)
                .gateway(via)
                .build();
            let out = if add {
                handle.route().add(msg).replace().execute().await
            } else {
                handle.route().del(msg).execute().await
            };
            let r = match out {
                Ok(()) => Ok(()),
                Err(rtnetlink::Error::NetlinkError(e)) if !add && e.raw_code() == -3 => Ok(()),
                Err(e) => Err(io::Error::other(format!(
                    "route {dst}/{len} via {via}: {e}"
                ))),
            };
            if first.is_ok() {
                first = r;
            }
        }
        task.abort();
        first
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frame as the socket sees it: the outer tag (TPID, VID) off the
    /// frame, the rest in it.
    struct Seen<'a> {
        tag: Option<(u16, u16)>,
        pkttype: u8,
        frame: &'a [u8],
    }

    /// The kernel's interpreter for the few opcodes used.
    fn run(p: &[Ins], s: &Seen<'_>) -> u32 {
        let mut a = 0u32;
        let mut pc = 0usize;
        while let Some(&(code, jt, jf, k)) = p.get(pc) {
            pc += 1;
            match code {
                LD_W_ABS if k == SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT => {
                    a = u32::from(s.tag.is_some())
                }
                // The PCP bits come along: the filter must mask them off.
                LD_W_ABS if k == SKF_AD_OFF + SKF_AD_VLAN_TAG => {
                    a = s.tag.map_or(0, |t| u32::from(t.1) | 0x2000)
                }
                LD_W_ABS if k == SKF_AD_OFF + SKF_AD_VLAN_TPID => {
                    a = s.tag.map_or(0, |t| u32::from(t.0))
                }
                LD_W_ABS if k == SKF_AD_OFF + SKF_AD_PKTTYPE => a = u32::from(s.pkttype),
                LD_H_ABS => {
                    let i = k as usize;
                    // A load past the end ends the program with 0 (drop).
                    let (Some(x), Some(y)) = (s.frame.get(i), s.frame.get(i + 1)) else {
                        return 0;
                    };
                    a = u32::from(u16::from_be_bytes([*x, *y]));
                }
                ALU_AND_K => a &= k,
                JEQ_K => pc += usize::from(if a == k { jt } else { jf }),
                RET_K => return k,
                other => panic!("opcode {other:#x}"),
            }
        }
        panic!("fell off the end")
    }

    /// dst, src, then `rest` (the EtherType, maybe after an inner tag).
    fn frame(rest: &[u8]) -> Vec<u8> {
        let mut f = vec![0xff; 6];
        f.extend_from_slice(&[2, 0, 0, 0, 0, 9]);
        f.extend_from_slice(rest);
        f.resize(60, 0);
        f
    }

    const DISC: [u8; 2] = [0x88, 0x63];
    const SES: [u8; 2] = [0x88, 0x64];
    const IPV4: [u8; 2] = [0x08, 0x00];

    fn inner(vid: u16, et: [u8; 2]) -> Vec<u8> {
        let mut v = vec![0x81, 0x00];
        v.extend_from_slice(&vid.to_be_bytes());
        v.extend_from_slice(&et);
        v
    }

    fn keeps(l: Listen, tag: Option<(u16, u16)>, rest: &[u8]) -> bool {
        let f = frame(rest);
        run(
            &program(l),
            &Seen {
                tag,
                pkttype: 0,
                frame: &f,
            },
        ) == ACCEPT
    }

    #[test]
    fn each_socket_keeps_only_pppoe_of_its_tags() {
        let q100 = Some((TPID_8021Q, 100));
        let s200 = Some((0x88a8, 200));
        // Untagged: no tag, PPPoE only.
        assert!(keeps(Listen::Untagged, None, &DISC));
        assert!(keeps(Listen::Untagged, None, &SES));
        assert!(!keeps(Listen::Untagged, None, &IPV4));
        assert!(
            !keeps(Listen::Untagged, q100, &DISC),
            "a tagged frame is not untagged"
        );
        // One 802.1Q tag.
        assert!(keeps(Listen::Vlan(100), q100, &DISC));
        assert!(keeps(Listen::Vlan(100), q100, &SES));
        assert!(!keeps(Listen::Vlan(100), Some((TPID_8021Q, 101)), &DISC));
        assert!(!keeps(Listen::Vlan(100), None, &DISC));
        assert!(
            !keeps(Listen::Vlan(100), Some((0x88a8, 100)), &DISC),
            "802.1Q only"
        );
        assert!(
            !keeps(Listen::Vlan(100), q100, &inner(7, DISC)),
            "QinQ is not single-tagged PPPoE"
        );
        // Two tags: the S-tag's VID and TPID, then an 802.1Q tag in the
        // frame and PPPoE behind it.
        let st = Listen::Stacked {
            outer: 200,
            tpid: 0x88a8,
        };
        assert!(keeps(st, s200, &inner(3044, DISC)));
        assert!(keeps(st, s200, &inner(1, SES)));
        assert!(!keeps(st, s200, &inner(3044, IPV4)));
        assert!(!keeps(st, s200, &DISC), "one tag only");
        assert!(
            !keeps(st, Some((TPID_8021Q, 200)), &inner(3044, DISC)),
            "wrong TPID"
        );
        assert!(!keeps(st, Some((0x88a8, 201)), &inner(3044, DISC)));
        let q_in_q = Listen::Stacked {
            outer: 200,
            tpid: TPID_8021Q,
        };
        assert!(keeps(q_in_q, Some((TPID_8021Q, 200)), &inner(3044, DISC)));
    }

    #[test]
    fn the_ports_never_read_back_what_the_bng_sent() {
        for (l, tag, rest) in [
            (Listen::Untagged, None, DISC.to_vec()),
            (Listen::Vlan(100), Some((TPID_8021Q, 100)), SES.to_vec()),
            (
                Listen::Stacked {
                    outer: 9,
                    tpid: 0x88a8,
                },
                Some((0x88a8, 9)),
                inner(5, DISC),
            ),
        ] {
            let f = frame(&rest);
            assert_eq!(
                run(
                    &program(l),
                    &Seen {
                        tag,
                        pkttype: PACKET_OUTGOING,
                        frame: &f
                    }
                ),
                0
            );
            assert_eq!(
                run(
                    &program(l),
                    &Seen {
                        tag,
                        pkttype: 0,
                        frame: &f
                    }
                ),
                ACCEPT
            );
        }
    }

    /// A short frame (the load at 16 past the end) is dropped, as the
    /// kernel does.
    #[test]
    fn a_short_frame_is_dropped() {
        let p = program(Listen::Stacked {
            outer: 9,
            tpid: 0x88a8,
        });
        let f = [0u8; 14];
        assert_eq!(
            run(
                &p,
                &Seen {
                    tag: Some((0x88a8, 9)),
                    pkttype: 0,
                    frame: &f
                }
            ),
            0
        );
    }

    #[test]
    fn the_tap_keeps_only_outgoing_frames() {
        let p = outgoing_only();
        assert_eq!(
            run(
                &p,
                &Seen {
                    tag: None,
                    pkttype: PACKET_OUTGOING,
                    frame: &[]
                }
            ),
            ACCEPT
        );
        assert_eq!(
            run(
                &p,
                &Seen {
                    tag: None,
                    pkttype: 0,
                    frame: &[]
                }
            ),
            0
        );
    }
}
