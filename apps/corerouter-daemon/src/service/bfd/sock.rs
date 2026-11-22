//! The BFD engine's sockets (Linux): one receive socket per thread on each
//! of 3784 (single hop, RFC 5881) and 4784 (multihop, RFC 5883), all of a
//! port in one `SO_REUSEPORT` group, and a classic BPF program on the
//! group that hands a packet to socket `Your Discriminator mod N` — the
//! thread that owns the session (discriminators are chosen so). Packets
//! with Your Discriminator 0 (a session coming up) go to socket 0, which
//! finds the owner by address. Each datagram comes with its TTL / Hop
//! Limit (RFC 5881 §5) and the address it was sent to.
//!
//! Transmit: one socket per thread and family, bound to a source port of
//! 49152–65535 (RFC 5881 §4), TTL 255. RFC 5881 §4 says the port SHOULD
//! differ per session; one per thread keeps 1 000 sessions at 4 sockets
//! per thread instead of 1 000 descriptors (receivers demultiplex by
//! discriminator and address, not port; `docs/bfd.md`).

use std::io::{IoSlice, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};

use nix::libc;
use nix::sys::socket::{
    AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType, SockaddrIn, SockaddrIn6,
    SockaddrStorage, bind, recvmsg, sendmsg, setsockopt, socket, sockopt,
};

pub(crate) fn nix_io(e: nix::Error) -> std::io::Error {
    std::io::Error::from_raw_os_error(e as i32)
}

/// One received datagram.
pub(crate) struct Datagram {
    pub len: usize,
    pub from: IpAddr,
    pub to: Option<IpAddr>,
    pub ttl: Option<u8>,
}

pub(crate) struct Rx {
    fd: OwnedFd,
    pub multihop: bool,
}

fn family(v6: bool) -> AddressFamily {
    if v6 { AddressFamily::Inet6 } else { AddressFamily::Inet }
}

fn new_fd(v6: bool) -> std::io::Result<OwnedFd> {
    socket(
        family(v6),
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        None,
    )
    .map_err(nix_io)
}

fn bind_to(fd: &OwnedFd, at: SocketAddr) -> std::io::Result<()> {
    match at {
        SocketAddr::V4(a) => bind(fd.as_raw_fd(), &SockaddrIn::from(a)).map_err(nix_io),
        SocketAddr::V6(a) => bind(fd.as_raw_fd(), &SockaddrIn6::from(a)).map_err(nix_io),
    }
}

/// `ld [8]; mod #n; ret a`: the 32-bit word at offset 8 of the UDP payload
/// (Your Discriminator, RFC 5880 §4.1) modulo the group size. A reuseport
/// program sees the payload from offset 0 (the kernel pulls the UDP header
/// before running it); a load past the end returns 0, socket 0.
fn steer_program(n: u32) -> [libc::sock_filter; 3] {
    [
        libc::sock_filter { code: 0x20, jt: 0, jf: 0, k: 8 },          // BPF_LD|BPF_W|BPF_ABS
        libc::sock_filter { code: 0x94, jt: 0, jf: 0, k: n.max(1) },   // BPF_ALU|BPF_MOD|BPF_K
        libc::sock_filter { code: 0x16, jt: 0, jf: 0, k: 0 },          // BPF_RET|BPF_A
    ]
}

impl Rx {
    /// Binds one member of the port's reuseport group. Members must be
    /// bound in thread order: the program's answer is the bind order.
    pub(crate) fn bind(at: SocketAddr, multihop: bool) -> std::io::Result<Self> {
        let v6 = at.is_ipv6();
        let fd = new_fd(v6)?;
        setsockopt(&fd, sockopt::ReusePort, &true).map_err(nix_io)?;
        if v6 {
            setsockopt(&fd, sockopt::Ipv6V6Only, &true).map_err(nix_io)?;
            setsockopt(&fd, sockopt::Ipv6RecvPacketInfo, &true).map_err(nix_io)?;
            setsockopt(&fd, sockopt::Ipv6RecvHopLimit, &true).map_err(nix_io)?;
        } else {
            setsockopt(&fd, sockopt::Ipv4PacketInfo, &true).map_err(nix_io)?;
            setsockopt(&fd, sockopt::Ipv4RecvTtl, &true).map_err(nix_io)?;
        }
        // A burst of 1 000 sessions' packets fits (the default ~200 KB does too,
        // but a slow thread should not drop).
        let _ = setsockopt(&fd, sockopt::RcvBuf, &(1 << 20));
        bind_to(&fd, at)?;
        Ok(Self { fd, multihop })
    }

    /// Attaches the steering program to the group of this socket (once per
    /// group). `Err` leaves the kernel's hash: packets that land on the
    /// wrong thread are handed over (counted as `forwarded`).
    pub(crate) fn steer(&self, n: u32) -> std::io::Result<()> {
        let mut prog = steer_program(n);
        let fprog = libc::sock_fprog {
            len: prog.len() as u16,
            filter: prog.as_mut_ptr(),
        };
        setsockopt(&self.fd, sockopt::AttachReusePortCbpf, &fprog).map_err(nix_io)
    }

    pub(crate) fn fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// One datagram, `None` when the queue is empty.
    pub(crate) fn recv(&self, buf: &mut [u8]) -> std::io::Result<Option<Datagram>> {
        let mut cmsg = nix::cmsg_space!(libc::in6_pktinfo, libc::c_int);
        let mut iov = [IoSliceMut::new(buf)];
        let msg = match recvmsg::<SockaddrStorage>(self.fd.as_raw_fd(), &mut iov, Some(&mut cmsg), MsgFlags::MSG_DONTWAIT) {
            Ok(m) => m,
            Err(nix::Error::EAGAIN) => return Ok(None),
            Err(e) => return Err(nix_io(e)),
        };
        let (mut to, mut ttl) = (None, None);
        for c in msg.cmsgs().map_err(nix_io)? {
            match c {
                ControlMessageOwned::Ipv4PacketInfo(i) => {
                    to = Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(i.ipi_addr.s_addr))));
                }
                ControlMessageOwned::Ipv6PacketInfo(i) => {
                    to = Some(IpAddr::V6(Ipv6Addr::from(i.ipi6_addr.s6_addr)));
                }
                ControlMessageOwned::Ipv4Ttl(t) => ttl = u8::try_from(t).ok(),
                ControlMessageOwned::Ipv6HopLimit(t) => ttl = u8::try_from(t).ok(),
                _ => {}
            }
        }
        let from = msg.address.as_ref().and_then(|a| {
            a.as_sockaddr_in()
                .map(|v4| IpAddr::V4(v4.ip()))
                .or_else(|| a.as_sockaddr_in6().map(|v6| IpAddr::V6(v6.ip())))
        });
        let Some(from) = from else {
            return Ok(None);
        };
        // An IPv4-mapped source on a v6 socket is IPv4 (V6ONLY prevents it).
        Ok(Some(Datagram {
            len: msg.bytes,
            from,
            to,
            ttl,
        }))
    }
}

/// The transmit socket of one thread and family.
pub(crate) struct Tx {
    fd: OwnedFd,
    v6: bool,
}

impl Tx {
    /// Binds a free port of 49152–65535, starting at `start`.
    pub(crate) fn bind(ip: IpAddr, start: u16) -> std::io::Result<Self> {
        let v6 = ip.is_ipv6();
        let fd = new_fd(v6)?;
        if v6 {
            setsockopt(&fd, sockopt::Ipv6V6Only, &true).map_err(nix_io)?;
            setsockopt(&fd, sockopt::Ipv6Ttl, &255).map_err(nix_io)?;
        } else {
            setsockopt(&fd, sockopt::Ipv4Ttl, &255).map_err(nix_io)?;
        }
        let range = corerouter_proto_bfd::SOURCE_PORTS;
        let span = u32::from(range.end() - range.start()) + 1;
        let first = u32::from(start.saturating_sub(*range.start())) % span;
        let mut last = None;
        for i in 0..256u32 {
            let port = *range.start() + ((first + i) % span) as u16;
            match bind_to(&fd, SocketAddr::new(ip, port)) {
                Ok(()) => return Ok(Self { fd, v6 }),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| std::io::Error::other("no free BFD source port")))
    }

    /// Sends from `local` when given (IP_PKTINFO), else the route's source.
    pub(crate) fn send(&self, bytes: &[u8], to: SocketAddr, local: Option<IpAddr>) -> std::io::Result<()> {
        let iov = [IoSlice::new(bytes)];
        let r = match (to, local) {
            (SocketAddr::V4(dst), l) if !self.v6 => {
                let src = match l {
                    Some(IpAddr::V4(s)) => u32::from(s).to_be(),
                    _ => 0,
                };
                let info = libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr { s_addr: src },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };
                let cm = [ControlMessage::Ipv4PacketInfo(&info)];
                sendmsg(
                    self.fd.as_raw_fd(),
                    &iov,
                    if src == 0 { &[] } else { &cm },
                    MsgFlags::MSG_DONTWAIT,
                    Some(&SockaddrIn::from(dst)),
                )
            }
            (SocketAddr::V6(dst), l) if self.v6 => {
                let info = libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr {
                        s6_addr: match l {
                            Some(IpAddr::V6(s)) => s.octets(),
                            _ => [0; 16],
                        },
                    },
                    ipi6_ifindex: 0,
                };
                let cm = [ControlMessage::Ipv6PacketInfo(&info)];
                let with = matches!(l, Some(IpAddr::V6(_)));
                sendmsg(
                    self.fd.as_raw_fd(),
                    &iov,
                    if with { &cm } else { &[] },
                    MsgFlags::MSG_DONTWAIT,
                    Some(&SockaddrIn6::from(dst)),
                )
            }
            _ => return Err(std::io::Error::other("address family mismatch")),
        };
        r.map(|_| ()).map_err(nix_io)
    }
}
