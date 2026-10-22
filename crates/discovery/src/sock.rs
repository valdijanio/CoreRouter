//! The UDP sockets of CRDP.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::time::Duration;

use corerouter_proto_discovery::{Announcement, MAX_PACKET, decode};
use socket2::{Domain, Protocol, Socket, Type};

/// IPv6 all-nodes, link scope.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
/// How long a receive blocks, so threads notice when they should stop.
pub const RECV_TIMEOUT: Duration = Duration::from_millis(500);

fn shared_socket(domain: Domain) -> io::Result<Socket> {
    let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    // Every CRDP process on a host (daemons, GUI) binds the same port; each
    // one gets its own copy of every broadcast and multicast datagram.
    s.set_reuse_address(true)?;
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "freebsd"
    ))]
    s.set_reuse_port(true)?;
    s.set_read_timeout(Some(RECV_TIMEOUT))?;
    Ok(s)
}

/// Receives IPv4 broadcasts on `0.0.0.0:port`.
pub fn listen_v4(port: u16) -> io::Result<UdpSocket> {
    let s = shared_socket(Domain::IPV4)?;
    s.set_broadcast(true)?;
    s.bind(&SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)).into())?;
    Ok(s.into())
}

/// Receives IPv6 datagrams to `ff02::1` on `[::]:port` (IPv6 only, so IPv4
/// copies are not delivered twice).
pub fn listen_v6(port: u16) -> io::Result<UdpSocket> {
    let s = shared_socket(Domain::IPV6)?;
    s.set_only_v6(true)?;
    s.bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)).into())?;
    Ok(s.into())
}

/// Join all-nodes on interface `index` (the kernel is always a member; the
/// explicit join makes delivery to this socket not depend on defaults).
pub fn join_all_nodes(sock: &UdpSocket, index: u32) {
    if let Err(e) = sock.join_multicast_v6(&ALL_NODES, index) {
        // Already joined (EADDRINUSE) is the normal case on a re-scan.
        if e.kind() != io::ErrorKind::AddrInUse {
            log::debug!("join ff02::1 on interface {index}: {e}");
        }
    }
}

/// Send one IPv6 datagram to `ff02::1` out of interface `index`.
pub fn send_v6(sock: &UdpSocket, packet: &[u8], index: u32, port: u16) -> io::Result<()> {
    let to = SocketAddrV6::new(ALL_NODES, port, 0, index);
    sock.send_to(packet, to).map(|_| ())
}

/// Send one IPv4 broadcast from `from` to `broadcast:port`. Binding to the
/// interface's own address makes the kernel route it out of that interface.
pub fn send_v4(from: Ipv4Addr, broadcast: Ipv4Addr, packet: &[u8], port: u16) -> io::Result<()> {
    let s = UdpSocket::bind(SocketAddrV4::new(from, 0))?;
    s.set_broadcast(true)?;
    s.send_to(packet, SocketAddrV4::new(broadcast, port))
        .map(|_| ())
}

/// One received announcement, or `None` on timeout or garbage (logged at
/// debug: anyone on the link can send anything).
pub fn receive(
    sock: &UdpSocket,
    buf: &mut [u8; MAX_PACKET + 1],
) -> Option<(Announcement, SocketAddr)> {
    let (n, from) = match sock.recv_from(buf) {
        Ok(x) => x,
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
            ) =>
        {
            return None;
        }
        Err(e) => {
            log::debug!("CRDP receive: {e}");
            std::thread::sleep(RECV_TIMEOUT);
            return None;
        }
    };
    match decode(buf.get(..n).unwrap_or_default()) {
        Ok(a) => Some((a, from)),
        Err(e) => {
            log::debug!("CRDP datagram from {from} dropped: {e}");
            None
        }
    }
}

/// True when `ip` belongs to this host (binding to it succeeds). Used to
/// reach a neighbor running on this same machine over loopback.
pub fn is_local(ip: std::net::IpAddr, scope: u32) -> bool {
    match ip {
        std::net::IpAddr::V4(a) => {
            a.is_loopback() || UdpSocket::bind(SocketAddrV4::new(a, 0)).is_ok()
        }
        std::net::IpAddr::V6(a) => {
            a.is_loopback() || UdpSocket::bind(SocketAddrV6::new(a, 0, 0, scope)).is_ok()
        }
    }
}
