//! DHCPv6 client transport (G4.7b) on one interface, without `unsafe`: a
//! UDP socket on port 546 bound to the device (`SO_BINDTODEVICE`), sending
//! every message to All_DHCP_Relay_Agents_and_Servers (`ff02::1:2`, port
//! 547) out of that interface (RFC 9915 §7.1); the kernel picks the
//! link-local source. Servers answer to that link-local address, so no
//! multicast group is joined. Several interfaces share port 546 through
//! `SO_REUSEADDR` plus the device binding, as the DHCPv4 unicast socket does.
//!
//! Until the link-local address finishes DAD (about a second after the
//! link comes up) the kernel refuses to send: the client's retransmission
//! covers that.

use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};

use corerouter_hal::HalError;
use corerouter_hal::dhcp::{
    ALL_DHCP_SERVERS, CLIENT_PORT6, Datagram6, Dhcp6Port, MAX_MESSAGE, SERVER_PORT6,
};
use corerouter_model::IfName;
use socket2::{Domain, Protocol, Socket, Type};

use crate::l2::{if_info, io_err};

/// Datagrams read per call (a flood cannot stall the service loop).
const RECV_BUDGET: usize = 64;

pub struct LinuxDhcp6Port {
    name: IfName,
    mac: [u8; 6],
    ifindex: u32,
    sock: UdpSocket,
}

impl LinuxDhcp6Port {
    pub fn open(name: &IfName) -> io::Result<Self> {
        let info = if_info(name)?;
        let ifindex = nix::net::if_::if_nametoindex(name.as_str()).map_err(io_err)?;
        let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_only_v6(true)?;
        sock.set_reuse_address(true)?;
        sock.set_nonblocking(true)?;
        sock.bind_device(Some(name.as_str().as_bytes()))?;
        sock.set_multicast_if_v6(ifindex)?;
        sock.set_multicast_loop_v6(false)?;
        sock.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, CLIENT_PORT6)).into())
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("UDP port {CLIENT_PORT6} ({e}; another DHCPv6 client on this host?)"),
                )
            })?;
        Ok(Self {
            name: name.clone(),
            mac: info.mac,
            ifindex,
            sock: sock.into(),
        })
    }
}

impl Dhcp6Port for LinuxDhcp6Port {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn send(&mut self, payload: &[u8]) -> Result<(), HalError> {
        let to = SocketAddrV6::new(ALL_DHCP_SERVERS, SERVER_PORT6, 0, self.ifindex);
        self.sock
            .send_to(payload, to)
            .map(|_| ())
            .map_err(|e| HalError::Io(format!("{}: {e}", self.name)))
    }

    fn recv(&mut self) -> Result<Option<Datagram6>, HalError> {
        let mut buf = [0u8; MAX_MESSAGE];
        for _ in 0..RECV_BUDGET {
            match self.sock.recv_from(&mut buf) {
                Ok((n, SocketAddr::V6(from))) => {
                    // Only from a server's port; a truncated message is dropped.
                    if from.port() != SERVER_PORT6 || n >= MAX_MESSAGE {
                        continue;
                    }
                    let Some(payload) = buf.get(..n) else {
                        continue;
                    };
                    return Ok(Some(Datagram6 {
                        payload: payload.to_vec(),
                        src: *from.ip(),
                        src_mac: None,
                    }));
                }
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(e) => return Err(HalError::Io(format!("{}: {e}", self.name))),
            }
        }
        Ok(None)
    }
}
