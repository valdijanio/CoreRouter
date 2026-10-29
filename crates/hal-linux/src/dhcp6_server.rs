//! DHCPv6 server and relay transport (G4.2c), without `unsafe`: a UDP
//! socket on port 547 bound to the interface and joined to
//! All_DHCP_Relay_Agents_and_Servers (`ff02::1:2`, RFC 9915 §7.1) — where
//! clients send — answering to the client's link-local address port 546
//! (or a relay agent's port 547) out of that interface; and, for the
//! relay, one socket on port 547 not bound to an interface, towards the
//! servers. Several sockets share port 547 through `SO_REUSEADDR` plus the
//! device binding, like the client's 546.

use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};

use corerouter_hal::HalError;
use corerouter_hal::dhcp::{ALL_DHCP_SERVERS, MAX_MESSAGE, SERVER_PORT6};
use corerouter_hal::dhcp_server::{Dhcp6ServerPort, Dhcp6Uplink, Heard6};
use corerouter_model::IfName;
use socket2::{Domain, Protocol, Socket, Type};

use crate::l2::{if_info, io_err};

const RECV_BUDGET: usize = 256;
/// Receive buffer of the server's sockets: a SOLICIT storm must not
/// overflow the default between two rounds (as DHCPv4, G0.31).
const RCVBUF: usize = 4 << 20;

fn read(sock: &UdpSocket, name: &str) -> Result<Option<Heard6>, HalError> {
    let mut buf = [0u8; MAX_MESSAGE];
    for _ in 0..RECV_BUDGET {
        match sock.recv_from(&mut buf) {
            Ok((n, SocketAddr::V6(from))) => {
                if n >= MAX_MESSAGE {
                    continue;
                }
                let Some(payload) = buf.get(..n) else {
                    continue;
                };
                return Ok(Some(Heard6 {
                    payload: payload.to_vec(),
                    src: *from.ip(),
                }));
            }
            Ok(_) => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(HalError::Io(format!("{name}: {e}"))),
        }
    }
    Ok(None)
}

pub struct LinuxDhcp6ServerPort {
    name: IfName,
    mac: [u8; 6],
    ifindex: u32,
    sock: UdpSocket,
}

impl LinuxDhcp6ServerPort {
    pub fn open(name: &IfName) -> io::Result<Self> {
        let info = if_info(name)?;
        let ifindex = nix::net::if_::if_nametoindex(name.as_str()).map_err(io_err)?;
        let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_only_v6(true)?;
        sock.set_reuse_address(true)?;
        sock.set_nonblocking(true)?;
        crate::l2::rcvbuf(&sock, RCVBUF);
        sock.bind_device(Some(name.as_str().as_bytes()))?;
        sock.set_multicast_loop_v6(false)?;
        sock.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, SERVER_PORT6)).into())?;
        sock.join_multicast_v6(&ALL_DHCP_SERVERS, ifindex)?;
        Ok(Self {
            name: name.clone(),
            mac: info.mac,
            ifindex,
            sock: sock.into(),
        })
    }
}

impl Dhcp6ServerPort for LinuxDhcp6ServerPort {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn recv(&mut self) -> Result<Option<Heard6>, HalError> {
        read(&self.sock, self.name.as_str())
    }

    fn send(&mut self, payload: &[u8], to: Ipv6Addr, port: u16) -> Result<(), HalError> {
        // A link-local or multicast destination needs the interface.
        let scope = if to.is_unicast_link_local() || to.is_multicast() {
            self.ifindex
        } else {
            0
        };
        self.sock
            .send_to(payload, SocketAddrV6::new(to, port, 0, scope))
            .map(|_| ())
            .map_err(|e| HalError::Io(format!("{} → [{to}]:{port}: {e}", self.name)))
    }

    fn describe(&self) -> String {
        format!("udp6 547 on {}", self.name)
    }
}

/// The relay's socket towards the servers.
pub struct LinuxDhcp6Uplink {
    sock: UdpSocket,
}

impl LinuxDhcp6Uplink {
    pub fn open() -> io::Result<Self> {
        let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_only_v6(true)?;
        sock.set_reuse_address(true)?;
        sock.set_nonblocking(true)?;
        crate::l2::rcvbuf(&sock, RCVBUF);
        sock.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, SERVER_PORT6)).into())?;
        Ok(Self { sock: sock.into() })
    }
}

impl Dhcp6Uplink for LinuxDhcp6Uplink {
    fn recv(&mut self) -> Result<Option<Heard6>, HalError> {
        read(&self.sock, "relay6 uplink")
    }

    fn send(&mut self, payload: &[u8], to: Ipv6Addr) -> Result<(), HalError> {
        self.sock
            .send_to(payload, SocketAddrV6::new(to, SERVER_PORT6, 0, 0))
            .map(|_| ())
            .map_err(|e| HalError::Io(format!("relay6 → [{to}]: {e}")))
    }
}
