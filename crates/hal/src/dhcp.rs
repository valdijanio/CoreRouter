//! DHCP client transport (G4.7): how a DHCP client sends and receives on
//! one interface, as bytes. Building and parsing the messages is the job of
//! `proto-dhcp` (L2); the engine glues the two.
//!
//! Everything is non-blocking: the engine polls [`DhcpPort::recv`] from its
//! service tick. The Linux backend reads and writes whole frames
//! (`AF_PACKET`), so a client hears its server before the interface has an
//! address and learns the server's MAC (for `allowed_servers`). The virtual
//! lab answers with a [`DhcpResponder`] — a simulated server, installed by
//! the engine — so the lab and the CI get leases without any network.

use std::net::Ipv4Addr;
use std::sync::Arc;

use corerouter_model::IfName;

use crate::HalError;

pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;
/// Largest DHCP message accepted (hostile input; RFC 2131 only promises
/// 576 bytes, jumbo frames carry more).
pub const MAX_MESSAGE: usize = 4096;

/// Where a message goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dest {
    /// 255.255.255.255 from port 68 to 67, as a link broadcast.
    Broadcast,
    /// The server (renewing; release): routed by the kernel when the
    /// interface has an address.
    Unicast(Ipv4Addr),
}

/// One DHCP message received on the client port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// UDP payload: the DHCP message.
    pub payload: Vec<u8>,
    /// IP source of the packet (the server, or the relay that forwarded it).
    pub src: Ipv4Addr,
    /// Ethernet source, when the platform sees it.
    pub src_mac: Option<[u8; 6]>,
}

/// A DHCP client socket on one interface.
pub trait DhcpPort: Send {
    /// Hardware address the client puts in `chaddr`.
    fn mac(&self) -> [u8; 6];

    /// Send one DHCP message from `src` (0.0.0.0 before a lease) to `dest`.
    fn send(&mut self, payload: &[u8], src: Ipv4Addr, dest: Dest) -> Result<(), HalError>;

    /// Next message for the client port, or `None` when nothing is waiting.
    fn recv(&mut self) -> Result<Option<Datagram>, HalError>;

    /// Start an ARP probe for `ip` (RFC 5227) before using it. `Ok(false)`:
    /// this platform cannot probe, so nothing will be reported.
    fn probe(&mut self, ip: Ipv4Addr) -> Result<bool, HalError> {
        let _ = ip;
        Ok(false)
    }

    /// The MAC of a host that answered the running probe, if one did.
    fn conflict(&mut self) -> Result<Option<[u8; 6]>, HalError> {
        Ok(None)
    }

    /// The probe is over: release what it holds.
    fn end_probe(&mut self) {}
}

/// A simulated DHCP server for the virtual lab and the tests.
pub trait DhcpResponder: Send + Sync {
    /// Answers to `payload`, sent by the client with hardware address `mac`
    /// on lab port `port`.
    fn answer(&self, port: &IfName, mac: [u8; 6], payload: &[u8], dest: Dest) -> Vec<Datagram>;

    /// The MAC of a lab host that already uses `ip` on `port`, if any (an
    /// ARP probe for `ip` finds it).
    fn conflict(&self, port: &IfName, ip: Ipv4Addr) -> Option<[u8; 6]> {
        let _ = (port, ip);
        None
    }
}

pub type SharedResponder = Arc<dyn DhcpResponder>;
