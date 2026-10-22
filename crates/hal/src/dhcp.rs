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

use std::net::{Ipv4Addr, Ipv6Addr};
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

/// Network number N (1..=254) of lab port `port`: its trailing number, else
/// a hash of its name. Behind it the lab has `100.64.N.0/24` and
/// `2001:db8:0:N::/64` (see `proto_dhcp::lab` and `lab6`).
pub fn lab_net(port: &IfName) -> u8 {
    let name = port.as_str();
    let digits = name.len() - name.trim_end_matches(|c: char| c.is_ascii_digit()).len();
    let n = name
        .get(name.len().saturating_sub(digits)..)
        .and_then(|d| d.parse::<u32>().ok())
        .filter(|n| (1..=254).contains(n))
        .unwrap_or_else(|| 1 + lab_hash(name.as_bytes()) % 254);
    u8::try_from(n).unwrap_or(1)
}

/// FNV-1a, the lab's stable hash.
pub fn lab_hash(bytes: &[u8]) -> u32 {
    bytes.iter().fold(2_166_136_261u32, |h, b| {
        (h ^ u32::from(*b)).wrapping_mul(16_777_619)
    })
}

/// The lab router's MAC behind port N (also its DHCP servers').
pub fn lab_router_mac(n: u8) -> [u8; 6] {
    [0x02, 0xdc, 0, 0, 0, n]
}

/// Modified EUI-64 interface identifier of `mac` (RFC 4291 App. A).
pub fn eui64(mac: [u8; 6]) -> u64 {
    let [a, b, c, d, e, f] = mac;
    u64::from_be_bytes([a ^ 0x02, b, c, 0xff, 0xfe, d, e, f])
}

/// Link-local address of `mac` (fe80::/64 + EUI-64).
pub fn link_local(mac: [u8; 6]) -> Ipv6Addr {
    Ipv6Addr::from((0xfe80u128 << 112) | u128::from(eui64(mac)))
}

// ---- DHCPv6 (G4.7b) --------------------------------------------------------

/// DHCPv6 client and server ports (RFC 8415 §7.2).
pub const CLIENT_PORT6: u16 = 546;
pub const SERVER_PORT6: u16 = 547;
/// All_DHCP_Relay_Agents_and_Servers (RFC 8415 §7.1): where a client sends.
pub const ALL_DHCP_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// One DHCPv6 message received on port 546.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram6 {
    pub payload: Vec<u8>,
    /// IPv6 source: the server's (or relay's) link-local address.
    pub src: Ipv6Addr,
    /// Ethernet source, when the platform sees it.
    pub src_mac: Option<[u8; 6]>,
}

/// A DHCPv6 client socket on one interface. Every message goes to
/// [`ALL_DHCP_SERVERS`] from the interface's link-local address (the client
/// never unicasts: the Server Unicast option is deprecated, RFC 9915).
pub trait Dhcp6Port: Send {
    /// Hardware address of the interface (the DUID-LL is made of it).
    fn mac(&self) -> [u8; 6];

    fn send(&mut self, payload: &[u8]) -> Result<(), HalError>;

    /// Next message for port 546, or `None` when nothing is waiting.
    fn recv(&mut self) -> Result<Option<Datagram6>, HalError>;
}

/// A simulated DHCPv6 server for the virtual lab and the tests.
pub trait Dhcp6Responder: Send + Sync {
    /// Answers to `payload`, sent by the client with hardware address `mac`
    /// on lab port `port`.
    fn answer(&self, port: &IfName, mac: [u8; 6], payload: &[u8]) -> Vec<Datagram6>;
}

pub type SharedResponder6 = Arc<dyn Dhcp6Responder>;
