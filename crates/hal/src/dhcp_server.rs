//! DHCP server transport (G4.2a): how the server hears clients on one
//! interface and answers them, as bytes. Building and reading the messages
//! is `proto-dhcp`'s job; the engine glues the two, like the client's
//! [`crate::dhcp`].
//!
//! The Linux backend reads whole frames (`AF_PACKET`), so the server hears
//! clients that have no address yet and sees their MAC, answers a client
//! without an address by unicast to its MAC (RFC 2131 §4.1, no ARP entry
//! needed) and also hears other servers' replies (the rogue-server alert).
//! The virtual lab has simulated hosts behind each port ([`LabClients`]).

use std::net::Ipv4Addr;
use std::sync::Arc;

use corerouter_model::IfName;

use crate::HalError;

/// Something heard on the server's interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heard {
    /// UDP payload: the DHCP message.
    pub payload: Vec<u8>,
    /// IP source (0.0.0.0 from a client without an address; a relay agent's
    /// address for a relayed request).
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    /// Ethernet source.
    pub src_mac: [u8; 6],
    /// `false`: a message to port 68 — another server's reply (or a relay's
    /// copy), heard for the alert; `true`: a request to port 67.
    pub to_server: bool,
}

/// Where a reply goes (RFC 2131 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyTo {
    /// 255.255.255.255:68 as a link broadcast.
    Broadcast,
    /// The client at `ip` (its new address) by unicast to `mac`, port 68,
    /// without ARP (it does not answer ARP yet).
    Client { ip: Ipv4Addr, mac: [u8; 6] },
    /// A relay agent, port 67, routed.
    Relay(Ipv4Addr),
    /// A client that has an address (`ciaddr`), port 68, routed.
    Unicast(Ipv4Addr),
}

/// The DHCP server's socket on one interface.
pub trait DhcpServerPort: Send {
    fn mac(&self) -> [u8; 6];

    /// The clock, for platforms that simulate the network (the lab). Called
    /// before every round of `recv`.
    fn tick(&mut self, now_unix: u64) {
        let _ = now_unix;
    }

    /// Next message, or `None` when nothing is waiting.
    fn recv(&mut self) -> Result<Option<Heard>, HalError>;

    /// Send one reply from `src` (the server's address) port 67.
    fn send(&mut self, payload: &[u8], src: Ipv4Addr, to: ReplyTo) -> Result<(), HalError>;

    /// Ask who has `ip` (an ARP request from `src`, the server address)
    /// before offering it (RFC 2131 §3.1, §4.4.1). `Ok(false)`: this
    /// platform cannot probe.
    fn probe(&mut self, ip: Ipv4Addr, src: Ipv4Addr) -> Result<bool, HalError> {
        let _ = (ip, src);
        Ok(false)
    }

    /// Hosts that answered (or claimed) a probed address since the last
    /// call: (address, their MAC).
    fn probe_replies(&mut self) -> Result<Vec<(Ipv4Addr, [u8; 6])>, HalError> {
        Ok(Vec::new())
    }

    /// What the socket listens on, for people (`udp 67 on ether2`).
    fn describe(&self) -> String {
        String::new()
    }

    /// Send a client's DISCOVER (port 68 to 67, broadcast, from 0.0.0.0):
    /// the alert looks for servers that only answer by unicast (G4.2b).
    fn send_discover(&mut self, payload: &[u8]) -> Result<(), HalError> {
        let _ = payload;
        Ok(())
    }
}

/// The relay agent's side towards the servers (G4.2b): UDP port 67 on
/// every interface, routed. Replies of the servers come back here.
pub trait DhcpUplink: Send {
    /// Next message to port 67 (`src` is the server's address).
    fn recv(&mut self) -> Result<Option<Heard>, HalError>;

    /// Send `payload` to `server` port 67.
    fn send(&mut self, payload: &[u8], server: Ipv4Addr) -> Result<(), HalError>;
}

/// The virtual lab's hosts: simulated DHCP clients (and a squatter, and a
/// rogue server) behind each lab port, for the lab, the screenshots and the
/// CI. Implemented by `proto_dhcp::lab_hosts`; the engine offers it to the
/// HAL like the lab's simulated servers.
pub trait LabClients: Send + Sync {
    /// What the hosts behind `port` send at `now_unix`.
    fn poll(&self, port: &IfName, now_unix: u64) -> Vec<Heard>;

    /// The router's server sent them `payload`.
    fn deliver(&self, port: &IfName, payload: &[u8], to: ReplyTo, now_unix: u64);

    /// The MAC of a lab host that answers ARP for `ip` behind `port`.
    fn arp(&self, port: &IfName, ip: Ipv4Addr) -> Option<[u8; 6]>;
}

pub type SharedLabClients = Arc<dyn LabClients>;
