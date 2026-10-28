//! LSP ping and traceroute (G3.5b, RFC 8029 with RFC 9570).
//!
//! - [`wire`]: the MPLS echo request / reply codec;
//! - [`respond`]: what an LSR answers (egress and transit), without I/O;
//! - [`sim`]: the lab's LSPs, answered by that same responder;
//! - the traits here: the sending side ([`LspProber`] → [`LspSocket`],
//!   used by the engine's tasks without the session lock) and the
//!   answering side ([`LspResponderIo`], on a thread of the daemon).
//!
//! A request leaves as the data plane would send traffic of the FEC: with
//! the FEC's label stack, to the next hop of its route, but addressed to
//! 127.0.0.1 with IP TTL 1 (RFC 8029 §4.3) so that no router forwards it as
//! IP and the LSR where it leaves the LSP (or where its label TTL expires)
//! hands it to its control plane. Since RFC 9570 §4 it carries no Router
//! Alert option.

pub mod respond;
pub mod sim;
pub mod wire;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use corerouter_model::IfName;
use ipnet::IpNet;
use serde::Serialize;

use crate::HalError;
use crate::mpls::Origin;
use crate::probe::ProbeError;

pub use respond::{Heard, LsrView, Verdict};

/// One way the FEC leaves this router (the FTN entry: the route of the
/// prefix with its labels).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LspPath {
    /// Labels pushed, top first; empty: the next hop is the egress
    /// (implicit null), the request goes out unlabeled.
    pub labels: Vec<u32>,
    pub nexthop: Option<IpAddr>,
    pub interface: IfName,
    /// The address requests of this path come from.
    pub src: Option<IpAddr>,
    /// Link MTU, when known.
    pub mtu: Option<u16>,
    /// Who installed the route (LDP, static…).
    pub origin: Origin,
}

/// One echo request to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LspRequest<'a> {
    pub path: &'a LspPath,
    /// TTL of the top label (255 to ping, 1, 2… to trace). An unlabeled
    /// path uses it as the IP TTL, which then is at most 1 (§4.3).
    pub ttl: u8,
    /// IP destination in 127/8 (IPv4) or ::1 (IPv6, RFC 9570 §4).
    pub dst: IpAddr,
    /// DSCP << 2, also the label's TC (its top 3 bits).
    pub tos: u8,
    /// The encoded echo request ([`wire::encode`]). The socket stamps its
    /// TimeStamp Sent.
    pub payload: &'a [u8],
}

/// A reply that came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LspAnswer {
    pub from: IpAddr,
    /// The UDP payload (an echo reply, to be parsed).
    pub payload: Vec<u8>,
    /// From sending the request with this reply's sequence number to now.
    pub rtt: Option<Duration>,
}

/// An open LSP ping socket: sends requests along LSPs, hears the replies.
pub trait LspSocket: Send {
    /// How `fec` leaves this router now (several: ECMP). Empty: no route.
    fn paths(&mut self, fec: IpNet) -> Result<Vec<LspPath>, ProbeError>;
    /// Send one request. `Err(Unreachable)` is an answer for this request
    /// (no neighbor entry, link down); other errors end the task.
    fn send(&mut self, req: &LspRequest<'_>) -> Result<(), ProbeError>;
    /// The next reply, waiting at most `wait` (simulated sockets answer at
    /// once and may return `None` early).
    fn recv(&mut self, wait: Duration) -> Result<Option<LspAnswer>, ProbeError>;
}

/// Opens LSP ping sockets; shared with task threads.
pub trait LspProber: Send + Sync {
    fn describe(&self) -> String;
    fn open(&self) -> Result<Box<dyn LspSocket>, ProbeError>;
}

pub type SharedLspProber = Arc<dyn LspProber>;

/// The responder's I/O: requests heard on the MPLS links, replies sent
/// from UDP port 3503. It also is the [`LsrView`] the answers come from
/// ([`LspResponderIo::view`]), kept fresh by the backend (cached reads).
pub trait LspResponderIo: Send {
    /// Interfaces to listen on (the MPLS ones); replaces the set.
    fn set_interfaces(&mut self, names: &[IfName]) -> Vec<(IfName, String)>;
    /// The next request, waiting at most `wait`.
    fn recv(&mut self, wait: Duration) -> Result<Option<Heard>, HalError>;
    /// Send one reply.
    fn send(
        &mut self,
        to: SocketAddr,
        from: Option<IpAddr>,
        tos: Option<u8>,
        payload: &[u8],
    ) -> Result<(), HalError>;
    /// What the LSR knows now.
    fn view(&mut self) -> &dyn LsrView;
    /// NTP time now (for TimeStamp Received).
    fn now_ntp(&self) -> (u32, u32);
}

/// The 127/8 destination of request `n` (RFC 8029 §2.1: varying it
/// exercises ECMP paths; a fixed one keeps a ping on one path). IPv6:
/// ::1 (RFC 9570 §4).
pub fn destination(v6: bool, n: u32) -> IpAddr {
    if v6 {
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    } else {
        let [_, b, c, d] = n.to_be_bytes();
        // 127.0.0.0 and 127.255.255.255 avoided.
        let d = d.clamp(1, 254);
        IpAddr::V4(std::net::Ipv4Addr::new(127, b, c, d))
    }
}
