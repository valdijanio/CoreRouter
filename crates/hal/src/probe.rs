//! ICMP echo probes for the diagnostic tools (ping, MTU discovery, MTR).
//!
//! The engine never touches sockets: a [`Hal`](crate::Hal) hands out a
//! [`Prober`] (`Send + Sync`, used from a task thread without the session
//! lock), which opens [`ProbeSocket`]s. A socket is dual-stack (it opens the
//! IPv4 and IPv6 sides on first use), sends echo requests to any number of
//! destinations and reports, from either family, what came back:
//! echo replies and the ICMP errors routers send about a probe (time
//! exceeded, unreachable, fragmentation needed / packet too big).
//!
//! Sizes are whole IP packets (IP header + ICMP header + payload), like the
//! `size` of RouterOS `/tool ping`. Round-trip times are measured by the
//! socket itself (send to receive), so the engine needs no clock.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

/// IPv4 header (no options) + ICMP echo header.
pub const V4_OVERHEAD: u16 = 28;
/// IPv6 header + ICMPv6 echo header.
pub const V6_OVERHEAD: u16 = 48;
/// Largest IP packet a probe may have (IPv4 total length; IPv6 jumbograms
/// are not supported).
pub const MAX_PACKET: u16 = 65_535;

/// Smallest packet (no payload) for `addr`'s family.
pub fn overhead(addr: IpAddr) -> u16 {
    match addr {
        IpAddr::V4(_) => V4_OVERHEAD,
        IpAddr::V6(_) => V6_OVERHEAD,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn of(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }
}

/// What a probe is (G6.4c). ICMP echo is what ping and the MTR send;
/// traceroute can also send UDP or TCP SYN, which firewalls that drop ICMP
/// let through and which reach a service's own path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase", tag = "proto")]
pub enum ProbeProto {
    #[default]
    Icmp,
    /// UDP to `port` (classic traceroute: `port + seq`, so each probe is a
    /// flow of its own; Paris: `port`, the same flow). The destination
    /// answers "port unreachable".
    Udp { port: u16 },
    /// A TCP SYN to `port` (a `connect`). The destination answers SYN-ACK
    /// (a service listens; the connection is reset at once) or RST.
    Tcp { port: u16 },
}

/// Socket-wide options, fixed when the socket is opened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SocketOptions {
    /// Traffic class byte (DSCP << 2) for IPv4 TOS / IPv6 traffic class.
    pub tos: u8,
    /// IPv4: set DF and never fragment locally; IPv6: never fragment locally.
    pub dont_fragment: bool,
    /// Source address for probes of its family (the other family is sent
    /// without one).
    pub src: Option<IpAddr>,
    /// Device to send through (`SO_BINDTODEVICE`): an interface, or a VRF
    /// device to use that VRF's routing table.
    pub device: Option<String>,
    /// What the probes are (default ICMP echo).
    pub proto: ProbeProto,
    /// Paris traceroute (Augustin et al., IMC 2006): every probe of the
    /// socket is the same flow for a per-flow load balancer — same ports,
    /// and for ICMP the same checksum (a payload word compensates the
    /// sequence number) — so all of them take one of the ECMP paths
    /// instead of zig-zagging between them.
    pub paris: bool,
}

/// One echo request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    pub dst: IpAddr,
    /// Echo sequence number; replies and errors carry it back.
    pub seq: u16,
    /// IPv4 TTL / IPv6 hop limit; `None`: the system default.
    pub ttl: Option<u8>,
    /// Whole IP packet size (at least [`overhead`] of `dst`).
    pub size: u16,
}

/// What a reply says about a probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyKind {
    /// Echo reply from the destination.
    Echo,
    /// A router dropped it because the TTL / hop limit reached zero.
    TtlExceeded,
    /// Destination unreachable (any code but "fragmentation needed").
    Unreachable(String),
    /// Too big for a link on the path: IPv4 "fragmentation needed" with DF,
    /// IPv6 "packet too big". `mtu`: the next-hop MTU, when reported.
    TooBig { mtu: Option<u16> },
    /// The destination answered a UDP or TCP probe: "port unreachable",
    /// "syn-ack" or "rst" (for traceroute, the end of the path).
    Reached(String),
}

/// The 16-bit word that, put in an ICMP echo's payload, keeps its checksum
/// the same whatever `seq` is (Paris): `seq + word` is `0xFFFF` in one's
/// complement, so the sum over the header and payload does not change.
pub fn paris_word(seq: u16) -> u16 {
    !seq
}

/// One answer to a probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub seq: u16,
    /// Who answered: the destination, or the router reporting an error.
    pub from: IpAddr,
    pub kind: ReplyKind,
    /// Size of the reply packet, when known.
    pub size: Option<u16>,
    /// TTL / hop limit the reply arrived with, when known.
    pub ttl: Option<u8>,
    /// From sending the probe to receiving this.
    pub rtt: Duration,
    /// MPLS label stack the router reported (RFC 4950), top first; empty
    /// when none (or the socket cannot see ICMP extensions).
    pub mpls: Vec<MplsLabel>,
}

/// One MPLS label stack entry (RFC 3032 §2.1; RFC 5462 renamed EXP to TC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MplsLabel {
    pub label: u32,
    pub tc: u8,
    /// S: bottom of the stack.
    pub bottom: bool,
    pub ttl: u8,
}

impl std::fmt::Display for MplsLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "L={} TC={} S={} TTL={}",
            self.label,
            self.tc,
            u8::from(self.bottom),
            self.ttl
        )
    }
}

/// A name lookup that must not hold up the probes: asked again later
/// until it is `Done`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup<T> {
    Pending,
    Done(T),
}

/// The AS that originates the prefix of an address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AsInfo {
    pub asn: u32,
    /// Short name ("LEVEL3").
    pub name: Option<String>,
    /// The announced prefix ("4.0.0.0/9").
    pub prefix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError {
    /// Larger than the local link / known path MTU allows (`EMSGSIZE`).
    #[error("packet too big for the path (mtu {})", mtu_text(.0))]
    TooBig(Option<u16>),
    /// No route, network down… (an answer for this probe, not a failure of
    /// the tool).
    #[error("{0}")]
    Unreachable(String),
    #[error("name '{0}' could not be resolved")]
    NotFound(String),
    /// The socket cannot be opened (permissions, unsupported family…).
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    Io(String),
}

fn mtu_text(mtu: &Option<u16>) -> String {
    mtu.map_or_else(|| "unknown".to_owned(), |m| m.to_string())
}

/// An open ICMP socket (both families).
pub trait ProbeSocket: Send {
    /// Send one echo request. `Err(TooBig | Unreachable)` is a local answer
    /// for this probe; other errors mean the socket is unusable.
    fn send(&mut self, probe: &Probe) -> Result<(), ProbeError>;

    /// Next reply to one of this socket's probes, waiting at most `wait`.
    /// `Ok(None)`: nothing arrived in time. May return early with `None`
    /// (simulated backends answer at once), so callers wait out the rest of
    /// their interval themselves.
    fn recv(&mut self, wait: Duration) -> Result<Option<Reply>, ProbeError>;
}

/// Opens probe sockets. Shared with task threads, so `Send + Sync`.
pub trait Prober: Send + Sync {
    /// "host ICMP (raw socket)", "simulated (deterministic)"…
    fn describe(&self) -> String;

    /// Addresses of `name` (a DNS name; IP literals never reach here).
    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, ProbeError>;

    /// A socket with `options`. Failing to open one family's side is
    /// reported by the first `send` to that family.
    fn open(&self, options: &SocketOptions) -> Result<Box<dyn ProbeSocket>, ProbeError>;

    /// The name of `ip` (PTR), without waiting: `Pending` while a lookup
    /// runs elsewhere, `Done(None)` when there is none. Default: no names.
    fn reverse_name(&self, _ip: IpAddr) -> Lookup<Option<String>> {
        Lookup::Done(None)
    }

    /// The origin AS of `ip`, without waiting, like [`Self::reverse_name`].
    fn origin_as(&self, _ip: IpAddr) -> Lookup<Option<AsInfo>> {
        Lookup::Done(None)
    }
}

pub type SharedProber = Arc<dyn Prober>;
