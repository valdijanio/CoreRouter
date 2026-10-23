//! What gets exported: flow records, NAT events and port block events.
//! Plain data, the same for IPFIX and NetFlow v9 (the templates decide the
//! bytes) and for the router's own store of recent flows.

use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

/// `flowEndReason` (IANA, RFC 7012 §5.11.3): why this record was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EndReason {
    /// No packets for the inactive timeout (also a UDP or ICMP
    /// connection the kernel let expire).
    Idle,
    /// Still running at the active timeout: a long flow is reported in parts.
    Active,
    /// The connection ended (TCP closed).
    End,
    /// Ended by the exporter (traffic flow turned off, the router stopping).
    Forced,
    /// Lost track of it (an event the kernel dropped, a full cache).
    LackOfResources,
}

impl EndReason {
    pub fn code(self) -> u8 {
        match self {
            Self::Idle => 1,
            Self::Active => 2,
            Self::End => 3,
            Self::Forced => 4,
            Self::LackOfResources => 5,
        }
    }

    pub fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            1 => Self::Idle,
            2 => Self::Active,
            3 => Self::End,
            4 => Self::Forced,
            5 => Self::LackOfResources,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Active => "active",
            Self::End => "end",
            Self::Forced => "forced",
            Self::LackOfResources => "lack-of-resources",
        }
    }
}

/// `biflowDirection` (RFC 5103 §6.3): which side of the connection sent
/// the packets of this record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    /// From the side that opened the connection (a subscriber, usually).
    Initiator,
    /// The answers.
    Reverse,
}

impl Direction {
    pub fn code(self) -> u8 {
        match self {
            Self::Initiator => 1,
            Self::Reverse => 2,
        }
    }
}

/// One direction of one connection over one period: the classic flow
/// record, with the addresses and ports before and after NAT (equal when
/// nothing was translated).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Flow {
    /// Unix milliseconds.
    pub start_ms: u64,
    pub end_ms: u64,
    pub protocol: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    /// TCP/UDP/SCTP ports, or the ICMP query id in `src_port`.
    pub src_port: u16,
    pub dst_port: u16,
    pub post_src: IpAddr,
    pub post_dst: IpAddr,
    pub post_src_port: u16,
    pub post_dst_port: u16,
    pub octets: u64,
    pub packets: u64,
    /// ifIndex numbers (0: unknown), as the interface options record maps
    /// them to names.
    pub ingress: u32,
    pub egress: u32,
    pub end_reason: EndReason,
    pub direction: Direction,
}

impl Flow {
    /// The inside address of the connection: the source of the
    /// initiator's packets, the destination after NAT of the answers (the
    /// subscriber behind a CGNAT).
    pub fn subscriber(&self) -> IpAddr {
        match self.direction {
            Direction::Initiator => self.src,
            Direction::Reverse => self.post_dst,
        }
    }
}

/// `natEvent` values (IANA "NAT Event Type", RFC 8158 §4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NatEventType {
    Nat44SessionCreate,
    Nat44SessionDelete,
    PortBlockAllocation,
    PortBlockDeallocation,
}

impl NatEventType {
    pub fn code(self) -> u8 {
        match self {
            Self::Nat44SessionCreate => 4,
            Self::Nat44SessionDelete => 5,
            Self::PortBlockAllocation => 16,
            Self::PortBlockDeallocation => 17,
        }
    }

    pub fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            4 => Self::Nat44SessionCreate,
            5 => Self::Nat44SessionDelete,
            16 => Self::PortBlockAllocation,
            17 => Self::PortBlockDeallocation,
            _ => return None,
        })
    }
}

/// A NAT44 session created or deleted (RFC 8158 §4.2.1, §4.2.2): the
/// record a connection provider keeps to answer "who was this public
/// address and port at that moment".
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NatEvent {
    /// Unix milliseconds of the event.
    pub time_ms: u64,
    /// When the session started (Unix ms; 0 unknown). On a delete it makes
    /// the record complete by itself — start, end, both tuples — even when
    /// the create was lost (a kernel overrun).
    pub start_ms: u64,
    pub event: NatEventType,
    pub protocol: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub post_src: Ipv4Addr,
    pub post_dst: Ipv4Addr,
    pub post_src_port: u16,
    pub post_dst_port: u16,
}

/// A block of ports given to or taken from a subscriber (CGNAT port block
/// allocation, RFC 8158 §4.2.10/§4.2.11): one record per block instead of
/// one per connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortBlock {
    pub time_ms: u64,
    pub event: NatEventType,
    pub src: Ipv4Addr,
    pub post_src: Ipv4Addr,
    pub port_start: u16,
    pub port_end: u16,
    /// 1 for a contiguous block.
    pub step: u16,
    pub ports: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Record {
    Flow(Flow),
    Nat(NatEvent),
    PortBlock(PortBlock),
}

impl Record {
    /// Unix milliseconds the record is about (a flow's end).
    pub fn time_ms(&self) -> u64 {
        match self {
            Self::Flow(f) => f.end_ms,
            Self::Nat(n) => n.time_ms,
            Self::PortBlock(b) => b.time_ms,
        }
    }
}

/// Metadata the exporter sends next to the templates, as options records:
/// the sampling rate (so a collector scales the counters) and the
/// interface names behind the ifIndex numbers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Meta {
    /// 1 in N connections reported; 1 (or 0) is every one.
    pub sampling_interval: u32,
    /// (ifIndex, name).
    pub interfaces: Vec<(u32, String)>,
}
