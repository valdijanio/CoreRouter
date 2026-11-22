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

/// `natEvent` values (IANA "NAT Event Type", RFC 8158 §4.3 Table 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NatEventType {
    /// 3: a pool has no address (in blocks mode: no block) left.
    AddressesExhausted,
    Nat44SessionCreate,
    Nat44SessionDelete,
    /// 13: a hard limit refused a mapping (§4.4, [`Quota`]).
    QuotaExceeded,
    PortBlockAllocation,
    PortBlockDeallocation,
    /// 18: a threshold the operator set was crossed (§4.5, [`Threshold`]).
    ThresholdReached,
}

impl NatEventType {
    pub fn code(self) -> u8 {
        match self {
            Self::AddressesExhausted => 3,
            Self::Nat44SessionCreate => 4,
            Self::Nat44SessionDelete => 5,
            Self::QuotaExceeded => 13,
            Self::PortBlockAllocation => 16,
            Self::PortBlockDeallocation => 17,
            Self::ThresholdReached => 18,
        }
    }

    /// The code a collector that predates RFC 8158 understands: the NAT44
    /// session events as 1/2 ("NAT translation create/delete", Historic in
    /// §4.3, still what ipt-netflow and older Juniper and F5 collectors
    /// read); every other event keeps its own.
    pub fn legacy_code(self) -> u8 {
        match self {
            Self::Nat44SessionCreate => 1,
            Self::Nat44SessionDelete => 2,
            other => other.code(),
        }
    }

    /// Reads the RFC 8158 codes and the Historic 1/2.
    pub fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            1 | 4 => Self::Nat44SessionCreate,
            2 | 5 => Self::Nat44SessionDelete,
            3 => Self::AddressesExhausted,
            13 => Self::QuotaExceeded,
            16 => Self::PortBlockAllocation,
            17 => Self::PortBlockDeallocation,
            18 => Self::ThresholdReached,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AddressesExhausted => "addresses-exhausted",
            Self::Nat44SessionCreate => "session-create",
            Self::Nat44SessionDelete => "session-delete",
            Self::QuotaExceeded => "quota-exceeded",
            Self::PortBlockAllocation => "block-alloc",
            Self::PortBlockDeallocation => "block-release",
            Self::ThresholdReached => "threshold-reached",
        }
    }
}

/// `natQuotaExceededEvent` (RFC 8158 §4.4 Table 3, IE 466).
pub mod quota {
    pub const MAX_SESSION_ENTRIES: u32 = 1;
    pub const MAX_BIB_ENTRIES: u32 = 2;
    /// A subscriber has every port (or every block) it may have.
    pub const MAX_ENTRIES_PER_USER: u32 = 3;
    pub const MAX_SUBSCRIBERS: u32 = 4;
}

/// `natThresholdEvent` (RFC 8158 §4.5 Table 4, IE 467).
pub mod threshold {
    pub const ADDRESS_POOL_HIGH: u32 = 1;
    pub const ADDRESS_POOL_LOW: u32 = 2;
    pub const ADDRESS_PORT_HIGH: u32 = 3;
    /// A subscriber uses more of its ports than the alert percentage.
    pub const ADDRESS_PORT_PER_USER_HIGH: u32 = 4;
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
    /// Who the subscriber is (G4.4j), when the router knows: the PPPoE
    /// login (`userName`, IE 371) and the VLAN it came in on (`vlanId`, IE
    /// 58; RFC 8158 §4.6 "vlanID/ingressVRFID"). Empty and 0 when not.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub vlan: u16,
    /// `natPoolId` (IE 283): the CGNAT pool's id; 0 unknown.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub pool: u32,
}

fn is_zero(v: &u16) -> bool {
    *v == 0
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

/// A NAT limit hit or a threshold crossed (RFC 8158 §4.6.5, §4.6.7.3,
/// §4.6.8.3): the pool out of addresses or blocks, a subscriber refused
/// for having every port it may have, a subscriber above the alert
/// percentage. Rate-limited where it is made (§5.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NatLimit {
    pub time_ms: u64,
    /// [`NatEventType::AddressesExhausted`], [`NatEventType::QuotaExceeded`]
    /// or [`NatEventType::ThresholdReached`].
    pub event: NatEventType,
    /// `natQuotaExceededEvent` ([`quota`]) or `natThresholdEvent`
    /// ([`threshold`]); 0 for addresses exhausted.
    pub kind: u32,
    /// The subscriber of a per-user event; unspecified otherwise.
    pub src: Ipv4Addr,
    /// `natPoolId`.
    pub pool: u32,
    /// The limit: `maxEntriesPerUser` (ports) of a quota,
    /// `addressPortMappingPerUserHighThreshold` (percent) of a threshold.
    pub limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum Record {
    Flow(Flow),
    Nat(NatEvent),
    PortBlock(PortBlock),
    NatLimit(NatLimit),
}

impl Record {
    /// Unix milliseconds the record is about (a flow's end).
    pub fn time_ms(&self) -> u64 {
        match self {
            Self::Flow(f) => f.end_ms,
            Self::Nat(n) => n.time_ms,
            Self::PortBlock(b) => b.time_ms,
            Self::NatLimit(l) => l.time_ms,
        }
    }

    /// A NAT event of any kind (not a traffic flow).
    pub fn is_nat(&self) -> bool {
        !matches!(self, Self::Flow(_))
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
