//! The connection tracking table (G2.2): what the kernel's conntrack holds,
//! as `IP › Firewall › Connections` shows it, and the lab's simulated one.
//!
//! One [`Conn`] per tracked connection, both directions: `orig` is the
//! tuple as the first packet came (the subscriber's private address for a
//! CGNAT connection), `reply` the tuple the answers carry (the public
//! address and port the NAT chose). [`Via`] says whether packets still go
//! through the rules or the flowtable fast path took the connection
//! (software, or the NIC itself: G2.4).

use std::net::IpAddr;

use serde::Serialize;

/// `IPS_*` status bits (`include/uapi/linux/netfilter/nf_conntrack_common.h`).
pub mod status {
    pub const EXPECTED: u32 = 1 << 0;
    pub const SEEN_REPLY: u32 = 1 << 1;
    pub const ASSURED: u32 = 1 << 2;
    pub const CONFIRMED: u32 = 1 << 3;
    pub const SRC_NAT: u32 = 1 << 4;
    pub const DST_NAT: u32 = 1 << 5;
    pub const DYING: u32 = 1 << 9;
    pub const OFFLOAD: u32 = 1 << 14;
    pub const HW_OFFLOAD: u32 = 1 << 15;
}

/// One direction of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Tuple {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// TCP/UDP/SCTP ports, or the ICMP query id in `src_port` (0 otherwise).
    pub src_port: u16,
    /// The destination port; for ICMP, type and code (`type << 8 | code`).
    pub dst_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Via {
    /// Every packet goes through the firewall rules.
    Rules,
    /// The software flowtable (`nf_flowtable`, RouterOS "fasttrack").
    Software,
    /// Offloaded to the NIC (`flags offload`, e.g. mlx5 switchdev).
    Hardware,
}

impl Via {
    pub fn as_str(self) -> &'static str {
        match self {
            Via::Rules => "rules",
            Via::Software => "software",
            Via::Hardware => "hardware",
        }
    }
}

/// TCP states (`enum tcp_conntrack`), as RouterOS names them.
pub fn tcp_state_name(state: u8) -> &'static str {
    match state {
        1 => "syn-sent",
        2 => "syn-received",
        3 => "established",
        4 => "fin-wait",
        5 => "close-wait",
        6 => "last-ack",
        7 => "time-wait",
        8 => "close",
        9 => "syn-sent2",
        _ => "none",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Conn {
    /// The kernel's id (`CTA_ID`): what `kill` names.
    pub id: u32,
    /// IP protocol number (6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6…).
    pub protocol: u8,
    pub orig: Tuple,
    pub reply: Tuple,
    /// `status::*` bits.
    pub status: u32,
    /// Seconds until it expires.
    pub timeout: u32,
    pub tcp_state: Option<u8>,
    pub mark: u32,
    pub orig_packets: u64,
    pub orig_bytes: u64,
    pub reply_packets: u64,
    pub reply_bytes: u64,
}

impl Conn {
    pub fn via(&self) -> Via {
        if self.status & status::HW_OFFLOAD != 0 {
            Via::Hardware
        } else if self.status & status::OFFLOAD != 0 {
            Via::Software
        } else {
            Via::Rules
        }
    }

    pub fn has(&self, bit: u32) -> bool {
        self.status & bit != 0
    }

    /// RouterOS' "connection-state" of the connection.
    pub fn state(&self) -> &'static str {
        match self.tcp_state {
            Some(s) => tcp_state_name(s),
            None if self.has(status::ASSURED) => "stream",
            None if self.has(status::SEEN_REPLY) => "established",
            None => "new",
        }
    }
}

/// The table's size and its trouble counters (`conntrack -S`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Stats {
    pub count: u64,
    pub max: u64,
    /// Summed over CPUs: a new connection that found no free NAT tuple or
    /// lost a race (`insert_failed`), packets dropped for a full table
    /// (`drop`), entries evicted to make room (`early_drop`).
    pub insert_failed: u64,
    pub drop: u64,
    pub early_drop: u64,
}

/// What `connections` reads at most (a CGNAT box holds millions; the
/// engine filters and pages what comes back).
pub const MAX_READ: usize = 2_000_000;
