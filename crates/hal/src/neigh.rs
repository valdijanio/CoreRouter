//! Neighbor tables (G1.27d): what the data plane knows of the hosts next
//! to it, IPv4 (ARP, RFC 826) and IPv6 (Neighbor Discovery, RFC 4861).
//!
//! A backend gives one dump and a live feed of changes ([`NeighborFeed`]);
//! the engine keeps the table up to date from the feed, one change at a
//! time, without polling. States use the words of RFC 4861 §7.3.2, which
//! Linux uses for ARP too (`NUD_*`).

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use corerouter_model::IfName;
use serde::Serialize;

use crate::HalError;

/// Neighbors one dump returns at most (hostile kernel or a flood: the
/// table never grows past this).
pub const MAX_NEIGHBORS: usize = 1 << 20;

/// State of a neighbor entry (RFC 4861 §7.3.2, plus Linux's own three).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NeighState {
    /// Address resolution in progress: a request (ARP) or a Neighbor
    /// Solicitation was sent and nothing answered yet.
    Incomplete,
    /// Confirmed within the reachable time (RFC 4861 §7.3.2 REACHABLE).
    Reachable,
    /// Not confirmed lately; still used, checked on the next packet.
    Stale,
    /// Used while stale: waiting `DELAY_FIRST_PROBE_TIME` (5 s) for an
    /// upper-layer confirmation before probing.
    Delay,
    /// Unicast probes being sent (`MAX_UNICAST_SOLICIT`).
    Probe,
    /// Resolution failed: nothing answered (RFC 7048 calls it UNREACHABLE).
    Failed,
    /// Set by the operator; never expires (Linux `NUD_PERMANENT`).
    Permanent,
    /// No resolution needed (point-to-point, multicast; `NUD_NOARP`).
    Noarp,
}

impl NeighState {
    pub const ALL: [Self; 8] = [
        Self::Incomplete,
        Self::Reachable,
        Self::Stale,
        Self::Delay,
        Self::Probe,
        Self::Failed,
        Self::Permanent,
        Self::Noarp,
    ];

    /// From Linux's `ndm_state` bit mask (`NUD_*`); `None` for
    /// `NUD_NONE` (an entry being created) or an unknown bit.
    pub fn from_nud(bits: u16) -> Option<Self> {
        // One bit is set; if several were, the most settled one wins.
        [
            (0x80, Self::Permanent),
            (0x40, Self::Noarp),
            (0x02, Self::Reachable),
            (0x04, Self::Stale),
            (0x08, Self::Delay),
            (0x10, Self::Probe),
            (0x20, Self::Failed),
            (0x01, Self::Incomplete),
        ]
        .into_iter()
        .find(|(b, _)| bits & b != 0)
        .map(|(_, s)| s)
    }

    pub fn nud(self) -> u16 {
        match self {
            Self::Incomplete => 0x01,
            Self::Reachable => 0x02,
            Self::Stale => 0x04,
            Self::Delay => 0x08,
            Self::Probe => 0x10,
            Self::Failed => 0x20,
            Self::Noarp => 0x40,
            Self::Permanent => 0x80,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Incomplete => "incomplete",
            Self::Reachable => "reachable",
            Self::Stale => "stale",
            Self::Delay => "delay",
            Self::Probe => "probe",
            Self::Failed => "failed",
            Self::Permanent => "permanent",
            Self::Noarp => "noarp",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }

    /// Whether a packet to this neighbor leaves with a known MAC: the
    /// states where layer 2 resolved (or did not need to).
    pub fn resolved(self) -> bool {
        !matches!(self, Self::Incomplete | Self::Failed)
    }
}

/// One entry of a neighbor table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Neighbor {
    pub interface: IfName,
    pub address: IpAddr,
    /// Link-layer address; `None` while incomplete or failed (or not
    /// Ethernet).
    pub mac: Option<[u8; 6]>,
    pub state: NeighState,
    /// The neighbor said it is a router (IPv6 `NTF_ROUTER`, RFC 4861 §4.4
    /// R flag).
    pub router: bool,
    /// Seconds since the entry was last confirmed reachable, when the
    /// platform says (`NDA_CACHEINFO`).
    pub confirmed_secs: Option<u32>,
    /// Seconds since the entry last changed.
    pub updated_secs: Option<u32>,
}

/// A change in a neighbor table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeighEvent {
    /// New entry, or one that changed (state, MAC).
    Upsert(Neighbor),
    /// The entry is gone (expired, flushed, its interface went away).
    Remove { interface: IfName, address: IpAddr },
}

/// A live view of the platform's neighbor tables: one dump, then the
/// changes as they happen. Kept by one thread, read with no lock held.
pub trait NeighborFeed: Send {
    /// Every entry now (at most [`MAX_NEIGHBORS`]); `false` when the
    /// table had more.
    fn dump(&mut self, out: &mut Vec<Neighbor>) -> Result<bool, HalError>;

    /// Append the changes that arrive within `wait_ms` (at most `max`).
    /// Changes the platform could not deliver (a full socket buffer) are
    /// counted in [`NeighborFeed::lost`]: the caller dumps again.
    fn recv(&mut self, wait_ms: u32, max: usize, out: &mut Vec<NeighEvent>)
    -> Result<(), HalError>;

    /// Times changes were lost since the feed opened.
    fn lost(&self) -> u64;

    /// What feeds it, for people: `netlink` or `lab`.
    fn name(&self) -> &'static str;
}

/// One static entry outside the config (DHCP `add-arp`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticNeigh {
    pub interface: IfName,
    pub address: Ipv4Addr,
    /// `None`: remove it.
    pub mac: Option<[u8; 6]>,
}

/// A host that answered an ARP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpReply {
    pub mac: [u8; 6],
    pub rtt: Duration,
}

/// Sends ARP requests out of one interface (`arping`; RouterOS
/// `/ping arp-ping=yes`): reachability of a host that drops ICMP.
pub trait ArpPinger: Send {
    /// One request for `target` from `src` (the interface's own address,
    /// RFC 826 sender fields), and the first reply within `timeout`.
    fn ping(
        &mut self,
        src: Ipv4Addr,
        target: Ipv4Addr,
        timeout: Duration,
    ) -> Result<Option<ArpReply>, HalError>;
}

/// The MAC as RouterOS prints it.
pub fn mac_text(mac: [u8; 6]) -> String {
    let [a, b, c, d, e, f] = mac;
    format!("{a:02X}:{b:02X}:{c:02X}:{d:02X}:{e:02X}:{f:02X}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nud_bits_round_trip() {
        for s in NeighState::ALL {
            assert_eq!(NeighState::from_nud(s.nud()), Some(s));
            assert_eq!(NeighState::parse(s.as_str()), Some(s));
        }
        assert_eq!(NeighState::from_nud(0), None);
        assert_eq!(NeighState::from_nud(0x0100), None);
    }

    #[test]
    fn only_incomplete_and_failed_are_unresolved() {
        let bad: Vec<_> = NeighState::ALL
            .into_iter()
            .filter(|s| !s.resolved())
            .collect();
        assert_eq!(bad, [NeighState::Incomplete, NeighState::Failed]);
    }
}
