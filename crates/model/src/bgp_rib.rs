//! BGP routes as the routing daemon holds them (G3.2c): what one
//! neighbor sent us or what we sent it (`routing.bgp.route.list`), and
//! every path of one prefix (`routing.bgp.route.explain`). Operational
//! state, read on demand, never saved.
//!
//! A full table is ~1 M routes from each transit, so a route is kept
//! small: its prefix, an index into the attribute sets of the table
//! (interned: the routes of one neighbor share a few hundred thousand
//! AS paths at most, **estimado** from public tables) and flags. 24 bytes
//! per route, **medido** in the size test below.

use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// BGP ORIGIN (RFC 4271 §5.1.1), in preference order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    #[default]
    Igp,
    Egp,
    Incomplete,
}

impl Origin {
    pub fn name(self) -> &'static str {
        match self {
            Origin::Igp => "igp",
            Origin::Egp => "egp",
            Origin::Incomplete => "incomplete",
        }
    }

    /// FRR prints `IGP`, `EGP`, `incomplete` (and `?` in tables).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "igp" | "i" => Some(Origin::Igp),
            "egp" | "e" => Some(Origin::Egp),
            "incomplete" | "?" => Some(Origin::Incomplete),
            _ => None,
        }
    }
}

/// The path attributes many routes share.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct BgpAttrs {
    /// As FRR prints it: `64500 64501 {64510,64511}`; empty: our own.
    pub as_path: String,
    pub origin: Origin,
    pub next_hop: Option<IpAddr>,
    /// MULTI_EXIT_DISC.
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
    /// The daemon's own weight (not a BGP attribute; FRR, Cisco).
    pub weight: u32,
    /// RFC 1997 `asn:value` and well-known names; RFC 8092 `a:b:c`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub communities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub large_communities: Vec<String>,
}

/// One route of a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BgpRoute {
    pub prefix: IpNet,
    /// Index into [`BgpRib::attrs`].
    pub attrs: u32,
    pub flags: u8,
}

impl BgpRoute {
    /// The daemon chose it as the best path of the prefix.
    pub const BEST: u8 = 1;
    /// Received but refused by the inbound policy (RPKI invalid, RFC 8212,
    /// a filter): known only with the neighbor's Adj-RIB-In kept.
    pub const FILTERED: u8 = 2;

    pub fn best(&self) -> bool {
        self.flags & Self::BEST != 0
    }

    pub fn filtered(&self) -> bool {
        self.flags & Self::FILTERED != 0
    }
}

/// Which way a table goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// What the neighbor sent (RouterOS `received`): before the inbound
    /// policy when the Adj-RIB-In is kept, the accepted ones otherwise.
    Received,
    /// What we send it, after the outbound policy.
    Advertised,
}

impl Direction {
    pub fn name(self) -> &'static str {
        match self {
            Direction::Received => "received",
            Direction::Advertised => "advertised",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "received" | "in" => Some(Direction::Received),
            "advertised" | "out" => Some(Direction::Advertised),
            _ => None,
        }
    }
}

/// The routes of one neighbor, one way, one family or both.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BgpRib {
    pub routes: Vec<BgpRoute>,
    pub attrs: Vec<BgpAttrs>,
    /// The table holds the routes before the inbound policy (filtered ones
    /// included and flagged).
    pub pre_policy: bool,
    /// Why part of it could not be read (one family down, a cut answer).
    pub warnings: Vec<String>,
}

impl BgpRib {
    pub fn attrs_of(&self, r: &BgpRoute) -> Option<&BgpAttrs> {
        usize::try_from(r.attrs).ok().and_then(|i| self.attrs.get(i))
    }
}

/// An AS_PATH segment (RFC 4271 §4.3, RFC 5065 for confederations).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SegmentKind {
    Sequence,
    Set,
    ConfedSequence,
    ConfedSet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsSegment {
    pub kind: SegmentKind,
    pub asns: Vec<u32>,
}

/// How the path reached us.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PeerKind {
    /// Originated here (network, redistribute, aggregate).
    Local,
    #[default]
    External,
    Internal,
    /// From a peer of another member AS of our confederation.
    ConfedExternal,
}

/// One path of a prefix, with what the decision process compares.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BgpPath {
    /// The neighbor's address (`0.0.0.0`/`::` for our own).
    pub peer: String,
    pub peer_router_id: Option<Ipv4Addr>,
    pub peer_kind: PeerKind,
    pub segments: Vec<AsSegment>,
    /// As FRR prints it.
    pub as_path: String,
    pub origin: Origin,
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
    pub weight: u32,
    pub next_hop: Option<String>,
    /// Cost to the next hop in the IGP (RFC 4271 §9.1.2.2 e).
    pub igp_metric: Option<u32>,
    pub next_hop_reachable: bool,
    /// The daemon may use it (next hop reachable, no loop, …).
    pub valid: bool,
    pub best: bool,
    pub multipath: bool,
    /// The daemon's word for why the best one won (FRR `selectionReason`).
    pub selection_reason: Option<String>,
    /// Route reflection (RFC 4456): set on reflected routes.
    pub originator_id: Option<Ipv4Addr>,
    pub cluster_list_len: u32,
    pub communities: Vec<String>,
    pub large_communities: Vec<String>,
    /// Unix time it was last updated.
    pub last_update: Option<u64>,
    /// The daemon's RPKI state of the path, when it validates.
    pub rpki: Option<String>,
    pub stale: bool,
}

/// Every path the daemon holds for one prefix.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BgpPrefix {
    pub prefix: String,
    pub paths: Vec<BgpPath>,
    /// The table's defaults the comparison needs.
    pub default_local_pref: Option<u32>,
    pub local_as: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_route_is_small() {
        // A full table is a million of them per neighbor.
        assert!(std::mem::size_of::<BgpRoute>() <= 24, "{}", std::mem::size_of::<BgpRoute>());
    }

    #[test]
    fn names_parse() {
        assert_eq!(Origin::parse("IGP"), Some(Origin::Igp));
        assert_eq!(Origin::parse("?"), Some(Origin::Incomplete));
        assert_eq!(Direction::parse("out"), Some(Direction::Advertised));
        assert!(Origin::Igp < Origin::Incomplete);
    }
}
