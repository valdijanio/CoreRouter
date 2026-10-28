//! OSPF operational state (G3.4b): what `hal-frr` reads from `ospfd` and
//! `ospf6d` — neighbors, the interfaces' state, the link-state database
//! and the routes — for `/routing ospf neighbor`, `lsa`, the routes, the
//! Topology tab and the Diagnose. Not configuration: the daemon's `frr`
//! service fills it, outside the session lock.
//!
//! The LSDB is kept compact (one fixed-size row per LSA, the router and
//! network links in one flat array), because a large area has tens of
//! thousands of LSAs and the topology is rebuilt from it.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// One adjacency, as RouterOS v7 `/routing ospf neighbor print` shows it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OspfNeighbor {
    /// The `routing.ospf.instances` key.
    pub instance: String,
    /// 2 or 3.
    pub version: u8,
    pub router_id: String,
    /// Its address on the link (v3: link-local).
    pub address: String,
    pub interface: String,
    /// Dotted area id of the interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub area: Option<String>,
    /// RFC 2328 §10.1 state: Down, Attempt, Init, 2-Way, ExStart,
    /// Exchange, Loading, Full.
    pub state: String,
    /// The neighbor's role on the link: DR, Backup, DROther, ptp.
    pub role: String,
    pub priority: Option<u32>,
    /// Seconds in the current state (Full: the adjacency's uptime).
    pub state_secs: Option<u64>,
    /// Seconds until the dead timer fires.
    pub dead_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bfd: Option<String>,
    /// LSAs waiting: retransmit, request, DB summary.
    #[serde(default)]
    pub retransmit: u64,
    #[serde(default)]
    pub request: u64,
    #[serde(default)]
    pub summary: u64,
}

/// One OSPF interface as the daemon runs it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OspfIfState {
    pub instance: String,
    pub version: u8,
    pub interface: String,
    pub area: Option<String>,
    /// broadcast, point-to-point, …, as the daemon names it.
    pub network_type: Option<String>,
    /// RFC 2328 §9.1: Down, Loopback, Waiting, Point-To-Point, DROther,
    /// Backup, DR.
    pub state: Option<String>,
    pub address: Option<String>,
    pub cost: Option<u32>,
    pub mtu: Option<u32>,
    pub mtu_mismatch_detection: Option<bool>,
    pub hello: Option<u32>,
    pub dead: Option<u32>,
    pub dr: Option<String>,
    pub bdr: Option<String>,
    pub passive: bool,
    pub neighbors: u32,
    pub adjacent: u32,
}

/// LSA types as numbers (v2: RFC 2328 §A.4.1, RFC 5250; v3: the function
/// code of RFC 5340 §A.4.2.1, with 0x2000 etc. mapped onto the v2 names
/// where they mean the same: 1 router, 2 network, 3 inter-area prefix,
/// 4 inter-area router, 5 external, 7 NSSA, 8 link, 9 intra-area prefix).
pub type LsaKind = u8;

/// One LSA header, compact (24 bytes + the area).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Lsa {
    pub kind: LsaKind,
    /// Area id (u32); `u32::MAX` for AS-scope (externals).
    pub area: u32,
    pub id: u32,
    pub adv: u32,
    pub age: u16,
    pub seq: u32,
    /// Router LSA: [`Lsdb::links`] from `link_start`, `link_count` of them.
    pub link_start: u32,
    pub link_count: u16,
    /// Router LSA bits: 1 ABR, 2 ASBR, 4 virtual-link end. Network LSA:
    /// the mask length. Summary/external: the metric's low 16 bits are in
    /// `metric`.
    pub flags: u8,
    pub metric: u32,
    /// Summary/external/NSSA: prefix length (with `id`, the prefix).
    pub plen: u8,
}

/// RFC 2328 §A.4.2: a router link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    /// 1 point-to-point, 2 transit network, 3 stub network, 4 virtual.
    pub kind: u8,
    pub id: u32,
    pub data: u32,
    pub metric: u16,
}

/// The link-state database of one instance, compact.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Lsdb {
    pub version: u8,
    pub router_id: Option<u32>,
    pub lsas: Vec<Lsa>,
    pub links: Vec<Link>,
    /// Network LSAs: the attached routers (by `Lsa::link_start` too).
    pub attached: Vec<u32>,
    /// LSAs the reader dropped (over the cap, malformed).
    pub dropped: u64,
    /// G3.4f: the Segment Routing database, when SR is on.
    #[serde(default, skip_serializing_if = "crate::ospf_sr::SrDb::is_empty")]
    pub sr: crate::ospf_sr::SrDb,
}

/// One OSPF route as the daemon computed it (`show ip ospf route json`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OspfRoute {
    pub instance: String,
    pub prefix: String,
    /// `intra-area`, `inter-area`, `ext-1`, `ext-2`, `nssa-1`, `nssa-2`.
    pub kind: String,
    pub cost: u32,
    /// External type 2: the external metric (`cost` is to the ASBR).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type2_cost: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub area: Option<String>,
    /// `via` addresses with their interface (`directly attached`: no
    /// address).
    pub nexthops: Vec<(Option<String>, String)>,
    /// G3.4d: what zebra installed for it, with the TI-LFA backups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fast_reroute: Option<RouteFrr>,
}

/// One next hop as zebra installed it: address, interface, labels.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FrrHop {
    pub via: Option<String>,
    pub interface: String,
    pub labels: Vec<u32>,
}

/// A route's primary next hops and its backups (TI-LFA, RFC 9855).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RouteFrr {
    pub primary: Vec<FrrHop>,
    pub backup: Vec<FrrHop>,
}

pub fn ip(v: u32) -> Ipv4Addr {
    Ipv4Addr::from(v)
}
