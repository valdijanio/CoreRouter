//! OSPFv2/OSPFv3 (G3.4), as RouterOS v7 models them: a
//! `/routing ospf instance` per version and VRF, `/routing ospf area`s of
//! an instance, `/routing ospf area range`s that summarize an area, and
//! `/routing ospf interface-template`s that put interfaces in an area —
//! matched by name (or interface list) and by network, first template
//! wins. `neighbor`, `lsa` and routes are state, not config
//! (`crate::ospf_state`).
//!
//! CoreRouter adds key chains (`/routing ospf keychain`): several keys
//! with send and accept windows, so a key is rotated without dropping an
//! adjacency (RFC 5709 §3.3, RFC 7166 §4.2, RFC 8177 for the model).
//! Every key is [`Sealed`]: the config, its history, the journal and MCP
//! carry the box, never the key.
//!
//! `proto-ospf` validates all of it and renders it for FRR (`ospfd`,
//! `ospf6d`).

use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::sealed::Sealed;
use crate::types::ItemId;

/// Most instances, areas, ranges, templates, key chains (an ISP backbone
/// router has tens of areas and a few hundred interfaces, **estimado**).
pub const MAX_INSTANCES: usize = 64;
pub const MAX_AREAS: usize = 1_000;
pub const MAX_RANGES: usize = 10_000;
pub const MAX_TEMPLATES: usize = 4_000;
pub const MAX_KEYCHAINS: usize = 256;
pub const MAX_KEYS: usize = 64;
pub const MAX_NEIGHBORS: usize = 1_000;
/// Most interfaces or networks one template lists.
pub const MAX_MATCHES: usize = 256;

/// The VRF of the main routing table (RouterOS `vrf=main`).
pub const MAIN_VRF: &str = "main";

/// The OSPF version: 2 (IPv4, RFC 2328) or 3 (IPv6, RFC 5340).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
pub enum Version {
    #[default]
    V2,
    V3,
}

impl Version {
    pub fn number(self) -> u8 {
        match self {
            Version::V2 => 2,
            Version::V3 => 3,
        }
    }

    pub fn parse(n: u64) -> Option<Self> {
        match n {
            2 => Some(Version::V2),
            3 => Some(Version::V3),
            _ => None,
        }
    }
}

impl From<Version> for u8 {
    fn from(v: Version) -> u8 {
        v.number()
    }
}

impl TryFrom<u8> for Version {
    type Error = String;
    fn try_from(n: u8) -> Result<Self, String> {
        Version::parse(u64::from(n)).ok_or_else(|| format!("OSPF version {n}: 2 or 3"))
    }
}

/// An OSPF area id: 32 bits, written dotted (`0.0.0.0`) or as a number
/// (`0`), as RFC 2328 §C.2 allows; always shown dotted (FRR prints it back
/// the way it was typed, so the render types it dotted).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct AreaId(pub u32);

impl AreaId {
    pub const BACKBONE: AreaId = AreaId(0);

    pub fn is_backbone(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for AreaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Ipv4Addr::from(self.0))
    }
}

impl FromStr for AreaId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Ok(a) = s.parse::<Ipv4Addr>() {
            return Ok(AreaId(u32::from(a)));
        }
        s.parse::<u32>()
            .map(AreaId)
            .map_err(|_| "an area id: dotted (0.0.0.1) or a number 0..=4294967295".to_owned())
    }
}

impl Serialize for AreaId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for AreaId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Routes an instance redistributes into OSPF as externals (RouterOS
/// `redistribute=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Redistribute {
    Connected,
    Static,
    Bgp,
    /// Routes other programs put in the kernel (the BNG's subscriber
    /// routes, G4.3cd).
    Kernel,
}

impl Redistribute {
    pub const ALL: [Redistribute; 4] = [
        Redistribute::Connected,
        Redistribute::Static,
        Redistribute::Bgp,
        Redistribute::Kernel,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Redistribute::Connected => "connected",
            Redistribute::Static => "static",
            Redistribute::Bgp => "bgp",
            Redistribute::Kernel => "kernel",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.name() == s)
    }
}

/// RouterOS `originate-default`: whether this router announces 0.0.0.0/0
/// (`::/0`) as an external.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OriginateDefault {
    #[default]
    Never,
    /// Only while this router has a default route itself.
    IfInstalled,
    Always,
}

impl OriginateDefault {
    pub fn name(self) -> &'static str {
        match self {
            OriginateDefault::Never => "never",
            OriginateDefault::IfInstalled => "if-installed",
            OriginateDefault::Always => "always",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Self::Never, Self::IfInstalled, Self::Always]
            .into_iter()
            .find(|o| o.name() == s)
    }
}

/// `/routing ospf instance`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OspfInstance {
    pub name: String,
    #[serde(default)]
    pub version: Version,
    /// `main`, or the name of a VRF interface.
    #[serde(default = "main_vrf")]
    pub vrf: String,
    /// `None`: the daemon picks one (the highest loopback address); a
    /// fixed one is safer (RFC 2328 §C.1: it must be unique in the AS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_id: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redistribute: Vec<Redistribute>,
    /// `/routing filter` chain the redistributed routes go through
    /// (RouterOS `out-filter-chain`; G3.2b).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub out_filter_chain: Option<String>,
    #[serde(default)]
    pub originate_default: OriginateDefault,
    /// G4.3ce: announce the PPPoE and IPoE address pools, each summarized
    /// in one external (only while a subscriber of the pool is online).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub subscriber_pools: bool,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

fn main_vrf() -> String {
    MAIN_VRF.to_owned()
}

/// RouterOS `type` of an area.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AreaType {
    /// A normal area: every LSA floods into it.
    #[default]
    Default,
    /// No AS-external LSAs (RFC 2328 §3.6); a default route instead.
    Stub,
    /// Not-so-stubby (RFC 3101): externals of its own as type-7.
    Nssa,
}

impl AreaType {
    pub fn name(self) -> &'static str {
        match self {
            AreaType::Default => "default",
            AreaType::Stub => "stub",
            AreaType::Nssa => "nssa",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Self::Default, Self::Stub, Self::Nssa]
            .into_iter()
            .find(|t| t.name() == s)
    }
}

/// RouterOS `nssa-translate` (RFC 3101 §3.1 `NSSATranslatorRole`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NssaTranslate {
    /// Elected among the area's ABRs (the RFC default).
    #[default]
    Candidate,
    Yes,
    No,
}

impl NssaTranslate {
    pub fn name(self) -> &'static str {
        match self {
            NssaTranslate::Candidate => "candidate",
            NssaTranslate::Yes => "yes",
            NssaTranslate::No => "no",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [Self::Candidate, Self::Yes, Self::No]
            .into_iter()
            .find(|t| t.name() == s)
    }
}

/// `/routing ospf area`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OspfArea {
    pub name: String,
    pub instance: String,
    pub area_id: AreaId,
    #[serde(default, rename = "type")]
    pub kind: AreaType,
    /// Stub/NSSA only: no inter-area summaries either, just the default
    /// (a "totally stubby" area).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_summaries: bool,
    /// Stub/NSSA only: the cost of the default the ABR announces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_cost: Option<u32>,
    #[serde(default, skip_serializing_if = "is_candidate")]
    pub nssa_translate: NssaTranslate,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

fn is_candidate(t: &NssaTranslate) -> bool {
    *t == NssaTranslate::Candidate
}

/// `/routing ospf area range`: on an ABR, the area's networks inside
/// `prefix` are announced to the other areas as one summary (RFC 2328
/// §12.4.3), or not at all.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OspfAreaRange {
    pub id: ItemId,
    pub area: String,
    pub prefix: IpNet,
    #[serde(default = "yes")]
    pub advertise: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<u32>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

fn yes() -> bool {
    true
}

/// RouterOS interface `type`: how OSPF finds and talks to neighbors on the
/// link (RFC 2328 §1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkType {
    /// Multicast hellos, a DR elected.
    #[default]
    Broadcast,
    /// Two routers on the link, no DR (a /30, /31 or PPP link).
    Ptp,
    /// No multicast: neighbors listed by hand, a DR elected.
    Nbma,
    /// One subnet, many routers, no DR.
    Ptmp,
    /// A backbone link through a transit area (v2 only; RFC 2328 §15).
    VirtualLink,
}

impl NetworkType {
    pub const ALL: [NetworkType; 5] = [
        NetworkType::Broadcast,
        NetworkType::Ptp,
        NetworkType::Nbma,
        NetworkType::Ptmp,
        NetworkType::VirtualLink,
    ];

    pub fn name(self) -> &'static str {
        match self {
            NetworkType::Broadcast => "broadcast",
            NetworkType::Ptp => "ptp",
            NetworkType::Nbma => "nbma",
            NetworkType::Ptmp => "ptmp",
            NetworkType::VirtualLink => "virtual-link",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "point-to-point" => Some(NetworkType::Ptp),
            "point-to-multipoint" => Some(NetworkType::Ptmp),
            "non-broadcast" => Some(NetworkType::Nbma),
            _ => Self::ALL.into_iter().find(|t| t.name() == s),
        }
    }
}

/// RouterOS `auth`: how OSPF packets are authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthType {
    /// The key in clear in every packet (RFC 2328 §D.3): no protection.
    Simple,
    /// Keyed MD5 (RFC 2328 §D.3): broken, kept for old neighbors.
    Md5,
    /// HMAC-SHA (RFC 5709 for v2, RFC 7166 for v3).
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl AuthType {
    pub const ALL: [AuthType; 6] = [
        AuthType::Simple,
        AuthType::Md5,
        AuthType::Sha1,
        AuthType::Sha256,
        AuthType::Sha384,
        AuthType::Sha512,
    ];
    /// What a key or template gets when the operator gives a key and no
    /// algorithm.
    pub const DEFAULT: AuthType = AuthType::Sha256;

    pub fn name(self) -> &'static str {
        match self {
            AuthType::Simple => "simple",
            AuthType::Md5 => "md5",
            AuthType::Sha1 => "sha1",
            AuthType::Sha256 => "sha256",
            AuthType::Sha384 => "sha384",
            AuthType::Sha512 => "sha512",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.name() == s)
    }

    /// Simple and MD5: an eavesdropper or a precomputed table breaks them.
    pub fn is_weak(self) -> bool {
        matches!(self, AuthType::Simple | AuthType::Md5)
    }

    /// A keyed hash (everything but `simple`).
    pub fn is_crypto(self) -> bool {
        self != AuthType::Simple
    }

    /// FRR's `cryptographic-algorithm` (lib/keychain).
    pub fn frr_algorithm(self) -> &'static str {
        match self {
            AuthType::Simple => "cleartext",
            AuthType::Md5 => "md5",
            AuthType::Sha1 => "hmac-sha-1",
            AuthType::Sha256 => "hmac-sha-256",
            AuthType::Sha384 => "hmac-sha-384",
            AuthType::Sha512 => "hmac-sha-512",
        }
    }
}

/// `/routing ospf interface-template`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OspfTemplate {
    pub id: ItemId,
    pub area: String,
    /// Interface names or interface lists.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
    /// An interface with an address inside one of these matches (IPv4
    /// networks for v2, IPv6 for v3).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub networks: Vec<IpNet>,
    #[serde(rename = "type")]
    pub kind: NetworkType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hello_interval: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dead_interval: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retransmit_interval: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transmit_delay: Option<u16>,
    /// Announce the interface's networks, but send no hello on it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub passive: bool,
    /// Accept a DD packet with a different MTU (RFC 2328 §10.6 drops it).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub mtu_ignore: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthType>,
    /// Key id of `auth_key` (0..=255 for v2, RFC 2328 §D.3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_id: Option<u16>,
    /// One key, sealed (RouterOS `auth-key`).
    #[serde(skip_serializing_if = "Sealed::is_empty")]
    pub auth_key: Sealed,
    /// Or a key chain: several keys, rotated by their windows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keychain: Option<String>,
    /// BFD profile watching the adjacencies (G3.6 owns the profiles).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bfd: Option<String>,
    /// v3: the instance id of the link (RFC 5340 §2.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<u8>,
    /// `virtual-link`: the router id at the far end and the transit area.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlink_neighbor_id: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlink_transit_area: Option<String>,
    pub disabled: bool,
    pub comment: String,
}

impl OspfTemplate {
    pub fn has_key(&self) -> bool {
        !self.auth_key.is_empty()
    }
}

/// `/routing ospf static-neighbor`: a neighbor on an NBMA link (no
/// multicast to find it; RFC 2328 §9.5.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OspfStaticNeighbor {
    pub id: ItemId,
    pub instance: String,
    pub address: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub poll_interval: Option<u16>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

/// One key of a key chain. A window `None` is open at that end.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OspfKey {
    /// Key id on the wire (8 bits for v2, 16 for v3).
    pub id: u16,
    pub algorithm: AuthType,
    pub key_string: Sealed,
    /// Unix seconds: sent from/until, accepted from/until.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_from: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_until: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_from: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_until: Option<u64>,
}

impl OspfKey {
    pub fn sends_at(&self, t: u64) -> bool {
        self.send_from.is_none_or(|f| f <= t) && self.send_until.is_none_or(|u| t < u)
    }

    pub fn accepts_at(&self, t: u64) -> bool {
        self.accept_from.is_none_or(|f| f <= t) && self.accept_until.is_none_or(|u| t < u)
    }
}

/// `/routing ospf keychain`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OspfKeychain {
    pub name: String,
    #[serde(default)]
    pub keys: Vec<OspfKey>,
    #[serde(default)]
    pub comment: String,
}

/// Everything OSPF in `routing`.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ospf {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub instances: BTreeMap<String, OspfInstance>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub areas: BTreeMap<String, OspfArea>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ranges: Vec<OspfAreaRange>,
    /// In order: the first template that matches an interface wins.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub templates: Vec<OspfTemplate>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub static_neighbors: Vec<OspfStaticNeighbor>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub keychains: BTreeMap<String, OspfKeychain>,
    pub next_id: u32,
}

impl Ospf {
    pub fn is_empty(&self) -> bool {
        *self == Ospf::default()
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    /// The instance area `area` belongs to.
    pub fn instance_of_area(&self, area: &str) -> Option<&OspfInstance> {
        self.areas
            .get(area)
            .and_then(|a| self.instances.get(&a.instance))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn area_ids_read_both_ways_and_print_dotted() {
        assert_eq!("0".parse::<AreaId>().unwrap(), AreaId::BACKBONE);
        assert_eq!("0.0.0.1".parse::<AreaId>().unwrap(), AreaId(1));
        assert_eq!("258".parse::<AreaId>().unwrap().to_string(), "0.0.1.2");
        assert!("x".parse::<AreaId>().is_err());
        let j = serde_json::to_string(&AreaId(1)).unwrap();
        assert_eq!(j, "\"0.0.0.1\"");
        assert_eq!(serde_json::from_str::<AreaId>(&j).unwrap(), AreaId(1));
    }

    #[test]
    fn key_windows() {
        let k = OspfKey {
            id: 1,
            algorithm: AuthType::Sha256,
            key_string: Sealed::default(),
            send_from: Some(100),
            send_until: Some(200),
            accept_from: None,
            accept_until: Some(300),
        };
        assert!(!k.sends_at(99));
        assert!(k.sends_at(100));
        assert!(!k.sends_at(200));
        assert!(k.accepts_at(0));
        assert!(!k.accepts_at(300));
    }

    #[test]
    fn empty_ospf_is_not_serialized_and_round_trips() {
        let o = Ospf::default();
        assert!(o.is_empty());
        let mut o = Ospf::default();
        o.instances.insert(
            "v2".into(),
            OspfInstance {
                name: "v2".into(),
                version: Version::V2,
                vrf: MAIN_VRF.into(),
                router_id: Some([10, 0, 0, 1].into()),
                redistribute: vec![Redistribute::Connected],
                out_filter_chain: None,
                originate_default: OriginateDefault::Never,
                subscriber_pools: false,
                disabled: false,
                comment: String::new(),
            },
        );
        let j = serde_json::to_string(&o).unwrap();
        assert!(j.contains("\"version\":2"), "{j}");
        assert_eq!(serde_json::from_str::<Ospf>(&j).unwrap(), o);
    }
}
