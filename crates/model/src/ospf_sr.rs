//! Segment Routing over OSPFv2 (G3.4f; RFC 8402 architecture, RFC 8660
//! the MPLS data plane, RFC 8665 the OSPFv2 extensions).
//!
//! RouterOS has no Segment Routing; the names follow Cisco IOS-XR and FRR
//! (`segment-routing global-block`, `prefix-sid index`). FRR's `ospfd`
//! runs one SR database per process, in the default VRF only, for every
//! area of the instance: so SR is switched on per OSPFv2 instance (the one
//! in VRF `main`), not per area.
//!
//! - [`SegmentRouting`]: the switch, the SRGB (the labels every router
//!   reserves for the prefix SIDs, RFC 8402 §2) and the SRLB (its local
//!   labels, the adjacency SIDs).
//! - [`PrefixSid`]: a SID index for one of the router's own /32 loopback
//!   addresses (RFC 8665 §5): every router forwards to that prefix with the
//!   label `its SRGB start + index`.
//! - [`SrDb`]: what `ospfd` learned from the network (state, not config).

use std::fmt;
use std::str::FromStr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::types::ItemId;

/// FRR's and Cisco's default SRGB (`DEFAULT_SRGB_LABEL`, size 8000).
pub const DEFAULT_SRGB: LabelBlock = LabelBlock {
    start: 16_000,
    end: 23_999,
};
/// FRR's default SRLB (`DEFAULT_SRLB_LABEL`, size 1000).
pub const DEFAULT_SRLB: LabelBlock = LabelBlock {
    start: 15_000,
    end: 15_999,
};
/// The smallest block FRR takes (`MIN_SRGB_SIZE`, `MIN_SRLB_SIZE`).
pub const MIN_BLOCK: u32 = 16;
/// FRR's prefix SID index is 16 bits (`index (0-65535)`).
pub const MAX_INDEX: u32 = 65_535;
/// Most prefix SIDs one router originates (one per loopback; a router has
/// a handful, **estimado**).
pub const MAX_PREFIX_SIDS: usize = 1_000;
/// FRR's `segment-routing node-msd (1-16)`.
pub const MAX_MSD: u8 = 16;

/// A range of MPLS labels, both ends included; written `16000-23999`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LabelBlock {
    pub start: u32,
    pub end: u32,
}

impl LabelBlock {
    /// How many labels (0 for a reversed block).
    pub fn size(self) -> u32 {
        if self.end < self.start {
            0
        } else {
            self.end - self.start + 1
        }
    }

    pub fn contains(self, label: u32) -> bool {
        (self.start..=self.end).contains(&label)
    }

    pub fn overlaps(self, other: LabelBlock) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// The label of SID `index` (RFC 8402 §2: SRGB start + index), `None`
    /// when the index falls outside the block.
    pub fn label(self, index: u32) -> Option<u32> {
        (index < self.size()).then(|| self.start + index)
    }
}

impl fmt::Display for LabelBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

impl FromStr for LabelBlock {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || "a label block: start-end (16000-23999)".to_owned();
        let (a, b) = s.trim().split_once('-').ok_or_else(bad)?;
        let start = a.trim().parse().map_err(|_| bad())?;
        let end = b.trim().parse().map_err(|_| bad())?;
        Ok(LabelBlock { start, end })
    }
}

impl Serialize for LabelBlock {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for LabelBlock {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

fn default_srgb() -> LabelBlock {
    DEFAULT_SRGB
}

fn default_srlb() -> LabelBlock {
    DEFAULT_SRLB
}

fn is_default_srgb(b: &LabelBlock) -> bool {
    *b == DEFAULT_SRGB
}

fn is_default_srlb(b: &LabelBlock) -> bool {
    *b == DEFAULT_SRLB
}

/// `/routing ospf segment-routing` (ours): SR on an OSPFv2 instance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentRouting {
    /// The OSPFv2 instance (in VRF `main`: FRR runs SR there only).
    pub instance: String,
    #[serde(default = "default_srgb", skip_serializing_if = "is_default_srgb")]
    pub srgb: LabelBlock,
    #[serde(default = "default_srlb", skip_serializing_if = "is_default_srlb")]
    pub srlb: LabelBlock,
    /// The deepest label stack this router pushes (RFC 8476 node MSD);
    /// `None`: not announced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_msd: Option<u8>,
    /// G3.4d: Topology Independent LFA (RFC 9855), FRR's `fast-reroute
    /// ti-lfa [node-protection]` for the whole instance.
    #[serde(default, skip_serializing_if = "TiLfa::is_off")]
    pub ti_lfa: TiLfa,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

/// TI-LFA protection (RFC 9855 §2): of the link to the next hop, or of the
/// next-hop router itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TiLfa {
    #[default]
    Off,
    Link,
    Node,
}

impl TiLfa {
    pub const ALL: [TiLfa; 3] = [TiLfa::Off, TiLfa::Link, TiLfa::Node];

    pub fn name(self) -> &'static str {
        match self {
            TiLfa::Off => "off",
            TiLfa::Link => "link",
            TiLfa::Node => "node",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.name() == s)
    }

    pub fn is_off(&self) -> bool {
        *self == TiLfa::Off
    }
}

impl SegmentRouting {
    pub fn new(instance: impl Into<String>) -> Self {
        SegmentRouting {
            instance: instance.into(),
            srgb: DEFAULT_SRGB,
            srlb: DEFAULT_SRLB,
            node_msd: None,
            ti_lfa: TiLfa::Off,
            disabled: false,
            comment: String::new(),
        }
    }
}

/// What the router before the last asks of the label of a prefix SID
/// (RFC 8665 §5: the NP and E flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SidBehavior {
    /// Penultimate hop popping: the label comes off one hop early (the
    /// default, and what LDP does).
    #[default]
    Php,
    /// The label arrives here (NP set): the last hop sees it, e.g. for
    /// per-SID counters.
    NoPhp,
    /// The label is swapped for explicit null (NP and E set, RFC 3032
    /// §2.1): the traffic class survives to the last hop.
    ExplicitNull,
}

impl SidBehavior {
    pub const ALL: [SidBehavior; 3] = [
        SidBehavior::Php,
        SidBehavior::NoPhp,
        SidBehavior::ExplicitNull,
    ];

    pub fn name(self) -> &'static str {
        match self {
            SidBehavior::Php => "php",
            SidBehavior::NoPhp => "no-php",
            SidBehavior::ExplicitNull => "explicit-null",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|b| b.name() == s)
    }
}

fn is_php(b: &SidBehavior) -> bool {
    *b == SidBehavior::Php
}

/// `/routing ospf prefix-sid`: the SID of one of this router's /32s.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixSid {
    pub id: ItemId,
    /// A /32 on a loopback interface (FRR refuses any other).
    pub prefix: Ipv4Net,
    /// Index in the SRGB: the label is SRGB start + index on every router.
    pub index: u32,
    #[serde(default, skip_serializing_if = "is_php")]
    pub behavior: SidBehavior,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

/// The SR config FRR runs: present, not disabled, on an enabled OSPFv2
/// instance in VRF `main`.
pub fn active(ospf: &crate::ospf::Ospf) -> Option<&SegmentRouting> {
    let sr = ospf.segment_routing.as_ref().filter(|s| !s.disabled)?;
    let inst = ospf.instances.get(&sr.instance)?;
    (!inst.disabled
        && inst.version == crate::ospf::Version::V2
        && inst.vrf == crate::ospf::MAIN_VRF)
        .then_some(sr)
}

/// The label blocks SR reserves while it runs (SRGB, SRLB): LDP and the
/// static LSPs keep out of them.
pub fn reserved(ospf: &crate::ospf::Ospf) -> Vec<LabelBlock> {
    active(ospf).map_or_else(Vec::new, |s| vec![s.srgb, s.srlb])
}

// ---- state: what ospfd learned (`show ip ospf database segment-routing`) ----

/// One prefix SID as `ospfd` has it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SrPrefix {
    /// The prefix, as u32 and length.
    pub prefix: u32,
    pub plen: u8,
    pub sid: u32,
    /// The label this router takes in for it (0: none installed).
    pub in_label: u32,
    /// Where it goes: out label, interface, next hop.
    pub out: Vec<SrHop>,
}

/// One way out of a SID.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SrHop {
    pub label: u32,
    pub interface: String,
    pub nexthop: u32,
}

/// One SR router of the area (`srNodes[]`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SrNode {
    pub router_id: u32,
    pub srgb_start: u32,
    pub srgb_size: u32,
    pub srlb_start: u32,
    pub srlb_size: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msd: Option<u8>,
    pub prefixes: Vec<SrPrefix>,
    /// Adjacency SIDs it announced (they live in its SRLB).
    pub adjacencies: u32,
}

/// The SR database of one instance.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SrDb {
    /// This router (`srdbID`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_id: Option<u32>,
    pub nodes: Vec<SrNode>,
}

impl SrDb {
    pub fn is_empty(&self) -> bool {
        self.router_id.is_none() && self.nodes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_read_print_and_compare() {
        let b: LabelBlock = "16000-23999".parse().unwrap();
        assert_eq!(b, DEFAULT_SRGB);
        assert_eq!(b.size(), 8000);
        assert_eq!(b.to_string(), "16000-23999");
        assert!(b.overlaps(LabelBlock { start: 23_999, end: 30_000 }));
        assert!(!b.overlaps(DEFAULT_SRLB));
        assert_eq!(b.label(0), Some(16_000));
        assert_eq!(b.label(7999), Some(23_999));
        assert_eq!(b.label(8000), None);
        assert!("x".parse::<LabelBlock>().is_err());
        assert_eq!(LabelBlock { start: 5, end: 4 }.size(), 0);
    }

    #[test]
    fn defaults_are_left_out_of_the_json() {
        let sr = SegmentRouting::new("v2");
        let j = serde_json::to_string(&sr).unwrap();
        assert_eq!(j, r#"{"instance":"v2","disabled":false,"comment":""}"#);
        assert_eq!(serde_json::from_str::<SegmentRouting>(&j).unwrap(), sr);
    }
}
