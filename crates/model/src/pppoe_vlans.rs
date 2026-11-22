//! Stacked VLANs (QinQ) on a PPPoE server (G4.3l): the access network tags
//! each subscriber line with an S-tag (per OLT, PON or DSLAM) and a C-tag
//! (per line, the TR-101 1:1 model), and the BNG terminates PPPoE inside
//! both, without a kernel VLAN interface per subscriber.
//!
//! RouterOS' `pppoe-over-vlan-range` is one tag (`vlan_mode=single`, the
//! default); `vlan_mode=stacked` is Junos' `stacked-vlan-ranges`: an outer
//! range (S-tag, TPID 0x88a8 or 0x8100) and an inner range (C-tag, 802.1Q,
//! `any` by default).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ppp::VlanRange;
use crate::types::ParseError;

/// How the server's VLANs are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VlanMode {
    /// One 802.1Q tag (`pppoe_over_vlan_range`), RouterOS.
    #[default]
    Single,
    /// Two tags: `outer_vlan_range` and `inner_vlan_range`.
    Stacked,
}

impl VlanMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Stacked => "stacked",
        }
    }

    pub fn parse(t: &str) -> Option<Self> {
        match t.trim() {
            "single" => Some(Self::Single),
            "stacked" | "qinq" => Some(Self::Stacked),
            _ => None,
        }
    }

    pub fn is_default(&self) -> bool {
        *self == Self::Single
    }
}

/// The outer tag's TPID in stacked mode: 802.1ad (0x88a8, the standard
/// S-tag) or 802.1Q (0x8100, "Q-in-Q" on older access gear).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Tpid {
    #[default]
    Dot1ad,
    Dot1q,
}

impl Tpid {
    pub fn value(self) -> u16 {
        match self {
            Self::Dot1ad => 0x88a8,
            Self::Dot1q => 0x8100,
        }
    }

    pub fn is_default(&self) -> bool {
        *self == Self::Dot1ad
    }
}

impl FromStr for Tpid {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "0x88a8" | "88a8" | "802.1ad" => Ok(Self::Dot1ad),
            "0x8100" | "8100" | "802.1q" => Ok(Self::Dot1q),
            _ => Err(ParseError::new("TPID", s, "0x88a8 (802.1ad) or 0x8100")),
        }
    }
}

impl fmt::Display for Tpid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#06x}", self.value())
    }
}

impl Serialize for Tpid {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Tpid {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
    }
}

/// Outer VLAN ids a server may listen on without the XDP data plane (one
/// socket each: `hal-linux::pppoe_io::MAX_VLAN_IDS`).
pub const MAX_OUTER_VLANS: usize = 512;

/// RFC 4638: largest PPP-Max-Payload a server may accept (1500 = a
/// baby-jumbo access network of 1508 bytes carries a full 1500 MTU).
pub const MAX_PAYLOAD: u16 = 1500;

/// VLAN ids in `ranges`.
pub fn count(ranges: &[VlanRange]) -> usize {
    ranges
        .iter()
        .map(|r| usize::from(r.last.saturating_sub(r.first)) + 1)
        .sum()
}

/// `inner` allows VLAN `vid` (empty = any).
pub fn allows(ranges: &[VlanRange], vid: u16) -> bool {
    ranges.is_empty() || ranges.iter().any(|r| (r.first..=r.last).contains(&vid))
}

/// Overlapping ranges, as `100-120 and 110-130`.
pub fn overlap(ranges: &[VlanRange]) -> Option<String> {
    let mut r: Vec<VlanRange> = ranges.to_vec();
    r.sort();
    r.windows(2)
        .find(|w| matches!(w, [a, b] if b.first <= a.last))
        .and_then(|w| match w {
            [a, b] => Some(format!("{a} and {b}")),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpid_and_mode_text() {
        assert_eq!("0x8100".parse::<Tpid>().unwrap(), Tpid::Dot1q);
        assert_eq!("802.1ad".parse::<Tpid>().unwrap().value(), 0x88a8);
        assert!("0x9100".parse::<Tpid>().is_err());
        assert_eq!(Tpid::Dot1ad.to_string(), "0x88a8");
        assert_eq!(serde_json::to_string(&Tpid::Dot1q).unwrap(), "\"0x8100\"");
        assert_eq!(VlanMode::parse("qinq"), Some(VlanMode::Stacked));
    }

    #[test]
    fn ranges() {
        let r: Vec<VlanRange> = ["100-199", "300"].iter().map(|t| t.parse().unwrap()).collect();
        assert_eq!(count(&r), 101);
        assert!(allows(&r, 300) && !allows(&r, 200) && allows(&[], 7));
        let o: Vec<VlanRange> = ["100-120", "110-130"].iter().map(|t| t.parse().unwrap()).collect();
        assert_eq!(overlap(&o).as_deref(), Some("100-120 and 110-130"));
        assert_eq!(overlap(&r), None);
    }
}
