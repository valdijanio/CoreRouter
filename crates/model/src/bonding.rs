//! `/interface bonding` (G1.8): link aggregation. A bond is an interface
//! (`InterfaceKind::Bonding`, the Linux `bond` device); its slaves name it
//! in `Interface::bond`, the same way bridge ports name their bridge, so a
//! port can never be a slave of two bonds. Names and values follow RouterOS
//! v7 (`mode=802.3ad`, `transmit-hash-policy=layer-3-and-4`, `lacp-rate`).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::types::ParseError;

/// Bonding mode (RouterOS `mode`, Linux `mode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BondMode {
    #[serde(rename = "balance-rr")]
    BalanceRr,
    #[serde(rename = "active-backup")]
    ActiveBackup,
    #[serde(rename = "balance-xor")]
    BalanceXor,
    #[serde(rename = "broadcast")]
    Broadcast,
    /// IEEE 802.1AX (formerly 802.3ad) with LACP.
    #[serde(rename = "802.3ad")]
    Lacp,
    #[serde(rename = "balance-tlb")]
    BalanceTlb,
    #[serde(rename = "balance-alb")]
    BalanceAlb,
}

impl BondMode {
    pub const ALL: [Self; 7] = [
        Self::Lacp,
        Self::ActiveBackup,
        Self::BalanceRr,
        Self::BalanceXor,
        Self::Broadcast,
        Self::BalanceTlb,
        Self::BalanceAlb,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::BalanceRr => "balance-rr",
            Self::ActiveBackup => "active-backup",
            Self::BalanceXor => "balance-xor",
            Self::Broadcast => "broadcast",
            Self::Lacp => "802.3ad",
            Self::BalanceTlb => "balance-tlb",
            Self::BalanceAlb => "balance-alb",
        }
    }

    /// Modes where `primary` means something (kernel bonding.rst: only
    /// active-backup, balance-tlb and balance-alb).
    pub fn has_primary(self) -> bool {
        matches!(
            self,
            Self::ActiveBackup | Self::BalanceTlb | Self::BalanceAlb
        )
    }

    /// Modes that hash flows over the slaves (`xmit_hash_policy`).
    pub fn hashes(self) -> bool {
        matches!(self, Self::Lacp | Self::BalanceXor | Self::BalanceTlb)
    }
}

impl fmt::Display for BondMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for BondMode {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        // `lacp` and `802.1ax` are what an operator coming from Junos/IEEE types.
        if s.eq_ignore_ascii_case("lacp") || s.eq_ignore_ascii_case("802.1ax") {
            return Ok(Self::Lacp);
        }
        Self::ALL
            .into_iter()
            .find(|m| m.label().eq_ignore_ascii_case(s))
            .ok_or_else(|| {
                ParseError::new(
                    "bonding mode",
                    s,
                    "use 802.3ad | active-backup | balance-rr | balance-xor | broadcast | balance-tlb | balance-alb",
                )
            })
    }
}

/// Which headers pick the slave of a flow (RouterOS `transmit-hash-policy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum HashPolicy {
    #[default]
    #[serde(rename = "layer-2")]
    Layer2,
    #[serde(rename = "layer-2-and-3")]
    Layer23,
    #[serde(rename = "layer-3-and-4")]
    Layer34,
    #[serde(rename = "encap-2-and-3")]
    Encap23,
    #[serde(rename = "encap-3-and-4")]
    Encap34,
}

impl HashPolicy {
    pub const ALL: [Self; 5] = [
        Self::Layer2,
        Self::Layer23,
        Self::Layer34,
        Self::Encap23,
        Self::Encap34,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Layer2 => "layer-2",
            Self::Layer23 => "layer-2-and-3",
            Self::Layer34 => "layer-3-and-4",
            Self::Encap23 => "encap-2-and-3",
            Self::Encap34 => "encap-3-and-4",
        }
    }
}

impl FromStr for HashPolicy {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|m| m.label().eq_ignore_ascii_case(s.trim()))
            .ok_or_else(|| {
                ParseError::new(
                    "transmit hash policy",
                    s,
                    "use layer-2 | layer-2-and-3 | layer-3-and-4 | encap-2-and-3 | encap-3-and-4",
                )
            })
    }
}

/// How often LACPDUs are asked from the partner (RouterOS `lacp-rate`).
/// IEEE 802.1AX: fast = 1 s periodic (3 s timeout), slow = 30 s (90 s).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum LacpRate {
    #[default]
    #[serde(rename = "30secs")]
    Slow,
    #[serde(rename = "1sec")]
    Fast,
}

impl LacpRate {
    pub fn label(self) -> &'static str {
        match self {
            Self::Slow => "30secs",
            Self::Fast => "1sec",
        }
    }
}

impl FromStr for LacpRate {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "30secs" | "slow" => Ok(Self::Slow),
            "1sec" | "fast" => Ok(Self::Fast),
            _ => Err(ParseError::new("LACP rate", s, "use 30secs | 1sec")),
        }
    }
}

/// RouterOS `mii-interval` default (and the kernel's recommended `miimon`).
pub const DEFAULT_MII_INTERVAL_MS: u32 = 100;

pub(crate) fn default_mii_interval() -> u32 {
    DEFAULT_MII_INTERVAL_MS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_round_trip() {
        for m in BondMode::ALL {
            assert_eq!(m.label().parse::<BondMode>().unwrap(), m);
            let json = serde_json::to_string(&m).unwrap();
            assert_eq!(json, format!("\"{}\"", m.label()));
        }
        for h in HashPolicy::ALL {
            assert_eq!(h.label().parse::<HashPolicy>().unwrap(), h);
        }
        assert_eq!("lacp".parse::<BondMode>().unwrap(), BondMode::Lacp);
        assert_eq!("fast".parse::<LacpRate>().unwrap(), LacpRate::Fast);
        assert!("802.3".parse::<BondMode>().is_err());
    }
}
