//! `/routing rule` (G1.27e): policy routing rules in the RouterOS v7 model.
//! They run top to bottom; the first that decides wins. Which kernel rules
//! they become is `corerouter_hal::policy`.

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::firewall::Name;
use crate::types::{IfName, ItemId, RoutingTable};

/// Hostile-input bound. The kernel walks its rules one by one per packet, so
/// this also bounds the cost per packet (`docs/policy-routing.md`).
pub const MAX_RULES: usize = 4096;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleAction {
    /// Look in `table`; no route there: the next rule goes on.
    #[default]
    Lookup,
    /// Look in `table` only; no route there: unreachable.
    LookupOnlyInTable,
    /// Silently discarded.
    Drop,
    /// Discarded with an ICMP unreachable.
    Unreachable,
}

impl RuleAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lookup => "lookup",
            Self::LookupOnlyInTable => "lookup-only-in-table",
            Self::Drop => "drop",
            Self::Unreachable => "unreachable",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        [
            Self::Lookup,
            Self::LookupOnlyInTable,
            Self::Drop,
            Self::Unreachable,
        ]
        .into_iter()
        .find(|a| a.as_str() == s)
    }

    /// It looks in a table (`table` means something).
    pub fn looks_up(self) -> bool {
        matches!(self, Self::Lookup | Self::LookupOnlyInTable)
    }

    /// A packet that matches never reaches the next rules.
    pub fn is_final(self) -> bool {
        !matches!(self, Self::Lookup)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingRule {
    pub id: ItemId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_address: Option<IpNet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_address: Option<IpNet>,
    /// Incoming interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<IfName>,
    /// Routing mark the firewall's mangle set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_mark: Option<Name>,
    #[serde(default)]
    pub action: RuleAction,
    #[serde(default)]
    pub table: RoutingTable,
    /// Routes of this prefix length or shorter are ignored (Linux's
    /// `suppress_prefixlength`; 0 hides the default route).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_prefix: Option<u8>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl RoutingRule {
    /// `Some(true)`: IPv6 only; `Some(false)`: IPv4 only; `None`: both (no
    /// address to tell).
    pub fn is_v6(&self) -> Option<bool> {
        self.src_address
            .or(self.dst_address)
            .map(|a| a.addr().is_ipv6())
    }

    /// Every packet this one matches, `earlier` matches too: `earlier`
    /// hides it when its action is final.
    pub fn covered_by(&self, earlier: &Self) -> bool {
        let net = |theirs: Option<IpNet>, mine: Option<IpNet>| match (theirs, mine) {
            (None, _) => true,
            (Some(t), Some(m)) => t.contains(&m.addr()) && t.prefix_len() <= m.prefix_len(),
            (Some(_), None) => false,
        };
        net(earlier.src_address, self.src_address)
            && net(earlier.dst_address, self.dst_address)
            && (earlier.interface.is_none() || earlier.interface == self.interface)
            && (earlier.routing_mark.is_none() || earlier.routing_mark == self.routing_mark)
            && (earlier.is_v6().is_none() || earlier.is_v6() == self.is_v6())
    }

    /// `ip` is of this rule's family.
    pub fn same_family(&self, ip: IpAddr) -> bool {
        self.is_v6().is_none_or(|v6| v6 == ip.is_ipv6())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(src: Option<&str>, dst: Option<&str>, i: Option<&str>) -> RoutingRule {
        RoutingRule {
            id: ItemId(1),
            src_address: src.map(|s| s.parse().unwrap()),
            dst_address: dst.map(|s| s.parse().unwrap()),
            interface: i.map(|s| s.parse().unwrap()),
            routing_mark: None,
            action: RuleAction::Drop,
            table: RoutingTable::Main,
            min_prefix: None,
            disabled: false,
            comment: String::new(),
        }
    }

    #[test]
    fn covered_by_compares_each_match() {
        let wide = r(Some("10.0.0.0/8"), None, None);
        assert!(r(Some("10.1.0.0/16"), None, None).covered_by(&wide));
        assert!(r(Some("10.1.0.0/16"), Some("1.1.1.1/32"), Some("ether1")).covered_by(&wide));
        assert!(!r(Some("11.0.0.0/8"), None, None).covered_by(&wide));
        assert!(!r(None, Some("1.1.1.1/32"), None).covered_by(&wide));
        assert!(!wide.covered_by(&r(Some("10.1.0.0/16"), None, None)));
        assert!(!r(None, None, None).covered_by(&r(None, None, Some("ether1"))));
        // A rule of one family does not hide one of both.
        assert!(!r(None, None, None).covered_by(&r(Some("0.0.0.0/0"), None, None)));
        assert!(r(Some("10.0.0.1/32"), None, None).covered_by(&r(None, None, None)));
    }

    #[test]
    fn family_comes_from_the_addresses() {
        assert_eq!(r(None, None, None).is_v6(), None);
        assert_eq!(r(Some("10.0.0.0/8"), None, None).is_v6(), Some(false));
        assert_eq!(r(None, Some("2001:db8::/32"), None).is_v6(), Some(true));
    }

    #[test]
    fn actions_read_back() {
        for a in ["lookup", "lookup-only-in-table", "drop", "unreachable"] {
            assert_eq!(RuleAction::parse(a).unwrap().as_str(), a);
        }
        assert_eq!(RuleAction::parse("x"), None);
        let json = serde_json::to_string(&RuleAction::LookupOnlyInTable).unwrap();
        assert_eq!(json, "\"lookup-only-in-table\"");
    }
}
