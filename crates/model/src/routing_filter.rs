//! `/routing filter` (G3.2b): the route policy of RouterOS v7. A rule is a
//! line of the filter language (`if (dst in 10.0.0.0/8) { reject }`) in a
//! named chain; a BGP connection names the chain its received routes go
//! through (`input_filter`) and the one its sent routes go through
//! (`output_filter`). Rules run in list order, chain by chain; a route no
//! rule accepts is rejected (RouterOS: the default action is reject).
//!
//! The rule text is kept as the operator wrote it (as RouterOS does);
//! `proto-bgp::filter` parses it, evaluates it and renders it for FRR.
//! Named prefix and community lists sit next to the rules.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::types::ItemId;

/// Most rules (a large IXP policy is a few thousand lines, **estimado**).
pub const MAX_RULES: usize = 20_000;
/// Longest rule text.
pub const MAX_RULE_LEN: usize = 4096;
/// Most named lists of each kind.
pub const MAX_LISTS: usize = 2_000;
/// Most entries of one prefix list (an IRR-generated customer list of a
/// big transit is ~100 000, **estimado**).
pub const MAX_PREFIX_ENTRIES: usize = 200_000;
/// Most communities of one community list.
pub const MAX_COMMUNITIES: usize = 1_000;

/// One `/routing filter rule`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterRule {
    pub id: ItemId,
    pub chain: String,
    /// The rule in the filter language.
    pub rule: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One entry of a prefix list, in the prefix-list form operators know
/// from FRR and Cisco: `10.0.0.0/8` (exactly that prefix), `10.0.0.0/8 le
/// 24` (it and its more specifics up to /24), `0.0.0.0/0 ge 25` (anything
/// /25 or longer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrefixEntry {
    pub prefix: IpNet,
    pub ge: Option<u8>,
    pub le: Option<u8>,
}

impl PrefixEntry {
    /// The lengths it matches, inclusive.
    pub fn lengths(&self) -> (u8, u8) {
        let plen = self.prefix.prefix_len();
        let max = self.prefix.max_prefix_len();
        match (self.ge, self.le) {
            (None, None) => (plen, plen),
            (Some(g), None) => (g, max),
            (None, Some(l)) => (plen, l),
            (Some(g), Some(l)) => (g, l),
        }
    }

    /// Whether `net` falls in it.
    pub fn matches(&self, net: &IpNet) -> bool {
        let (lo, hi) = self.lengths();
        let len = net.prefix_len();
        len >= lo && len <= hi && self.prefix.contains(net)
    }
}

impl FromStr for PrefixEntry {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let mut words = s.split_whitespace();
        let raw = words.next().ok_or("an empty prefix")?;
        let prefix: IpNet = raw
            .parse()
            .map_err(|_| format!("{:?} is not a prefix (10.0.0.0/8, 2001:db8::/32)", cut(raw)))?;
        if prefix.trunc() != prefix {
            return Err(format!("{prefix} has host bits set (did you mean {}?)", prefix.trunc()));
        }
        let mut entry = PrefixEntry { prefix, ge: None, le: None };
        while let Some(k) = words.next() {
            let v = words
                .next()
                .ok_or_else(|| format!("{k} needs a length"))?
                .parse::<u8>()
                .map_err(|_| format!("{k} needs a length 0..=128"))?;
            match k {
                "ge" if entry.ge.is_none() => entry.ge = Some(v),
                "le" if entry.le.is_none() => entry.le = Some(v),
                _ => return Err(format!("{:?}: expected ge N or le N", cut(k))),
            }
        }
        let plen = prefix.prefix_len();
        let max = prefix.max_prefix_len();
        let (lo, hi) = entry.lengths();
        // FRR's rule (and Cisco's): len < ge <= le <= max.
        if entry.ge.is_some_and(|g| g <= plen) || entry.le.is_some_and(|l| l <= plen) || lo > hi || hi > max {
            return Err(format!("{s:?}: the lengths must satisfy {plen} < ge <= le <= {max}"));
        }
        Ok(entry)
    }
}

impl fmt::Display for PrefixEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.prefix)?;
        if let Some(g) = self.ge {
            write!(f, " ge {g}")?;
        }
        if let Some(l) = self.le {
            write!(f, " le {l}")?;
        }
        Ok(())
    }
}

impl Serialize for PrefixEntry {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PrefixEntry {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

fn cut(s: &str) -> String {
    s.chars().take(48).collect()
}

/// A named prefix list (`dst in NAME`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixList {
    pub name: String,
    #[serde(default)]
    pub entries: Vec<PrefixEntry>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

/// A named community list (`bgp-communities any-list NAME`): normal
/// communities (RFC 1997, `65000:100` or a well-known name) and large ones
/// (RFC 8092, `65000:1:2`) together; each matcher takes its own kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommunityList {
    pub name: String,
    /// As written, checked by `proto-bgp`.
    #[serde(default)]
    pub communities: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

/// Everything under `/routing filter`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoutingFilter {
    /// In order: chains run their rules top to bottom.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<FilterRule>,
    pub next_id: u32,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub prefix_lists: BTreeMap<String, PrefixList>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub community_lists: BTreeMap<String, CommunityList>,
}

impl RoutingFilter {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && self.next_id == 0 && self.prefix_lists.is_empty() && self.community_lists.is_empty()
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    /// The chains, in the order their first rule appears.
    pub fn chains(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for r in &self.rules {
            if !out.contains(&r.chain.as_str()) {
                out.push(&r.chain);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_entries_parse_like_frr() {
        let e: PrefixEntry = "10.0.0.0/8 le 24".parse().unwrap();
        assert_eq!(e.lengths(), (8, 24));
        assert!(e.matches(&"10.1.0.0/16".parse().unwrap()));
        assert!(!e.matches(&"10.1.1.0/25".parse().unwrap()));
        assert!(!e.matches(&"11.0.0.0/8".parse().unwrap()));
        let any: PrefixEntry = "0.0.0.0/0 ge 25".parse().unwrap();
        assert_eq!(any.lengths(), (25, 32));
        assert_eq!(any.to_string(), "0.0.0.0/0 ge 25");
        let exact: PrefixEntry = "2001:db8::/32".parse().unwrap();
        assert!(exact.matches(&"2001:db8::/32".parse().unwrap()));
        assert!(!exact.matches(&"2001:db8::/48".parse().unwrap()));
        for bad in ["10.0.0.1/8", "10.0.0.0/8 ge 8", "10.0.0.0/8 le 33", "10.0.0.0/8 ge 24 le 16", "x", "10.0.0.0/8 lt 9", ""] {
            assert!(bad.parse::<PrefixEntry>().is_err(), "{bad}");
        }
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(json, "\"10.0.0.0/8 le 24\"");
        assert_eq!(serde_json::from_str::<PrefixEntry>(&json).unwrap(), e);
    }
}
