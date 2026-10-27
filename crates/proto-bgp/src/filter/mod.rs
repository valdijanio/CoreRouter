//! `/routing filter` (G3.2b): BGP route policy in the RouterOS v7 language.
//!
//! - [`parse`]: the rule text to a tree, with errors that say where;
//! - [`eval`]: the policy run on routes, for the preview ("which routes
//!   pass") and the commit impact, split over threads for a full table;
//! - [`frr`]: the same policy as FRR route-maps, prefix-lists,
//!   community-lists and AS-path access-lists, so a diff against the
//!   running config types only what changed;
//! - [`sample`]: a reproducible set of routes for the virtual lab, where
//!   no neighbor sends any.
//!
//! Communities follow RFC 1997 (normal, `ASN:value`, and the well-known
//! ones by name) and RFC 8092 (large, `ASN:value1:value2`).

pub mod eval;
pub mod frr;
pub mod parse;
pub mod sample;

use std::fmt;

use corerouter_model::Issue;
use corerouter_model::routing_filter::{MAX_COMMUNITIES, MAX_LISTS, MAX_PREFIX_ENTRIES, MAX_RULES, RoutingFilter};
use ipnet::IpNet;

/// A large community (RFC 8092 §3: global administrator, two local data
/// parts, 4 bytes each).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Large(pub u32, pub u32, pub u32);

impl fmt::Display for Large {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.0, self.1, self.2)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommunityValue {
    Normal(u32),
    Large(Large),
}

impl fmt::Display for CommunityValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommunityValue::Normal(c) => f.write_str(&community_text(*c)),
            CommunityValue::Large(l) => l.fmt(f),
        }
    }
}

/// The well-known communities by the names FRR prints (RFC 1997 §6,
/// RFC 3765, RFC 7611, RFC 7999, RFC 8326, RFC 9494, draft LLGR), so the
/// render reads back from `show running-config` unchanged.
pub const WELL_KNOWN: &[(&str, u32)] = &[
    ("graceful-shutdown", 0xFFFF_0000),
    ("accept-own", 0xFFFF_0001),
    ("llgr-stale", 0xFFFF_0006),
    ("no-llgr", 0xFFFF_0007),
    ("accept-own-nexthop", 0xFFFF_0008),
    ("blackhole", 0xFFFF_029A),
    ("no-export", 0xFFFF_FF01),
    ("no-advertise", 0xFFFF_FF02),
    ("local-AS", 0xFFFF_FF03),
    ("no-peer", 0xFFFF_FF04),
];

/// A normal community as FRR writes it.
pub fn community_text(c: u32) -> String {
    match WELL_KNOWN.iter().find(|(_, v)| *v == c) {
        Some((n, _)) => (*n).to_owned(),
        None => format!("{}:{}", c >> 16, c & 0xFFFF),
    }
}

/// `65000:100`, a well-known name (`no-export`; RouterOS also writes
/// `local-as`) or `65000:1:2` (large).
pub fn parse_community(s: &str) -> Result<CommunityValue, String> {
    let t = s.trim();
    if let Some((_, v)) = WELL_KNOWN.iter().find(|(n, _)| n.eq_ignore_ascii_case(t)) {
        return Ok(CommunityValue::Normal(*v));
    }
    let parts: Vec<&str> = t.split(':').collect();
    let bad = || {
        format!(
            "{:?} is not a community (65000:100, no-export, blackhole…; large: 65000:1:2){}",
            parse::cut(t),
            parse::did_you_mean(t, &WELL_KNOWN.iter().map(|(n, _)| *n).collect::<Vec<_>>())
        )
    };
    match parts.as_slice() {
        [a, b] => {
            let a: u16 = a.parse().map_err(|_| format!("{}: the AS part of a normal community is 0..=65535 (larger AS: a large community)", parse::cut(t)))?;
            let b: u16 = b.parse().map_err(|_| format!("{}: the value part is 0..=65535", parse::cut(t)))?;
            Ok(CommunityValue::Normal((u32::from(a) << 16) | u32::from(b)))
        }
        [a, b, c] => {
            let n = |x: &str| x.parse::<u32>().map_err(|_| format!("{}: each part of a large community is 0..=4294967295", parse::cut(t)));
            Ok(CommunityValue::Large(Large(n(a)?, n(b)?, n(c)?)))
        }
        _ => Err(bad()),
    }
}

/// Where a route came from (RouterOS `protocol`, FRR `source-protocol`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    Bgp,
    Connected,
    Static,
    Ospf,
    Rip,
}

impl Protocol {
    pub const ALL: [Protocol; 5] = [Protocol::Bgp, Protocol::Connected, Protocol::Static, Protocol::Ospf, Protocol::Rip];

    pub fn name(self) -> &'static str {
        match self {
            Protocol::Bgp => "bgp",
            Protocol::Connected => "connected",
            Protocol::Static => "static",
            Protocol::Ospf => "ospf",
            Protocol::Rip => "rip",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == s)
    }
}

/// One route, as the policy sees it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Route {
    pub prefix: IpNet,
    pub protocol: Protocol,
    /// AS_PATH, the neighbor first (sequences only).
    pub as_path: Vec<u32>,
    /// Sorted, no repeats.
    pub communities: Vec<u32>,
    pub large: Vec<Large>,
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
}

impl Route {
    pub fn bgp(prefix: IpNet, as_path: Vec<u32>) -> Self {
        Route {
            prefix,
            protocol: Protocol::Bgp,
            as_path,
            communities: Vec::new(),
            large: Vec::new(),
            med: None,
            local_pref: None,
        }
    }

    /// The AS path as FRR writes it ("65001 65002").
    pub fn path_text(&self) -> String {
        let mut s = String::with_capacity(self.as_path.len() * 6);
        for (i, a) in self.as_path.iter().enumerate() {
            if i > 0 {
                s.push(' ');
            }
            s.push_str(&a.to_string());
        }
        s
    }
}

/// The checks on names, sizes and list entries (the rules themselves are
/// checked by [`eval::Policy::build`]).
pub fn validate_lists(f: &RoutingFilter) -> Vec<Issue> {
    let mut out = Vec::new();
    if f.rules.len() > MAX_RULES {
        out.push(Issue::new("routing.filter.rules", format!("at most {MAX_RULES} rules")));
    }
    let mut ids = std::collections::HashSet::new();
    for r in &f.rules {
        let path = format!("routing.filter.rules.{}", r.id);
        if !ids.insert(r.id) {
            out.push(Issue::new(&path, "the id is used twice"));
        }
        if let Err(e) = parse::check_chain(&r.chain) {
            out.push(Issue::new(format!("{path}.chain"), e));
        }
    }
    if f.prefix_lists.len() > MAX_LISTS || f.community_lists.len() > MAX_LISTS {
        out.push(Issue::new("routing.filter", format!("at most {MAX_LISTS} lists of each kind")));
    }
    for (key, l) in &f.prefix_lists {
        let path = format!("routing.filter.prefix_lists.{key}");
        if l.name != *key {
            out.push(Issue::new(&path, "list name does not match its key"));
        }
        if let Err(e) = parse::check_name(key) {
            out.push(Issue::new(&path, e));
        }
        if l.entries.len() > MAX_PREFIX_ENTRIES {
            out.push(Issue::new(format!("{path}.entries"), format!("at most {MAX_PREFIX_ENTRIES} entries")));
        }
    }
    for (key, l) in &f.community_lists {
        let path = format!("routing.filter.community_lists.{key}");
        if l.name != *key {
            out.push(Issue::new(&path, "list name does not match its key"));
        }
        if let Err(e) = parse::check_name(key) {
            out.push(Issue::new(&path, e));
        }
        if l.communities.len() > MAX_COMMUNITIES {
            out.push(Issue::new(format!("{path}.communities"), format!("at most {MAX_COMMUNITIES} communities")));
        }
        for c in &l.communities {
            if let Err(e) = parse_community(c) {
                out.push(Issue::new(format!("{path}.communities"), e));
            }
        }
    }
    out
}

/// The sample's seed for a connection and direction: the same routes on
/// every preview of it.
pub fn sample_seed(connection: &str, received: bool) -> u64 {
    fnv(connection) ^ u64::from(received)
}

/// FNV-1a, 64 bits: stable names for the generated FRR lists (the same
/// content gets the same name in every build and release, so a diff
/// against the running config is empty when nothing changed).
pub(crate) fn fnv(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn communities_parse_and_print_like_frr() {
        assert_eq!(parse_community("65000:100"), Ok(CommunityValue::Normal(65000 << 16 | 100)));
        assert_eq!(parse_community("no-export"), Ok(CommunityValue::Normal(0xFFFF_FF01)));
        assert_eq!(parse_community("local-as"), Ok(CommunityValue::Normal(0xFFFF_FF03)));
        assert_eq!(community_text(0xFFFF_FF03), "local-AS");
        assert_eq!(community_text(0xFFFF_029A), "blackhole");
        assert_eq!(parse_community("65535:666").map(|c| c.to_string()), Ok("blackhole".into()));
        assert_eq!(parse_community("4200000000:1:2"), Ok(CommunityValue::Large(Large(4_200_000_000, 1, 2))));
        assert!(parse_community("70000:1").unwrap_err().contains("large community"));
        assert!(parse_community("no-exprot").unwrap_err().contains("did you mean \"no-export\""));
        assert!(parse_community("1:2:3:4").is_err());
    }
}
