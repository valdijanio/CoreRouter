//! `/ip pool` (G4.2a): named sets of IPv4 addresses the DHCP server (and,
//! later, PPPoE and hotspot) hands out, as RouterOS has them: one or more
//! ranges and an optional `next_pool` tried when this one is full.
//!
//! Which addresses are in use is operational state of whoever hands them
//! out (`ip.pool.used.print` asks the DHCP server); only the definition is
//! config.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::types::{ItemId, ParseError};

/// Pools in the config (**estimado**, hostile-input bound).
pub const MAX_POOLS: usize = 1024;
pub const MAX_RANGES: usize = 64;
/// Addresses in one pool: a /12 (a CGNAT-sized LAN is a /10, split in
/// pools per BNG; **estimado**). The server scans ranges, so this bounds it.
pub const MAX_POOL_SIZE: u64 = 1 << 20;
/// `next_pool` hops followed before giving up (a chain, not a loop).
pub const MAX_CHAIN: usize = 16;

/// One range of a pool: `10.0.0.10-10.0.0.200`, `10.0.0.0/24` (every host
/// of it: RouterOS keeps network and broadcast out too) or one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PoolRange {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
}

impl PoolRange {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Option<Self> {
        (u32::from(start) <= u32::from(end)).then_some(Self { start, end })
    }

    pub fn len(&self) -> u64 {
        u64::from(u32::from(self.end)) - u64::from(u32::from(self.start)) + 1
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (u32::from(self.start)..=u32::from(self.end)).contains(&u32::from(ip))
    }

    pub fn overlaps(&self, other: &Self) -> bool {
        u32::from(self.start) <= u32::from(other.end)
            && u32::from(other.start) <= u32::from(self.end)
    }
}

impl FromStr for PoolRange {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        if let Some((a, b)) = t.split_once('-') {
            let (Ok(a), Ok(b)) = (a.trim().parse::<Ipv4Addr>(), b.trim().parse::<Ipv4Addr>())
            else {
                return Err(ParseError::new(
                    "pool range",
                    s,
                    "expected 10.0.0.10-10.0.0.200, 10.0.0.0/24 or one address",
                ));
            };
            return Self::new(a, b)
                .ok_or_else(|| ParseError::new("pool range", s, "the first address is after the last"));
        }
        if t.contains('/') {
            let net: Ipv4Net = t
                .parse()
                .map_err(|_| ParseError::new("pool range", s, "not a prefix (10.0.0.0/24)"))?;
            let net = net.trunc();
            let (first, last) = match net.prefix_len() {
                32 | 31 => (net.network(), net.broadcast()),
                _ => (
                    Ipv4Addr::from(u32::from(net.network()).saturating_add(1)),
                    Ipv4Addr::from(u32::from(net.broadcast()).saturating_sub(1)),
                ),
            };
            return Self::new(first, last)
                .ok_or_else(|| ParseError::new("pool range", s, "an empty prefix"));
        }
        let ip: Ipv4Addr = t.parse().map_err(|_| {
            ParseError::new(
                "pool range",
                s,
                "expected 10.0.0.10-10.0.0.200, 10.0.0.0/24 or one address",
            )
        })?;
        Ok(Self { start: ip, end: ip })
    }
}

impl fmt::Display for PoolRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

impl TryFrom<String> for PoolRange {
    type Error = ParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<PoolRange> for String {
    fn from(r: PoolRange) -> Self {
        r.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpPool {
    pub id: ItemId,
    pub name: String,
    pub ranges: Vec<PoolRange>,
    /// Tried when this pool has no free address (RouterOS `next-pool`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_pool: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl IpPool {
    pub fn size(&self) -> u64 {
        self.ranges.iter().map(PoolRange::len).sum()
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        self.ranges.iter().any(|r| r.contains(ip))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IpPools {
    pub pools: Vec<IpPool>,
    pub next_id: u32,
}

impl IpPools {
    pub fn is_empty(&self) -> bool {
        self.pools.is_empty()
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    pub fn get(&self, name: &str) -> Option<&IpPool> {
        self.pools.iter().find(|p| p.name == name)
    }

    /// `name` and the pools its `next_pool` chain reaches, in order, each
    /// once (a loop ends the chain).
    pub fn chain(&self, name: &str) -> Vec<&IpPool> {
        let mut out: Vec<&IpPool> = Vec::new();
        let mut at = self.get(name);
        while let Some(p) = at {
            if out.len() >= MAX_CHAIN || out.iter().any(|q| q.name == p.name) {
                break;
            }
            out.push(p);
            at = p.next_pool.as_deref().and_then(|n| self.get(n));
        }
        out
    }
}

/// Pool names: what RouterOS allows in a name, without spaces (they appear
/// unquoted in the terminal).
pub fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_parse_like_routeros() {
        let r: PoolRange = "10.0.0.10-10.0.0.200".parse().unwrap();
        assert_eq!(r.len(), 191);
        assert_eq!(r.to_string(), "10.0.0.10-10.0.0.200");
        let p: PoolRange = "192.168.88.0/24".parse().unwrap();
        assert_eq!(p.to_string(), "192.168.88.1-192.168.88.254");
        let one: PoolRange = "10.0.0.7".parse().unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one.to_string(), "10.0.0.7");
        assert!("10.0.0.9-10.0.0.1".parse::<PoolRange>().is_err());
        assert!("nope".parse::<PoolRange>().is_err());
        assert!(r.overlaps(&"10.0.0.200-10.0.0.250".parse().unwrap()));
        assert!(!r.overlaps(&"10.0.0.201-10.0.0.250".parse().unwrap()));
    }

    #[test]
    fn chains_stop_at_loops() {
        let pool = |id, name: &str, next: Option<&str>| IpPool {
            id: ItemId(id),
            name: name.into(),
            ranges: vec!["10.0.0.1".parse().unwrap()],
            next_pool: next.map(Into::into),
            comment: String::new(),
        };
        let pools = IpPools {
            pools: vec![pool(1, "a", Some("b")), pool(2, "b", Some("a"))],
            next_id: 2,
        };
        let names: Vec<&str> = pools.chain("a").iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["a", "b"]);
        let back: IpPools = serde_json::from_str(&serde_json::to_string(&pools).unwrap()).unwrap();
        assert_eq!(back, pools);
    }
}
