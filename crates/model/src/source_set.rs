//! Who may talk to a service: prefixes, ranges and firewall address lists,
//! turned into a set a packet can be checked against in O(log n) (G4.6c).
//!
//! A service keeps a list of [`SourceEntry`] in its config, as text, and asks
//! the engine what the names hold right now. An address list can have 60 000
//! entries (G0.21), so the walk of a list per packet is not an option: the
//! [`SourceSet`] is sorted and merged once, then only read.

use std::net::IpAddr;

use crate::firewall::{AddrMatch, Name};

/// One item of an allow list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceEntry {
    /// `192.168.0.0/16`, `10.0.0.1` or `10.0.0.1-10.0.0.9`.
    Match(AddrMatch),
    /// The name of a `/ip firewall address-list`, static and dynamic entries.
    List(Name),
}

impl SourceEntry {
    /// An address form first: a list cannot be named like an address.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Ok(m) = s.parse::<AddrMatch>() {
            return Ok(Self::Match(m));
        }
        s.parse::<Name>().map(Self::List).map_err(|_| {
            format!("'{s}' is neither an address, a prefix, a range nor an address-list name")
        })
    }
}

/// The addresses of a canonical `ip` as a number; IPv4 keeps its own space.
fn v4(ip: IpAddr) -> Option<u32> {
    match ip.to_canonical() {
        IpAddr::V4(a) => Some(u32::from(a)),
        IpAddr::V6(_) => None,
    }
}

fn v6(ip: IpAddr) -> Option<u128> {
    match ip.to_canonical() {
        IpAddr::V4(_) => None,
        IpAddr::V6(a) => Some(u128::from(a)),
    }
}

/// Sorted, without overlaps, adjacent ranges joined.
fn merged<T: Ord + Copy>(mut ranges: Vec<(T, T)>, next: impl Fn(T) -> Option<T>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (lo, hi) in ranges {
        match out.last_mut() {
            Some((_, end)) if next(*end).is_none_or(|n| lo <= n) => *end = (*end).max(hi),
            _ => out.push((lo, hi)),
        }
    }
    out
}

fn inside<T: Ord + Copy>(ranges: &[(T, T)], x: T) -> bool {
    let after = ranges.partition_point(|(lo, _)| *lo <= x);
    after
        .checked_sub(1)
        .and_then(|i| ranges.get(i))
        .is_some_and(|(_, hi)| x <= *hi)
}

/// A set of addresses, read per packet without a lock.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl SourceSet {
    pub fn new(items: impl IntoIterator<Item = AddrMatch>) -> Self {
        let (mut a, mut b) = (Vec::new(), Vec::new());
        for m in items {
            let (lo, hi) = m.bounds();
            match (v4(lo), v4(hi), v6(lo), v6(hi)) {
                (Some(lo), Some(hi), ..) => a.push((lo, hi)),
                (_, _, Some(lo), Some(hi)) => b.push((lo, hi)),
                _ => {}
            }
        }
        Self {
            v4: merged(a, |n: u32| n.checked_add(1)),
            v6: merged(b, |n: u128| n.checked_add(1)),
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(a) => inside(&self.v4, u32::from(a)),
            IpAddr::V6(a) => inside(&self.v6, u128::from(a)),
        }
    }

    /// Disjoint ranges held.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn set(items: &[&str]) -> SourceSet {
        SourceSet::new(items.iter().map(|s| s.parse::<AddrMatch>().unwrap()))
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn entries_are_addresses_or_names() {
        assert!(matches!(SourceEntry::parse("192.168.0.0/16"), Ok(SourceEntry::Match(_))));
        assert!(matches!(SourceEntry::parse("10.0.0.1"), Ok(SourceEntry::Match(_))));
        assert!(matches!(SourceEntry::parse(" fe80::/10 "), Ok(SourceEntry::Match(_))));
        assert!(matches!(SourceEntry::parse("10.0.0.1-10.0.0.9"), Ok(SourceEntry::Match(_))));
        assert!(matches!(SourceEntry::parse("ntp-clients"), Ok(SourceEntry::List(_))));
        assert!(SourceEntry::parse("not a net").is_err());
        assert!(SourceEntry::parse("").is_err());
        assert!(SourceEntry::parse(&"x".repeat(64)).is_err());
    }

    #[test]
    fn membership_at_the_edges() {
        let s = set(&["10.0.0.0/8", "192.168.1.5-192.168.1.9", "2001:db8::/32"]);
        for yes in ["10.0.0.0", "10.255.255.255", "192.168.1.5", "192.168.1.9", "2001:db8::1", "::ffff:10.1.1.1"] {
            assert!(s.contains(ip(yes)), "{yes}");
        }
        for no in ["9.255.255.255", "11.0.0.0", "192.168.1.4", "192.168.1.10", "2001:db9::", "::ffff:8.8.8.8", "::1"] {
            assert!(!s.contains(ip(no)), "{no}");
        }
        assert!(!SourceSet::default().contains(ip("10.0.0.1")), "an empty set holds nobody");
    }

    #[test]
    fn overlaps_and_neighbours_merge() {
        let s = set(&["10.0.0.0/25", "10.0.0.128/25", "10.0.0.5", "10.0.0.0/24", "11.0.0.0/8"]);
        assert_eq!(s.len(), 2);
        // The very top does not overflow.
        let top = set(&["255.255.255.255", "255.255.255.254", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]);
        assert_eq!(top.len(), 2);
        assert!(top.contains(ip("255.255.255.255")));
    }

    proptest! {
        /// The binary search says what a walk of the raw items says.
        #[test]
        fn agrees_with_a_walk(
            nets in proptest::collection::vec((any::<u32>(), 8u8..=32), 0..40),
            probes in proptest::collection::vec(any::<u32>(), 0..80),
        ) {
            let items: Vec<AddrMatch> = nets
                .iter()
                .map(|(a, p)| AddrMatch::Net(ipnet::IpNet::new(IpAddr::from(a.to_be_bytes()), *p).unwrap().trunc()))
                .collect();
            let s = SourceSet::new(items.clone());
            let around = nets.iter().flat_map(|(a, _)| [*a, a.wrapping_add(1), a.wrapping_sub(1)]);
            for p in probes.into_iter().chain(around) {
                let ip = IpAddr::from(p.to_be_bytes());
                prop_assert_eq!(s.contains(ip), items.iter().any(|m| m.contains(ip)));
            }
        }
    }
}
