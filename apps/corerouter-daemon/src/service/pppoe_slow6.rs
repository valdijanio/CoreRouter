//! IPv6 of PPPoE subscribers on the slow path (G4.3l): without the XDP
//! data plane the BNG forwards the subscribers' IPv6 itself, as it does
//! IPv4 since G4.3d.
//!
//! - **Upstream:** a packet from a session whose source is inside the
//!   session's /64 or delegated prefix (the anti-spoofing of the XDP,
//!   G4.3e) goes to the stack through a raw IPv6 socket; link-local and
//!   multicast stay with the session's control plane (RS, NS, DHCPv6).
//! - **Downstream:** every /64 and delegated prefix gets a route through
//!   `bng0`; what the kernel sends there comes back here and is found by
//!   longest prefix in a [`Net6Index`].

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv6Addr;

use ipnet::Ipv6Net;

/// Prefixes of the sessions, looked up by longest match. A /64 and the
/// delegated prefixes (/48–/64 in practice) give a handful of distinct
/// lengths, so a lookup is one hash probe per length in use (longest
/// first), not a walk of the sessions.
#[derive(Debug, Clone)]
pub(crate) struct Net6Index<V> {
    by: HashMap<(u8, u128), V>,
    /// Prefix lengths in use and how many prefixes have each.
    lens: BTreeMap<u8, usize>,
}

impl<V> Default for Net6Index<V> {
    fn default() -> Self {
        Self {
            by: HashMap::new(),
            lens: BTreeMap::new(),
        }
    }
}

fn masked(a: u128, len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        a & (u128::MAX << (128 - u32::from(len.min(128))))
    }
}

impl<V: Copy> Net6Index<V> {
    pub(crate) fn insert(&mut self, net: Ipv6Net, v: V) {
        let key = (
            net.prefix_len(),
            masked(u128::from(net.network()), net.prefix_len()),
        );
        if self.by.insert(key, v).is_none() {
            *self.lens.entry(net.prefix_len()).or_default() += 1;
        }
    }

    pub(crate) fn remove(&mut self, net: Ipv6Net) {
        let key = (
            net.prefix_len(),
            masked(u128::from(net.network()), net.prefix_len()),
        );
        if self.by.remove(&key).is_some()
            && let Some(n) = self.lens.get_mut(&net.prefix_len())
        {
            *n -= 1;
            if *n == 0 {
                self.lens.remove(&net.prefix_len());
            }
        }
    }

    /// The value of the longest prefix holding `a`.
    pub(crate) fn get(&self, a: Ipv6Addr) -> Option<V> {
        let a = u128::from(a);
        self.lens
            .keys()
            .rev()
            .find_map(|len| self.by.get(&(*len, masked(a, *len))).copied())
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by.len()
    }
}

/// The source and destination of an IPv6 packet (RFC 8200 §3).
pub(crate) fn addrs(p: &[u8]) -> Option<(Ipv6Addr, Ipv6Addr)> {
    let src: [u8; 16] = p.get(8..24)?.try_into().ok()?;
    let dst: [u8; 16] = p.get(24..40)?.try_into().ok()?;
    (p.first()? >> 4 == 6).then(|| (Ipv6Addr::from(src), Ipv6Addr::from(dst)))
}

/// Traffic for the control plane of the session (link-local or multicast
/// destination: RS, NS, DHCPv6, echo to our link-local) rather than to be
/// forwarded.
pub(crate) fn for_the_link(dst: Ipv6Addr) -> bool {
    dst.is_multicast() || dst.is_unicast_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(t: &str) -> Ipv6Net {
        t.parse().unwrap()
    }

    #[test]
    fn longest_prefix_wins_and_removal_is_exact() {
        let mut ix = Net6Index::default();
        ix.insert(net("2001:db8:1::/48"), 1);
        ix.insert(net("2001:db8:1:5::/64"), 2);
        ix.insert(net("2001:db8:8800::/56"), 3);
        assert_eq!(ix.get("2001:db8:1:5::9".parse().unwrap()), Some(2));
        assert_eq!(ix.get("2001:db8:1:6::9".parse().unwrap()), Some(1));
        assert_eq!(ix.get("2001:db8:8800:ff::1".parse().unwrap()), Some(3));
        assert_eq!(ix.get("2001:db8:9::1".parse().unwrap()), None);
        ix.remove(net("2001:db8:1:5::/64"));
        assert_eq!(ix.get("2001:db8:1:5::9".parse().unwrap()), Some(1));
        ix.remove(net("2001:db8:1:5::/64"));
        assert_eq!(ix.len(), 2);
        ix.insert(net("2001:db8:1::/48"), 7);
        assert_eq!(ix.len(), 2, "a prefix again replaces its value");
        assert_eq!(ix.get("2001:db8:1::1".parse().unwrap()), Some(7));
    }

    #[test]
    fn packets_and_scopes() {
        let mut p = vec![0x60, 0, 0, 0, 0, 0, 58, 64];
        p.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(addrs(&p).map(|a| a.1), Some("2001:db8::2".parse().unwrap()));
        assert_eq!(addrs(&p[..30]), None);
        p[0] = 0x45;
        assert_eq!(addrs(&p), None, "not IPv6");
        assert!(for_the_link("fe80::1".parse().unwrap()));
        assert!(for_the_link("ff02::2".parse().unwrap()));
        assert!(!for_the_link("2001:db8::1".parse().unwrap()));
    }
}
