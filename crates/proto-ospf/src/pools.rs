//! The subscriber pools an instance announces (G4.3ce, OSPF part): the
//! `/ip pool`s PPPoE profiles hand out (`remote-address`) and those of the
//! IPoE DHCP servers, `next-pool` chains followed, each range summarized
//! into the smallest prefix that covers it, and the prefixes merged.
//!
//! The render redistributes the subscribers' routes (a PPP session is a
//! connected /32, an IPoE lease a kernel route) through a prefix-list of
//! these, and `summary-address` folds them into one type-5 LSA per prefix
//! (`ospfd`'s external aggregation): the core sees one route per pool, not
//! one per subscriber, and the summary is withdrawn by itself when the
//! last subscriber of the pool goes.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use corerouter_model::Config;
use corerouter_model::ppp::AddrOrPool;
use ipnet::Ipv4Net;

/// Most prefixes announced (a summary per pool range; past this the pools
/// are fragmented and the operator should use area ranges or BGP).
pub const MAX_CIDRS: usize = 4_096;

/// The pools PPPoE and IPoE hand subscribers out of, by name.
pub fn pool_names(cfg: &Config) -> BTreeSet<&str> {
    let mut out = BTreeSet::new();
    for p in &cfg.ppp.profiles {
        if let Some(AddrOrPool::Pool(name)) = &p.remote_address {
            out.insert(name.as_str());
        }
    }
    for s in &cfg.ip.dhcp_server.servers {
        if (s.ipoe || s.use_radius != corerouter_model::ipoe::UseRadius::No)
            && let Some(p) = &s.address_pool
        {
            out.insert(p.as_str());
        }
    }
    out
}

/// The smallest prefix holding `start..=end`.
pub fn cover(start: Ipv4Addr, end: Ipv4Addr) -> Ipv4Net {
    let (a, b) = (u32::from(start), u32::from(end));
    let diff = a ^ b;
    let len = if diff == 0 {
        32
    } else {
        u8::try_from(diff.leading_zeros()).unwrap_or(0)
    };
    Ipv4Net::new(start, len)
        .map(|n| n.trunc())
        .unwrap_or_default()
}

/// The announced prefixes: each pool range's cover, the covered ones and
/// siblings merged (`Ipv4Net::aggregate`).
pub fn cidrs(cfg: &Config) -> Vec<Ipv4Net> {
    let mut nets = Vec::new();
    let mut seen = BTreeSet::new();
    for name in pool_names(cfg) {
        for p in cfg.ip.pools.chain(name) {
            if !seen.insert(p.name.as_str()) {
                continue;
            }
            for r in &p.ranges {
                nets.push(cover(r.start, r.end));
            }
        }
    }
    let mut out = Ipv4Net::aggregate(&nets);
    out.truncate(MAX_CIDRS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_are_the_smallest_prefix() {
        let c = |a: &str, b: &str| cover(a.parse().unwrap(), b.parse().unwrap()).to_string();
        assert_eq!(c("100.64.0.1", "100.64.0.254"), "100.64.0.0/24");
        assert_eq!(c("100.64.0.0", "100.64.3.255"), "100.64.0.0/22");
        assert_eq!(c("10.0.0.5", "10.0.0.5"), "10.0.0.5/32");
        assert_eq!(c("10.0.0.255", "10.0.1.0"), "10.0.0.0/23");
        assert_eq!(c("0.0.0.0", "255.255.255.255"), "0.0.0.0/0");
    }
}
