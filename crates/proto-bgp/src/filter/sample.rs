//! Routes for a preview without neighbors (the virtual lab) and for the
//! benchmarks: reproducible (a seed), shaped like a full table — mostly
//! /24 and shorter IPv4, some IPv6, AS paths of 1..=6 hops starting at the
//! neighbor, a few prepends and communities — plus the routes a policy
//! should catch: a default route, bogons (RFC 6890), too-long prefixes.

use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use super::{Large, Route};

/// xorshift64*: small, fast, the same on every platform.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
}

/// The special routes every sample starts with (what a good input policy
/// rejects: RFC 8212 aside, the first things an operator filters).
const SPECIAL: &[&str] = &[
    "0.0.0.0/0",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "203.0.113.128/25",
    "198.18.0.0/15",
    "::/0",
    "2001:db8::/32",
    "fc00::/7",
];

/// `n` routes as neighbor `peer_as` would send them.
pub fn routes(n: usize, seed: u64, peer_as: u32) -> Vec<Route> {
    let mut rng = Rng(seed | 1);
    let mut out = Vec::with_capacity(n);
    for s in SPECIAL.iter().take(n) {
        if let Ok(p) = s.parse::<IpNet>() {
            out.push(Route::bgp(p, vec![peer_as]));
        }
    }
    while out.len() < n {
        let prefix = if rng.below(10) == 0 {
            // IPv6: 2000::/3, /32../48.
            let len = 32 + rng.below(17) as u8;
            let hi = 0x2000_0000_0000_0000_0000_0000_0000_0000u128 | (u128::from(rng.next()) << 64 >> 3);
            match Ipv6Net::new(Ipv6Addr::from(hi), len) {
                Ok(net) => IpNet::V6(net.trunc()),
                Err(_) => continue,
            }
        } else {
            // IPv4: mostly /24 (about 60 % of a full table), then /16../23,
            // and ~2 % longer than /24 (leaks a policy should catch).
            let len = match rng.below(50) {
                0 => 25 + rng.below(4) as u8,
                1..=30 => 24,
                31..=35 => 16 + rng.below(4) as u8,
                36..=45 => 20 + rng.below(4) as u8,
                _ => 8 + rng.below(8) as u8,
            };
            // Public-looking space: 1..=223, skipping 10/8 and 127/8.
            let first = match 1 + rng.below(223) as u32 {
                10 | 127 => 11,
                f => f,
            };
            let addr = (first << 24) | (rng.next() as u32 & 0x00FF_FFFF);
            match Ipv4Net::new(Ipv4Addr::from(addr), len) {
                Ok(net) => IpNet::V4(net.trunc()),
                Err(_) => continue,
            }
        };
        let hops = 1 + rng.below(6) as usize;
        let mut path = Vec::with_capacity(hops + 2);
        path.push(peer_as);
        for _ in 1..hops {
            // Mostly 16-bit public ASNs, some 4-byte ones.
            let asn = if rng.below(5) == 0 {
                131_072 + rng.below(270_000) as u32
            } else {
                1 + rng.below(64_000) as u32
            };
            path.push(asn);
        }
        if rng.below(20) == 0
            && let Some(last) = path.last().copied()
        {
            path.push(last);
            path.push(last);
        }
        let mut r = Route::bgp(prefix, path);
        match rng.below(8) {
            0 => r.communities = vec![(peer_as & 0xFFFF) << 16 | 100],
            1 => r.communities = vec![(peer_as & 0xFFFF) << 16 | 200, 0xFFFF_FF01],
            2 => r.large = vec![Large(peer_as, 1, rng.below(10) as u32)],
            _ => {}
        }
        if rng.below(4) == 0 {
            r.med = Some(rng.below(1000) as u32);
        }
        out.push(r);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_are_reproducible_and_shaped() {
        let a = routes(10_000, 42, 64500);
        assert_eq!(a, routes(10_000, 42, 64500));
        assert_eq!(a.len(), 10_000);
        assert!(a.iter().all(|r| r.as_path.first() == Some(&64500)));
        let v6 = a.iter().filter(|r| matches!(r.prefix, IpNet::V6(_))).count();
        assert!((500..2_000).contains(&v6), "{v6}");
        assert!(a.iter().all(|r| r.prefix.trunc() == r.prefix));
        assert!(a.iter().all(|r| r.communities.windows(2).all(|w| w[0] < w[1])));
        assert_eq!(routes(3, 1, 1).len(), 3);
    }
}
