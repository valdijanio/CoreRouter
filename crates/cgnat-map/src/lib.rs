// SPDX-License-Identifier: GPL-2.0-or-later
//! The deterministic CGNAT port arithmetic (RFC 7422 §2): subscriber
//! number ↔ (public address number, port block), block ↔ ports. Scalars
//! only, no allocation, no panic, `no_std`, so the same functions run in
//! the model (`corerouter_model::cgnat::Layout`, which numbers addresses
//! through its ranges) and in the XDP program (G2.5b, which numbers them
//! through maps). One formula: "who was" answered from the config agrees
//! with what the fast path translated.

#![no_std]
#![forbid(unsafe_code)]

/// A pool's port geometry: blocks of `ports` ports from `first_port`,
/// `per_address` of them on each public address. Built by the model from
/// a validated pool (`ports > 0`, the blocks fit the port range).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Geometry {
    pub first_port: u16,
    pub ports: u16,
    pub per_address: u32,
}

impl Geometry {
    /// The (public address number, block) of subscriber number `index`:
    /// consecutive subscribers share an address, `per_address` per address.
    pub fn split(&self, index: u64) -> Option<(u64, u32)> {
        let per = u64::from(self.per_address);
        let address = index.checked_div(per)?;
        let block = u32::try_from(index.checked_rem(per)?).ok()?;
        Some((address, block))
    }

    /// Back from [`Geometry::split`]: the subscriber number of block
    /// `block` on address number `address`.
    pub fn join(&self, address: u64, block: u32) -> Option<u64> {
        if block >= self.per_address {
            return None;
        }
        address
            .checked_mul(u64::from(self.per_address))?
            .checked_add(u64::from(block))
    }

    /// First and last port of block `block`.
    pub fn ports_of(&self, block: u32) -> Option<(u16, u16)> {
        if block >= self.per_address || self.ports == 0 {
            return None;
        }
        let first =
            u32::from(self.first_port).checked_add(block.checked_mul(u32::from(self.ports))?)?;
        let last = first.checked_add(u32::from(self.ports) - 1)?;
        Some((u16::try_from(first).ok()?, u16::try_from(last).ok()?))
    }

    /// The block holding `port`, if any (below the first port or past the
    /// last whole block: none).
    pub fn block_of(&self, port: u16) -> Option<u32> {
        let off = u32::from(port).checked_sub(u32::from(self.first_port))?;
        let block = off.checked_div(u32::from(self.ports))?;
        (block < self.per_address).then_some(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn geometry() -> impl Strategy<Value = Geometry> {
        (0u16..=65535)
            .prop_flat_map(|first| (Just(first), 1u32..=65536 - u32::from(first)))
            .prop_map(|(first, ports)| {
                let ports = u16::try_from(ports.min(65535)).unwrap();
                let range = 65536 - u32::from(first);
                Geometry {
                    first_port: first,
                    ports,
                    per_address: range / u32::from(ports),
                }
            })
    }

    #[test]
    fn rfc_7422_example() {
        // §2: the reserved ports (0-1023) left out, the rest cut into
        // blocks; 2000-port blocks give 32 per address and leave 512 ports
        // unused at the top.
        let g = Geometry {
            first_port: 1024,
            ports: 2000,
            per_address: 64512 / 2000,
        };
        assert_eq!(g.per_address, 32);
        assert_eq!(g.split(33), Some((1, 1)));
        assert_eq!(g.ports_of(1), Some((3024, 5023)));
        assert_eq!(g.block_of(5023), Some(1));
        assert_eq!(g.ports_of(31), Some((63024, 65023)));
        assert_eq!(g.block_of(1023), None);
        assert_eq!(g.block_of(65535), None, "past the last whole block");
        assert_eq!(g.join(1, 1), Some(33));
        assert_eq!(g.join(0, 32), None);
    }

    #[test]
    fn degenerate_geometry_never_panics() {
        let g = Geometry {
            first_port: 0,
            ports: 0,
            per_address: 0,
        };
        assert_eq!(g.split(5), None);
        assert_eq!(g.ports_of(0), None);
        assert_eq!(g.block_of(10), None);
        assert_eq!(g.join(u64::MAX, 0), None);
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 2000, failure_persistence: None, ..ProptestConfig::default() })]

        /// split and join are inverses; a block's ports map back to it and
        /// stay inside the geometry; blocks do not overlap.
        #[test]
        fn round_trips(g in geometry(), index in 0u64..1 << 40, port in any::<u16>()) {
            let (a, b) = g.split(index).unwrap();
            prop_assert_eq!(g.join(a, b), Some(index));
            let (first, last) = g.ports_of(b).unwrap();
            prop_assert_eq!(u32::from(last) - u32::from(first) + 1, u32::from(g.ports));
            prop_assert!(first >= g.first_port);
            prop_assert_eq!(g.block_of(first), Some(b));
            prop_assert_eq!(g.block_of(last), Some(b));
            if let Some(blk) = g.block_of(port) {
                let (f, l) = g.ports_of(blk).unwrap();
                prop_assert!(f <= port && port <= l);
            }
        }

        /// The same numbers as the plain formula in wide integers.
        #[test]
        fn matches_the_reference(g in geometry(), index in 0u64..1 << 40) {
            let per = u128::from(g.per_address);
            let (a, b) = g.split(index).unwrap();
            prop_assert_eq!(u128::from(a), u128::from(index) / per);
            prop_assert_eq!(u128::from(b), u128::from(index) % per);
            let first = u128::from(g.first_port) + u128::from(b) * u128::from(g.ports);
            prop_assert_eq!(g.ports_of(b).map(|p| u128::from(p.0)), Some(first));
        }
    }
}
