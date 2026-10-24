// SPDX-License-Identifier: GPL-2.0-or-later
//! Frames and a reference model for the tests (feature `testing`): the
//! host proptests here and the kernel differential test of `hal-linux`
//! (`tests/xdp_root.rs`) build the same frames and expect the same
//! decisions.

extern crate std;

use std::collections::BTreeMap;
use std::vec;
use std::vec::Vec;

use proptest::prelude::*;

use crate::bucket::Bucket;
use crate::filter::Lookups;
use crate::parse::{self, Addr, IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP};

/// A frame to build.
#[derive(Debug, Clone)]
pub struct Spec {
    pub vlans: Vec<u16>,
    pub src: Addr,
    pub dst: Addr,
    pub proto: u8,
    pub sport: u16,
    pub dport: u16,
    pub flags: u8,
    pub payload: usize,
}

/// The frame `s` describes (no FCS).
pub fn build(s: &Spec) -> Vec<u8> {
    let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2];
    for (i, tci) in s.vlans.iter().enumerate() {
        let tpid: u16 = if i == 0 && s.vlans.len() == 2 {
            0x88a8
        } else {
            0x8100
        };
        f.extend(tpid.to_be_bytes());
        f.extend(tci.to_be_bytes());
    }
    let l4 = l4(s);
    match (s.src, s.dst) {
        (Addr::V4(src), Addr::V4(dst)) => {
            f.extend(0x0800u16.to_be_bytes());
            let total = 20 + l4.len();
            f.extend([0x45, 0]);
            f.extend((total as u16).to_be_bytes());
            f.extend([0, 0, 0x40, 0, 64, s.proto, 0, 0]);
            f.extend(src);
            f.extend(dst);
        }
        (Addr::V6(src), Addr::V6(dst)) => {
            f.extend(0x86ddu16.to_be_bytes());
            f.extend([0x60, 0, 0, 0]);
            f.extend((l4.len() as u16).to_be_bytes());
            f.extend([s.proto, 64]);
            f.extend(src);
            f.extend(dst);
        }
        // Mixed families: nothing to build.
        _ => return Vec::new(),
    }
    f.extend(l4);
    f
}

fn l4(s: &Spec) -> Vec<u8> {
    let mut h = Vec::new();
    match s.proto {
        IPPROTO_TCP => {
            h.extend(s.sport.to_be_bytes());
            h.extend(s.dport.to_be_bytes());
            h.extend([0; 8]);
            h.extend([0x50, s.flags, 0xff, 0xff, 0, 0, 0, 0]);
        }
        IPPROTO_UDP => {
            h.extend(s.sport.to_be_bytes());
            h.extend(s.dport.to_be_bytes());
            h.extend(((8 + s.payload) as u16).to_be_bytes());
            h.extend([0, 0]);
        }
        _ => h.extend([8, 0, 0, 0]),
    }
    h.extend(std::iter::repeat_n(0xab, s.payload));
    h
}

/// Two addresses of one family.
pub fn addr_pair() -> impl Strategy<Value = (Addr, Addr)> {
    prop_oneof![
        (any::<[u8; 4]>(), any::<[u8; 4]>()).prop_map(|(a, b)| (Addr::V4(a), Addr::V4(b))),
        (any::<[u8; 16]>(), any::<[u8; 16]>()).prop_map(|(a, b)| (Addr::V6(a), Addr::V6(b))),
    ]
}

/// Any frame the builder makes.
pub fn spec() -> impl Strategy<Value = Spec> {
    (
        prop::collection::vec(0u16..4096, 0..=2),
        addr_pair(),
        prop::sample::select(vec![IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP]),
        any::<u16>(),
        any::<u16>(),
        any::<u8>(),
        0usize..64,
    )
        .prop_map(|(vlans, (src, dst), proto, sport, dport, flags, payload)| {
            // ICMPv6 for IPv6 sources.
            let proto = match (proto, src) {
                (IPPROTO_ICMP, Addr::V6(_)) => parse::IPPROTO_ICMPV6,
                (p, _) => p,
            };
            Spec {
                vlans,
                src,
                dst,
                proto,
                sport,
                dport,
                flags,
                payload,
            }
        })
}

/// Lists and buckets in plain collections; longest-prefix match the
/// slow, obvious way.
#[derive(Default, Clone)]
pub struct Model {
    /// `(network, prefix length, list index)`.
    pub block: Vec<(Addr, u32, u32)>,
    pub allow: Vec<(Addr, u32)>,
    pub buckets: BTreeMap<[u8; 16], Bucket>,
}

/// Whether `net/len` holds `a`.
pub fn covers(net: &Addr, len: u32, a: &Addr) -> bool {
    let bits = |x: &[u8]| -> u128 {
        x.iter().fold(0u128, |acc, b| (acc << 8) | u128::from(*b)) << (128 - x.len() * 8)
    };
    let (n, x) = match (net, a) {
        (Addr::V4(n), Addr::V4(x)) => (bits(n), bits(x)),
        (Addr::V6(n), Addr::V6(x)) => (bits(n), bits(x)),
        _ => return false,
    };
    len == 0 || (n ^ x) >> (128 - len) == 0
}

impl Lookups for Model {
    fn blocked(&self, src: &Addr) -> Option<u32> {
        self.block
            .iter()
            .filter(|(n, l, _)| covers(n, *l, src))
            .max_by_key(|(_, l, _)| *l)
            .map(|(_, _, i)| *i)
    }
    fn allowed(&self, src: &Addr) -> bool {
        self.allow.iter().any(|(n, l)| covers(n, *l, src))
    }
    fn bucket(&mut self, src: &Addr) -> Option<&mut Bucket> {
        self.buckets.get_mut(&src.mapped())
    }
    fn new_bucket(&mut self, src: &Addr, b: Bucket) {
        self.buckets.insert(src.mapped(), b);
    }
}
