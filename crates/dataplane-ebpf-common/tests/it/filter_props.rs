// SPDX-License-Identifier: GPL-2.0-or-later
//! G2.5a: properties of the XDP filter's parse and decision, the same code
//! the kernel runs. Frames are built from parameters (Ethernet, VLAN tags,
//! IPv4/IPv6, TCP/UDP/ICMP), then cut, corrupted or replaced by noise.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use corerouter_dataplane_ebpf_common::bucket::{self, NANOS};
use corerouter_dataplane_ebpf_common::filter::{Lookups, Reason, Settings, decide};
use corerouter_dataplane_ebpf_common::parse::{
    Addr, Fragment, IPPROTO_TCP, IPPROTO_UDP, Malformed, Parsed, TCP_ACK, TCP_FIN, TCP_RST,
    TCP_SYN, parse, tcp_flags_valid,
};
use corerouter_dataplane_ebpf_common::testing::{Model, Spec, addr_pair, build, spec};
use proptest::prelude::*;

const ALL_ON: Settings = Settings {
    drop_malformed: true,
    drop_bad_tcp_flags: true,
    block: true,
    allow: true,
    rate_pps: 0,
    burst: 0,
    fast_nat: false,
};

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2000,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// Any bytes: no panic, and nothing read past the frame (the slice
    /// impl would return `None`, so a result that points past it is a bug).
    #[test]
    fn noise_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..200)) {
        if let Parsed::Ip(info) = parse(&bytes[..]) {
            prop_assert!(info.l4_off <= bytes.len() + 2048 * 3);
        }
        let mut m = Model::default();
        let s = Settings { rate_pps: 10, burst: 2, ..ALL_ON };
        let _ = decide(&bytes[..], &s, &mut m, 1);
    }

    /// A well-formed frame parses to what it was built from.
    #[test]
    fn built_frames_parse_back(s in spec()) {
        let f = build(&s);
        let Parsed::Ip(info) = parse(&f[..]) else {
            return Err(TestCaseError::fail(format!("{:?}", parse(&f[..]))));
        };
        prop_assert_eq!(info.src, s.src);
        prop_assert_eq!(info.dst, s.dst);
        prop_assert_eq!(info.proto, s.proto);
        prop_assert_eq!(info.fragment, Fragment::No);
        if s.proto == IPPROTO_TCP {
            prop_assert_eq!((info.src_port, info.dst_port, info.tcp_flags), (s.sport, s.dport, s.flags));
            let want = (!tcp_flags_valid(s.flags)).then_some(Malformed::BadTcpFlags);
            prop_assert_eq!(info.malformed, want);
        } else {
            prop_assert_eq!(info.malformed, None);
        }
        if s.proto == IPPROTO_UDP {
            prop_assert_eq!((info.src_port, info.dst_port), (s.sport, s.dport));
        }
    }

    /// The verifier-visible offsets of an IPv4 packet are its offsets
    /// (the masks of `IpInfo::v4_offsets` never change a parsed value),
    /// also with options and two VLAN tags.
    #[test]
    fn v4_offset_masks_are_identity(s in spec(), opts in 0u8..=10) {
        let mut f = build(&s);
        let Addr::V4(_) = s.src else { return Ok(()) };
        let at = 14 + 4 * s.vlans.len();
        if opts > 0 {
            // Grow the header with `opts` words of NOP options.
            let total = u16::from_be_bytes([f[at + 2], f[at + 3]]) + u16::from(opts) * 4;
            f[at] = 0x45 + opts;
            f[at + 2..at + 4].copy_from_slice(&total.to_be_bytes());
            for _ in 0..opts {
                for _ in 0..4 {
                    f.insert(at + 20, 1);
                }
            }
        }
        if let Parsed::Ip(info) = parse(&f[..]) {
            prop_assert_eq!(info.v4_offsets(), (info.ip_off, info.l4_off));
        }
    }

    /// Cut anywhere inside the datagram: never a clean IP packet.
    #[test]
    fn truncated_frames_are_malformed(s in spec(), cut in any::<prop::sample::Index>()) {
        let f = build(&s);
        let n = cut.index(f.len());
        let short = &f[..n];
        match parse(short) {
            Parsed::Bad(_) => {}
            Parsed::Ip(info) => prop_assert!(info.malformed.is_some(), "{n}/{}: {info:?}", f.len()),
            Parsed::NotIp => prop_assert!(n < 14 + 4 * s.vlans.len(), "cut at {n}"),
        }
        let v = decide(short, &ALL_ON, &mut Model::default(), 0);
        prop_assert!(v.drop || n < 14 + 4 * s.vlans.len(), "{v:?}");
    }

    /// Ethernet padding after the datagram changes nothing.
    #[test]
    fn padding_is_ignored(s in spec(), pad in 0usize..40) {
        let f = build(&s);
        let mut padded = f.clone();
        padded.extend(std::iter::repeat_n(0, pad));
        prop_assert_eq!(parse(&f[..]), parse(&padded[..]));
    }

    /// Block and allow lists: blocked sources drop, allowed ones never do
    /// (unless malformed), with the longest prefix's list index.
    #[test]
    fn lists_decide_like_the_model(
        s in spec(),
        nets in prop::collection::vec((addr_pair(), 0u32..=128, any::<bool>()), 0..6),
    ) {
        let mut m = Model::default();
        for (i, ((a, _), len, allow)) in nets.into_iter().enumerate() {
            let len = if matches!(a, Addr::V4(_)) { len.min(32) } else { len };
            if allow {
                m.allow.push((a, len));
            } else {
                m.block.push((a, len, i as u32));
            }
        }
        // Mix in the source itself sometimes, so matches happen.
        if s.sport % 3 == 0 {
            m.block.push((s.src, 24, 99));
        }
        let mut good = s.clone();
        good.flags = TCP_SYN;
        let f = build(&good);
        let v = decide(&f[..], &ALL_ON, &mut m.clone(), 0);
        let allowed = m.allowed(&s.src);
        match m.blocked(&s.src) {
            Some(list) if !allowed => {
                prop_assert!(v.drop);
                prop_assert_eq!(v.reason, Reason::Blocked);
                prop_assert_eq!(v.list, Some(list));
            }
            _ => prop_assert!(!v.drop, "{v:?}"),
        }
        prop_assert_eq!(v.src, Some(s.src));
    }

    /// Bad TCP flags drop with their own reason, and only when asked to.
    #[test]
    fn tcp_flags_follow_the_setting(mut s in spec(), on in any::<bool>()) {
        s.proto = IPPROTO_TCP;
        let f = build(&s);
        let set = Settings { drop_bad_tcp_flags: on, ..ALL_ON };
        let v = decide(&f[..], &set, &mut Model::default(), 0);
        let bad = !tcp_flags_valid(s.flags);
        prop_assert_eq!(v.drop, bad && on);
        if v.drop {
            prop_assert_eq!(v.reason, Reason::BadTcpFlags);
        }
    }

    /// A source sending at one instant gets exactly `burst` packets
    /// through; one sending below the rate is never limited.
    #[test]
    fn rate_limit_is_a_token_bucket(rate in 1u64..1_000_000, burst in 1u64..64, n in 1usize..200) {
        let s = Spec { vlans: vec![], src: Addr::V4([192, 0, 2, 1]), dst: Addr::V4([198, 51, 100, 1]),
            proto: IPPROTO_UDP, sport: 1, dport: 2, flags: 0, payload: 0 };
        let f = build(&s);
        let set = Settings { rate_pps: rate, burst, ..ALL_ON };
        let mut m = Model::default();
        let passed = (0..n).filter(|_| !decide(&f[..], &set, &mut m, 1_000).drop).count();
        prop_assert_eq!(passed as u64, (n as u64).min(burst));
        // Spaced at the rate (rounded up), nothing drops.
        let mut m = Model::default();
        let gap = NANOS.div_ceil(rate);
        for i in 0..n as u64 {
            let v = decide(&f[..], &set, &mut m, 1_000 + i * gap);
            prop_assert!(!v.drop, "packet {i} at gap {gap}");
        }
    }

    /// Over any arrival pattern, a bucket lets through at most
    /// `burst + rate × elapsed` packets.
    #[test]
    fn bucket_never_exceeds_its_envelope(
        rate in 1u64..100_000,
        burst in 1u64..100,
        gaps in prop::collection::vec(0u64..2_000_000, 1..300),
    ) {
        let mut b = bucket::fresh(0, burst);
        let mut now = 0u64;
        let mut passed = 1u64;
        for g in gaps {
            now += g;
            if bucket::take(&mut b, now, rate, burst) {
                passed += 1;
            }
        }
        let envelope = burst + (u128::from(now) * u128::from(rate) / u128::from(NANOS)) as u64;
        prop_assert!(passed <= envelope, "{passed} > {envelope}");
    }
}

/// RFC 1858 §3.2: TCP fragment at offset 1 is an overlap attack.
#[test]
fn tiny_tcp_fragment_is_malformed() {
    let s = Spec {
        vlans: vec![],
        src: Addr::V4([192, 0, 2, 1]),
        dst: Addr::V4([198, 51, 100, 1]),
        proto: IPPROTO_TCP,
        sport: 1,
        dport: 80,
        flags: TCP_ACK,
        payload: 0,
    };
    let mut f = build(&s);
    // Fragment offset 1 (8 bytes), no DF.
    f[20] = 0;
    f[21] = 1;
    let Parsed::Ip(info) = parse(&f[..]) else {
        panic!()
    };
    assert_eq!(info.malformed, Some(Malformed::TinyFragment));
    // A first fragment too short for the TCP header.
    let mut g = build(&s);
    g.truncate(14 + 20 + 8);
    g[16..18].copy_from_slice(&28u16.to_be_bytes());
    g[20] = 0x20; // MF
    g[21] = 0;
    let Parsed::Ip(info) = parse(&g[..]) else {
        panic!()
    };
    assert_eq!(info.malformed, Some(Malformed::TinyFragment));
    // Later fragments carry no header to check: they pass.
    let mut h = build(&s);
    h[20] = 0;
    h[21] = 3;
    assert!(!decide(&h[..], &ALL_ON, &mut Model::default(), 0).drop);
}

#[test]
fn classic_scans_are_bad_flags() {
    for flags in [0, TCP_SYN | TCP_FIN, TCP_SYN | TCP_RST, TCP_FIN, 0x29] {
        assert!(!tcp_flags_valid(flags), "{flags:#x}");
    }
    assert!(tcp_flags_valid(TCP_RST));
}
