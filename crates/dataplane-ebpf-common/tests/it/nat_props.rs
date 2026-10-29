// SPDX-License-Identifier: GPL-2.0-or-later
//! G2.5b: the NAT rewrite against a full checksum recompute. Frames from
//! the shared builder (IPv4 TCP/UDP, any payload), checksums filled in,
//! then any source and destination rewrite: every checksum still
//! verifies, the fields hold the new values, the payload is untouched, and
//! rewriting back gives the original frame.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use corerouter_dataplane_ebpf_common::nat::{Endpoint, NotHere, rewrite};
use corerouter_dataplane_ebpf_common::parse::{Addr, IPPROTO_TCP, IPPROTO_UDP, Parsed, parse};
use corerouter_dataplane_ebpf_common::testing::{Spec, build, checksums_ok, with_checksums};
use proptest::prelude::*;

fn v4_spec() -> impl Strategy<Value = Spec> {
    (
        any::<[u8; 4]>(),
        any::<[u8; 4]>(),
        prop::sample::select(vec![IPPROTO_TCP, IPPROTO_UDP]),
        any::<u16>(),
        any::<u16>(),
        0usize..200,
    )
        .prop_map(|(s, d, proto, sport, dport, payload)| Spec {
            vlans: vec![],
            src: Addr::V4(s),
            dst: Addr::V4(d),
            proto,
            sport,
            dport,
            flags: 0x10,
            payload,
        })
}

fn endpoint() -> impl Strategy<Value = Option<Endpoint>> {
    prop::option::of(
        (any::<[u8; 4]>(), any::<u16>()).prop_map(|(addr, port)| Endpoint { addr, port }),
    )
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 3000, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn rewrite_keeps_checksums_valid(s in v4_spec(), src in endpoint(), dst in endpoint()) {
        let original = with_checksums(build(&s));
        prop_assert!(checksums_ok(&original));
        let mut f = original.clone();
        let Parsed::Ip(info) = parse(&f[..]) else { panic!() };
        rewrite(&mut f[..], &info, src, dst).unwrap();
        prop_assert!(checksums_ok(&f), "{f:02x?}");
        if let Some(e) = src {
            prop_assert_eq!(&f[26..30], &e.addr[..]);
            prop_assert_eq!(&f[34..36], &e.port.to_be_bytes()[..]);
        }
        if let Some(e) = dst {
            prop_assert_eq!(&f[30..34], &e.addr[..]);
            prop_assert_eq!(&f[36..38], &e.port.to_be_bytes()[..]);
        }
        let payload_at = if s.proto == IPPROTO_TCP { 54 } else { 42 };
        prop_assert_eq!(&f[payload_at..], &original[payload_at..]);
        // And back.
        let back_src = src.map(|_| Endpoint { addr: original[26..30].try_into().unwrap(), port: s.sport });
        let back_dst = dst.map(|_| Endpoint { addr: original[30..34].try_into().unwrap(), port: s.dport });
        let Parsed::Ip(info) = parse(&f[..]) else { panic!() };
        rewrite(&mut f[..], &info, back_src, back_dst).unwrap();
        prop_assert!(checksums_ok(&f));
        if s.proto == IPPROTO_TCP {
            prop_assert_eq!(f, original);
        }
    }

    /// No UDP checksum (0) stays none; only the IP header follows.
    #[test]
    fn udp_without_checksum_stays_without(s in v4_spec(), src in endpoint()) {
        let mut s = s;
        s.proto = IPPROTO_UDP;
        let mut f = with_checksums(build(&s));
        f[40] = 0;
        f[41] = 0;
        let Parsed::Ip(info) = parse(&f[..]) else { panic!() };
        rewrite(&mut f[..], &info, src, None).unwrap();
        prop_assert_eq!(&f[40..42], &[0, 0][..]);
        prop_assert!(checksums_ok(&f));
    }
}

#[test]
fn fragments_and_other_protocols_stay_in_the_kernel() {
    let s = Spec {
        vlans: vec![],
        src: Addr::V4([100, 64, 0, 1]),
        dst: Addr::V4([198, 51, 100, 1]),
        proto: IPPROTO_UDP,
        sport: 1,
        dport: 2,
        flags: 0,
        payload: 8,
    };
    let mut f = with_checksums(build(&s));
    f[20] = 0x20; // more fragments
    let Parsed::Ip(info) = parse(&f[..]) else {
        panic!()
    };
    assert_eq!(
        rewrite(&mut f[..], &info, None, None),
        Err(NotHere::Fragment)
    );
    let icmp = Spec { proto: 1, ..s };
    let mut g = with_checksums(build(&icmp));
    let Parsed::Ip(info) = parse(&g[..]) else {
        panic!()
    };
    assert_eq!(
        rewrite(&mut g[..], &info, None, None),
        Err(NotHere::Protocol)
    );
}
