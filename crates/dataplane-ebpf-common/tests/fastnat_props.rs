// SPDX-License-Identifier: GPL-2.0-or-later
//! G2.5b: the CGNAT fast path's step, against full recomputes. A
//! subscriber's packet and the answer to it, translated with the two
//! directions of one conntrack entry: the checksums verify, the TTL went
//! down by one, the endpoints are the NAT's, and control packets, tagged
//! frames and dying TTLs stay with the kernel.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use corerouter_dataplane_ebpf_common::fastnat::{Kernel, admit, key_of, translate, value};
use corerouter_dataplane_ebpf_common::nat::Endpoint;
use corerouter_dataplane_ebpf_common::parse::{
    Addr, IPPROTO_TCP, IPPROTO_UDP, Parsed, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, parse,
};
use corerouter_dataplane_ebpf_common::testing::{Spec, build, checksums_ok, with_checksums};
use proptest::prelude::*;

fn info(f: &[u8]) -> corerouter_dataplane_ebpf_common::parse::IpInfo {
    match parse(f) {
        Parsed::Ip(i) => i,
        other => panic!("{other:?}"),
    }
}

/// One NATed connection: subscriber `sub:sp` to `srv:dp`, seen outside
/// as `public:pp`.
#[derive(Debug, Clone)]
struct Conn {
    proto: u8,
    sub: [u8; 4],
    srv: [u8; 4],
    public: [u8; 4],
    sp: u16,
    dp: u16,
    pp: u16,
    payload: usize,
}

fn conn() -> impl Strategy<Value = Conn> {
    (
        prop::sample::select(vec![IPPROTO_TCP, IPPROTO_UDP]),
        any::<[u8; 4]>(),
        any::<[u8; 4]>(),
        any::<[u8; 4]>(),
        any::<u16>(),
        any::<u16>(),
        any::<u16>(),
        0usize..300,
    )
        .prop_map(|(proto, sub, srv, public, sp, dp, pp, payload)| Conn {
            proto,
            sub,
            srv,
            public,
            sp,
            dp,
            pp,
            payload,
        })
}

fn frame(
    proto: u8,
    src: [u8; 4],
    dst: [u8; 4],
    sp: u16,
    dp: u16,
    payload: usize,
    ttl: u8,
) -> Vec<u8> {
    let mut f = build(&Spec {
        vlans: vec![],
        src: Addr::V4(src),
        dst: Addr::V4(dst),
        proto,
        sport: sp,
        dport: dp,
        flags: TCP_ACK | TCP_PSH,
        payload,
    });
    f[22] = ttl;
    with_checksums(f)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 3000, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn both_directions_translate(c in conn(), ttl in 2u8..=255) {
        // Out: sub:sp → srv:dp becomes public:pp → srv:dp.
        let out = value(Endpoint { addr: c.public, port: c.pp }, Endpoint { addr: c.srv, port: c.dp });
        let mut f = frame(c.proto, c.sub, c.srv, c.sp, c.dp, c.payload, ttl);
        let i = info(&f);
        prop_assert!(key_of(&i).is_some());
        prop_assert_eq!(admit(&f[..], &i), Ok(()));
        translate(&mut f[..], &i, &out).unwrap();
        prop_assert!(checksums_ok(&f), "{f:02x?}");
        prop_assert_eq!(f[22], ttl - 1);
        prop_assert_eq!(&f[26..30], &c.public[..]);
        prop_assert_eq!(&f[30..34], &c.srv[..]);
        prop_assert_eq!(&f[34..36], &c.pp.to_be_bytes()[..]);
        // The same packet, built already translated, is identical.
        let want = frame(c.proto, c.public, c.srv, c.pp, c.dp, c.payload, ttl - 1);
        prop_assert_eq!(&f, &want);

        // Back: srv:dp → public:pp becomes srv:dp → sub:sp.
        let back = value(Endpoint { addr: c.srv, port: c.dp }, Endpoint { addr: c.sub, port: c.sp });
        let mut g = frame(c.proto, c.srv, c.public, c.dp, c.pp, c.payload, ttl);
        let i = info(&g);
        translate(&mut g[..], &i, &back).unwrap();
        prop_assert!(checksums_ok(&g));
        let want = frame(c.proto, c.srv, c.sub, c.dp, c.sp, c.payload, ttl - 1);
        prop_assert_eq!(&g, &want);
    }

    #[test]
    fn the_kernel_keeps_what_it_must(c in conn(), flags in prop::sample::select(vec![TCP_SYN, TCP_SYN | TCP_ACK, TCP_FIN | TCP_ACK, TCP_RST, TCP_RST | TCP_ACK])) {
        let mut s = Spec {
            vlans: vec![],
            src: Addr::V4(c.sub),
            dst: Addr::V4(c.srv),
            proto: IPPROTO_TCP,
            sport: c.sp,
            dport: c.dp,
            flags,
            payload: 0,
        };
        let f = with_checksums(build(&s));
        prop_assert_eq!(admit(&f[..], &info(&f)), Err(Kernel::Control));
        s.flags = TCP_ACK;
        s.vlans = vec![10];
        let tagged = build(&s);
        prop_assert_eq!(admit(&tagged[..], &info(&tagged)), Err(Kernel::Tagged));
        for ttl in [0u8, 1] {
            let f = frame(IPPROTO_UDP, c.sub, c.srv, c.sp, c.dp, 0, ttl);
            prop_assert_eq!(admit(&f[..], &info(&f)), Err(Kernel::Ttl));
        }
    }
}
