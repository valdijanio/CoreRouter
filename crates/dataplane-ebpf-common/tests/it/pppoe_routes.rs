// SPDX-License-Identifier: GPL-2.0-or-later
//! G4.3cd: blocks routed to a subscriber (`PPPOE_RT4`/`PPPOE_RT6`) and the
//! uplink with VLAN tags, through the whole program model (the code the
//! kernel runs): a packet to any host of the block reaches the subscriber
//! exactly as one to its own address does; one from a host of the block is
//! the subscriber's, from another subscriber's block is spoofed; a frame
//! from a tagged uplink goes out the same as the untagged one, and one the
//! kernel must handle keeps its tags.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use corerouter_dataplane_ebpf_common::filter::Settings;
use corerouter_dataplane_ebpf_common::parse::{Addr, IPPROTO_UDP};
use corerouter_dataplane_ebpf_common::pppoe::{
    self, F_FAST_DOWN, F_IPV4, F_IPV6, PPP_IPV4, PPP_IPV6, Session, Stat, Up,
};
use corerouter_dataplane_ebpf_common::testing::{
    Model, Spec, Subs, XDP_DROP, XDP_PASS, XDP_REDIRECT, build, pppoe_frame, program_model,
    test_session, with_checksums,
};
use proptest::prelude::*;

const ACCESS: u32 = 7;
const UPLINK: u32 = 9;

fn run(f: &[u8], ifindex: u32, subs: &mut Subs) -> (u32, Vec<u8>, Option<u32>, Option<Stat>) {
    program_model(
        f,
        ifindex,
        &Settings::default(),
        subs,
        &mut Model::default(),
        1,
    )
}

/// Two subscribers: 5 with 203.0.113.8/29 and 2001:db8:100::/48 routed to
/// it, 6 with 198.51.100.0/28.
fn lab(tags: u8) -> (Subs, Session, Session) {
    let a = test_session(5, ACCESS, tags, F_IPV4 | F_IPV6 | F_FAST_DOWN);
    let b = test_session(6, ACCESS, tags, F_IPV4 | F_IPV6 | F_FAST_DOWN);
    let mut s = Subs::default();
    s.insert(5, &a, 0);
    s.insert(6, &b, 0);
    s.routes4.push(([203, 0, 113, 8], 29, 5));
    s.routes4.push(([198, 51, 100, 0], 28, 6));
    let mut p6 = [0u8; 16];
    p6[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00]);
    s.routes6.push((p6, 48, 5));
    (s, a, b)
}

fn spec(src: Addr, dst: Addr, vlans: Vec<u16>) -> Spec {
    Spec {
        vlans,
        src,
        dst,
        proto: IPPROTO_UDP,
        sport: 4000,
        dport: 53,
        flags: 0,
        payload: 32,
    }
}

/// `f` (untagged, checksums right) with uplink tags `vids` inserted
/// (802.1ad outside when two, as `testing::build`).
fn tagged(f: &[u8], vids: &[u16]) -> Vec<u8> {
    let mut g = f[..12].to_vec();
    for (i, v) in vids.iter().enumerate() {
        let tpid: u16 = if i == 0 && vids.len() == 2 {
            0x88a8
        } else {
            0x8100
        };
        g.extend(tpid.to_be_bytes());
        g.extend((v & 0x0fff).to_be_bytes());
    }
    g.extend(&f[12..]);
    g
}

fn host6(last: [u8; 10]) -> [u8; 16] {
    let mut a = [0u8; 16];
    a[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x01, 0x00]);
    a[6..].copy_from_slice(&last);
    a
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1000, failure_persistence: None, ..ProptestConfig::default() })]

    /// Any host of the block, IPv4 or IPv6, from an uplink with 0, 1 or 2
    /// tags: to the subscriber's access port, the same frame as untagged.
    #[test]
    fn a_routed_block_reaches_its_subscriber(
        access_tags in 0u8..=2, uplink_tags in 0usize..=2, host in 0u8..8, v6 in any::<bool>(),
        iid in any::<[u8; 10]>(), vids in any::<[u16; 2]>(),
    ) {
        let (mut subs, a, _) = lab(access_tags);
        let dst = if v6 { Addr::V6(host6(iid)) } else { Addr::V4([203, 0, 113, 8 + host]) };
        let src = if v6 { Addr::V6([0x2a, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]) } else { Addr::V4([8, 8, 8, 8]) };
        let untagged = with_checksums(build(&spec(src, dst, Vec::new())));
        let frame = tagged(&untagged, &vids[..uplink_tags]);
        let (act, out, to, st) = run(&frame, UPLINK, &mut subs);
        prop_assert_eq!(act, XDP_REDIRECT, "{:?}", st);
        prop_assert_eq!(to, Some(ACCESS));
        prop_assert_eq!(&out[0..6], &a.client_mac[..]);
        let (_, plain_out, _, _) = run(&untagged, UPLINK, &mut subs);
        prop_assert_eq!(&out, &plain_out, "a tagged uplink changes nothing toward the subscriber");
        let off = 12 + 4 * usize::from(access_tags);
        prop_assert_eq!(&out[off + 8..off + 10], &(if v6 { PPP_IPV6 } else { PPP_IPV4 }).to_be_bytes()[..]);
    }

    /// Outside every block and every subscriber: untouched, the kernel's.
    #[test]
    fn other_addresses_are_not_touched(a in any::<[u8; 4]>(), tags in 0usize..=2) {
        prop_assume!(!(a[0] == 203 && a[1] == 0 && a[2] == 113 && (8..16).contains(&a[3])));
        prop_assume!(!(a[0] == 198 && a[1] == 51 && a[2] == 100 && a[3] < 16));
        prop_assume!(a[0] != 100);
        let (mut subs, _, _) = lab(0);
        let f = tagged(&with_checksums(build(&spec(Addr::V4([8, 8, 8, 8]), Addr::V4(a), Vec::new()))), &[10, 11][..tags]);
        let (act, out, _, st) = run(&f, UPLINK, &mut subs);
        prop_assert_eq!(act, XDP_PASS);
        prop_assert_eq!(out, f);
        prop_assert_eq!(st, None);
    }
}

#[test]
fn a_host_of_the_block_sends_as_the_subscriber() {
    let (mut subs, a, b) = lab(1);
    let from = |s: &Session, src: Addr| {
        let f = with_checksums(build(&spec(src, Addr::V4([8, 8, 8, 8]), Vec::new())));
        pppoe_frame(s, &f, PPP_IPV4)
    };
    // Its own block: on to the kernel (decapsulated), not spoofed.
    let up = from(&a, Addr::V4([203, 0, 113, 13]));
    assert!(matches!(pppoe::upstream(&up[..], ACCESS, &mut subs, 1), Up::Session(u) if u.idx == 5));
    // Another subscriber's block, or no block: spoofed.
    for src in [[198, 51, 100, 3], [203, 0, 113, 16]] {
        let f = from(&a, Addr::V4(src));
        assert_eq!(
            pppoe::upstream(&f[..], ACCESS, &mut subs, 1),
            Up::Drop(Stat::Spoofed, Some(5)),
            "{src:?}"
        );
    }
    let f = from(&b, Addr::V4([203, 0, 113, 9]));
    assert_eq!(
        pppoe::upstream(&f[..], ACCESS, &mut subs, 1),
        Up::Drop(Stat::Spoofed, Some(6))
    );
    // IPv6: a host of the /48.
    let f6 = with_checksums(build(&spec(
        Addr::V6(host6([0, 7, 0, 0, 0, 0, 0, 0, 0, 1])),
        Addr::V6([0x2a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        Vec::new(),
    )));
    let up6 = pppoe_frame(&a, &f6, PPP_IPV6);
    assert!(matches!(pppoe::upstream(&up6[..], ACCESS, &mut subs, 1), Up::Session(u) if u.v6));
    let up6b = pppoe_frame(&b, &f6, PPP_IPV6);
    assert_eq!(
        pppoe::upstream(&up6b[..], ACCESS, &mut subs, 1),
        Up::Drop(Stat::Spoofed, Some(6))
    );
}

#[test]
fn the_kernels_cases_keep_their_tags() {
    let (mut subs, _, _) = lab(0);
    // TTL 1 from a tagged uplink: the kernel answers (time exceeded); the
    // frame must still carry its VLAN.
    let mut f = with_checksums(build(&spec(
        Addr::V4([8, 8, 8, 8]),
        Addr::V4([203, 0, 113, 9]),
        Vec::new(),
    )));
    f[14 + 8] = 1;
    let f = tagged(&with_checksums(f), &[42]);
    let (act, out, _, st) = run(&f, UPLINK, &mut subs);
    assert_eq!((act, st), (XDP_PASS, Some(Stat::DownTtl)));
    assert_eq!(out, f);
    // A session without F_FAST_DOWN: the kernel's, untouched.
    let slow = test_session(7, ACCESS, 0, F_IPV4);
    subs.insert(7, &slow, 0);
    subs.routes4.push(([192, 0, 2, 0], 24, 7));
    let g = tagged(
        &with_checksums(build(&spec(
            Addr::V4([8, 8, 8, 8]),
            Addr::V4([192, 0, 2, 77]),
            Vec::new(),
        ))),
        &[42, 43],
    );
    let (act, out, _, st) = run(&g, UPLINK, &mut subs);
    assert_eq!((act, st), (XDP_PASS, Some(Stat::DownKernel)));
    assert_eq!(out, g);
    // A frame too short for its tags is not a subscriber's.
    let (act, _, _, _) = run(&g[..20], UPLINK, &mut subs);
    assert_ne!(act, XDP_DROP);
}
