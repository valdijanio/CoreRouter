// SPDX-License-Identifier: GPL-2.0-or-later
//! G4.3f: the IPoE subscribers of the XDP program, the same code the kernel
//! runs (`testing::program_model`): the IP↔MAC binding (TR-146 R-38), DHCP
//! untouched, unknown hosts and other ports left to the kernel, the
//! policer both ways with the kernel still forwarding, and noise.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use corerouter_dataplane_ebpf_common::filter::Settings;
use corerouter_dataplane_ebpf_common::ipoe::{self, F_IPOE};
use corerouter_dataplane_ebpf_common::parse::{Addr, IPPROTO_TCP, IPPROTO_UDP};
use corerouter_dataplane_ebpf_common::policer::Rate;
use corerouter_dataplane_ebpf_common::pppoe::{self, Down, F_IPV4, Session, Stat};
use corerouter_dataplane_ebpf_common::testing::{
    Model, Spec, Subs, XDP_DROP, XDP_PASS, build, program_model, test_session, with_checksums,
};
use proptest::prelude::*;

const ACCESS: u32 = 7;
const UPLINK: u32 = 9;

fn sub(idx: u32) -> Session {
    Session {
        sid: ipoe::SID,
        ..test_session(idx, ACCESS, 0, F_IPOE | F_IPV4)
    }
}

fn subs_with(s: &Session) -> Subs {
    let mut m = Subs::default();
    m.insert(5, s, 0);
    m.ipoe_ports.insert(ACCESS);
    m
}

fn spec(src: [u8; 4], dst: [u8; 4], proto: u8, dport: u16, payload: usize) -> Spec {
    Spec {
        vlans: Vec::new(),
        src: Addr::V4(src),
        dst: Addr::V4(dst),
        proto,
        sport: 40_000,
        dport,
        flags: 0x10,
        payload,
    }
}

/// From the subscriber of `s` to the BNG's MAC.
fn up(s: &Session, src: [u8; 4], proto: u8, dport: u16, payload: usize) -> Vec<u8> {
    let mut f = with_checksums(build(&spec(src, [198, 51, 100, 1], proto, dport, payload)));
    f[..6].copy_from_slice(&s.server_mac);
    f[6..12].copy_from_slice(&s.client_mac);
    f
}

fn down(s: &Session, payload: usize) -> Vec<u8> {
    with_checksums(build(&spec(
        [198, 51, 100, 1],
        s.ipv4,
        IPPROTO_TCP,
        443,
        payload,
    )))
}

fn run(
    f: &[u8],
    ifindex: u32,
    subs: &mut Subs,
    now: u64,
) -> (u32, Vec<u8>, Option<u32>, Option<Stat>) {
    program_model(
        f,
        ifindex,
        &Settings::default(),
        subs,
        &mut Model::default(),
        now,
    )
}

#[test]
fn the_binding_dhcp_and_strangers() {
    let s = sub(3);
    let mut subs = subs_with(&s);
    // Its own address: on to the kernel untouched, counted as a session's.
    let f = up(&s, s.ipv4, IPPROTO_TCP, 80, 100);
    let (act, out, _, st) = run(&f, ACCESS, &mut subs, 1);
    assert_eq!((act, st), (XDP_PASS, Some(Stat::UpKernel)));
    assert_eq!(out, f, "nothing stripped");
    // Another address from its MAC: spoofed (TR-146 R-38).
    let (act, _, _, st) = run(
        &up(&s, [100, 64, 9, 9], IPPROTO_TCP, 80, 100),
        ACCESS,
        &mut subs,
        1,
    );
    assert_eq!((act, st), (XDP_DROP, Some(Stat::Spoofed)));
    // DHCP passes whatever its source (a DISCOVER is from 0.0.0.0).
    let (act, _, _, st) = run(
        &up(&s, [0, 0, 0, 0], IPPROTO_UDP, 67, 300),
        ACCESS,
        &mut subs,
        1,
    );
    assert_eq!((act, st), (XDP_PASS, Some(Stat::IpoeDhcp)));
    // A host the map does not know, or another port: as without IPoE.
    let mut other = s;
    other.client_mac = [2, 0xee, 0, 0, 0, 1];
    let (act, _, _, st) = run(
        &up(&other, [100, 64, 9, 9], IPPROTO_TCP, 80, 100),
        ACCESS,
        &mut subs,
        1,
    );
    assert_eq!((act, st), (XDP_PASS, None));
    let (act, _, _, st) = run(
        &up(&s, [100, 64, 9, 9], IPPROTO_TCP, 80, 100),
        UPLINK,
        &mut subs,
        1,
    );
    assert_eq!((act, st), (XDP_PASS, None));
    // To another MAC (a broadcast, a neighbour): not routed by us.
    let mut b = up(&s, [100, 64, 9, 9], IPPROTO_TCP, 80, 100);
    b[..6].copy_from_slice(&[0xff; 6]);
    assert_eq!(run(&b, ACCESS, &mut subs, 1).0, XDP_PASS);
    // A PPPoE session of the same MAC (SID ≠ 0) is another key.
    assert_ne!(
        ipoe::key(ACCESS, s.client_mac),
        test_session(3, ACCESS, 0, F_IPV4).key()
    );
}

/// The RouterOS policer both ways: over the rate dropped, the rest to the
/// kernel (which forwards it through its firewall) and counted.
#[test]
fn the_policer_limits_both_ways() {
    let mut s = sub(4);
    // 1 Mbit/s, no burst: a bucket of a few kB.
    s.up = Rate::mikrotik(1_000_000, 0, 0, 0);
    s.down = Rate::mikrotik(1_000_000, 0, 0, 0);
    let mut subs = subs_with(&s);
    let mut passed = [0u32; 2];
    let mut dropped = [0u32; 2];
    for i in 0..200u64 {
        let now = 1 + i * 1000; // 1 µs apart: far over 1 Mbit/s
        let (a, _, _, st) = run(
            &up(&s, s.ipv4, IPPROTO_TCP, 80, 1000),
            ACCESS,
            &mut subs,
            now,
        );
        if a == XDP_DROP {
            assert_eq!(st, Some(Stat::UpPoliced));
            dropped[0] += 1;
        } else {
            passed[0] += 1;
        }
        let (a, _, _, st) = run(&down(&s, 1000), UPLINK, &mut subs, now);
        if a == XDP_DROP {
            assert_eq!(st, Some(Stat::DownPoliced));
            dropped[1] += 1;
        } else {
            assert_eq!(st, Some(Stat::IpoeDownKernel));
            passed[1] += 1;
        }
    }
    for d in 0..2 {
        assert!(passed[d] > 0 && dropped[d] > 150, "{passed:?} {dropped:?}");
    }
    // Without a limit everything goes, counted for accounting.
    let s = sub(4);
    let mut subs = subs_with(&s);
    let (ip_len, ttl) = pppoe::ip_meta(
        &corerouter_dataplane_ebpf_common::testing::Buf::new(&down(&s, 1000)),
        false,
    )
    .unwrap();
    assert!(matches!(
        pppoe::downstream(&mut subs, 5, false, ip_len, ttl, 1, false),
        Down::Counted(Stat::IpoeDownKernel, 5, l) if l == ip_len
    ));
    // A flow conntrack accepted (CGNAT fast path) is sent from XDP: the
    // MACs rewritten, nothing pushed.
    let Down::Encap(d) = pppoe::downstream(&mut subs, 5, false, ip_len, ttl, 1, true) else {
        panic!("encap");
    };
    assert!(d.ipoe);
    let mut buf = corerouter_dataplane_ebpf_common::testing::Buf::new(&down(&s, 10));
    let before = buf.frame().len();
    pppoe::encap(&mut buf, &d).unwrap();
    assert_eq!(buf.frame().len(), before);
    assert_eq!(&buf.frame()[..6], &s.client_mac);
    assert_eq!(&buf.frame()[6..12], &s.server_mac);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, failure_persistence: None, ..ProptestConfig::default() })]

    /// Noise on an IPoE port, alone or after the subscriber's MACs and an
    /// IPv4 ethertype: no panic, and a known subscriber's frame is never
    /// redirected upstream (the kernel's or dropped).
    #[test]
    fn noise_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..200), head in any::<bool>()) {
        let s = sub(9);
        let mut subs = subs_with(&s);
        let f = if head {
            let mut f = Vec::new();
            f.extend(s.server_mac);
            f.extend(s.client_mac);
            f.extend(0x0800u16.to_be_bytes());
            f.extend(&bytes);
            f
        } else {
            bytes.clone()
        };
        let (act, _, _, _) = run(&f, ACCESS, &mut subs, 1);
        prop_assert!(act == XDP_PASS || act == XDP_DROP);
    }
}
