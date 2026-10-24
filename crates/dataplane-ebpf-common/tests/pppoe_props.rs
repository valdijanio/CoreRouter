// SPDX-License-Identifier: GPL-2.0-or-later
//! G4.3c: properties of the PPPoE data plane, the same code the kernel
//! runs: session frames built from parameters (0–2 VLAN tags, IPv4/IPv6,
//! TCP/UDP/ICMP), then cut, padded, corrupted, spoofed or replaced by
//! noise; the whole program modelled (`testing::program_model`), both
//! directions; the policer against its bounds.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use corerouter_dataplane_ebpf_common::filter::Settings;
use corerouter_dataplane_ebpf_common::parse::{Addr, IPPROTO_TCP, IPPROTO_UDP};
use corerouter_dataplane_ebpf_common::policer::{self, NANOS, Rate};
use corerouter_dataplane_ebpf_common::pppoe::{
    self, Access, Down, F_FAST_DOWN, F_IPV4, F_IPV6, F_PD, PPP_IPV4, PPP_IPV6, Session, Stat, Up,
};
use corerouter_dataplane_ebpf_common::testing::{
    Buf, Model, Spec, Subs, XDP_DROP, XDP_PASS, XDP_REDIRECT, build, checksums_ok, pppoe_frame,
    program_model, spec, test_session, with_checksums,
};
use proptest::prelude::*;

const ACCESS: u32 = 7;
const UPLINK: u32 = 9;
const ALL: u16 = F_IPV4 | F_IPV6 | F_PD;

/// A session (index, tags) and an IP packet spec whose addresses are its
/// own (upstream source / downstream destination); `toward`: the
/// subscriber's address is the destination.
fn case() -> impl Strategy<Value = (Session, Spec, bool)> {
    (0u32..5000, 0u8..=2, spec(), any::<bool>(), any::<[u8; 8]>()).prop_map(
        |(idx, tags, mut sp, toward, iid)| {
            let s = test_session(idx, ACCESS, tags, ALL | F_FAST_DOWN);
            sp.vlans.clear();
            // A clean packet (the filter calls bad TCP flags malformed,
            // and malformed packets are the kernel's).
            sp.flags = 0x10;
            let mine = match sp.src {
                Addr::V4(_) => Addr::V4(s.ipv4),
                Addr::V6(_) => {
                    let mut a = [0u8; 16];
                    a[..8].copy_from_slice(&s.ipv6_prefix);
                    a[8..].copy_from_slice(&iid);
                    // Not link-local / multicast by construction (2001:db8::).
                    Addr::V6(a)
                }
            };
            if toward {
                sp.dst = mine;
            } else {
                sp.src = mine;
                // A multicast destination is link control (userspace).
                if let Addr::V6(d) = &mut sp.dst
                    && d[0] == 0xff
                {
                    d[0] = 0x20;
                }
            }
            (s, sp, toward)
        },
    )
}

fn subs_with(s: &Session) -> Subs {
    let mut m = Subs::default();
    m.insert(5, s, 0);
    m
}

/// The plain frame of `sp`, checksums right.
fn plain(sp: &Spec) -> Vec<u8> {
    with_checksums(build(sp))
}

fn is_v6(sp: &Spec) -> bool {
    matches!(sp.src, Addr::V6(_))
}

/// `f` with the TTL/hop limit one lower and the checksums recomputed.
fn aged(f: &[u8], v6: bool) -> Vec<u8> {
    let mut g = f.to_vec();
    if v6 {
        g[14 + 7] -= 1;
        g
    } else {
        g[14 + 8] -= 1;
        with_checksums(g)
    }
}

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

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2000,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// Any bytes, alone or after a valid session header: no panic, and a
    /// session verdict only for what fits in the frame.
    #[test]
    fn noise_never_panics(
        (s, _, _) in case(),
        bytes in prop::collection::vec(any::<u8>(), 0..160),
        header in any::<bool>(),
    ) {
        let mut subs = subs_with(&s);
        let f = if header {
            let mut f = pppoe_frame(&s, &[0u8; 14], PPP_IPV4);
            let n = f.len();
            f.truncate(n - 2);
            f.extend(PPP_IPV4.to_be_bytes());
            f.extend(&bytes);
            // Fix LENGTH to the noise, so the header itself is valid.
            let off = 14 + 4 * usize::from(pppoe::View::of(&s.to_words()).tags());
            let len = (bytes.len() + 2) as u16;
            f[off + 4..off + 6].copy_from_slice(&len.to_be_bytes());
            f
        } else {
            bytes.clone()
        };
        if let Up::Session(u) = pppoe::upstream(&f[..], ACCESS, &mut subs, 1) {
            prop_assert!(14 + 4 * usize::from(u.tags) + 8 + usize::from(u.ip_len) <= f.len());
        }
        let _ = run(&f, ACCESS, &mut subs);
        let _ = run(&bytes, UPLINK, &mut subs);
        let mut b = Buf::new(&bytes);
        let _ = pppoe::decap(&mut b, 2, true);
    }

    /// Upstream: the subscriber's frame comes out as the plain IP frame it
    /// carried (same MACs), for the kernel; downstream: the plain frame
    /// goes out as a session frame to the subscriber, TTL one lower,
    /// checksums right, to its access port.
    #[test]
    fn both_directions_round_trip((s, sp, toward) in case()) {
        let f = plain(&sp);
        let v6 = is_v6(&sp);
        let mut subs = subs_with(&s);
        let tags = usize::from(pppoe::View::of(&s.to_words()).tags());
        if toward {
            let (act, out, to, st) = run(&f, UPLINK, &mut subs);
            prop_assert_eq!(act, XDP_REDIRECT, "{:?}", st);
            prop_assert_eq!(to, Some(ACCESS));
            prop_assert_eq!(st, Some(Stat::DownFast));
            prop_assert_eq!(&out[0..6], &s.client_mac[..]);
            prop_assert_eq!(&out[6..12], &s.server_mac[..]);
            let off = 12 + 4 * tags;
            prop_assert_eq!(&out[off..off + 4], &[0x88, 0x64, 0x11, 0][..]);
            prop_assert_eq!(u16::from_be_bytes([out[off + 4], out[off + 5]]), s.sid);
            let ip = &out[off + 10..];
            let len = u16::from_be_bytes([out[off + 6], out[off + 7]]);
            prop_assert_eq!(usize::from(len), ip.len() + 2);
            prop_assert_eq!(&out[off + 8..off + 10], &(if v6 { PPP_IPV6 } else { PPP_IPV4 }).to_be_bytes()[..]);
            let want = aged(&f, v6);
            prop_assert_eq!(ip, &want[14..]);
            if tags >= 1 {
                prop_assert_eq!(u16::from_be_bytes([out[14], out[15]]), s.vlan & 0x0fff);
            }
        } else {
            let up = pppoe_frame(&s, &f, if v6 { PPP_IPV6 } else { PPP_IPV4 });
            let (act, out, _, st) = run(&up, ACCESS, &mut subs);
            prop_assert_eq!(act, XDP_PASS);
            prop_assert_eq!(st, Some(Stat::UpKernel));
            prop_assert_eq!(&out[..12], &up[..12]);
            prop_assert_eq!(&out[12..], &f[12..]);
            if !v6 {
                prop_assert!(checksums_ok(&out));
            }
        }
    }

    /// A session frame cut anywhere before its end never goes on as a
    /// session; Ethernet padding after it changes nothing but the tail.
    #[test]
    fn cut_and_padded_frames((s, mut sp, _) in case(), cut in any::<prop::sample::Index>(), pad in 0usize..40) {
        sp.src = match sp.src { Addr::V4(_) => Addr::V4(s.ipv4), a => a };
        if is_v6(&sp) {
            let mut a = [0u8; 16];
            a[..8].copy_from_slice(&s.ipv6_prefix);
            a[15] = 1;
            sp.src = Addr::V6(a);
        }
        let f = plain(&sp);
        let up = pppoe_frame(&s, &f, if is_v6(&sp) { PPP_IPV6 } else { PPP_IPV4 });
        let mut subs = subs_with(&s);
        let n = cut.index(up.len());
        let v = pppoe::upstream(&up[..n], ACCESS, &mut subs, 1);
        prop_assert!(!matches!(v, Up::Session(_)), "{n}/{}: {v:?}", up.len());
        let mut padded = up.clone();
        padded.extend(std::iter::repeat_n(0u8, pad));
        let a = run(&up, ACCESS, &mut subs);
        let b = run(&padded, ACCESS, &mut subs);
        prop_assert_eq!(a.0, b.0);
        prop_assert_eq!(a.3, b.3);
        prop_assert_eq!(&b.1[..a.1.len()], &a.1[..]);
    }

    /// Spoofing: another source address, SID, client MAC, port or VLAN is
    /// dropped; link-local and multicast IPv6 go to userspace.
    #[test]
    fn spoofed_frames((s, mut sp, _) in case(), what in 0u8..6, x in any::<u16>()) {
        let v6 = is_v6(&sp);
        let mine = if v6 {
            let mut a = [0u8; 16];
            a[..8].copy_from_slice(&s.ipv6_prefix);
            a[15] = 1;
            Addr::V6(a)
        } else {
            Addr::V4(s.ipv4)
        };
        sp.src = mine;
        let mut s2 = s;
        let mut ifindex = ACCESS;
        let mut want = Up::Drop(Stat::UnknownSession, None);
        match what {
            0 => {
                sp.src = match mine {
                    Addr::V4(mut a) => { a[3] ^= (x as u8) | 1; Addr::V4(a) }
                    Addr::V6(mut a) => { a[6] ^= (x as u8) | 1; Addr::V6(a) }
                };
                want = Up::Drop(Stat::Spoofed, Some(5));
            }
            1 => s2.sid ^= x | 1,
            2 => s2.client_mac[5] ^= (x as u8) | 1,
            3 => ifindex = ACCESS + 1,
            4 => s2.vlan = if s.vlan == 0 { pppoe::TAGGED | 5 } else { s.vlan ^ ((x & 0x0fff) | 1) },
            _ => {
                if !v6 { return Ok(()); }
                sp.src = Addr::V6([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
                want = Up::User(Stat::Ipv6Control);
            }
        }
        let f = plain(&sp);
        let up = pppoe_frame(&s2, &f, if v6 { PPP_IPV6 } else { PPP_IPV4 });
        let mut subs = subs_with(&s);
        prop_assert_eq!(pppoe::upstream(&up[..], ifindex, &mut subs, 1), want);
    }

    /// The PPP protocol field (RFC 1661 §2): IPv4/IPv6 are data, 0x4000
    /// and up go to userspace as control, the rest as other protocols.
    #[test]
    fn protocol_field((s, sp, _) in case(), proto in any::<u16>()) {
        let up = pppoe_frame(&s, &plain(&sp), proto);
        let mut subs = subs_with(&s);
        let v = pppoe::upstream(&up[..], ACCESS, &mut subs, 1);
        match proto {
            PPP_IPV4 | PPP_IPV6 => prop_assert!(!matches!(v, Up::User(Stat::Control | Stat::OtherProtocol))),
            p if p >= 0x4000 => prop_assert_eq!(v, Up::User(Stat::Control)),
            _ => prop_assert_eq!(v, Up::User(Stat::OtherProtocol)),
        }
    }

    /// Downstream what the fast path cannot do goes to the kernel: TTL
    /// ≤ 1 (time exceeded), larger than the subscriber's MTU (fragment or
    /// "fragmentation needed"/"packet too big", RFC 1191/8201), a session
    /// not marked fast.
    #[test]
    fn downstream_slow_path(len in 20u16..=9000, ttl in any::<u8>(), mtu in prop::sample::select(vec![0u16, 1480, 1492, 1500]), fast in any::<bool>()) {
        let mut s = test_session(1, ACCESS, 0, ALL);
        s.mtu = mtu;
        if fast { s.flags |= F_FAST_DOWN; }
        let mut subs = subs_with(&s);
        let d = pppoe::downstream(&mut subs, 5, false, len, ttl, 1, false);
        let limit = if mtu == 0 { pppoe::DEFAULT_MTU } else { mtu };
        let want = if !fast {
            Some(Stat::DownKernel)
        } else if ttl <= 1 {
            Some(Stat::DownTtl)
        } else if len > limit {
            Some(Stat::DownMtu)
        } else {
            None
        };
        match (d, want) {
            (Down::Kernel(st, 5), Some(w)) => prop_assert_eq!(st, w),
            (Down::Encap(e), None) => prop_assert_eq!(e.ip_len, len),
            other => return Err(TestCaseError::fail(format!("{other:?}"))),
        }
        // Conntrack-accepted flows (CGNAT fast path) skip the fast flag.
        let d = pppoe::downstream(&mut subs, 5, false, 100, 64, 1, true);
        prop_assert!(matches!(d, Down::Encap(_)));
    }

}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// The policer never lets more than the bucket plus the (burst) rate
    /// through, and under load it gives at least the plain rate.
    #[test]
    fn policer_bounds(
        rate_k in 64u64..20_000,
        burst_x in 0u64..4,
        time_s in 1u64..16,
        sizes in prop::collection::vec(64u64..1500, 1..8),
        secs in 1u64..6,
    ) {
        let rate_bps = rate_k * 1000;
        let r = Rate::mikrotik(rate_bps, rate_bps * burst_x, 0, time_s * NANOS);
        let mut st = policer::fresh(&r, 0);
        // Offer twice the top rate, in the given sizes, evenly spaced.
        let top = if r.bursts() { r.burst_rate } else { r.rate };
        let mean = sizes.iter().sum::<u64>() / sizes.len() as u64;
        let step = (NANOS * mean / (2 * top)).max(1);
        let end = secs * NANOS;
        let (mut t, mut passed, mut i, mut biggest) = (0u64, 0u64, 0usize, 0u64);
        while t < end {
            let b = sizes[i % sizes.len()];
            biggest = biggest.max(b);
            if policer::admit(&mut st, &r, t, b) {
                passed += b;
            }
            i += 1;
            t += step;
        }
        let depth = r.depth.max(r.burst_depth);
        let upper = depth + top * secs;
        prop_assert!(passed <= upper, "{passed} > {upper} ({r:?})");
        let lower = (r.rate * secs).saturating_sub(2 * biggest + r.rate * step / NANOS);
        prop_assert!(passed >= lower, "{passed} < {lower} ({r:?})");
    }
}

/// The layout the daemon fills is the one the program reads.
#[test]
fn session_view_matches_session() {
    for tags in 0..=2 {
        let s = test_session(42, ACCESS, tags, ALL);
        let v = pppoe::View::of(&s.to_words());
        assert_eq!(v.tags(), tags);
        assert_eq!(v.ipv4, s.ipv4);
        assert_eq!(v.client_mac, s.client_mac);
        assert_eq!(Session::from_words(&s.to_words()), s);
    }
}

/// Discovery and non-PPPoE frames.
#[test]
fn discovery_and_other_ethertypes() {
    let mut f = [0u8; 60];
    f[12..14].copy_from_slice(&pppoe::ETH_P_PPP_DISC.to_be_bytes());
    assert_eq!(pppoe::access(&f[..]), Access::Discovery);
    f[12..16].copy_from_slice(&[0x81, 0, 0, 5]);
    f[16..18].copy_from_slice(&pppoe::ETH_P_PPP_DISC.to_be_bytes());
    assert_eq!(pppoe::access(&f[..]), Access::Discovery);
    f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    assert_eq!(pppoe::access(&f[..]), Access::NotPppoe);
    let mut subs = Subs::default();
    let (act, _, _, st) = run(
        &build(&Spec {
            vlans: vec![],
            src: Addr::V4([1, 1, 1, 1]),
            dst: Addr::V4([2, 2, 2, 2]),
            proto: IPPROTO_UDP,
            sport: 1,
            dport: 2,
            flags: 0,
            payload: 4,
        }),
        UPLINK,
        &mut subs,
    );
    assert_eq!((act, st), (XDP_PASS, None));
    let _ = (IPPROTO_TCP, XDP_DROP);
}

/// The policer is shared between hosts and the kernel; one sanity number.
#[test]
fn policer_rate_is_exact_over_ten_seconds() {
    let r = Rate::mikrotik(100_000_000, 0, 0, 0);
    let mut st = policer::fresh(&r, 0);
    let mut passed = 0u64;
    let mut t = 0;
    while t < 10 * NANOS {
        if policer::admit(&mut st, &r, t, 1500) {
            passed += 1500;
        }
        t += 1_000;
    }
    let want = 12_500_000 * 10;
    assert!(passed.abs_diff(want) <= r.depth + 1500, "{passed}");
}
