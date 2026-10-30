use super::*;
use corerouter_dataplane_ebpf_common::lsp_tap;
use corerouter_hal::lsp::too_big;

/// A classic BPF interpreter for the opcodes of the filters: what the
/// kernel returns for `pkt` (0: dropped).
fn run(prog: &[Insn], pkt: &[u8]) -> u32 {
    let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
    let byte = |at: usize| pkt.get(at).map(|b| u32::from(*b));
    let half = |at: usize| Some(byte(at)? << 8 | byte(at + 1)?);
    let word = |at: usize| Some(half(at)? << 16 | half(at + 2)?);
    let len = u32::try_from(pkt.len()).unwrap();
    while let Some(&(code, jt, jf, k)) = prog.get(pc) {
        let k_at = k as usize;
        let jump = |c: bool| if c { usize::from(jt) } else { usize::from(jf) };
        pc += 1;
        match code {
            LD_B_ABS => {
                a = match byte(k_at) {
                    Some(v) => v,
                    None => return 0,
                }
            }
            LD_H_ABS => {
                a = match half(k_at) {
                    Some(v) => v,
                    None => return 0,
                }
            }
            LD_W_ABS => {
                a = match word(k_at) {
                    Some(v) => v,
                    None => return 0,
                }
            }
            LD_H_IND => {
                a = match half(x as usize + k_at) {
                    Some(v) => v,
                    None => return 0,
                }
            }
            LDX_B_MSH => {
                x = match byte(k_at) {
                    Some(v) => (v & 0xf) * 4,
                    None => return 0,
                }
            }
            LD_W_LEN => a = len,
            AND_K => a &= k,
            JEQ_K => pc += jump(a == k),
            JGT_K => pc += jump(a > k),
            JSET_K => pc += jump(a & k != 0),
            RET_K => return k,
            other => panic!("opcode {other:#x}"),
        }
    }
    panic!("fell off the program")
}

fn name() -> IfName {
    "ether1".parse().unwrap()
}

fn frame(labels: &[u32], ttl: u8, src: &str, dst: &str, port: u16) -> Vec<u8> {
    let payload = vec![7u8; 40];
    let mut f = build_frame(&FrameSpec {
        dst_mac: [2, 0, 0, 0, 0, 2],
        src_mac: [2, 0, 0, 0, 0, 1],
        labels,
        ttl,
        tos: 0xa0,
        src: src.parse().unwrap(),
        dst: dst.parse().unwrap(),
        src_port: 50_000,
        id: 1,
        payload: &payload,
    })
    .unwrap();
    // The destination port, to test the filters on other ports.
    let at = f.len() - 40 - 6;
    f[at..at + 2].copy_from_slice(&port.to_be_bytes());
    f
}

#[test]
fn a_labeled_request_parses_back() {
    let f = frame(&[100, 200], 1, "10.0.0.1", "127.0.0.1", 3503);
    assert_eq!(&f[12..14], &[0x88, 0x47]);
    let h = parse_frame(&f, &name()).unwrap();
    assert_eq!(h.stack.len(), 2);
    assert_eq!(
        (
            h.stack[0].label,
            h.stack[0].ttl,
            h.stack[0].tc,
            h.stack[0].bottom
        ),
        (100, 1, 5, false)
    );
    assert!(h.stack[1].bottom);
    assert_eq!(
        (h.src, h.dst),
        ("10.0.0.1".parse().unwrap(), "127.0.0.1".parse().unwrap())
    );
    assert_eq!(
        (h.src_port, h.dst_port, h.payload.len()),
        (50_000, 3503, 40)
    );
}

#[test]
fn the_ipv4_header_is_right() {
    let f = frame(&[], 255, "10.0.0.1", "127.0.0.1", 3503);
    assert_eq!(&f[12..14], &[0x08, 0x00]);
    let ip = &f[14..34];
    // TTL 1 (§4.3), UDP, no options (no Router Alert, RFC 9570 §4).
    assert_eq!((ip[0], ip[8], ip[9]), (0x45, 1, 17));
    assert_eq!(fold(sum16(ip, 0)), 0, "IP checksum");
    // UDP checksum over the pseudo-header verifies to 0.
    let udp = &f[34..];
    let mut acc = sum16(&ip[12..20], 0);
    acc = acc.wrapping_add(17).wrapping_add(udp.len() as u32);
    assert_eq!(fold(sum16(udp, acc)), 0, "UDP checksum");
    let h = parse_frame(&f, &name()).unwrap();
    assert!(h.stack.is_empty());
}

#[test]
fn ipv6_frames_round_trip() {
    let f = frame(&[16], 1, "2001:db8::1", "::1", 3503);
    let h = parse_frame(&f, &name()).unwrap();
    assert_eq!(h.dst, "::1".parse::<IpAddr>().unwrap());
    let f = frame(&[], 1, "2001:db8::1", "::1", 3503);
    assert_eq!(&f[12..14], &[0x86, 0xdd]);
    assert_eq!(f[14 + 7], 1, "hop limit 1");
}

#[test]
fn the_filters_keep_only_candidates() {
    // MPLS: TTL 1 or 0, or explicit null.
    assert_ne!(
        run(
            MPLS_FILTER,
            &frame(&[100], 1, "10.0.0.1", "127.0.0.1", 3503)
        ),
        0
    );
    assert_ne!(
        run(
            MPLS_FILTER,
            &frame(&[100], 0, "10.0.0.1", "127.0.0.1", 3503)
        ),
        0
    );
    assert_eq!(
        run(
            MPLS_FILTER,
            &frame(&[100], 64, "10.0.0.1", "127.0.0.1", 3503)
        ),
        0
    );
    assert_ne!(
        run(MPLS_FILTER, &frame(&[0], 64, "10.0.0.1", "127.0.0.1", 3503)),
        0
    );
    assert_ne!(
        run(MPLS_FILTER, &frame(&[2], 64, "2001:db8::1", "::1", 3503)),
        0
    );
    assert_eq!(
        run(MPLS_FILTER, &frame(&[3], 64, "10.0.0.1", "127.0.0.1", 3503)),
        0
    );
    assert_eq!(
        run(MPLS_FILTER, &frame(&[6], 64, "10.0.0.1", "127.0.0.1", 3503)),
        0
    );
    // IPv4: 127/8 and port 3503 only.
    assert_ne!(
        run(IP4_FILTER, &frame(&[], 1, "10.0.0.1", "127.0.0.1", 3503)),
        0
    );
    assert_ne!(
        run(IP4_FILTER, &frame(&[], 1, "10.0.0.1", "127.9.8.7", 3503)),
        0
    );
    assert_eq!(
        run(IP4_FILTER, &frame(&[], 1, "10.0.0.1", "10.0.0.2", 3503)),
        0
    );
    assert_eq!(
        run(IP4_FILTER, &frame(&[], 1, "10.0.0.1", "127.0.0.1", 53)),
        0
    );
    let mut frag = frame(&[], 1, "10.0.0.1", "127.0.0.1", 3503);
    frag[20] = 0x20; // more fragments
    assert_eq!(run(IP4_FILTER, &frag), 0);
    // IPv6: ::1 and ::ffff:127/104 only.
    assert_ne!(
        run(IP6_FILTER, &frame(&[], 1, "2001:db8::1", "::1", 3503)),
        0
    );
    assert_ne!(
        run(
            IP6_FILTER,
            &frame(&[], 1, "2001:db8::1", "::ffff:127.0.0.9", 3503)
        ),
        0
    );
    assert_eq!(
        run(
            IP6_FILTER,
            &frame(&[], 1, "2001:db8::1", "::ffff:10.0.0.1", 3503)
        ),
        0
    );
    assert_eq!(
        run(IP6_FILTER, &frame(&[], 1, "2001:db8::1", "::2", 3503)),
        0
    );
    assert_eq!(
        run(
            IP6_FILTER,
            &frame(&[], 1, "2001:db8::1", "2001:db8::2", 3503)
        ),
        0
    );
    assert_eq!(
        run(IP6_FILTER, &frame(&[], 1, "2001:db8::1", "::1", 3504)),
        0
    );
}

/// G3.9d: an expired labeled frame is an echo request for the responder
/// only when it goes to 127/8 port 3503; anything else expired becomes an
/// ICMP candidate, and unexpired frames stay with the responder.
#[test]
fn frames_split_into_echo_requests_and_expired_packets() {
    let echo = frame(&[100], 1, "10.0.0.1", "127.0.0.1", 3503);
    assert!(matches!(
        classify(&echo, &name(), None),
        Some(Frame::Echo(_))
    ));
    // A traceroute probe (UDP 33435 to a real host) whose label TTL expired.
    let probe = frame(&[100, 16], 1, "10.0.0.1", "10.9.9.9", 33435);
    let Some(Frame::Expired(e)) = classify(&probe, &name(), None) else {
        panic!("{:?}", classify(&probe, &name(), None))
    };
    assert_eq!(
        e.stack.iter().map(|l| l.label).collect::<Vec<_>>(),
        [100, 16]
    );
    assert_eq!(e.packet.first().map(|b| b >> 4), Some(4));
    // Port 3503 to a real host is not an echo request either.
    let odd = frame(&[100], 1, "10.0.0.1", "10.9.9.9", 3503);
    assert!(matches!(
        classify(&odd, &name(), None),
        Some(Frame::Expired(_))
    ));
    // Not expired: the responder's (explicit null) path, as before (the
    // filter keeps only these; `respond` drops what is not a request).
    let alive = frame(&[0], 9, "10.0.0.1", "127.0.0.1", 3503);
    assert!(matches!(
        classify(&alive, &name(), None),
        Some(Frame::Echo(_))
    ));
    let transit = frame(&[100], 9, "10.0.0.1", "10.9.9.9", 33435);
    assert!(matches!(
        classify(&transit, &name(), None),
        Some(Frame::Echo(_))
    ));
    assert_eq!(classify(&[0u8; 10], &name(), None), None);
}

/// G3.9da: with a length, the MPLS filter also keeps long frames (cut to
/// what the error quotes) and still everything the plain one keeps.
#[test]
fn the_mpls_filter_keeps_long_frames_when_asked() {
    let big = mpls_filter(Some(200));
    let short = frame(&[100], 64, "10.0.0.1", "10.9.9.9", 80);
    assert!(short.len() <= 200);
    assert_eq!(run(&big, &short), 0);
    let mut long = short.clone();
    long.resize(201, 0);
    assert_eq!(run(&big, &long), (14 + too_big::SNAP) as u32);
    assert_eq!(run(&mpls_filter(None), &long), 0);
    for f in [
        frame(&[100], 1, "10.0.0.1", "10.9.9.9", 80),
        frame(&[0], 64, "10.0.0.1", "127.0.0.1", 3503),
        frame(&[2], 64, "2001:db8::1", "::1", 3503),
    ] {
        assert_eq!(run(&big, &f), run(MPLS_FILTER, &f), "{f:?}");
        assert_ne!(run(&big, &f), 0);
    }
    // Jumps stay inside the program.
    for (i, (code, jt, jf, _)) in big.iter().enumerate() {
        assert!(i + 1 + usize::from(*jt.max(jf)) < big.len() || *code == RET_K);
    }
}

/// G3.9da: a frame longer than `big` that is not expired nor an echo
/// request is a too-big candidate; without `big`, as before.
#[test]
fn long_labeled_frames_are_too_big_candidates() {
    let mut f = frame(&[100], 64, "10.0.0.1", "10.9.9.9", 80);
    // A 1500-octet IP packet with DF, as the tap cut it.
    let ip = 14 + 4;
    f.resize(ip + 1500, 0);
    f[ip + 2..ip + 4].copy_from_slice(&1500u16.to_be_bytes());
    f[ip + 6] = 0x40;
    let cut = &f[..14 + too_big::SNAP];
    let Some(Frame::TooBig(t)) = classify(cut, &name(), Some(1500)) else {
        panic!("{:?}", classify(cut, &name(), Some(1500)))
    };
    assert_eq!((t.len, t.stack.len()), (1500, 1));
    // 1504 octets of payload: not over 1504.
    assert!(!matches!(
        classify(cut, &name(), Some(1504)),
        Some(Frame::TooBig(_))
    ));
    assert!(!matches!(
        classify(cut, &name(), None),
        Some(Frame::TooBig(_))
    ));
    // Expired wins: the kernel checks the TTL first.
    let mut old = f.clone();
    old[17] = 1;
    assert!(matches!(
        classify(&old, &name(), Some(100)),
        Some(Frame::Expired(_))
    ));
}

/// The taps listen on every device: their filters first check that it is
/// an Ethernet one (`SKF_AD_HATYPE`), then run as written.
#[test]
fn filters_on_unbound_taps_are_ethernet_only() {
    for prog in [MPLS_FILTER, IP4_FILTER, IP6_FILTER] {
        let p = ether_only(prog);
        assert_eq!(
            p[..3],
            [
                (LD_W_ABS, 0, 0, 0xffff_f01c),
                (JEQ_K, 1, 0, 1),
                (RET_K, 0, 0, 0)
            ]
        );
        assert_eq!(&p[3..], prog);
        // Jumps stay inside the program (BPF only jumps forward).
        for (i, (_, jt, jf, _)) in p.iter().enumerate() {
            assert!(i + 1 + usize::from(*jt.max(jf)) < p.len() || p[i].0 == RET_K);
        }
    }
}

#[test]
fn icmp_frames_carry_the_stack_or_the_bare_packet() {
    let stack = [
        MplsLabel {
            label: 200,
            tc: 1,
            bottom: false,
            ttl: 255,
        },
        MplsLabel {
            label: 16,
            tc: 1,
            bottom: true,
            ttl: 255,
        },
    ];
    let packet = [0x45u8, 0, 0, 20];
    let f = icmp_frame([2; 6], [4; 6], &stack, &packet);
    assert_eq!(&f[..12], &[2, 2, 2, 2, 2, 2, 4, 4, 4, 4, 4, 4]);
    assert_eq!(&f[12..14], &[0x88, 0x47]);
    assert_eq!(&f[14..18], &((200u32 << 12) | (1 << 9) | 255).to_be_bytes());
    assert_eq!(
        &f[18..22],
        &((16u32 << 12) | (1 << 9) | 0x100 | 255).to_be_bytes()
    );
    assert_eq!(&f[22..], &packet);
    // Popped to an unlabeled next hop: the IP ethertype of the packet.
    assert_eq!(
        &icmp_frame([2; 6], [4; 6], &[], &packet)[12..14],
        &[0x08, 0x00]
    );
    assert_eq!(
        &icmp_frame([2; 6], [4; 6], &[], &[0x60, 0, 0, 0])[12..14],
        &[0x86, 0xdd]
    );
}

#[test]
fn route_answers_with_mpls_encap_parse() {
    // rtmsg (AF_INET, /32, table main, proto zebra, unicast) + RTA_OIF 3 +
    // RTA_GATEWAY 10.0.0.2 + RTA_ENCAP_TYPE MPLS + RTA_ENCAP {DST 100}.
    let mut b = vec![2, 32, 0, 0, 254, 11, 0, 1, 0, 0, 0, 0];
    let attr = |b: &mut Vec<u8>, kind: u16, data: &[u8]| {
        b.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        b.extend_from_slice(&kind.to_ne_bytes());
        b.extend_from_slice(data);
        b.resize(b.len().div_ceil(4) * 4, 0);
    };
    attr(&mut b, RTA_OIF, &3u32.to_ne_bytes());
    attr(&mut b, RTA_GATEWAY, &[10, 0, 0, 2]);
    attr(&mut b, RTA_ENCAP_TYPE, &LWTUNNEL_ENCAP_MPLS.to_ne_bytes());
    let mut encap = Vec::new();
    attr(
        &mut encap,
        MPLS_IPTUNNEL_DST,
        &crate::mpls::encode_label(100, true),
    );
    attr(&mut b, RTA_ENCAP, &encap);
    let r = parse_route(&b).unwrap();
    assert!(r.unicast && !r.static_route);
    assert_eq!(
        r.nexthops,
        vec![RawFtn {
            ifindex: Some(3),
            gateway: Some("10.0.0.2".parse().unwrap()),
            labels: vec![100],
        }]
    );
    // The request asks for the FIB entry of a /32.
    let q = route_request("10.255.0.3".parse().unwrap(), 9);
    assert_eq!(
        u32::from_ne_bytes(q[0..4].try_into().unwrap()) as usize,
        q.len()
    );
    assert_eq!(&q[16..18], &[2, 32]);
}

/// What the packet socket of a frame's protocol keeps of it, as a
/// [`lsp_tap::Keep`] (the classic filters, G3.5b–G3.9da).
fn classic(f: &[u8], big: Option<u32>) -> lsp_tap::Keep {
    let prog = match f.get(12..14) {
        Some([0x88, 0x47]) => mpls_filter(big),
        Some([0x08, 0x00]) => IP4_FILTER.to_vec(),
        Some([0x86, 0xdd]) => IP6_FILTER.to_vec(),
        _ => return lsp_tap::Keep::No,
    };
    match run(&prog, f) {
        0 => lsp_tap::Keep::No,
        KEEP => lsp_tap::Keep::Whole,
        n => {
            assert_eq!(n as usize, lsp_tap::SNAP);
            lsp_tap::Keep::Head
        }
    }
}

/// G3.9db: the tc tap keeps what the packet sockets kept, frame for frame.
#[test]
fn the_tc_tap_keeps_what_the_classic_filters_kept() {
    assert_eq!(lsp_tap::SNAP, 14 + too_big::SNAP);
    let mut cases = vec![
        frame(&[100], 1, "10.0.0.1", "127.0.0.1", 3503),
        frame(&[100], 9, "10.0.0.1", "10.9.9.9", 80),
        frame(&[0], 9, "10.0.0.1", "127.0.0.1", 3503),
        frame(&[2], 9, "2001:db8::1", "::1", 3503),
        frame(&[], 1, "10.0.0.1", "127.0.0.1", 3503),
        frame(&[], 1, "10.0.0.1", "127.0.0.1", 3504),
        frame(&[], 1, "10.0.0.1", "10.0.0.2", 3503),
        frame(&[], 1, "2001:db8::1", "::1", 3503),
        frame(&[], 1, "2001:db8::1", "::ffff:127.0.0.9", 3503),
        frame(&[], 1, "2001:db8::1", "2001:db8::2", 3503),
    ];
    let mut long = frame(&[100], 9, "10.0.0.1", "10.9.9.9", 80);
    long.resize(1600, 0);
    cases.push(long);
    for f in &cases {
        for big in [None, Some(1514), Some(100)] {
            let set = lsp_tap::Settings {
                big: big.unwrap_or(0),
            };
            assert_eq!(
                lsp_tap::keep(&f[..], f.len() as u32, false, set),
                classic(f, big),
                "{f:?} big {big:?}"
            );
        }
    }
}

proptest::proptest! {
    /// G3.9db: the same on hostile frames (the protocol word forced to one
    /// the taps hear).
    #[test]
    fn the_tc_tap_and_the_classic_filters_agree(
        mut b in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..200),
        kind in 0usize..3,
        big in proptest::prelude::any::<u8>(),
    ) {
        if let Some(t) = b.get_mut(12..14) {
            t.copy_from_slice(&[[0x88, 0x47], [0x08, 0x00], [0x86, 0xdd]][kind]);
        }
        let big = (big > 0).then_some(u32::from(big));
        let set = lsp_tap::Settings { big: big.unwrap_or(0) };
        proptest::prop_assert_eq!(lsp_tap::keep(&b[..], b.len() as u32, false, set), classic(&b, big));
    }

    #[test]
    fn hostile_frames_and_routes_never_panic(b in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..300)) {
        let _ = parse_frame(&b, &name());
        let _ = parse_route(&b);
        for prog in [MPLS_FILTER, IP4_FILTER, IP6_FILTER, &mpls_filter(Some(100))] {
            let _ = run(prog, &b);
        }
        let _ = classify(&b, &name(), Some(60));
    }
}
