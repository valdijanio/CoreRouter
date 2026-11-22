use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::str::FromStr;

use ipnet::IpNet;
use proptest::prelude::*;

use super::*;
use crate::icmp_ext;
use crate::lsp::expired::Delivery;
use crate::mpls::{MplsNexthop, MplsRoute, Origin};

struct View {
    labels: BTreeMap<u32, MplsRoute>,
    routed: Vec<IpAddr>,
    /// MTU of ether2 (ether1, where packets come in, has 1500).
    mtu2: Option<u16>,
}

fn ifn(s: &str) -> IfName {
    IfName::from_str(s).unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

impl LsrView for View {
    fn label_entry(&self, label: u32) -> Option<MplsRoute> {
        self.labels.get(&label).cloned()
    }
    fn fec_route(&self, p: IpNet) -> Option<Vec<MplsNexthop>> {
        self.routed.contains(&p.addr()).then(|| {
            vec![MplsNexthop {
                via: Some(ip("10.0.12.1")),
                interface: Some(ifn("ether1")),
                out_labels: vec![],
            }]
        })
    }
    fn is_local(&self, _: IpNet) -> bool {
        false
    }
    fn interface_addrs(&self, i: &IfName) -> Vec<IpAddr> {
        if i.as_str() == "ether1" {
            vec![ip("10.0.12.2"), ip("fd00:12::2")]
        } else {
            vec![]
        }
    }
    fn mtu(&self, i: &IfName) -> Option<u16> {
        match i.as_str() {
            "ether2" => self.mtu2,
            _ => Some(1500),
        }
    }
}

/// R2 of R1 — R2 — R3, the link to R3 with MTU 1400: label 100 swaps to
/// 200, label 101 pops (PHP), label 102 swaps and pushes one more (200
/// over 300, a TI-LFA repair), label 103 has ECMP over ether1 and ether2.
fn transit(routed: &[&str]) -> View {
    let nh = |i: &str, out: Vec<u32>| MplsNexthop {
        via: Some(ip("10.0.23.3")),
        interface: Some(ifn(i)),
        out_labels: out,
    };
    let entry = |label: u32, nexthops: Vec<MplsNexthop>| MplsRoute {
        label,
        origin: Origin::Ldp,
        nexthops,
    };
    View {
        labels: BTreeMap::from([
            (100, entry(100, vec![nh("ether2", vec![200])])),
            (101, entry(101, vec![nh("ether2", vec![])])),
            (102, entry(102, vec![nh("ether2", vec![200, 300])])),
            (
                103,
                entry(103, vec![nh("ether1", vec![200]), nh("ether2", vec![201])]),
            ),
        ]),
        routed: routed.iter().map(|s| ip(s)).collect(),
        mtu2: Some(1400),
    }
}

fn label(label: u32, ttl: u8, bottom: bool) -> MplsLabel {
    MplsLabel {
        label,
        tc: 0,
        bottom,
        ttl,
    }
}

/// `len` octets of TCP from `src` to `dst`, DF as given.
fn tcp4(src: &str, dst: &str, len: usize, df: bool) -> Vec<u8> {
    let (IpAddr::V4(s), IpAddr::V4(d)) = (ip(src), ip(dst)) else {
        panic!("IPv4 only")
    };
    let mut p = vec![0x45, 0];
    p.extend_from_slice(&(len as u16).to_be_bytes());
    p.extend_from_slice(&[0x12, 0x34, if df { 0x40 } else { 0 }, 0, 63, 6, 0, 0]);
    p.extend_from_slice(&s.octets());
    p.extend_from_slice(&d.octets());
    p.extend((20..len).map(|i| i as u8));
    p
}

fn tcp6(src: &str, dst: &str, len: usize) -> Vec<u8> {
    let mut p = vec![0x60, 0, 0, 0];
    p.extend_from_slice(&((len - 40) as u16).to_be_bytes());
    p.extend_from_slice(&[6, 63]);
    p.extend_from_slice(&src.parse::<Ipv6Addr>().unwrap().octets());
    p.extend_from_slice(&dst.parse::<Ipv6Addr>().unwrap().octets());
    p.extend((40..len).map(|i| i as u8));
    p
}

fn frame(stack: &[MplsLabel], ip_packet: &[u8]) -> Vec<u8> {
    let mut f: Vec<u8> = stack
        .iter()
        .flat_map(|l| crate::lsp::wire::label_word(l).to_be_bytes())
        .collect();
    f.extend_from_slice(ip_packet);
    f
}

fn too_big(stack: &[MplsLabel], ip_packet: &[u8]) -> TooBig {
    parse(&ifn("ether1"), &frame(stack, ip_packet)).unwrap()
}

#[test]
fn a_frame_parses_with_its_length_and_a_bounded_copy() {
    let p = tcp4("192.0.2.1", "198.51.100.9", 1500, true);
    let t = too_big(&[label(100, 64, true)], &p);
    assert_eq!((t.len, t.packet.len()), (1500, QUOTE6));
    assert_eq!(t.packet, p[..QUOTE6]);
    // The tap copies at most SNAP octets: the length still comes from
    // the header.
    let f = frame(&[label(100, 64, true)], &p);
    let cut = parse(&ifn("ether1"), &f[..SNAP]).unwrap();
    assert_eq!((cut.len, cut.packet.len()), (1500, QUOTE6));
    // Expired (a time exceeded instead), explicit null, not IP: none.
    assert!(parse(&ifn("ether1"), &frame(&[label(100, 1, true)], &p)).is_none());
    assert!(parse(&ifn("ether1"), &frame(&[label(0, 64, true)], &p)).is_none());
    assert!(parse(&ifn("ether1"), &frame(&[label(100, 64, true)], &[0; 40])).is_none());
}

/// What the kernel takes: the link MTU minus the stack that would leave
/// (`mtu - new_header_size`).
#[test]
fn the_limit_counts_the_labels_that_would_leave() {
    let v = transit(&[]);
    // Swap: 1400 − 4.
    assert_eq!(limit(&[label(100, 64, true)], &v), Ok(1396));
    // PHP with one label: the IP packet leaves bare.
    assert_eq!(limit(&[label(101, 64, true)], &v), Ok(1400));
    // PHP over a VPN label: that one stays.
    assert_eq!(
        limit(&[label(101, 64, false), label(16, 64, true)], &v),
        Ok(1396)
    );
    // Swap and push, over a VPN label: three leave.
    assert_eq!(
        limit(&[label(102, 64, false), label(16, 64, true)], &v),
        Ok(1388)
    );
    // ECMP: the smallest way.
    assert_eq!(limit(&[label(103, 64, true)], &v), Ok(1396));
    assert_eq!(
        limit(&[label(999, 64, true)], &v),
        Err("label has no entry")
    );
    let unknown = View {
        mtu2: None,
        ..transit(&[])
    };
    assert_eq!(
        limit(&[label(100, 64, true)], &unknown),
        Err("MTU of the way out unknown")
    );
}

/// RFC 3032 §3.4 steps 2 and 4.b: what the error reports is the frame
/// payload minus the stack as it came, and never more than what fits.
#[test]
fn the_next_hop_mtu_takes_off_the_stack_that_came() {
    let v = transit(&[]);
    let mtu = |stack: &[MplsLabel]| next_hop_mtu(stack, &v);
    // Swap: the same stack leaves.
    assert_eq!(mtu(&[label(100, 64, true)]), Ok(1396));
    // PHP: 1400 fits, but the ingress pushes its label again.
    assert_eq!(mtu(&[label(101, 64, true)]), Ok(1396));
    assert_eq!(mtu(&[label(101, 64, false), label(16, 64, true)]), Ok(1392));
    // Swap and push: more leaves than came, the limit wins.
    assert_eq!(mtu(&[label(102, 64, false), label(16, 64, true)]), Ok(1388));
    assert_eq!(mtu(&[label(103, 64, true)]), Ok(1396));
    // A packet between the two after a pop is forwarded: no error.
    let p = tcp4("192.0.2.1", "198.51.100.9", 1398, true);
    assert_eq!(
        answer(
            &too_big(&[label(101, 64, true)], &p),
            &transit(&["192.0.2.1"])
        ),
        Err("fits the way out")
    );
}

#[test]
fn ipv4_with_df_gets_fragmentation_needed_with_the_mtu_and_the_stack() {
    let p = tcp4("192.0.2.1", "198.51.100.9", 1500, true);
    let t = too_big(&[label(100, 64, true)], &p);
    let a = answer(&t, &transit(&["192.0.2.1"])).unwrap();
    assert_eq!(a.delivery, Delivery::Ip);
    assert_eq!(a.to, ip("192.0.2.1"));
    let pkt = &a.packet;
    assert_eq!((pkt[0], pkt[8], pkt[9]), (0x45, 255, 1));
    assert_eq!(icmp_ext::checksum(&pkt[..20]), 0, "IP header checksum");
    assert_eq!(&pkt[12..16], &[10, 0, 12, 2], "from the incoming link");
    let icmp = &pkt[20..];
    assert_eq!(icmp_ext::checksum(icmp), 0, "ICMP checksum");
    // RFC 792 type 3 code 4; RFC 4884 §4.1 length 32 words at octet 5;
    // RFC 1191 §4 Next-Hop MTU at octets 6–7.
    assert_eq!(&icmp[..2], &[3, 4]);
    assert_eq!(icmp[5], 32);
    assert_eq!(u16::from_be_bytes([icmp[6], icmp[7]]), 1396);
    assert_eq!(&icmp[8..8 + QUOTE], &p[..QUOTE]);
    assert_eq!(
        icmp_ext::mpls_labels(icmp, false),
        vec![label(100, 64, true)]
    );
}

#[test]
fn what_fits_or_has_no_df_gets_nothing() {
    let v = transit(&["192.0.2.1"]);
    let one = [label(100, 64, true)];
    // Exactly the limit fits (`skb->len <= mtu`).
    let fits = tcp4("192.0.2.1", "198.51.100.9", 1396, true);
    assert_eq!(answer(&too_big(&one, &fits), &v), Err("fits the way out"));
    let over = tcp4("192.0.2.1", "198.51.100.9", 1397, true);
    assert!(answer(&too_big(&one, &over), &v).is_ok());
    // RFC 3032 §3.4: without DF the LSR may silently discard it.
    let no_df = tcp4("192.0.2.1", "198.51.100.9", 1500, false);
    assert_eq!(
        answer(&too_big(&one, &no_df), &v),
        Err("DF not set (RFC 3032 §3.4: dropped)")
    );
    // The usual rules: not the first fragment, not about an ICMP error.
    let mut frag = tcp4("192.0.2.1", "198.51.100.9", 1500, true);
    frag[7] = 0x10;
    assert_eq!(
        answer(&too_big(&one, &frag), &v),
        Err("not the first fragment")
    );
    let mut err = tcp4("192.0.2.1", "198.51.100.9", 1500, true);
    (err[9], err[20]) = (1, 3);
    assert_eq!(answer(&too_big(&one, &err), &v), Err("about an ICMP error"));
}

#[test]
fn a_vpn_stack_goes_back_along_the_lsp() {
    let p = tcp4("192.0.2.1", "198.51.100.9", 1500, true);
    let stack = [label(100, 64, false), label(16, 64, true)];
    let a = answer(&too_big(&stack, &p), &transit(&["192.0.2.1"])).unwrap();
    let Delivery::Lsp {
        interface,
        stack: out,
        ..
    } = &a.delivery
    else {
        panic!("{:?}", a.delivery)
    };
    assert_eq!(interface.as_str(), "ether2");
    assert_eq!(
        out.iter().map(|l| (l.label, l.ttl)).collect::<Vec<_>>(),
        [(200, 255), (16, 255)]
    );
    let icmp = &a.packet[20..];
    // 1400 − 8: the VPN label stays on.
    assert_eq!(u16::from_be_bytes([icmp[6], icmp[7]]), 1392);
}

#[test]
fn ipv6_gets_packet_too_big_quoting_up_to_the_minimum_mtu() {
    let p = tcp6("2001:db8::1", "2001:db8:9::9", 1500);
    let t = too_big(&[label(100, 64, true)], &p);
    let a = answer(&t, &transit(&["2001:db8::1"])).unwrap();
    let pkt = &a.packet;
    assert_eq!(pkt.len(), 1280, "fits the minimum IPv6 MTU");
    assert_eq!((pkt[6], pkt[7]), (58, 255));
    let icmp = &pkt[40..];
    // RFC 4443 §3.2: type 2 code 0, the MTU in octets 4–7, no extension.
    assert_eq!(&icmp[..2], &[2, 0]);
    assert_eq!(
        u32::from_be_bytes([icmp[4], icmp[5], icmp[6], icmp[7]]),
        1396
    );
    assert_eq!(&icmp[8..], &p[..QUOTE6]);
    let mut pseudo = pkt[8..40].to_vec();
    pseudo.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(icmp);
    assert_eq!(icmp_ext::checksum(&pseudo), 0, "ICMPv6 checksum");
    // RFC 4443 §2.4(e.2): about a multicast destination too.
    let m = tcp6("2001:db8::1", "ff0e::1", 1500);
    assert!(
        answer(
            &too_big(&[label(100, 64, true)], &m),
            &transit(&["2001:db8::1"])
        )
        .is_ok()
    );
}

#[test]
fn small_ipv6_with_a_fragment_header_is_not_answered() {
    // RFC 3032 §3.5 step 4: ≤ 1280 octets with a fragment header is to be
    // fragmented, not answered. A link of 1200 makes 1280 too big.
    let v = View {
        mtu2: Some(1200),
        ..transit(&["2001:db8::1"])
    };
    let mut p = tcp6("2001:db8::1", "2001:db8:9::9", 1280);
    p[6] = 44;
    assert_eq!(
        answer(&too_big(&[label(100, 64, true)], &p), &v),
        Err("IPv6 to fragment (RFC 3032 §3.5)")
    );
    // Behind a destination options header too.
    p[6] = 60;
    (p[40], p[41]) = (44, 0);
    assert!(has_fragment_header(&p));
    // Without one: Packet Too Big.
    p[6] = 6;
    assert!(answer(&too_big(&[label(100, 64, true)], &p), &v).is_ok());
}

proptest! {
    /// Hostile frames: never a panic, any answer bounded.
    #[test]
    fn hostile_frames_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1600)) {
        let view = View { mtu2: Some(68), ..transit(&["192.0.2.1"]) };
        if let Some(t) = parse(&ifn("ether1"), &bytes) {
            prop_assert!(t.packet.len() <= QUOTE6);
            let _ = origin(&t);
            if let Ok(a) = answer(&t, &view) {
                prop_assert!(a.packet.len() <= 1280);
            }
        }
    }
}
