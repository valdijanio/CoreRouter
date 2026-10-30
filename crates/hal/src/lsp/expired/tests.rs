use std::collections::BTreeMap;
use std::str::FromStr;

use proptest::prelude::*;

use super::*;
use crate::mpls::{MplsNexthop, MplsRoute, Origin};

struct View {
    labels: BTreeMap<u32, MplsRoute>,
    routed: Vec<IpAddr>,
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
            vec![ip("fe80::2"), ip("10.0.12.2"), ip("fd00:12::2")]
        } else {
            vec![]
        }
    }
    fn mtu(&self, _: &IfName) -> Option<u16> {
        Some(1500)
    }
}

/// R2 of R1 — R2 — R3: label 100 swaps to 200 towards R3, label 101 pops
/// (PHP) towards R3.
fn transit(routed: &[&str]) -> View {
    let entry = |label: u32, out: Vec<u32>| MplsRoute {
        label,
        origin: Origin::Ldp,
        nexthops: vec![MplsNexthop {
            via: Some(ip("10.0.23.3")),
            interface: Some(ifn("ether2")),
            out_labels: out,
        }],
    };
    View {
        labels: BTreeMap::from([(100, entry(100, vec![200])), (101, entry(101, vec![]))]),
        routed: routed.iter().map(|s| ip(s)).collect(),
    }
}

fn label(label: u32, ttl: u8, bottom: bool) -> MplsLabel {
    MplsLabel {
        label,
        tc: 5,
        bottom,
        ttl,
    }
}

/// A traceroute probe: UDP from `src` to `dst`, port 33435, IP TTL 1.
fn udp4(src: &str, dst: &str, payload: usize) -> Vec<u8> {
    let (IpAddr::V4(s), IpAddr::V4(d)) = (ip(src), ip(dst)) else {
        panic!("IPv4 only")
    };
    let total = 28 + payload;
    let mut p = vec![0x45, 0];
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&[0x12, 0x34, 0, 0, 1, 17, 0, 0]);
    p.extend_from_slice(&s.octets());
    p.extend_from_slice(&d.octets());
    p.extend_from_slice(&[0x80, 0x00, 0x82, 0x9b]);
    p.extend_from_slice(&((8 + payload) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend((0..payload).map(|i| i as u8));
    p
}

fn icmp6_echo(src: &str, dst: &str) -> Vec<u8> {
    let mut p = vec![0x60, 0, 0, 0, 0, 16, 58, 1];
    p.extend_from_slice(&src.parse::<Ipv6Addr>().unwrap().octets());
    p.extend_from_slice(&dst.parse::<Ipv6Addr>().unwrap().octets());
    p.extend_from_slice(&[128, 0, 0, 0, 0, 7, 0, 1]);
    p.extend_from_slice(&[0xaa; 8]);
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

fn expired(stack: &[MplsLabel], ip_packet: &[u8]) -> Expired {
    parse(&ifn("ether1"), &frame(stack, ip_packet)).unwrap()
}

/// The ICMP part of an IPv4 answer, after checking its IP header.
fn icmp4(a: &Icmp, from: &str, to: &str) -> Vec<u8> {
    let p = &a.packet;
    assert_eq!(p[0], 0x45);
    assert_eq!(p[8], 255, "IP TTL");
    assert_eq!(p[9], 1, "ICMP");
    assert_eq!(usize::from(u16::from_be_bytes([p[2], p[3]])), p.len());
    assert_eq!(icmp_ext::checksum(&p[..20]), 0, "IP header checksum");
    assert_eq!(
        IpAddr::from(<[u8; 4]>::try_from(&p[12..16]).unwrap()),
        ip(from)
    );
    assert_eq!(
        IpAddr::from(<[u8; 4]>::try_from(&p[16..20]).unwrap()),
        ip(to)
    );
    let icmp = p[20..].to_vec();
    assert_eq!(icmp_ext::checksum(&icmp), 0, "ICMP checksum");
    icmp
}

#[test]
fn a_frame_parses_only_when_its_top_ttl_expired() {
    let probe = udp4("192.0.2.1", "198.51.100.9", 12);
    let e = expired(&[label(100, 1, true)], &probe);
    assert_eq!(e.stack, vec![label(100, 1, true)]);
    assert_eq!(e.packet, probe);
    assert_eq!(e.interface.as_str(), "ether1");
    assert!(parse(&ifn("ether1"), &frame(&[label(100, 0, true)], &probe)).is_some());
    assert!(parse(&ifn("ether1"), &frame(&[label(100, 2, true)], &probe)).is_none());
    // Only the top label's TTL counts (RFC 3032 §2.4.1).
    let deep = frame(&[label(100, 1, false), label(16, 64, true)], &probe);
    assert_eq!(parse(&ifn("ether1"), &deep).unwrap().stack.len(), 2);
}

#[test]
fn ethernet_padding_and_long_packets_are_cut() {
    // A 40-byte probe padded to the 46-byte Ethernet minimum.
    let probe = udp4("192.0.2.1", "198.51.100.9", 12);
    let mut padded = frame(&[label(100, 1, true)], &probe);
    padded.extend_from_slice(&[0xee; 10]);
    assert_eq!(parse(&ifn("ether1"), &padded).unwrap().packet, probe);
    // A big one: only what is quoted is kept.
    let big = udp4("192.0.2.1", "198.51.100.9", 1400);
    assert_eq!(expired(&[label(100, 1, true)], &big).packet, big[..QUOTE]);
}

#[test]
fn malformed_frames_are_none() {
    let probe = udp4("192.0.2.1", "198.51.100.9", 12);
    let ifc = ifn("ether1");
    // No bottom of stack.
    assert!(parse(&ifc, &[0, 0x64, 0x00, 0x01]).is_none());
    // Seventeen labels.
    let mut deep: Vec<MplsLabel> = (0..17).map(|i| label(100 + i, 1, false)).collect();
    if let Some(l) = deep.last_mut() {
        l.bottom = true;
    }
    assert!(parse(&ifc, &frame(&deep, &probe)).is_none());
    // Not IP under the stack.
    assert!(parse(&ifc, &frame(&[label(100, 1, true)], &[0x00; 40])).is_none());
    assert!(parse(&ifc, &frame(&[label(100, 1, true)], &[])).is_none());
}

#[test]
fn one_label_with_a_route_back_goes_by_ip_with_the_rfc_4950_stack() {
    let probe = udp4("192.0.2.1", "198.51.100.9", 12);
    let e = expired(&[label(100, 1, true)], &probe);
    let a = answer(&e, &transit(&["192.0.2.1"])).unwrap();
    assert_eq!(a.delivery, Delivery::Ip);
    assert_eq!(a.to, ip("192.0.2.1"));
    let icmp = icmp4(&a, "10.0.12.2", "192.0.2.1");
    // RFC 792: type 11 code 0; RFC 4884 §4.1: length 32 words at octet 5.
    assert_eq!(&icmp[..2], &[11, 0]);
    assert_eq!(icmp[5], 32);
    // The quote: the probe, zero-padded to 128 octets.
    assert_eq!(&icmp[8..8 + probe.len()], &probe[..]);
    assert!(icmp[8 + probe.len()..8 + QUOTE].iter().all(|b| *b == 0));
    // RFC 4950: the stack as it arrived, read back by our own traceroute.
    assert_eq!(
        icmp_ext::mpls_labels(&icmp, false),
        vec![label(100, 1, true)]
    );
}

#[test]
fn one_label_without_a_route_back_follows_the_lsp() {
    let probe = udp4("192.0.2.1", "198.51.100.9", 12);
    let e = expired(&[label(100, 1, true)], &probe);
    let a = answer(&e, &transit(&[])).unwrap();
    assert_eq!(
        a.delivery,
        Delivery::Lsp {
            interface: ifn("ether2"),
            nexthop: Some(ip("10.0.23.3")),
            stack: vec![MplsLabel {
                label: 200,
                tc: 5,
                bottom: true,
                ttl: 255
            }],
        }
    );
}

#[test]
fn a_vpn_stack_always_follows_the_lsp() {
    // RFC 3032 §2.3.2: the source may be a customer address this LSR does
    // not know, or knows in another table; even with a route, the stack
    // goes back along the LSP.
    let probe = udp4("192.0.2.1", "198.51.100.9", 12);
    let stack = [label(100, 1, false), label(16, 7, true)];
    let a = answer(&expired(&stack, &probe), &transit(&["192.0.2.1"])).unwrap();
    let Delivery::Lsp { stack: out, .. } = &a.delivery else {
        panic!("{:?}", a.delivery)
    };
    assert_eq!(
        out,
        &vec![
            MplsLabel {
                label: 200,
                tc: 5,
                bottom: false,
                ttl: 255
            },
            MplsLabel {
                label: 16,
                tc: 5,
                bottom: true,
                ttl: 255
            },
        ]
    );
    // The object reports the stack as received, inner TTL included.
    let icmp = icmp4(&a, "10.0.12.2", "192.0.2.1");
    assert_eq!(icmp_ext::mpls_labels(&icmp, false), stack.to_vec());
    // PHP: the top label pops, the inner one stays.
    let stack = [label(101, 1, false), label(16, 7, true)];
    let a = answer(&expired(&stack, &probe), &transit(&[])).unwrap();
    let Delivery::Lsp { stack: out, .. } = &a.delivery else {
        panic!("{:?}", a.delivery)
    };
    assert_eq!(
        out,
        &vec![MplsLabel {
            label: 16,
            tc: 5,
            bottom: true,
            ttl: 255
        }]
    );
}

#[test]
fn an_unknown_label_goes_by_ip_or_not_at_all() {
    let probe = udp4("192.0.2.1", "198.51.100.9", 12);
    let stack = [label(999, 1, false), label(16, 7, true)];
    let e = expired(&stack, &probe);
    assert_eq!(
        answer(&e, &transit(&["192.0.2.1"])).unwrap().delivery,
        Delivery::Ip
    );
    assert_eq!(answer(&e, &transit(&[])), Err("no way back to the source"));
}

#[test]
fn no_error_about_errors_fragments_or_group_addresses() {
    let view = transit(&["192.0.2.1"]);
    let one = [label(100, 1, true)];
    // RFC 1812 §4.3.2.7: never about an ICMP error…
    let mut err = udp4("192.0.2.1", "198.51.100.9", 12);
    err[9] = 1;
    err[20] = 11;
    assert_eq!(
        answer(&expired(&one, &err), &view),
        Err("about an ICMP error")
    );
    // …but an echo request is answered (Windows and RouterOS trace so).
    err[20] = 8;
    assert!(answer(&expired(&one, &err), &view).is_ok());
    // Not the first fragment.
    let mut frag = udp4("192.0.2.1", "198.51.100.9", 12);
    frag[7] = 0x10;
    assert_eq!(
        answer(&expired(&one, &frag), &view),
        Err("not the first fragment")
    );
    // Multicast destination, unspecified or broadcast source.
    let m = udp4("192.0.2.1", "239.1.1.1", 12);
    assert!(answer(&expired(&one, &m), &view).is_err());
    let z = udp4("0.0.0.0", "198.51.100.9", 12);
    assert!(answer(&expired(&one, &z), &view).is_err());
    let b = udp4("255.255.255.255", "198.51.100.9", 12);
    assert!(answer(&expired(&one, &b), &view).is_err());
    // A TTL that did not expire is not an error.
    let mut e = expired(&one, &udp4("192.0.2.1", "198.51.100.9", 12));
    e.stack[0].ttl = 9;
    assert_eq!(answer(&e, &view), Err("TTL not expired"));
}

#[test]
fn no_address_on_the_link_means_the_view_picks_one() {
    let probe = udp4("192.0.2.1", "198.51.100.9", 12);
    let mut e = expired(&[label(100, 1, true)], &probe);
    e.interface = ifn("ether9");
    assert_eq!(
        answer(&e, &transit(&["192.0.2.1"])),
        Err("no address to send from")
    );
}

#[test]
fn ipv6_gets_icmpv6_time_exceeded_with_the_pseudo_header_checksum() {
    let probe = icmp6_echo("2001:db8::1", "2001:db8:9::9");
    let e = expired(&[label(100, 1, true)], &probe);
    let a = answer(&e, &transit(&["2001:db8::1"])).unwrap();
    assert_eq!(a.delivery, Delivery::Ip);
    let p = &a.packet;
    assert_eq!(p[0] >> 4, 6);
    assert_eq!(p[6], 58);
    assert_eq!(p[7], 255, "hop limit");
    assert_eq!(usize::from(u16::from_be_bytes([p[4], p[5]])), p.len() - 40);
    // A global address of the link, not the link-local one.
    assert_eq!(
        &p[8..24],
        &"fd00:12::2".parse::<Ipv6Addr>().unwrap().octets()
    );
    let icmp = &p[40..];
    // RFC 4443 §3.3: type 3 code 0; RFC 4884 §4.5: 16 words at octet 4.
    assert_eq!(&icmp[..2], &[3, 0]);
    assert_eq!(icmp[4], 16);
    let mut pseudo = p[8..40].to_vec();
    pseudo.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(icmp);
    assert_eq!(icmp_ext::checksum(&pseudo), 0, "ICMPv6 checksum");
    assert_eq!(icmp_ext::mpls_labels(icmp, true), vec![label(100, 1, true)]);
    // An ICMPv6 error is not answered.
    let mut err = probe.clone();
    err[40] = 1;
    assert_eq!(
        answer(
            &expired(&[label(100, 1, true)], &err),
            &transit(&["2001:db8::1"])
        ),
        Err("about an ICMP error")
    );
}

proptest! {
    /// Hostile frames: never a panic, and any answer is a well-formed IP
    /// packet within bounds.
    #[test]
    fn hostile_frames_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        let view = transit(&["192.0.2.1"]);
        if let Some(e) = parse(&ifn("ether1"), &bytes) {
            prop_assert!(e.packet.len() <= QUOTE);
            if let Ok(a) = answer(&e, &view) {
                prop_assert!(a.packet.len() <= 40 + 8 + QUOTE + 8 + 4 * MAX_STACK);
            }
        }
    }
}
