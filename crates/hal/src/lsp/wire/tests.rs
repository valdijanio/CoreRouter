use super::*;
use proptest::prelude::*;

/// RFC 8029 §3, second figure: a Target FEC Stack with an LDP IPv4 FEC
/// and a VPN IPv4 prefix (RD 8 octets + prefix + length = 13): sub-TLVs
/// padded to 4 octets, so the outer Length is 32.
#[test]
fn rfc_8029_fec_stack_example() {
    let vpn = {
        let mut v = vec![0, 0, 0xfd, 0xe8, 0, 0, 0, 1]; // an RD
        v.extend_from_slice(&[203, 0, 113, 0, 24]);
        v
    };
    let fecs = vec![
        Fec::Ldp("192.0.2.1/32".parse().unwrap()),
        Fec::Other {
            kind: 6,
            value: vpn.clone(),
        },
    ];
    let mut e = Echo::request(1, 1, fecs.clone());
    e.sent = (1, 2);
    let b = encode(&e);
    let tlv = &b[HEADER_LEN..];
    assert_eq!(&tlv[..4], &[0, 1, 0, 32], "FEC TLV type 1, length 32");
    // Sub-type 1, length 5, prefix, length, MBZ.
    assert_eq!(&tlv[4..16], &[0, 1, 0, 5, 192, 0, 2, 1, 32, 0, 0, 0]);
    // Sub-type 6, length 13, padded to 16.
    assert_eq!(&tlv[16..20], &[0, 6, 0, 13]);
    assert_eq!(&tlv[20..33], vpn.as_slice());
    assert_eq!(&tlv[33..36], &[0, 0, 0]);
    assert_eq!(tlv.len(), 36);
    let back = parse(&b).unwrap();
    assert_eq!(back.fec_stack, Some(fecs));
    assert_eq!(back, e);
}

#[test]
fn the_header_is_32_octets_in_rfc_order() {
    let mut e = Echo::request(0xAABBCCDD, 7, vec![Fec::Nil { label: 0 }]);
    e.flags = FLAG_VALIDATE;
    e.sent = ntp(1_700_000_000, 500_000_000);
    let b = encode(&e);
    assert_eq!(&b[..8], &[0, 1, 0, 1, 1, 2, 0, 0]);
    assert_eq!(&b[8..12], &[0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(&b[12..16], &[0, 0, 0, 7]);
    // NTP: 1970 + 2 208 988 800 s; half a second is 2^31.
    assert_eq!(e.sent, (3_908_988_800, 1 << 31));
    assert_eq!(ids(&b), Some((0xAABBCCDD, 7)));
    assert_eq!(parse(&b[..31]), Err(WireError::Short));
    let mut v2 = b.clone();
    v2[1] = 2;
    assert_eq!(parse(&v2), Err(WireError::Version(2)));
}

#[test]
fn ddmap_with_label_stack_round_trips() {
    let d = Ddmap {
        mtu: 1500,
        address: DsAddress::V4 {
            addr: "10.0.0.2".parse().unwrap(),
            iface: "10.0.0.2".parse().unwrap(),
        },
        flags: DS_FLAG_IF_LABEL_STACK,
        return_code: 0,
        return_subcode: 0,
        labels: vec![DsLabel {
            label: 17,
            tc: 0,
            bottom: true,
            protocol: PROTO_LDP,
        }],
        other: vec![],
    };
    let mut e = Echo::request(1, 2, vec![Fec::Ldp("10.255.0.1/32".parse().unwrap())]);
    e.ddmaps.push(d.clone());
    let b = encode(&e);
    // FEC TLV (4 + 12) after the header, then the DDMAP.
    let ddmap = &b[HEADER_LEN + 16..];
    assert_eq!(&ddmap[..4], &[0, 20, 0, 24]);
    // MTU 1500, type 1, flags I.
    assert_eq!(&ddmap[4..8], &[0x05, 0xdc, 1, 2]);
    // RC, RSC, sub-TLV length 8 (label stack sub-TLV: 4 + 4).
    assert_eq!(&ddmap[16..20], &[0, 0, 0, 8]);
    // Label 17 << 12 | S, protocol LDP.
    assert_eq!(&ddmap[20..28], &[0, 2, 0, 4, 0x00, 0x01, 0x11, 3]);
    assert_eq!(parse(&b).unwrap().ddmaps, vec![d]);
}

/// Errata 8788: an unnumbered IPv6 DDMAP is 16 octets of router id and 4
/// of interface index (K = 28 with the fixed fields).
#[test]
fn ipv6_unnumbered_uses_a_4_octet_index() {
    let d = Ddmap {
        mtu: 9000,
        address: DsAddress::V6Unnumbered {
            addr: "2001:db8::2".parse().unwrap(),
            index: 5,
        },
        flags: 0,
        return_code: 0,
        return_subcode: 0,
        labels: vec![],
        other: vec![],
    };
    let mut e = Echo::request(1, 2, vec![Fec::Ldp("2001:db8::2/128".parse().unwrap())]);
    e.ddmaps.push(d.clone());
    let b = encode(&e);
    // FEC TLV: 4 + (4 + 17, padded to 20) = 28 octets.
    let ddmap = &b[HEADER_LEN + 28..];
    assert_eq!(u16::from_be_bytes([ddmap[2], ddmap[3]]), 4 + 20 + 4);
    assert_eq!(parse(&b).unwrap().ddmaps, vec![d]);
}

#[test]
fn unknown_mandatory_tlvs_are_kept_and_optional_ones_ignored() {
    let mut b = encode(&Echo::request(1, 1, vec![Fec::Nil { label: 0 }]));
    b.extend_from_slice(&[0x80, 0x01, 0, 1, 9, 0, 0, 0]); // optional
    b.extend_from_slice(&[0x00, 0x63, 0, 2, 1, 2, 0, 0]); // mandatory, 99
    let e = parse(&b).unwrap();
    assert_eq!(e.unknown, vec![0x00, 0x63, 0, 2, 1, 2, 0, 0]);
}

#[test]
fn hostile_lengths_are_errors() {
    let mut b = encode(&Echo::request(1, 1, vec![]));
    b.truncate(HEADER_LEN);
    b.extend_from_slice(&[0, 1, 0xff, 0xff, 0, 0]);
    assert_eq!(parse(&b), Err(WireError::Truncated(1)));
    // A FEC sub-TLV claiming more than its parent holds.
    let mut b = encode(&Echo::request(1, 1, vec![]));
    b.truncate(HEADER_LEN);
    b.extend_from_slice(&[0, 1, 0, 8, 0, 1, 0, 40, 10, 0, 0, 1]);
    assert_eq!(parse(&b), Err(WireError::Malformed(TLV_FEC_STACK)));
    // A prefix length past 32.
    let mut b = encode(&Echo::request(1, 1, vec![]));
    b.truncate(HEADER_LEN);
    b.extend_from_slice(&[0, 1, 0, 12, 0, 1, 0, 5, 10, 0, 0, 1, 33, 0, 0, 0]);
    assert_eq!(parse(&b), Err(WireError::Malformed(TLV_FEC_STACK)));
    // Too many TLVs.
    let mut b = encode(&Echo::request(1, 1, vec![]));
    for _ in 0..=MAX_TLVS {
        b.extend_from_slice(&[0x80, 0, 0, 0]);
    }
    assert_eq!(parse(&b), Err(WireError::TooMany));
}

#[test]
fn every_code_has_a_text_and_a_letter() {
    for c in 0..=16u8 {
        assert!(!describe(c, 1).is_empty());
    }
    assert_eq!(letter(code::EGRESS), '!');
    assert_eq!(letter(code::LABEL_SWITCHED), 'L');
    assert!(describe(code::NO_LABEL_ENTRY, 2).ends_with("stack-depth 2"));
}

fn arb_fec() -> impl Strategy<Value = Fec> {
    prop_oneof![
        (any::<u32>(), 0u8..=32).prop_map(|(a, l)| Fec::Ldp(
            IpNet::V4(Ipv4Net::new(Ipv4Addr::from(a), l).unwrap()).trunc()
        )),
        (any::<u128>(), 0u8..=128).prop_map(|(a, l)| Fec::Generic(
            IpNet::V6(Ipv6Net::new(Ipv6Addr::from(a), l).unwrap()).trunc()
        )),
        (0u32..0x10_0000).prop_map(|label| Fec::Nil { label }),
    ]
}

fn arb_ddmap() -> impl Strategy<Value = Ddmap> {
    (
        any::<u16>(),
        any::<u32>(),
        any::<u8>(),
        proptest::collection::vec((0u32..0x10_0000, 0u8..8, any::<bool>(), any::<u8>()), 0..4),
    )
        .prop_map(|(mtu, a, rc, labels)| Ddmap {
            mtu,
            address: DsAddress::V4Unnumbered {
                addr: Ipv4Addr::from(a),
                index: a,
            },
            flags: 0,
            return_code: rc,
            return_subcode: 1,
            labels: labels
                .into_iter()
                .map(|(label, tc, bottom, protocol)| DsLabel {
                    label,
                    tc,
                    bottom,
                    protocol,
                })
                .collect(),
            other: vec![],
        })
}

proptest! {
    /// Hostile input never panics; what parses encodes back to something
    /// that parses the same.
    #[test]
    fn garbage_never_panics(b in proptest::collection::vec(any::<u8>(), 0..600)) {
        if let Ok(e) = parse(&b) {
            let again = parse(&encode(&e));
            prop_assert!(again.is_ok());
        }
        let _ = ids(&b);
    }

    #[test]
    fn a_valid_header_with_garbage_tlvs_never_panics(
        tail in proptest::collection::vec(any::<u8>(), 0..400)
    ) {
        let mut b = encode(&Echo::request(1, 1, vec![]));
        b.truncate(HEADER_LEN);
        b.extend_from_slice(&tail);
        let _ = parse(&b);
    }

    #[test]
    fn messages_round_trip(
        handle in any::<u32>(), seq in any::<u32>(), flags in 0u16..8,
        fecs in proptest::collection::vec(arb_fec(), 0..4),
        ddmaps in proptest::collection::vec(arb_ddmap(), 0..3),
        pad in proptest::option::of(proptest::collection::vec(1u8..3, 1..40)),
        tos in proptest::option::of(any::<u8>()),
    ) {
        let mut e = Echo::request(handle, seq, fecs);
        e.flags = flags;
        e.ddmaps = ddmaps;
        e.pad = pad;
        e.reply_tos = tos;
        prop_assert_eq!(parse(&encode(&e)), Ok(e));
    }
}
