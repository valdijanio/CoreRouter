use super::*;

fn ll(last: u16) -> Ipv6Addr {
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, last)
}

fn ra_cfg() -> RaConfig {
    RaConfig {
        managed: false,
        other: true,
        mtu: Some(1492),
        prefixes: vec![PrefixInfo {
            prefix: "2001:db8:0:7::".parse().unwrap(),
            len: 64,
            on_link: true,
            autonomous: true,
            valid: 86_400,
            preferred: 14_400,
        }],
        rdnss: vec![
            "2001:db8::53".parse().unwrap(),
            "2001:db8::54".parse().unwrap(),
        ],
        dnssl: vec!["isp.example".into()],
        dns_lifetime: 1800,
        ..RaConfig::default()
    }
}

#[test]
fn rfc5072_5_link_local_from_the_interface_identifier() {
    let a = link_local([0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55]);
    assert_eq!(a, "fe80::211:22ff:fe33:4455".parse::<Ipv6Addr>().unwrap());
    assert_eq!(iid_of(a), [0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55]);
    let g = with_iid("2001:db8:1:2::".parse().unwrap(), iid_of(a));
    assert_eq!(
        g,
        "2001:db8:1:2:211:22ff:fe33:4455"
            .parse::<Ipv6Addr>()
            .unwrap()
    );
}

#[test]
fn rfc5453_reserved_identifiers_are_never_proposed() {
    assert!(is_reserved_iid([0; 8]));
    assert!(is_reserved_iid([0x02, 0, 0x5e, 0xff, 0xfe, 0, 0x52, 0x12]));
    assert!(!is_reserved_iid([0x02, 0, 0x5e, 0xff, 0xfe, 0, 0x52, 0x13]));
    assert!(is_reserved_iid([
        0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80
    ]));
    assert!(!is_reserved_iid([0xff; 8]));
    assert!(!is_reserved_iid([
        0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
    ]));
}

#[test]
fn rfc8064_identifier_is_stable_per_line_and_opaque() {
    let key = [7u8; 32];
    let v = Vlans {
        outer: 100,
        inner: 0,
        outer_tpid: 0,
    };
    let mac = Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let a = stable_iid(&key, 3, v, mac, IidRole::Peer);
    // Same line, same value (after a reconnect, after a restart).
    assert_eq!(a, stable_iid(&key, 3, v, mac, IidRole::Peer));
    // Not the modified EUI-64 of the MAC (RFC 8064 §1: that leaks it).
    assert_ne!(a, [0x02, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55]);
    // Another line, role, port or secret: another value.
    let other = Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x56]);
    assert_ne!(a, stable_iid(&key, 3, v, other, IidRole::Peer));
    assert_ne!(a, stable_iid(&key, 3, v, mac, IidRole::Local));
    assert_ne!(a, stable_iid(&key, 4, v, mac, IidRole::Peer));
    assert_ne!(a, stable_iid(&[8; 32], 3, v, mac, IidRole::Peer));
    let v2 = Vlans { outer: 101, ..v };
    assert_ne!(a, stable_iid(&key, 3, v2, mac, IidRole::Peer));
    assert!(!is_reserved_iid(a));
}

#[test]
fn rfc8200_8_1_checksum_verifies_to_zero() {
    let mut p = Vec::new();
    router_advert(&mut p, ll(1), ALL_NODES, &ra_cfg());
    let h = parse_ipv6(&p).unwrap();
    assert_eq!(checksum(h.src, h.dst, next::ICMPV6, h.payload), 0);
    // Odd length data: the last byte is the high half of a padded word.
    let mut u = Vec::new();
    udp6(&mut u, ll(1), ll(2), 546, 547, &[1, 2, 3]);
    let h = parse_ipv6(&u).unwrap();
    assert_eq!(h.payload.len() % 2, 1);
    assert_eq!(checksum(h.src, h.dst, next::UDP, h.payload), 0);
}

#[test]
fn rfc4861_4_2_router_advertisement_layout() {
    let mut p = Vec::new();
    router_advert(&mut p, ll(1), ALL_NODES, &ra_cfg());
    // IPv6: hop limit 255 (§4.2: "Hop Limit 255"), next header 58.
    assert_eq!(p[0] >> 4, 6);
    assert_eq!(p[6], next::ICMPV6);
    assert_eq!(p[7], 255);
    let m = &p[40..];
    assert_eq!(m[0], icmp::ROUTER_ADVERT);
    assert_eq!(m[1], 0);
    assert_eq!(m[4], 64);
    assert_eq!(m[5], 0x40, "O set, M clear");
    assert_eq!(u16::from_be_bytes([m[6], m[7]]), 1800);
    // MTU option (§4.6.4): type 5, length 1.
    assert_eq!(&m[16..20], &[5, 1, 0, 0]);
    assert_eq!(u32::from_be_bytes([m[20], m[21], m[22], m[23]]), 1492);
    // PIO (§4.6.2): type 3, length 4, /64, L|A.
    assert_eq!(&m[24..28], &[3, 4, 64, 0xc0]);
    // RDNSS (RFC 8106 §5.1): length 1 + 2 × 2 = 5.
    let r = &m[56..];
    assert_eq!(&r[..4], &[25, 5, 0, 0]);
    assert_eq!(u32::from_be_bytes([r[4], r[5], r[6], r[7]]), 1800);
    // DNSSL (§5.2): padded to 8 octets.
    let s = &m[56 + 40..];
    assert_eq!(s[0], 31);
    assert_eq!((usize::from(s[1]) * 8) % 8, 0);
    assert_eq!(&s[8..21], b"\x03isp\x07example\x00");
    assert_eq!(m.len(), 56 + 40 + usize::from(s[1]) * 8);
}

#[test]
fn ra_round_trips_through_the_reader() {
    let mut p = Vec::new();
    let cfg = ra_cfg();
    router_advert(&mut p, ll(1), ll(9), &cfg);
    let ra = parse_ra(&p).unwrap();
    assert_eq!(ra.src, ll(1));
    assert!(ra.other && !ra.managed);
    assert_eq!(ra.mtu, Some(1492));
    assert_eq!(ra.prefixes, cfg.prefixes);
    assert_eq!(ra.rdnss, cfg.rdnss);
    assert_eq!(ra.dns_lifetime, Some(1800));
}

#[test]
fn rfc4861_4_6_2_preferred_never_above_valid_and_prefix_truncated() {
    let mut cfg = ra_cfg();
    cfg.prefixes[0].preferred = 99_999;
    cfg.prefixes[0].prefix = "2001:db8:0:7::1".parse().unwrap();
    let mut p = Vec::new();
    router_advert(&mut p, ll(1), ALL_NODES, &cfg);
    let ra = parse_ra(&p).unwrap();
    assert_eq!(ra.prefixes[0].preferred, 86_400);
    assert_eq!(
        ra.prefixes[0].prefix,
        "2001:db8:0:7::".parse::<Ipv6Addr>().unwrap()
    );
}

#[test]
fn ra_drops_bad_names_and_extra_servers() {
    let mut cfg = ra_cfg();
    cfg.rdnss = (1..=20)
        .map(|i| Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i))
        .collect();
    cfg.dnssl = vec![
        "".into(),
        "a..b".into(),
        "x".repeat(64),
        "ok.example".into(),
    ];
    let mut p = Vec::new();
    router_advert(&mut p, ll(1), ALL_NODES, &cfg);
    assert!(p.len() <= MAX_BUILT);
    let ra = parse_ra(&p).unwrap();
    assert_eq!(ra.rdnss.len(), MAX_DNS);
    assert!(ra.dnssl_raw.starts_with(b"\x02ok\x07example\x00"));
}

#[test]
fn rfc4861_6_1_1_router_solicitation_checks() {
    let mut p = Vec::new();
    router_solicit(&mut p, ll(5));
    assert_eq!(classify(&p), Inbound::RouterSolicit { src: ll(5) });
    // Hop limit not 255: routed from elsewhere, discarded.
    let mut q = p.clone();
    q[7] = 254;
    assert!(matches!(classify(&q), Inbound::Invalid(_)));
    // Bad checksum.
    let mut q = p.clone();
    q[42] ^= 1;
    assert!(matches!(classify(&q), Inbound::Invalid(_)));
    // Code not 0 (checksum recomputed so only the code is wrong).
    let mut q = Vec::new();
    let mut body = vec![icmp::ROUTER_SOLICIT, 1, 0, 0, 0, 0, 0, 0];
    let c = checksum(ll(5), ALL_ROUTERS, next::ICMPV6, &body);
    body[2..4].copy_from_slice(&c.to_be_bytes());
    ipv6_header(&mut q, ll(5), ALL_ROUTERS, next::ICMPV6, 255, body.len());
    q.extend_from_slice(&body);
    assert_eq!(classify(&q), Inbound::Invalid("ND code is not 0"));
}

fn icmp_packet(src: Ipv6Addr, dst: Ipv6Addr, kind: u8, body: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    icmp6(&mut p, src, dst, kind, body);
    p
}

#[test]
fn rfc4861_6_1_1_unspecified_source_without_link_layer_option() {
    let with = icmp_packet(
        Ipv6Addr::UNSPECIFIED,
        ALL_ROUTERS,
        icmp::ROUTER_SOLICIT,
        &[0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0],
    );
    assert!(matches!(classify(&with), Inbound::Invalid(_)));
    let zero_len = icmp_packet(
        ll(5),
        ALL_ROUTERS,
        icmp::ROUTER_SOLICIT,
        &[0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
    );
    assert_eq!(
        classify(&zero_len),
        Inbound::Invalid("ND option of length 0")
    );
}

#[test]
fn rfc4861_7_1_1_neighbor_solicitation_checks() {
    let target = ll(1);
    let mut body = vec![0u8; 4];
    body.extend_from_slice(&target.octets());
    let ns = icmp_packet(ll(5), ll(1), icmp::NEIGHBOR_SOLICIT, &body);
    assert_eq!(
        classify(&ns),
        Inbound::NeighborSolicit { src: ll(5), target }
    );
    // DAD (from ::) to the solicited-node group is fine; to a unicast is not.
    let sn = "ff02::1:ff00:1".parse().unwrap();
    let dad = icmp_packet(Ipv6Addr::UNSPECIFIED, sn, icmp::NEIGHBOR_SOLICIT, &body);
    assert!(matches!(classify(&dad), Inbound::NeighborSolicit { .. }));
    let bad = icmp_packet(Ipv6Addr::UNSPECIFIED, ll(1), icmp::NEIGHBOR_SOLICIT, &body);
    assert!(matches!(classify(&bad), Inbound::Invalid(_)));
    let mut mbody = vec![0u8; 4];
    mbody.extend_from_slice(&ALL_NODES.octets());
    let m = icmp_packet(ll(5), ll(1), icmp::NEIGHBOR_SOLICIT, &mbody);
    assert_eq!(classify(&m), Inbound::Invalid("NS target is multicast"));
}

#[test]
fn rfc4443_echo_reply_echoes_identifier_and_data() {
    let req = icmp_packet(ll(5), ll(1), icmp::ECHO_REQUEST, &[0, 7, 0, 1, b'h', b'i']);
    let Inbound::EchoRequest { src, dst, body } = classify(&req) else {
        panic!("not an echo request");
    };
    let mut rep = Vec::new();
    echo_reply(&mut rep, dst, src, body);
    let h = parse_ipv6(&rep).unwrap();
    assert_eq!(h.payload[0], icmp::ECHO_REPLY);
    assert_eq!(&h.payload[4..], &[0, 7, 0, 1, b'h', b'i']);
    assert_eq!(checksum(h.src, h.dst, next::ICMPV6, h.payload), 0);
}

#[test]
fn rfc8415_7_2_dhcpv6_to_the_server_port() {
    let mut p = Vec::new();
    udp6(
        &mut p,
        ll(5),
        ALL_DHCP,
        DHCP6_CLIENT_PORT,
        DHCP6_SERVER_PORT,
        b"\x01abc",
    );
    assert_eq!(
        classify(&p),
        Inbound::Dhcp6 {
            src: ll(5),
            dst: ALL_DHCP,
            src_port: DHCP6_CLIENT_PORT,
            payload: b"\x01abc",
        }
    );
    // RFC 8200 §8.1: UDP checksum 0 is invalid over IPv6.
    let mut z = p.clone();
    z[46] = 0;
    z[47] = 0;
    assert!(matches!(classify(&z), Inbound::Invalid(_)));
    // Another port: not ours.
    let mut o = Vec::new();
    udp6(&mut o, ll(5), ll(1), 1000, 53, b"x");
    assert_eq!(classify(&o), Inbound::Other);
}

#[test]
fn header_length_is_bounded_by_payload_length() {
    let mut p = Vec::new();
    router_solicit(&mut p, ll(5));
    p.extend_from_slice(&[0xaa; 10]); // trailing pad (Ethernet minimum)
    assert!(matches!(classify(&p), Inbound::RouterSolicit { .. }));
    p.truncate(44);
    assert!(matches!(parse_ipv6(&p), Err(WireError::BadLength { .. })));
    assert!(matches!(
        parse_ipv6(&[0x60; 10]),
        Err(WireError::Truncated { .. })
    ));
    assert!(matches!(
        parse_ipv6(&[0x40; 40]),
        Err(WireError::Malformed(_))
    ));
}

#[test]
fn rfc4861_6_2_4_initial_then_spread_and_rs_rate_limited() {
    let mut t = RaTimer::new(1000);
    assert_eq!(t.next_at, 1000, "first RA at once");
    let (min, max) = (200_000, 600_000);
    t.sent(1000, 123_456_789, min, max);
    assert!(t.next_at - 1000 <= MAX_INITIAL_RTR_ADVERT_INTERVAL_MS);
    t.sent(t.next_at, 42, min, max);
    assert!(t.next_at - t.last_sent.unwrap() <= MAX_INITIAL_RTR_ADVERT_INTERVAL_MS);
    // The third initial one was sent: from now on Min..Max.
    let at = t.next_at;
    t.sent(at, 987_654_321, min, max);
    let gap = t.next_at - at;
    assert!((min..max).contains(&gap), "{gap}");
    t.sent(t.next_at, 1, min, max);
    // §6.2.6: not two RAs within MIN_DELAY_BETWEEN_RAS.
    let last = t.last_sent.unwrap();
    assert_eq!(t.solicited_at(last + 1), last + MIN_DELAY_BETWEEN_RAS_MS);
    assert_eq!(t.solicited_at(last + 10_000), last + 10_000);
}

#[test]
fn icmp_ra_carries_sllao_and_preference() {
    // G3.9ha: the Ethernet sender's RA, as a raw socket sends it.
    let cfg = RaConfig {
        sllao: Some([0x02, 0, 0, 0, 0, 0x14]),
        preference: 0b01,
        reachable_ms: 30_000,
        ..ra_cfg()
    };
    let m = router_advert_icmp(&cfg);
    assert_eq!(
        &m[..4],
        &[icmp::ROUTER_ADVERT, 0, 0, 0],
        "checksum left to the kernel"
    );
    // RFC 4191 §2.2: Prf = 01 (high) in bits 3-4, O set.
    assert_eq!(m[5], 0x40 | 0b01 << 3);
    // RFC 4861 §4.6.1: type 1, length 1 (8 octets), the MAC.
    assert_eq!(&m[16..24], &[1, 1, 0x02, 0, 0, 0, 0, 0x14]);
    let ra = parse_ra_icmp(ll(1), &m).unwrap();
    assert_eq!(ra.sllao, Some([0x02, 0, 0, 0, 0, 0x14]));
    assert_eq!(ra.preference, 0b01);
    assert_eq!(ra.reachable_ms, 30_000);
    assert_eq!(ra.prefixes, cfg.prefixes);
    // The same RA as a whole packet (PPP) has the same body.
    let mut p = Vec::new();
    router_advert(&mut p, ll(1), ALL_NODES, &cfg);
    assert_eq!(&p[IPV6_HLEN + 4..], &m[4..]);
    // 10 is reserved (RFC 4191 §2.2): sent as medium.
    let m = router_advert_icmp(&RaConfig {
        preference: 0b10,
        ..ra_cfg()
    });
    assert_eq!((m[5] >> 3) & 0b11, 0);
}

#[test]
fn rs_validation_of_rfc_4861_6_1_1() {
    let host = ll(9);
    let mut rs = vec![icmp::ROUTER_SOLICIT, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(parse_rs_icmp(host, 255, &rs).unwrap().sllao, None);
    rs.extend_from_slice(&[1, 1, 2, 0, 0, 0, 0, 9]);
    assert_eq!(
        parse_rs_icmp(host, 255, &rs).unwrap().sllao,
        Some([2, 0, 0, 0, 0, 9])
    );
    // Hop limit not 255: it crossed a router.
    assert!(parse_rs_icmp(host, 254, &rs).is_err());
    // From :: with a link-layer address.
    assert!(parse_rs_icmp(Ipv6Addr::UNSPECIFIED, 255, &rs).is_err());
    // Zero-length option, code not 0, too short.
    let mut bad = rs.clone();
    bad[9] = 0;
    assert!(parse_rs_icmp(host, 255, &bad).is_err());
    let mut bad = rs.clone();
    bad[1] = 1;
    assert!(parse_rs_icmp(host, 255, &bad).is_err());
    assert!(parse_rs_icmp(host, 255, &rs[..6]).is_err());
    assert!(parse_rs_icmp(host, 255, &[icmp::ROUTER_ADVERT, 0, 0, 0, 0, 0, 0, 0]).is_err());
}
