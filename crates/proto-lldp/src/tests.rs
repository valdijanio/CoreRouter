use super::*;
use proptest::prelude::*;

fn tlv(t: u8, v: &[u8]) -> Vec<u8> {
    let h = (u16::from(t) << 9) | u16::try_from(v.len()).unwrap();
    [&h.to_be_bytes()[..], v].concat()
}

/// A PDU as a typical managed switch sends it, built byte by byte from the
/// 802.1AB TLV layouts (not with our encoder).
fn switch_pdu() -> Vec<u8> {
    [
        tlv(1, &[4, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        tlv(2, b"\x05gi0/1"),
        tlv(3, &[0, 120]),
        tlv(4, b"uplink"),
        tlv(5, b"sw-core"),
        tlv(6, b"Some Switch OS 1.2"),
        tlv(7, &[0, 0x14, 0, 0x04]),
        tlv(8, &[5, 1, 10, 0, 0, 2, 2, 0, 0, 0, 3, 0]),
        tlv(127, &[0x00, 0x80, 0xC2, 1, 0, 10]),
        tlv(42, b"future"),
        tlv(0, &[]),
        vec![0; 20], // Ethernet padding after End
    ]
    .concat()
}

#[test]
fn decodes_a_switch_pdu() {
    let du = decode(&switch_pdu()).unwrap();
    assert_eq!(
        du.chassis_id,
        ChassisId::Mac([0, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
    assert_eq!(du.chassis_id.to_string(), "00:11:22:33:44:55");
    assert_eq!(du.port_id, PortId::InterfaceName("gi0/1".into()));
    assert_eq!(du.ttl_secs, 120);
    assert_eq!(du.port_description.as_deref(), Some("uplink"));
    assert_eq!(du.system_name.as_deref(), Some("sw-core"));
    assert_eq!(du.system_description.as_deref(), Some("Some Switch OS 1.2"));
    let caps = du.capabilities.unwrap();
    assert_eq!(Capabilities::names(caps.system), ["bridge", "router"]);
    assert_eq!(Capabilities::names(caps.enabled), ["bridge"]);
    assert_eq!(
        du.management_addresses,
        [ManagementAddress::ip("10.0.0.2".parse().unwrap(), 3)]
    );
    assert_eq!(
        du.org_specific,
        [OrgTlv {
            oui: [0x00, 0x80, 0xC2],
            subtype: 1,
            info: vec![0, 10]
        }]
    );
    assert_eq!(
        du.unknown,
        [UnknownTlv {
            tlv_type: 42,
            value: b"future".to_vec()
        }]
    );
    assert!(!du.is_shutdown());
}

#[test]
fn round_trips_through_our_encoder() {
    let du = decode(&switch_pdu()).unwrap();
    assert_eq!(decode(&encode(&du).unwrap()).unwrap(), du);
}

#[test]
fn encodes_the_mandatory_tlvs_byte_exact() {
    let du = Lldpdu::new(
        ChassisId::Mac([2, 0, 0, 0, 0, 1]),
        PortId::InterfaceName("ether1".into()),
        TTL_SECS,
    );
    let want = [
        tlv(1, &[4, 2, 0, 0, 0, 0, 1]),
        tlv(2, b"\x05ether1"),
        tlv(3, &[0, 120]),
        tlv(0, &[]),
    ]
    .concat();
    assert_eq!(encode(&du).unwrap(), want);
}

#[test]
fn end_tlv_is_optional() {
    let pdu = [tlv(1, &[7, b'x']), tlv(2, &[7, b'y']), tlv(3, &[0, 0])].concat();
    let du = decode(&pdu).unwrap();
    assert!(du.is_shutdown());
    assert_eq!(du.chassis_id, ChassisId::Local("x".into()));
}

#[test]
fn rejects_out_of_order_and_missing_mandatory_tlvs() {
    let ttl_first = [tlv(3, &[0, 1]), tlv(1, &[7, b'x']), tlv(2, &[7, b'y'])].concat();
    assert!(matches!(
        decode(&ttl_first),
        Err(DecodeError::OutOfOrder {
            expected: "Chassis ID",
            ..
        })
    ));
    let no_ttl = [tlv(1, &[7, b'x']), tlv(2, &[7, b'y']), tlv(0, &[])].concat();
    assert!(matches!(
        decode(&no_ttl),
        Err(DecodeError::OutOfOrder {
            expected: "Time To Live",
            ..
        })
    ));
    assert_eq!(decode(&[]), Err(DecodeError::Missing("Chassis ID")));
    let dup = [
        tlv(1, &[7, b'x']),
        tlv(2, &[7, b'y']),
        tlv(3, &[0, 1]),
        tlv(1, &[7, b'z']),
    ]
    .concat();
    assert_eq!(decode(&dup), Err(DecodeError::Duplicate("Chassis ID")));
}

#[test]
fn rejects_truncation_and_bad_lengths() {
    let mut pdu = switch_pdu();
    pdu.truncate(5);
    assert!(matches!(
        decode(&pdu),
        Err(DecodeError::TruncatedValue { tlv_type: 1, .. })
    ));
    assert_eq!(decode(&[0x02]), Err(DecodeError::TruncatedHeader(0)));
    let empty_id = [tlv(1, &[4])].concat();
    assert!(matches!(
        decode(&empty_id),
        Err(DecodeError::Malformed { .. })
    ));
    let bad_caps = [
        tlv(1, &[7, b'x']),
        tlv(2, &[7, b'y']),
        tlv(3, &[0, 1]),
        tlv(7, &[0, 1, 0]),
    ]
    .concat();
    assert!(matches!(
        decode(&bad_caps),
        Err(DecodeError::Malformed {
            tlv: "System Capabilities",
            ..
        })
    ));
    assert_eq!(
        decode(&vec![0; MAX_LLDPDU_LEN + 1]),
        Err(DecodeError::TooLong(MAX_LLDPDU_LEN + 1))
    );
}

#[test]
fn malformed_typed_ids_fall_back_to_other() {
    // MAC subtype with 5 bytes, address family 9, invalid UTF-8 name.
    let pdu = [
        tlv(1, &[4, 1, 2, 3, 4, 5]),
        tlv(2, &[5, 0xFF, 0xFE]),
        tlv(3, &[0, 1]),
    ]
    .concat();
    let du = decode(&pdu).unwrap();
    assert_eq!(
        du.chassis_id,
        ChassisId::Other {
            subtype: 4,
            value: vec![1, 2, 3, 4, 5]
        }
    );
    assert_eq!(du.chassis_id.to_string(), "0102030405");
    assert!(matches!(du.port_id, PortId::Other { subtype: 5, .. }));
}

#[test]
fn encoder_enforces_limits() {
    let mut du = Lldpdu::new(
        ChassisId::Local("x".into()),
        PortId::Local("y".into()),
        TTL_SECS,
    );
    du.system_name = Some("n".repeat(MAX_TEXT_LEN + 1));
    assert!(matches!(encode(&du), Err(EncodeError::TooLong { .. })));
    du.system_name = None;
    du.chassis_id = ChassisId::Local(String::new());
    assert!(matches!(encode(&du), Err(EncodeError::Empty { .. })));
    du.chassis_id = ChassisId::Local("x".into());
    du.unknown.push(UnknownTlv {
        tlv_type: 5,
        value: vec![],
    });
    assert_eq!(encode(&du), Err(EncodeError::ReservedType(5)));
    du.unknown.clear();
    du.org_specific = (0..4)
        .map(|_| OrgTlv {
            oui: [0; 3],
            subtype: 0,
            info: vec![0; 500],
        })
        .collect();
    assert!(matches!(encode(&du), Err(EncodeError::PduTooLong(_))));
}

#[test]
fn text_is_cut_on_a_char_boundary() {
    let long = "é".repeat(200); // 400 bytes
    let pdu = [
        tlv(1, &[7, b'x']),
        tlv(2, &[7, b'y']),
        tlv(3, &[0, 1]),
        tlv(5, long.as_bytes()),
    ]
    .concat();
    let name = decode(&pdu).unwrap().system_name.unwrap();
    assert!(name.len() <= MAX_TEXT_LEN);
    assert_eq!(name, "é".repeat(127));
}

// ---------------------------------------------------------------- proptest

fn text_s() -> impl Strategy<Value = String> {
    proptest::string::string_regex("[ -~é]{1,40}").unwrap()
}

fn ip_s() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        any::<[u8; 4]>().prop_map(IpAddr::from),
        any::<[u8; 16]>().prop_map(IpAddr::from),
    ]
}

fn chassis_s() -> impl Strategy<Value = ChassisId> {
    prop_oneof![
        any::<[u8; 6]>().prop_map(ChassisId::Mac),
        ip_s().prop_map(ChassisId::NetworkAddress),
        text_s().prop_map(ChassisId::InterfaceName),
        text_s().prop_map(ChassisId::Local),
        (
            prop_oneof![Just(1u8), Just(2), Just(3), 8u8..],
            prop::collection::vec(any::<u8>(), 1..40)
        )
            .prop_map(|(subtype, value)| ChassisId::Other { subtype, value }),
    ]
}

fn port_s() -> impl Strategy<Value = PortId> {
    prop_oneof![
        text_s().prop_map(PortId::InterfaceAlias),
        any::<[u8; 6]>().prop_map(PortId::Mac),
        ip_s().prop_map(PortId::NetworkAddress),
        text_s().prop_map(PortId::InterfaceName),
        text_s().prop_map(PortId::Local),
        (
            prop_oneof![Just(2u8), Just(6), 8u8..],
            prop::collection::vec(any::<u8>(), 1..40)
        )
            .prop_map(|(subtype, value)| PortId::Other { subtype, value }),
    ]
}

fn mgmt_s() -> impl Strategy<Value = ManagementAddress> {
    let addr = prop_oneof![
        ip_s().prop_map(MgmtAddr::Ip),
        (3u8.., prop::collection::vec(any::<u8>(), 1..=31))
            .prop_map(|(family, value)| MgmtAddr::Other { family, value }),
    ];
    (
        addr,
        any::<u8>(),
        any::<u32>(),
        prop::collection::vec(any::<u8>(), 0..8),
    )
        .prop_map(|(address, if_subtype, if_number, oid)| ManagementAddress {
            address,
            if_subtype,
            if_number,
            oid,
        })
}

prop_compose! {
    fn lldpdu_s()(
        chassis_id in chassis_s(),
        port_id in port_s(),
        ttl_secs in any::<u16>(),
        port_description in proptest::option::of(text_s()),
        system_name in proptest::option::of(text_s()),
        system_description in proptest::option::of(text_s()),
        capabilities in proptest::option::of(any::<(u16, u16)>()
            .prop_map(|(system, enabled)| Capabilities { system, enabled })),
        management_addresses in prop::collection::vec(mgmt_s(), 0..3),
        org_specific in prop::collection::vec(
            (any::<[u8; 3]>(), any::<u8>(), prop::collection::vec(any::<u8>(), 0..20))
                .prop_map(|(oui, subtype, info)| OrgTlv { oui, subtype, info }), 0..3),
        unknown in prop::collection::vec(
            (9u8..=126, prop::collection::vec(any::<u8>(), 0..20))
                .prop_map(|(tlv_type, value)| UnknownTlv { tlv_type, value }), 0..3),
    ) -> Lldpdu {
        Lldpdu {
            chassis_id, port_id, ttl_secs, port_description, system_name,
            system_description, capabilities, management_addresses, org_specific, unknown,
        }
    }
}

/// Byte soup shaped like TLVs (valid headers, random types and values), so
/// the decoder gets past the first header more often than with pure noise.
fn tlv_soup() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        (0u8..=127, prop::collection::vec(any::<u8>(), 0..64)),
        0..12,
    )
    .prop_map(|tlvs| tlvs.iter().flat_map(|(t, v)| tlv(*t, v)).collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = decode(&bytes);
    }

    #[test]
    fn decode_never_panics_on_tlv_soup(mut bytes in tlv_soup(), head in chassis_s()) {
        // Half the time start with a valid Chassis ID to reach deeper code.
        if bytes.len() % 2 == 0 {
            let mut v = tlv(1, &chassis_bytes(&head).unwrap());
            v.extend(tlv(2, &[7, b'p']));
            v.extend(tlv(3, &[0, 9]));
            v.append(&mut bytes);
            bytes = v;
        }
        if let Ok(du) = decode(&bytes) {
            // Whatever decodes re-encodes to the same thing (or is too big).
            if let Ok(again) = encode(&du) {
                prop_assert_eq!(decode(&again).unwrap(), du);
            }
        }
    }

    #[test]
    fn encode_decode_round_trip(du in lldpdu_s()) {
        let bytes = encode(&du).unwrap();
        prop_assert!(bytes.len() <= MAX_ENCODED_LEN);
        prop_assert_eq!(decode(&bytes).unwrap(), du);
    }

    #[test]
    fn decoded_text_respects_limits(len in 0usize..=511, fill in any::<u8>()) {
        let pdu = [
            tlv(1, &[7, b'x']), tlv(2, &[7, b'y']), tlv(3, &[0, 1]),
            tlv(6, &vec![fill; len]),
        ].concat();
        let du = decode(&pdu).unwrap();
        prop_assert!(du.system_description.unwrap().len() <= MAX_TEXT_LEN);
    }
}
