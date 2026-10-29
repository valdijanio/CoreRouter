//! Short, deterministic fuzzing of the RADIUS receive paths for
//! `cargo xtask ci`; the long run is `cargo fuzz run radius`
//! (docs/fuzzing.md). Seeds and regressions under `fuzz/` replay here.
//! Also the codec's round-trip properties.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::path::Path;

use corerouter_proto_radius::crypto;
use corerouter_proto_radius::fuzz::{packet, text};
use corerouter_proto_radius::packet::{AttrList, Builder, Code, Packet, PushAttr, attr};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};

fn config(cases: u32) -> Config {
    let long = std::env::var("COREROUTER_FUZZ_CASES")
        .ok()
        .and_then(|n| n.parse().ok());
    Config {
        cases: long.unwrap_or(cases),
        rng_seed: if long.is_some() {
            RngSeed::Random
        } else {
            RngSeed::Fixed(0x2865)
        },
        failure_persistence: None,
        ..Config::default()
    }
}

fn corpus(target: &str) -> Vec<(String, Vec<u8>)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz");
    let mut out = Vec::new();
    for kind in ["seeds", "regressions"] {
        let Ok(dir) = std::fs::read_dir(root.join(kind).join(target)) else {
            continue;
        };
        for f in dir.flatten() {
            out.push((
                f.path().display().to_string(),
                std::fs::read(f.path()).unwrap(),
            ));
        }
    }
    out
}

#[test]
fn seeds_and_regressions_replay() {
    let seeds = corpus("radius");
    assert!(seeds.len() >= 5, "fuzz/seeds/radius is missing");
    for (name, data) in seeds {
        packet(&data).unwrap_or_else(|e| panic!("{name}: {e}"));
        text(&data).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

fn code() -> impl Strategy<Value = Code> {
    prop::sample::select(vec![
        Code::AccessRequest,
        Code::AccessAccept,
        Code::AccessReject,
        Code::AccountingRequest,
        Code::AccountingResponse,
        Code::AccessChallenge,
        Code::StatusServer,
        Code::DisconnectRequest,
        Code::CoaRequest,
        Code::CoaAck,
    ])
}

/// Attributes with a bias to the types the receive paths look at.
fn attrs() -> impl Strategy<Value = Vec<(u8, Vec<u8>)>> {
    let typ = prop_oneof![
        prop::sample::select(vec![
            1u8, 2, 3, 4, 8, 24, 26, 33, 44, 55, 60, 69, 80, 87, 97, 101, 241, 245
        ]),
        any::<u8>(),
    ];
    prop::collection::vec((typ, prop::collection::vec(any::<u8>(), 0..64)), 0..12)
}

fn build(code: Code, id: u8, attrs: &[(u8, Vec<u8>)], ma: bool) -> Vec<u8> {
    let mut b = Builder::with_authenticator(code, id, [id; 16]);
    if ma {
        b.message_authenticator().unwrap();
    }
    for (t, v) in attrs {
        b.push(*t, v).unwrap();
    }
    if code.is_request() {
        crypto::sign_request(b, b"fuzz")
    } else {
        crypto::sign_response(b, &[1; 16], b"fuzz")
    }
}

proptest! {
    #![proptest_config(config(2000))]

    #[test]
    fn arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..600)) {
        packet(&data).map_err(TestCaseError::fail)?;
    }

    /// Valid, signed packets with a few bytes changed: past the framing
    /// checks, into the authenticators and attribute decoders.
    #[test]
    fn mutated_valid_packets(
        code in code(), id: u8, attrs in attrs(), ma: bool,
        flips in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..4),
    ) {
        let mut data = build(code, id, &attrs, ma);
        packet(&data).map_err(TestCaseError::fail)?;
        for (i, v) in flips {
            let at = i.index(data.len());
            data[at] ^= v;
        }
        packet(&data).map_err(TestCaseError::fail)?;
    }

    #[test]
    fn text_inputs(s in "\\PC{0,120}") {
        text(s.as_bytes()).map_err(TestCaseError::fail)?;
    }

    /// Builder → parse gives back the same attributes, in order.
    #[test]
    fn attributes_round_trip(code in code(), id: u8, attrs in attrs()) {
        let bytes = build(code, id, &attrs, false);
        let p = Packet::parse(&bytes).unwrap();
        prop_assert_eq!(p.code(), code);
        prop_assert_eq!(p.identifier(), id);
        let got: Vec<(u8, Vec<u8>)> = p.attributes().map(|a| (a.typ, a.value.to_vec())).collect();
        prop_assert_eq!(got, attrs);
    }

    /// Every signed packet verifies with its secret and not with another.
    #[test]
    fn signatures_verify(code in code(), id: u8, attrs in attrs()) {
        // A second Message-Authenticator is invalid by definition.
        let attrs: Vec<_> = attrs.into_iter().filter(|(t, _)| *t != attr::MESSAGE_AUTHENTICATOR).collect();
        let bytes = build(code, id, &attrs, true);
        let p = Packet::parse(&bytes).unwrap();
        let ma_auth = if code.is_request() { crypto::request_ma_auth(&p) } else { [1; 16] };
        prop_assert_eq!(crypto::check_message_authenticator(&p, &ma_auth, b"fuzz"), crypto::MaCheck::Valid);
        prop_assert_ne!(crypto::check_message_authenticator(&p, &ma_auth, b"fuzy"), crypto::MaCheck::Valid);
        if code.has_computed_request_authenticator() {
            prop_assert!(crypto::verify_computed_request(&p, b"fuzz"));
            prop_assert!(!crypto::verify_computed_request(&p, b"fuzy"));
        } else if !code.is_request() {
            prop_assert!(crypto::verify_response(&p, &[1; 16], b"fuzz"));
            prop_assert!(!crypto::verify_response(&p, &[1; 16], b"fuzy"));
        }
    }

    /// RFC 2865 §5.2: hide/unhide; trailing NULs are padding by definition.
    #[test]
    fn user_password_round_trip(
        pw in prop::collection::vec(1u8..=255, 0..=128),
        secret in prop::collection::vec(any::<u8>(), 1..40),
        ra: [u8; 16],
    ) {
        let h = crypto::hide_user_password(&pw, &secret, &ra).unwrap();
        prop_assert_eq!(h.len() % 16, 0);
        prop_assert_eq!(crypto::unhide_user_password(&h, &secret, &ra).unwrap(), pw);
    }

    /// RFC 2868 §3.5 / RFC 2548 §2.4.2.
    #[test]
    fn salt_round_trip(
        plain in prop::collection::vec(any::<u8>(), 0..=239),
        secret in prop::collection::vec(any::<u8>(), 1..40),
        ra: [u8; 16], salt in 0x8000u16..=0xFFFF,
    ) {
        let v = crypto::salt_encrypt(&plain, &secret, &ra, salt.to_be_bytes()).unwrap();
        prop_assert!(v.len() <= 253);
        prop_assert_eq!(crypto::salt_decrypt(&v, &secret, &ra).unwrap(), plain);
    }

    /// Long-Extended values of any size come back whole.
    #[test]
    fn long_extended_round_trip(value in prop::collection::vec(any::<u8>(), 0..1500), ext: u8) {
        let mut l = AttrList::new();
        l.push_long_extended(attr::LONG_EXTENDED_2, ext, &value).unwrap();
        let mut b = Builder::new(Code::AccessAccept, 0);
        b.extend(&l).unwrap();
        let bytes = b.into_unsigned();
        let p = Packet::parse(&bytes).unwrap();
        let got = p.long_extended(attr::LONG_EXTENDED_2, ext).unwrap();
        prop_assert_eq!(got.as_ref(), &value[..]);
    }
}
