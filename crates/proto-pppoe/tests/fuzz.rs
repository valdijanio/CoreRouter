//! Hostile input, the short deterministic run of the fuzz oracles
//! (`src/fuzz.rs`; the long run is `crates/proto-pppoe/fuzz`, libFuzzer).
//! Random bytes and, more useful, real frames from a lab conversation with
//! bits flipped, bytes cut and lengths rewritten. `PPPOE_FUZZ_CASES=N`
//! raises the case count.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use corerouter_proto_pppoe::fuzz;
use corerouter_proto_pppoe::lab::{Lab, LabConfig};
use corerouter_proto_pppoe::lcp::AuthProto;
use proptest::prelude::*;
use std::sync::OnceLock;

fn cases() -> u32 {
    std::env::var("PPPOE_FUZZ_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512)
}

/// Every frame of a short lab run (all phases, all auth protocols, IPv6CP).
fn corpus() -> &'static [Vec<u8>] {
    static C: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    C.get_or_init(|| {
        fn any(_: &[u8]) -> bool {
            true
        }
        let mut l = Lab::new(LabConfig {
            clients: 4,
            start_spread_ms: 1,
            auth_cycle: vec![
                AuthProto::Pap,
                AuthProto::ChapMd5,
                AuthProto::MsChapV1,
                AuthProto::MsChapV2,
            ],
            ipv6: true,
            tap: Some(any),
            ..LabConfig::default()
        });
        l.start_all();
        l.run_until(15_000);
        assert_eq!(l.clients_up(), 4);
        l.tapped.clone()
    })
}

/// A real frame, mutated.
fn mutated() -> impl Strategy<Value = Vec<u8>> {
    let n = corpus().len();
    (
        0..n,
        proptest::collection::vec((any::<u16>(), any::<u8>(), 0u8..4), 0..8),
        any::<u16>(),
    )
        .prop_map(move |(i, edits, cut)| {
            let mut f = corpus()[i].clone();
            for (pos, val, kind) in edits {
                let len = f.len().max(1);
                let p = usize::from(pos) % len;
                match kind {
                    0 => {
                        if let Some(b) = f.get_mut(p) {
                            *b ^= 1 << (val % 8);
                        }
                    }
                    1 => {
                        if let Some(b) = f.get_mut(p) {
                            *b = val;
                        }
                    }
                    2 => f.insert(p.min(f.len()), val),
                    _ => {
                        if p < f.len() {
                            f.remove(p);
                        }
                    }
                }
            }
            if cut % 4 == 0 {
                f.truncate(usize::from(cut) % (f.len() + 1));
            }
            f
        })
}

/// Several mutated frames, length-prefixed, for the machine oracles.
fn stream() -> impl Strategy<Value = Vec<u8>> {
    (any::<u8>(), proptest::collection::vec(mutated(), 1..24)).prop_map(|(head, fs)| {
        let mut v = vec![head];
        for f in fs {
            let f = &f[..f.len().min(255)];
            v.push(f.len() as u8);
            v.extend_from_slice(f);
        }
        v
    })
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: cases(),
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

fn ra_config() -> impl Strategy<Value = corerouter_proto_pppoe::nd::RaConfig> {
    use corerouter_proto_pppoe::nd::{PrefixInfo, RaConfig};
    use std::net::Ipv6Addr;
    let prefix = (
        any::<u128>(),
        any::<u8>(),
        any::<bool>(),
        any::<bool>(),
        any::<u32>(),
        any::<u32>(),
    )
        .prop_map(
            |(a, len, on_link, autonomous, valid, preferred)| PrefixInfo {
                prefix: Ipv6Addr::from_bits(a),
                len,
                on_link,
                autonomous,
                valid,
                preferred,
            },
        );
    (
        any::<(u8, bool, bool, u16, Option<u32>, u32)>(),
        proptest::collection::vec(prefix, 0..12),
        proptest::collection::vec(any::<u128>().prop_map(Ipv6Addr::from_bits), 0..12),
        proptest::collection::vec("[a-z0-9.-]{0,70}", 0..10),
    )
        .prop_map(
            |((hop, m, o, life, mtu, dl), prefixes, rdnss, dnssl)| RaConfig {
                hop_limit: hop,
                managed: m,
                other: o,
                router_lifetime: life,
                mtu,
                prefixes,
                rdnss,
                dnssl,
                dns_lifetime: dl,
                ..RaConfig::default()
            },
        )
}

/// IPv6 packets of a dual-stack session, built by the codecs themselves.
fn v6_corpus() -> Vec<Vec<u8>> {
    use corerouter_proto_pppoe::nd;
    let a: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
    let b: std::net::Ipv6Addr = "fe80::2".parse().unwrap();
    let mut out = Vec::new();
    let mut p = Vec::new();
    nd::router_solicit(&mut p, b);
    out.push(p.clone());
    p.clear();
    nd::router_advert(
        &mut p,
        a,
        nd::ALL_NODES,
        &nd::RaConfig {
            mtu: Some(1492),
            prefixes: vec![nd::PrefixInfo {
                prefix: "2001:db8::".parse().unwrap(),
                len: 64,
                on_link: true,
                autonomous: true,
                valid: 3600,
                preferred: 1800,
            }],
            rdnss: vec![a],
            dnssl: vec!["example.net".into()],
            ..nd::RaConfig::default()
        },
    );
    out.push(p.clone());
    p.clear();
    nd::neighbor_advert(&mut p, a, b, a, true);
    out.push(p.clone());
    p.clear();
    nd::udp6(
        &mut p,
        b,
        nd::ALL_DHCP,
        546,
        547,
        &[1, 0, 0, 1, 0, 1, 0, 2, 0, 3],
    );
    out.push(p);
    out
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn nd_random_bytes(b in proptest::collection::vec(any::<u8>(), 0..300)) {
        fuzz::nd(&b).map_err(TestCaseError::fail)?;
    }

    #[test]
    fn nd_mutated(i in 0usize..4, edits in proptest::collection::vec((any::<u16>(), any::<u8>()), 0..6)) {
        let mut f = v6_corpus()[i].clone();
        for (pos, val) in edits {
            let p = usize::from(pos) % f.len();
            f[p] = val;
        }
        fuzz::nd(&f).map_err(TestCaseError::fail)?;
    }

    #[test]
    fn ra_built_from_any_config_reads_back(cfg in ra_config()) {
        fuzz::ra_round_trip(&cfg, "fe80::1".parse().unwrap()).map_err(TestCaseError::fail)?;
    }

    #[test]
    fn discovery_random_bytes(b in proptest::collection::vec(any::<u8>(), 0..300)) {
        fuzz::discovery(&b).map_err(TestCaseError::fail)?;
    }

    #[test]
    fn discovery_mutated(b in mutated()) {
        fuzz::discovery(&b).map_err(TestCaseError::fail)?;
    }

    #[test]
    fn session_random_bytes(b in proptest::collection::vec(any::<u8>(), 0..300)) {
        fuzz::session(&b).map_err(TestCaseError::fail)?;
        fuzz::auth(&b).map_err(TestCaseError::fail)?;
    }

    #[test]
    fn session_mutated(b in mutated()) {
        fuzz::session(&b).map_err(TestCaseError::fail)?;
    }

    #[test]
    fn server_survives_mutated_conversations(b in stream()) {
        fuzz::server(&b).map_err(TestCaseError::fail)?;
    }

    #[test]
    fn live_conversation_with_edits_in_flight(b in proptest::collection::vec(any::<u8>(), 0..64)) {
        fuzz::conversation(&b).map_err(TestCaseError::fail)?;
    }

    #[test]
    fn client_survives_mutated_conversations(b in stream()) {
        fuzz::client(&b).map_err(TestCaseError::fail)?;
    }
}

#[test]
fn every_corpus_frame_passes_the_oracles_unmodified() {
    assert!(corpus().len() > 50);
    for f in corpus() {
        fuzz::discovery(f).unwrap();
        fuzz::session(f).unwrap();
    }
    let mut stream = vec![0u8];
    for f in corpus().iter().take(200) {
        stream.push(f.len().min(255) as u8);
        stream.extend_from_slice(&f[..f.len().min(255)]);
    }
    let st = fuzz::server_stats(&stream).unwrap();
    // The captured conversation drives the oracle's server deep: sessions
    // made, authenticated and up (so mutations explore those states).
    assert!(st.sessions_created >= 1, "{st:?}");
    assert!(st.auth_ok >= 1, "{st:?}");
}
