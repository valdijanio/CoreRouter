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

proptest! {
    #![proptest_config(config())]

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
