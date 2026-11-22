//! Hostile input, the short deterministic run of the fuzz oracles
//! (`src/fuzz.rs`; the long run is `crates/proto-ha/fuzz`, libFuzzer):
//! random bytes, real frames with bits flipped and bytes cut, and
//! generated messages and records that must round-trip exactly.
//! `HA_FUZZ_CASES=N` raises the case count.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::net::Ipv4Addr;
use std::sync::{Arc, OnceLock};

use corerouter_proto_ha::fuzz;
use corerouter_proto_ha::hello::{self, HelloFrame};
use corerouter_proto_ha::lab::record;
use corerouter_proto_ha::msg::{Counters, FrameReader, Heartbeat, Key, Msg, Op, Record, Role};
use corerouter_proto_ha::record::{Prefix6, SessionRecord};
use corerouter_proto_ha::role::PeerView;
use proptest::prelude::*;

fn cases() -> u32 {
    std::env::var("HA_FUZZ_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512)
}

/// Real frames of every kind (a sync stream and access hellos).
fn corpus() -> &'static [Vec<u8>] {
    static C: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    C.get_or_init(|| {
        let key = |n: u32| Key::new(&n.to_le_bytes()).unwrap();
        let rec = |n| Arc::from(record(n, 1).to_bytes().unwrap());
        let msgs = [
            Msg::SnapshotBegin {
                stream: 1,
                base: 9,
                total: 2,
            },
            Msg::SnapshotChunk {
                stream: 1,
                records: vec![Record {
                    key: key(1),
                    value: rec(1),
                    counters: Counters::default(),
                }],
            },
            Msg::SnapshotEnd {
                stream: 1,
                base: 9,
                count: 1,
            },
            Msg::Delta {
                stream: 1,
                first: 10,
                ops: vec![
                    Op::Upsert {
                        key: key(2),
                        value: rec(2),
                    },
                    Op::Remove { key: key(1) },
                    Op::Counters {
                        key: key(2),
                        c: Counters {
                            rx_bytes: 5,
                            ..Counters::default()
                        },
                    },
                ],
            },
            Msg::Ack { stream: 1, seq: 12 },
            Msg::Resync { stream: 1, from: 3 },
            Msg::Handover { epoch: 2 },
        ];
        let mut out: Vec<Vec<u8>> = msgs
            .iter()
            .map(|m| {
                let mut b = Vec::new();
                m.encode(&mut b).unwrap();
                b
            })
            .collect();
        out.push(record(7, 3).to_bytes().unwrap());
        let k = hello::derive("hello", b"fuzz");
        let mut h = Vec::new();
        HelloFrame {
            view: view(Role::Active),
            seq: 1,
        }
        .encode(&k, &mut h);
        out.push(h);
        out
    })
}

fn view(role: Role) -> PeerView {
    PeerView {
        node_id: 1,
        incarnation: 2,
        hears: 3,
        view_seq: 4,
        acked: 5,
        epoch: 6,
        role,
        priority: 100,
        witness: true,
        in_sync: true,
        eligible: true,
    }
}

fn mutate(mut b: Vec<u8>, flips: &[(usize, u8)], cut: Option<usize>) -> Vec<u8> {
    for (i, x) in flips {
        if !b.is_empty() {
            let n = b.len();
            b[i % n] ^= x;
        }
    }
    if let Some(c) = cut {
        b.truncate(c % (b.len() + 1));
    }
    b
}

fn arb_record() -> impl Strategy<Value = SessionRecord> {
    (
        any::<u32>(),
        any::<(u16, u16, u16)>(),
        any::<([u8; 6], [u8; 6], u32, u32)>(),
        proptest::collection::vec(any::<u8>(), 0..40),
        proptest::option::of(any::<u32>()),
        proptest::option::of(any::<[u8; 8]>()),
        proptest::option::of((any::<[u8; 16]>(), 0u8..=128)),
        proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..30), 0..4),
        "[a-z0-9/]{0,20}",
        any::<(u64, u64, u64)>(),
        (
            proptest::collection::vec(any::<[u8; 16]>(), 0..4),
            proptest::collection::vec("[0-9a-f:./| -]{1,40}", 0..6),
            any::<(u64, u64, Option<u32>)>(),
            "[a-z0-9-]{0,16}",
        ),
    )
        .prop_map(
            |(
                n,
                (vlan, inner, sid),
                (cm, sm, m1, m2),
                user,
                ip,
                iid,
                pfx,
                class,
                text,
                (a, b, c),
                (dns6, routes, (li, lo, nb), fb),
            )| {
                let mut r = record(n, 0);
                r.vlan = vlan;
                r.inner_vlan = inner;
                r.sid = sid;
                r.client_mac = cm;
                r.server_mac = sm;
                r.our_magic = m1;
                r.peer_magic = m2;
                r.username = user.into();
                r.ipv4 = ip.map(Ipv4Addr::from);
                r.ipv6_iid = iid;
                r.delegated = pfx.map(|(a, len)| Prefix6 {
                    addr: a.into(),
                    len,
                });
                r.class = class.into_iter().map(Into::into).collect();
                r.rate_limit = Some(text.clone().into());
                r.acct_session_id = text.into();
                r.counters = Counters {
                    rx_bytes: a,
                    tx_bytes: b,
                    rx_packets: c,
                    tx_packets: a ^ b,
                };
                r.dns6 = dns6.into_iter().map(Into::into).collect();
                r.routes = routes.into_iter().map(Into::into).collect();
                r.limit_in = li;
                r.limit_out = lo;
                r.nbns = [None, nb.map(Ipv4Addr::from)];
                r.fallback_profile = fb.into();
                r
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), ..ProptestConfig::default() })]

    #[test]
    fn random_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..2048), kind in any::<u8>()) {
        fuzz::stream(&data);
        fuzz::message(kind, &data);
        fuzz::record(&data);
        fuzz::access_hello(&data);
    }

    #[test]
    fn mutated_real_frames_never_panic(
        pick in any::<usize>(),
        flips in proptest::collection::vec((any::<usize>(), 1u8..), 0..6),
        cut in proptest::option::of(any::<usize>()),
    ) {
        let c = corpus();
        let b = mutate(c[pick % c.len()].clone(), &flips, cut);
        fuzz::stream(&b);
        if b.len() > 12 {
            fuzz::message(b[5], &b[12..]);
        }
        fuzz::record(&b);
        fuzz::access_hello(&b);
    }

    #[test]
    fn records_round_trip(r in arb_record()) {
        let b = r.to_bytes().unwrap();
        prop_assert_eq!(SessionRecord::decode(&b).unwrap(), r);
    }

    #[test]
    fn messages_round_trip_through_any_split(
        recs in proptest::collection::vec(arb_record(), 1..20),
        removes in proptest::collection::vec(any::<u32>(), 0..20),
        hb in any::<(u64, u64, u64, u64, u64, u8, bool, bool, u32)>(),
        split in any::<usize>(),
    ) {
        let ops: Vec<Op> = recs
            .iter()
            .map(|r| Op::Upsert { key: r.key(), value: Arc::from(r.to_bytes().unwrap()) })
            .chain(removes.iter().map(|n| Op::Remove { key: Key::new(&n.to_le_bytes()).unwrap() }))
            .collect();
        let msgs = vec![
            Msg::Delta { stream: hb.0, first: hb.1 % (1 << 60), ops },
            Msg::Heartbeat(Heartbeat {
                node_id: hb.0,
                incarnation: hb.1,
                hears: hb.2,
                view_seq: hb.3,
                acked: hb.4,
                epoch: hb.4 ^ 1,
                role: Role::Standby,
                priority: hb.5,
                witness: hb.6,
                in_sync: hb.7,
                eligible: !hb.7,
                stream: hb.2,
                seq: hb.3,
                sessions: hb.8,
            }),
        ];
        let mut bytes = Vec::new();
        for m in &msgs {
            m.encode(&mut bytes).unwrap();
        }
        let at = split % (bytes.len() + 1);
        let mut fr = FrameReader::new();
        let mut back = Vec::new();
        for part in [&bytes[..at], &bytes[at..]] {
            fr.push(part);
            while let Some(m) = fr.next_msg().unwrap() {
                back.push(m);
            }
        }
        prop_assert_eq!(back, msgs);
    }
}
