//! G4.3h — the hot paths of BNG redundancy: encoding and decoding one
//! session record, a delta of 2048 changes through the codec into the
//! replica (the steady state of a busy BNG), a whole snapshot of 100 000
//! sessions (what a standby that starts or reconnects late costs) and the
//! access hello (HMAC). Under `cargo bench` it also prints the bytes per
//! session on the wire and the replica's memory per session.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-proto-ha --bench ha`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::hint::black_box;
use std::sync::Arc;

use corerouter_proto_ha::hello::{self, HelloFrame};
use corerouter_proto_ha::lab::record;
use corerouter_proto_ha::msg::{FrameReader, Hello, Op, Role, VERSION};
use corerouter_proto_ha::record::SessionRecord;
use corerouter_proto_ha::role::PeerView;
use corerouter_proto_ha::sync::{Publisher, Replica, SyncConfig};
use criterion::{BatchSize, Criterion, Throughput, criterion_group};

fn fresh_hello() -> Hello {
    Hello {
        version: VERSION,
        node_id: 2,
        epoch: 0,
        role: Role::Standby,
        priority: 100,
        hot_standby: true,
        stream: 0,
        applied: 0,
        sessions: 0,
        sections: vec![],
        features: 0,
    }
}

/// The publisher's output, encoded, into the replica; returns the bytes.
fn transfer(p: &mut Publisher, r: &mut Replica) -> usize {
    let mut bytes = 0;
    let mut fr = FrameReader::new();
    let mut back = Vec::new();
    loop {
        let mut out = Vec::new();
        p.poll(1 << 22, &mut out);
        if out.is_empty() {
            return bytes;
        }
        let mut wire = Vec::new();
        for m in &out {
            m.encode(&mut wire).unwrap();
        }
        bytes += wire.len();
        fr.push(&wire);
        while let Some(m) = fr.next_msg().unwrap() {
            r.handle(0, &m, &mut back);
        }
        r.poll(1_000_000, &mut back);
        for m in back.drain(..) {
            p.handle(0, &m);
        }
    }
}

fn publisher(n: u32) -> Publisher {
    let mut p = Publisher::new(1, SyncConfig::default());
    for i in 0..n {
        let r = record(i, 0);
        p.upsert(0, r.key(), Arc::from(r.to_bytes().unwrap()));
    }
    p
}

fn codec(c: &mut Criterion) {
    let r = record(12_345, 3);
    let b = r.to_bytes().unwrap();
    let mut g = c.benchmark_group("ha_record");
    g.throughput(Throughput::Elements(1));
    g.bench_function("encode", |x| {
        let mut out = Vec::with_capacity(512);
        x.iter(|| {
            out.clear();
            black_box(&r).encode(&mut out).unwrap();
        })
    });
    g.bench_function("decode", |x| {
        x.iter(|| SessionRecord::decode(black_box(&b)).unwrap())
    });
    g.finish();

    let key = hello::derive("hello", b"bench");
    let f = HelloFrame {
        view: PeerView {
            node_id: 1,
            incarnation: 2,
            hears: 3,
            view_seq: 4,
            acked: 5,
            epoch: 6,
            role: Role::Active,
            priority: 100,
            witness: true,
            in_sync: true,
            eligible: true,
        },
        seq: 9,
    };
    let mut body = Vec::new();
    f.encode(&key, &mut body);
    let mut g = c.benchmark_group("ha_access_hello");
    g.throughput(Throughput::Elements(1));
    g.bench_function("encode+decode", |x| {
        let mut out = Vec::with_capacity(128);
        x.iter(|| {
            out.clear();
            f.encode(&key, &mut out);
            HelloFrame::decode(&key, black_box(&out)).unwrap()
        })
    });
    g.finish();
}

fn sync(c: &mut Criterion) {
    // Steady state: 2048 changes (logins with a whole record, logouts,
    // counters) published, encoded, decoded and applied.
    let mut g = c.benchmark_group("ha_delta");
    g.throughput(Throughput::Elements(2048));
    g.bench_function("2048_changes_through_the_codec", |x| {
        x.iter_batched(
            || {
                let mut p = publisher(20_000);
                let mut r = Replica::new(SyncConfig::default());
                p.connect(&fresh_hello());
                transfer(&mut p, &mut r);
                (p, r)
            },
            |(mut p, mut r)| {
                for i in 0..2048u32 {
                    let rec = record(i * 7 % 25_000, i);
                    match i % 4 {
                        0 | 1 => p.upsert(1, rec.key(), Arc::from(rec.to_bytes().unwrap())),
                        2 => p.remove(1, rec.key()),
                        _ => p.counters(
                            1,
                            rec.key(),
                            corerouter_proto_ha::msg::Counters {
                                rx_bytes: u64::from(i),
                                ..Default::default()
                            },
                        ),
                    }
                }
                transfer(&mut p, &mut r)
            },
            BatchSize::LargeInput,
        )
    });
    g.finish();

    let mut g = c.benchmark_group("ha_snapshot");
    g.sample_size(10);
    g.throughput(Throughput::Elements(100_000));
    g.bench_function("100k_sessions", |x| {
        x.iter_batched(
            || {
                let mut p = publisher(100_000);
                p.connect(&fresh_hello());
                (p, Replica::new(SyncConfig::default()))
            },
            |(mut p, mut r)| {
                let n = transfer(&mut p, &mut r);
                assert_eq!(r.len(), 100_000);
                n
            },
            BatchSize::LargeInput,
        )
    });
    g.finish();
}

/// Bytes per session on the wire and RSS of a replica of 100 000 (Linux),
/// printed, not criterion rows.
fn report() {
    let start = rss();
    let mut p = publisher(100_000);
    p.connect(&fresh_hello());
    let base = rss();
    let mut r = Replica::new(SyncConfig::default());
    let bytes = transfer(&mut p, &mut r);
    let full = rss();
    println!(
        "ha: publisher of 100000 sessions RSS +{} MiB ({} B per session, table and log)",
        base.saturating_sub(start) >> 20,
        base.saturating_sub(start) / 100_000
    );
    let rec = record(1, 0).to_bytes().unwrap().len();
    let op = Op::Upsert {
        key: record(1, 0).key(),
        value: Arc::from(record(1, 0).to_bytes().unwrap()),
    };
    println!(
        "ha: snapshot of 100000 sessions = {} KiB on the wire ({} B per session; record {rec} B, \
         upsert op {} B); replica RSS +{} MiB ({} B per session)",
        bytes >> 10,
        bytes / 100_000,
        op.wire_len(),
        full.saturating_sub(base) >> 20,
        full.saturating_sub(base) / 100_000
    );
}

fn rss() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map_or(0, |pages| pages * 4096)
}

criterion_group!(benches, codec, sync);

fn main() {
    // First, before criterion's allocations blur the RSS.
    if std::env::args().any(|a| a == "--bench") {
        report();
    }
    benches();
    Criterion::default().configure_from_args().final_summary();
}
