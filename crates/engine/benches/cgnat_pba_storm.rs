//! G4.4j — a storm of CGNAT port block allocations (every subscriber of a
//! big blocks-mode pool coming back after a reboot): the engine's cost per
//! block under the session lock — finding a free block, the journal line,
//! the log line and the IPFIX record for the exporter's queue — and the
//! exporter's drain of that queue.
//!
//! `cargo xtask bench` runs it; alone:
//! `cargo bench -p corerouter-engine --bench cgnat_pba_storm`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::net::Ipv4Addr;

use corerouter_engine::Session;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use serde_json::json;

const T0: u64 = 1_780_000_000;
const N: u32 = 10_000;

/// A /17 of subscribers over 4096 public addresses, the exporter taking
/// the events.
fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.tick(T0);
    s.execute(
        "ip.firewall.cgnat.pool.add",
        &json!({"name": "storm", "mode": "blocks", "inside": "100.64.128.0/17", "outside": "10.200.0.0/20", "ports_per_subscriber": 1000}),
    )
    .unwrap();
    s.tick(T0 + 1);
    s.nat_log_want(true, true);
    s
}

fn storm(c: &mut Criterion) {
    let mut g = c.benchmark_group("cgnat_pba_storm");
    g.sample_size(10);
    g.throughput(Throughput::Elements(u64::from(N)));
    g.bench_function("allocate_10k_blocks", |b| {
        b.iter_batched(
            lab,
            |mut s| {
                for i in 0..N {
                    let sub = Ipv4Addr::from(u32::from(Ipv4Addr::new(100, 64, 128, 0)) + i);
                    black_box(s.cgnat_block_for(sub, T0 + 2).unwrap());
                }
                s
            },
            BatchSize::PerIteration,
        );
    });
    g.bench_function("drain_10k_records", |b| {
        b.iter_batched(
            || {
                let mut s = lab();
                for i in 0..N {
                    let sub = Ipv4Addr::from(u32::from(Ipv4Addr::new(100, 64, 128, 0)) + i);
                    s.cgnat_block_for(sub, T0 + 2).unwrap();
                }
                s
            },
            |mut s| {
                let mut out = Vec::new();
                s.nat_log_take(usize::MAX, &mut out);
                black_box(out.len());
                s
            },
            BatchSize::PerIteration,
        );
    });
    g.finish();
}

criterion_group!(benches, storm);
criterion_main!(benches);
