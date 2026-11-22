//! G6.4a — Torch's cost per captured frame: decode the headers, turn the
//! frame to the interface's side, filter, and add it to its row. This is
//! what a capture thread pays for every frame it reads (the socket's own
//! cost is `hal-linux/benches/netns_capture.rs`).
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-engine --bench torch`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::time::Duration;

use corerouter_engine::tools::torch::{Filter, Group, Torch};
use corerouter_hal::capture::{Dir, FrameBatch};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

/// Frames per batch, as the job reads them.
const BATCH: usize = 1024;

/// An IPv4/TCP frame of flow `i` (1024 subscribers × 4 sites).
fn frame(i: usize) -> Vec<u8> {
    let sub = (i % 1024) as u16;
    let mut f = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x08, 0x00];
    f.extend_from_slice(&[0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0]);
    f.extend_from_slice(&[100, 64, (sub >> 8) as u8, sub as u8]);
    f.extend_from_slice(&[8, 8, 8, (i % 4) as u8]);
    f.extend_from_slice(&(40_000 + sub).to_be_bytes());
    f.extend_from_slice(&443u16.to_be_bytes());
    f.extend_from_slice(&[0u8; 16]);
    f
}

fn batch() -> FrameBatch {
    let mut b = FrameBatch::new(BATCH);
    for i in 0..BATCH {
        let dir = if i % 3 == 0 { Dir::Tx } else { Dir::Rx };
        b.push(Duration::ZERO, dir, None, 1500, &frame(i * 7));
    }
    b
}

fn ingest(c: &mut Criterion) {
    let b = batch();
    let mut g = c.benchmark_group("torch_ingest");
    g.throughput(Throughput::Elements(BATCH as u64));
    for (name, fields) in [
        ("src_dst", &["src", "dst"][..]),
        ("five_tuple", &["src", "dst", "proto", "port"][..]),
    ] {
        let mut group = Group::default();
        for f in fields {
            group.set(f);
        }
        let mut t = Torch::new(group, Filter::default(), 1);
        g.bench_function(name, |bench| {
            bench.iter(|| t.ingest(black_box(&b)));
        });
        // One interval's rows out (the per-second cost).
        black_box(t.flush(1.0, 64, None));
    }
    g.finish();
}

criterion_group!(benches, ingest);
criterion_main!(benches);
