//! An atomic `engine.batch` the size of a big `/import` (audit-e2e): N
//! address-list entries in one transaction on a fresh lab. Each step used
//! to copy the whole candidate (its own rollback point) although the batch
//! already keeps one: quadratic in N.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-engine --bench batch_import`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use corerouter_engine::Session;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use serde_json::{Value, json};

fn steps(n: usize) -> Value {
    let steps: Vec<Value> = (0..n)
        .map(|i| {
            json!({"command": "ip.firewall.address-list.add", "params": {
                "list": format!("l{}", i % 20),
                "address": format!("100.64.{}.{}", i / 256, i % 256),
            }})
        })
        .collect();
    Value::Array(steps)
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("batch_import");
    g.sample_size(10).measurement_time(Duration::from_secs(5));
    for n in [1000usize, 4000] {
        let batch = steps(n);
        g.bench_with_input(BenchmarkId::new("address_list", n), &batch, |b, batch| {
            b.iter_batched(
                Session::virtual_lab,
                |mut s| {
                    s.batch(batch, true).unwrap();
                    s
                },
                criterion::BatchSize::LargeInput,
            );
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
