//! G4.8a — the `health` service's work under the session lock: hand one
//! reading to the engine (loads, rates, history) and judge the health
//! checks. The reading itself is taken outside the lock
//! (`hal-linux/benches/resource.rs`).
//!
//! `cargo bench -p corerouter-engine --bench health`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use corerouter_engine::Session;
use corerouter_hal::system_resource::{LabSampler, ResourceSampler, Want};
use criterion::{Criterion, criterion_group, criterion_main};

fn health(c: &mut Criterion) {
    let mut s = Session::virtual_lab();
    let mut lab = LabSampler::new();
    let mut t = 0u64;
    let mut g = c.benchmark_group("health");
    g.bench_function("ingest_and_check", |b| {
        b.iter_batched(
            || {
                t += 5000;
                lab.sample(Want {
                    processes: false,
                    now_ms: Some(t),
                })
            },
            |sample| {
                s.resource_ingest(sample);
                s.health_alerts()
            },
            criterion::BatchSize::SmallInput,
        );
    });
    g.finish();
}

criterion_group!(benches, health);
criterion_main!(benches);
