//! G2.3e — "who was" (public address + port + time → subscriber) on a
//! deterministic pool of 65 536 subscribers whose definition changed once a
//! day for a year (365 epochs in the history, RFC 7422 §3): the answer is
//! the formula of the epoch in force, so the cost is a search in the
//! history plus `Layout::reverse`, independent of traffic.
//!
//! `cargo xtask bench` runs it; alone:
//! `cargo bench -p corerouter-engine --bench cgnat_who_was`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;

use corerouter_engine::Session;
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::json;

const T0: u64 = 1_780_000_000;
const DAY: u64 = 86_400;

fn lab(epochs: u64) -> Session {
    let mut s = Session::virtual_lab();
    s.tick(T0);
    s.execute(
        "ip.firewall.cgnat.pool.add",
        &json!({"name": "c1", "inside": "100.64.0.0/16", "outside": "203.0.112.0/22", "ports_per_subscriber": 1000}),
    )
    .unwrap();
    for d in 1..epochs {
        s.tick(T0 + d * DAY);
        // Alternate the ports so every day is a new definition.
        let ports = if d % 2 == 0 { 1000 } else { 960 };
        s.execute("ip.firewall.cgnat.pool.set", &json!({"id": "c1", "ports_per_subscriber": ports}))
            .unwrap();
    }
    s.tick(T0 + epochs * DAY);
    s
}

fn who_was(c: &mut Criterion) {
    let mut g = c.benchmark_group("cgnat_who_was");
    for epochs in [1u64, 365] {
        let mut s = lab(epochs);
        let t = T0 + epochs * DAY / 2 + 3600;
        g.bench_function(format!("64Ki subscribers, {epochs} epochs"), |b| {
            b.iter(|| {
                s.execute(
                    "ip.firewall.cgnat.who-was",
                    black_box(&json!({"public": "203.0.113.7", "port": 4321, "time": t})),
                )
                .unwrap()
            });
        });
    }
    g.finish();
}

criterion_group!(benches, who_was);
criterion_main!(benches);
