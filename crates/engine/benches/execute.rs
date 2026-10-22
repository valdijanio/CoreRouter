//! G0.9 — `Session::execute` of common commands on the virtual lab: the
//! engine's cost of one command (validation, journal, apply, rollback point),
//! without any transport.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-engine --bench execute`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;

use corerouter_engine::Session;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use serde_json::{Value, json};

/// A fresh lab per iteration (built untimed), so every add starts from the
/// same state instead of a list that grows with the iteration count.
fn on_fresh_lab(c: &mut Criterion, name: &str, id: &str, params: &Value) {
    c.bench_function(name, |b| {
        b.iter_batched(
            Session::virtual_lab,
            |mut s| {
                s.execute(id, black_box(params)).unwrap();
                s
            },
            BatchSize::SmallInput,
        );
    });
}

fn execute(c: &mut Criterion) {
    let mut s = Session::virtual_lab();
    c.bench_function("engine_execute/interface.list", |b| {
        b.iter(|| s.execute("interface.list", black_box(&json!({}))).unwrap());
    });
    c.bench_function("engine_execute/ip.address.list", |b| {
        b.iter(|| s.execute("ip.address.list", black_box(&json!({}))).unwrap());
    });
    on_fresh_lab(
        c,
        "engine_execute/ip.address.add",
        "ip.address.add",
        &json!({"address": "10.0.0.1/24", "interface": "ether1"}),
    );
    on_fresh_lab(
        c,
        "engine_execute/ip.firewall.filter.add",
        "ip.firewall.filter.add",
        &json!({"chain": "input", "protocol": "tcp", "dst_port": "22",
                "src_address": "203.0.113.0/24", "action": "drop"}),
    );
    // A rejected command: the validation path an operator's typo takes.
    c.bench_function("engine_execute/rejected_param", |b| {
        b.iter(|| {
            s.execute(
                "ip.address.add",
                black_box(&json!({"adress": "10.0.0.1/24", "interface": "ether1"})),
            )
            .unwrap_err()
        });
    });
    // Session::virtual_lab itself: what the fresh-lab benchmarks leave out.
    c.bench_function("engine_execute/virtual_lab_new", |b| {
        b.iter(Session::virtual_lab);
    });
}

criterion_group!(benches, execute);
criterion_main!(benches);
