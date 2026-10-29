//! The revision delta of a firewall commit (`config_delta::diff`, written
//! at every commit): one filter rule changed with 4 000 filter, 4 000 raw
//! and 2 000 mangle rules, the most the tables take (`MAX_RULES`). The
//! raw table was serialized and compared whole at every firewall commit
//! until it joined the big lists (2026-10-29).
//!
//! `cargo xtask bench config_delta`; alone: `cargo bench -p corerouter-model --bench config_delta`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::time::Duration;

use corerouter_model::config::Config;
use corerouter_model::config_delta;
use corerouter_model::firewall::FirewallRule;
use criterion::{Criterion, criterion_group, criterion_main};

fn rule(i: u32, chain: &str, action: &str) -> FirewallRule {
    serde_json::from_value(serde_json::json!({
        "id": format!("*{:X}", i + 1),
        "chain": chain,
        "matchers": {"in_interface": "ether2", "protocol": "tcp", "dst_port": format!("{}", 10000 + i)},
        "action": {"type": action},
        "comment": "bench",
    }))
    .unwrap()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("config_delta");
    g.sample_size(20);
    g.measurement_time(Duration::from_secs(3));
    let mut old = Config::default();
    let fw = &mut old.ip.firewall;
    for i in 0..4000 {
        fw.filter.push(rule(i, "input", "drop"));
        fw.raw.push(rule(4000 + i, "prerouting", "drop"));
    }
    for i in 0..2000 {
        fw.mangle.push(rule(8000 + i, "prerouting", "accept"));
    }
    let mut new = old.clone();
    new.ip.firewall.filter.get_mut(2000).unwrap().comment = "changed".into();
    g.bench_function("one_filter_rule_of_10000", |b| {
        b.iter(|| black_box(config_delta::diff(&old, &new).unwrap()));
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
