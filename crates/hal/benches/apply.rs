//! G0.9 — `VirtualHal::apply` of N addresses, routes and filter rules (the
//! lab's share of a commit: firewall render + diff). The kernel side of the
//! same change is `hal-linux/benches/netns_apply.rs`.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-hal --bench apply`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::hint::black_box;

use corerouter_hal::Hal;
use corerouter_hal::virt::VirtualHal;
use corerouter_model::Config;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

type Build = fn(&Config, usize) -> Config;

fn apply(c: &mut Criterion) {
    let base = common::base("ether1");
    let kinds: [(&str, Build); 3] = [
        ("addresses", |b, n| common::addresses(b, "ether1", n)),
        ("routes", common::routes),
        ("filter_rules", common::filter_rules),
    ];
    let mut g = c.benchmark_group("hal_virtual_apply");
    for (kind, build) in kinds {
        for n in common::SIZES {
            let to = build(&base, n);
            let mut hal = VirtualHal::new(8);
            hal.apply(&Config::default(), &base).unwrap();
            g.throughput(Throughput::Elements(n as u64));
            g.bench_with_input(BenchmarkId::new(kind, n), &to, |b, to| {
                b.iter(|| hal.apply(black_box(&base), black_box(to)).unwrap());
            });
        }
    }
    g.finish();
}

criterion_group!(benches, apply);
criterion_main!(benches);
