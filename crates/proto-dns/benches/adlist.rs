//! G4.1d — adlist: parse a 1 000 000-name hosts file, build its set, and
//! look names up (blocked, under a blocked domain, not listed): the lookup
//! runs for every query of the LAN.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-proto-dns --bench adlist`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;

use corerouter_proto_dns::adlist::{Loaded, parse};
use criterion::{Criterion, criterion_group, criterion_main};

const NAMES: usize = 1_000_000;

fn hosts() -> String {
    (0..NAMES)
        .map(|i| format!("0.0.0.0 ads{i}.tracker{}.example\n", i % 997))
        .collect()
}

fn bench(c: &mut Criterion) {
    let text = hosts();
    let mut g = c.benchmark_group("dns_adlist");
    g.sample_size(10);
    g.bench_function("parse_and_build_1m", |b| {
        b.iter(|| Loaded::new(1, parse(black_box(&text), NAMES)))
    });
    g.finish();
    let mut parsed = parse(&text, NAMES);
    parsed.domains.push("blocked-domain.example".into());
    let list = Loaded::new(1, parsed);
    eprintln!("adlist: {} names, {} bytes", list.len(), list.names.bytes());
    c.bench_function("dns_adlist_lookup_hit", |b| {
        b.iter(|| list.matches(black_box("ads123456.tracker333.example")))
    });
    c.bench_function("dns_adlist_lookup_subdomain", |b| {
        b.iter(|| list.matches(black_box("a.b.c.blocked-domain.example")))
    });
    c.bench_function("dns_adlist_lookup_miss", |b| {
        b.iter(|| list.matches(black_box("www.cdn.provider.example.net")))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
