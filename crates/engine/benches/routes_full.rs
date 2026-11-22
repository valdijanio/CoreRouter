//! G1.27c — a full BGP-sized routing table in the engine: one million
//! routes (IPv4 /24s and /16s, 5% IPv6 /48s, some backups at distance 20).
//! What reading it costs: the whole `ip.route.list`, and (G1.27c) a page
//! of `ip.route.page`: cold (the kept lines rebuilt), then first and last
//! page, filtered by prefix and by state, and aggregated by /16.
//!
//! `cargo xtask bench routes_1m`; alone: `cargo bench -p corerouter-engine --bench routes_full`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::time::{Duration, Instant};

use corerouter_engine::route_table::RouteCache;
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::json;

/// Routes in the table (a full IPv4 BGP table is ~1 M prefixes).
const N: usize = 1_000_000;

fn routes_1m(c: &mut Criterion) {
    let t = Instant::now();
    // Too big for the saved config (and a protocol's table, not static
    // routes): put in place directly.
    let mut s = corerouter_engine::perf::with_running(corerouter_engine::perf::full_table(N));
    eprintln!(
        "routes_1m: session with {} routes in {:?}",
        s.store().running().ip.routes.len(),
        t.elapsed()
    );
    assert_eq!(
        s.store().running().ip.routes.len(),
        N,
        "the table was not restored"
    );
    let mut g = c.benchmark_group("routes_1m");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(20));
    g.bench_function("ip.route.list", |b| {
        b.iter(|| s.execute("ip.route.list", black_box(&json!({}))).unwrap());
    });
    // G1.27c: a page, the lines rebuilt first (the table just changed).
    g.bench_function("ip.route.page/cold", |b| {
        b.iter(|| {
            if let Some(c) = s.ext_mut::<RouteCache>() {
                *c = RouteCache::default();
            }
            s.execute("ip.route.page", black_box(&json!({}))).unwrap()
        });
    });
    // The same lines kept: what each refresh of the window costs.
    for (name, p) in [
        ("ip.route.page/first", json!({})),
        ("ip.route.page/last", json!({"offset": N - 500})),
        ("ip.route.page/prefix", json!({"prefix": "12.0.0.0/8"})),
        ("ip.route.page/aggregate", json!({"aggregate": true})),
        ("ip.route.page/inactive", json!({"state": "inactive"})),
    ] {
        g.bench_function(name, |b| {
            b.iter(|| s.execute("ip.route.page", black_box(&p)).unwrap());
        });
    }
    g.finish();
}

criterion_group!(benches, routes_1m);
criterion_main!(benches);
