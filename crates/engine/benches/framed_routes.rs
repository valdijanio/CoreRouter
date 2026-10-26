//! G4.3cd — the router's table of blocks routed to subscribers
//! (`corerouter_engine::framed`): 10 000 sessions with 1–4 blocks each
//! (/29, /56, /30, /48). The cost of one login's routes (checks + claims),
//! of a logout's release, and of the slow path's lookup per packet (the
//! block that holds an address: `RouteSet`, O(log n)) must not grow with
//! the total.
//!
//! `cargo xtask bench` runs it; alone:
//! `cargo bench -p corerouter-engine --bench framed_routes`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::net::IpAddr;

use corerouter_engine::framed::{self, Forbidden, FramedTable, Holder};
use corerouter_model::framed_route::{FramedRoute, RouteOrigin};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

fn routes_of(i: u32) -> Vec<(FramedRoute, RouteOrigin)> {
    let all = [
        format!("20.{}.{}.0/29", i >> 8, i & 0xff),
        format!("2001:db8:{:x}:{:x}00::/56", 0xf000 | (i >> 8), i & 0xff),
        format!("21.{}.{}.0/30", i >> 8, i & 0xff),
        format!("2001:db9:{i:x}::/48"),
    ];
    all.iter()
        .take(1 + (i % 4) as usize)
        .map(|t| (t.parse().unwrap(), RouteOrigin::FramedRoute))
        .collect()
}

fn holder(i: u32) -> Holder {
    Holder {
        session: format!("*1-{i}"),
        user: format!("u{i}"),
        origin: RouteOrigin::FramedRoute,
        lane: 0,
        service: "pppoe",
    }
}

fn filled(n: u32) -> FramedTable {
    let t = FramedTable::default();
    let f = Forbidden::default();
    for i in 0..n {
        let a = framed::admit(&t, &f, &routes_of(i), &holder(i), None, true);
        assert!(a.refused.is_empty(), "{:?}", a.refused);
    }
    t
}

fn bench(c: &mut Criterion) {
    let f = Forbidden::default();
    for n in [0u32, 10_000] {
        let t = filled(n);
        let mut g = c.benchmark_group(format!("framed_routes/{n}_sessions"));
        // One login with 4 blocks, then its logout (so the table stays at n).
        let i = 60_000;
        let want = routes_of(i + 3);
        g.bench_function("login_4_routes_and_logout", |b| {
            b.iter(|| {
                let a = framed::admit(&t, &f, black_box(&want), &holder(i), None, true);
                framed::release_all(&t, &a.routes, "*1-60000");
                a.routes.len()
            })
        });
        let ip: IpAddr = "20.15.7.5".parse().unwrap();
        g.bench_function("slow_path_lookup", |b| {
            b.iter(|| t.holder_of(black_box(ip)).is_some())
        });
        g.finish();
    }
    c.bench_function("framed_routes/fill_10000_sessions", |b| {
        b.iter_batched(|| (), |()| filled(10_000).len(), BatchSize::PerIteration)
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
