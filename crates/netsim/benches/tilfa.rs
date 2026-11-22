//! G3.4d: TI-LFA coverage of 10 000 prefixes over a 500-router area (a
//! ring of rings with cross links, 20 prefixes per router), from one
//! router: half the routes with a backup, the other half explained (the
//! memoized repair per destination and neighbor).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::net::Ipv4Addr;

use corerouter_netsim::tilfa::{CoverInput, Protection, Topology, coverage, repairs};
use criterion::{Criterion, criterion_group, criterion_main};

fn ip(i: usize) -> Ipv4Addr {
    Ipv4Addr::from(0x0AFF_0000 + u32::try_from(i).unwrap())
}

fn topo(n: usize) -> Topology {
    let mut arcs = Vec::new();
    let mut link = |a: usize, b: usize, c: u32| {
        arcs.push((ip(a), ip(b), c));
        arcs.push((ip(b), ip(a), c));
    };
    for i in 0..n {
        link(i, (i + 1) % n, 10);
        if i % 10 == 0 {
            link(i, (i * 7 + 13) % n, 30);
        }
    }
    Topology::new(&arcs)
}

fn bench(c: &mut Criterion) {
    let t = topo(500);
    let prefixes: Vec<String> = (0..10_000)
        .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
        .collect();
    let inputs: Vec<CoverInput<'_>> = prefixes
        .iter()
        .enumerate()
        .map(|(i, p)| CoverInput {
            prefix: p,
            dest: Some(ip(1 + i % 499)),
            neighbor: Some(if i % 3 == 0 { ip(1) } else { ip(499) }),
            has_backup: i % 2 == 0,
        })
        .collect();
    let cov = coverage(&t, ip(0), Protection::Link, &inputs);
    eprintln!(
        "coverage: {} of {} protected, {} explained",
        cov.protected,
        cov.total,
        cov.unprotected.len()
    );
    let mut g = c.benchmark_group("tilfa 500 routers");
    g.sample_size(10);
    g.bench_function("coverage of 10 000 prefixes", |b| {
        b.iter(|| black_box(coverage(&t, ip(0), Protection::Link, black_box(&inputs))).protected)
    });
    g.bench_function("repairs to every router", |b| {
        b.iter(|| black_box(repairs(&t, ip(0), Protection::Link)).len())
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
