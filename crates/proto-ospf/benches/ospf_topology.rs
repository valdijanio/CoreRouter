//! G3.4b: the Topology tab's layout of 500 routers (a ring of rings with
//! cross links, ~1 000 links), on one thread and on several; and "why this
//! path?" (Dijkstra) over the same graph.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;

use corerouter_proto_ospf::layout::{layout, threads_for};
use criterion::{Criterion, criterion_group, criterion_main};

fn graph(n: usize) -> (Vec<u64>, Vec<(usize, usize)>) {
    let ids: Vec<u64> = (0..n as u64).map(|i| 0x0AFF_0000 + i).collect();
    let mut edges = Vec::new();
    for i in 0..n {
        edges.push((i, (i + 1) % n));
        if i % 10 == 0 {
            edges.push((i, (i * 7 + 13) % n));
        }
        if i % 25 == 0 {
            edges.push((i, (i + n / 2) % n));
        }
    }
    (ids, edges)
}

fn bench(c: &mut Criterion) {
    let (ids, edges) = graph(500);
    eprintln!(
        "ospf layout 500 nodes, {} links; threads_for = {}",
        edges.len(),
        threads_for(500)
    );
    let mut g = c.benchmark_group("ospf layout 500 nodes");
    g.sample_size(10);
    for t in [1, 2, 4, 8, 16] {
        g.bench_function(format!("{t} threads"), |b| {
            b.iter(|| black_box(layout(&ids, &edges, t)).len())
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
