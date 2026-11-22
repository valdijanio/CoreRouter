//! G3.7: the network simulator's cost (`docs/netsim.md`).
//!
//! - `netsim/converge/<n>/<threads>`: a grid of `n` routers (OSPF on every
//!   link, eBGP between neighbors, a /24 each) from power-on to 60 virtual
//!   seconds, on 1 thread and on 8 (does the window pool pay?).
//! - `netsim/steady/100`: 60 virtual seconds of a converged 100-router grid
//!   (hellos and keepalives only).
//! - `netsim/cut/100`: a link cut and the 10 s after it.
//!
//! 500 routers take seconds per run: `NETSIM_BENCH_BIG=1` adds them (and
//! `examples/measure.rs` prints the full table).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;

use corerouter_netsim::preset::{self, BgpMode};
use corerouter_netsim::{Fault, LinkId, SEC, Simulation};
use criterion::{Criterion, criterion_group, criterion_main};

fn grid(n: usize, threads: usize) -> Simulation {
    let mut sim = preset::grid(n, BgpMode::Ebgp).build(1).unwrap();
    sim.set_threads(threads);
    sim
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("netsim");
    g.sample_size(10);
    let mut sizes = vec![10, 100];
    if std::env::var_os("NETSIM_BENCH_BIG").is_some() {
        sizes.push(500);
    }
    for n in sizes {
        for threads in [1, 8] {
            g.bench_function(format!("converge/{n}/{threads}"), |b| {
                b.iter(|| {
                    let mut sim = grid(n, threads);
                    sim.advance(60 * SEC, u64::MAX);
                    black_box(sim.fingerprint())
                })
            });
        }
    }
    let mut base = grid(100, 1);
    base.advance(60 * SEC, u64::MAX);
    g.bench_function("steady/100", |b| {
        b.iter(|| {
            let t = base.now();
            base.advance(t + 60 * SEC, u64::MAX);
            black_box(base.stats().events)
        })
    });
    g.bench_function("cut/100", |b| {
        b.iter(|| {
            let mut sim = grid(100, 1);
            sim.advance(60 * SEC, u64::MAX);
            let t = sim.now();
            sim.schedule(t, Fault::LinkCut { link: LinkId(90) })
                .unwrap();
            sim.advance(t + 10 * SEC, u64::MAX);
            black_box(sim.fingerprint())
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
