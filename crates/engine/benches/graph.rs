//! The traffic history (G4.5): what a second of collection costs with 8,
//! 64 and 512 interfaces kept (it runs in the clock's tick, under the
//! session lock), what reading a year of one interface costs
//! (`system.graph.query range=year`, the Graphs window), and what a store
//! takes out of the session (`take_patches`, under the lock; the daemon
//! writes outside it). Memory per series is printed once: it is fixed by
//! the layout (`Rrd::size_for`).
//!
//! `cargo xtask bench graph`; alone: `cargo bench -p corerouter-engine --bench graph`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;

use corerouter_engine::graph::query::{self, Request};
use corerouter_engine::graph::rrd::Rrd;
use corerouter_engine::graph::{GraphDb, INTERFACE_SOURCES, Link};
use corerouter_hal::LinkState;
use corerouter_hal::resources::Resources;
use corerouter_model::IfName;
use corerouter_model::graphing::Graphing;
use criterion::{Criterion, criterion_group, criterion_main};

const T0: u64 = 1_800_000_000;

fn links(n: usize) -> (Vec<IfName>, Vec<LinkState>) {
    let names: Vec<IfName> = (0..n)
        .map(|i| format!("ether{i}").parse().unwrap())
        .collect();
    let states = names
        .iter()
        .map(|name| LinkState {
            name: name.clone(),
            running: true,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            kind: "ether".into(),
            mtu: 1500,
            mac: None,
            unmanaged: None,
            errors: Some(corerouter_hal::LinkErrors::default()),
        })
        .collect();
    (names, states)
}

fn step(db: &mut GraphDb, cfg: &Graphing, names: &[IfName], states: &mut [LinkState], t: u64) {
    for s in states.iter_mut() {
        s.rx_bytes += 125_000_000;
        s.tx_bytes += 60_000_000;
        s.rx_packets += 100_000;
        s.tx_packets += 60_000;
    }
    let l: Vec<Link<'_>> = names
        .iter()
        .zip(states.iter())
        .map(|(name, live)| Link {
            name,
            kind: "ether",
            live: Some(live),
        })
        .collect();
    let r = Resources {
        cpu_busy: t * 10,
        cpu_total: t * 100,
        mem_total: 1 << 34,
        mem_available: 1 << 33,
        conntrack: Some(100_000),
        conntrack_max: Some(1 << 20),
    };
    black_box(db.sample(t, cfg, &l, Some(r)));
}

fn collect(c: &mut Criterion) {
    let mut g = c.benchmark_group("graph_collect");
    for n in [8usize, 64, 512] {
        let cfg = Graphing {
            max_memory_mib: 4096,
            ..Graphing::default()
        };
        let (names, mut states) = links(n);
        let mut db = GraphDb::default();
        let mut t = T0;
        // Past the first minutes, so buckets close as in steady state.
        for _ in 0..600 {
            t += 1;
            step(&mut db, &cfg, &names, &mut states, t);
        }
        eprintln!(
            "graph: {n} interfaces kept: {} bytes of history ({} per interface)",
            db.memory_bytes(),
            Rrd::size_for(INTERFACE_SOURCES.len())
        );
        g.bench_function(format!("second/{n}"), |b| {
            b.iter(|| {
                t += 1;
                step(&mut db, &cfg, &names, &mut states, t);
            });
        });
        g.bench_function(format!("store/{n}"), |b| {
            b.iter_custom(|iters| {
                let mut spent = std::time::Duration::ZERO;
                for _ in 0..iters {
                    for _ in 0..300 {
                        t += 1;
                        step(&mut db, &cfg, &names, &mut states, t);
                    }
                    let at = std::time::Instant::now();
                    black_box(db.take_patches(false));
                    spent += at.elapsed();
                }
                spent
            });
        });
    }
    g.finish();
}

fn year(c: &mut Criterion) {
    // A year of one interface, one value a second (as collected).
    let mut r = Rrd::new("interface:ether1", INTERFACE_SOURCES.len());
    let start = T0 - 365 * 86_400;
    for t in start..T0 {
        let v = (t % 86_400) as f32 * 1e4;
        r.update(t, &[v, v / 2.0, v / 1e3, v / 2e3, 0.0, 0.0]);
    }
    let mut db = GraphDb::default();
    db.load("interface-ether1.rrd", &r.encode()).unwrap();
    let mut g = c.benchmark_group("graph_query");
    for (name, range) in query::RANGES {
        let req = Request {
            keys: vec!["interface:ether1".into()],
            range,
            step: None,
            end: None,
            fields: None,
            stats: true,
            max: true,
        };
        g.bench_function(name, |b| {
            b.iter(|| black_box(query::run(&db, &req, T0).unwrap()))
        });
    }
    g.finish();
}

criterion_group!(benches, collect, year);
criterion_main!(benches);
