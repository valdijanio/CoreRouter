//! G4.9g — one queue live and the queues' history:
//!
//! - `queue_stats/cached/N`: one `queue.simple.stats` of a fixed queue with
//!   N simple queues in place, as the "Queue <name>" modal asks it once a
//!   second (the queue already resolved for this revision): must not grow
//!   with N;
//! - `queue_stats/first/N`: the first call (the queue looked up by name in
//!   the list's index, then by id); `…/first_moved/N` after a move, when
//!   the list is no longer in id order and the lookup by id walks it;
//! - `queue_graph/second/N`: one second of queue history (the `queue`
//!   service's round) with N fixed queues kept, `graph` on, under a cap
//!   that holds them all (`max_memory_mib` 4096; at most 4096 series);
//!   `…/capped/N` under the default 64 MiB, most queues refused.
//!
//! Memory per queue series and the total for 10 000 marked queues are
//! printed once (fixed by the layout, `Rrd::size_for`).
//!
//! `cargo xtask bench queue_live`; alone: `cargo bench -p corerouter-engine --bench queue_live`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use corerouter_engine::graph::rrd::Rrd;
use corerouter_engine::graph::{GraphDb, QUEUE_SOURCES};
use corerouter_engine::queue_live::QueueWatch;
use corerouter_engine::{MemoryStorage, Session, Slot};
use corerouter_model::queue::SimpleQueue;
use corerouter_model::{ConfigStore, ItemId, persist};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use serde_json::json;

const T0: u64 = 1_800_000_000;

/// `n` fixed queues (loaded as a saved config: past ~90 000 a commit would
/// pass the 15 MiB the config may take), the history cap at `mib`.
fn with_queues(n: usize, mib: u32) -> Session {
    let mut cfg = Session::virtual_lab().store().running().clone();
    for i in 0..n {
        let target = format!("10.{}.{}.{}/32", i >> 16, (i >> 8) & 255, i & 255);
        let mut q = SimpleQueue::new(ItemId(i as u32 + 1), format!("queue{}", i + 1), vec![target.parse().unwrap()]);
        q.max_limit = "10M/50M".parse().unwrap();
        cfg.queue.simple.push(q);
    }
    cfg.queue.next_id = n as u32;
    cfg.system.graphing.max_memory_mib = mib;
    let storage = MemoryStorage::default();
    storage.put(Slot::Current, Some(persist::encode(&ConfigStore::new(cfg)).unwrap()));
    let mut s = Session::with_storage(Box::new(corerouter_hal::virt::VirtualHal::default()), Box::new(storage));
    s.tick(T0);
    // The lab's shaper counts every queue once.
    s.queue_sync();
    s
}

fn stats(c: &mut Criterion) {
    let mut g = c.benchmark_group("queue_stats");
    for n in [10_000usize, 100_000] {
        let mut s = with_queues(n, 64);
        let name = format!("queue{}", n / 2);
        s.execute("queue.simple.stats", &json!({"id": name})).unwrap();
        g.bench_function(BenchmarkId::new("cached", n), |b| {
            b.iter(|| s.execute("queue.simple.stats", &json!({"id": name})).unwrap());
        });
        g.bench_function(BenchmarkId::new("first", n), |b| {
            b.iter(|| {
                *s.ext_mut::<QueueWatch>().unwrap() = QueueWatch::default();
                s.execute("queue.simple.stats", &json!({"id": name})).unwrap()
            });
        });
        // The last queue to the top: ids out of order from here on.
        s.execute("queue.simple.move", &json!({"id": format!("queue{n}"), "destination": "queue1"})).unwrap();
        s.queue_sync();
        g.bench_function(BenchmarkId::new("first_moved", n), |b| {
            b.iter(|| {
                *s.ext_mut::<QueueWatch>().unwrap() = QueueWatch::default();
                s.execute("queue.simple.stats", &json!({"id": name})).unwrap()
            });
        });
    }
    g.finish();
}

fn history(c: &mut Criterion) {
    let per = Rrd::size_for(QUEUE_SOURCES.len());
    println!(
        "queue series: {per} bytes ({:.0} KiB) each; 10 000 marked queues: {:.2} GiB (cap 4 GiB, at most {} series)",
        per as f64 / 1024.0,
        per as f64 * 10_000.0 / (1u64 << 30) as f64,
        corerouter_engine::graph::MAX_SERIES
    );
    let mut g = c.benchmark_group("queue_graph");
    g.sample_size(20);
    for (n, mib, kind) in [(1_000usize, 4096u32, "second"), (4_000, 4096, "second"), (10_000, 64, "capped"), (10_000, 4096, "capped")] {
        let mut s = with_queues(n, mib);
        s.queue_graph_sample();
        let db = s.ext::<GraphDb>().unwrap();
        println!(
            "{n} fixed queues, cap {mib} MiB: {} series kept, {} refused, {:.1} MiB",
            db.keys().filter(|k| k.starts_with("queue:")).count(),
            db.refused_queues(),
            db.memory_bytes() as f64 / (1u64 << 20) as f64
        );
        let id = if kind == "capped" { format!("{n}@{mib}MiB") } else { n.to_string() };
        g.bench_function(BenchmarkId::new(kind, id), |b| b.iter(|| s.queue_graph_sample()));
    }
    g.finish();
}

criterion_group!(benches, stats, history);
criterion_main!(benches);
