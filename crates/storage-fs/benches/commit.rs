//! G1.23 — one commit on the file backend (temp file, fsync, rename,
//! directory fsync) with a big config and a full history: 10 000 static
//! routes and 64 revisions, what a carrier edge router carries. Before
//! G1.23 every commit rewrote the whole history; now it writes the running
//! config and its own revision.
//!
//! `cargo xtask bench commit_fs`; alone: `cargo bench -p corerouter-storage-fs --bench commit`.
//! The directory is under the build's tmp dir (a real disk, not tmpfs).

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::time::Duration;

use corerouter_engine::{ConfigStorage, Session};
use corerouter_hal::VirtualHal;
use corerouter_model::{Config, ConfigStore, Gateway, RouteEntry, RoutingTable, persist};
use corerouter_storage_fs::FileStorage;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use serde_json::json;

/// The lab's own config with `n` distinct static /24 routes.
fn routes(n: usize) -> Config {
    let mut cfg = Session::virtual_lab().store().running().clone();
    for i in 0..n {
        let [hi, lo] = u16::try_from(i).unwrap().to_be_bytes();
        let id = cfg.ip.next_route_id();
        cfg.ip.routes.push(RouteEntry {
            id,
            dst_address: format!("172.{}.{lo}.0/24", 16 + hi).parse().unwrap(),
            gateway: Gateway::ip("192.0.2.254".parse().unwrap()),
            distance: 1,
            routing_table: RoutingTable::Main,
            disabled: false,
            comment: String::new(),
        });
    }
    cfg
}

/// A config directory holding `cfg` with `revisions` revisions of history.
fn directory(name: &str, cfg: Config, revisions: usize) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    let mut store = ConfigStore::new(cfg);
    for i in 0..revisions {
        store.candidate_mut().system.identity = format!("r{i}");
        store.commit("bench", None).unwrap();
    }
    let mut storage = FileStorage::open(&dir).unwrap();
    storage.save(&persist::encode(&store).unwrap()).unwrap();
    dir
}

fn commit(c: &mut Criterion) {
    let mut g = c.benchmark_group("storage_fs");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(5));
    for n in [1000usize, 10_000] {
        let dir = directory(&format!("bench-commit-{n}"), routes(n), 64);
        let mut s = Session::with_storage(
            Box::new(VirtualHal::default()),
            Box::new(FileStorage::open(&dir).unwrap()),
        );
        assert_eq!(s.store().history().len(), 64);
        let mut flip = false;
        g.bench_function(BenchmarkId::new("commit/routes_history64", n), |b| {
            b.iter(|| {
                flip = !flip;
                let comment = if flip { "a" } else { "b" };
                s.execute(
                    "interface.set",
                    &json!({"name": "ether2", "comment": comment}),
                )
                .unwrap()
            });
        });
        assert!(s.storage_status().last_error.is_none());
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }
    g.finish();
}

criterion_group!(benches, commit);
criterion_main!(benches);
