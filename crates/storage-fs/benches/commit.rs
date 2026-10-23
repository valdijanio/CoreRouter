//! G1.23 — one commit on the file backend (temp file, fsync, rename,
//! directory fsync) with a big config and a full history: 10 000 static
//! routes and 64 revisions, what a carrier edge router carries. Before
//! G1.23 every commit rewrote the whole history; now it writes the running
//! config and its own revision.
//!
//! `history64/*` (audit-history): the same with a 5 MiB and a 10 MiB config
//! (what an ISP edge carries: thousands of rules, tens of thousands of
//! address-list entries, routes and static leases) — a small commit, the
//! boot (`Session::with_storage`), and, printed, how many of the 64
//! revisions a reboot restores and the bytes on disk.
//!
//! `cargo xtask bench commit_fs`; alone: `cargo bench -p corerouter-storage-fs --bench commit`.
//! The directory is under the build's tmp dir (a real disk, not tmpfs).

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use corerouter_engine::{ConfigStorage, Session};
use corerouter_hal::VirtualHal;
use corerouter_model::firewall::{Action, AddressListEntry};
use corerouter_model::{
    AddressEntry, Config, ConfigStore, FirewallRule, Gateway, ItemId, RouteEntry, RoutingTable,
    persist,
};
use corerouter_storage_fs::FileStorage;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use serde_json::json;

/// The lab's own config with 192.0.2.1/24 on ether1 and `n` distinct
/// static /24 routes through 192.0.2.254.
fn routes(n: usize) -> Config {
    let mut cfg = Session::virtual_lab().store().running().clone();
    let id = cfg.ip.next_address_id();
    cfg.ip.addresses.push(AddressEntry {
        id,
        address: "192.0.2.1/24".parse().unwrap(),
        interface: "ether1".parse().unwrap(),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
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

/// The i-th of up to 65 536 distinct addresses inside 10.1.0.0/16.
fn host(i: usize) -> Ipv4Addr {
    let [hi, lo] = u16::try_from(i).unwrap().to_be_bytes();
    Ipv4Addr::new(10, 1, hi, lo)
}

/// The lab with `rules` filter rules, `lists` address-list entries,
/// `routes` static routes and `leases` static DHCP leases.
fn isp(rules: usize, lists: usize, n_routes: usize, leases: usize) -> Config {
    let mut cfg = routes(n_routes);
    for i in 0..rules {
        let matchers = serde_json::from_value(json!({
            "src_address": host(i).to_string(), "protocol": "tcp"}))
        .unwrap();
        cfg.ip.firewall.filter.push(FirewallRule {
            id: ItemId(u32::try_from(i + 1).unwrap()),
            chain: "forward".parse().unwrap(),
            family: Default::default(),
            matchers,
            action: Action::Drop,
            disabled: false,
            comment: format!("customer {i}"),
            section: false,
            zone: false,
        });
    }
    for i in 0..lists {
        cfg.ip.firewall.address_lists.push(AddressListEntry {
            id: ItemId(u32::try_from(i + 1).unwrap()),
            list: format!("l{}", i % 200).parse().unwrap(),
            address: host(i).to_string().parse().unwrap(),
            disabled: false,
            comment: String::new(),
        });
    }
    for i in 0..leases {
        let (hi, lo) = (i >> 8, i & 0xff);
        let lease = serde_json::from_value(json!({
            "id": format!("*{:X}", i + 1),
            "address": format!("100.64.{hi}.{lo}"),
            "mac_address": format!("02:00:00:00:{hi:02x}:{lo:02x}"),
            "comment": format!("subscriber {i}"),
        }))
        .unwrap();
        cfg.ip.dhcp_server.leases.push(lease);
    }
    // Restored like a saved file: id counters past the items.
    persist::repair_ids(cfg)
}

/// Bytes of the files in `dir` whose name starts with `prefix`.
fn disk_bytes(dir: &Path, prefix: &str) -> f64 {
    let bytes: u64 = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| {
            let e = e.ok()?;
            e.file_name().to_str()?.starts_with(prefix).then_some(())?;
            e.metadata().ok()
        })
        .map(|m| m.len())
        .sum();
    bytes as f64 / 1_048_576.0
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

fn boot(dir: &Path) -> Session {
    Session::with_storage(
        Box::new(VirtualHal::default()),
        Box::new(FileStorage::open(dir).unwrap()),
    )
}

fn history64(c: &mut Criterion) {
    let mut g = c.benchmark_group("storage_fs/history64");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(10));
    for (name, cfg) in [
        ("5mib", isp(4000, 20_000, 10_000, 10_000)),
        ("10mib", isp(4000, 65_536, 30_000, 0)),
    ] {
        let dir =
            PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("bench-history64-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        let size = persist::encoded_len(&cfg);
        FileStorage::open(&dir)
            .unwrap()
            .save(&persist::encode(&ConfigStore::new(cfg)).unwrap())
            .unwrap();
        // 63 small commits: 64 revisions in memory.
        let mut s = boot(&dir);
        for i in 0..63 {
            s.execute(
                "interface.set",
                &json!({"name": "ether2", "comment": format!("c{i}")}),
            )
            .unwrap();
        }
        assert_eq!(s.store().history().len(), 64);
        let mut flip = false;
        g.bench_function(BenchmarkId::new("commit", name), |b| {
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
        let memory: Vec<u32> = s.store().history().iter().map(|r| r.number).collect();
        drop(s);
        let restored = boot(&dir);
        let back: Vec<u32> = restored
            .store()
            .history()
            .iter()
            .map(|r| r.number)
            .collect();
        eprintln!(
            "history64/{name}: config {:.1} MiB, {} of {} revisions restored, \
             {:.1} MiB on disk ({:.2} MiB in revision files)",
            size as f64 / 1_048_576.0,
            back.len(),
            memory.len(),
            disk_bytes(&dir, ""),
            disk_bytes(&dir, "rev-"),
        );
        drop(restored);
        g.bench_function(BenchmarkId::new("boot", name), |b| {
            b.iter(|| boot(&dir).store().history().len());
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
    g.finish();
}

criterion_group!(benches, commit, history64);
criterion_main!(benches);
