//! G1.23 — one commit on the file backend (temp file, fsync, rename,
//! directory fsync) with a big config and a full history: 10 000 static
//! routes and 64 revisions, what a carrier edge router carries. Before
//! G1.23 every commit rewrote the whole history; now it writes the running
//! config and its own revision.
//!
//! `commit/ppp_secret_add/N` (G4.3gb): one `ppp.secret.add` (its own
//! commit, with fsync) with N secrets in place, removed again outside the
//! timing: what provisioning a subscriber by API costs on a big base.
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
use criterion::{BenchmarkId, Criterion, criterion_group};
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
    for n in [10_000u32, 100_000] {
        let mut cfg = Session::virtual_lab().store().running().clone();
        for i in 0..n {
            cfg.ppp.secrets.push(corerouter_model::ppp::PppSecret {
                id: ItemId(i + 1),
                name: format!("cliente{i}@isp"),
                password: format!("senha{i}").into(),
                profile: "default".into(),
                ..Default::default()
            });
        }
        cfg.ppp.next_id = n;
        let dir = directory(&format!("bench-secrets-{n}"), cfg, 1);
        let mut s = boot(&dir);
        assert_eq!(
            s.store().running().ppp.secrets.len(),
            n as usize,
            "{:?}",
            s.storage_status()
        );
        let mut tag = 0u64;
        g.bench_function(BenchmarkId::new("commit/ppp_secret_add", n), |b| {
            b.iter_custom(|iters| {
                let mut spent = Duration::ZERO;
                for _ in 0..iters {
                    tag += 1;
                    let name = format!("bench{tag}");
                    let t = std::time::Instant::now();
                    s.execute("ppp.secret.add", &json!({"name": name, "password": "x"}))
                        .unwrap();
                    spent += t.elapsed();
                    s.execute("ppp.secret.remove", &json!({"id": name}))
                        .unwrap();
                }
                spent
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
        // The boot's peak memory, alone in a process of its own.
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .env(BOOT_RSS, &dir)
            .output()
            .unwrap();
        eprint!(
            "history64/{name}: {}",
            String::from_utf8_lossy(&child.stdout)
        );
        g.bench_function(BenchmarkId::new("boot", name), |b| {
            b.iter(|| boot(&dir).store().history().len());
        });
        let _ = std::fs::remove_dir_all(&dir);
    }
    g.finish();
}

/// Set to a config directory: the bench process only boots it and prints
/// the peak resident memory (`VmHWM`) and what stays resident (`VmRSS`).
const BOOT_RSS: &str = "COREROUTER_BENCH_BOOT_RSS";

fn status_kib(field: &str) -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find_map(|l| {
            l.strip_prefix(field)?
                .trim()
                .strip_suffix("kB")?
                .trim()
                .parse()
                .ok()
        })
        .unwrap_or(0)
}

fn boot_rss(dir: &str) {
    let before = status_kib("VmRSS:");
    let s = boot(Path::new(dir));
    let n = s.store().history().len();
    println!(
        "boot of {n} revisions: peak RSS {} MiB, resident after {} MiB (process start {} MiB)",
        status_kib("VmHWM:") / 1024,
        status_kib("VmRSS:") / 1024,
        before / 1024,
    );
}

criterion_group!(benches, commit, history64);

fn main() {
    if let Ok(dir) = std::env::var(BOOT_RSS) {
        boot_rss(&dir);
        return;
    }
    benches();
    Criterion::default().configure_from_args().final_summary();
}
