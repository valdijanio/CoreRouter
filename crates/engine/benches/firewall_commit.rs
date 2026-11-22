//! The commit of one firewall rule with thousands in place (G0.31j): the
//! validation of the image (T1, 2026-10-29) measured ~100 ms to change one
//! comment with 4 000 filter + 4 000 raw + 2 000 mangle rules, against 6 ms
//! of a commit without a firewall. `commit/interface_comment` is that
//! reference commit on the same config; `commit/filter_comment` and
//! `commit/filter_dst_port` change one filter rule (a comment, a matcher)
//! and `commit/raw_comment` one raw rule; `validate/firewall` is the whole
//! validation the commit no longer runs. `filter_10000` is the ISP config
//! of the G0.31 benchmarks (10 000 filter rules), which `MAX_RULES` refused
//! until G0.31j.
//!
//! `cargo xtask bench firewall_commit`; alone:
//! `cargo bench -p corerouter-engine --bench firewall_commit`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;
use std::time::Duration;

use corerouter_engine::{MemoryStorage, Session, Slot};
use corerouter_firewall::sample;
use corerouter_model::firewall::{Action, FirewallRule};
use corerouter_model::{Config, ConfigStore, persist};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use serde_json::json;

/// The i-th of up to 65 536 distinct addresses inside 10.1.0.0/16.
fn host(i: u32) -> Ipv4Addr {
    let [hi, lo] = u16::try_from(i % 65_536).unwrap().to_be_bytes();
    Ipv4Addr::new(10, 1 + u8::try_from(i / 65_536).unwrap(), hi, lo)
}

/// Rule `id`: one source address and one TCP port, so no rule shadows
/// another (what a long hand-written block list looks like).
fn rule(id: u32, chain: &str, action: Action) -> FirewallRule {
    let src = host(id).to_string();
    let port = (1000 + id % 60_000).to_string();
    let mut r = sample::rule(
        id,
        chain,
        sample::m(&[
            ("src_address", src.as_str()),
            ("protocol", "tcp"),
            ("dst_port", port.as_str()),
        ])
        .unwrap(),
        action,
    )
    .unwrap();
    r.comment = format!("rule {id}");
    r
}

fn config(filter: u32, raw: u32, mangle: u32) -> Config {
    let mut cfg = Session::virtual_lab().store().running().clone();
    let fw = &mut cfg.ip.firewall;
    let mut id = 0;
    for i in 0..filter {
        id += 1;
        let chain = if i % 2 == 0 { "input" } else { "forward" };
        fw.filter.push(rule(id, chain, Action::Drop));
    }
    for _ in 0..raw {
        id += 1;
        fw.raw.push(rule(id, "prerouting", Action::Drop));
    }
    for _ in 0..mangle {
        id += 1;
        fw.mangle.push(rule(id, "prerouting", Action::Accept));
    }
    cfg
}

/// A session whose running config is `cfg` (restored from storage, which
/// also repairs the id counters).
fn session_with(cfg: &Config) -> Session {
    let storage = MemoryStorage::default();
    let text = persist::encode(&ConfigStore::new(cfg.clone())).unwrap();
    storage.put(Slot::Current, Some(text));
    let s = Session::with_storage(
        Box::new(corerouter_hal::virt::VirtualHal::default()),
        Box::new(storage),
    );
    assert_eq!(
        s.store().running().ip.firewall.filter.len(),
        cfg.ip.firewall.filter.len(),
        "config not restored"
    );
    s
}

fn firewall_commit(c: &mut Criterion) {
    let mut g = c.benchmark_group("firewall_commit");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(4));
    for (name, cfg) in [
        ("4000_4000_2000", config(4000, 4000, 2000)),
        ("filter_10000", config(10_000, 0, 0)),
    ] {
        g.bench_function(BenchmarkId::new("validate/firewall", name), |b| {
            b.iter(|| corerouter_firewall::validate(std::hint::black_box(&cfg)));
        });
        let mut s = session_with(&cfg);
        // Before G0.31j a table over `MAX_RULES` (4096) was an issue: every
        // commit failed, so there is nothing to measure.
        if s.execute(
            "interface.set",
            &json!({"name": "ether2", "comment": "probe"}),
        )
        .is_err()
        {
            eprintln!("firewall_commit/{name}: config refused, skipped");
            continue;
        }
        let mid = s
            .store()
            .running()
            .ip
            .firewall
            .filter
            .get(1000)
            .unwrap()
            .id
            .to_string();
        let raw = s
            .store()
            .running()
            .ip
            .firewall
            .raw
            .get(1000)
            .map(|r| r.id.to_string());
        let mut flip = false;
        let mut next = || {
            flip = !flip;
            if flip { "a" } else { "b" }
        };
        g.bench_function(BenchmarkId::new("commit/interface_comment", name), |b| {
            b.iter(|| {
                s.execute(
                    "interface.set",
                    &json!({"name": "ether2", "comment": next()}),
                )
                .unwrap()
            });
        });
        g.bench_function(BenchmarkId::new("commit/filter_comment", name), |b| {
            b.iter(|| {
                s.execute(
                    "ip.firewall.filter.set",
                    &json!({"id": mid, "comment": next()}),
                )
                .unwrap()
            });
        });
        g.bench_function(BenchmarkId::new("commit/filter_dst_port", name), |b| {
            b.iter(|| {
                let port = if next() == "a" { "61001" } else { "61002" };
                s.execute(
                    "ip.firewall.filter.set",
                    &json!({"id": mid, "dst_port": port}),
                )
                .unwrap()
            });
        });
        if let Some(raw) = raw {
            g.bench_function(BenchmarkId::new("commit/raw_comment", name), |b| {
                b.iter(|| {
                    s.execute(
                        "ip.firewall.raw.set",
                        &json!({"id": raw, "comment": next()}),
                    )
                    .unwrap()
                });
            });
        }
    }
    g.finish();
}

criterion_group!(benches, firewall_commit);
criterion_main!(benches);
