//! G0.31 — how long one query holds the session lock with an ISP-sized
//! config. Every command of the daemon runs inside `lock(&shared)`: while
//! a read runs, DHCP, PPPoE, the metrics scrape and every other client
//! wait. `sweep` runs every query of the registry once with `{}` on a
//! config of 1000 VLANs, 10 000 filter rules, 100 000 address-list
//! entries and 60 000 static routes (the cap is 65 536) and prints the slowest (cold = first call,
//! warm = best of the next three); the criterion group times the worst.
//!
//! `cargo bench -p corerouter-engine --bench lock_hold` (the sweep prints
//! first; `LOCK_HOLD_SWEEP=0` skips it).

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use corerouter_engine::Session;
use corerouter_firewall::sample;
use corerouter_model::firewall::{Action, AddressListEntry};
use corerouter_model::{AddressEntry, Gateway, ItemId, RouteEntry, RoutingTable};
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::{Value, json};

const VLANS: usize = 1000;
const RULES: usize = 10_000;
const LIST_ENTRIES: usize = 100_000;
const ROUTES: usize = 60_000;

fn v4(i: usize) -> Ipv4Addr {
    Ipv4Addr::from(0x0A00_0000u32 + u32::try_from(i).unwrap())
}

/// The lab with the big config committed (VLANs by command, the rest put
/// straight into the running config, as `perf::with_running` does).
fn big() -> Session {
    let mut s = Session::virtual_lab();
    for i in 0..VLANS {
        s.execute(
            "interface.vlan.add",
            &json!({"name": format!("vlan{}", i + 1), "parent": "ether2", "vlan_id": i + 1}),
        )
        .unwrap();
    }
    let mut cfg = s.store().running().clone();
    let chains = 50;
    for c in 0..chains {
        cfg.ip.firewall.filter.push(
            sample::rule(
                u32::try_from(c + 1).unwrap(),
                "forward",
                sample::m(&[]).unwrap(),
                sample::act(&format!(r#"{{"type":"jump","jump_target":"cust{c}"}}"#)).unwrap(),
            )
            .unwrap(),
        );
    }
    for i in chains..RULES {
        let src = v4(i).to_string();
        cfg.ip.firewall.filter.push(
            sample::rule(
                u32::try_from(i + 1).unwrap(),
                &format!("cust{}", i % chains),
                sample::m(&[("src_address", src.as_str()), ("protocol", "tcp")]).unwrap(),
                Action::Drop,
            )
            .unwrap(),
        );
    }
    for i in 0..LIST_ENTRIES {
        cfg.ip.firewall.address_lists.push(AddressListEntry {
            id: ItemId(u32::try_from(i + 1).unwrap()),
            list: format!("l{}", i % 200).parse().unwrap(),
            address: v4(i).to_string().parse().unwrap(),
            disabled: false,
            comment: String::new(),
        });
    }
    let mut routes = Vec::with_capacity(ROUTES);
    for i in 0..ROUTES {
        let k = u32::try_from(i).unwrap();
        routes.push(RouteEntry {
            id: ItemId(k + 1),
            dst_address: format!("{}/24", Ipv4Addr::from(0x2000_0000u32 + k * 256))
                .parse()
                .unwrap(),
            gateway: Gateway::ip("192.168.88.254".parse().unwrap()),
            distance: 1,
            routing_table: RoutingTable::Main,
            disabled: false,
            comment: String::new(),
            check_gateway: Default::default(),
            bfd_profile: String::new(),
        });
    }
    cfg.ip.routes = routes.into();
    cfg.ip.next_route_id = u32::try_from(ROUTES + 1).unwrap();
    for i in 0..4 {
        let id = cfg.ip.next_address_id();
        cfg.ip.addresses.push(AddressEntry {
            id,
            address: format!("192.168.{}.1/24", 88 + i).parse().unwrap(),
            interface: "ether1".parse().unwrap(),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
    }
    corerouter_engine::perf::with_running(cfg)
}

/// Every query that takes `{}`, with the time of its first call and the
/// best of three more; the slowest first.
fn sweep(s: &mut Session) -> Vec<(String, Duration, Duration, usize)> {
    let list = s.list();
    let mut out = Vec::new();
    for c in list.as_array().into_iter().flatten() {
        let id = c["id"].as_str().unwrap_or_default().to_string();
        if c["kind"] != "query" || c["task"].as_bool() == Some(true) || id.starts_with("tool.") {
            continue;
        }
        let t = Instant::now();
        let first = s.execute(&id, &json!({}));
        let cold = t.elapsed();
        let Ok(v) = first else { continue };
        let size = serde_json::to_string(&v).map(|t| t.len()).unwrap_or(0);
        let mut warm = Duration::MAX;
        for _ in 0..3 {
            let t = Instant::now();
            black_box(s.execute(&id, &json!({})).ok());
            warm = warm.min(t.elapsed());
        }
        out.push((id, cold, warm, size));
    }
    out.sort_by_key(|a| std::cmp::Reverse(a.1.max(a.2)));
    out
}

fn lock_hold(c: &mut Criterion) {
    let t = Instant::now();
    let mut s = big();
    eprintln!("lock_hold: big config built in {:?}", t.elapsed());
    if std::env::var("LOCK_HOLD_SWEEP").as_deref() != Ok("0") {
        let rows = sweep(&mut s);
        eprintln!("lock_hold sweep: {} queries", rows.len());
        eprintln!(
            "{:<48} {:>12} {:>12} {:>12}",
            "query", "cold", "warm", "bytes"
        );
        for (id, cold, warm, size) in rows.iter().take(40) {
            eprintln!("{id:<48} {cold:>12.2?} {warm:>12.2?} {size:>12}");
        }
    }
    let mut g = c.benchmark_group("lock_hold");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(5));
    g.bench_function("state.inspect", |b| {
        b.iter(|| black_box(s.inspect(None).ok()))
    });
    for id in ["config.diff", "interface.list", "ip.firewall.filter.list"] {
        g.bench_function(id, |b| {
            b.iter(|| black_box(s.execute(id, &Value::Null).ok()))
        });
    }
    // Transactional mode with one pending change (the identity): what the
    // GUI asks on every refresh while the operator edits.
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    s.execute("system.identity.set", &json!({"name": "edge-2"}))
        .unwrap();
    g.bench_function("config.diff/pending_identity", |b| {
        b.iter(|| black_box(s.execute("config.diff", &Value::Null).ok()))
    });
    g.bench_function("state.inspect/pending_identity", |b| {
        b.iter(|| black_box(s.inspect(None).ok()))
    });
    // One pending route: the 60 000 routes are serialized on both sides
    // (item-by-item diff of a big list: G0.31a).
    s.execute(
        "ip.route.add",
        &json!({"dst_address": "198.51.100.0/24", "gateway": "192.168.88.254"}),
    )
    .unwrap();
    g.bench_function("config.diff/pending_route", |b| {
        b.iter(|| black_box(s.execute("config.diff", &Value::Null).ok()))
    });
    g.finish();
}

criterion_group!(benches, lock_hold);
criterion_main!(benches);
