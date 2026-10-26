//! Engine cost with a big config already committed (audit-net): what one
//! more commit costs with N filter rules, routes, addresses or address-list
//! entries in place, the whole-config validation alone, and `ip.route.list`.
//! Before audit-net several of these grew quadratically with N. And
//! `import/*` (audit-perf): an atomic batch of N adds, what `/import` of an
//! `/export` sends (every step copied the whole candidate before).
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-engine --bench scale`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::net::Ipv4Addr;
use std::time::Duration;

use corerouter_engine::validate::validate_all;
use corerouter_engine::{MemoryStorage, Session, Slot};
use corerouter_firewall::sample;
use corerouter_model::firewall::{Action, AddressListEntry};
use corerouter_model::{
    AddressEntry, Config, ConfigStore, Gateway, IfName, ItemId, RouteEntry, RoutingTable, persist,
};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use serde_json::json;

fn name(s: &str) -> IfName {
    s.parse().unwrap()
}

/// The i-th of up to 65 536 distinct addresses inside 10.1.0.0/16.
fn host(i: usize) -> Ipv4Addr {
    let [hi, lo] = u16::try_from(i).unwrap().to_be_bytes();
    Ipv4Addr::new(10, 1, hi, lo)
}

/// The lab's own config (8 ports) with 192.0.2.1/24 on ether1.
fn lab() -> Config {
    let mut cfg = Session::virtual_lab().store().running().clone();
    push_address(&mut cfg, "192.0.2.1/24");
    cfg
}

fn push_address(cfg: &mut Config, a: &str) {
    let id = cfg.ip.next_address_id();
    cfg.ip.addresses.push(AddressEntry {
        id,
        address: a.parse().unwrap(),
        interface: name("ether1"),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
}

/// `n` filter rules: forward jumps to 50 custom chains, each dropping
/// source addresses (a long hand-written block list split by customer).
fn filter_rules(n: usize) -> Config {
    let mut cfg = lab();
    let chains = 50;
    for c in 0..chains {
        let rule = sample::rule(
            u32::try_from(c + 1).unwrap(),
            "forward",
            sample::m(&[]).unwrap(),
            sample::act(&format!(r#"{{"type":"jump","jump_target":"cust{c}"}}"#)).unwrap(),
        )
        .unwrap();
        cfg.ip.firewall.filter.push(rule);
    }
    for i in chains..n {
        let src = host(i).to_string();
        let rule = sample::rule(
            u32::try_from(i + 1).unwrap(),
            &format!("cust{}", i % chains),
            sample::m(&[("src_address", src.as_str()), ("protocol", "tcp")]).unwrap(),
            Action::Drop,
        )
        .unwrap();
        cfg.ip.firewall.filter.push(rule);
    }
    cfg
}

/// `n` distinct static /24 routes via 192.0.2.254.
fn routes(n: usize) -> Config {
    let mut cfg = lab();
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

/// `n` /32 addresses on ether1.
fn addresses(n: usize) -> Config {
    let mut cfg = lab();
    for i in 0..n {
        push_address(&mut cfg, &format!("{}/32", host(i)));
    }
    cfg
}

/// `n` address-list entries spread over 200 lists.
fn address_lists(n: usize) -> Config {
    let mut cfg = lab();
    for i in 0..n {
        cfg.ip.firewall.address_lists.push(AddressListEntry {
            id: ItemId(u32::try_from(i + 1).unwrap()),
            list: format!("l{}", i % 200).parse().unwrap(),
            address: host(i).to_string().parse().unwrap(),
            disabled: false,
            comment: String::new(),
        });
    }
    cfg
}

/// A session whose running config is `cfg` (restored from storage).
fn session_with(cfg: &Config) -> Session {
    let storage = MemoryStorage::default();
    let text = persist::encode(&ConfigStore::new(cfg.clone())).unwrap();
    storage.put(Slot::Current, Some(text));
    let s = Session::with_storage(
        Box::new(corerouter_hal::virt::VirtualHal::default()),
        Box::new(storage),
    );
    // (The restore repairs the id counters the fixtures leave at 0.)
    let diff: Vec<_> = corerouter_model::store::diff_configs(cfg, s.store().running())
        .into_iter()
        .filter(|d| !format!("{d:?}").contains("next_"))
        .collect();
    assert!(diff.is_empty(), "config not restored: {:?}", diff.first());
    s
}

type Build = fn(usize) -> Config;

fn scale(c: &mut Criterion) {
    let cases: [(&str, Build, &[usize]); 4] = [
        ("filter_rules", filter_rules, &[1000, 3000]),
        ("routes", routes, &[1000, 10_000]),
        ("addresses", addresses, &[1000, 10_000]),
        ("address_lists", address_lists, &[20_000]),
    ];
    let mut g = c.benchmark_group("engine_scale");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(3));
    for (kind, build, sizes) in cases {
        for &n in sizes {
            let cfg = build(n);
            g.bench_with_input(
                BenchmarkId::new(format!("validate_all/{kind}"), n),
                &cfg,
                |b, cfg| {
                    b.iter(|| validate_all(black_box(cfg)));
                },
            );
            // G0.22: each validator on its own (what threads could split).
            if n == 10_000 && kind == "routes" {
                for u in corerouter_engine::validate::UNITS {
                    g.bench_with_input(
                        BenchmarkId::new(format!("validate_unit/{}/{kind}", u.name), n),
                        &cfg,
                        |b, cfg| b.iter(|| (u.run)(black_box(cfg))),
                    );
                }
            }
            // One more commit that touches nothing of the big list.
            let mut s = session_with(&cfg);
            let mut flip = false;
            g.bench_function(BenchmarkId::new(format!("commit/{kind}"), n), |b| {
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
            if kind == "routes" {
                g.bench_function(BenchmarkId::new("ip.route.list", n), |b| {
                    b.iter(|| s.execute("ip.route.list", black_box(&json!({}))).unwrap());
                });
            }
        }
    }
    // `/import`: one atomic batch of N address-list adds on a fresh lab.
    for n in [1000usize, 5000] {
        let steps: Vec<_> = (0..n)
            .map(|i| {
                json!({"command": "ip.firewall.address-list.add",
                       "params": {"list": "blocked", "address": host(i).to_string()}})
            })
            .collect();
        let steps = json!(steps);
        g.bench_function(BenchmarkId::new("import/address_lists", n), |b| {
            b.iter_batched(
                Session::virtual_lab,
                |mut s| {
                    s.batch(black_box(&steps), true).unwrap();
                    s
                },
                criterion::BatchSize::LargeInput,
            );
        });
    }
    g.finish();
}

criterion_group!(benches, scale);
criterion_main!(benches);
