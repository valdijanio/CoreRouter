//! G0.16 — one command at a time in transactional mode on a big config: what
//! the rollback point of each command costs. Before G0.16 every action
//! command copied the whole candidate, so building a config one command per
//! item was quadratic (323 s for a 10 MiB config, **medido** 2026-10-23).
//!
//! - `single/address_list_add_remove/60000`: one address-list entry added
//!   and removed again (two commands) with a 60 000-entry list in place;
//! - `single/address_list_add/60000`: the add alone (G0.21: < 20 µs), the
//!   entry removed again outside the timing;
//! - `single/interface.set/routes_10000`: a comment on a port with 10 000
//!   routes in place (touches nothing of the routes);
//! - `build/N`: a fresh lab built with N commands (65 % address-list
//!   entries, 30 % routes, 5 % filter rules, the mix of the 10 MiB case):
//!   the time per command should not grow with N.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-engine --bench transactional`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::Ipv4Addr;
use std::time::Duration;

use corerouter_engine::{MemoryStorage, Session, Slot};
use corerouter_model::firewall::AddressListEntry;
use corerouter_model::{ConfigStore, Gateway, ItemId, RouteEntry, RoutingTable, persist};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use serde_json::{Value, json};

/// The i-th address counting from 11.0.0.0 (distinct for any `u32`).
fn addr(i: u32) -> Ipv4Addr {
    Ipv4Addr::from(0x0b00_0000_u32.wrapping_add(i))
}

/// A session restored from a config with `lists` address-list entries and
/// `routes` routes, in transactional mode.
fn big_session(lists: u32, routes: u32) -> Session {
    let mut cfg = Session::virtual_lab().store().running().clone();
    for i in 0..lists {
        cfg.ip.firewall.address_lists.push(AddressListEntry {
            id: ItemId(i + 1),
            list: format!("l{}", i % 200).parse().unwrap(),
            address: addr(i).to_string().parse().unwrap(),
            disabled: false,
            comment: String::new(),
        });
    }
    cfg.ip.firewall.next_address_list_id = lists;
    for i in 0..routes {
        let [_, _, hi, lo] = i.to_be_bytes();
        cfg.ip.routes.push(RouteEntry {
            id: ItemId(i + 1),
            dst_address: format!("172.{}.{lo}.0/24", 16 + u32::from(hi))
                .parse()
                .unwrap(),
            gateway: Gateway::ip("192.0.2.254".parse().unwrap()),
            distance: 1,
            routing_table: RoutingTable::Main,
            disabled: false,
            comment: String::new(),
        });
    }
    cfg.ip.next_route_id = routes;
    let storage = MemoryStorage::default();
    storage.put(
        Slot::Current,
        Some(persist::encode(&ConfigStore::new(cfg)).unwrap()),
    );
    let mut s = Session::with_storage(
        Box::new(corerouter_hal::virt::VirtualHal::default()),
        Box::new(storage),
    );
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    s
}

/// Step `i` of the build: the 10 MiB case's mix of commands.
fn build_step(i: u32) -> (&'static str, Value) {
    match i % 20 {
        0 => (
            "ip.firewall.filter.add",
            json!({"chain": "forward", "protocol": "tcp",
                   "src_address": addr(i).to_string(), "action": "drop"}),
        ),
        1..=6 => {
            let [_, _, hi, lo] = i.to_be_bytes();
            (
                "ip.route.add",
                json!({"dst_address": format!("172.{}.{lo}.0/24", 16 + u32::from(hi)),
                       "gateway": "192.0.2.254"}),
            )
        }
        _ => (
            "ip.firewall.address-list.add",
            json!({"list": format!("l{}", i % 200), "address": addr(i).to_string()}),
        ),
    }
}

fn transactional(c: &mut Criterion) {
    let mut g = c.benchmark_group("engine_txn");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(5));

    // Added and removed again, so the list stays at 60 000 (the limit is
    // 65 536) however many iterations criterion runs.
    let mut s = big_session(60_000, 0);
    g.bench_function(
        BenchmarkId::new("single/address_list_add_remove", 60_000),
        |b| {
            b.iter(|| {
                let added = s
                    .execute(
                        "ip.firewall.address-list.add",
                        &json!({"list": "bench", "address": "198.51.100.7"}),
                    )
                    .unwrap();
                s.execute(
                    "ip.firewall.address-list.remove",
                    &json!({"id": added["id"]}),
                )
                .unwrap()
            });
        },
    );

    g.bench_function(BenchmarkId::new("single/address_list_add", 60_000), |b| {
        b.iter_custom(|iters| {
            let mut spent = Duration::ZERO;
            for _ in 0..iters {
                let t = std::time::Instant::now();
                let added = s
                    .execute(
                        "ip.firewall.address-list.add",
                        &json!({"list": "bench", "address": "198.51.100.7"}),
                    )
                    .unwrap();
                spent += t.elapsed();
                s.execute(
                    "ip.firewall.address-list.remove",
                    &json!({"id": added["id"]}),
                )
                .unwrap();
            }
            spent
        });
    });

    let mut s = big_session(0, 10_000);
    let mut flip = false;
    g.bench_function(
        BenchmarkId::new("single/interface.set", "routes_10000"),
        |b| {
            b.iter(|| {
                flip = !flip;
                let comment = if flip { "a" } else { "b" };
                s.execute(
                    "interface.set",
                    &json!({"name": "ether2", "comment": comment}),
                )
                .unwrap()
            });
        },
    );

    for n in [2_000_u32, 8_000] {
        g.bench_function(BenchmarkId::new("build", n), |b| {
            b.iter_batched(
                || {
                    let mut s = Session::virtual_lab();
                    s.execute(
                        "ip.address.add",
                        &json!({"address": "192.0.2.1/24", "interface": "ether1"}),
                    )
                    .unwrap();
                    s.execute("config.mode.set", &json!({"mode": "transactional"}))
                        .unwrap();
                    s
                },
                |mut s| {
                    for i in 0..n {
                        let (id, params) = build_step(i);
                        s.execute(id, &params).unwrap();
                    }
                    s
                },
                BatchSize::PerIteration,
            );
        });
    }
    g.finish();
}

criterion_group!(benches, transactional);
criterion_main!(benches);
