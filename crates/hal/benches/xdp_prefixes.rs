//! G0.22 × G2.5a — what the XDP filter's userspace pays per change with N
//! address-list entries in a block list (the map writes themselves are one
//! call per changed prefix either way):
//!
//! - `…/plan_of/N`: the way before, [`XdpPlan::of`] (every entry covered,
//!   sorted) and the difference with the plan applied before (two
//!   `BTreeMap`s), as `hal-linux`'s `XdpState::sync` did on every commit
//!   and on every dynamic entry;
//! - `…/follow/N`: [`XdpPrefixes::follow`] (only the blocks of entries the
//!   commit changed) or [`XdpPrefixes::dynamic`], then `take_changes`.
//!
//! Changes: `unrelated` (a commit that touches no address list),
//! `static_add` (one `ip.firewall.address-list.add`), `dynamic_add` (one
//! dynamic entry: a PPP session that came up with an address list).
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-hal --bench xdp_prefixes`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::hint::black_box;

use corerouter_hal::xdp::{XdpPlan, XdpPrefixes};
use corerouter_model::firewall::{AddrMatch, AddressListEntry, DynamicAddress};
use corerouter_model::xdp::{XdpInterface, XdpMode};
use corerouter_model::{Config, IfName, Interface, InterfaceKind, ItemId};
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use ipnet::IpNet;

fn entry(i: u32) -> AddressListEntry {
    AddressListEntry {
        id: ItemId(i + 1),
        list: "bad".parse().unwrap(),
        address: AddrMatch::Net(IpNet::from(std::net::IpAddr::from(
            std::net::Ipv4Addr::from(0x0a00_0000 + i),
        ))),
        disabled: false,
        comment: String::new(),
    }
}

/// `n` block-list entries, the filter on ether1.
fn config(n: u32) -> Config {
    let mut cfg = Config::default();
    let e1: IfName = "ether1".parse().unwrap();
    cfg.interfaces.insert(
        e1.clone(),
        Interface::new(e1.clone(), InterfaceKind::Ethernet),
    );
    cfg.ip.xdp.interfaces.push(XdpInterface {
        interface: e1,
        mode: XdpMode::Auto,
        disabled: false,
        comment: String::new(),
    });
    cfg.ip.xdp.filter.block_lists = vec!["bad".parse().unwrap()];
    for i in 0..n {
        cfg.ip.firewall.address_lists.push(entry(i));
    }
    cfg
}

/// The old sync's difference: what to remove and what to write.
fn diff(from: &[(IpNet, u32)], to: &[(IpNet, u32)]) -> usize {
    let old: BTreeMap<IpNet, u32> = from.iter().copied().collect();
    let new: BTreeMap<IpNet, u32> = to.iter().copied().collect();
    old.keys().filter(|k| !new.contains_key(k)).count()
        + new.iter().filter(|(k, v)| old.get(k) != Some(v)).count()
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("xdp_prefixes");
    g.sample_size(10);
    for n in [1_000u32, 10_000, 100_000] {
        let base = config(n);
        let applied = XdpPlan::of(&base, &[]);
        let mut x = XdpPrefixes::default();
        x.follow(&base, []);
        let _ = x.take_changes();
        let mut unrelated = base.clone();
        unrelated.system.identity = "other".into();
        let mut added = base.clone();
        added.ip.firewall.address_lists.push(entry(n + 1));
        let d = DynamicAddress {
            list: "bad".parse().unwrap(),
            address: AddrMatch::Net("192.0.2.1/32".parse().unwrap()),
            timeout_secs: 0,
            added_by_rule: false,
        };
        let one = [d.clone()];
        for (change, cfg) in [("unrelated", &unrelated), ("static_add", &added)] {
            g.bench_function(BenchmarkId::new(format!("{change}/plan_of"), n), |b| {
                b.iter(|| diff(&applied.block, &XdpPlan::of(black_box(cfg), &[]).block));
            });
            g.bench_function(BenchmarkId::new(format!("{change}/follow"), n), |b| {
                // The copy is set up untimed and dropped untimed.
                b.iter_batched(
                    || x.clone(),
                    |mut y| {
                        y.follow(black_box(cfg), []);
                        let c = y.take_changes();
                        (y, c)
                    },
                    BatchSize::LargeInput,
                );
            });
        }
        g.bench_function(BenchmarkId::new("dynamic_add/plan_of", n), |b| {
            b.iter(|| diff(&applied.block, &XdpPlan::of(black_box(&base), &one).block));
        });
        g.bench_function(BenchmarkId::new("dynamic_add/follow", n), |b| {
            b.iter_batched(
                || x.clone(),
                |mut y| {
                    y.dynamic(black_box(&d), true);
                    let c = y.take_changes();
                    (y, c)
                },
                BatchSize::LargeInput,
            );
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
