//! G1.27d — a BNG-sized neighbor table in the engine: 100 thousand ARP
//! entries on 8 ports (5% IPv6). What it costs: loading a dump, applying
//! one event (the feed's work per kernel change), and a page of
//! `ip.arp.list` unfiltered, by CIDR, by MAC prefix, by state. Prints the
//! resident memory the table adds (`/proc/self/statm`).
//!
//! `cargo bench -p corerouter-engine --bench neigh_table`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use corerouter_engine::Session;
use corerouter_engine::neigh_table::NeighTable;
use corerouter_hal::neigh::{NeighEvent, NeighState, Neighbor};
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::json;

/// Resident memory of the process now, from `/proc/self/statm` (Linux;
/// 0 elsewhere). The project forbids `unsafe`, so no counting allocator.
fn rss() -> i64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|t| t.split_whitespace().nth(1)?.parse::<i64>().ok())
        .map_or(0, |pages| pages * 4096)
}

const N: u32 = 100_000;

fn neighbor(i: u32) -> Neighbor {
    let port = format!("ether{}", 1 + i % 8);
    let address = if i.is_multiple_of(20) {
        IpAddr::V6(Ipv6Addr::new(
            0x2001,
            0xdb8,
            0,
            (i % 8) as u16,
            0,
            0,
            (i >> 16) as u16,
            i as u16,
        ))
    } else {
        IpAddr::V4(Ipv4Addr::from(0x6440_0000 + i))
    };
    let state = match i % 10 {
        0..=6 => NeighState::Reachable,
        7 | 8 => NeighState::Stale,
        _ => NeighState::Incomplete,
    };
    Neighbor {
        interface: port.parse().unwrap(),
        address,
        mac: state.resolved().then_some({
            [
                0x02,
                (i >> 24) as u8,
                (i >> 16) as u8,
                (i >> 8) as u8,
                i as u8,
                7,
            ]
        }),
        state,
        router: false,
        confirmed_secs: Some(i % 30),
        updated_secs: Some(i % 60),
    }
}

fn neigh_100k(c: &mut Criterion) {
    let dump: Vec<Neighbor> = (0..N).map(neighbor).collect();
    let before = rss();
    let mut t = NeighTable::default();
    t.load(dump.clone(), 1_000_000);
    let held = rss() - before;
    eprintln!(
        "neigh_100k: {} entries, resident memory +{} bytes: ~{} bytes per entry",
        t.len(),
        held,
        held / i64::from(N)
    );
    let mut g = c.benchmark_group("neigh_100k");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(5));
    g.bench_function("load", |b| {
        b.iter(|| {
            let mut t = NeighTable::default();
            t.load(black_box(dump.clone()), 1_000_000);
            t
        });
    });
    // One kernel change: an entry going stale and back.
    let mut flip = 0u32;
    g.bench_function("apply_one_event", |b| {
        b.iter(|| {
            flip = flip.wrapping_add(1);
            let mut n = neighbor(flip % N);
            n.state = if flip.is_multiple_of(2) {
                NeighState::Stale
            } else {
                NeighState::Reachable
            };
            t.apply(black_box(&[NeighEvent::Upsert(n)]), 1_000_001);
        });
    });

    let mut s = Session::virtual_lab();
    {
        let shared = s.neigh_shared();
        let mut tab = shared.lock();
        tab.load(dump.clone(), 1_000_000);
        tab.fed = true;
    }
    for (name, p) in [
        ("list/first_page", json!({})),
        ("list/last_page", json!({"offset": 94_500})),
        ("list/cidr_/20", json!({"search": "100.64.16.0/20"})),
        ("list/mac_prefix", json!({"search": "02:00:01"})),
        ("list/state_incomplete", json!({"state": "incomplete"})),
        ("list/text_ether3", json!({"search": "ether3"})),
        // G1.27d OUI: every row's vendor looked up (no vendor matches).
        ("list/text_vendor", json!({"search": "cisco"})),
    ] {
        g.bench_function(name, |b| {
            b.iter(|| s.execute("ip.arp.list", black_box(&p)).unwrap());
        });
    }
    // One vendor lookup in the built-in table (binary search in place).
    let t = corerouter_model::oui::Table::new(corerouter_model::oui::BUILTIN).unwrap();
    let mut i = 0u32;
    g.bench_function("oui_lookup", |b| {
        b.iter(|| {
            i = i.wrapping_add(0x9e37);
            let mac = [((i >> 16) as u8) & 0xfc, (i >> 8) as u8, i as u8, 0, 0, 0];
            black_box(t.vendor(mac))
        });
    });
    g.bench_function("oui_check_table", |b| {
        b.iter(|| {
            corerouter_model::oui::Table::new(black_box(corerouter_model::oui::BUILTIN))
                .unwrap()
                .len()
        });
    });
    g.finish();
}

criterion_group!(benches, neigh_100k);
criterion_main!(benches);
