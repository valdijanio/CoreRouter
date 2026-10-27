//! G2.7b — the CGNAT usage scan and the capacity numbers for 65 536
//! subscribers with 20 connections each (1.3 million connections):
//!
//! - building the usage out of the connections, which the daemon does
//!   **outside** the session lock: the sorted vector of 12-byte entries
//!   (ours) against the sets per subscriber and protocol (what the scan did
//!   before, as a reference);
//! - handing it over (`cgnat_scan_feed`): the time the lock is held;
//! - `ip.firewall.cgnat.capacity.get` on the 64 Ki pool;
//! - the memory of the 7-day peaks (printed).
//!
//! `cargo xtask bench` runs it; alone:
//! `cargo bench -p corerouter-engine --bench cgnat_capacity`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::{HashMap, HashSet};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use corerouter_engine::Session;
use corerouter_engine::cgnat_blocks::UsageBuilder;
use corerouter_hal::conntrack::{Conn, Stats, Tuple, status};
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::json;

const T0: u64 = 1_780_000_000;
const SUBS: u32 = 65_536;
const PER: u32 = 20;

fn conns() -> Vec<Conn> {
    let mut out = Vec::with_capacity((SUBS * PER) as usize);
    for i in 0..SUBS {
        let sub = Ipv4Addr::from(0x6440_0000 + i);
        // 64 subscribers per public address, 1000 ports each.
        let public = Ipv4Addr::from(0xcb00_7000 + i / 64);
        let first = 1024 + (i % 64) as u16 * 1000;
        for k in 0..PER {
            let proto = if k % 4 == 3 { 17 } else { 6 };
            out.push(Conn {
                id: i * PER + k,
                protocol: proto,
                orig: Tuple {
                    src: IpAddr::V4(sub),
                    dst: IpAddr::V4(Ipv4Addr::new(142, 250, 79, (k % 200) as u8)),
                    src_port: 40_000 + k as u16,
                    dst_port: 443,
                },
                reply: Tuple {
                    src: IpAddr::V4(Ipv4Addr::new(142, 250, 79, (k % 200) as u8)),
                    dst: IpAddr::V4(public),
                    src_port: 443,
                    dst_port: first + k as u16,
                },
                status: status::CONFIRMED | status::SRC_NAT | status::SEEN_REPLY,
                timeout: 300,
                tcp_state: Some(3),
                mark: 0,
                orig_packets: 1,
                orig_bytes: 60,
                reply_packets: 1,
                reply_bytes: 60,
            });
        }
    }
    out
}

/// The scan before G2.7b: a set of ports per (subscriber, protocol).
fn sets(conns: &[Conn]) -> usize {
    let mut ports: HashMap<(Ipv4Addr, u8), HashSet<u16>> = HashMap::new();
    for c in conns.iter().filter(|c| c.has(status::SRC_NAT)) {
        let IpAddr::V4(sub) = c.orig.src else {
            continue;
        };
        ports
            .entry((sub, c.protocol))
            .or_default()
            .insert(c.reply.dst_port);
    }
    ports.len()
}

fn build(conns: &[Conn]) -> corerouter_engine::cgnat_blocks::Usage {
    let mut b = UsageBuilder::default();
    for c in conns {
        b.add(c);
    }
    b.finish(Stats::default())
}

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.tick(T0);
    s.execute(
        "ip.firewall.cgnat.pool.add",
        &json!({"name": "c1", "inside": "100.64.0.0/16", "outside": "203.0.112.0/22", "ports_per_subscriber": 1000}),
    )
    .unwrap();
    s
}

fn capacity(c: &mut Criterion) {
    let conns = conns();
    let mut g = c.benchmark_group("cgnat_capacity");
    g.sample_size(10);
    g.bench_function(
        "usage of 1.3M connections, sorted entries (outside the lock)",
        |b| b.iter(|| black_box(build(black_box(&conns))).len()),
    );
    g.bench_function(
        "usage of 1.3M connections, sets per subscriber (before)",
        |b| b.iter(|| sets(black_box(&conns))),
    );
    let mut s = lab();
    let mut now = T0 + 20;
    g.bench_function("hand the usage of 64Ki subscribers over (lock held)", |b| {
        b.iter_batched(
            || build(&conns),
            |u| {
                now += 1;
                s.cgnat_scan_feed(now, u);
            },
            criterion::BatchSize::LargeInput,
        )
    });
    g.bench_function("ip.firewall.cgnat.capacity.get, 64Ki subscribers", |b| {
        b.iter(|| {
            s.execute(
                "ip.firewall.cgnat.capacity.get",
                black_box(&json!({"pool": "c1"})),
            )
            .unwrap()
        })
    });
    g.finish();
    let u = build(&conns);
    let store = s.cgnat_capacity().unwrap();
    eprintln!(
        "usage: {} entries, {} KiB; peaks: {} subscribers, {} KiB",
        u.len(),
        u.len() * 12 / 1024,
        store.subscribers(),
        store.bytes() / 1024
    );
}

criterion_group!(benches, capacity);
criterion_main!(benches);
