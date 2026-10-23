//! audit-services — the neighbor table's cost per received discovery
//! datagram (CRDP/LLDP/MNDP), paid under the session lock: "is it new?" and
//! record, with the table full (`MAX_NEIGHBORS`), so every new key evicts.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-engine --bench neighbors`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;

use corerouter_engine::neighbors::{MAX_NEIGHBORS, NeighborTable};
use corerouter_model::{NeighborEntry, NeighborProtocol};
use criterion::{Criterion, criterion_group, criterion_main};

/// Interfaces the full table is spread over (256 rows each).
const PORTS: usize = 16;

fn entry(port: usize, node: u64, seen: u64) -> NeighborEntry {
    NeighborEntry {
        interface: format!("ether{}", port + 1).parse().unwrap(),
        protocol: NeighborProtocol::Crdp,
        mac: None,
        addresses: Vec::new(),
        identity: format!("r{node}"),
        version: String::new(),
        platform: String::new(),
        board: String::new(),
        uptime_secs: None,
        node_id: Some(format!("{node:016x}")),
        remote_interface: None,
        mgmt: None,
        last_seen: seen,
        hold_secs: 120,
    }
}

fn full() -> NeighborTable {
    let mut t = NeighborTable::default();
    for i in 0..MAX_NEIGHBORS as u64 {
        t.record(entry(i as usize % PORTS, i, 1000));
    }
    t
}

/// What a receive loop does per datagram: learn whether the row is new
/// (for the "neighbor appeared" log line) and record it.
fn receive(t: &mut NeighborTable, e: NeighborEntry) -> bool {
    t.record(e)
}

fn neighbors(c: &mut Criterion) {
    let mut t = full();
    let mut n = MAX_NEIGHBORS as u64;
    c.bench_function("neighbors/record_new_key_full_table", |b| {
        b.iter(|| {
            n += 1;
            black_box(receive(
                &mut t,
                entry(n as usize % PORTS, n, 1000 + n / 1000),
            ))
        });
    });
    let mut t = full();
    let mut i = 0u64;
    c.bench_function("neighbors/refresh_known_key_full_table", |b| {
        b.iter(|| {
            i = (i + 1) % MAX_NEIGHBORS as u64;
            black_box(receive(&mut t, entry(i as usize % PORTS, i, 1001)))
        });
    });
}

criterion_group!(benches, neighbors);
criterion_main!(benches);
