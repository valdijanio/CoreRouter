//! G4.2a — the DHCP server in a storm: N clients at once (after a power
//! cut), each DISCOVER → OFFER → REQUEST → ACK, through the pure server
//! (`proto_dhcp::server`), journal lines serialized as the engine does.
//! Throughput is leases/s (N elements per iteration). `probed` also parks
//! every offer for its ARP probe and releases them with one clock tick.
//!
//! `ipoe` (G4.3f) authorizes each client first, at 10 000 and 100 000.
//!
//! `cargo xtask bench storm`; alone: `cargo bench -p corerouter-proto-dhcp --bench server_storm`.
//! The p50/p99 of each message: `cargo run --release -p corerouter-proto-dhcp --example storm`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../examples/storm/lab.rs"]
mod lab;

use std::hint::black_box;

use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};

fn storm(c: &mut Criterion) {
    let mut g = c.benchmark_group("dhcp_server_storm");
    g.sample_size(10);
    for n in [1_000usize, 10_000] {
        for probed in [false, true] {
            let lab = lab::Storm::new(n, probed);
            g.throughput(Throughput::Elements(n as u64));
            let id = format!("{}/{n}", if probed { "probed" } else { "dora" });
            g.bench_function(&id, |b| {
                b.iter_batched(
                    || lab.server(),
                    |mut srv| black_box(lab.run(&mut srv, |f| f())),
                    BatchSize::LargeInput,
                );
            });
        }
    }
    g.finish();
}

/// G4.3f: the same DORA when each client is authorized first (IPoE, the
/// verdict at once), and the plain one, at 10 000 and 100 000 clients: the
/// cost per lease must not grow with the leases already there.
fn ipoe(c: &mut Criterion) {
    let mut g = c.benchmark_group("dhcp_server_ipoe");
    g.sample_size(10);
    for n in [10_000usize, 100_000] {
        for ipoe in [false, true] {
            let lab = lab::Storm::with(n, false, ipoe);
            // Every client gets its lease (a storm of 100 000 is not a flood).
            let acks = lab.run(&mut lab.server(), |f| f());
            assert_eq!(acks, n, "{n} clients, ipoe={ipoe}: {acks} ACKs");
            g.throughput(Throughput::Elements(n as u64));
            let id = format!("{}/{n}", if ipoe { "authorized" } else { "dora" });
            g.bench_function(&id, |b| {
                b.iter_batched(
                    || lab.server(),
                    |mut srv| black_box(lab.run(&mut srv, |f| f())),
                    BatchSize::LargeInput,
                );
            });
        }
    }
    g.finish();
}

criterion_group!(benches, storm, ipoe);
criterion_main!(benches);
