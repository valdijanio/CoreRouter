//! G4.4b — the flow exporter's hot path: conntrack events through the
//! meter, and records into IPFIX / NetFlow v9 messages. A big CGNAT sees
//! tens of thousands of connections open and close per second; this is
//! the CPU each one costs.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-proto-flow --bench flow_codec`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

use corerouter_hal::conntrack::{Conn, Event, EventKind, Tuple, status};
use corerouter_proto_flow::export::{Config, DEFAULT_MESSAGE};
use corerouter_proto_flow::meter::AnyInterface;
use corerouter_proto_flow::{Exporter, Meter, MeterConfig, Record, Version};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

const N: u32 = 10_000;

fn conn(i: u32) -> Conn {
    let sub = IpAddr::V4(Ipv4Addr::from(0x6440_0000 + (i % 4096)));
    let server = IpAddr::V4(Ipv4Addr::new(192, 0, 2, (i % 200) as u8));
    let public = IpAddr::V4(Ipv4Addr::new(203, 0, 113, (i % 16) as u8));
    let port = 1024 + (i % 60_000) as u16;
    Conn {
        id: i,
        protocol: 6,
        orig: Tuple {
            src: sub,
            dst: server,
            src_port: port,
            dst_port: 443,
        },
        reply: Tuple {
            src: server,
            dst: public,
            src_port: 443,
            dst_port: port,
        },
        status: status::CONFIRMED | status::SRC_NAT,
        timeout: 120,
        tcp_state: Some(7),
        mark: 0,
        orig_packets: 20,
        orig_bytes: 3000,
        reply_packets: 30,
        reply_bytes: 40_000,
    }
}

fn records() -> Vec<Record> {
    let mut m = Meter::new(MeterConfig::default());
    let mut out = Vec::new();
    for i in 0..N {
        let c = conn(i);
        let ev = Event {
            kind: EventKind::Destroy,
            conn: c,
            start_ns: None,
            stop_ns: None,
        };
        m.event(&ev, 1_700_000_000_000, &AnyInterface, &mut out);
    }
    out
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("flow");
    g.throughput(Throughput::Elements(u64::from(N)));
    g.bench_function("meter_new_destroy_10k", |b| {
        let events: Vec<(Event, Event)> = (0..N)
            .map(|i| {
                let c = conn(i);
                (
                    Event {
                        kind: EventKind::New,
                        conn: c.clone(),
                        start_ns: None,
                        stop_ns: None,
                    },
                    Event {
                        kind: EventKind::Destroy,
                        conn: c,
                        start_ns: None,
                        stop_ns: None,
                    },
                )
            })
            .collect();
        b.iter(|| {
            let mut m = Meter::new(MeterConfig::default());
            let mut out = Vec::with_capacity(4 * N as usize);
            for (n, _) in &events {
                m.event(n, 1, &AnyInterface, &mut out);
            }
            for (_, d) in &events {
                m.event(d, 2, &AnyInterface, &mut out);
            }
            black_box(out.len())
        });
    });
    let recs = records();
    for v in [Version::Ipfix, Version::V9] {
        g.bench_function(format!("encode_{v:?}_10k_conns"), |b| {
            let mut e = Exporter::new(Config {
                version: v,
                domain: 1,
                max_size: DEFAULT_MESSAGE,
                refresh_ms: 600_000,
                refresh_packets: 20,
                stream: false,
                boot_ms: 0,
            });
            let mut out = Vec::new();
            b.iter(|| {
                out.clear();
                e.encode(1_700_000_000_000, &recs, &mut out);
                black_box(out.len())
            });
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
