//! G0.9 — CRDP codec: encode and decode a full announcement (every TLV, two
//! addresses per family).
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-proto-discovery --bench codec`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::net::Ipv4Addr;

use corerouter_proto_discovery::{Announcement, NodeId, decode};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

fn announcement() -> Announcement {
    Announcement {
        node_id: NodeId([7; 16]),
        hold_secs: 120,
        identity: "core-1".into(),
        version: "0.1.0".into(),
        platform: "CoreRouter".into(),
        board: "x86_64".into(),
        uptime_secs: Some(3600),
        interface: "ether1".into(),
        mac: Some([2, 0, 0, 0, 0, 1]),
        ipv4: vec![
            (Ipv4Addr::new(10, 0, 0, 1), 24),
            (Ipv4Addr::new(192, 0, 2, 1), 24),
        ],
        ipv6: vec![
            ("fe80::1".parse().unwrap(), 64),
            ("2001:db8::1".parse().unwrap(), 64),
        ],
        control_port: Some(7979),
        ws_port: Some(7980),
        tls_port: Some(8729),
        wss_port: Some(8730),
    }
}

fn codec(c: &mut Criterion) {
    let a = announcement();
    let bytes = a.encode().unwrap();
    assert_eq!(decode(&bytes).unwrap(), a);
    let mut g = c.benchmark_group("crdp");
    g.throughput(Throughput::Elements(1));
    g.bench_function("encode", |b| b.iter(|| black_box(&a).encode().unwrap()));
    g.bench_function("decode", |b| b.iter(|| decode(black_box(&bytes)).unwrap()));
    g.finish();
}

criterion_group!(benches, codec);
criterion_main!(benches);
