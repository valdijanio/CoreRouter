//! G0.9 — MNDP decoder (we never encode MNDP): an announcement shaped like
//! RouterOS's, built by hand from the public TLV list.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-proto-mndp --bench codec`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::net::Ipv6Addr;

use corerouter_proto_mndp::decode;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

fn tlv(t: u16, v: &[u8]) -> Vec<u8> {
    let l = u16::try_from(v.len()).unwrap();
    [&t.to_be_bytes()[..], &l.to_be_bytes(), v].concat()
}

fn announcement() -> Vec<u8> {
    let v6: Ipv6Addr = "fe80::4e5e:cff:fe01:203".parse().unwrap();
    [
        vec![0, 0, 0x12, 0x34],
        tlv(1, &[0x4C, 0x5E, 0x0C, 1, 2, 3]),
        tlv(5, b"branch-7"),
        tlv(7, b"7.16.1 (stable)"),
        tlv(8, b"MikroTik"),
        tlv(10, &3600u32.to_le_bytes()),
        tlv(11, b"ABCD-1234"),
        tlv(12, b"RB4011iGS+"),
        tlv(14, &[1]),
        tlv(15, &v6.octets()),
        tlv(16, b"ether2"),
        tlv(17, &[192, 168, 88, 1]),
    ]
    .concat()
}

fn codec(c: &mut Criterion) {
    let bytes = announcement();
    decode(&bytes).unwrap();
    let mut g = c.benchmark_group("mndp");
    g.throughput(Throughput::Elements(1));
    g.bench_function("decode", |b| b.iter(|| decode(black_box(&bytes)).unwrap()));
    g.finish();
}

criterion_group!(benches, codec);
criterion_main!(benches);
