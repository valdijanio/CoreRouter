//! G0.9 — LLDP codec: encode and decode an LLDPDU shaped like a switch's
//! (all basic TLVs, two management addresses, one 802.1 TLV).
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-proto-lldp --bench codec`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;

use corerouter_proto_lldp::{
    Capabilities, ChassisId, Lldpdu, ManagementAddress, OrgTlv, PortId, decode, encode,
};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

fn pdu() -> Lldpdu {
    let mut du = Lldpdu::new(
        ChassisId::Mac([0x02, 0, 0, 0, 0, 0x01]),
        PortId::InterfaceName("ether1".into()),
        120,
    );
    du.port_description = Some("uplink to core-2".into());
    du.system_name = Some("core-1".into());
    du.system_description = Some("CoreRouter 0.1.0 x86_64".into());
    du.capabilities = Some(Capabilities {
        system: 0x0014,
        enabled: 0x0010,
    });
    du.management_addresses = vec![
        ManagementAddress::ip("10.0.0.1".parse().unwrap(), 1),
        ManagementAddress::ip("2001:db8::1".parse().unwrap(), 1),
    ];
    // IEEE 802.1 Port VLAN ID = 1.
    du.org_specific = vec![OrgTlv {
        oui: [0x00, 0x80, 0xC2],
        subtype: 1,
        info: vec![0, 1],
    }];
    du
}

fn codec(c: &mut Criterion) {
    let du = pdu();
    let bytes = encode(&du).unwrap();
    assert_eq!(decode(&bytes).unwrap(), du);
    let mut g = c.benchmark_group("lldp");
    g.throughput(Throughput::Elements(1));
    g.bench_function("encode", |b| b.iter(|| encode(black_box(&du)).unwrap()));
    g.bench_function("decode", |b| b.iter(|| decode(black_box(&bytes)).unwrap()));
    g.finish();
}

criterion_group!(benches, codec);
criterion_main!(benches);
