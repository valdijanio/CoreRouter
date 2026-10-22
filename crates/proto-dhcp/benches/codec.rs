//! G0.9 — DHCPv4 codec: encode a client DISCOVER, decode the server's ACK
//! (with options 1, 3, 6, 15, 42, 51, 54 and 121), and the raw option walk
//! behind `ip.dhcp-client.options`.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-proto-dhcp --bench codec`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::net::Ipv4Addr;

use corerouter_hal::DhcpResponder;
use corerouter_hal::dhcp::Dest;
use corerouter_model::IfName;
use corerouter_proto_dhcp::lab::{Knobs, LabServer};
use corerouter_proto_dhcp::v4::{self, Outgoing};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use dhcproto::v4::MessageType;

const MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];

fn message(kind: MessageType, requested: Option<Ipv4Addr>) -> Vec<u8> {
    Outgoing {
        kind,
        xid: 0x1234_5678,
        secs: 0,
        mac: MAC,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        broadcast: true,
        requested,
        server_id: None,
        client_id: &[1, 2, 0, 0, 0, 0, 1],
        host_name: Some("core-1"),
        vendor_class: None,
        extra: &[],
    }
    .encode()
    .unwrap()
}

fn codec(c: &mut Criterion) {
    let port: IfName = "ether1".parse().unwrap();
    let server = LabServer::new(Knobs {
        classless: true,
        ..Knobs::default()
    });
    let mine = LabServer::address_for(&port, MAC);
    let request = message(MessageType::Request, Some(mine));
    let ack = server
        .answer(&port, MAC, &request, Dest::Broadcast)
        .into_iter()
        .next()
        .unwrap()
        .payload;
    assert_eq!(v4::decode(&ack).unwrap().kind, MessageType::Ack);

    let mut g = c.benchmark_group("dhcpv4");
    g.throughput(Throughput::Elements(1));
    g.bench_function("encode_discover", |b| {
        b.iter(|| message(black_box(MessageType::Discover), None));
    });
    g.bench_function("decode_ack", |b| {
        b.iter(|| v4::decode(black_box(&ack)).unwrap());
    });
    g.bench_function("raw_options_ack", |b| {
        b.iter(|| v4::raw_options(black_box(&ack)));
    });
    // Garbage is the common case on a hostile link: how fast is "no"?
    let junk = vec![0xA5u8; 548];
    g.bench_function("decode_junk", |b| {
        b.iter(|| v4::decode(black_box(&junk)).unwrap_err());
    });
    g.finish();
}

criterion_group!(benches, codec);
criterion_main!(benches);
