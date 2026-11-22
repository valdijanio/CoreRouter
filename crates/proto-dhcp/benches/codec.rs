//! G0.9 — DHCPv4 codec: encode a client DISCOVER, decode the server's ACK
//! (with options 1, 3, 6, 15, 42, 51, 54 and 121), and the raw option walk
//! behind `ip.dhcp-client.options`.
//!
//! G4.3e: the DHCPv6 server of one PPP session (`sub6`) answering a
//! Solicit with Rapid Commit (IA_NA + IA_PD + DNS).
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

fn sub6(c: &mut Criterion) {
    use corerouter_proto_dhcp::sub6::{Grant6, Sub6, duid_ll};
    use corerouter_proto_dhcp::v6::{self, IaReq, msg, opt};
    let mut g = c.benchmark_group("dhcp6_session");
    g.throughput(Throughput::Elements(1));
    let solicit = v6::Outgoing {
        kind: msg::SOLICIT,
        xid: 7,
        client_id: &[0, 3, 0, 1, 2, 0, 0, 0, 0, 9],
        server_id: None,
        elapsed_cs: 0,
        rapid_commit: true,
        ia_na: Some(IaReq {
            iaid: 1,
            ..IaReq::default()
        }),
        ia_pd: Some(IaReq {
            iaid: 2,
            ..IaReq::default()
        }),
        oro: &[opt::DNS_SERVERS],
    }
    .encode();
    let mut s = Sub6::new(Grant6 {
        server_duid: duid_ll(MAC),
        address: Some("2001:db8:0:5::1234".parse().unwrap()),
        link: Some("2001:db8:0:5::/64".parse().unwrap()),
        prefix: Some("2001:db8:100:500::/56".parse().unwrap()),
        dns: vec!["2001:db8::53".parse().unwrap()],
        domains: Vec::new(),
        lease_time: 86_400,
        rapid_commit: true,
    });
    g.bench_function("solicit_rapid_commit", |b| {
        b.iter(|| s.handle(black_box(&solicit)).reply.map(|r| r.len()))
    });
    g.finish();
}

criterion_group!(benches, codec, sub6);
criterion_main!(benches);
