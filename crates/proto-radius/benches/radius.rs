//! G4.3b — RADIUS: decode and encode of a BNG Access-Request (with
//! Message-Authenticator, PAP, NAS and RFC 4679 attributes), the Accept's
//! checks, the dictionary walk, Mikrotik-Rate-Limit, a CoA through the
//! Dynamic Authorization Server, and the client + test server exchange
//! (requests per second, no sockets).
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-proto-radius --bench radius`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::net::SocketAddr;

use corerouter_proto_radius::client::{Client, ClientConfig, Event, ServerConfig};
use corerouter_proto_radius::crypto;
use corerouter_proto_radius::dict::{Dictionary, vendor};
use corerouter_proto_radius::dynauth::{
    self, DynAuthClient, DynAuthConfig, DynAuthServer, Incoming, Outcome, RequestKind,
};
use corerouter_proto_radius::packet::{AttrList, Builder, Code, Packet, PushAttr, attr};
use corerouter_proto_radius::rate_limit::RateLimit;
use corerouter_proto_radius::testserver::TestServer;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

const SECRET: &[u8] = b"bench-secret";

fn request_attrs() -> AttrList {
    let mut l = AttrList::new();
    l.push_text(attr::USER_NAME, "cliente.0042@provedor")
        .unwrap();
    l.push_ipv4(attr::NAS_IP_ADDRESS, [10, 0, 0, 1].into())
        .unwrap();
    l.push_text(attr::NAS_IDENTIFIER, "bng-sp-01").unwrap();
    l.push_u32(attr::NAS_PORT, 15_000_042).unwrap();
    l.push_u32(attr::NAS_PORT_TYPE, 15).unwrap();
    l.push_u32(attr::SERVICE_TYPE, 2).unwrap();
    l.push_u32(attr::FRAMED_PROTOCOL, 1).unwrap();
    l.push_text(attr::CALLING_STATION_ID, "AA:BB:CC:00:00:42")
        .unwrap();
    l.push_text(attr::CALLED_STATION_ID, "provedor-pppoe")
        .unwrap();
    l.push_text(attr::NAS_PORT_ID, "vlan1042").unwrap();
    l.push_text(attr::ACCT_SESSION_ID, "81a00042").unwrap();
    l.push_vsa(vendor::DSL_FORUM, 1, b"OLT-01 xpon 0/1/3:42")
        .unwrap();
    l.push_vsa(vendor::DSL_FORUM, 2, b"ZTEG1234ABCD").unwrap();
    l
}

fn access_request(id: u8, ra: [u8; 16], attrs: &AttrList) -> Vec<u8> {
    let mut b = Builder::with_authenticator(Code::AccessRequest, id, ra);
    b.message_authenticator().unwrap();
    b.push(
        attr::USER_PASSWORD,
        &crypto::hide_user_password(b"senha-forte", SECRET, &ra).unwrap(),
    )
    .unwrap();
    b.extend(attrs).unwrap();
    crypto::sign_request(b, SECRET)
}

fn codec(c: &mut Criterion) {
    let attrs = request_attrs();
    let ra = [0x5a; 16];
    let req = access_request(7, ra, &attrs);
    let mut b = Builder::new(Code::AccessAccept, 7);
    b.message_authenticator().unwrap();
    b.push_vsa(
        vendor::MIKROTIK,
        8,
        b"100M/300M 150M/450M 80M/240M 16/16 8 50M/150M",
    )
    .unwrap();
    b.push_ipv4(attr::FRAMED_IP_ADDRESS, [100, 64, 1, 42].into())
        .unwrap();
    b.push_u32(attr::SESSION_TIMEOUT, 86_400).unwrap();
    b.push_u32(attr::ACCT_INTERIM_INTERVAL, 300).unwrap();
    b.push_vsa(vendor::MIKROTIK, 19, b"clientes-ativos")
        .unwrap();
    let accept = crypto::sign_response(b, &ra, SECRET);
    let dict = Dictionary::builtin();

    let mut g = c.benchmark_group("radius");
    g.throughput(Throughput::Elements(1));
    g.bench_function("decode_access_request", |b| {
        b.iter(|| {
            let p = Packet::parse(black_box(&req)).unwrap();
            black_box(p.attributes().map(|a| a.value.len()).sum::<usize>() + p.vsas().count())
        })
    });
    g.bench_function("decode_dictionary", |b| {
        b.iter(|| {
            let p = Packet::parse(black_box(&req)).unwrap();
            black_box(dict.decode_packet(&p).len())
        })
    });
    g.bench_function("encode_access_request", |b| {
        b.iter(|| black_box(access_request(7, ra, black_box(&attrs))))
    });
    g.bench_function("verify_accept", |b| {
        b.iter(|| {
            let p = Packet::parse(black_box(&accept)).unwrap();
            assert!(crypto::verify_response(&p, &ra, SECRET));
            assert_eq!(
                crypto::check_message_authenticator(&p, &ra, SECRET),
                crypto::MaCheck::Valid
            );
            black_box(p.vsa(vendor::MIKROTIK, 8))
        })
    });
    g.bench_function("rate_limit_parse", |b| {
        b.iter(|| {
            black_box(
                "100M/300M 150M/450M 80M/240M 16/16 8 50M/150M"
                    .parse::<RateLimit>()
                    .unwrap(),
            )
        })
    });

    let dac: SocketAddr = "10.9.9.9:4000".parse().unwrap();
    let mut coa = AttrList::new();
    coa.push_text(attr::ACCT_SESSION_ID, "81a00042").unwrap();
    coa.push_vsa(vendor::MIKROTIK, 8, b"20M/50M").unwrap();
    let mut srv = DynAuthServer::new(DynAuthConfig {
        clients: vec![DynAuthClient {
            addr: dac.ip(),
            secret: SECRET.to_vec(),
        }],
        ..DynAuthConfig::default()
    });
    let mut id = 0u8;
    let mut now = 0u64;
    g.bench_function("coa_handle_and_ack", |b| {
        b.iter(|| {
            id = id.wrapping_add(1);
            now += 1;
            let bytes = dynauth::build_request(RequestKind::Coa, id, &coa, SECRET, true);
            let Ok(Incoming::Request(r)) = srv.handle(dac, &bytes, 0, now * 400_000) else {
                panic!("CoA dropped");
            };
            black_box(srv.respond(&r, Outcome::Ack, &AttrList::new(), 0))
        })
    });
    g.finish();
}

/// Client and test server in one loop: submit, transmit, server answer,
/// response matched. Per request: MD5 for the authenticators, HMAC-MD5 for
/// two Message-Authenticators, the PAP hiding both ways.
fn exchange(c: &mut Criterion) {
    let addr: SocketAddr = "10.0.0.10:1812".parse().unwrap();
    const BATCH: u64 = 1000;
    let mut g = c.benchmark_group("radius_client");
    g.throughput(Throughput::Elements(BATCH));
    g.bench_function("access_round_trip_1000", |b| {
        let mut server = TestServer::new(SECRET, 1);
        server.add_user("cliente.0042@provedor", "senha-forte", AttrList::new());
        let mut client = Client::new(
            ClientConfig::default(),
            vec![ServerConfig::auth(addr, SECRET)],
            [3; 32],
        );
        let attrs = request_attrs();
        let from: SocketAddr = "10.0.0.1:40000".parse().unwrap();
        let mut buf = Vec::new();
        let mut now = 0;
        b.iter(|| {
            now += 1;
            for _ in 0..BATCH {
                client
                    .access(attrs.clone(), Some(b"senha-forte"), now)
                    .unwrap();
            }
            let mut done = 0;
            while let Some(t) = client.poll_transmit(&mut buf) {
                let r = server.handle(from, &buf, now).unwrap();
                client.handle_input(t.from, addr, &r.bytes, now).unwrap();
            }
            while let Some(e) = client.poll_event() {
                if matches!(
                    e,
                    Event::Response {
                        code: Code::AccessAccept,
                        ..
                    }
                ) {
                    done += 1;
                }
            }
            assert_eq!(done, BATCH);
        })
    });
    g.finish();
}

criterion_group!(benches, codec, exchange);
criterion_main!(benches);
