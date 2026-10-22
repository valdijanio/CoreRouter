//! G4.1a — the router's resolver: encode a query, check and read a reply
//! (CNAME + two A records + SOA), and a cache hit among 10 000 entries.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-proto-dns --bench resolver`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::net::IpAddr;

use corerouter_model::dns::QType;
use corerouter_proto_dns::cache::Cache;
use corerouter_proto_dns::message::{Outcome, parse_name, parse_reply, query};
use criterion::{Criterion, criterion_group, criterion_main};
use hickory_proto::op::{Message, OpCode};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record};

fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn bench(c: &mut Criterion) {
    let qn = parse_name("www.example.com").unwrap();
    c.bench_function("dns_query_encode", |b| {
        b.iter(|| query(black_box(&qn.name), QType::A, 1232).unwrap())
    });

    let (id, q) = query(&qn.name, QType::A, 1232).unwrap();
    let qm = Message::from_vec(&q).unwrap();
    let mut m = Message::response(id, OpCode::Query);
    m.add_queries(qm.queries.clone());
    m.add_answer(Record::from_rdata(
        n("www.example.com."),
        300,
        RData::CNAME(CNAME(n("edge.cdn.example."))),
    ));
    for ip in [[192, 0, 2, 7], [192, 0, 2, 8]] {
        m.add_answer(Record::from_rdata(
            n("edge.cdn.example."),
            60,
            RData::A(A(ip.into())),
        ));
    }
    let reply = m.to_vec().unwrap();
    c.bench_function("dns_reply_parse", |b| {
        b.iter(|| parse_reply(id, &qn.name, QType::A, black_box(&reply)).unwrap())
    });

    let mut cache = Cache::new(64 << 20);
    for i in 0..10_000u32 {
        let o = Outcome::Addresses {
            addresses: vec![IpAddr::from(i.to_be_bytes())],
            canonical: None,
            ttl: 3600,
        };
        cache.put(&format!("host{i}.example"), QType::A, &o, None, 0, 604_800);
    }
    c.bench_function("dns_cache_hit_10k", |b| {
        b.iter(|| {
            cache
                .get(black_box("host5000.example"), QType::A, 1000)
                .unwrap()
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
