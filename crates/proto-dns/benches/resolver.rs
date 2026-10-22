//! G4.1a — the router's resolver: encode a query, check and read a reply
//! (CNAME + two A records + SOA), and a cache hit among 10 000 entries.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-proto-dns --bench resolver`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::net::Ipv4Addr;

use corerouter_proto_dns::cache::Cache;
use corerouter_proto_dns::message::{Answer, Rcode, parse_name, parse_reply, query};
use criterion::{Criterion, criterion_group, criterion_main};
use hickory_proto::op::{Message, OpCode};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};

fn n(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn bench(c: &mut Criterion) {
    let qn = parse_name("www.example.com").unwrap();
    c.bench_function("dns_query_encode", |b| {
        b.iter(|| query(black_box(&qn.name), RecordType::A, 1232).unwrap())
    });

    let (id, q) = query(&qn.name, RecordType::A, 1232).unwrap();
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
        b.iter(|| parse_reply(id, &qn.name, RecordType::A, black_box(&reply)).unwrap())
    });

    let mut cache = Cache::new(64 << 20);
    for i in 0..10_000u32 {
        let name = format!("host{i}.example");
        let o = Answer::local(
            Rcode::NoError,
            vec![Record::from_rdata(
                n(&format!("{name}.")),
                3600,
                RData::A(A(Ipv4Addr::from(i))),
            )],
        );
        cache.put(&name, RecordType::A, &o, None, 0, 604_800, 60);
    }
    c.bench_function("dns_cache_hit_10k", |b| {
        b.iter(|| {
            cache
                .get(black_box("host5000.example"), RecordType::A, 1000)
                .unwrap()
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
