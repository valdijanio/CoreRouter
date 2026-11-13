//! G4.1a — the router's resolver: encode a query, check and read a reply
//! (CNAME + two A records + SOA), a cache hit among 10 000 entries, and a
//! full 64 MiB cache: a hit and a unique name's miss + store (G4.1x).
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-proto-dns --bench resolver`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

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

    // Insert into a full cache (16 MiB, ~60 000 entries): every put evicts.
    let mut full = Cache::new(16 << 20);
    let rec = |i: u32| {
        Answer::local(
            Rcode::NoError,
            vec![Record::from_rdata(
                n(&format!("h{i}.example.")),
                3600,
                RData::A(A(Ipv4Addr::from(i))),
            )],
        )
    };
    let mut i = 0u32;
    while full.used_bytes() + 1024 < 16 << 20 {
        i += 1;
        full.put(
            &format!("h{i}.example"),
            RecordType::A,
            &rec(i),
            None,
            u64::from(i),
            604_800,
            60,
        );
    }
    let filled = full.len();
    c.bench_function("dns_cache_put_full", |b| {
        b.iter(|| {
            i += 1;
            full.put(
                &format!("h{i}.example"),
                RecordType::A,
                &rec(i),
                None,
                u64::from(i),
                604_800,
                60,
            );
        })
    });
    assert!(full.len() >= filled / 2);

    // G4.1x: the lab's 64 MiB cache, full (~95 000 answers), its first
    // 10 000 names asked again (the hot ones). A hit on them, and the
    // path of a unique name (the miss's lookup, then its answer stored:
    // something is evicted, or it is refused).
    let mut big = Cache::new(64 << 20);
    let mut j = 0u32;
    while big.used_bytes() + 1024 < 64 << 20 {
        j += 1;
        let name = format!("h{j}.example");
        big.get(&name, RecordType::A, 0);
        big.put(&name, RecordType::A, &rec(j), None, 0, 604_800, 60);
    }
    let hot: Vec<String> = (1..=10_000).map(|i| format!("h{i}.example")).collect();
    for name in &hot {
        big.get(name, RecordType::A, 1);
    }
    let mut k = 0usize;
    c.bench_function("dns_cache_hit_64mib", |b| {
        b.iter(|| {
            k = (k + 1) % hot.len();
            big.get(black_box(&hot[k]), RecordType::A, 1000)
        })
    });
    // Random names, like an attack's (sequential ones would favour an
    // ordered map by locality).
    let names: Vec<String> = (0..1_000_000u64)
        .map(|i| format!("{:016x}.wt.example", i.wrapping_mul(0x9e37_79b9_7f4a_7c15)))
        .collect();
    let answer = rec(7);
    let mut u = 0usize;
    c.bench_function("dns_cache_flood_64mib", |b| {
        b.iter(|| {
            u = (u + 1) % names.len();
            let name = &names[u];
            if big.get(black_box(name), RecordType::A, 2000).is_none() {
                big.put(name, RecordType::A, &answer, None, 2000, 604_800, 60);
            }
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
