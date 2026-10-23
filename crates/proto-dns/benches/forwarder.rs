//! G4.1b — the LAN forwarder's chain, bytes in to bytes out: a query
//! answered from the cache (warm), by a static entry, and a miss that goes
//! to an upstream answering at once (cold: the chain's own cost, without
//! the network's). Each iteration is one query; queries per second on one
//! core = 1 / time.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-proto-dns --bench forwarder`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::hint::black_box;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use corerouter_model::Config;
use corerouter_model::dns_static::{StaticEntry, StaticType};
use corerouter_model::types::ItemId;
use corerouter_proto_dns::resolver::{Resolver, Settings, Transport, TransportError};
use corerouter_proto_dns::server::{Forwarder, Start};
use criterion::{Criterion, criterion_group, criterion_main};
use hickory_proto::op::{Message, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};

/// An upstream that answers every A query at once, TTL 0 (never cached,
/// so every iteration is a miss).
struct Instant0;

impl Transport for Instant0 {
    fn now_ms(&self) -> u64 {
        1000
    }

    fn exchange(
        &mut self,
        _: SocketAddr,
        query: &[u8],
        _: bool,
        _: u64,
        accept: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<Vec<u8>, TransportError> {
        let q = Message::from_vec(query).unwrap();
        let mut m = Message::response(q.metadata.id, OpCode::Query);
        m.add_queries(q.queries.clone());
        m.add_answer(Record::from_rdata(
            q.queries[0].name().clone(),
            0,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        let b = m.to_vec().unwrap();
        assert!(accept(&b));
        Ok(b)
    }
}

/// The same upstream, with a long TTL (the answer is cached).
struct Ttl300;

impl Transport for Ttl300 {
    fn now_ms(&self) -> u64 {
        1000
    }
    fn exchange(
        &mut self,
        s: SocketAddr,
        q: &[u8],
        tcp: bool,
        w: u64,
        accept: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<Vec<u8>, TransportError> {
        let mut m = Message::from_vec(&Instant0.exchange(s, q, tcp, w, accept)?).unwrap();
        m.answers[0].ttl = 300;
        Ok(m.to_vec().unwrap())
    }
}

fn ask(name: &str) -> Vec<u8> {
    let mut m = Message::query();
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    m.to_vec().unwrap()
}

fn forwarder(statics: usize) -> Forwarder {
    let mut cfg = Config::default();
    cfg.ip.dns.servers = vec![IpAddr::from([192, 0, 2, 53])];
    cfg.ip.dns.allow_remote_requests = true;
    cfg.ip.dns.max_queries_per_client = 0;
    for i in 0..statics {
        let mut e = StaticEntry::new(ItemId(u32::try_from(i).unwrap() + 1));
        e.name = format!("host{i}.lan");
        e.rtype = StaticType::A;
        e.address = Some(IpAddr::from([10, 0, 0, 1]));
        cfg.ip.dns_static.entries.push(e);
    }
    let resolver = Arc::new(Resolver::new(Settings::new(&cfg.ip.dns, &[])));
    let f = Forwarder::new(resolver);
    f.configure(Arc::new(cfg), vec!["192.168.88.0/24".parse().unwrap()]);
    f
}

fn bench(c: &mut Criterion) {
    let client = IpAddr::from([192, 168, 88, 10]);
    let f = forwarder(0);
    let warm = ask("www.example.com.");
    match f.start(&warm, client, false, 1000) {
        Start::Pending(p) => {
            f.finish(*p, &mut Ttl300);
        }
        Start::Done(_) => panic!("first query must miss"),
    }
    c.bench_function("dns_forward_cache_hit", |b| {
        b.iter(|| match f.start(black_box(&warm), client, false, 2000) {
            Start::Done(d) => d.reply.unwrap(),
            Start::Pending(_) => panic!("miss"),
        })
    });

    let fs = forwarder(1000);
    let st = ask("host999.lan.");
    c.bench_function("dns_forward_static_1k", |b| {
        b.iter(|| match fs.start(black_box(&st), client, false, 2000) {
            Start::Done(d) => d.reply.unwrap(),
            Start::Pending(_) => panic!("miss"),
        })
    });

    let cold = ask("miss.example.com.");
    c.bench_function("dns_forward_cache_miss", |b| {
        b.iter(|| match f.start(black_box(&cold), client, false, 2000) {
            Start::Pending(p) => f.finish(*p, &mut Instant0).reply.unwrap(),
            Start::Done(_) => panic!("hit"),
        })
    });

    // A full cache (8 MiB, ~30 000 entries, filled with 40 000 names):
    // a hit, and a miss whose answer must evict another entry.
    let mut full_cfg = Config::default();
    full_cfg.ip.dns.servers = vec![IpAddr::from([192, 0, 2, 53])];
    full_cfg.ip.dns.allow_remote_requests = true;
    full_cfg.ip.dns.max_queries_per_client = 0;
    full_cfg.ip.dns.cache_size = 8192;
    let resolver = Arc::new(Resolver::new(Settings::new(&full_cfg.ip.dns, &[])));
    let ff = Forwarder::new(resolver);
    ff.configure(Arc::new(full_cfg), vec!["192.168.88.0/24".parse().unwrap()]);
    let mut n = 0u64;
    let miss = |f: &Forwarder, n: &mut u64| {
        *n += 1;
        match f.start(&ask(&format!("h{n}.example.com.")), client, false, 2000) {
            Start::Pending(p) => f.finish(*p, &mut Ttl300).reply.unwrap(),
            Start::Done(_) => panic!("hit"),
        }
    };
    for _ in 0..40_000 {
        miss(&ff, &mut n);
    }
    let last = ask(&format!("h{n}.example.com."));
    c.bench_function("dns_forward_cache_hit_full", |b| {
        b.iter(|| match ff.start(black_box(&last), client, false, 2000) {
            Start::Done(d) => d.reply.unwrap(),
            Start::Pending(_) => panic!("miss"),
        })
    });
    c.bench_function("dns_forward_cache_miss_full", |b| {
        b.iter(|| miss(&ff, &mut n))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
