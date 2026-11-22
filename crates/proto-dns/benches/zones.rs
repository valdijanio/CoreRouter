//! G4.1c — the chain with authoritative zones, bytes in to bytes out: a
//! name answered from a 1000-record zone (AA), an NXDOMAIN from it (SOA in
//! the authority section), and a cache hit for a name outside 100
//! configured zones (what every query to the internet pays for the zones
//! stage). Each iteration is one query.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-proto-dns --bench zones`.

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
use corerouter_model::dns_zone::{Zone, ZoneRecord};
use corerouter_model::types::ItemId;
use corerouter_proto_dns::resolver::{Resolver, Settings, Transport, TransportError};
use corerouter_proto_dns::server::{Forwarder, Start};
use criterion::{Criterion, criterion_group, criterion_main};
use hickory_proto::op::{Message, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};

/// Answers every A query at once with TTL 300 (warms the cache).
struct Up;

impl Transport for Up {
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
            300,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        let b = m.to_vec().unwrap();
        assert!(accept(&b));
        Ok(b)
    }
}

fn ask(name: &str) -> Vec<u8> {
    let mut m = Message::query();
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    m.to_vec().unwrap()
}

fn forwarder(zones: usize, records: usize) -> Forwarder {
    let mut cfg = Config::default();
    cfg.ip.dns.servers = vec![IpAddr::from([192, 0, 2, 53])];
    cfg.ip.dns.allow_remote_requests = true;
    cfg.ip.dns.max_queries_per_client = 0;
    let dz = &mut cfg.ip.dns_zones;
    for z in 0..zones {
        let name = format!("zone{z}.example");
        let id = dz.next_id();
        let mut zone = Zone::new(id, &name);
        zone.serial = 1;
        dz.zones.push(zone);
        for i in 0..records {
            let mut r = ZoneRecord::new(ItemId(0), &name, &format!("host{i}"));
            r.id = dz.next_record_id();
            r.address = Some(IpAddr::from([10, 0, 0, 1]));
            dz.records.push(r);
        }
    }
    let resolver = Arc::new(Resolver::new(Settings::new(&cfg.ip.dns, &[])));
    let f = Forwarder::new(resolver);
    f.configure(Arc::new(cfg), vec!["192.168.88.0/24".parse().unwrap()]);
    f
}

fn done(f: &Forwarder, q: &[u8], client: IpAddr) -> Vec<u8> {
    match f.start(black_box(q), client, false, 2000) {
        Start::Done(d) => d.reply.unwrap(),
        Start::Pending(_) => panic!("went upstream"),
    }
}

fn bench(c: &mut Criterion) {
    let client = IpAddr::from([192, 168, 88, 10]);
    let f = forwarder(1, 1000);
    let hit = ask("host500.zone0.example.");
    done(&f, &hit, client);
    c.bench_function("dns_zone_answer", |b| b.iter(|| done(&f, &hit, client)));
    let nx = ask("nope.zone0.example.");
    c.bench_function("dns_zone_nxdomain", |b| b.iter(|| done(&f, &nx, client)));

    let f = forwarder(100, 10);
    let out = ask("www.example.com.");
    match f.start(&out, client, false, 1000) {
        Start::Pending(p) => {
            f.finish(*p, &mut Up);
        }
        Start::Done(_) => panic!("first query must miss"),
    }
    c.bench_function("dns_forward_cache_hit_100_zones", |b| {
        b.iter(|| done(&f, &out, client))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
