//! G4.1h — what the statistics stage costs a query: a static answer (the
//! cheapest the chain gives, so the counting is a large share of it) from
//! one client, from 4096 clients in turn (CGNAT: more than the 1024 the
//! client table holds, so every query is a newcomer), and from several
//! threads at once (the four UDP threads per family and the workers of the
//! daemon count into the same statistics).
//!
//! `cargo xtask bench dns_stats`; alone:
//! `cargo bench -p corerouter-proto-dns --bench statistics`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::hint::black_box;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use corerouter_model::Config;
use corerouter_model::dns_static::{StaticEntry, StaticType};
use corerouter_model::types::ItemId;
use corerouter_proto_dns::resolver::{Resolver, Settings};
use corerouter_proto_dns::server::{Forwarder, Start};
use criterion::{Criterion, criterion_group, criterion_main};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};

fn ask(name: &str) -> Vec<u8> {
    let mut m = Message::query();
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    m.to_vec().unwrap()
}

/// One static entry, the CGNAT range allowed, no per-client limit.
fn forwarder() -> Forwarder {
    let mut cfg = Config::default();
    cfg.ip.dns.allow_remote_requests = true;
    cfg.ip.dns.max_queries_per_client = 0;
    let mut e = StaticEntry::new(ItemId(1));
    e.name = "nas.lan".into();
    e.rtype = StaticType::A;
    e.address = Some(IpAddr::from([10, 0, 0, 1]));
    cfg.ip.dns_static.entries.push(e);
    let resolver = Arc::new(Resolver::new(Settings::new(&cfg.ip.dns, &[])));
    let f = Forwarder::new(resolver);
    f.configure(
        Arc::new(cfg),
        vec![
            "100.64.0.0/10".parse().unwrap(),
            "192.168.88.0/24".parse().unwrap(),
        ],
    );
    f
}

fn one(f: &Forwarder, q: &[u8], client: IpAddr) -> Vec<u8> {
    match f.start(black_box(q), client, false, 2000) {
        Start::Done(d) => d.reply.unwrap(),
        Start::Pending(_) => panic!("static entries never wait"),
    }
}

/// A CGNAT address (`100.64.x.y`), `i` of 4096.
fn cgnat(i: u32) -> IpAddr {
    IpAddr::from((0x6440_0000 + (i % 4096)).to_be_bytes())
}

/// `threads` threads answering `iters` queries between them; the time is
/// the wall clock, so per iteration it is the cost of one query with that
/// many threads counting at once (lower is better; flat means they scale).
fn parallel(f: &Forwarder, q: &[u8], threads: u32, iters: u64) -> Duration {
    let per = iters.div_ceil(u64::from(threads));
    let start = Instant::now();
    std::thread::scope(|s| {
        for t in 0..threads {
            s.spawn(move || {
                for i in 0..per {
                    let i = u32::try_from(i % 4096).unwrap();
                    black_box(one(f, q, cgnat(t * 512 + i)));
                }
            });
        }
    });
    start.elapsed()
}

fn bench(c: &mut Criterion) {
    let f = forwarder();
    let q = ask("nas.lan.");
    let lan = IpAddr::from([192, 168, 88, 10]);
    c.bench_function("dns_stats_static_one_client", |b| {
        b.iter(|| one(&f, &q, lan))
    });

    let mut i = 0u32;
    c.bench_function("dns_stats_static_cgnat_4096", |b| {
        b.iter(|| {
            i = i.wrapping_add(1);
            one(&f, &q, cgnat(i))
        })
    });

    for threads in [4u32, 16] {
        c.bench_function(&format!("dns_stats_static_{threads}_threads"), |b| {
            b.iter_custom(|iters| parallel(&f, &q, threads, iters))
        });
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
