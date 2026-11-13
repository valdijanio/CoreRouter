//! G4.1zd — what the query log costs: a static answer (the cheapest the
//! chain gives, so the log is a large share of it) with the log off and on,
//! from one client, from 4096 CGNAT clients and from 4 and 16 threads at
//! once (the daemon's UDP readers and workers push into the same sink),
//! and the writer's work per query (raw entry → block → deflate).
//!
//! `cargo xtask bench dns_log`; alone:
//! `cargo bench -p corerouter-proto-dns --bench querylog`.

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
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use corerouter_model::Config;
use corerouter_model::dns_log::DnsLog;
use corerouter_model::dns_static::{StaticEntry, StaticType};
use corerouter_model::types::ItemId;
use corerouter_proto_dns::querylog::format::{BlockBuilder, Record};
use corerouter_proto_dns::querylog::{Anon, Sink, decode_batch};
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

fn forwarder(log: bool) -> Forwarder {
    let mut cfg = Config::default();
    cfg.ip.dns.allow_remote_requests = true;
    cfg.ip.dns.max_queries_per_client = 0;
    cfg.ip.dns_log.enabled = log;
    let mut e = StaticEntry::new(ItemId(1));
    e.name = "nas.lan".into();
    e.rtype = StaticType::A;
    e.address = Some(IpAddr::from([10, 0, 0, 1]));
    cfg.ip.dns_static.entries.push(e);
    let resolver = Arc::new(Resolver::new(Settings::new(&cfg.ip.dns, &[])));
    let f = Forwarder::new(resolver);
    f.configure(
        Arc::new(cfg),
        vec!["100.64.0.0/10".parse().unwrap(), "192.168.88.0/24".parse().unwrap()],
    );
    f
}

/// What the daemon does per query: the chain, then the entry to the sink.
fn one(f: &Forwarder, sink: &Sink, q: &[u8], client: IpAddr) -> usize {
    match f.start(black_box(q), client, false, 2000) {
        Start::Done(d) => {
            if let Some(e) = &d.log {
                sink.push(e, 120);
            }
            d.reply.map_or(0, |r| r.len())
        }
        Start::Pending(_) => panic!("static entries never wait"),
    }
}

fn cgnat(i: u32) -> IpAddr {
    IpAddr::from((0x6440_0000 + (i % 4096)).to_be_bytes())
}

/// A writer draining the sink as the daemon's does (decode, block, deflate).
fn writer(sink: Arc<Sink>, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<u64> {
    std::thread::spawn(move || {
        let anon = Anon::new(&DnsLog::default(), [3; 16]);
        let mut block = BlockBuilder::new(anon.mode());
        let mut bytes = 0u64;
        while !stop.load(Ordering::Relaxed) {
            for b in sink.drain() {
                for (e, lat) in decode_batch(&b.bytes) {
                    block.push(&Record {
                        at_ms: e.at_ms,
                        client: anon.client(e.client),
                        name: e.name,
                        qtype: e.qtype,
                        rcode: e.rcode,
                        flags: e.flags,
                        by: e.by,
                        ede: e.ede,
                        latency_us: lat,
                    });
                    if block.full() {
                        bytes += block.finish().map_or(0, |b| b.len() as u64);
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        bytes
    })
}

fn parallel(f: &Forwarder, sink: &Sink, q: &[u8], threads: u32, iters: u64) -> Duration {
    let per = iters.div_ceil(u64::from(threads));
    let start = Instant::now();
    std::thread::scope(|s| {
        for t in 0..threads {
            s.spawn(move || {
                for i in 0..per {
                    let i = u32::try_from(i % 4096).unwrap();
                    black_box(one(f, sink, q, cgnat(t * 512 + i)));
                }
            });
        }
    });
    start.elapsed()
}

fn bench(c: &mut Criterion) {
    let q = ask("nas.lan.");
    let lan = IpAddr::from([192, 168, 88, 10]);
    for log in [false, true] {
        let tag = if log { "on" } else { "off" };
        let f = forwarder(log);
        let sink = Arc::new(Sink::default());
        sink.set_on(log);
        let stop = Arc::new(AtomicBool::new(false));
        let w = writer(sink.clone(), stop.clone());
        c.bench_function(&format!("dns_log_{tag}_one_client"), |b| b.iter(|| one(&f, &sink, &q, lan)));
        let mut i = 0u32;
        c.bench_function(&format!("dns_log_{tag}_cgnat_4096"), |b| {
            b.iter(|| {
                i = i.wrapping_add(1);
                one(&f, &sink, &q, cgnat(i))
            })
        });
        for threads in [4u32, 16] {
            c.bench_function(&format!("dns_log_{tag}_{threads}_threads"), |b| {
                b.iter_custom(|iters| parallel(&f, &sink, &q, threads, iters))
            });
        }
        stop.store(true, Ordering::Relaxed);
        let _ = w.join();
    }

    // The writer's share: one query from raw entry to compressed block.
    let sink = Sink::default();
    sink.set_on(true);
    let names: Vec<String> = (0..20_000).map(|i| format!("host{}.example{}.com", i % 3000, i % 97)).collect();
    let mut k = 0usize;
    for i in 0..65_536u32 {
        k = (k + 7919) % names.len();
        let e = corerouter_proto_dns::querylog::Entry {
            at_ms: u64::from(i),
            client: cgnat(i.wrapping_mul(2_654_435_761)),
            name: names[k % (1 + (i as usize % names.len()))].clone(),
            qtype: 1,
            rcode: 0,
            flags: 0,
            by: 0,
            ede: None,
        };
        sink.push(&e, 100);
    }
    let raw: Vec<Vec<u8>> = sink.drain().into_iter().map(|b| b.bytes).collect();
    let anon = Anon::new(&DnsLog::default(), [3; 16]);
    c.bench_function("dns_log_writer_65536", |b| {
        b.iter(|| {
            let mut block = BlockBuilder::new(anon.mode());
            for buf in &raw {
                for (e, lat) in decode_batch(buf) {
                    block.push(&Record {
                        at_ms: e.at_ms,
                        client: anon.client(e.client),
                        name: e.name,
                        qtype: e.qtype,
                        rcode: e.rcode,
                        flags: e.flags,
                        by: e.by,
                        ede: e.ede,
                        latency_us: lat,
                    });
                }
            }
            black_box(block.finish())
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20).measurement_time(Duration::from_secs(3));
    targets = bench
}
criterion_main!(benches);
