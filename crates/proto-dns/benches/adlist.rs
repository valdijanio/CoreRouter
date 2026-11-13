//! G4.1d — adlist: parse a 1 000 000-name hosts file, build its set, and
//! look names up (blocked, under a blocked domain, not listed): the lookup
//! runs for every query of the LAN.
//!
//! G4.1z: the same name asked in a loop keeps the whole path of the lookup
//! in the CPU cache, which a router never sees. `lookup_10k` asks 10 000
//! different names in turn (the lab's hot set, `h<i>.up.lab`), and
//! `forward_hit_10k` runs them through the forwarder's whole chain as cache
//! hits, without a list and with the 1 M-name one: the loss the lab measured
//! (`docs/dns-stress.md`, "Adlist de 1 M de nomes"). `domains` is the same
//! million as Adblock rules (`||name^`, the format of the big curated
//! lists), where every label of the name asked is one more lookup.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-proto-dns --bench adlist`.

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
use corerouter_proto_dns::adlist::{Adlists, Loaded, parse};
use corerouter_proto_dns::resolver::{Resolver, Settings, Transport, TransportError};
use corerouter_proto_dns::server::{Forwarder, Start};
use criterion::{Criterion, criterion_group, criterion_main};
use hickory_proto::op::{Message, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};

const NAMES: usize = 1_000_000;
/// The lab's hot set (`--hot`, `scripts/dns-stress-lab.sh`).
const HOT: usize = 10_000;

fn hosts() -> String {
    (0..NAMES)
        .map(|i| format!("0.0.0.0 ads{i}.tracker{}.example\n", i % 997))
        .collect()
}

/// An upstream that answers every A query at once, cached for 300 s.
struct Ttl300;

impl Transport for Ttl300 {
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

/// A forwarder with the hot set in its cache (64 MiB, as the lab's).
fn warm_forwarder(client: IpAddr, hot: &[Vec<u8>]) -> Forwarder {
    let mut cfg = Config::default();
    cfg.ip.dns.servers = vec![IpAddr::from([192, 0, 2, 53])];
    cfg.ip.dns.allow_remote_requests = true;
    cfg.ip.dns.max_queries_per_client = 0;
    cfg.ip.dns.cache_size = 65_536;
    let resolver = Arc::new(Resolver::new(Settings::new(&cfg.ip.dns, &[])));
    let f = Forwarder::new(resolver);
    f.configure(Arc::new(cfg), vec!["192.168.88.0/24".parse().unwrap()]);
    for q in hot {
        match f.start(q, client, false, 1000) {
            Start::Pending(p) => {
                f.finish(*p, &mut Ttl300);
            }
            Start::Done(_) => panic!("first query must miss"),
        }
    }
    f
}

fn bench(c: &mut Criterion) {
    let text = hosts();
    let mut g = c.benchmark_group("dns_adlist");
    g.sample_size(10);
    g.bench_function("parse_and_build_1m", |b| {
        b.iter(|| Loaded::new(1, parse(black_box(&text), NAMES)))
    });
    g.finish();
    let mut parsed = parse(&text, NAMES);
    drop(text);
    let rules = Arc::new(Loaded::new(
        2,
        corerouter_proto_dns::adlist::Parsed {
            domains: parsed.names.clone(),
            ..Default::default()
        },
    ));
    parsed.domains.push("blocked-domain.example".into());
    let list = Arc::new(Loaded::new(1, parsed));
    eprintln!("adlist: {} names, {} bytes", list.len(), list.names.bytes());
    c.bench_function("dns_adlist_lookup_hit", |b| {
        b.iter(|| list.matches(black_box("ads123456.tracker333.example")))
    });
    c.bench_function("dns_adlist_lookup_subdomain", |b| {
        b.iter(|| list.matches(black_box("a.b.c.blocked-domain.example")))
    });
    c.bench_function("dns_adlist_lookup_miss", |b| {
        b.iter(|| list.matches(black_box("www.cdn.provider.example.net")))
    });

    // G4.1z: 10 000 names in turn, as a LAN asks them.
    let hot: Vec<String> = (0..HOT).map(|i| format!("h{i}.up.lab")).collect();
    let listed: Vec<String> = (0..HOT)
        .map(|i| {
            let j = (i * 97) % NAMES;
            format!("ads{j}.tracker{}.example", j % 997)
        })
        .collect();
    let mut g = c.benchmark_group("dns_adlist_lookup_10k");
    // Names between the listed ones: the search cannot reuse a path.
    let spread: Vec<String> = (0..HOT)
        .map(|i| {
            let j = (i * 97) % NAMES;
            format!("ads{j}x.tracker{}.example", j % 997)
        })
        .collect();
    for (what, set, names) in [
        ("miss", &list, &hot),
        ("hit", &list, &listed),
        ("spread", &list, &spread),
        ("domains_spread", &rules, &spread),
    ] {
        let mut i = 0usize;
        g.bench_function(what, |b| {
            b.iter(|| {
                i = (i + 1) % HOT;
                set.matches(black_box(&names[i]))
            })
        });
    }
    g.finish();

    let client = IpAddr::from([192, 168, 88, 10]);
    let queries: Vec<Vec<u8>> = hot.iter().map(|n| ask(&format!("{n}."))).collect();
    let f = warm_forwarder(client, &queries);
    let mut g = c.benchmark_group("dns_adlist_forward_hit_10k");
    for (what, lists) in [
        ("none", Vec::new()),
        ("1m", vec![list.clone()]),
        ("1m_domains", vec![rules.clone()]),
    ] {
        f.state::<Adlists>().set(lists);
        let mut i = 0usize;
        g.bench_function(what, |b| {
            b.iter(|| {
                i = (i + 1) % HOT;
                match f.start(black_box(&queries[i]), client, false, 2000) {
                    Start::Done(d) => d.reply.unwrap(),
                    Start::Pending(_) => panic!("miss"),
                }
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
