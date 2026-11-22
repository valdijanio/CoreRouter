//! G4.1c-2 — DNSSEC: signing a whole 1000-record zone (ECDSA P-256 and
//! Ed25519, KSK + ZSK, NSEC3), and answers from the signed zone through
//! the chain with DO: a positive answer with its RRSIG, and an NXDOMAIN
//! with the NSEC3 proof (hashes computed per query).
//!
//! `cargo xtask bench` runs it; alone:
//! `cargo bench -p corerouter-proto-dns --features dnssec --bench dnssec`.

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

use corerouter_model::Config;
use corerouter_model::dns_zone::{Zone, ZoneRecord};
use corerouter_model::dnssec::{DnssecAlgorithm, DnssecKey, KeyRole, KeyState};
use corerouter_model::types::ItemId;
use corerouter_proto_dns::resolver::{Resolver, Settings};
use corerouter_proto_dns::server::{Forwarder, Start};
use corerouter_proto_dns::zone::{self, ZoneData, dnssec};
use criterion::{Criterion, criterion_group, criterion_main};
use hickory_proto::op::{Edns, Message, Query};
use hickory_proto::rr::{Name, RecordType};

const NOW: u32 = 1_792_670_400;

fn config(records: usize) -> Config {
    let mut cfg = Config::default();
    cfg.ip.dns.allow_remote_requests = true;
    cfg.ip.dns.max_queries_per_client = 0;
    cfg.ip.dns.max_udp_packet_size = 4096;
    let dz = &mut cfg.ip.dns_zones;
    let id = dz.next_id();
    let mut z = Zone::new(id, "example.com");
    z.serial = 1;
    z.dnssec = true;
    dz.zones.push(z);
    for i in 0..records {
        let mut r = ZoneRecord::new(ItemId(0), "example.com", &format!("host{i}"));
        r.id = dz.next_record_id();
        r.address = Some(IpAddr::from([10, 0, 0, 1]));
        dz.records.push(r);
    }
    cfg
}

fn keys(a: DnssecAlgorithm) -> Vec<DnssecKey> {
    [KeyRole::Ksk, KeyRole::Zsk]
        .into_iter()
        .enumerate()
        .map(|(i, role)| {
            let g = dnssec::generate("example.com", a, role).unwrap();
            DnssecKey {
                id: u32::try_from(i).unwrap() + 1,
                zone: "example.com".into(),
                role,
                algorithm: a,
                key_tag: g.key_tag,
                state: KeyState::Active,
                private_key: g.private_key,
                dnskey: g.dnskey,
                ds: g.ds,
                created_unix: 0,
                changed_unix: 0,
            }
        })
        .collect()
}

fn unsigned(cfg: &Config) -> ZoneData {
    let z = &cfg.ip.dns_zones.zones[0];
    let recs: Vec<&ZoneRecord> = cfg.ip.dns_zones.records.iter().collect();
    zone::primary(z, &recs).unwrap()
}

fn ask(name: &str) -> Vec<u8> {
    let mut m = Message::query();
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    let mut e = Edns::new();
    e.set_dnssec_ok(true);
    e.set_max_payload(4096);
    m.set_edns(e);
    m.to_vec().unwrap()
}

fn bench(c: &mut Criterion) {
    let cfg = config(1000);
    let z = unsigned(&cfg);
    let mut g = c.benchmark_group("dnssec_sign_1k");
    g.sample_size(10);
    for a in [DnssecAlgorithm::EcdsaP256, DnssecAlgorithm::Ed25519] {
        let k = keys(a);
        g.bench_function(a.as_str(), |b| {
            b.iter(|| dnssec::sign(black_box(&z), &k, 2, NOW, 1_209_600).unwrap())
        });
    }
    g.finish();

    let signed = dnssec::sign(&z, &keys(DnssecAlgorithm::EcdsaP256), 2, NOW, 1_209_600).unwrap();
    let resolver = Arc::new(Resolver::new(Settings::new(&cfg.ip.dns, &[])));
    let f = Forwarder::new(resolver);
    f.configure(Arc::new(cfg), vec!["192.168.88.0/24".parse().unwrap()]);
    zone::set_signed(&f, "example.com", signed);
    let client = IpAddr::from([192, 168, 88, 10]);
    let done = |q: &[u8]| match f.start(black_box(q), client, false, 2000) {
        Start::Done(d) => d.reply.unwrap(),
        Start::Pending(_) => panic!("went upstream"),
    };
    let hit = ask("host500.example.com.");
    c.bench_function("dns_zone_signed_answer_do", |b| b.iter(|| done(&hit)));
    let nx = ask("nope.example.com.");
    c.bench_function("dns_zone_signed_nxdomain_do", |b| b.iter(|| done(&nx)));
}

criterion_group!(benches, bench);
criterion_main!(benches);
