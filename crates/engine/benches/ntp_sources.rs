//! G4.6c: what the NTP server's allow list costs when it names an address
//! list of 60 000 entries: the walk under the session lock, every 2 s, and the
//! sorting outside it. And the check per packet, which is what matters.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::hint::black_box;

use corerouter_engine::Session;
use corerouter_model::firewall::AddrMatch;
use corerouter_model::source_set::SourceSet;
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::json;

fn bench(c: &mut Criterion) {
    let mut s = Session::virtual_lab();
    let items: Vec<AddrMatch> = (0..60_000u32)
        .map(|i| {
            let ip = std::net::IpAddr::from((0x0A00_0000u32 + i * 3).to_be_bytes());
            ip.to_string().parse().unwrap()
        })
        .collect();
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    for i in 0..60_000u32 {
        let ip = std::net::Ipv4Addr::from(0x0A00_0000u32 + i * 3).to_string();
        s.execute(
            "ip.firewall.address-list.add",
            &json!({"list": "big", "address": ip}),
        )
        .unwrap();
    }
    s.execute("config.commit", &json!({})).unwrap();
    s.execute("config.mode.set", &json!({"mode": "immediate"}))
        .unwrap();
    s.execute("system.ntp.server.set", &json!({"allowed": ["big"]}))
        .unwrap();
    c.bench_function("ntp_sources/walk_60000_under_lock", |b| {
        b.iter(|| black_box(s.ntp_server_sources()));
    });
    c.bench_function("ntp_sources/sort_60000_outside_lock", |b| {
        b.iter(|| black_box(SourceSet::new(items.iter().copied())));
    });
    let set = SourceSet::new(items.iter().copied());
    let mut i = 0u32;
    c.bench_function("ntp_sources/contains_of_60000", |b| {
        b.iter(|| {
            i = i.wrapping_add(7);
            let ip = std::net::IpAddr::from((0x0A00_0000u32 + (i % 200_000)).to_be_bytes());
            black_box(set.contains(ip))
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
