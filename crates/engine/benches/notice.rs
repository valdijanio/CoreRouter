//! G4.10b: the subscriber notices' round with 100 000 subscribers in a
//! profile's list — `notice_tick` (the daemon runs it every 2 s under the
//! session lock), who a subscriber is under (`notice_profile_of`, what a
//! command asks), the members walk and the throttle profile's queues (the
//! queue service asks for them every second).
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-engine --bench notice`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use corerouter_engine::Session;
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::{Value, json};

const LISTED: u32 = 100_000;

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.tick(1_800_000_000);
    s.execute(
        "ip.subscriber-notice.profile.add",
        &json!({"name": "atraso", "mode": "block", "address_list": "bloqueados", "kill_connections": false}),
    )
    .unwrap();
    for k in 0..LISTED / 10_000 {
        let steps: Vec<Value> = (k * 10_000..(k + 1) * 10_000)
            .map(|i| {
                json!({"command": "ip.firewall.address-list.add", "params": {
                    "list": "bloqueados", "address": Ipv4Addr::from(0x6440_0000 + i).to_string(),
                }})
            })
            .collect();
        s.batch(&Value::Array(steps), true).unwrap();
    }
    s
}

fn bench(c: &mut Criterion) {
    let mut s = lab();
    let t = std::time::Instant::now();
    s.notice_tick();
    eprintln!(
        "notice: first tick with {LISTED} members (all new): {:?}",
        t.elapsed()
    );
    let mut g = c.benchmark_group("notice");
    g.sample_size(10).measurement_time(Duration::from_secs(5));
    g.bench_function("tick/100k members, steady", |b| b.iter(|| s.notice_tick()));
    g.bench_function("members/100k", |b| b.iter(|| s.notice_members().len()));
    let ip = IpAddr::V4(Ipv4Addr::from(0x6440_0000 + 77_777));
    g.bench_function("profile_of/member (100k listed)", |b| {
        b.iter(|| s.notice_profile_of(ip).is_some())
    });
    let out = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    g.bench_function("profile_of/non-member (100k listed)", |b| {
        b.iter(|| s.notice_profile_of(out).is_none())
    });
    s.execute(
        "ip.subscriber-notice.profile.set",
        &json!({"id": "atraso", "mode": "throttle", "rate_limit": "1M/1M"}),
    )
    .unwrap();
    g.bench_function("throttle_queues/100k members", |b| {
        b.iter(|| corerouter_engine::subscriber_notice::throttle_queues(&s).len())
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
