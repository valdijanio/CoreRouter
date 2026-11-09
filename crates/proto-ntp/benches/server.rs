//! G4.6c: what one request costs the NTP server, without the socket.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::hash_map::RandomState;
use std::hint::black_box;
use std::net::IpAddr;

use corerouter_proto_ntp::server::{self, RATE_SLOTS, RateLimiter, SystemVars};
use corerouter_proto_ntp::{Packet, Timestamp};
use criterion::{Criterion, criterion_group, criterion_main};

fn bench(c: &mut Criterion) {
    const T: i128 = 1_794_000_000_000_000_000;
    let sys = SystemVars {
        leap: 0,
        stratum: 3,
        precision: -20,
        root_delay_nanos: 1_000_000,
        root_dispersion_nanos: 1_000_000,
        reference_id: [192, 0, 2, 1],
        reference_nanos: T,
        ages: true,
    };
    let request = Packet::client_request(Timestamp::from_unix_nanos(T)).encode();
    c.bench_function("ntp_server/parse_and_reply", |b| {
        b.iter(|| {
            let p = server::parse_request(black_box(&request)).unwrap();
            black_box(server::reply(&p, &sys, T, T + 1000).encode())
        });
    });
    c.bench_function("ntp_server/rate_limit_hit", |b| {
        let mut l = RateLimiter::new(RATE_SLOTS, RandomState::new());
        let ip = IpAddr::from([192, 168, 88, 2]);
        let mut now = 0u64;
        b.iter(|| {
            now += 3_000;
            black_box(l.check(black_box(ip), now))
        });
    });
    c.bench_function("ntp_server/rate_limit_many_sources", |b| {
        let mut l = RateLimiter::new(RATE_SLOTS, RandomState::new());
        let mut i = 0u32;
        b.iter(|| {
            i = i.wrapping_add(1);
            black_box(l.check(IpAddr::from(i.to_be_bytes()), 1))
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
