// SPDX-License-Identifier: GPL-2.0-or-later
//! G2.5a: cost of the XDP filter decision on the host (the same code the
//! kernel runs, minus the map lookups: here plain collections). A lower
//! bound for the per-packet work in XDP; the kernel numbers come from the
//! root test in CI (docs/xdp.md).
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;

use corerouter_dataplane_ebpf_common::bucket::Bucket;
use corerouter_dataplane_ebpf_common::filter::{Lookups, Settings, decide};
use corerouter_dataplane_ebpf_common::parse::{Addr, IPPROTO_UDP, parse};
use corerouter_dataplane_ebpf_common::testing::{Spec, build};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

#[derive(Default)]
struct Plain {
    buckets: BTreeMap<[u8; 16], Bucket>,
}

impl Lookups for Plain {
    fn blocked(&self, src: &Addr) -> Option<u32> {
        matches!(src, Addr::V4([203, 0, 113, _])).then_some(0)
    }
    fn allowed(&self, _: &Addr) -> bool {
        false
    }
    fn bucket(&mut self, src: &Addr) -> Option<&mut Bucket> {
        self.buckets.get_mut(&src.mapped())
    }
    fn new_bucket(&mut self, src: &Addr, b: Bucket) {
        self.buckets.insert(src.mapped(), b);
    }
}

/// Ethernet + IPv4 + UDP, 64 bytes on the wire with the FCS.
fn udp4(src: [u8; 4]) -> Vec<u8> {
    build(&Spec {
        vlans: vec![],
        src: Addr::V4(src),
        dst: Addr::V4([198, 51, 100, 1]),
        proto: IPPROTO_UDP,
        sport: 1234,
        dport: 53,
        flags: 0,
        payload: 18,
    })
}

fn bench(c: &mut Criterion) {
    let pass = udp4([192, 0, 2, 1]);
    let blocked = udp4([203, 0, 113, 9]);
    c.bench_function("xdp_parse_udp4", |b| b.iter(|| parse(black_box(&pass[..]))));
    let all = Settings {
        drop_malformed: true,
        drop_bad_tcp_flags: true,
        block: true,
        allow: false,
        rate_pps: 1_000_000,
        burst: 1_000,
    };
    let mut l = Plain::default();
    let mut now = 0u64;
    c.bench_function("xdp_decide_pass_rate_limited", |b| {
        b.iter(|| {
            now += 1_000;
            decide(black_box(&pass[..]), &all, &mut l, now)
        })
    });
    c.bench_function("xdp_decide_blocked", |b| {
        b.iter(|| decide(black_box(&blocked[..]), &all, &mut l, now))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
