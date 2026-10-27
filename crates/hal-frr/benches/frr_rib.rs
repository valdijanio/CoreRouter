//! G3.2c: reading one neighbor's full table from bgpd's JSON
//! (`received-routes json`, the FRR 10.7 format), streamed into the
//! compact table: 1 M routes, ~150 k distinct AS paths. The JSON is built
//! once in memory; what is measured is our side (bgpd's own time to print
//! it is measured in the VM lab, `scripts/frr-rpki-live.sh`).

use std::fmt::Write as _;
use std::hint::black_box;

use corerouter_hal_frr::rib::{Builder, parse_slice, parse_table};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

fn json(n: u32) -> String {
    let mut s = String::with_capacity(usize::try_from(n).unwrap_or(0) * 260);
    s.push_str("{\n\"bgpTableVersion\":4,\"bgpLocalRouterId\":\"198.51.100.1\",\"defaultLocPrf\":100,\"localAS\":65000,\"receivedRoutes\": {");
    for i in 0..n {
        let (a, b, c) = (1 + (i >> 16) % 223, (i >> 8) & 0xff, i & 0xff);
        let net = format!("{a}.{b}.{c}.0/24");
        if i > 0 {
            s.push(',');
        }
        let _ = write!(
            s,
            "\"{net}\":{{\"addrPrefix\":\"{a}.{b}.{c}.0\",\"prefixLen\":24,\"network\":\"{net}\",\"nextHop\":\"198.51.100.18\",\"metric\":0,\"locPrf\":100,\"weight\":0,\"path\":\"64500 {} {}\",\"origin\":\"IGP\",\"valid\":true,\"best\":true}}",
            3356 + i % 7,
            1 + (i % 150_000)
        );
    }
    s.push_str(
        "}\n,\"totalPrefixCounter\":1000000,\"filteredPrefixCounter\":0,\"totalPathsCount\":0}",
    );
    s
}

fn bench(c: &mut Criterion) {
    let text = json(1_000_000);
    let mut g = c.benchmark_group("frr_rib");
    g.sample_size(10);
    g.throughput(Throughput::Bytes(text.len() as u64));
    g.bench_function("parse_1m_received_routes", |b| {
        b.iter(|| {
            let mut builder = Builder::new(true, None);
            let p = parse_table(text.as_bytes(), &mut builder);
            black_box((p.map(|p| p.routes), builder.finish().attrs.len()))
        })
    });
    g.bench_function("parse_1m_from_slice", |b| {
        b.iter(|| {
            let mut builder = Builder::new(true, None);
            let p = parse_slice(text.as_bytes(), &mut builder);
            black_box((p.map(|p| p.routes), builder.finish().attrs.len()))
        })
    });
    g.finish();
    eprintln!("JSON of 1 M routes: {} MiB", text.len() >> 20);
}

criterion_group!(benches, bench);
criterion_main!(benches);
