//! G3.4b: reading an OSPF LSDB of 10 000 LSAs as ospfd prints it
//! (`show ip ospf database … json`): streamed into the compact table
//! against parsed whole into a `serde_json::Value`, time and peak memory
//! (a counting allocator).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::hint::black_box;

use corerouter_hal_frr::ospf::read_lsdb_slice;
use corerouter_model::ospf_state::{Link, Lsa, Lsdb};
use criterion::{Criterion, criterion_group, criterion_main};

/// Resident memory of this process, KiB (Linux; 0 elsewhere).
fn rss_kib() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|n| n.parse().ok()))
        })
        .unwrap_or(0)
}

/// `routers` router LSAs with 4 links each, `routers / 4` network LSAs
/// and the rest externals, `total` LSAs in all, one JSON per LSA type.
fn database(total: usize, routers: usize) -> Vec<String> {
    let ip = |i: usize| format!("10.{}.{}.{}", (i >> 16) & 255, (i >> 8) & 255, i & 255);
    let mut r = String::from(r#"{"routerId":"10.0.0.1","routerLinkStates":{"areas":{"0.0.0.0":["#);
    for i in 0..routers {
        if i > 0 {
            r.push(',');
        }
        let _ = write!(
            r,
            r#"{{"lsaAge":100,"options":"*|-|-|-|-|-|E|-","lsaFlags":6,"flags":0,"lsaType":"router-LSA","linkStateId":"{0}","advertisingRouter":"{0}","lsaSeqNumber":"80000003","checksum":"1a2b","length":72,"numOfLinks":4,"routerLinks":{{"#,
            ip(i)
        );
        for k in 0..4 {
            if k > 0 {
                r.push(',');
            }
            let _ = write!(
                r,
                r#""link{k}":{{"linkType":"another Router (point-to-point)","neighborRouterId":"{}","routerInterfaceAddress":"{}","numOfTosMetrics":0,"tos0Metric":10}}"#,
                ip((i + k + 1) % routers),
                ip(i * 4 + k)
            );
        }
        r.push_str("}}");
    }
    r.push_str("]}}}");
    let nets = routers / 4;
    let mut n = String::from(r#"{"networkLinkStates":{"areas":{"0.0.0.0":["#);
    for i in 0..nets {
        if i > 0 {
            n.push(',');
        }
        let _ = write!(
            n,
            r#"{{"lsaAge":5,"linkStateId":"{}","advertisingRouter":"{}","lsaSeqNumber":"80000002","networkMask":24,"attchedRouters":{{"{}":{{"attachedRouterId":"x"}},"{}":{{"attachedRouterId":"x"}}}}}}"#,
            ip(i + 100_000),
            ip(i),
            ip(i),
            ip(i + 1)
        );
    }
    n.push_str("]}}}");
    let mut e = String::from(r#"{"asExternalLinkStates":["#);
    for i in 0..total.saturating_sub(routers + nets) {
        if i > 0 {
            e.push(',');
        }
        let _ = write!(
            e,
            r#"{{"lsaAge":1,"options":"*|-|-|-|-|-|E|-","lsaType":"AS-external-LSA","linkStateId":"{}","advertisingRouter":"{}","lsaSeqNumber":"80000001","checksum":"abcd","length":36,"networkMask":24,"metricType":"E2 (Larger than any link state path)","metric":20,"forwardAddress":"0.0.0.0","externalRouteTag":0}}"#,
            ip(i + 200_000),
            ip(i % routers.max(1))
        );
    }
    e.push_str("]}");
    vec![r, n, e]
}

fn bench(c: &mut Criterion) {
    let parts = database(10_000, 2_000);
    let bytes: usize = parts.iter().map(String::len).sum();
    // Memory kept by each result (RSS growth while it is held).
    let before = rss_kib();
    let mut db = Lsdb::default();
    for p in &parts {
        read_lsdb_slice(p.as_bytes(), &mut db).unwrap();
    }
    assert_eq!(db.lsas.len(), 10_000);
    let streamed = rss_kib().saturating_sub(before);
    let compact = db.lsas.capacity() * std::mem::size_of::<Lsa>()
        + db.links.capacity() * std::mem::size_of::<Link>()
        + db.attached.capacity() * 4;
    let before = rss_kib();
    let trees: Vec<serde_json::Value> = parts
        .iter()
        .map(|p| serde_json::from_str(p).unwrap())
        .collect();
    let tree = rss_kib().saturating_sub(before);
    eprintln!(
        "ospf lsdb 10000 LSAs: {} KiB of JSON; compact table {} KiB (RSS +{streamed} KiB); as a Value tree RSS +{tree} KiB",
        bytes >> 10,
        compact >> 10
    );
    black_box((db, trees));
    c.bench_function("ospf lsdb 10000 LSAs streamed", |b| {
        b.iter(|| {
            let mut db = Lsdb::default();
            for p in &parts {
                read_lsdb_slice(black_box(p.as_bytes()), &mut db).unwrap();
            }
            db.lsas.len()
        })
    });
    c.bench_function("ospf lsdb 10000 LSAs as Value", |b| {
        b.iter(|| {
            parts
                .iter()
                .map(|p| {
                    serde_json::from_str::<serde_json::Value>(black_box(p))
                        .map(|_| 1)
                        .unwrap_or(0)
                })
                .sum::<usize>()
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
