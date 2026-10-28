//! G3.4f: the SR database of 10 000 prefix SIDs as ospfd prints it (`show
//! ip ospf database segment-routing json`): read into the model, and the
//! SID clashes checked over it (what the Segment Routing tab and the
//! prefix SID preview do on every read).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fmt::Write as _;
use std::hint::black_box;

use corerouter_hal_frr::sr::sr_db;
use corerouter_model::ospf_sr::{PrefixSid, SidBehavior};
use corerouter_model::types::ItemId;
use criterion::{Criterion, criterion_group, criterion_main};

/// `routers` SR nodes with `per` prefix SIDs each, one way out each.
fn database(routers: usize, per: usize) -> String {
    let ip = |i: usize| format!("10.{}.{}.{}", (i >> 16) & 255, (i >> 8) & 255, i & 255);
    let mut s = String::from(r#"{"srdbID":"10.0.0.1","srNodes":["#);
    for r in 0..routers {
        if r > 0 {
            s.push(',');
        }
        let _ = write!(
            s,
            r#"{{"routerID":"{}","srgbSize":8000,"srgbLabel":16000,"srlbSize":1000,"srlbLabel":15000,"algorithms":[{{"0":"SPF"}}],"nodeMsd":8,"extendedPrefix":["#,
            ip(r + 1)
        );
        for p in 0..per {
            let i = r * per + p;
            if p > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                r#"{{"prefix":"{}/32","sid":{},"inputLabel":{},"prefixRoute":[{{"outputLabel":{},"interface":"ether1","nexthop":"10.254.0.2"}}]}}"#,
                ip(0x0040_0000 + i),
                i % 7999 + 1,
                16_000 + i % 7999 + 1,
                16_000 + i % 7999 + 1
            );
        }
        s.push_str(r#"],"extendedLink":[{"prefix":"10.254.0.2/32","sid":15000}]}"#);
    }
    s.push_str("]}");
    s
}

fn bench(c: &mut Criterion) {
    let json = database(1_000, 10);
    eprintln!(
        "SR database: 1 000 routers, 10 000 prefix SIDs, {} KiB of JSON",
        json.len() / 1024
    );
    let db = sr_db(&json).unwrap();
    let local: Vec<PrefixSid> = (0..4)
        .map(|i| PrefixSid {
            id: ItemId(i + 1),
            prefix: format!("10.255.0.{}/32", i + 1).parse().unwrap(),
            index: i + 1,
            behavior: SidBehavior::Php,
            disabled: false,
            comment: String::new(),
        })
        .collect();
    let clashes = corerouter_proto_ospf::sr::conflicts(&db, &local);
    eprintln!("{} clashes found", clashes.len());
    let mut g = c.benchmark_group("ospf sr 10k sids");
    g.sample_size(20);
    g.bench_function("read sr database", |b| {
        b.iter(|| black_box(sr_db(black_box(&json)).unwrap()).nodes.len())
    });
    g.bench_function("sid clashes", |b| {
        b.iter(|| black_box(corerouter_proto_ospf::sr::conflicts(black_box(&db), &local)).len())
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
