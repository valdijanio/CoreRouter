//! G3.4n: the OSPF query commands on a large network, as the window, the
//! CLI and MCP call them: 4 000 OSPF interfaces, 500 neighbors and an LSDB
//! of 100 000 LSAs (2 000 routers) with 200 000 routes. Time per call and
//! the answer's size (what crosses the control channel).
//!
//! `cargo xtask bench ospf_queries`; alone:
//! `cargo bench -p corerouter-engine --bench ospf_queries`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::hint::black_box;
use std::time::Instant;

use corerouter_engine::Session;
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::{Value, json};

fn run(s: &mut Session, id: &str, p: &Value) -> Value {
    s.execute(id, p).unwrap()
}

fn bench(c: &mut Criterion) {
    let built = Instant::now();
    let mut s = corerouter_engine::perf::ospf_scale(4_000, 500, 2_000, 100_000, 200_000);
    eprintln!(
        "ospf_scale built in {:.0} ms",
        built.elapsed().as_secs_f64() * 1e3
    );
    let cases: &[(&str, &str, Value)] = &[
        ("neighbor_list_500", "routing.ospf.neighbor.list", json!({})),
        (
            "interface_list_4000",
            "routing.ospf.interface.list",
            json!({}),
        ),
        (
            "lsa_page_100k",
            "routing.ospf.lsa.list",
            json!({"instance": "v2", "limit": 200}),
        ),
        (
            "lsa_find_100k",
            "routing.ospf.lsa.list",
            json!({"instance": "v2", "find": "10.1.7", "limit": 200}),
        ),
        (
            "route_list_200k",
            "routing.ospf.route.list",
            json!({"instance": "v2"}),
        ),
        (
            "route_find_200k",
            "routing.ospf.route.list",
            json!({"instance": "v2", "find": "20.1."}),
        ),
        (
            "path_200k",
            "routing.ospf.path",
            json!({"instance": "v2", "to": "10.1.3.232"}),
        ),
        (
            "diagnose_4000",
            "routing.ospf.neighbor.diagnose",
            json!({"interface": "vlan7"}),
        ),
    ];
    // The answer sizes, once (the bytes a control-channel reply carries).
    for (name, id, p) in cases {
        let v = run(&mut s, id, p);
        let rows = v.get("rows").and_then(Value::as_array).map_or(0, Vec::len);
        eprintln!(
            "{name}: {} KiB, {rows} rows",
            serde_json::to_vec(&v).unwrap().len() >> 10
        );
    }
    // The topology's first call lays the map out; later ones reuse it.
    let first = Instant::now();
    let v = run(&mut s, "routing.ospf.topology", &json!({"instance": "v2"}));
    eprintln!(
        "topology_2000 first call (layout): {:.0} ms, {} nodes, {} KiB",
        first.elapsed().as_secs_f64() * 1e3,
        v["nodes"].as_array().map_or(0, Vec::len),
        serde_json::to_vec(&v).unwrap().len() >> 10
    );
    let mut g = c.benchmark_group("ospf_query");
    g.sample_size(20);
    for (name, id, p) in cases {
        g.bench_function(*name, |b| b.iter(|| black_box(run(&mut s, id, p))));
    }
    g.bench_function("topology_2000_laid_out", |b| {
        b.iter(|| {
            black_box(run(
                &mut s,
                "routing.ospf.topology",
                &json!({"instance": "v2"}),
            ))
        })
    });
    // G3.4n: the window's refresh while it holds the map.
    let t = run(&mut s, "routing.ospf.topology", &json!({"instance": "v2"}));
    if let Some(token) = t.get("token").cloned() {
        let p = json!({"instance": "v2", "known": token});
        eprintln!(
            "topology_2000 unchanged: {} B",
            serde_json::to_vec(&run(&mut s, "routing.ospf.topology", &p))
                .unwrap()
                .len()
        );
        g.bench_function("topology_2000_unchanged", |b| {
            b.iter(|| black_box(run(&mut s, "routing.ospf.topology", &p)))
        });
    }
    // What the FRR thread holds the session lock for after each poll:
    // storing the sample (and, before G3.4n, freeing the previous one).
    let status = s.routing_status().cloned().unwrap();
    g.bench_function("set_routing_status_4000_ifs", |b| {
        b.iter_batched(
            || status.clone(),
            |st| s.set_routing_status(st),
            criterion::BatchSize::LargeInput,
        )
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
