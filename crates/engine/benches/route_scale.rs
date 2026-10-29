//! G0.31d/e — static routes by the tens of thousands, through the
//! commands: an import of 60 000 routes in two `engine.batch` of 30 000
//! (printed, once), then with them in place one more route checked
//! (`ip.route.add` in transactional mode: the duplicate check, G0.31d) and
//! one more route committed (`ip.route.add` + `ip.route.remove` in
//! immediate mode: two commits, G0.31e).
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-engine --bench route_scale`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::hint::black_box;
use std::time::{Duration, Instant};

use corerouter_engine::Session;
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::{Value, json};

/// Routes imported (the G0.31 audit's table).
const N: usize = 60_000;
/// Steps per `engine.batch` (below `MAX_BATCH`).
const CHUNK: usize = 30_000;

/// Route `i`: a /24 out of 10.0.0.0/8 and 11.0.0.0/8, via one gateway.
fn route(i: usize) -> Value {
    json!({
        "dst_address": format!("{}.{}.{}.0/24", 10 + i / 65_536, (i / 256) % 256, i % 256),
        "gateway": "192.168.88.254",
    })
}

fn import(s: &mut Session) {
    let mut line = String::new();
    for k in 0..N / CHUNK {
        let steps: Vec<Value> = (k * CHUNK..(k + 1) * CHUNK)
            .map(|i| json!({"command": "ip.route.add", "params": route(i)}))
            .collect();
        let t = Instant::now();
        s.batch(&Value::Array(steps), true).unwrap();
        line.push_str(&format!(" {:.2} s", t.elapsed().as_secs_f64()));
    }
    eprintln!("route_scale: import of {N} routes, by batch of {CHUNK}:{line}");
}

fn bench(c: &mut Criterion) {
    let mut s = Session::virtual_lab();
    s.execute(
        "ip.address.add",
        &json!({"address": "192.168.88.1/24", "interface": "ether1"}),
    )
    .unwrap();
    import(&mut s);
    assert_eq!(s.store().running().ip.routes.len(), N);
    let extra = json!({"dst_address": "172.16.0.0/24", "gateway": "192.168.88.254"});
    let mut g = c.benchmark_group("route_scale");
    g.sample_size(20).measurement_time(Duration::from_secs(5));
    // G0.31e: each command a commit with 60 000 routes in place.
    g.bench_function("commit/add_remove", |b| {
        b.iter(|| {
            let id = s.execute("ip.route.add", black_box(&extra)).unwrap()["id"].clone();
            s.execute("ip.route.remove", &json!({ "id": id })).unwrap();
        });
    });
    // G0.31d: the command alone (no commit), against 60 000 routes.
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    g.bench_function("check/add_remove", |b| {
        b.iter(|| {
            let id = s.execute("ip.route.add", black_box(&extra)).unwrap()["id"].clone();
            s.execute("ip.route.remove", &json!({ "id": id })).unwrap();
        });
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
