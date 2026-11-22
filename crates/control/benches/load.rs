//! audit-perf — the control channel under load: N connections at once,
//! each sending `engine.execute interface.list` back to back on plain TCP
//! (local token). One iteration is one request from each connection, so
//! criterion's throughput is requests per second over all of them; the
//! latency percentiles of every request are printed after each group
//! (`p50`/`p99`). N stops at `MAX_CONNECTIONS` (16): a 17th connection is
//! refused by design.
//!
//! `cargo xtask bench control_load`; alone: `cargo bench -p corerouter-control --bench load`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Mutex;
use std::time::{Duration, Instant};

use corerouter_control::{Client, Endpoint, Gate, SharedHost, bind_loopback, spawn};
use corerouter_engine::{Session, shared};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use serde_json::{Value, json};

const TIMEOUT: Duration = Duration::from_secs(10);

/// `n` authenticated connections to one server on a lab session.
fn clients(n: usize) -> Vec<Client> {
    let session = shared(Session::virtual_lab());
    let gate = Gate::default();
    let token = corerouter_control::auth::new_token().unwrap();
    gate.add_local_token(&token);
    let listener = bind_loopback(0).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    spawn(Endpoint::loopback(listener), SharedHost(session), gate).unwrap();
    (0..n)
        .map(|_| {
            let mut c = Client::connect(&addr, TIMEOUT).unwrap();
            c.set_token(Some(token.clone()));
            // A request with the token: the connection leaves the few
            // slots of the not-logged-in (`ping` checks no token).
            c.call("auth.whoami", Value::Null).unwrap();
            c
        })
        .collect()
}

fn percentile(sorted: &[Duration], p: usize) -> Duration {
    let i = (sorted.len().saturating_sub(1)).saturating_mul(p) / 100;
    sorted.get(i).copied().unwrap_or_default()
}

fn load(c: &mut Criterion) {
    let list = json!({"command": "interface.list", "params": {}});
    let mut g = c.benchmark_group("control_load");
    g.sample_size(20);
    g.measurement_time(Duration::from_secs(4));
    for n in [1usize, 4, 16] {
        let mut conns = clients(n);
        let latencies: Mutex<Vec<Duration>> = Mutex::new(Vec::new());
        g.throughput(Throughput::Elements(n as u64));
        g.bench_function(BenchmarkId::new("tcp/interface.list", n), |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                std::thread::scope(|scope| {
                    for client in conns.iter_mut() {
                        let list = &list;
                        let latencies = &latencies;
                        scope.spawn(move || {
                            let mut mine = Vec::with_capacity(iters as usize);
                            for _ in 0..iters {
                                let t = Instant::now();
                                client.call("engine.execute", list.clone()).unwrap();
                                mine.push(t.elapsed());
                            }
                            latencies.lock().unwrap().extend(mine);
                        });
                    }
                });
                start.elapsed()
            });
        });
        let mut all = latencies.into_inner().unwrap();
        all.sort_unstable();
        eprintln!(
            "control_load/tcp/interface.list/{n}: {} requests, p50 {:?}, p99 {:?}, max {:?}",
            all.len(),
            percentile(&all, 50),
            percentile(&all, 99),
            all.last().copied().unwrap_or_default()
        );
    }
    g.finish();
}

criterion_group!(benches, load);
criterion_main!(benches);
