//! G4.3gb / G0.21 / G0.22 — what one write costs with a big list already in
//! the config (the copy-on-write sections of G0.16 copy a whole list on the
//! first write after a commit):
//!
//! - `ppp_secret_add/single/N`: one `ppp.secret.add` in immediate mode (its
//!   own commit) with N secrets in place: what an API or RADIUS-driven
//!   provisioning pays per subscriber;
//! - `ppp_secret_add/batch_step/N`: a non-atomic `engine.batch` of 100 adds
//!   (each step commits); the time is per batch of 100;
//! - `ppp_secret_add/atomic_step/N`: the same 100 adds in one atomic batch
//!   (one commit at the end);
//! - `ppp_secret_set/single/N`: a comment on the secret in the middle.
//!
//! The adds are removed again outside the timing, so N stays put.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-engine --bench config_store`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::{Duration, Instant};

use corerouter_engine::{MemoryStorage, Session, Slot};
use corerouter_model::ppp::PppSecret;
use corerouter_model::{ConfigStore, ItemId, persist};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use serde_json::{Value, json};

/// A session restored from a config with `n` secrets, in immediate mode.
fn with_secrets(n: u32) -> Session {
    let mut cfg = Session::virtual_lab().store().running().clone();
    for i in 0..n {
        cfg.ppp.secrets.push(PppSecret {
            id: ItemId(i + 1),
            name: format!("cliente{i}@isp"),
            password: format!("senha{i}").into(),
            profile: "default".into(),
            ..PppSecret::default()
        });
    }
    cfg.ppp.next_id = n;
    let storage = MemoryStorage::default();
    storage.put(
        Slot::Current,
        Some(persist::encode(&ConfigStore::new(cfg)).unwrap()),
    );
    Session::with_storage(
        Box::new(corerouter_hal::virt::VirtualHal::default()),
        Box::new(storage),
    )
}

fn add_steps(tag: u64, k: usize) -> Value {
    let steps: Vec<Value> = (0..k)
        .map(|i| {
            json!({"command": "ppp.secret.add", "params": {
                "name": format!("bench{tag}-{i}"), "password": "x",
            }})
        })
        .collect();
    Value::Array(steps)
}

fn remove_steps(tag: u64, k: usize) -> Value {
    let steps: Vec<Value> = (0..k)
        .map(|i| json!({"command": "ppp.secret.remove", "params": {"id": format!("bench{tag}-{i}")}}))
        .collect();
    Value::Array(steps)
}

const STEPS: usize = 100;

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("config_store");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(4));
    for n in [1_000_u32, 10_000, 100_000] {
        let mut s = with_secrets(n);
        let mut tag = 0_u64;
        g.bench_function(BenchmarkId::new("ppp_secret_add/single", n), |b| {
            b.iter_custom(|iters| {
                let mut spent = Duration::ZERO;
                for _ in 0..iters {
                    tag += 1;
                    let name = format!("bench{tag}");
                    let t = Instant::now();
                    s.execute("ppp.secret.add", &json!({"name": name, "password": "x"}))
                        .unwrap();
                    spent += t.elapsed();
                    s.execute("ppp.secret.remove", &json!({"id": name}))
                        .unwrap();
                }
                spent
            });
        });
        let mid = format!("cliente{}@isp", n / 2);
        let mut flip = false;
        g.bench_function(BenchmarkId::new("ppp_secret_set/single", n), |b| {
            b.iter(|| {
                flip = !flip;
                let comment = if flip { "a" } else { "b" };
                s.execute("ppp.secret.set", &json!({"id": mid, "comment": comment}))
                    .unwrap()
            });
        });
        g.throughput(Throughput::Elements(STEPS as u64));
        for (kind, atomic) in [("batch_step", false), ("atomic_step", true)] {
            g.bench_function(BenchmarkId::new(format!("ppp_secret_add/{kind}"), n), |b| {
                b.iter_custom(|iters| {
                    let mut spent = Duration::ZERO;
                    for _ in 0..iters {
                        tag += 1;
                        let steps = add_steps(tag, STEPS);
                        let t = Instant::now();
                        s.batch(&steps, atomic).unwrap();
                        spent += t.elapsed();
                        s.batch(&remove_steps(tag, STEPS), true).unwrap();
                    }
                    spent
                });
            });
        }
        g.throughput(Throughput::Elements(1));
    }
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
