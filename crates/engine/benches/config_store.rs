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
//! - `ppp_secret_set/single/N`: a comment on the secret in the middle;
//! - `identity_set/queues/N` (G4.9 × G0.22): `system.identity.set` with N
//!   simple queues in place, a commit that touches none of them;
//! - `ipoe_index/secret_add/N` (G0.21 × G4.3f): what the DHCP round pays to
//!   follow a config with N IPoE secrets and N static leases with a rate
//!   after one `ppp.secret.add`; `ipoe_index/lease_set/N`: after one lease's
//!   `rate_limit` changed.
//!
//! The adds are removed again outside the timing, so N stays put.
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-engine --bench config_store`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use corerouter_engine::ipoe::{IpoeIndex, IpoeView};
use corerouter_engine::{MemoryStorage, Session, Slot};
use corerouter_model::dhcp_server::StaticLease;
use corerouter_model::ppp::{PppSecret, PppService};
use corerouter_model::{Config, ConfigStore, ItemId, persist};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use serde_json::{Value, json};

/// A session restored from a config with `n` secrets, in immediate mode.
fn with_secrets(n: u32) -> Session {
    let mut cfg = Session::virtual_lab().store().running().clone();
    for i in 0..n {
        cfg.ppp.secrets.push(PppSecret {
            id: ItemId(i + 1),
            name: format!("cliente{i}@isp"),
            password: format!("senha{i}"),
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
    {
        let n = 10_000usize;
        let mut s = Session::virtual_lab();
        let steps: Vec<Value> = (0..n)
            .map(|i| {
                json!({"command": "queue.simple.add", "params": {
                    "name": format!("q{i}"),
                    "target": format!("10.{}.{}.{}/32", i >> 16, (i >> 8) & 255, i & 255),
                    "max_limit": "10M/50M",
                }})
            })
            .collect();
        s.batch(&Value::Array(steps), true).unwrap();
        assert_eq!(s.store().running().queue.simple.len(), n);
        let mut flip = false;
        g.bench_function(BenchmarkId::new("identity_set/queues", n), |b| {
            b.iter(|| {
                flip = !flip;
                let name = if flip { "a" } else { "b" };
                s.execute("system.identity.set", &json!({"name": name}))
                    .unwrap()
            });
        });
    }
    for n in [1_000_u32, 10_000, 100_000] {
        let base = ipoe_config(n);
        let mut idx = IpoeIndex::of(&base);
        let mut tag = 0_u32;
        g.bench_function(BenchmarkId::new("ipoe_index/secret_add", n), |b| {
            b.iter_custom(|iters| {
                let mut spent = Duration::ZERO;
                for _ in 0..iters {
                    tag += 1;
                    let mut cfg = base.clone();
                    cfg.ppp.secrets.push(PppSecret {
                        id: ItemId(n + tag),
                        name: format!("novo{tag}"),
                        service: PppService::Ipoe,
                        ..PppSecret::default()
                    });
                    let t = Instant::now();
                    idx.refresh(&cfg);
                    spent += t.elapsed();
                    assert!(
                        IpoeView::new(&cfg, &idx)
                            .secret(&format!("novo{tag}"))
                            .is_some()
                    );
                }
                spent
            });
        });
        g.bench_function(BenchmarkId::new("ipoe_index/lease_set", n), |b| {
            b.iter_custom(|iters| {
                let mut spent = Duration::ZERO;
                for _ in 0..iters {
                    tag += 1;
                    let mut cfg = base.clone();
                    let leases = &mut cfg.ip.dhcp_server.leases;
                    if let Some(l) = leases.get_mut(n as usize / 2) {
                        l.rate_limit = format!("{tag}M/{tag}M");
                    }
                    let t = Instant::now();
                    idx.refresh(&cfg);
                    spent += t.elapsed();
                }
                spent
            });
        });
    }
    g.finish();
}

/// `n` IPoE secrets and `n` static leases with a rate, the indexes of the
/// secrets already built (as a running config that served lookups).
fn ipoe_config(n: u32) -> Config {
    let mut cfg = Config::default();
    for i in 0..n {
        cfg.ppp.secrets.push(PppSecret {
            id: ItemId(i + 1),
            name: format!("olt1/{i}"),
            service: PppService::Ipoe,
            ..PppSecret::default()
        });
    }
    let leases = &mut cfg.ip.dhcp_server.leases;
    for i in 0..n {
        let mut l = StaticLease::new(ItemId(i + 1), Ipv4Addr::from(0x6440_0000 + i));
        l.rate_limit = "10M/50M".into();
        leases.push(l);
    }
    let _ = cfg.ppp.secrets.by_name("olt1/0");
    cfg
}

criterion_group!(benches, bench);
criterion_main!(benches);
