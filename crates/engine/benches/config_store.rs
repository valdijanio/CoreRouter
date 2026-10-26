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
//!   `rate_limit` changed;
//! - `queue_simple_add/single/N` (G4.9 × G0.21): one named `queue.simple.add`
//!   (its own commit) with N simple queues in place; `…/unnamed/N` the same
//!   without a name (it gets the first free `queue<k>`); `…/batch_step/N`
//!   and `…/atomic_step/N` 100 adds per batch, as for the secrets;
//!   `queue_sync/idle/N`: one round of the daemon's `queue` service (once
//!   a second, under the session lock) when nothing changed.
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
use corerouter_model::queue::SimpleQueue;
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
    // 80 000, not 100 000: ~90 000 queues (~170 bytes each saved) reach the
    // 15 MiB the config may take on disk, so a commit is refused.
    for n in [1_000_usize, 10_000, 80_000] {
        let mut s = with_queues(n);
        let mut tag = 0_u64;
        g.throughput(Throughput::Elements(1));
        for named in [true, false] {
            let kind = if named { "single" } else { "unnamed" };
            g.bench_function(BenchmarkId::new(format!("queue_simple_add/{kind}"), n), |b| {
                b.iter_custom(|iters| {
                    let mut spent = Duration::ZERO;
                    for _ in 0..iters {
                        tag += 1;
                        let p = if named {
                            json!({"name": format!("bench{tag}"), "target": "172.16.0.1/32", "max_limit": "10M/50M"})
                        } else {
                            json!({"target": "172.16.0.1/32", "max_limit": "10M/50M"})
                        };
                        let t = Instant::now();
                        let r = s.execute("queue.simple.add", &p).unwrap();
                        spent += t.elapsed();
                        s.execute("queue.simple.remove", &json!({"id": r.get("id")}))
                            .unwrap();
                    }
                    spent
                });
            });
        }
        s.queue_sync();
        g.bench_function(BenchmarkId::new("queue_sync/idle", n), |b| {
            b.iter(|| s.queue_sync());
        });
        g.throughput(Throughput::Elements(STEPS as u64));
        for (kind, atomic) in [("batch_step", false), ("atomic_step", true)] {
            g.bench_function(
                BenchmarkId::new(format!("queue_simple_add/{kind}"), n),
                |b| {
                    b.iter_custom(|iters| {
                        let mut spent = Duration::ZERO;
                        for _ in 0..iters {
                            tag += 1;
                            let steps: Vec<Value> = (0..STEPS)
                                .map(|i| {
                                    json!({"command": "queue.simple.add", "params": {
                                        "name": format!("b{tag}-{i}"),
                                        "target": format!("172.16.{}.{}/32", i >> 8, i & 255),
                                        "max_limit": "10M/50M",
                                    }})
                                })
                                .collect();
                            let t = Instant::now();
                            s.batch(&Value::Array(steps), atomic).unwrap();
                            spent += t.elapsed();
                            let ids: Vec<String> =
                                (0..STEPS).map(|i| format!("b{tag}-{i}")).collect();
                            s.execute("queue.simple.remove", &json!({"id": ids}))
                                .unwrap();
                        }
                        spent
                    });
                },
            );
        }
        g.throughput(Throughput::Elements(1));
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

/// A session restored from a config with `n` simple queues named as
/// RouterOS names new ones (`queue1`…), one per /32, in immediate mode.
fn with_queues(n: usize) -> Session {
    let mut cfg = Session::virtual_lab().store().running().clone();
    for i in 0..n {
        let target = format!("10.{}.{}.{}/32", i >> 16, (i >> 8) & 255, i & 255);
        let mut q = SimpleQueue::new(
            ItemId(i as u32 + 1),
            format!("queue{}", i + 1),
            vec![target.parse().unwrap()],
        );
        q.max_limit = "10M/50M".parse().unwrap();
        cfg.queue.simple.push(q);
    }
    cfg.queue.next_id = n as u32;
    let storage = MemoryStorage::default();
    storage.put(
        Slot::Current,
        Some(persist::encode(&ConfigStore::new(cfg)).unwrap()),
    );
    let s = Session::with_storage(
        Box::new(corerouter_hal::virt::VirtualHal::default()),
        Box::new(storage),
    );
    assert_eq!(s.store().running().queue.simple.len(), n);
    s
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
