//! G0.21 / G4.3gb — one write to a big list shared with another copy of
//! the config (the rollback point, the running config): `CowArc<Vec<T>>`
//! (G0.16, the whole list copied) against `CowList<T>` (one block), with
//! 100 000 PPP secrets. And what the blocks cost to read: a whole walk.
//!
//! `cargo xtask bench cow_list`; alone: `cargo bench -p corerouter-model --bench cow_list`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::hint::black_box;
use std::time::Duration;

use corerouter_model::ItemId;
use corerouter_model::cow::CowArc;
use corerouter_model::cow_list::CowList;
use corerouter_model::cow_map::CowMap;
use corerouter_model::ppp::PppSecret;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

const N: u32 = 100_000;

fn secret(i: u32) -> PppSecret {
    PppSecret {
        id: ItemId(i + 1),
        name: format!("cliente{i}@isp"),
        password: format!("senha{i}").into(),
        profile: "default".into(),
        ..PppSecret::default()
    }
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("cow_list");
    g.sample_size(20);
    g.measurement_time(Duration::from_secs(3));
    let vec: CowArc<Vec<PppSecret>> = (0..N).map(secret).collect::<Vec<_>>().into();
    let list: CowList<PppSecret> = (0..N).map(secret).collect();
    let mid = usize::try_from(N / 2).unwrap();
    g.bench_function(BenchmarkId::new("set_shared/vec", N), |b| {
        b.iter(|| {
            let mut v = vec.clone();
            v.get_mut(mid).unwrap().disabled = true;
            v
        });
    });
    g.bench_function(BenchmarkId::new("set_shared/blocks", N), |b| {
        b.iter(|| {
            let mut v = list.clone();
            v.get_mut(mid).unwrap().disabled = true;
            v
        });
    });
    g.bench_function(BenchmarkId::new("push_shared/blocks", N), |b| {
        b.iter(|| {
            let mut v = list.clone();
            v.push(secret(N));
            v
        });
    });
    g.bench_function(BenchmarkId::new("remove_shared/blocks", N), |b| {
        b.iter(|| {
            let mut v = list.clone();
            v.remove(mid);
            v
        });
    });
    g.bench_function(BenchmarkId::new("walk/vec", N), |b| {
        b.iter(|| vec.iter().filter(|s| black_box(s.disabled)).count());
    });
    g.bench_function(BenchmarkId::new("walk/blocks", N), |b| {
        b.iter(|| list.iter().filter(|s| black_box(s.disabled)).count());
    });
    g.bench_function(BenchmarkId::new("get/blocks", N), |b| {
        b.iter(|| list.get(black_box(mid)).map(|s| s.id));
    });
    let index: CowMap<String, ItemId> = (0..N)
        .map(|i| (format!("cliente{i}@isp"), ItemId(i + 1)))
        .collect();
    g.bench_function(BenchmarkId::new("index_insert_shared", N), |b| {
        b.iter(|| {
            let mut m = index.clone();
            m.insert("novo@isp".into(), ItemId(N + 1));
            m
        });
    });
    g.bench_function(BenchmarkId::new("index_get", N), |b| {
        b.iter(|| index.get(black_box("cliente777@isp")).copied());
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
