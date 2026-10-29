//! G1.6e: one `system.package.upload.chunk` of 1 MiB through
//! `Session::execute` — the JSON line already parsed, then the parameter
//! check, the base64 decode and the hand-over to the bounded queue. This is
//! what the session lock is held for per chunk; the package service drains
//! the queue on its own thread (here: the bench drains it).
//!
//! `cargo xtask bench` runs it; alone: `cargo bench -p corerouter-engine --bench package_upload`.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::time::Duration;

use base64::Engine as _;
use corerouter_engine::Session;
use corerouter_engine::package::{feed_status, take_job, take_upload};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use serde_json::json;

const CHUNK: usize = 1 << 20;

const SIZE: u64 = 4 << 30;

/// A new upload of [`SIZE`] bytes and its stream.
fn start(s: &mut Session) -> (u64, std::sync::mpsc::Receiver<Vec<u8>>) {
    let _ = s.execute("system.package.upload.abort", &json!({}));
    let id = s
        .execute("system.package.upload.start", &json!({"size": SIZE}))
        .unwrap()["upload"]
        .as_u64()
        .unwrap();
    let job = take_job(s).unwrap();
    let rx = take_upload(s, job.id).unwrap();
    // The service would finish the job; here nothing does.
    corerouter_engine::package::feed_progress(s, "bench", 0, 0);
    (id, rx)
}

fn chunk(c: &mut Criterion) {
    let mut s = Session::virtual_lab();
    feed_status(
        &mut s,
        json!({"supported": true, "running": "a", "trial": null}),
    );
    let (mut id, mut rx) = start(&mut s);
    let data: Vec<u8> = (0..CHUNK).map(|i| (i % 251) as u8).collect();
    let text = base64::engine::general_purpose::STANDARD.encode(&data);
    let mut offset = 0u64;
    let mut g = c.benchmark_group("package_upload");
    g.throughput(Throughput::Bytes(CHUNK as u64));
    g.measurement_time(Duration::from_secs(4));
    g.bench_function("chunk_1MiB", |b| {
        b.iter(|| {
            if offset + CHUNK as u64 > SIZE {
                corerouter_engine::package::finish(&mut s, id, "upload", Err("bench".into()));
                (id, rx) = start(&mut s);
                offset = 0;
            }
            let p = json!({"upload": id, "offset": offset, "data": text});
            let r = s.execute("system.package.upload.chunk", &p).unwrap();
            assert_eq!(r["busy"], false);
            offset += CHUNK as u64;
            drop(rx.try_recv());
        })
    });
    g.finish();
}

criterion_group!(benches, chunk);
criterion_main!(benches);
