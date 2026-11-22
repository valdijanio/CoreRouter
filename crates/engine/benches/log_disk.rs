//! G4.6g: what the disk action costs. `log_event` runs under the session
//! lock, with and without a rule to `disk`; `encode` is the writer's per-line
//! work outside it; `restore` is the boot's: a full window read back.

use std::hint::black_box;

use corerouter_engine::Session;
use corerouter_engine::log_disk::{WINDOW, decode_all, encode};
use corerouter_engine::logging::DAEMON;
use corerouter_model::logging::LogEvent;
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::{Value, json};

fn event() -> LogEvent {
    LogEvent {
        seq: 0,
        time: 1_800_000_000,
        topics: vec!["system".into(), "info".into()],
        origin: "admin · GUI".into(),
        message: "Nome do roteador alterado para «edge1»".into(),
        detail: json!({"command": "system.identity.set", "journal": 42, "params": {"name": "edge1"}, "result": {"name": "edge1"}, "revision": 42}),
    }
}

fn bench(c: &mut Criterion) {
    let mut plain = Session::virtual_lab();
    c.bench_function("log_disk/log_event/no_rule", |b| {
        b.iter(|| plain.log_event(&["system", "info"], DAEMON, "x".into(), Value::Null));
    });
    let mut disk = Session::virtual_lab();
    disk.execute(
        "system.logging.add",
        &json!({"topics": ["info"], "action": "disk"}),
    )
    .ok();
    disk.log_disk_attach(Vec::new(), 0);
    c.bench_function("log_disk/log_event/disk_rule", |b| {
        b.iter(|| {
            disk.log_event(&["system", "info"], DAEMON, "x".into(), Value::Null);
            // The writer's swap, every second in the daemon.
            black_box(disk.log_disk_take());
        });
    });
    let e = event();
    c.bench_function("log_disk/encode", |b| {
        b.iter(|| black_box(encode(black_box(&e))))
    });
    let file: String = std::iter::repeat_n(encode(&e).unwrap_or_default(), WINDOW).collect();
    c.bench_function("log_disk/restore_window", |b| {
        b.iter(|| black_box(decode_all(file.as_bytes())))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
