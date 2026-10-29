//! G4.8a — what one reading of System › Resources costs on this machine
//! (`/proc`, `/sys`, `statvfs`; no root): the `health` service takes one
//! every 5 s (every second while someone looks), the process list only on
//! demand, the sensors every 10 s (`sensors`: what that read costs).
//! G1.6qd: `router` is the router's own processes on every reading (pids
//! known), `router_scan` the look at all of `/proc` every 30 s.
//!
//! ```sh
//! cargo bench -p corerouter-hal-linux --bench resource
//! ```

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("skipped: /proc is Linux-only");
}

#[cfg(target_os = "linux")]
fn main() {
    use corerouter_hal::system_resource::{ResourceSampler, Want};
    use corerouter_hal_linux::resource::Collector;
    use criterion::Criterion;

    let mut c = Criterion::default().configure_from_args();
    let mut g = c.benchmark_group("resource");
    let mut col = Collector::default();
    g.bench_function("sample", |b| {
        b.iter(|| col.sample(Want::default()));
    });
    g.bench_function("sensors", |b| {
        b.iter(|| col.sensors());
    });
    g.bench_function("router", |b| {
        col.router(0);
        b.iter(|| col.router(1));
    });
    let mut t = 0u64;
    g.bench_function("router_scan", |b| {
        b.iter(|| {
            t += 60_000;
            col.router(t)
        });
    });
    g.bench_function("sample_with_processes", |b| {
        b.iter(|| {
            col.sample(Want {
                processes: true,
                now_ms: None,
            })
        });
    });
    g.finish();
    c.final_summary();
}
