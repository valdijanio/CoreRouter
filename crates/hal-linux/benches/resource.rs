//! G4.8a — what one reading of System › Resources costs on this machine
//! (`/proc`, `/sys`, `statvfs`; no root): the `health` service takes one
//! every 5 s (every second while someone looks), the process list only on
//! demand, the sensors every 10 s (`sensors`: what that read costs).
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
