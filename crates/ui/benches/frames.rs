//! audit-gui — one frame of the real UI over big lists (an ISP box with
//! thousands of addresses or firewall rules): the cost a list window adds to
//! every frame while it is open. 60 fps leaves 16 ms for the whole frame.
//!
//! `cargo xtask bench ui_frame`; alone: `cargo bench -p corerouter-ui --bench frames`.

use corerouter_ui::perf::Frames;
use criterion::{Criterion, criterion_group, criterion_main};

fn frames(c: &mut Criterion) {
    let mut g = c.benchmark_group("ui_frame");
    g.sample_size(10);
    let mut f = Frames::addresses(10_000, 20, false);
    g.bench_function("addresses_10k", |b| b.iter(|| f.frame()));
    let mut f = Frames::addresses(10_000, 20, true);
    g.bench_function("addresses_10k_all_selected", |b| b.iter(|| f.frame()));
    let mut f = Frames::addresses(1_000, 4_000, false);
    g.bench_function("addresses_1k_4kB_comments", |b| b.iter(|| f.frame()));
    let mut f = Frames::firewall(5_000);
    g.bench_function("firewall_5k_shadowed", |b| b.iter(|| f.frame()));
    // G1.27c: a full BGP table in IP › Routes.
    let mut f = Frames::routes(1_000_000);
    g.bench_function("routes_1m", |b| b.iter(|| f.frame()));
    let mut f = Frames::terminal(5_000, 200);
    g.bench_function("terminal_5000_lines", |b| b.iter(|| f.frame()));
    // G4.8a: System › Resources (Overview) open.
    let mut f = Frames::panel("resources");
    g.bench_function("resources_overview", |b| b.iter(|| f.frame()));
    g.finish();
}

criterion_group!(benches, frames);
criterion_main!(benches);
