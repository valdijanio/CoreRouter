//! G1.6b: the costs of an update on the router — the verity tree of a slot
//! (read-back check, scrub) on 1 and N threads, and the streamed copy of a
//! package payload with and without the read/write pipeline.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Write;

use corerouter_sysupdate::{package, verity};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};

const MIB: usize = 1 << 20;

fn data(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect()
}

fn tree(c: &mut Criterion) {
    let mut g = c.benchmark_group("verity_tree");
    g.sample_size(10);
    // 16 MiB is today's rootfs; 256 MiB a full slot.
    for mib in [16usize, 256] {
        let d = data(mib * MIB);
        g.throughput(Throughput::Bytes(d.len() as u64));
        for threads in [1usize, 4, 8] {
            g.bench_function(format!("{mib}MiB_{threads}t"), |b| {
                b.iter(|| verity::tree(&d, &[0], threads))
            });
        }
    }
    g.finish();
}

fn copy(c: &mut Criterion) {
    let mut g = c.benchmark_group("package_copy");
    g.sample_size(10);
    let d = data(64 * MIB);
    g.throughput(Throughput::Bytes(d.len() as u64));
    let dir = std::env::temp_dir().join(format!("crpkg-bench-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    for pipelined in [false, true] {
        let name = if pipelined { "pipelined" } else { "sequential" };
        g.bench_function(format!("64MiB_to_file_{name}"), |b| {
            b.iter(|| {
                let mut f = std::fs::File::create(dir.join("slot")).unwrap();
                let mut parts: [(u64, &mut dyn Write); 1] = [(d.len() as u64, &mut f)];
                let r = package::copy(&mut d.as_slice(), &mut parts, pipelined, &mut |_| {});
                f.sync_all().unwrap();
                r
            })
        });
    }
    let _ = std::fs::remove_dir_all(&dir);
    g.finish();
}

criterion_group!(benches, tree, copy);
criterion_main!(benches);
