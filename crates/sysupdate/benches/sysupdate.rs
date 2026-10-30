//! G1.6b: the costs of an update on the router — the verity tree of a slot
//! (read-back check, scrub) on 1 and N threads, and the streamed copy of a
//! package payload with and without the read/write pipeline.
//! G1.6c: a whole install from an ISO file to a disk file (today's sizes:
//! 20 MiB ESP, 20 MiB rootfs, 64 MiB `/config`), with and without the
//! pipeline and the parallel read-back.
//! G1.6u: the configuration snapshot of the test VM's `/config` (a 10.7 MB
//! revision, 60 small ones, 3.7 MB of graphs) as a full copy (before) and
//! linked (now), and the walk of `/config` the status makes every 2 s.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Write;

use corerouter_sysupdate::gpt::{self, NewPart};
use corerouter_sysupdate::install::{self, Content};
use corerouter_sysupdate::package::{Blob, Key, Manifest, Rootfs};
use corerouter_sysupdate::{SlotId, iso, package, state, verity};
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

/// An installer ISO (in memory) with the image's sizes, and its key.
fn medium() -> (Vec<u8>, Vec<Key>) {
    let key = package::generate_key().unwrap();
    let keys = vec![Key::from_hex(&package::public_hex(&key).unwrap()).unwrap()];
    let m = MIB as u64;
    // efi 32 MiB at 1, rootfs-a 32, rootfs-b 1, config 64.
    let layout = [
        ("efi", iso::ESP_TYPE, 1, 32),
        ("rootfs-a", "4f68bce3-e8cd-4db1-96e7-fbcaf984b709", 33, 32),
        ("rootfs-b", "4f68bce3-e8cd-4db1-96e7-fbcaf984b709", 65, 1),
        ("config", "0fc63daf-8483-4772-8e79-3d69d8477de4", 66, 64),
    ];
    let guids = [
        "4f9a520b-35f7-4633-a4bb-e9f871d1473c",
        "3e1088b8-5b4b-4fbb-b756-a271f641d018",
        "868e1d1d-85bb-4c62-a083-f61aa7a5cda2",
        "4c6422db-190c-4f35-b930-a98862b6be7d",
    ];
    let parts: Vec<NewPart> = layout
        .iter()
        .zip(guids)
        .map(|((n, t, at, size), g)| NewPart {
            name: (*n).into(),
            type_guid: (*t).into(),
            guid: g.into(),
            first_lba: at * m / 512,
            last_lba: (at + size) * m / 512 - 1,
            attrs: 0,
        })
        .collect();
    let lbas = 131 * m / 512;
    let (p, at, b) = gpt::build(lbas, 512, "39dfcaa2-2c8a-4912-acaa-6af0c68b5350", &parts).unwrap();
    let mut disk = vec![0u8; (lbas * 512) as usize];
    disk[..p.len()].copy_from_slice(&p);
    disk[at as usize..at as usize + b.len()].copy_from_slice(&b);
    let squash = data(20 * MIB);
    let tree = verity::tree(&squash, &[1; 16], 4).unwrap();
    let mut rootfs = squash.clone();
    rootfs.extend_from_slice(&tree.bytes);
    let kernel = data(4096);
    let man = Manifest {
        format: 1,
        version: "0.1.0".into(),
        build: 1,
        commit: "bench".into(),
        channel: "development".into(),
        kernel_version: "6.18.59".into(),
        config_format: 1,
        kernel: Blob {
            size: kernel.len() as u64,
            sha256: package::sha256_hex(&kernel),
        },
        rootfs: Rootfs {
            size: rootfs.len() as u64,
            sha256: package::sha256_hex(&rootfs),
            data_blocks: tree.data_blocks,
            hash_blocks: tree.hash_blocks,
            salt: verity::hex(&[1; 16]),
            root_hash: verity::hex(&tree.root),
        },
    };
    let mut pkg = package::sign(&man, &key).unwrap();
    pkg.extend_from_slice(&kernel);
    pkg.extend_from_slice(&rootfs);
    let esp = data(20 * MIB);
    let config = data(5 * MIB);
    let index = install::index_of(
        &mut std::io::Cursor::new(&disk),
        &man,
        &[
            (install::PACKAGE, &pkg),
            ("ESP.IMG", &esp),
            ("CONFIG.IMG", &config),
        ],
        &[
            (
                "efi",
                Content::Image {
                    file: "ESP.IMG".into(),
                },
            ),
            ("rootfs-a", Content::Rootfs),
            (
                "config",
                Content::Filesystem {
                    file: "CONFIG.IMG".into(),
                },
            ),
        ],
    )
    .unwrap();
    let text = serde_json::to_vec(&index).unwrap();
    let sig = package::sign_detached(&text, &key).unwrap();
    let boot = vec![0u8; 4096];
    let all: [(&str, &[u8]); 6] = [
        (install::INDEX, &text),
        (install::SIGNATURE, &sig),
        (install::PACKAGE, &pkg),
        ("ESP.IMG", &esp),
        ("CONFIG.IMG", &config),
        ("EFIBOOT.IMG", &boot),
    ];
    let mut readers: Vec<&[u8]> = all.iter().map(|(_, d)| *d).collect();
    let mut files: Vec<iso::File<'_>> = all
        .iter()
        .zip(readers.iter_mut())
        .map(|((n, d), r)| iso::File {
            name: (*n).into(),
            size: d.len() as u64,
            data: r,
        })
        .collect();
    let mut out = Vec::new();
    iso::write(&mut out, &mut files, "EFIBOOT.IMG", 0).unwrap();
    (out, keys)
}

fn install_disk(c: &mut Criterion) {
    let mut g = c.benchmark_group("install");
    g.sample_size(10);
    let (img, keys) = medium();
    let dir = std::env::temp_dir().join(format!("crinstall-bench-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let disk_bytes = 160 * MIB as u64;
    let mut m = install::Medium::open(std::io::Cursor::new(img), &keys).unwrap();
    g.throughput(Throughput::Bytes(109 * MIB as u64));
    for (pipelined, parallel_verify) in [(false, false), (true, false), (false, true), (true, true)]
    {
        let name = format!(
            "{}_{}",
            if pipelined { "pipelined" } else { "sequential" },
            if parallel_verify {
                "parallel_verify"
            } else {
                "serial_verify"
            }
        );
        let o = install::Opts {
            keep_config: false,
            pipelined,
            parallel_verify,
            threads: 4,
        };
        g.bench_function(name, |b| {
            b.iter(|| {
                let f = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(dir.join("disk"))
                    .unwrap();
                f.set_len(disk_bytes).unwrap();
                install::install(&mut m, &f, disk_bytes, 512, &o, &mut |_, _| {}).unwrap()
            })
        });
    }
    let _ = std::fs::remove_dir_all(&dir);
    g.finish();
}

/// The test VM's `/config` (G1.6u), plus `graphs` series files.
fn vm_config(dir: &std::path::Path, series: usize) {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir.join("graphs")).unwrap();
    std::fs::write(dir.join("running.json"), vec![b'{'; 4859]).unwrap();
    std::fs::write(dir.join("running.json.prev"), vec![b'{'; 4608]).unwrap();
    std::fs::write(dir.join("rev-81.json"), data(10_753_090)).unwrap();
    for n in 0..60 {
        std::fs::write(dir.join(format!("rev-{n}.json")), vec![b'r'; 300]).unwrap();
    }
    std::fs::write(dir.join("journal-config.log"), vec![b'j'; 774]).unwrap();
    for n in 0..series {
        std::fs::write(
            dir.join(format!("graphs/interface-ether{n}.rrd")),
            vec![0u8; 672_984],
        )
        .unwrap();
    }
}

fn full_copy(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        if e.file_name() == "package" {
            continue;
        }
        if e.file_type().unwrap().is_dir() {
            full_copy(&e.path(), &to.join(e.file_name()));
        } else {
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
}

fn config_snapshot(c: &mut Criterion) {
    let mut g = c.benchmark_group("config_snapshot");
    g.sample_size(20);
    let dir = std::env::temp_dir().join(format!("crsnap-bench-{}", std::process::id()));
    vm_config(&dir, 6);
    g.bench_function("vm_full_copy_before", |b| {
        b.iter(|| {
            let to = dir.join("package/config-a");
            let _ = std::fs::remove_dir_all(&to);
            full_copy(&dir, &to);
            // As the old snapshot: its metadata written and synced.
            state::write_atomic(&to.join("snapshot.json"), b"{}").unwrap();
        })
    });
    let _ = std::fs::remove_dir_all(dir.join("package"));
    g.bench_function("vm_linked", |b| {
        b.iter(|| state::snapshot(&dir, SlotId::A, "1", 1).unwrap())
    });
    g.bench_function("vm_usage", |b| b.iter(|| state::usage(&dir)));
    vm_config(&dir, 4096);
    g.bench_function("usage_4096_series", |b| b.iter(|| state::usage(&dir)));
    let _ = std::fs::remove_dir_all(&dir);
    g.finish();
}

criterion_group!(benches, tree, copy, install_disk, config_snapshot);
criterion_main!(benches);
