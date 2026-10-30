//! G1.6u: an update on a small `/config` (the 56 MB of the test VM that
//! filled up). Each case runs in a mount namespace of its own (`unshare
//! --user --map-root-user --mount`, no root) with `/config` on a tmpfs of
//! 3 MiB, so "No space left on device" is the kernel's, not a simulation.
//! The test binary re-runs itself inside the namespace, hence a binary of
//! its own (not `tests/it`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use corerouter_sysupdate::ab::{Opts, Platform};
use corerouter_sysupdate::package::{self, Blob, Key, Manifest, Rootfs};
use corerouter_sysupdate::state::{self, Confirm, Reason, State};
use corerouter_sysupdate::verity;

const INNER: &str = "COREROUTER_CONFIG_FULL_INNER";
const TMPFS: &str = "size=3m";

/// Runs test `name` again inside a fresh user + mount namespace; `false`
/// when this is that run (go on with the test).
fn outer(name: &str) -> bool {
    if std::env::var_os(INNER).is_some() {
        return false;
    }
    let exe = std::env::current_exe().unwrap();
    let out = Command::new("unshare")
        .args(["--user", "--map-root-user", "--mount", "--"])
        .arg(&exe)
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(INNER, "1")
        .output();
    match out {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            if err.contains("unshare failed") || err.contains("Operation not permitted") {
                eprintln!(
                    "skipped: no unprivileged user namespace here ({})",
                    err.trim()
                );
            } else {
                panic!(
                    "inside the namespace:\n{}\n{err}",
                    String::from_utf8_lossy(&o.stdout)
                );
            }
        }
        Err(e) => eprintln!("skipped: cannot run unshare: {e}"),
    }
    true
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sysupdate-full-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A `/config` of 3 MiB (tmpfs) under `dir`.
fn small_config(dir: &Path) -> PathBuf {
    let c = dir.join("config");
    std::fs::create_dir_all(&c).unwrap();
    let st = Command::new("mount")
        .args(["-t", "tmpfs", "-o", TMPFS, "none"])
        .arg(&c)
        .status()
        .unwrap();
    assert!(st.success(), "mount tmpfs");
    c
}

fn package(dir: &Path, key: &[u8], version: &str, build: u64) -> PathBuf {
    let kernel = vec![7u8; 100_000];
    let data: Vec<u8> = (0..20 * 4096u32).map(|i| (i % 251) as u8).collect();
    let salt = vec![1, 2, 3];
    let tree = verity::tree(&data, &salt, 1).unwrap();
    let mut rootfs = data;
    rootfs.extend_from_slice(&tree.bytes);
    let m = Manifest {
        format: 1,
        version: version.into(),
        build,
        commit: "c".into(),
        channel: "stable".into(),
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
            salt: verity::hex(&salt),
            root_hash: verity::hex(&tree.root),
        },
    };
    let mut out = package::sign(&m, key).unwrap();
    out.extend_from_slice(&kernel);
    out.extend_from_slice(&rootfs);
    let p = dir.join(format!("{version}.crpkg"));
    std::fs::write(&p, out).unwrap();
    p
}

fn opts() -> Opts {
    Opts {
        reason: Reason::Update,
        confirm: Confirm::Auto,
        timeout_s: 300,
        tuning: Vec::new(),
        mgmt: Vec::new(),
        now: 100,
        pipelined: false,
        threads: 1,
        config_format: 1,
        drill: false,
    }
}

/// The router: slots outside the tmpfs, `/config` on it, the factory
/// image in slot A.
fn router(dir: &Path, config: &Path) -> (Platform, Vec<u8>) {
    let key = package::generate_key().unwrap();
    let keys = vec![Key::from_hex(&package::public_hex(&key).unwrap()).unwrap()];
    std::fs::write(config.join("running.json"), r#"{"format_version":1}"#).unwrap();
    let mut p = Platform::lab(&dir.join("box"), config, keys, 2 << 20).unwrap();
    p.lab_seed("1.0", 10).unwrap();
    (p, key)
}

fn free(config: &Path) -> u64 {
    state::free_bytes(config).unwrap()
}

/// The test VM's case: a big revision in the history (1.2 MB here, 10.7 MB
/// there) and the graphs. A copy of it did not fit; linked, it does, and
/// the graphs stay out.
#[test]
fn a_big_history_fits_because_it_is_linked() {
    if outer("a_big_history_fits_because_it_is_linked") {
        return;
    }
    let dir = tmp("history");
    let config = small_config(&dir);
    let (p, key) = router(&dir, &config);
    std::fs::write(config.join("rev-81.json"), vec![b'r'; 1_200_000]).unwrap();
    std::fs::create_dir_all(config.join("graphs")).unwrap();
    std::fs::write(
        config.join("graphs/interface-ether3.rrd"),
        vec![0u8; 600_000],
    )
    .unwrap();
    let before = free(&config);
    assert!(
        before < 2 * 1_800_000,
        "a full copy would not fit: {before} free"
    );
    let pkg = package(&dir, &key, "1.1", 20);
    p.install(&pkg, false, &opts(), &mut |_, _| {}).unwrap();
    let snap = config.join("package/config-a");
    assert!(snap.join("rev-81.json").exists());
    assert!(!snap.join("graphs").exists());
    let used = before - free(&config);
    assert!(used < 256 << 10, "the snapshot took {used} bytes");
    let s = p.status(&State::load(&p.state_dir()).0);
    assert_eq!(s["snapshots"][0]["name"], "config-a");
    assert!(
        s["snapshots"][0]["own_bytes"].as_u64().unwrap() < 64 << 10,
        "{s}"
    );
    assert!(s["config_space"]["free"].as_u64().is_some());
    assert_eq!(s["config_space"]["usage"][0]["path"], "rev-81.json");
}

/// What must be copied does not fit: refused before the slot is written,
/// with the numbers and the biggest entries; nothing is left behind.
#[test]
fn no_room_is_refused_before_anything_is_written() {
    if outer("no_room_is_refused_before_anything_is_written") {
        return;
    }
    let dir = tmp("refused");
    let config = small_config(&dir);
    let (p, key) = router(&dir, &config);
    std::fs::write(config.join("journal-config.log"), vec![b'j'; 1_600_000]).unwrap();
    let before = free(&config);
    let pkg = package(&dir, &key, "1.1", 20);
    let e = p.install(&pkg, false, &opts(), &mut |_, _| {}).unwrap_err();
    assert!(e.contains("needs") && e.contains("is free"), "{e}");
    assert!(e.contains("journal-config.log"), "names the biggest: {e}");
    assert!(e.contains("system.package.snapshot.remove"), "{e}");
    assert_eq!(free(&config), before, "nothing written to /config");
    assert!(!config.join("package/config-a.new").exists());
    let s = p.status(&State::load(&p.state_dir()).0);
    assert!(s["trial"].is_null());
    assert_eq!(
        s["slots"][1]["state"], "empty",
        "slot B was not touched: {s}"
    );
}

/// The test VM as an older build left it: a partial `config-a.new` from a
/// copy cut by ENOSPC, `/config` at 0 bytes free. From far: the dry run
/// says what goes, the removal frees it, the update then goes through.
#[test]
fn a_full_config_is_recovered_from_far() {
    if outer("a_full_config_is_recovered_from_far") {
        return;
    }
    let dir = tmp("recover");
    let config = small_config(&dir);
    let (p, key) = router(&dir, &config);
    std::fs::write(config.join("rev-81.json"), vec![b'r'; 1_000_000]).unwrap();
    // What the old snapshot did: copy until the kernel says no.
    let partial = config.join("package/config-a.new");
    std::fs::create_dir_all(&partial).unwrap();
    let mut n = 0;
    loop {
        let r = std::fs::write(partial.join(format!("rev-{n}.json")), vec![b'c'; 256 << 10]);
        if let Err(e) = r {
            assert_eq!(e.raw_os_error(), Some(28), "ENOSPC: {e}");
            break;
        }
        n += 1;
    }
    assert!(free(&config) < 256 << 10);
    let s = p.status(&State::load(&p.state_dir()).0);
    assert_eq!(s["partials"][0]["name"], "config-a.new", "{s}");
    let r = p.remove_snapshots(&[], false, true).unwrap();
    assert_eq!(r["dry_run"], true);
    assert_eq!(r["snapshots"][0]["name"], "config-a.new");
    assert!(partial.exists(), "a dry run deletes nothing");
    let r = p.remove_snapshots(&[], false, false).unwrap();
    assert!(r["freed"].as_u64().unwrap() > 1 << 20, "{r}");
    assert!(!partial.exists());
    let pkg = package(&dir, &key, "1.1", 20);
    p.install(&pkg, false, &opts(), &mut |_, _| {}).unwrap();
    assert!(config.join("package/config-a/rev-81.json").exists());
    assert!(
        config.join("running.json").exists(),
        "the configuration was never touched"
    );
}
