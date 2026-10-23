//! System › Tuning (G1.26) against a real kernel, inside a throwaway
//! network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_tuning
//! ```
//!
//! A namespace has its own copy of the per-namespace parameters (ECMP
//! hash, rp_filter, forwarding, TCP of the control plane), which `apply`
//! writes and puts back; the host-wide ones (`netdev_budget`, neighbor
//! tables) are absent and the read-only ones (`rmem_max`, `kernel.panic`)
//! refuse, and either way the whole change is rolled back. `netdevsim`
//! cannot help here: creating one needs root in the host's namespace.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;
use std::sync::{Mutex, OnceLock};

use corerouter_hal::Hal;
use corerouter_hal_linux::LinuxHal;
use corerouter_model::Config;
use corerouter_model::tuning::PARAMS;

const ENV: &str = "COREROUTER_NETNS_TESTS";

/// The tests share the namespace: one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!(
            "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` \
             (cargo xtask netns)"
        );
        return false;
    }
    static FRESH: OnceLock<Result<(), String>> = OnceLock::new();
    let fresh = FRESH.get_or_init(|| {
        let out = Command::new("ip")
            .args(["-o", "link", "show"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let names: Vec<&str> = text
            .lines()
            .filter_map(|l| l.split(':').nth(1))
            .map(str::trim)
            .collect();
        if names == ["lo"] {
            Ok(())
        } else {
            Err(format!(
                "{ENV}=1 but this network namespace has {names:?}, not just lo; refusing to \
                 touch it (run inside `unshare --user --map-root-user --net`)"
            ))
        }
    });
    if let Err(e) = fresh {
        panic!("{e}");
    }
    true
}

fn read(name: &str) -> Option<i64> {
    let path = format!("/proc/sys/{}", name.replace('.', "/"));
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn with(values: &[(&str, i64)]) -> Config {
    let mut c = Config::default();
    for (n, v) in values {
        c.system.tuning.sysctl.insert((*n).to_owned(), *v);
    }
    c
}

const HASH: &str = "net.ipv4.fib_multipath_hash_policy";
const HASH6: &str = "net.ipv6.fib_multipath_hash_policy";
const SOMAXCONN: &str = "net.core.somaxconn";

#[test]
fn per_namespace_parameters_are_written_and_put_back() {
    if !in_netns() {
        return;
    }
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut hal = LinuxHal::new();
    let names: Vec<&str> = PARAMS.iter().map(|p| p.name).collect();
    let now = hal.sysctls(&names).unwrap();
    assert_eq!(now[HASH], read(HASH));
    assert!(now[SOMAXCONN].is_some());
    assert_eq!(
        now["net.core.netdev_budget"], None,
        "host-wide: not in a namespace"
    );

    let (hash, hash6, somax) = (
        read(HASH).unwrap(),
        read(HASH6).unwrap(),
        read(SOMAXCONN).unwrap(),
    );
    let base = Config::default();
    let tuned = with(&[(HASH, 1), (HASH6, 1), (SOMAXCONN, somax + 1024)]);
    hal.apply(&base, &tuned).unwrap();
    assert_eq!(read(HASH), Some(1));
    assert_eq!(read(HASH6), Some(1));
    assert_eq!(read(SOMAXCONN), Some(somax + 1024));

    // Changing one keeps the others; taking all out restores the originals.
    let more = with(&[(HASH, 2), (HASH6, 1), (SOMAXCONN, somax + 1024)]);
    hal.apply(&tuned, &more).unwrap();
    assert_eq!(read(HASH), Some(2));
    hal.apply(&more, &base).unwrap();
    assert_eq!(read(HASH), Some(hash));
    assert_eq!(read(HASH6), Some(hash6));
    assert_eq!(read(SOMAXCONN), Some(somax));
}

#[test]
fn a_refused_parameter_rolls_the_whole_change_back() {
    if !in_netns() {
        return;
    }
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut hal = LinuxHal::new();
    let hash = read(HASH).unwrap();
    let base = Config::default();
    // Read-only in a namespace other than the host's.
    let bad = with(&[(HASH, 1), ("net.core.rmem_max", 8 << 20)]);
    let err = hal.apply(&base, &bad).unwrap_err().to_string();
    assert!(err.contains("read-only here"), "{err}");
    assert_eq!(read(HASH), Some(hash), "rolled back");
    // Absent in a namespace.
    let absent = with(&[(HASH, 1), ("net.core.netdev_budget", 600)]);
    let err = hal.apply(&base, &absent).unwrap_err().to_string();
    assert!(err.contains("does not have it"), "{err}");
    assert_eq!(read(HASH), Some(hash));
}

#[test]
fn reads_the_machine_and_the_counters() {
    if !in_netns() {
        return;
    }
    let mut hal = LinuxHal::new();
    let si = hal.system_info().unwrap();
    assert!(si.cpus > 0 && si.mem_kib > 0, "{si:?}");
    assert!(si.kernel_version().is_some(), "{}", si.kernel);
    let k = hal.kernel_stats().unwrap();
    assert!(
        !k.softnet.is_empty(),
        "softnet_stat is per host, readable here"
    );
}
