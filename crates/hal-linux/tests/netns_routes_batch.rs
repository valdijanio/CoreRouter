//! G4.3hh: the slow path's routes to `bng0` in batches
//! (`SlowTx::apply_routes`) against a real kernel, inside a throwaway
//! network namespace — no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test --release -p corerouter-hal-linux --test netns_routes_batch -- --nocapture
//! ```
//!
//! Every route lands (the kernel's count checked), a refused one is
//! reported by index without stopping the others, a removal of a route
//! already gone is not a refusal, and the batch and the one-by-one path
//! leave the same table. `ROUTES_BATCH_N=100000` prints the takeover's
//! numbers: 1 and 8 workers, batches and one request each.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::time::Instant;

use corerouter_hal_linux::pppoe_io::{RouteOp, SlowPath};

const ENV: &str = "COREROUTER_NETNS_TESTS";

fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!(
            "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` (cargo xtask netns)"
        );
        return false;
    }
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
    assert!(
        names.iter().all(|n| *n == "lo" || *n == "bng0"),
        "{ENV}=1 but this namespace has {names:?}; refusing to touch it"
    );
    true
}

/// Routes through `bng0` in the kernel (IPv4 and IPv6).
fn count() -> usize {
    let n = |fam: &str| {
        let out = Command::new("ip")
            .args([fam, "route", "show", "dev", "bng0"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.starts_with("fe80"))
            .count()
    };
    n("-4") + n("-6")
}

fn v4(i: usize) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(Ipv4Addr::new(100, 64, 0, 0)) + i as u32)
}

fn ops(range: std::ops::Range<usize>, add: bool) -> Vec<RouteOp> {
    range
        .map(|i| RouteOp {
            dst: IpAddr::V4(v4(i)),
            len: 32,
            add,
        })
        .collect()
}

/// The tests share `bng0`: one at a time.
fn lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn every_route_lands_and_leaves_and_the_count_is_checked() {
    if !in_netns() {
        return;
    }
    let _g = lock();
    let slow = SlowPath::open().unwrap();
    let mut tx = slow.sender().unwrap();
    let n = 20_000;
    let mut add = ops(0..n, true);
    // IPv6: a /64 and a delegated /56 of one session go in the same send.
    let p6: Ipv6Addr = "2001:db8:1::".parse().unwrap();
    let d6: Ipv6Addr = "2001:db8:100::".parse().unwrap();
    add.push(RouteOp {
        dst: IpAddr::V6(p6),
        len: 64,
        add: true,
    });
    add.push(RouteOp {
        dst: IpAddr::V6(d6),
        len: 56,
        add: true,
    });
    let a = tx.apply_routes(&add, false).unwrap();
    assert_eq!((a.done, a.retried, a.refused.len()), (n + 2, 0, 0));
    assert_eq!(count(), n + 2, "the kernel holds every one");
    // Again: an add is a replace, nothing refused, nothing doubled.
    let a = tx.apply_routes(&add, false).unwrap();
    assert_eq!((a.done, a.refused.len()), (n + 2, 0));
    assert_eq!(count(), n + 2);
    let del: Vec<RouteOp> = add.iter().map(|o| RouteOp { add: false, ..*o }).collect();
    let a = tx.apply_routes(&del, false).unwrap();
    assert_eq!((a.done, a.refused.len()), (n + 2, 0));
    assert_eq!(count(), 0);
    // A removal of a route already gone is not a refusal.
    let a = tx.apply_routes(&del, false).unwrap();
    assert_eq!((a.done, a.retried, a.refused.len()), (n + 2, 0, 0));
}

#[test]
fn a_refused_route_is_named_and_the_rest_still_land() {
    if !in_netns() {
        return;
    }
    let _g = lock();
    let slow = SlowPath::open().unwrap();
    let mut tx = slow.sender().unwrap();
    let mut add = ops(0..3000, true);
    // A /33 is no IPv4 prefix: the kernel says EINVAL, in the middle of a
    // send and at its very end (the one that asks for the ACK).
    add.insert(
        1500,
        RouteOp {
            dst: IpAddr::V4(v4(9_999)),
            len: 33,
            add: true,
        },
    );
    add.push(RouteOp {
        dst: IpAddr::V4(v4(9_998)),
        len: 40,
        add: true,
    });
    let a = tx.apply_routes(&add, false).unwrap();
    assert_eq!(a.done, 3000);
    assert_eq!(a.retried, 2, "tried once more, alone");
    assert_eq!(a.refused, vec![(1500, 22), (3001, 22)], "index and EINVAL");
    assert_eq!(count(), 3000);
    let del: Vec<RouteOp> = ops(0..3000, false);
    assert!(tx.apply_routes(&del, false).unwrap().refused.is_empty());
    assert_eq!(count(), 0);
}

#[test]
fn the_batch_and_one_by_one_leave_the_same_table() {
    if !in_netns() {
        return;
    }
    let _g = lock();
    let slow = SlowPath::open().unwrap();
    let mut tx = slow.sender().unwrap();
    let table = || {
        let out = Command::new("ip")
            .args(["-4", "route", "show", "dev", "bng0"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let add = ops(0..500, true);
    tx.apply_routes(&add, true).unwrap();
    let each = table();
    tx.apply_routes(&ops(0..500, false), true).unwrap();
    assert_eq!(count(), 0);
    tx.apply_routes(&add, false).unwrap();
    assert_eq!(table(), each, "same routes, same attributes");
    tx.apply_routes(&ops(0..500, false), false).unwrap();
}

/// The takeover's shape: `workers` threads, each its own sender and its
/// part of `n` routes, at the same time. Wall time of the slowest.
fn takeover(slow: &SlowPath, n: usize, workers: usize, one_by_one: bool) -> f64 {
    let mut parts: Vec<_> = (0..workers)
        .map(|w| {
            let tx = slow.sender().unwrap();
            let mine: Vec<RouteOp> = ops(0..n, true)
                .into_iter()
                .skip(w)
                .step_by(workers)
                .collect();
            (tx, mine)
        })
        .collect();
    let start = Instant::now();
    std::thread::scope(|s| {
        for (tx, mine) in &mut parts {
            std::thread::Builder::new()
                .name("route-worker".into())
                .spawn_scoped(s, move || {
                    let a = tx.apply_routes(mine, one_by_one).unwrap();
                    assert!(a.refused.is_empty());
                })
                .unwrap();
        }
    });
    let t = start.elapsed().as_secs_f64();
    assert_eq!(count(), n);
    let mut tx = slow.sender().unwrap();
    assert!(
        tx.apply_routes(&ops(0..n, false), false)
            .unwrap()
            .refused
            .is_empty()
    );
    t
}

#[test]
fn takeover_numbers() {
    if !in_netns() {
        return;
    }
    let Some(n) = std::env::var("ROUTES_BATCH_N")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    else {
        eprintln!("skipped: ROUTES_BATCH_N=<routes> prints the numbers");
        return;
    };
    let _g = lock();
    let slow = SlowPath::open().unwrap();
    for (workers, each) in [(1, true), (8, true), (1, false), (8, false)] {
        let mut best = f64::MAX;
        for _ in 0..3 {
            best = best.min(takeover(&slow, n, workers, each));
        }
        eprintln!(
            "{n} routes, {workers} worker(s), {}: {:.1} ms ({:.2} µs per route)",
            if each {
                "one request each (rtnetlink)"
            } else {
                "batches"
            },
            best * 1e3,
            best * 1e6 / n as f64
        );
    }
}
