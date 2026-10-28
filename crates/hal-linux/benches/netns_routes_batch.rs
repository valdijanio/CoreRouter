//! G4.3hh — the slow path's routes to `bng0`: 10 000 `/32` added and
//! removed in batches (`RouteBatch`, many per `sendmsg`, ACK only on the
//! last) against one request each on the `rtnetlink` connection (the path
//! before), inside a throwaway network namespace (no root):
//!
//! ```sh
//! COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- \
//!     cargo bench -p corerouter-hal-linux --bench netns_routes_batch
//! ```
//!
//! A takeover of 100 000 sessions with 1 and 8 threads at once is in
//! `tests/netns_routes_batch.rs` (`ROUTES_BATCH_N=100000`).

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("skipped: netlink is Linux-only");
}

#[cfg(target_os = "linux")]
fn main() {
    use std::process::Command;
    const ENV: &str = "COREROUTER_NETNS_BENCH";
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!(
            "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` (cargo xtask bench)"
        );
        return;
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
        "{ENV}=1 but this namespace is not fresh ({names:?}); refusing to touch it"
    );
    let mut c = criterion::Criterion::default().configure_from_args();
    linux::routes(&mut c);
    c.final_summary();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use corerouter_hal_linux::pppoe_io::{RouteOp, SlowPath};
    use criterion::{Criterion, Throughput};

    const N: usize = 10_000;

    fn ops(add: bool) -> Vec<RouteOp> {
        (0..N)
            .map(|i| RouteOp {
                dst: IpAddr::V4(Ipv4Addr::from(
                    u32::from(Ipv4Addr::new(100, 64, 0, 0)) + i as u32,
                )),
                len: 32,
                add,
            })
            .collect()
    }

    pub fn routes(c: &mut Criterion) {
        let slow = SlowPath::open().unwrap();
        let mut tx = slow.sender().unwrap();
        let (add, del) = (ops(true), ops(false));
        let mut g = c.benchmark_group("slow_path_routes");
        g.throughput(Throughput::Elements(N as u64));
        g.sample_size(10);
        g.measurement_time(Duration::from_secs(10));
        for (name, each) in [("batch", false), ("one_by_one", true)] {
            g.bench_function(format!("add_{N}_{name}"), |b| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let t = Instant::now();
                        let a = tx.apply_routes(&add, each).unwrap();
                        total += t.elapsed();
                        assert_eq!(a.done, N);
                        tx.apply_routes(&del, false).unwrap();
                    }
                    total
                });
            });
        }
        g.finish();
    }
}
