//! G0.9 — `LinuxHal::apply` of N addresses and routes (rtnetlink) and filter
//! rules (`nft -f`, one transaction) against a real kernel, inside a throwaway
//! network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- \
//!     cargo bench -p corerouter-hal-linux --bench netns_apply
//! ```
//!
//! `cargo xtask bench` does exactly that, and skips with a warning where user
//! namespaces are not allowed. Without the variable the benchmark prints
//! "skipped" and exits; with it, it still refuses to run unless the namespace
//! holds nothing but `lo` (the guard of `tests/netns.rs`). Each iteration
//! applies the change from the base config and then undoes it, untimed.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(target_os = "linux")]
#[path = "../../hal/benches/common/mod.rs"]
mod common;

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("skipped: netlink and nftables are Linux-only");
}

#[cfg(target_os = "linux")]
fn main() {
    if !linux::ready() {
        return;
    }
    let mut c = criterion::Criterion::default().configure_from_args();
    linux::apply(&mut c);
    c.final_summary();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::hint::black_box;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use corerouter_hal::Hal;
    use corerouter_hal_linux::{LinuxHal, nft};
    use corerouter_model::Config;
    use criterion::{BenchmarkId, Criterion, SamplingMode, Throughput};

    use crate::common;

    const ENV: &str = "COREROUTER_NETNS_BENCH";
    const PORT: &str = "bench0";

    type Build = fn(&Config, usize) -> Config;

    /// True inside a fresh namespace with the variable set; panics if the
    /// variable is set anywhere else.
    pub fn ready() -> bool {
        if std::env::var_os(ENV).is_none_or(|v| v != "1") {
            eprintln!(
                "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` \
                 (cargo xtask bench)"
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
            names == ["lo"],
            "{ENV}=1 but this namespace has {names:?}, not just lo; refusing to touch it"
        );
        let made = Command::new("ip")
            .args(["link", "add", PORT, "type", "dummy"])
            .status()
            .unwrap();
        assert!(made.success(), "ip link add {PORT} type dummy failed");
        true
    }

    pub fn apply(c: &mut Criterion) {
        let mut hal = LinuxHal::new();
        let base = common::base(PORT);
        hal.apply(&Config::default(), &base).unwrap();
        let mut kinds: Vec<(&str, Build)> = vec![
            ("addresses", |b, n| common::addresses(b, PORT, n)),
            ("routes", common::routes),
        ];
        if nft::available() {
            kinds.push(("filter_rules", common::filter_rules));
        } else {
            eprintln!("skipped filter_rules: the `nft` program (nftables) is not installed");
        }
        let mut g = c.benchmark_group("hal_linux_apply");
        // One apply of 1000 items is milliseconds: few, equal samples.
        g.sampling_mode(SamplingMode::Flat)
            .sample_size(10)
            .warm_up_time(Duration::from_millis(500));
        for (kind, build) in kinds {
            for n in common::SIZES {
                let to = build(&base, n);
                g.throughput(Throughput::Elements(n as u64));
                g.bench_with_input(BenchmarkId::new(kind, n), &to, |b, to| {
                    b.iter_custom(|iters| {
                        let mut spent = Duration::ZERO;
                        for _ in 0..iters {
                            let t = Instant::now();
                            hal.apply(black_box(&base), black_box(to)).unwrap();
                            spent += t.elapsed();
                            hal.apply(to, &base).unwrap();
                        }
                        spent
                    });
                });
            }
        }
        g.finish();
    }
}
