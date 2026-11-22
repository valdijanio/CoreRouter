//! G2.3b — loading the CGNAT table: nfnetlink from Rust (`nfnl`) against
//! the `nft` program, for 1 Ki, 16 Ki and 64 Ki subscribers, and one
//! subscriber more on a 64 Ki table (the incremental change). Inside a
//! throwaway network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- \
//!     cargo bench -p corerouter-hal-linux --bench netns_cgnat
//! ```
//!
//! Both sides load the same table (`cgnat::table`; `nft` gets
//! `cgnat::nft_script`, its spelling of the same objects) in one
//! transaction that replaces the previous one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

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
    linux::load(&mut c);
    c.final_summary();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use corerouter_firewall::cgnat::{nft_script, table};
    use corerouter_hal_linux::{nfnl, nft};
    use corerouter_model::cgnat::{Cgnat, Pool};
    use criterion::{BenchmarkId, Criterion, SamplingMode, Throughput};

    const ENV: &str = "COREROUTER_NETNS_BENCH";

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
            "{ENV}=1 but this namespace has {names:?}; refusing to touch it"
        );
        true
    }

    /// `n` subscribers (a power of two) from 100.64.0.0, 1000 ports each
    /// (64 per public address); `cut_last` leaves the last one out.
    fn cgnat(n: u32, cut_last: bool) -> Cgnat {
        let last = 0x6440_0000u32 + n - 1 - u32::from(cut_last);
        let inside = format!("100.64.0.0-{}", std::net::Ipv4Addr::from(last));
        let public = (n / 64).max(1);
        let pbits = 32 - public.trailing_zeros();
        let pool: Pool = serde_json::from_value(serde_json::json!({
            "id": "*1", "name": "bench", "inside": [inside],
            "outside": [format!("198.18.0.0/{pbits}")], "ports_per_subscriber": 1000,
        }))
        .unwrap();
        Cgnat {
            pools: vec![pool],
            ..Cgnat::default()
        }
    }

    fn netlink(c: &Cgnat) {
        let t = table(c).unwrap();
        nfnl::apply(nfnl::replace(&t, 1), "bench").unwrap();
    }

    pub fn load(c: &mut Criterion) {
        let have_nft = nft::available();
        let mut g = c.benchmark_group("cgnat_load");
        g.sampling_mode(SamplingMode::Flat)
            .sample_size(10)
            .warm_up_time(Duration::from_millis(500));
        for n in [1024u32, 16_384, 65_536] {
            let cfg = cgnat(n, false);
            let script = nft_script(&cfg);
            g.throughput(Throughput::Elements(u64::from(n)));
            g.bench_with_input(BenchmarkId::new("netlink", n), &cfg, |b, cfg| {
                b.iter(|| netlink(cfg));
            });
            if have_nft {
                g.bench_with_input(BenchmarkId::new("nft", n), &script, |b, s| {
                    b.iter(|| nft::run(s).unwrap());
                });
            }
        }
        g.finish();

        // One subscriber more on a 64 Ki table.
        let (before, after) = (cgnat(65_536, true), cgnat(65_536, false));
        let (tb, ta) = (table(&before).unwrap(), table(&after).unwrap());
        let added = ta
            .sets
            .iter()
            .find(|s| s.name == "d_1")
            .and_then(|s| s.elements.last())
            .cloned()
            .unwrap();
        let mut g = c.benchmark_group("cgnat_one_more");
        g.sampling_mode(SamplingMode::Flat)
            .sample_size(10)
            .warm_up_time(Duration::from_millis(500));
        g.bench_function("netlink", |b| {
            b.iter_custom(|iters| {
                let mut spent = Duration::ZERO;
                for _ in 0..iters {
                    netlink(&before);
                    let t0 = Instant::now();
                    // The diff included: that is what a commit pays.
                    let batch = nfnl::update(&tb, &ta, 1).unwrap();
                    nfnl::apply(batch, "bench").unwrap();
                    spent += t0.elapsed();
                }
                spent
            });
        });
        if have_nft {
            let corerouter_firewall::program::Value::Addr(sub) = added.key else {
                panic!()
            };
            let Some(corerouter_firewall::program::Value::AddrPortRange(public, lo, hi)) =
                added.data
            else {
                panic!()
            };
            let line =
                format!("add element ip corerouter_cgnat d_1 {{ {sub} : {public} . {lo}-{hi} }}\n");
            g.bench_function("nft", |b| {
                b.iter_custom(|iters| {
                    let mut spent = Duration::ZERO;
                    for _ in 0..iters {
                        netlink(&before);
                        let t0 = Instant::now();
                        nft::run(&line).unwrap();
                        spent += t0.elapsed();
                    }
                    spent
                });
            });
        }
        g.finish();
    }
}
