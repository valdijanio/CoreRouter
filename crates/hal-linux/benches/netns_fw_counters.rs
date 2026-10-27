//! G2.1c — reading the counters of 10 000 firewall rules from the kernel:
//! one nfnetlink dump (`nft_counters::dump`, what the daemon does) against
//! `nft -j list table` and parsing its JSON (the obvious alternative),
//! inside a throwaway network namespace (no root, nothing reaches the
//! host):
//!
//! ```sh
//! COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- \
//!     cargo bench -p corerouter-hal-linux --bench netns_fw_counters
//! ```

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
    assert_eq!(
        names,
        ["lo"],
        "{ENV}=1 but this namespace is not fresh; refusing to touch it"
    );
    if !corerouter_hal_linux::nft::available() {
        eprintln!("skipped: the `nft` program is not installed");
        return;
    }
    let mut c = criterion::Criterion::default().configure_from_args();
    linux::counters(&mut c);
    c.final_summary();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::process::Command;

    use corerouter_firewall::sample::{m, rule};
    use corerouter_hal::Hal;
    use corerouter_hal_linux::LinuxHal;
    use corerouter_hal_linux::nft_counters::{NFPROTO_INET, dump};
    use corerouter_model::Config;
    use corerouter_model::firewall::Action;
    use criterion::{Criterion, Throughput};

    const N: u32 = 10_000;

    fn nft_json() -> usize {
        let out = Command::new("nft")
            .args(["-j", "list", "table", "inet", corerouter_firewall::TABLE])
            .output()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o.get("rule"))
            .filter(|r| {
                r["expr"]
                    .as_array()
                    .is_some_and(|e| e.iter().any(|x| x.get("counter").is_some()))
            })
            .count()
    }

    pub fn counters(c: &mut Criterion) {
        let mut cfg = Config::default();
        cfg.ip.firewall.filter = (0..N)
            .map(|i| {
                let src = format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff);
                rule(
                    i + 1,
                    "forward",
                    m(&[("src_address", &src)]).unwrap(),
                    Action::Drop,
                )
                .unwrap()
            })
            .collect::<Vec<_>>()
            .into();
        cfg.ip.firewall.next_rule_id = N;
        let mut hal = LinuxHal::new();
        hal.apply(&Config::default(), &cfg).unwrap();
        assert_eq!(
            dump(NFPROTO_INET, corerouter_firewall::TABLE)
                .unwrap()
                .len(),
            N as usize
        );
        assert_eq!(nft_json(), N as usize);

        let mut g = c.benchmark_group("netns_fw_counters");
        g.throughput(Throughput::Elements(u64::from(N)));
        g.sample_size(20);
        g.bench_function("10000 rules/nfnetlink dump", |b| {
            b.iter(|| {
                dump(NFPROTO_INET, corerouter_firewall::TABLE)
                    .unwrap()
                    .len()
            })
        });
        g.bench_function("10000 rules/nft -j + JSON", |b| b.iter(nft_json));
        g.finish();
        hal.apply(&cfg, &Config::default()).unwrap();
    }
}
