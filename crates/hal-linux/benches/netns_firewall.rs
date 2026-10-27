//! G2.8 — the firewall's table over nfnetlink against the `nft` program it
//! replaced, in a throwaway network namespace (no root, nothing reaches the
//! host):
//!
//! ```sh
//! COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- \
//!     cargo bench -p corerouter-hal-linux --bench netns_firewall
//! ```
//!
//! "nft" is what a commit did before G2.8: `nft -j list table` (to keep
//! the dynamic entries) and `nft -f` of the whole ruleset; a dynamic entry
//! was one `nft` process each (`address-list.add timeout=…`), and many at
//! once one `nft -f` script.
//!
//! - `load/N`: N rules into an empty table;
//! - `change_one/N`: one rule changed in the middle of N;
//! - `dynamic_add/N`: N timed address-list entries;
//! - `dynamic_read/N`: reading N dynamic entries back (a table replace).

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
        eprintln!("skipped: the `nft` program is not installed (the comparison needs it)");
        return;
    }
    let mut c = criterion::Criterion::default().configure_from_args();
    linux::rules(&mut c);
    linux::dynamic(&mut c);
    c.final_summary();
}

#[cfg(target_os = "linux")]
pub mod linux {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use corerouter_firewall::sample::{act, m, rule};
    use corerouter_hal_linux::{firewall, nft};
    use corerouter_model::Config;
    use corerouter_model::cow_list::CowList;
    use corerouter_model::firewall::{AddressListEntry, DynamicAddress, FirewallRule};
    use criterion::{BenchmarkId, Criterion, SamplingMode, Throughput};

    /// The old commit: read the dynamic entries (`nft -j`), replace all.
    fn old_commit(cfg: &Config) {
        let out = Command::new("nft")
            .args(["-j", "list", "table", "inet", "corerouter"])
            .output()
            .unwrap();
        let _: Option<serde_json::Value> = serde_json::from_slice(&out.stdout).ok();
        nft::run(&corerouter_firewall::script(cfg, &[])).unwrap();
    }

    /// Rule `i` of a varied ruleset: addresses, ports, lists, states.
    fn nth(i: u32) -> FirewallRule {
        let src = format!("10.{}.{}.0/24", (i >> 8) & 0xff, i & 0xff);
        let pairs: Vec<(&str, &str)> = match i % 4 {
            0 => vec![
                ("src_address", src.as_str()),
                ("protocol", "tcp"),
                ("dst_port", "22,80,443"),
            ],
            1 => vec![("src_address_list", "blocked"), ("connection_state", "new")],
            2 => vec![
                ("dst_address", src.as_str()),
                ("protocol", "udp"),
                ("dst_port", "1000-2000"),
            ],
            _ => vec![
                ("in_interface", "ether1"),
                ("connection_state", "established,related"),
            ],
        };
        let a = if i.is_multiple_of(3) {
            r#"{"type":"accept"}"#
        } else {
            r#"{"type":"drop"}"#
        };
        rule(i + 1, "forward", m(&pairs).unwrap(), act(a).unwrap()).unwrap()
    }

    fn ruleset(n: u32) -> Config {
        let mut cfg = Config::default();
        cfg.ip.firewall.address_lists.push(AddressListEntry {
            id: corerouter_model::ItemId(1),
            list: "blocked".parse().unwrap(),
            address: "203.0.113.0/24".parse().unwrap(),
            disabled: false,
            comment: String::new(),
        });
        cfg.ip.firewall.filter = CowList::from((0..n).map(nth).collect::<Vec<_>>());
        cfg.ip.firewall.next_rule_id = n + 1;
        cfg
    }

    /// `cfg` with the middle rule's action flipped.
    fn one_changed(cfg: &Config, n: u32) -> Config {
        let mut c = cfg.clone();
        let mut list: Vec<FirewallRule> = c.ip.firewall.filter.iter().cloned().collect();
        let mid = (n / 2) as usize;
        list[mid].action =
            act(r#"{"type":"reject","reject_with":"icmp-admin-prohibited"}"#).unwrap();
        c.ip.firewall.filter = CowList::from(list);
        c
    }

    fn flat(g: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
        g.sampling_mode(SamplingMode::Flat)
            .sample_size(10)
            .warm_up_time(Duration::from_millis(300));
    }

    pub fn rules(c: &mut Criterion) {
        let empty = Config::default();
        let mut g = c.benchmark_group("netns_firewall");
        flat(&mut g);
        for n in [100u32, 1000, 10_000] {
            let cfg = ruleset(n);
            g.throughput(Throughput::Elements(u64::from(n)));
            g.bench_with_input(BenchmarkId::new("load/nfnetlink", n), &cfg, |b, cfg| {
                b.iter_custom(|iters| {
                    let mut spent = Duration::ZERO;
                    for _ in 0..iters {
                        firewall::remove().unwrap();
                        let t = Instant::now();
                        firewall::apply(&empty, cfg).unwrap();
                        spent += t.elapsed();
                    }
                    spent
                })
            });
            g.bench_with_input(BenchmarkId::new("load/nft", n), &cfg, |b, cfg| {
                b.iter_custom(|iters| {
                    let mut spent = Duration::ZERO;
                    for _ in 0..iters {
                        firewall::remove().unwrap();
                        let t = Instant::now();
                        old_commit(cfg);
                        spent += t.elapsed();
                    }
                    spent
                })
            });
            let changed = one_changed(&cfg, n);
            firewall::apply(&empty, &cfg).unwrap();
            g.throughput(Throughput::Elements(1));
            g.bench_with_input(BenchmarkId::new("change_one/nfnetlink", n), &n, |b, _| {
                b.iter_custom(|iters| {
                    let mut spent = Duration::ZERO;
                    for _ in 0..iters {
                        let t = Instant::now();
                        let d = firewall::apply(&cfg, &changed).unwrap();
                        spent += t.elapsed();
                        assert!(!d.replaced);
                        firewall::apply(&changed, &cfg).unwrap();
                    }
                    spent
                })
            });
            g.bench_with_input(BenchmarkId::new("change_one/nft", n), &n, |b, _| {
                b.iter_custom(|iters| {
                    let mut spent = Duration::ZERO;
                    for _ in 0..iters {
                        let t = Instant::now();
                        old_commit(&changed);
                        spent += t.elapsed();
                        old_commit(&cfg);
                    }
                    spent
                })
            });
        }
        g.finish();
        firewall::remove().unwrap();
    }

    fn entries(n: u32) -> Vec<DynamicAddress> {
        (0..n)
            .map(|i| DynamicAddress {
                list: "flood".parse().unwrap(),
                // Every other address: no two entries touch.
                address: std::net::Ipv4Addr::from(0x0a00_0000 + i * 2)
                    .to_string()
                    .parse()
                    .unwrap(),
                timeout_secs: 3600,
                added_by_rule: false,
            })
            .collect()
    }

    /// `nft -f` at its best: one `add element` with every entry. (The old
    /// `address_list_dynamic_many` wrote one `add element` line per entry,
    /// which with 100 000 entries does not even fit the netlink send
    /// buffer of a user namespace: "Message too long".)
    fn old_many(ds: &[DynamicAddress]) {
        let items: Vec<String> = ds
            .iter()
            .map(|d| format!("{} timeout {}s", d.address, d.timeout_secs))
            .collect();
        nft::run(&format!(
            "add table inet corerouter\nadd set inet corerouter al4_flood {{ type ipv4_addr; flags interval, timeout; auto-merge; }}\nadd element inet corerouter al4_flood {{ {} }}\n",
            items.join(", ")
        ))
        .unwrap();
    }

    /// The old `address_list_dynamic`: one `nft` process per entry.
    fn old_one(d: &DynamicAddress) {
        nft::run(&format!(
            "add table inet corerouter\nadd set inet corerouter al4_flood {{ type ipv4_addr; flags interval, timeout; auto-merge; }}\nadd element inet corerouter al4_flood {{ {} timeout {}s }}\n",
            d.address, d.timeout_secs
        ))
        .unwrap();
    }

    pub fn dynamic(c: &mut Criterion) {
        let mut g = c.benchmark_group("netns_firewall");
        flat(&mut g);
        for n in [1000u32, 100_000] {
            let ds = entries(n);
            let ops: Vec<(bool, &DynamicAddress)> = ds.iter().map(|d| (true, d)).collect();
            g.throughput(Throughput::Elements(u64::from(n)));
            g.bench_with_input(BenchmarkId::new("dynamic_add/nfnetlink", n), &n, |b, _| {
                b.iter_custom(|iters| {
                    let mut spent = Duration::ZERO;
                    for _ in 0..iters {
                        firewall::remove().unwrap();
                        let t = Instant::now();
                        firewall::apply_dynamic(&ops).unwrap();
                        spent += t.elapsed();
                    }
                    spent
                })
            });
            g.bench_with_input(BenchmarkId::new("dynamic_add/nft script", n), &n, |b, _| {
                b.iter_custom(|iters| {
                    let mut spent = Duration::ZERO;
                    for _ in 0..iters {
                        firewall::remove().unwrap();
                        let t = Instant::now();
                        old_many(&ds);
                        spent += t.elapsed();
                    }
                    spent
                })
            });
            if n <= 1000 {
                g.bench_with_input(
                    BenchmarkId::new("dynamic_add/nft per entry", n),
                    &n,
                    |b, _| {
                        b.iter_custom(|iters| {
                            let mut spent = Duration::ZERO;
                            for _ in 0..iters {
                                firewall::remove().unwrap();
                                let t = Instant::now();
                                for d in &ds {
                                    old_one(d);
                                }
                                spent += t.elapsed();
                            }
                            spent
                        })
                    },
                );
            }
            // Reading them back (what a table replace does first).
            firewall::remove().unwrap();
            firewall::apply_dynamic(&ops).unwrap();
            assert_eq!(firewall::dynamic().unwrap().len(), n as usize);
            g.bench_with_input(BenchmarkId::new("dynamic_read/nfnetlink", n), &n, |b, _| {
                b.iter(|| firewall::dynamic().unwrap().len())
            });
            g.bench_with_input(BenchmarkId::new("dynamic_read/nft -j", n), &n, |b, _| {
                b.iter(|| {
                    let out = Command::new("nft")
                        .args(["-j", "list", "table", "inet", "corerouter"])
                        .output()
                        .unwrap();
                    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
                    v["nftables"].as_array().map_or(0, Vec::len)
                })
            });
        }
        g.finish();
        firewall::remove().unwrap();
    }
}
