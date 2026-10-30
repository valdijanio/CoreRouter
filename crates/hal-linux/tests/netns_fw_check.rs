//! G1.3g: the firewall checked against a real kernel without loading it
//! (a batch with no `BATCH_END`, as `nft --check`), inside a throwaway
//! network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_fw_check
//! ```
//!
//! - every rule the kernel refuses is named by its id, not only the first;
//! - a refusal found by the whole-table validation (a `dst-nat` in the
//!   `srcnat` hook, `nft_nat_validate`) is named too;
//! - nothing reaches the ruleset in use, and the next commit still goes
//!   from what the last one loaded (the generation did not move).
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

use corerouter_firewall::sample::{act, rule, sample};
use corerouter_hal::{Hal, RefusedItem};
use corerouter_hal_linux::{LinuxHal, nft};
use corerouter_model::{Config, ItemId};

const ENV: &str = "COREROUTER_NETNS_TESTS";

static KERNEL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn ready() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!("skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net`");
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
    if !nft::available() {
        eprintln!("skipped: the `nft` program (nftables) is not installed");
        return false;
    }
    true
}

fn ruleset() -> String {
    let out = Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// `cfg` with a `dst-nat` in `srcnat` (postrouting), which the kernel
/// refuses: rule `id`.
fn with_bad_nat(cfg: &Config, id: u32) -> Config {
    let mut out = cfg.clone();
    out.ip.firewall.nat.push(
        rule(
            id,
            "srcnat",
            Default::default(),
            act(r#"{"type":"dst-nat","to_addresses":"10.0.0.1"}"#).unwrap(),
        )
        .unwrap(),
    );
    out
}

fn ids(r: &[RefusedItem]) -> Vec<ItemId> {
    r.iter().map(|r| r.id).collect()
}

#[test]
fn a_check_names_every_refused_rule_and_loads_nothing() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let mut hal = LinuxHal::new();
    let good = sample();
    assert_eq!(hal.check_firewall(&good).unwrap(), [], "the sample loads");
    // Nothing loaded by the check.
    assert!(!ruleset().contains("corerouter"), "{}", ruleset());

    hal.apply(&Config::default(), &good).unwrap();
    let loaded = ruleset();

    let one = with_bad_nat(&good, 0x90);
    let refused = hal.check_firewall(&one).unwrap();
    assert_eq!(ids(&refused), [ItemId(0x90)], "{refused:?}");
    assert!(!refused[0].reason.is_empty());
    assert_eq!(ruleset(), loaded, "the check changed nothing");

    // Two bad rules: the first, then (without it) the second. With the
    // validation on, the kernel refuses every rule after a bad one, so
    // only the first is named.
    let two = with_bad_nat(&one, 0x91);
    let refused = hal.check_firewall(&two).unwrap();
    assert_eq!(ids(&refused), [ItemId(0x90)], "{refused:?}");
    let mut without = two.clone();
    without.ip.firewall.nat.retain(|r| r.id.0 != 0x90);
    assert_eq!(ids(&hal.check_firewall(&without).unwrap()), [ItemId(0x91)]);
    assert_eq!(ruleset(), loaded);

    // Without them the rest loads, from what the last commit loaded.
    let mut fixed = two.clone();
    fixed.ip.firewall.nat.retain(|r| r.id.0 < 0x90);
    fixed.ip.firewall.filter.retain(|r| r.id.0 != 2);
    assert_eq!(hal.check_firewall(&fixed).unwrap(), []);
    hal.apply(&good, &fixed).unwrap();
    assert!(!ruleset().contains("\"cr:*2\""), "{}", ruleset());
    hal.apply(&fixed, &Config::default()).unwrap();
    assert!(!ruleset().contains("corerouter"));
}

/// Slow layer (G0.30): 10 000 rules with one the kernel refuses only in
/// its whole-table validation, checked and applied (~15 s, the kernel's
/// replay validates the table once per rule).
#[test]
fn slow_checking_many_rules_with_one_bad() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let mut hal = LinuxHal::new();
    let mut cfg = Config::default();
    for i in 0..10_000u32 {
        cfg.ip.firewall.filter.push(
            rule(
                i + 1,
                "forward",
                corerouter_firewall::sample::m(&[(
                    "dst_address",
                    &format!("10.{}.{}.0/24", i / 256, i % 256),
                )])
                .unwrap(),
                act(r#"{"type":"drop"}"#).unwrap(),
            )
            .unwrap(),
        );
    }
    let t = std::time::Instant::now();
    assert_eq!(hal.check_firewall(&cfg).unwrap(), []);
    eprintln!("check of 10 000 rules, all good: {:?}", t.elapsed());
    let bad = with_bad_nat(&cfg, 20_001);
    let t = std::time::Instant::now();
    let refused = hal.check_firewall(&bad).unwrap();
    eprintln!("check of 10 001 rules, 1 refused: {:?}", t.elapsed());
    assert_eq!(ids(&refused), [ItemId(20_001)]);
    assert!(!ruleset().contains("corerouter"), "{}", ruleset());
    let t = std::time::Instant::now();
    assert!(hal.apply(&Config::default(), &bad).is_err());
    eprintln!(
        "apply of the same 10 001 rules (refused): {:?}",
        t.elapsed()
    );
    let t = std::time::Instant::now();
    hal.apply(&Config::default(), &cfg).unwrap();
    eprintln!("apply of the 10 000 good rules: {:?}", t.elapsed());
    hal.apply(&cfg, &Config::default()).unwrap();
}
