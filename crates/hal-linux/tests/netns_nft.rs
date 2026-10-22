//! The firewall (G2.1) against a real kernel, inside a throwaway network
//! namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_nft
//! ```
//!
//! Same guard as `tests/netns.rs`: without the variable every test returns
//! early; with it, the namespace must hold nothing but `lo` (so the host's
//! own nftables rules are never in reach). Without the `nft` program the
//! tests skip with a note (it is how `hal-linux` loads rulesets).
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

use corerouter_hal::{DynamicChange, Hal};
use corerouter_hal_linux::{LinuxHal, nft};
use corerouter_model::Config;
use corerouter_model::firewall::DynamicAddress;

const ENV: &str = "COREROUTER_NETNS_TESTS";

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

/// `nft list ruleset` without the ticking `expires …` of timed elements.
fn ruleset() -> String {
    let out = Command::new("nft")
        .args(["list", "ruleset"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.split(" expires ")
        .enumerate()
        .map(|(i, part)| {
            if i == 0 {
                part.to_owned()
            } else {
                part.trim_start_matches(|c: char| c.is_ascii_alphanumeric())
                    .to_owned()
            }
        })
        .collect()
}

#[test]
fn firewall_is_applied_replaced_and_removed_atomically() {
    if !ready() {
        return;
    }
    // A table of another owner must survive everything below.
    let mut other = Command::new("nft")
        .args(["add", "table", "inet", "someone-else"])
        .status()
        .unwrap();
    assert!(other.success());

    let mut hal = LinuxHal::new();
    // Only the firewall: the netlink half is tested in tests/netns.rs (the
    // kernel matches interfaces by name, so they need not exist).
    let fw_only = corerouter_firewall::sample::sample();
    let empty = Config::default();
    hal.apply(&empty, &fw_only).unwrap();
    let text = ruleset();
    assert!(text.contains("table inet corerouter"), "{text}");
    assert_eq!(text.matches("comment \"cr:").count(), 20, "{text}");
    assert!(text.contains("table inet someone-else"));

    // A dynamic entry survives a replace of the table.
    let d = DynamicAddress {
        list: "blocked".parse().unwrap(),
        address: "192.0.2.77".parse().unwrap(),
        timeout_secs: 300,
    };
    hal.address_list_dynamic(DynamicChange::Add(&d)).unwrap();
    assert_eq!(nft::dynamic().len(), 1);
    let mut changed = fw_only.clone();
    changed.ip.firewall.filter.retain(|r| r.id.0 != 2);
    hal.apply(&fw_only, &changed).unwrap();
    let text = ruleset();
    assert!(!text.contains("\"cr:*2\""), "{text}");
    assert!(text.contains("192.0.2.77"), "dynamic entry kept: {text}");

    // A ruleset the kernel refuses changes nothing (one transaction).
    let mut broken = changed.clone();
    broken.ip.firewall.nat.push(
        corerouter_firewall::sample::rule(
            90,
            "srcnat",
            Default::default(),
            corerouter_firewall::sample::act(r#"{"type":"dst-nat","to_addresses":"10.0.0.1"}"#)
                .unwrap(),
        )
        .unwrap(),
    );
    let before = ruleset();
    assert!(
        hal.apply(&changed, &broken).is_err(),
        "dnat in postrouting refused"
    );
    assert_eq!(ruleset(), before, "nothing changed");

    hal.address_list_dynamic(DynamicChange::Remove(&d)).unwrap();
    hal.apply(&changed, &empty).unwrap();
    let text = ruleset();
    assert!(!text.contains("corerouter"), "{text}");
    assert!(text.contains("someone-else"));
    other = Command::new("nft")
        .args(["delete", "table", "inet", "someone-else"])
        .status()
        .unwrap();
    assert!(other.success());
}
