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
//! own nftables rules are never in reach). The ruleset goes over nfnetlink
//! (G2.8); the tests read it back with the `nft` program and skip without
//! it.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

use corerouter_hal::{DynamicChange, Hal};
use corerouter_hal_linux::{LinuxHal, nft};
use corerouter_model::Config;
use corerouter_model::firewall::DynamicAddress;

const ENV: &str = "COREROUTER_NETNS_TESTS";

/// The tests share one kernel table: one at a time.
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
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
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
    assert_eq!(text.matches("comment \"cr:").count(), 31, "{text}");
    // Raw (G2.1c): before conntrack, and notrack ends the chain.
    assert!(text.contains("hook prerouting priority raw"), "{text}");
    assert!(text.contains("notrack accept"), "{text}");
    assert!(text.contains("table inet someone-else"));

    // A dynamic entry survives a replace of the table.
    let d = DynamicAddress {
        list: "blocked".parse().unwrap(),
        address: "192.0.2.77".parse().unwrap(),
        timeout_secs: 300,
        added_by_rule: false,
    };
    hal.address_list_dynamic(DynamicChange::Add(&d)).unwrap();
    assert_eq!(corerouter_hal_linux::firewall::dynamic().unwrap().len(), 1);
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

/// G2.1b: an `add-src-to-address-list` rule fills the list's dynamic set
/// from the packet path, the entries survive a table replace, a rule on
/// that list matches them, and `limit` loads.
#[test]
fn rules_fill_address_lists_from_the_packet_path() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    assert!(
        Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .status()
            .unwrap()
            .success()
    );
    let sample = |pairs: &[(&str, &str)]| corerouter_firewall::sample::m(pairs).unwrap();
    let act = |json: &str| corerouter_firewall::sample::act(json).unwrap();
    let rule = |id, chain, m, a| corerouter_firewall::sample::rule(id, chain, m, a).unwrap();
    let mut cfg = Config::default();
    cfg.ip.firewall.filter = corerouter_model::cow_list::CowList::from(vec![
        rule(
            1,
            "input",
            sample(&[
                ("protocol", "tcp"),
                ("dst_port", "2222"),
                ("connection_state", "new"),
            ]),
            act(
                r#"{"type":"add-src-to-address-list","address_list":"knock","address_list_timeout":"10m"}"#,
            ),
        ),
        rule(
            2,
            "input",
            sample(&[
                ("src_address_list", "knock"),
                ("protocol", "tcp"),
                ("dst_port", "2223"),
            ]),
            act(r#"{"type":"reject","reject_with":"tcp-reset"}"#),
        ),
        rule(
            3,
            "input",
            sample(&[("protocol", "icmp"), ("limit", "2/1s,2")]),
            act(r#"{"type":"accept"}"#),
        ),
    ]);
    let mut hal = LinuxHal::new();
    hal.apply(&Config::default(), &cfg).unwrap();

    // A SYN to 2222: nothing listens (refused), but the input chain saw it.
    let addr: std::net::SocketAddr = "127.0.0.1:2222".parse().unwrap();
    let _ = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(2));
    let kept = corerouter_hal_linux::firewall::dynamic().unwrap();
    assert!(
        kept.iter().any(|d| d.added_by_rule
            && d.list.as_str() == "knock"
            && d.address.to_string() == "127.0.0.1"
            && d.timeout_secs > 0),
        "{kept:?}\n{}",
        ruleset()
    );

    // A replace keeps it in the dynamic set, and rule 2 matches it.
    let mut changed = cfg.clone();
    changed.ip.firewall.filter.retain(|r| r.id.0 != 3);
    hal.apply(&cfg, &changed).unwrap();
    let text = ruleset();
    assert!(text.contains("set ad4_knock"), "{text}");
    assert!(text.contains("127.0.0.1"), "entry kept: {text}");
    let counters = |id: &str| -> String {
        ruleset()
            .lines()
            .filter(|l| l.contains(&format!("\"cr:{id}\"")))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let addr: std::net::SocketAddr = "127.0.0.1:2223".parse().unwrap();
    let _ = std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(2));
    let hits = counters("*2");
    assert!(
        hits.lines()
            .any(|l| l.contains("@ad4_knock") && l.contains("packets 1 ")),
        "the dynamic-set rule counted the SYN: {hits}"
    );

    hal.apply(&changed, &Config::default()).unwrap();
    assert!(!ruleset().contains("corerouter"));
}
