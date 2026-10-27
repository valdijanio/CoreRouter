//! Firewall diagnosis (G2.1c) against a real kernel, inside a throwaway
//! network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_fw_diag
//! ```
//!
//! - the rule counters in one nfnetlink dump (`nft_counters::dump`) match
//!   what `nft -j` says, and count real packets;
//! - the trace table marks the filter's packets, and the trace events name
//!   our chain, rule handle and verdict.
//!
//! The firewall itself is still loaded by `nft -f` (G2.8 moves it to
//! nfnetlink): without the program the tests skip.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::UdpSocket;
use std::process::Command;
use std::time::{Duration, Instant};

use corerouter_firewall::program::Family;
use corerouter_firewall::sample::{m, rule};
use corerouter_hal::Hal;
use corerouter_hal_linux::nft_counters::{NFPROTO_INET, dump};
use corerouter_hal_linux::nft_trace::{self, Listener, Match};
use corerouter_hal_linux::{LinuxHal, nfnl, nft};
use corerouter_model::firewall::{Action, Table};
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
    assert!(names == ["lo"], "{ENV}=1 but this namespace has {names:?}");
    if !nft::available() {
        eprintln!("skipped: the `nft` program (nftables) is not installed");
        return false;
    }
    let up = Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .unwrap();
    assert!(up.success());
    true
}

/// filter input: `*1` accepts UDP 9999, `*2` drops UDP 9998.
fn firewall() -> Config {
    let mut c = Config::default();
    c.ip.firewall.filter = vec![
        rule(
            1,
            "input",
            m(&[("protocol", "udp"), ("dst_port", "9999")]).unwrap(),
            Action::Accept,
        )
        .unwrap(),
        rule(
            2,
            "input",
            m(&[("protocol", "udp"), ("dst_port", "9998")]).unwrap(),
            Action::Drop,
        )
        .unwrap(),
    ]
    .into();
    c.ip.firewall.next_rule_id = 2;
    c
}

fn send(port: u16, n: usize) {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    for _ in 0..n {
        s.send_to(b"corerouter", ("127.0.0.1", port)).unwrap();
    }
}

fn counter(id: u32) -> (u64, u64) {
    dump(NFPROTO_INET, corerouter_firewall::TABLE)
        .unwrap()
        .into_iter()
        .filter(|r| {
            corerouter_firewall::nft::rule_of(&r.chain, r.comment.as_deref())
                == Some((Table::Filter, ItemId(id)))
        })
        .fold((0, 0), |(p, b), r| (p + r.packets, b + r.bytes))
}

#[test]
fn counters_in_one_dump_count_real_packets() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let mut hal = LinuxHal::new();
    let cfg = firewall();
    hal.apply(&Config::default(), &cfg).unwrap();

    let rules = dump(NFPROTO_INET, corerouter_firewall::TABLE).unwrap();
    assert_eq!(rules.len(), 2, "{rules:?}");
    assert!(
        rules
            .iter()
            .all(|r| r.chain == "filter_input" && r.handle > 0)
    );
    assert_eq!(counter(1), (0, 0));

    send(9999, 5);
    send(9998, 3);
    let (p1, b1) = counter(1);
    assert_eq!(p1, 5);
    assert!(b1 >= 5 * 38, "{b1} bytes");
    assert_eq!(counter(2).0, 3);

    // The same numbers as `nft -j` (what the dump replaces).
    let out = Command::new("nft")
        .args(["-j", "list", "table", "inet", corerouter_firewall::TABLE])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let json_packets: u64 = v["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|o| o.get("rule"))
        .filter(|r| r["comment"] == "cr:*1")
        .flat_map(|r| r["expr"].as_array().cloned().unwrap_or_default())
        .filter_map(|e| e.get("counter").and_then(|c| c["packets"].as_u64()))
        .sum();
    assert_eq!(json_packets, 5);

    // No firewall: no table, no rules, no error.
    hal.apply(&cfg, &Config::default()).unwrap();
    assert!(
        dump(NFPROTO_INET, corerouter_firewall::TABLE)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn the_trace_shows_the_rule_that_decided() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let mut hal = LinuxHal::new();
    let cfg = firewall();
    hal.apply(&Config::default(), &cfg).unwrap();
    let handle_of_2 = dump(NFPROTO_INET, corerouter_firewall::TABLE)
        .unwrap()
        .into_iter()
        .find(|r| r.comment.as_deref() == Some("cr:*2"))
        .unwrap()
        .handle;

    let filter = Match {
        protocol: Some(17),
        dport: Some(9998),
        ..Match::default()
    };
    let t = nft_trace::table(&filter);
    nfnl::apply(nfnl::replace(&t, 1), "trace").unwrap();
    let mut listen = Listener::open().unwrap();
    send(9997, 2); // not in the filter: never traced
    send(9998, 1);
    let mut events = Vec::new();
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3)
        && !events
            .iter()
            .any(|e: &nft_trace::Event| e.verdict == "drop")
    {
        listen.recv(200, 1000, &mut events).unwrap();
    }
    let drop = events
        .iter()
        .find(|e| {
            e.table == corerouter_firewall::TABLE
                && e.chain == "filter_input"
                && e.verdict == "drop"
        })
        .unwrap_or_else(|| panic!("no drop event: {events:#?}"));
    assert_eq!(drop.handle, Some(handle_of_2));
    assert_eq!(drop.dport, Some(9998));
    assert!(
        events.iter().all(|e| e.dport != Some(9997)),
        "only the filter's packets"
    );
    // Every event of that packet shares its trace id.
    assert!(events.iter().filter(|e| e.id == drop.id).count() >= 2);

    // Removing the trace table leaves the firewall alone.
    let mut b = nfnl::Batch::new(1);
    b.family(Family::Inet);
    b.new_table(nft_trace::TABLE);
    b.del_table(nft_trace::TABLE);
    nfnl::apply(b, "trace off").unwrap();
    assert_eq!(
        dump(NFPROTO_INET, corerouter_firewall::TABLE)
            .unwrap()
            .len(),
        2
    );
    assert!(dump(NFPROTO_INET, nft_trace::TABLE).unwrap().is_empty());
    hal.apply(&cfg, &Config::default()).unwrap();
}
