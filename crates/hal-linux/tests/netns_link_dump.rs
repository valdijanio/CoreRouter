//! The lean link dump (G1.3f) reads what `rtnetlink` read, on links of
//! every kind the router makes, and keeps up with many of them. Inside a
//! throwaway network namespace; run by `cargo xtask netns` (see
//! `tests/netns.rs` for the guard).
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};

use corerouter_hal_linux::{link_dump, links_rtnetlink};

const ENV: &str = "COREROUTER_NETNS_TESTS";

/// One test at a time: they count the process's link dumps.
static SERIAL: Mutex<()> = Mutex::new(());

fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!("skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net`");
        return false;
    }
    static FRESH: OnceLock<Vec<String>> = OnceLock::new();
    let names = FRESH.get_or_init(|| {
        let out = Command::new("ip")
            .args(["-o", "link", "show"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split(':').nth(1))
            .map(|n| n.trim().to_owned())
            .collect()
    });
    assert_eq!(names, &["lo"], "{ENV}=1 outside a fresh network namespace");
    true
}

/// `ip -batch` of `lines`.
fn ip_batch(lines: &[String]) {
    let mut child = Command::new("ip")
        .args(["-batch", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(lines.join("\n").as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn sorted(
    mut v: Vec<corerouter_hal_linux::owner::KernelLink>,
) -> Vec<corerouter_hal_linux::owner::KernelLink> {
    v.sort_by_key(|l| l.index);
    v
}

#[test]
fn reads_what_rtnetlink_read_on_every_kind_and_at_scale() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !in_netns() {
        return;
    }
    let mut lines: Vec<String> = [
        "link set lo up",
        "link add ld0 type dummy",
        "link set ld0 up",
        "link set ld0 mtu 1400 address 02:00:00:00:00:01",
        "link add link ld0 name ld0.10 type vlan id 10",
        "link add lbr type bridge",
        "link add ld1 type dummy",
        "link set ld1 master lbr",
        "link set lbr up",
        "link add lv0 type veth peer name lv1",
        "link set lv0 up",
        "link add lbond type bond",
        "link add ld2 type dummy",
        "link set ld2 master lbond",
        "link add lvrf type vrf table 10",
        "link add link ld0 name lmac type macvlan mode bridge",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    // Many: a BNG has a link per subscriber.
    lines.extend((0..3000).map(|i| format!("link add many{i} up type dummy")));
    ip_batch(&lines);
    let lean = sorted(link_dump::dump().unwrap());
    let old = sorted(links_rtnetlink().unwrap());
    assert_eq!(lean.len(), old.len());
    for (a, b) in lean.iter().zip(&old) {
        assert_eq!(a, b, "{}", b.name);
    }
    let kinds: Vec<&str> = lean.iter().filter_map(|l| l.kind.as_deref()).collect();
    for k in ["dummy", "vlan", "bridge", "veth", "bond", "vrf", "macvlan"] {
        assert!(kinds.contains(&k), "{k} in {kinds:?}");
    }
    assert!(lean.len() > 3000);
}

fn dumps() -> u64 {
    link_dump::DUMPS.load(std::sync::atomic::Ordering::Relaxed)
}

/// One link dump per tick: the route and address reads after the poll use
/// the index map it read; an apply drops it. A sample read before an apply
/// is refused; one read after it is folded in.
#[test]
fn one_dump_per_tick_and_no_stale_sample() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    use corerouter_hal::Hal;
    use corerouter_hal_linux::LinuxHal;
    use corerouter_model::{Config, IfName, Interface, InterfaceKind};
    if !in_netns() {
        return;
    }
    ip_batch(&[
        "link add sp1 type dummy".to_owned(),
        "link set sp1 up".to_owned(),
    ]);
    let n: IfName = "sp1".parse().unwrap();
    let mut cfg = Config::default();
    cfg.interfaces.insert(
        n.clone(),
        Interface::new(n.clone(), InterfaceKind::Ethernet),
    );
    let mut hal = LinuxHal::new();
    hal.apply(&Config::default(), &cfg).unwrap();
    hal.poll();
    let after_poll = dumps();
    hal.ipv6_learned().unwrap();
    assert_eq!(dumps(), after_poll, "the route read used the poll's links");
    hal.ipv6_learned().unwrap();
    assert_eq!(dumps(), after_poll + 1, "taken once, then read again");

    let stale = hal.link_reader().unwrap().read();
    let mut more = cfg.clone();
    more.interfaces.get_mut(&n).unwrap().mtu = 1400;
    hal.apply(&cfg, &more).unwrap();
    assert!(hal.poll_sample(stale).is_none(), "read before the apply");
    let fresh = hal.link_reader().unwrap().read();
    let live = hal.poll_sample(fresh).unwrap();
    let sp1 = live.iter().find(|l| l.name == n).unwrap();
    assert_eq!(sp1.mtu, 1400);
    assert!(hal.absent_ports().is_empty());
}
