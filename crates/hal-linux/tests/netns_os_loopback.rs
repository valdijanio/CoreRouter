//! G3.4i — the loopback named `lo` is the kernel's own `lo` (IFF_LOOPBACK,
//! what FRR's `ospfd` wants under a prefix SID), inside a throwaway network
//! namespace: `LinuxHal::apply` adds and removes CoreRouter's /32 and /128
//! there and nothing else. `lo` is never created, deleted, resized or taken
//! down, and 127.0.0.1/8 and ::1 stay, through a disable, a failed apply
//! (rollback), drift + reconcile and the removal of `lo` from the config.
//! Run by `cargo xtask netns` (see `tests/netns.rs` for the guard).
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;
use std::time::Instant;

use corerouter_hal::Hal;
use corerouter_hal::drift;
use corerouter_hal_linux::LinuxHal;
use corerouter_model::{AddressEntry, Config, IfName, Interface, InterfaceKind};

const ENV: &str = "COREROUTER_NETNS_TESTS";

/// True when the tests may touch the kernel; panics outside a fresh
/// namespace (anything but `lo` there).
fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!("skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net`");
        return false;
    }
    let names = ip(&["-o", "link", "show"]);
    let names: Vec<&str> = names
        .lines()
        .filter_map(|l| l.split(':').nth(1))
        .map(str::trim)
        .collect();
    assert_eq!(names, ["lo"], "{ENV}=1 outside a fresh network namespace");
    true
}

fn ip(args: &[&str]) -> String {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "ip {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn n(s: &str) -> IfName {
    s.parse().unwrap()
}

fn addr(cfg: &mut Config, on: &str, a: &str) {
    let id = cfg.ip.next_address_id();
    cfg.ip.addresses.push(AddressEntry {
        id,
        address: a.parse().unwrap(),
        interface: n(on),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
}

/// `lo` as `ip` sees it: still up, MTU 65536, and the OS's addresses there.
fn assert_os_lo_intact() {
    let link = ip(&["-o", "link", "show", "lo"]);
    assert!(link.contains("LOOPBACK") && link.contains(",UP"), "{link}");
    assert!(link.contains("mtu 65536"), "{link}");
    let a = ip(&["-o", "addr", "show", "dev", "lo"]);
    assert!(a.contains("127.0.0.1/8"), "{a}");
    assert!(a.contains("::1/128"), "{a}");
}

fn lo_addrs() -> String {
    ip(&["-o", "addr", "show", "dev", "lo"])
}

#[test]
fn lo_gets_only_corerouter_addresses() {
    if !in_netns() {
        return;
    }
    // A fresh namespace has `lo` down and bare; the OS brings it up at boot.
    ip(&["link", "set", "lo", "up"]);
    assert_os_lo_intact();

    let base = Config::default();
    let mut cfg = base.clone();
    cfg.interfaces
        .insert(n("lo"), Interface::new(n("lo"), InterfaceKind::Loopback));
    cfg.interfaces
        .insert(n("lo1"), Interface::new(n("lo1"), InterfaceKind::Loopback));
    addr(&mut cfg, "lo", "10.255.0.1/32");
    addr(&mut cfg, "lo", "2001:db8:ff::1/128");
    addr(&mut cfg, "lo1", "10.255.1.1/32");

    let mut hal = LinuxHal::new();
    let t = Instant::now();
    hal.apply(&base, &cfg).unwrap();
    eprintln!("apply (lo + a dummy, 3 addresses): {:?}", t.elapsed());
    let a = lo_addrs();
    assert!(a.contains("10.255.0.1/32"), "{a}");
    assert!(a.contains("2001:db8:ff::1/128"), "{a}");
    assert_os_lo_intact();
    // Any other loopback is still a dummy.
    assert!(ip(&["-d", "-o", "link", "show", "lo1"]).contains("dummy"));
    // The OS's addresses on `lo` are not drift.
    let have = hal.snapshot(&cfg).unwrap();
    assert_eq!(drift::diff(&drift::expected(&cfg), &have), []);

    // Behind CoreRouter's back: our /32 deleted, a stranger added. Reconcile
    // puts ours back, takes the stranger away, keeps 127.0.0.1 and ::1.
    ip(&["addr", "del", "10.255.0.1/32", "dev", "lo"]);
    ip(&["addr", "add", "192.0.2.77/32", "dev", "lo"]);
    let have = hal.snapshot(&cfg).unwrap();
    assert_eq!(drift::diff(&drift::expected(&cfg), &have).len(), 2);
    hal.reconcile(&cfg).unwrap();
    let a = lo_addrs();
    assert!(
        a.contains("10.255.0.1/32") && !a.contains("192.0.2.77"),
        "{a}"
    );
    assert_os_lo_intact();

    // Disabled in the config: our addresses go, `lo` stays up.
    let mut off = cfg.clone();
    off.interfaces.get_mut(&n("lo")).unwrap().disabled = true;
    hal.apply(&cfg, &off).unwrap();
    let a = lo_addrs();
    assert!(
        !a.contains("10.255.0.1") && !a.contains("2001:db8:ff::1"),
        "{a}"
    );
    assert_os_lo_intact();
    hal.apply(&off, &cfg).unwrap();
    assert!(lo_addrs().contains("10.255.0.1/32"));

    // Out of the config: our addresses go, `lo` is not deleted.
    hal.apply(&cfg, &base).unwrap();
    let a = lo_addrs();
    assert!(
        !a.contains("10.255.0.1") && !a.contains("2001:db8:ff::1"),
        "{a}"
    );
    assert_os_lo_intact();

    a_failed_apply_takes_the_lo_addresses_back();
}

/// A failed apply takes the lo addresses back (one test with the one
/// above: both use the namespace's only `lo`, so they never run in parallel).
fn a_failed_apply_takes_the_lo_addresses_back() {
    let base = Config::default();
    let mut cfg = base.clone();
    cfg.interfaces
        .insert(n("lo"), Interface::new(n("lo"), InterfaceKind::Loopback));
    addr(&mut cfg, "lo", "10.255.0.9/32");
    // A port that does not exist: its address fails after lo's went in
    // ("lo" < "nope"), so the executor undoes lo's.
    cfg.interfaces.insert(
        n("nope"),
        Interface::new(n("nope"), InterfaceKind::Ethernet),
    );
    addr(&mut cfg, "nope", "192.0.2.1/24");
    let mut hal = LinuxHal::new();
    assert!(hal.apply(&base, &cfg).is_err());
    assert!(!lo_addrs().contains("10.255.0.9"), "{}", lo_addrs());
    assert_os_lo_intact();
}
