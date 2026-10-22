//! G1.8 — bonding through `LinuxHal::apply` against a real kernel, inside a
//! throwaway network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_bond
//! ```
//!
//! (`cargo xtask netns` runs it in its own namespace.) Same guard as
//! `tests/netns.rs`. Dummy links stand in for the ethernet ports; `ip`
//! (iproute2) checks the result independently of our netlink code. A user
//! namespace cannot load the `bonding` module: without it the tests skip,
//! or fail with `COREROUTER_REQUIRE_BOND=1` (the CI loads it first).
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;
use std::sync::OnceLock;

use corerouter_hal::Hal;
use corerouter_hal_linux::LinuxHal;
use corerouter_model::{
    AddressEntry, BondMode, Config, HashPolicy, IfName, Interface, InterfaceKind, LacpRate,
};

const ENV: &str = "COREROUTER_NETNS_TESTS";
const REQUIRE_BOND: &str = "COREROUTER_REQUIRE_BOND";

fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!(
            "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` \
             (cargo xtask netns)"
        );
        return false;
    }
    static FRESH: OnceLock<Result<(), String>> = OnceLock::new();
    let fresh = FRESH.get_or_init(|| {
        let out = Command::new("ip")
            .args(["-o", "link", "show"])
            .output()
            .map_err(|e| format!("cannot run `ip`: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let names: Vec<&str> = text
            .lines()
            .filter_map(|l| l.split(':').nth(1))
            .map(str::trim)
            .collect();
        if names == ["lo"] {
            Ok(())
        } else {
            Err(format!(
                "{ENV}=1 but this network namespace has {names:?}, not just lo; refusing to \
                 touch it (run inside `unshare --user --map-root-user --net`)"
            ))
        }
    });
    if let Err(e) = fresh {
        panic!("{e}");
    }
    has_bond()
}

/// Whether this kernel can create a `bond` link, checked once with `ip`.
fn has_bond() -> bool {
    static HAS: OnceLock<bool> = OnceLock::new();
    let has = *HAS.get_or_init(|| {
        let ok = Command::new("ip")
            .args(["link", "add", "bondprobe", "type", "bond"])
            .output()
            .unwrap()
            .status
            .success();
        if ok {
            ip(&["link", "del", "bondprobe"]);
        }
        ok
    });
    if !has {
        assert!(
            std::env::var_os(REQUIRE_BOND).is_none_or(|v| v != "1"),
            "{REQUIRE_BOND}=1 but this kernel cannot create a bond link \
             (CONFIG_BONDING / module bonding; on the host: modprobe bonding)"
        );
        eprintln!("skipped: this kernel has no bonding support (module bonding)");
    }
    has
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

fn link(name: &str) -> String {
    ip(&["-d", "-o", "link", "show", "dev", name])
}

fn exists(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", "dev", name])
        .output()
        .unwrap()
        .status
        .success()
}

fn n(s: &str) -> IfName {
    s.parse().unwrap()
}

fn bond(mode: BondMode) -> InterfaceKind {
    InterfaceKind::Bonding {
        mode,
        primary: None,
        transmit_hash_policy: HashPolicy::Layer34,
        lacp_rate: LacpRate::Fast,
        mii_interval_ms: 100,
        min_links: 1,
    }
}

/// Dummy ports `names`, up, and the config that manages them.
fn ports(hal: &mut LinuxHal, names: &[&str]) -> Config {
    let mut cfg = Config::default();
    for p in names {
        ip(&["link", "add", p, "type", "dummy"]);
        ip(&["link", "set", p, "up"]);
        cfg.interfaces
            .insert(n(p), Interface::new(n(p), InterfaceKind::Ethernet));
    }
    hal.apply(&Config::default(), &cfg).unwrap();
    cfg
}

fn enslave(cfg: &mut Config, bond: &str, slaves: &[&str]) {
    for s in slaves {
        cfg.interfaces.get_mut(&n(s)).unwrap().bond = Some(n(bond));
    }
}

#[test]
fn lacp_bond_takes_its_slaves_and_gives_them_back() {
    if !in_netns() {
        return;
    }
    let mut hal = LinuxHal::new();
    let base = ports(&mut hal, &["b1p1", "b1p2", "b1p3"]);
    let mut to = base.clone();
    to.interfaces.insert(
        n("b1bond"),
        Interface::new(n("b1bond"), bond(BondMode::Lacp)),
    );
    enslave(&mut to, "b1bond", &["b1p1", "b1p2", "b1p3"]);
    to.interfaces.get_mut(&n("b1p3")).unwrap().disabled = true;
    let id = to.ip.next_address_id();
    to.ip.addresses.push(AddressEntry {
        id,
        address: "10.9.0.1/30".parse().unwrap(),
        interface: n("b1bond"),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
    // Slaves are up when enslaved: the executor takes them down first.
    hal.apply(&base, &to).unwrap();

    let b = link("b1bond");
    assert!(b.contains("bond mode 802.3ad"), "{b}");
    assert!(b.contains("miimon 100"), "{b}");
    assert!(b.contains("lacp_rate fast"), "{b}");
    assert!(b.contains("xmit_hash_policy layer3+4"), "{b}");
    assert!(b.contains("min_links 1"), "{b}");
    assert!(b.contains(",UP"), "{b}");
    for p in ["b1p1", "b1p2"] {
        let l = link(p);
        assert!(l.contains("master b1bond") && l.contains(",UP"), "{l}");
    }
    let p3 = link("b1p3");
    assert!(
        p3.contains("master b1bond") && !p3.contains(",UP"),
        "disabled slave: {p3}"
    );
    assert!(ip(&["-br", "addr", "show", "dev", "b1bond"]).contains("10.9.0.1/30"));

    hal.apply(&to, &to).unwrap();

    // A new mode recreates the bond; the slaves come back.
    let mut ab = to.clone();
    ab.interfaces.get_mut(&n("b1bond")).unwrap().kind = InterfaceKind::Bonding {
        mode: BondMode::ActiveBackup,
        primary: Some(n("b1p2")),
        transmit_hash_policy: HashPolicy::Layer2,
        lacp_rate: LacpRate::Slow,
        mii_interval_ms: 100,
        min_links: 0,
    };
    hal.apply(&to, &ab).unwrap();
    let b = link("b1bond");
    assert!(b.contains("bond mode active-backup"), "{b}");
    assert!(b.contains("primary b1p2"), "{b}");
    assert!(link("b1p1").contains("master b1bond"));
    assert!(ip(&["-br", "addr", "show", "dev", "b1bond"]).contains("10.9.0.1/30"));

    // Removing the bond leaves plain ports, up as configured.
    hal.apply(&ab, &base).unwrap();
    assert!(!exists("b1bond"));
    for p in ["b1p1", "b1p2", "b1p3"] {
        let l = link(p);
        assert!(!l.contains("master") && l.contains(",UP"), "{l}");
    }
}

#[test]
fn a_failed_apply_puts_the_slaves_back() {
    if !in_netns() {
        return;
    }
    let mut hal = LinuxHal::new();
    let mut base = ports(&mut hal, &["b2p1", "b2p2"]);
    let from = base.clone();
    let id = base.ip.next_address_id();
    base.ip.addresses.push(AddressEntry {
        id,
        address: "10.62.0.2/24".parse().unwrap(),
        interface: n("b2p2"),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
    hal.apply(&from, &base).unwrap();
    // Someone else's route: our identical one fails in the last step, after
    // the bond already took b2p1.
    ip(&[
        "route",
        "add",
        "203.0.113.0/24",
        "via",
        "10.62.0.99",
        "dev",
        "b2p2",
        "metric",
        "1",
        "proto",
        "static",
    ]);
    let mut to = base.clone();
    to.interfaces.insert(
        n("b2bond"),
        Interface::new(n("b2bond"), bond(BondMode::BalanceXor)),
    );
    enslave(&mut to, "b2bond", &["b2p1"]);
    let rid = to.ip.next_route_id();
    to.ip.routes.push(corerouter_model::RouteEntry {
        id: rid,
        dst_address: "203.0.113.0/24".parse().unwrap(),
        gateway: "10.62.0.1".parse().unwrap(),
        distance: 1,
        routing_table: corerouter_model::RoutingTable::Main,
        disabled: false,
        comment: String::new(),
    });
    let err = hal.apply(&base, &to).unwrap_err().to_string();
    assert!(
        err.contains("rolled back") && !err.contains("INCOMPLETE"),
        "{err}"
    );
    assert!(!exists("b2bond"), "bond left behind");
    let l = link("b2p1");
    assert!(!l.contains("master") && l.contains(",UP"), "{l}");
}

fn ifindex(name: &str) -> String {
    link(name).split(':').next().unwrap().trim().to_string()
}

/// G1.8d: miimon, min-links, hash and primary change on the live bond — same
/// ifindex, slaves stay — and a failed apply puts the old values back.
#[test]
fn live_settings_change_without_recreating_the_bond() {
    if !in_netns() {
        return;
    }
    let mut hal = LinuxHal::new();
    let base = ports(&mut hal, &["b3p1", "b3p2"]);
    let tune = |mode, primary: Option<&str>, hash, mii, min| InterfaceKind::Bonding {
        mode,
        primary: primary.map(n),
        transmit_hash_policy: hash,
        lacp_rate: LacpRate::Slow,
        mii_interval_ms: mii,
        min_links: min,
    };
    let mut from = base.clone();
    from.interfaces.insert(
        n("b3bond"),
        Interface::new(
            n("b3bond"),
            tune(BondMode::BalanceXor, None, HashPolicy::Layer2, 100, 0),
        ),
    );
    enslave(&mut from, "b3bond", &["b3p1", "b3p2"]);
    let id = from.ip.next_address_id();
    from.ip.addresses.push(AddressEntry {
        id,
        address: "10.63.0.1/24".parse().unwrap(),
        interface: n("b3bond"),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
    hal.apply(&base, &from).unwrap();
    let index = ifindex("b3bond");

    let mut to = from.clone();
    to.interfaces.get_mut(&n("b3bond")).unwrap().kind =
        tune(BondMode::BalanceXor, None, HashPolicy::Layer34, 250, 2);
    hal.apply(&from, &to).unwrap();
    let b = link("b3bond");
    assert!(b.contains("miimon 250"), "{b}");
    assert!(b.contains("min_links 2"), "{b}");
    assert!(b.contains("xmit_hash_policy layer3+4"), "{b}");
    assert_eq!(ifindex("b3bond"), index, "the bond was recreated");
    for p in ["b3p1", "b3p2"] {
        assert!(link(p).contains("master b3bond"), "{p} left the bond");
    }
    assert!(ip(&["-br", "addr", "show", "dev", "b3bond"]).contains("10.63.0.1/24"));

    // A failed apply (someone else's identical route makes the last step
    // fail) undoes the in-place change.
    ip(&[
        "route",
        "add",
        "198.51.100.0/24",
        "via",
        "10.63.0.99",
        "dev",
        "b3bond",
        "metric",
        "1",
        "proto",
        "static",
    ]);
    let mut bad = to.clone();
    bad.interfaces.get_mut(&n("b3bond")).unwrap().kind =
        tune(BondMode::BalanceXor, None, HashPolicy::Layer23, 50, 1);
    let rid = bad.ip.next_route_id();
    bad.ip.routes.push(corerouter_model::RouteEntry {
        id: rid,
        dst_address: "198.51.100.0/24".parse().unwrap(),
        gateway: "10.63.0.2".parse().unwrap(),
        distance: 1,
        routing_table: corerouter_model::RoutingTable::Main,
        disabled: false,
        comment: String::new(),
    });
    let err = hal.apply(&to, &bad).unwrap_err().to_string();
    assert!(
        err.contains("rolled back") && !err.contains("INCOMPLETE"),
        "{err}"
    );
    let b = link("b3bond");
    assert!(b.contains("miimon 250") && b.contains("min_links 2"), "{b}");
    assert!(b.contains("xmit_hash_policy layer3+4"), "{b}");
    ip(&["route", "del", "198.51.100.0/24"]);

    // Active-backup: the primary is set and cleared in place.
    let mut ab = to.clone();
    ab.interfaces.get_mut(&n("b3bond")).unwrap().kind =
        tune(BondMode::ActiveBackup, None, HashPolicy::Layer2, 100, 0);
    hal.apply(&to, &ab).unwrap();
    let index = ifindex("b3bond");
    let mut primary = ab.clone();
    primary.interfaces.get_mut(&n("b3bond")).unwrap().kind = tune(
        BondMode::ActiveBackup,
        Some("b3p2"),
        HashPolicy::Layer2,
        100,
        0,
    );
    hal.apply(&ab, &primary).unwrap();
    let b = link("b3bond");
    assert!(b.contains("primary b3p2"), "{b}");
    assert!(b.contains("active_slave b3p2"), "{b}");
    hal.apply(&primary, &ab).unwrap();
    let b = link("b3bond");
    assert!(!b.contains("primary b3p2"), "{b}");
    assert_eq!(ifindex("b3bond"), index, "the bond was recreated");

    hal.apply(&ab, &base).unwrap();
    assert!(!exists("b3bond"));
}
