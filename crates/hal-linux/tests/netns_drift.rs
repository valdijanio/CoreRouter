//! Drift (G1.3) against a real kernel, inside a throwaway network
//! namespace: `ip` changes what `LinuxHal::apply` set up, `snapshot` +
//! `drift::diff` see it, `reconcile` puts it back. Run by `cargo xtask
//! netns` (see `tests/netns.rs` for the guard).
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

use corerouter_hal::Hal;
use corerouter_hal::drift::{self, DriftKind};
use corerouter_hal_linux::LinuxHal;
use corerouter_model::{
    AddressEntry, Config, IfName, Interface, InterfaceKind, RouteEntry, RoutingTable, VlanId,
};

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

fn iface(cfg: &mut Config, name: &str, kind: InterfaceKind) {
    cfg.interfaces
        .insert(n(name), Interface::new(n(name), kind));
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

fn drifted(hal: &mut LinuxHal, cfg: &Config) -> Vec<(DriftKind, String)> {
    let have = hal.snapshot(cfg).unwrap();
    drift::diff(&drift::expected(cfg), &have)
        .into_iter()
        .map(|d| (d.kind, d.item))
        .collect()
}

#[test]
fn drift_is_seen_and_reconciled() {
    if !in_netns() {
        return;
    }
    for p in ["d1", "d2", "d3"] {
        ip(&["link", "add", p, "type", "dummy"]);
    }
    let mut cfg = Config::default();
    for p in ["d1", "d2", "d3"] {
        iface(&mut cfg, p, InterfaceKind::Ethernet);
    }
    iface(
        &mut cfg,
        "dv10",
        InterfaceKind::Vlan {
            parent: n("d2"),
            vlan_id: VlanId::new(10).unwrap(),
        },
    );
    iface(&mut cfg, "dbr", InterfaceKind::Bridge);
    cfg.interfaces.get_mut(&n("d3")).unwrap().bridge = Some(n("dbr"));
    addr(&mut cfg, "d1", "10.0.0.2/24");
    addr(&mut cfg, "d1", "2001:db8::2/64");
    addr(&mut cfg, "dv10", "10.10.0.1/24");
    let id = cfg.ip.next_route_id();
    cfg.ip.routes.push(RouteEntry {
        id,
        dst_address: "0.0.0.0/0".parse().unwrap(),
        gateway: "10.0.0.1".parse().unwrap(),
        distance: 1,
        routing_table: RoutingTable::Main,
        disabled: false,
        comment: String::new(),
        check_gateway: Default::default(),
        bfd_profile: String::new(),
    });

    let mut hal = LinuxHal::new();
    hal.apply(&Config::default(), &cfg).unwrap();
    assert_eq!(drifted(&mut hal, &cfg), [], "just applied: in sync");

    // Behind CoreRouter's back. Deleting the last IPv4 address of d1 also
    // makes the kernel flush the default route through it.
    ip(&["addr", "del", "10.0.0.2/24", "dev", "d1"]);
    ip(&["addr", "add", "192.0.2.9/24", "dev", "d2"]);
    ip(&[
        "route",
        "add",
        "198.51.100.0/24",
        "dev",
        "d2",
        "proto",
        "static",
        "metric",
        "5",
    ]);
    ip(&["link", "del", "dv10"]);
    ip(&["link", "set", "d2", "mtu", "1400"]);
    ip(&["link", "set", "d3", "nomaster"]);
    let mut found = drifted(&mut hal, &cfg);
    found.sort();
    let kinds: Vec<DriftKind> = found.iter().map(|(k, _)| *k).collect();
    assert_eq!(
        kinds,
        [
            DriftKind::LinkMissing,
            DriftKind::Mtu,
            DriftKind::Master,
            DriftKind::AddressMissing,
            DriftKind::AddressExtra,
            DriftKind::RouteMissing,
            DriftKind::RouteExtra,
        ],
        "{found:?}"
    );

    // Like `config.drift.reconcile`: a round, then look again.
    for _ in 0..3 {
        if drifted(&mut hal, &cfg).is_empty() {
            break;
        }
        hal.reconcile(&cfg).unwrap();
    }
    assert_eq!(drifted(&mut hal, &cfg), []);
    // Checked with `ip`, independently of our netlink code.
    let v10 = ip(&["-d", "-o", "addr", "show", "dev", "dv10"]);
    assert!(v10.contains("10.10.0.1/24"), "{v10}");
    let d2 = ip(&["-o", "addr", "show", "dev", "d2"]);
    assert!(!d2.contains("192.0.2.9"), "{d2}");
    let routes = ip(&["route", "show", "proto", "static"]);
    assert!(routes.contains("default via 10.0.0.1 dev d1"), "{routes}");
    assert!(!routes.contains("198.51.100.0"), "{routes}");
    assert!(ip(&["-o", "link", "show", "d3"]).contains("master dbr"));
    assert!(ip(&["-o", "link", "show", "d2"]).contains("mtu 1500"));
}
