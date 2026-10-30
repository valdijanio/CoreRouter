//! G1.3g against a real kernel, in a throwaway network namespace (no root,
//! nothing reaches the host; `cargo xtask netns` runs it): the boot's
//! routes go in one at a time, and the one the kernel refuses (another
//! program holds the same prefix and metric) stays out alone; the others
//! stay in, none taken back.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;
use std::sync::OnceLock;

use corerouter_hal::Hal;
use corerouter_hal_linux::LinuxHal;
use corerouter_model::{
    AddressEntry, Config, IfName, Interface, InterfaceKind, RouteEntry, RoutingTable,
};

const ENV: &str = "COREROUTER_NETNS_TESTS";

/// True when the tests may touch the kernel; panics outside a fresh
/// namespace (only `lo`), so a stray variable on the host touches nothing.
fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!("skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net`");
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
                "{ENV}=1 but this namespace has {names:?}; refusing to touch it"
            ))
        }
    });
    if let Err(e) = fresh {
        panic!("{e}");
    }
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

/// Two dummy ports `<p>1`, `<p>2` with 10.<net>.0.2/24, 10.<net>.1.2/24
/// and 2001:db8:<net>:0::2/64, 2001:db8:<net>:1::2/64.
fn base(p: &str, net: u8) -> Config {
    let mut c = Config::default();
    for (i, port) in [format!("{p}1"), format!("{p}2")].iter().enumerate() {
        ip(&["link", "add", port, "type", "dummy"]);
        c.interfaces
            .insert(n(port), Interface::new(n(port), InterfaceKind::Ethernet));
        for a in [
            format!("10.{net}.{i}.2/24"),
            format!("2001:db8:{net}:{i}::2/64"),
        ] {
            let id = c.ip.next_address_id();
            c.ip.addresses.push(AddressEntry {
                id,
                address: a.parse().unwrap(),
                interface: n(port),
                disabled: false,
                comment: String::new(),
                from_pool: None,
            });
        }
    }
    c
}

fn route(cfg: &mut Config, dst: &str, gw: &str) {
    let id = cfg.ip.next_route_id();
    cfg.ip.routes.push(RouteEntry {
        id,
        dst_address: dst.parse().unwrap(),
        gateway: gw.parse().unwrap(),
        distance: 1,
        routing_table: RoutingTable::Main,
        disabled: false,
        comment: String::new(),
        check_gateway: Default::default(),
        bfd_profile: String::new(),
    });
}

#[test]
fn a_refused_route_stays_out_alone() {
    if !in_netns() {
        return;
    }
    let mut hal = LinuxHal::new();
    let base = base("re", 82);
    hal.apply(&Config::default(), &base).unwrap();
    let mut routes = base.clone();
    route(&mut routes, "192.0.2.0/24", "10.82.0.1");
    route(&mut routes, "198.51.100.0/24", "10.82.0.1");
    route(&mut routes, "203.0.113.0/24", "10.82.1.1");
    let refused_id = routes.ip.routes.iter().nth(1).unwrap().id;
    // Another program got there first: same prefix, same metric.
    let ours = {
        let mut one = base.clone();
        route(&mut one, "198.51.100.0/24", "10.82.0.1");
        hal.apply(&base, &one).unwrap();
        let text = ip(&["route", "show", "198.51.100.0/24"]);
        hal.apply(&one, &base).unwrap();
        text
    };
    let metric = ours
        .split_whitespace()
        .skip_while(|w| *w != "metric")
        .nth(1)
        .unwrap_or("0")
        .to_owned();
    ip(&[
        "route",
        "add",
        "198.51.100.0/24",
        "via",
        "10.82.1.254",
        "metric",
        &metric,
    ]);
    // Whole, the kernel refuses it and takes everything back.
    assert!(hal.apply(&base, &routes).is_err());
    assert!(!ip(&["route", "show", "192.0.2.0/24"]).contains("10.82.0.1"));
    // One at a time: only the refused one stays out.
    let refused = hal.apply_routes_each(&base, &routes).unwrap();
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0].id, refused_id);
    assert!(refused[0].reason.contains("198.51.100.0/24"), "{refused:?}");
    assert!(ip(&["route", "show", "192.0.2.0/24"]).contains("via 10.82.0.1"));
    assert!(ip(&["route", "show", "203.0.113.0/24"]).contains("via 10.82.1.1"));
    let other = ip(&["route", "show", "198.51.100.0/24"]);
    assert!(
        other.contains("10.82.1.254") && !other.contains("10.82.0.1"),
        "the other program's route is untouched: {other}"
    );
    // More than added routes: not this way.
    let mut more = routes.clone();
    more.ip.addresses.clear();
    assert!(matches!(
        hal.apply_routes_each(&routes, &more),
        Err(corerouter_hal::HalError::Unsupported(_))
    ));
}

/// Slow layer (G0.30): 10 000 routes, one refused: one at a time costs what
/// the whole apply does (the executor sends them one by one either way).
#[test]
fn slow_ten_thousand_routes_one_refused() {
    if !in_netns() {
        return;
    }
    let mut hal = LinuxHal::new();
    let base = base("rt", 83);
    hal.apply(&Config::default(), &base).unwrap();
    let mut routes = base.clone();
    for i in 0..10_000u32 {
        route(
            &mut routes,
            &format!("10.{}.{}.0/24", 100 + i / 256, i % 256),
            "10.83.0.1",
        );
    }
    let t = std::time::Instant::now();
    hal.apply(&base, &routes).unwrap();
    eprintln!("apply of 10 000 routes, whole: {:?}", t.elapsed());
    hal.apply(&routes, &base).unwrap();
    ip(&[
        "route",
        "add",
        "10.110.5.0/24",
        "via",
        "10.83.1.254",
        "metric",
        "1",
    ]);
    let t = std::time::Instant::now();
    let refused = hal.apply_routes_each(&base, &routes).unwrap();
    eprintln!(
        "apply_routes_each of 10 000 routes, 1 refused: {:?}",
        t.elapsed()
    );
    assert_eq!(refused.len(), 1, "{refused:?}");
}
