//! G1.27 against a real kernel, in a throwaway network namespace (no root,
//! nothing reaches the host; `cargo xtask netns` runs it):
//!
//! - equal-distance static routes become one multipath route, and losing
//!   one path rewrites it with the rest (IPv4 and IPv6);
//! - the drift check reads a multipath route back as its paths;
//! - `route_get` (`RTM_GETROUTE`) answers like `ip route get`.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;
use std::sync::OnceLock;

use corerouter_hal::Hal;
use corerouter_hal::drift;
use corerouter_hal::route_get::{RouteKind, RouteQuery};
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
fn equal_distance_routes_are_one_multipath_route() {
    if !in_netns() {
        return;
    }
    let mut hal = LinuxHal::new();
    let base = base("m1p", 81);
    hal.apply(&Config::default(), &base).unwrap();
    let mut two = base.clone();
    route(&mut two, "192.0.2.0/24", "10.81.0.1");
    route(&mut two, "192.0.2.0/24", "10.81.1.1");
    route(&mut two, "2001:db8:aa::/48", "2001:db8:81::1");
    route(&mut two, "2001:db8:aa::/48", "2001:db8:81:1::1");
    hal.apply(&base, &two).unwrap();

    let v4 = ip(&["-4", "route", "show", "192.0.2.0/24"]);
    assert!(
        v4.contains("nexthop via 10.81.0.1 dev m1p1")
            && v4.contains("nexthop via 10.81.1.1 dev m1p2"),
        "{v4}"
    );
    let v6 = ip(&["-6", "route", "show", "2001:db8:aa::/48"]);
    assert!(
        v6.contains("2001:db8:81::1") && v6.contains("2001:db8:81:1::1"),
        "{v6}"
    );
    // The drift check reads the group back as its paths: nothing drifted.
    let have = hal.snapshot(&two).unwrap();
    assert_eq!(
        drift::diff(&drift::expected(&two), &have),
        vec![],
        "{have:?}"
    );
    // Applying again changes nothing.
    hal.apply(&two, &two).unwrap();
    hal.apply(&Config::default(), &two).unwrap();
    assert_eq!(ip(&["-4", "route", "show", "192.0.2.0/24"]), v4);

    // One path leaves: the other stays, as a plain route.
    let mut one = base.clone();
    route(&mut one, "192.0.2.0/24", "10.81.1.1");
    route(&mut one, "2001:db8:aa::/48", "2001:db8:81:1::1");
    hal.apply(&two, &one).unwrap();
    let v4 = ip(&["-4", "route", "show", "192.0.2.0/24"]);
    assert!(
        v4.starts_with("192.0.2.0/24 via 10.81.1.1 dev m1p2"),
        "{v4}"
    );
    let v6 = ip(&["-6", "route", "show", "2001:db8:aa::/48"]);
    assert!(
        v6.contains("via 2001:db8:81:1::1") && !v6.contains("2001:db8:81::1 "),
        "{v6}"
    );
    // And back, then all gone.
    hal.apply(&one, &two).unwrap();
    assert!(ip(&["-4", "route", "show", "192.0.2.0/24"]).contains("nexthop"));
    hal.apply(&two, &base).unwrap();
    assert_eq!(ip(&["-4", "route", "show", "192.0.2.0/24"]), "");
    assert_eq!(ip(&["-6", "route", "show", "2001:db8:aa::/48"]), "");
}

#[test]
fn route_get_answers_like_ip_route_get() {
    if !in_netns() {
        return;
    }
    let mut hal = LinuxHal::new();
    let mut cfg = base("m2p", 82);
    route(&mut cfg, "0.0.0.0/0", "10.82.0.1");
    route(&mut cfg, "198.51.100.0/24", "10.82.0.1");
    route(&mut cfg, "198.51.100.0/24", "10.82.1.1");
    route(&mut cfg, "198.51.100.0/25", "10.82.1.1");
    hal.apply(&Config::default(), &cfg).unwrap();
    let get = |hal: &mut LinuxHal, dst: &str| {
        hal.route_get(
            &cfg,
            &RouteQuery {
                dst: dst.parse().unwrap(),
                table: 254,
                src: None,
            },
        )
        .unwrap()
    };
    let r = get(&mut hal, "8.8.8.8");
    assert_eq!(r.kind, RouteKind::Unicast);
    assert_eq!(r.prefix, Some("0.0.0.0/0".parse().unwrap()));
    assert_eq!(r.hops.len(), 1);
    assert_eq!(r.hops[0].interface, n("m2p1"));
    assert_eq!(r.src, Some("10.82.0.2".parse().unwrap()));
    // The longer prefix wins.
    let r = get(&mut hal, "198.51.100.7");
    assert_eq!(r.prefix, Some("198.51.100.0/25".parse().unwrap()), "{r:?}");
    // ECMP: the FIB entry lists both paths.
    let r = get(&mut hal, "198.51.100.200");
    assert_eq!(r.prefix, Some("198.51.100.0/24".parse().unwrap()));
    assert_eq!(r.hops.len(), 2, "{r:?}");
    // On link, local, unreachable.
    let r = get(&mut hal, "10.82.1.77");
    assert_eq!((r.kind, r.hops[0].gateway), (RouteKind::Unicast, None));
    assert_eq!(get(&mut hal, "10.82.1.2").kind, RouteKind::Local);
    assert_eq!(
        get(&mut hal, "2001:db8:ffff::1").kind,
        RouteKind::Unreachable
    );
}

#[test]
fn a_route_of_someone_else_is_refused_not_replaced() {
    if !in_netns() {
        return;
    }
    let mut hal = LinuxHal::new();
    let base = base("f1p", 82);
    hal.apply(&Config::default(), &base).unwrap();
    // Added by hand: same prefix, metric and table as ours.
    ip(&[
        "route",
        "add",
        "100.82.0.0/24",
        "via",
        "10.82.0.1",
        "metric",
        "1",
    ]);
    let before = ip(&["-4", "route", "show", "100.82.0.0/24"]);
    let mut ours = base.clone();
    route(&mut ours, "100.82.1.0/24", "10.82.0.1");
    route(&mut ours, "100.82.0.0/24", "10.82.1.1");
    let err = hal.apply(&base, &ours).unwrap_err().to_string();
    assert!(err.contains("refusing to replace"), "{err}");
    // Untouched, and the route added before it in the same commit is
    // rolled back (G0.31: the add is tried before the table is read).
    assert_eq!(ip(&["-4", "route", "show", "100.82.0.0/24"]), before);
    assert_eq!(ip(&["-4", "route", "show", "100.82.1.0/24"]), "");
}
