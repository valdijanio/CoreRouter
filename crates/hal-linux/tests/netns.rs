//! `LinuxHal::apply` against a real kernel, inside a throwaway network
//! namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns
//! ```
//!
//! (`cargo xtask netns` does exactly that, and `cargo xtask ci` runs it.)
//! Without the variable every test returns early with a "skipped" note. With
//! it, the tests still refuse to run unless the namespace holds nothing but
//! `lo`, so a stray `COREROUTER_NETNS_TESTS=1` on the host cannot touch the
//! host's interfaces. `ip` (iproute2) is used to set up stand-in ports and
//! to check the result independently of our netlink code.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;
use std::sync::OnceLock;

use corerouter_hal::Hal;
use corerouter_hal_linux::LinuxHal;
use corerouter_model::{
    AddressEntry, Config, IfName, Interface, InterfaceKind, RouteEntry, RoutingTable, VlanId,
};

const ENV: &str = "COREROUTER_NETNS_TESTS";
/// With this set to 1 (the CI does it after `modprobe vrf`), a kernel
/// without VRF fails the VRF tests instead of skipping them.
const REQUIRE_VRF: &str = "COREROUTER_REQUIRE_VRF";

/// True when the tests may touch the kernel; panics if asked to run outside
/// a fresh namespace.
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

fn exists(name: &str) -> bool {
    Command::new("ip")
        .args(["link", "show", "dev", name])
        .output()
        .unwrap()
        .status
        .success()
}

/// A dummy link standing in for a physical port.
fn port(name: &str) {
    ip(&["link", "add", name, "type", "dummy"]);
}

fn n(s: &str) -> IfName {
    s.parse().unwrap()
}

fn eth(cfg: &mut Config, name: &str) {
    cfg.interfaces
        .insert(n(name), Interface::new(n(name), InterfaceKind::Ethernet));
}

fn add<'a>(cfg: &'a mut Config, name: &str, kind: InterfaceKind) -> &'a mut Interface {
    cfg.interfaces
        .insert(n(name), Interface::new(n(name), kind));
    cfg.interfaces.get_mut(&n(name)).unwrap()
}

fn vlan(parent: &str, id: u16) -> InterfaceKind {
    InterfaceKind::Vlan {
        parent: n(parent),
        vlan_id: VlanId::new(id).unwrap(),
    }
}

fn addr(cfg: &mut Config, iface: &str, a: &str) {
    let id = cfg.ip.next_address_id();
    cfg.ip.addresses.push(AddressEntry {
        id,
        address: a.parse().unwrap(),
        interface: n(iface),
        disabled: false,
        comment: String::new(),
    });
}

fn route<'a>(cfg: &'a mut Config, dst: &str, gw: &str) -> &'a mut RouteEntry {
    let id = cfg.ip.next_route_id();
    cfg.ip.routes.push(RouteEntry {
        id,
        dst_address: dst.parse().unwrap(),
        gateway: gw.parse().unwrap(),
        distance: 1,
        routing_table: RoutingTable::Main,
        disabled: false,
        comment: String::new(),
    });
    cfg.ip.routes.last_mut().unwrap()
}

/// Static routes the kernel has through links whose name starts with
/// `prefix` (other tests share the namespace), one `ip route` line each.
fn routes(prefix: &str) -> Vec<String> {
    let mut out: Vec<String> = ["-4", "-6"]
        .iter()
        .flat_map(|fam| {
            ip(&[fam, "route", "show", "table", "all", "proto", "static"])
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .filter(|l| {
            l.split_whitespace()
                .skip_while(|w| *w != "dev")
                .nth(1)
                .is_some_and(|d| d.starts_with(prefix))
        })
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    out.sort();
    out
}

fn mtu(cfg: &mut Config, name: &str, m: u16) {
    cfg.interfaces.get_mut(&n(name)).unwrap().mtu = m;
}

#[test]
fn vlan_bridge_loopback_and_addresses() {
    if !in_netns() {
        return;
    }
    port("a1eth1");
    port("a1eth2");
    let mut hal = LinuxHal::new();
    let mut base = Config::default();
    eth(&mut base, "a1eth1");
    eth(&mut base, "a1eth2");
    // What Session::new does at boot: manage the discovered ports.
    hal.apply(&Config::default(), &base).unwrap();
    assert!(ip(&["-o", "link", "show", "a1eth1"]).contains(",UP"));

    let mut to = base.clone();
    mtu(&mut to, "a1eth1", 9000);
    add(&mut to, "a1v10", vlan("a1eth1", 10)).mtu = 9000;
    add(&mut to, "a1br", InterfaceKind::Bridge);
    to.interfaces.get_mut(&n("a1eth2")).unwrap().bridge = Some(n("a1br"));
    add(&mut to, "a1lo", InterfaceKind::Loopback);
    add(&mut to, "a1v20", vlan("a1br", 20)).disabled = true;
    addr(&mut to, "a1v10", "10.0.10.1/24");
    addr(&mut to, "a1br", "192.0.2.1/24");
    addr(&mut to, "a1br", "2001:db8:1::1/64");
    addr(&mut to, "a1lo", "10.255.0.1/32");
    hal.apply(&base, &to).unwrap();

    let v10 = ip(&["-d", "-o", "link", "show", "a1v10"]);
    assert!(v10.contains("a1v10@a1eth1"), "{v10}");
    assert!(v10.contains("vlan protocol 802.1Q id 10"), "{v10}");
    assert!(v10.contains("mtu 9000") && v10.contains(",UP"), "{v10}");
    assert!(ip(&["-o", "link", "show", "a1eth1"]).contains("mtu 9000"));
    assert!(ip(&["-o", "link", "show", "a1eth2"]).contains("master a1br"));
    assert!(ip(&["-d", "-o", "link", "show", "a1br"]).contains("bridge"));
    assert!(ip(&["-d", "-o", "link", "show", "a1lo"]).contains("dummy"));
    let v20 = ip(&["-d", "-o", "link", "show", "a1v20"]);
    assert!(v20.contains("a1v20@a1br") && !v20.contains(",UP"), "{v20}");

    let addrs = ip(&["-br", "addr", "show"]);
    for (dev, a) in [
        ("a1v10", "10.0.10.1/24"),
        ("a1br", "192.0.2.1/24"),
        ("a1br", "2001:db8:1::1/64"),
        ("a1lo", "10.255.0.1/32"),
    ] {
        let line = addrs
            .lines()
            .find(|l| {
                l.split_whitespace()
                    .next()
                    .and_then(|d| d.split('@').next())
                    == Some(dev)
            })
            .unwrap_or_else(|| panic!("no {dev} in\n{addrs}"));
        assert!(line.contains(a), "{a} missing on {dev}: {line}");
    }

    // Applying the same transition again is a no-op, not an error.
    hal.apply(&to, &to).unwrap();

    // And back: everything CoreRouter created goes away, ports are restored.
    hal.apply(&to, &base).unwrap();
    for gone in ["a1v10", "a1v20", "a1br", "a1lo"] {
        assert!(!exists(gone), "{gone} still exists");
    }
    let e1 = ip(&["-o", "link", "show", "a1eth1"]);
    assert!(e1.contains("mtu 1500"), "{e1}");
    assert!(!ip(&["-o", "link", "show", "a1eth2"]).contains("master"));
}

#[test]
fn failure_rolls_back_every_done_step() {
    if !in_netns() {
        return;
    }
    port("b1eth1");
    port("b1eth2");
    let mut hal = LinuxHal::new();
    let mut base = Config::default();
    eth(&mut base, "b1eth1");
    eth(&mut base, "b1eth2");
    hal.apply(&Config::default(), &base).unwrap();
    // Other tests share the namespace: look only at this test's links, by
    // name (a MAC like `ce:b1:..` must not match).
    let mine = |args: &[&str]| -> String {
        ip(args)
            .lines()
            .filter(|l| {
                l.split(':')
                    .nth(1)
                    .is_some_and(|name| name.trim().starts_with("b1"))
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let before = mine(&["-d", "-o", "link", "show"]);
    let before_addrs = mine(&["-o", "addr", "show"]);

    // The config believes in a port the kernel does not have (unplugged NIC).
    let mut from = base.clone();
    eth(&mut from, "b1ghost");
    let mut to = from.clone();
    mtu(&mut to, "b1eth1", 1400);
    add(&mut to, "b1v20", vlan("b1eth1", 20)).mtu = 1400;
    add(&mut to, "b1br", InterfaceKind::Bridge);
    to.interfaces.get_mut(&n("b1eth2")).unwrap().bridge = Some(n("b1br"));
    addr(&mut to, "b1eth1", "10.20.0.1/24");
    addr(&mut to, "b1ghost", "10.21.0.1/24");

    let err = hal.apply(&from, &to).unwrap_err().to_string();
    assert!(
        err.contains("add address 10.21.0.1/24 to 'b1ghost'"),
        "{err}"
    );
    assert!(err.contains("does not exist in the kernel"), "{err}");
    assert!(err.contains("rolled back"), "{err}");
    assert!(!err.contains("INCOMPLETE"), "{err}");

    assert!(!exists("b1v20") && !exists("b1br"));
    assert_eq!(mine(&["-d", "-o", "link", "show"]), before);
    assert_eq!(mine(&["-o", "addr", "show"]), before_addrs);
}

#[test]
fn foreign_interfaces_are_never_touched() {
    if !in_netns() {
        return;
    }
    port("c1eth1");
    // Not in any config: must come out exactly as it went in.
    port("c1host");
    ip(&["link", "set", "c1host", "mtu", "1400", "up"]);
    ip(&["addr", "add", "198.51.100.1/24", "dev", "c1host"]);
    let snapshot = || {
        (
            ip(&["-d", "-o", "link", "show", "c1host"]),
            ip(&["-o", "addr", "show", "dev", "c1host"]),
        )
    };
    let before = snapshot();

    let mut hal = LinuxHal::new();
    let mut base = Config::default();
    eth(&mut base, "c1eth1");
    let mut to = base.clone();
    add(&mut to, "c1v5", vlan("c1eth1", 5));
    addr(&mut to, "c1v5", "198.51.100.1/24"); // same prefix as the foreign one
    hal.apply(&Config::default(), &base).unwrap();
    hal.apply(&base, &to).unwrap();
    hal.apply(&to, &base).unwrap();
    assert_eq!(snapshot(), before);

    // A config that claims a kernel link is a bridge it created must not be
    // able to delete a link of another kind.
    port("c1fake");
    let mut claims = Config::default();
    add(&mut claims, "c1fake", InterfaceKind::Bridge);
    let err = hal
        .apply(&claims, &Config::default())
        .unwrap_err()
        .to_string();
    assert!(err.contains("refusing to delete"), "{err}");
    assert!(exists("c1fake"));
}

#[test]
fn existing_links_are_adopted_only_if_they_match() {
    if !in_netns() {
        return;
    }
    port("d1eth1");
    let mut hal = LinuxHal::new();
    let mut cfg = Config::default();
    eth(&mut cfg, "d1eth1");
    add(&mut cfg, "d1v30", vlan("d1eth1", 30));
    addr(&mut cfg, "d1v30", "10.30.0.1/24");
    hal.apply(&Config::default(), &cfg).unwrap();

    // Daemon restart: boot applies default → config over the live kernel.
    hal.apply(&Config::default(), &cfg).unwrap();
    assert!(ip(&["-br", "addr", "show", "dev", "d1v30"]).contains("10.30.0.1/24"));

    // Same name, different VLAN id: not ours to reuse.
    let mut other = Config::default();
    eth(&mut other, "d1eth1");
    add(&mut other, "d1v30", vlan("d1eth1", 31));
    let err = hal
        .apply(&Config::default(), &other)
        .unwrap_err()
        .to_string();
    assert!(err.contains("does not match"), "{err}");
    assert!(ip(&["-d", "-o", "link", "show", "d1v30"]).contains("id 30"));
}

#[test]
fn static_routes_and_link_state() {
    if !in_netns() {
        return;
    }
    port("e1eth1");
    port("e1eth2");
    let mut hal = LinuxHal::new();
    let mut base = Config::default();
    for p in ["e1eth1", "e1eth2"] {
        eth(&mut base, p);
    }
    addr(&mut base, "e1eth1", "10.61.0.2/24");
    addr(&mut base, "e1eth1", "2001:db8:61::2/64");
    hal.apply(&Config::default(), &base).unwrap();

    let mut to = base.clone();
    route(&mut to, "0.0.0.0/0", "10.61.0.1");
    route(&mut to, "::/0", "2001:db8:61::1");
    route(&mut to, "0.0.0.0/0", "10.61.0.254").distance = 10; // backup
    route(&mut to, "198.51.100.0/24", "e1eth2");
    route(&mut to, "2001:db8:99::/48", "fe80::1%e1eth2");
    hal.apply(&base, &to).unwrap();

    let got = routes("e1");
    for want in [
        "default via 10.61.0.1 dev e1eth1",
        "default via 10.61.0.254 dev e1eth1 metric 10",
        "198.51.100.0/24 dev e1eth2",
        "default via 2001:db8:61::1 dev e1eth1",
        "2001:db8:99::/48 via fe80::1 dev e1eth2",
    ] {
        assert!(
            got.iter().any(|l| l.starts_with(want)),
            "missing '{want}' in {got:#?}"
        );
    }
    assert!(
        got.iter()
            .any(|l| l.starts_with("198.51.100.0/24") && l.contains("scope link"))
    );
    assert_eq!(got.len(), 5, "{got:#?}");

    // Applying again (or a daemon restart over the live kernel) changes nothing.
    hal.apply(&to, &to).unwrap();
    hal.apply(&Config::default(), &to).unwrap();
    assert_eq!(routes("e1"), got);

    // The kernel flushes routes (and IPv6 addresses) of a link that goes
    // down; disabling and enabling e1eth1 must end with every route back.
    let mut down = to.clone();
    down.interfaces.get_mut(&n("e1eth1")).unwrap().disabled = true;
    hal.apply(&to, &down).unwrap();
    assert!(!routes("e1").iter().any(|l| l.contains("dev e1eth1")));
    hal.apply(&down, &to).unwrap();
    assert_eq!(routes("e1"), got);

    hal.apply(&to, &base).unwrap();
    assert!(routes("e1").is_empty(), "{:#?}", routes("e1"));
}

/// Whether this kernel can create a `vrf` link (the module may be missing,
/// and a user namespace cannot load it). Checked once, with `ip`, so it is
/// independent of our netlink code.
fn kernel_has_vrf() -> bool {
    static HAS: OnceLock<bool> = OnceLock::new();
    *HAS.get_or_init(|| {
        let ok = Command::new("ip")
            .args(["link", "add", "vrfprobe", "type", "vrf", "table", "4242"])
            .output()
            .unwrap()
            .status
            .success();
        if ok {
            ip(&["link", "del", "vrfprobe"]);
        }
        ok
    })
}

/// Gate for VRF tests: without kernel VRF they skip, loudly — or fail, if
/// `COREROUTER_REQUIRE_VRF=1`, so a broken module load cannot pass silently.
fn has_vrf() -> bool {
    if kernel_has_vrf() {
        return true;
    }
    assert!(
        std::env::var_os(REQUIRE_VRF).is_none_or(|v| v != "1"),
        "{REQUIRE_VRF}=1 but this kernel cannot create a vrf link \
         (CONFIG_NET_VRF / module vrf; on the host: modprobe vrf)"
    );
    eprintln!("skipped: this kernel has no vrf support (CONFIG_NET_VRF / module vrf)");
    false
}

#[test]
fn features_probe_matches_the_kernel_and_leaves_nothing() {
    if !in_netns() {
        return;
    }
    let hal = LinuxHal::new();
    // Both answers are valid here; they just have to agree.
    assert_eq!(hal.features().vrf, kernel_has_vrf());
    assert_eq!(hal.features(), hal.features());
    let links = ip(&["-o", "link", "show"]);
    assert!(!links.contains("crvrf"), "probe link left behind:\n{links}");
}

#[test]
fn vrf_routes_live_in_their_own_table() {
    if !in_netns() || !has_vrf() {
        return;
    }
    port("g1eth1");
    port("g1eth2");
    let mut hal = LinuxHal::new();
    let mut base = Config::default();
    eth(&mut base, "g1eth1");
    eth(&mut base, "g1eth2");
    addr(&mut base, "g1eth1", "10.64.0.2/24");
    hal.apply(&Config::default(), &base).unwrap();

    // A VRF with its own copy of 10.64.0.0/24 and its own default route,
    // next to main's. Distance 5: tests share one namespace and run in
    // parallel, and `static_routes_and_link_state` puts main's default at
    // metrics 1 and 10 (same destination + metric = EEXIST).
    let mut to = base.clone();
    route(&mut to, "0.0.0.0/0", "10.64.0.1").distance = 5;
    add(&mut to, "g1blue", InterfaceKind::Vrf { table: 1064 });
    to.interfaces.get_mut(&n("g1eth2")).unwrap().vrf = Some(n("g1blue"));
    addr(&mut to, "g1eth2", "10.64.0.2/24");
    addr(&mut to, "g1eth2", "2001:db8:64::2/64");
    let r = route(&mut to, "0.0.0.0/0", "10.64.0.9");
    r.routing_table = RoutingTable::Vrf(n("g1blue"));
    hal.apply(&base, &to).unwrap();

    let got = routes("g1");
    assert!(
        got.iter()
            .any(|l| l.starts_with("default via 10.64.0.1 dev g1eth1")),
        "{got:#?}"
    );
    assert!(
        got.contains(&"default via 10.64.0.9 dev g1eth2 table 1064 metric 1".to_owned()),
        "{got:#?}"
    );
    let vrf = ip(&["-d", "-o", "link", "show", "g1blue"]);
    assert!(vrf.contains("vrf table 1064"), "{vrf}");
    assert!(ip(&["-o", "link", "show", "g1eth2"]).contains("master g1blue"));
    // Connected routes and the IPv6 address follow the member into the VRF.
    assert!(ip(&["route", "show", "table", "1064"]).contains("10.64.0.0/24 dev g1eth2"));
    assert!(ip(&["-o", "addr", "show", "dev", "g1eth2"]).contains("2001:db8:64::2/64"));

    hal.apply(&to, &to).unwrap();
    hal.apply(&Config::default(), &to).unwrap();
    assert_eq!(routes("g1"), got);

    // Back: routes gone, VRF deleted, g1eth2 released.
    hal.apply(&to, &base).unwrap();
    assert!(routes("g1").is_empty(), "{:#?}", routes("g1"));
    assert!(!exists("g1blue"));
    assert!(!ip(&["-o", "link", "show", "g1eth2"]).contains("master"));
}

#[test]
fn a_conflicting_kernel_route_rolls_the_apply_back() {
    if !in_netns() {
        return;
    }
    port("f1eth1");
    let mut hal = LinuxHal::new();
    let mut base = Config::default();
    eth(&mut base, "f1eth1");
    addr(&mut base, "f1eth1", "10.62.0.2/24");
    hal.apply(&Config::default(), &base).unwrap();
    // Someone else's route to the same prefix with the same metric.
    ip(&[
        "route",
        "add",
        "203.0.113.0/24",
        "via",
        "10.62.0.99",
        "dev",
        "f1eth1",
        "metric",
        "1",
        "proto",
        "static",
    ]);
    let foreign = routes("f1");
    let addrs = ip(&["-o", "addr", "show", "dev", "f1eth1"]);

    let mut to = base.clone();
    addr(&mut to, "f1eth1", "10.63.0.2/24");
    route(&mut to, "192.0.2.0/24", "10.62.0.1");
    route(&mut to, "203.0.113.0/24", "10.62.0.1");
    let err = hal.apply(&base, &to).unwrap_err().to_string();
    assert!(
        err.contains("already has another route to 203.0.113.0/24"),
        "{err}"
    );
    assert!(
        err.contains("rolled back") && !err.contains("INCOMPLETE"),
        "{err}"
    );
    // Our route and address are gone again; the foreign route is untouched.
    assert_eq!(routes("f1"), foreign);
    assert_eq!(ip(&["-o", "addr", "show", "dev", "f1eth1"]), addrs);

    // Removing a route that is already gone is not an error either.
    let mut with = base.clone();
    route(&mut with, "192.0.2.0/24", "10.62.0.1");
    hal.apply(&base, &with).unwrap();
    ip(&["route", "del", "192.0.2.0/24", "dev", "f1eth1"]);
    hal.apply(&with, &base).unwrap();
}
