//! Ports that are not there (G1.3b) against a real kernel, inside a
//! throwaway network namespace: a config restored with a port missing
//! brings the rest up (the management address first of all), a port that
//! goes away does not make the next apply fail, and one that comes back
//! gets its configuration on the next apply. `dummy` links stand in for
//! the NICs. Run by `cargo xtask netns` (see `tests/netns.rs` for the
//! guard); the tests share the namespace, so each has its own link names
//! (prefix) and subnets.
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

/// True when the tests may touch the kernel; panics outside a fresh
/// namespace (anything but `lo` there when the first test looks).
fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!("skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net`");
        return false;
    }
    static FRESH: OnceLock<Vec<String>> = OnceLock::new();
    let names = FRESH.get_or_init(|| {
        ip(&["-o", "link", "show"])
            .lines()
            .filter_map(|l| l.split(':').nth(1))
            .map(|n| n.trim().to_owned())
            .collect()
    });
    assert_eq!(names, &["lo"], "{ENV}=1 outside a fresh network namespace");
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

fn route(cfg: &mut Config, dst: &str, gateway: &str) {
    let id = cfg.ip.next_route_id();
    cfg.ip.routes.push(RouteEntry {
        id,
        dst_address: dst.parse().unwrap(),
        gateway: gateway.parse().unwrap(),
        distance: 1,
        routing_table: RoutingTable::Main,
        disabled: false,
        comment: String::new(),
        check_gateway: Default::default(),
        bfd_profile: String::new(),
    });
}

/// One test's names and subnets: `<x>m1` is the management port, `<x>p2`
/// the port that goes away (with a VLAN, an address, a route through it
/// and its own MTU), `<x>p3` a port of bridge `<x>br`.
struct Lab {
    x: &'static str,
    k: u8,
}

impl Lab {
    fn name(&self, s: &str) -> String {
        format!("{}{s}", self.x)
    }

    fn net(&self, third: u8, host: u8) -> String {
        format!("10.{}.{third}.{host}", self.k)
    }

    fn add(&self, names: &[&str]) {
        for p in names {
            ip(&["link", "add", &self.name(p), "type", "dummy"]);
        }
    }

    fn del(&self, name: &str) {
        ip(&["link", "del", &self.name(name)]);
    }

    fn config(&self) -> Config {
        let mut cfg = Config::default();
        let mut iface = |name: String, kind| {
            cfg.interfaces
                .insert(n(&name), Interface::new(n(&name), kind));
        };
        for p in ["m1", "p2", "p3"] {
            iface(self.name(p), InterfaceKind::Ethernet);
        }
        iface(
            self.name("p2v20"),
            InterfaceKind::Vlan {
                parent: n(&self.name("p2")),
                vlan_id: VlanId::new(20).unwrap(),
                service_tag: false,
            },
        );
        iface(self.name("br"), InterfaceKind::Bridge);
        cfg.interfaces.get_mut(&n(&self.name("p2"))).unwrap().mtu = 1400;
        cfg.interfaces.get_mut(&n(&self.name("p2v20"))).unwrap().mtu = 1400;
        cfg.interfaces.get_mut(&n(&self.name("p3"))).unwrap().bridge = Some(n(&self.name("br")));
        addr(
            &mut cfg,
            &self.name("m1"),
            &format!("{}/24", self.net(0, 2)),
        );
        addr(
            &mut cfg,
            &self.name("p2"),
            &format!("{}/24", self.net(2, 1)),
        );
        addr(
            &mut cfg,
            &self.name("p2v20"),
            &format!("{}/24", self.net(20, 1)),
        );
        route(&mut cfg, &format!("192.0.{}.0/24", self.k), &self.net(0, 1));
        route(
            &mut cfg,
            &format!("198.51.{}.0/24", self.k),
            &self.net(2, 254),
        );
        cfg
    }

    fn has_addr(&self, dev: &str, a: &str) -> bool {
        ip(&["-o", "addr", "show", "dev", &self.name(dev)]).contains(a)
    }

    fn exists(&self, dev: &str) -> bool {
        Command::new("ip")
            .args(["link", "show", "dev", &self.name(dev)])
            .output()
            .unwrap()
            .status
            .success()
    }

    fn link(&self, dev: &str) -> String {
        ip(&["-o", "link", "show", "dev", &self.name(dev)])
    }

    /// What the config puts on the management port and the bridge.
    fn rest_is_up(&self) {
        assert!(
            self.has_addr("m1", &format!("{}/24", self.net(0, 2))),
            "management address"
        );
        let routes = ip(&["route", "show"]);
        let want = format!(
            "192.0.{}.0/24 via {} dev {}",
            self.k,
            self.net(0, 1),
            self.name("m1")
        );
        assert!(routes.contains(&want), "{routes}");
        assert!(
            self.link("p3")
                .contains(&format!("master {}", self.name("br")))
        );
    }

    /// What the config puts on `p2`, all of it.
    fn p2_is_configured(&self) {
        assert!(self.link("p2").contains("mtu 1400"));
        assert!(self.has_addr("p2", &format!("{}/24", self.net(2, 1))));
        assert!(self.exists("p2v20"));
        assert!(self.has_addr("p2v20", &format!("{}/24", self.net(20, 1))));
        let routes = ip(&["route", "show"]);
        let want = format!(
            "198.51.{}.0/24 via {} dev {}",
            self.k,
            self.net(2, 254),
            self.name("p2")
        );
        assert!(routes.contains(&want), "{routes}");
    }

    fn p2(&self) -> IfName {
        n(&self.name("p2"))
    }
}

const NONE: [IfName; 0] = [];

#[test]
fn boot_with_a_port_missing_brings_up_the_rest_and_the_port_later() {
    if !in_netns() {
        return;
    }
    let l = Lab { x: "ab", k: 61 };
    l.add(&["m1", "p3"]);
    let cfg = l.config();
    let mut hal = LinuxHal::new();
    // The boot apply: before G1.3b, the ops on `p2` failed and the whole
    // apply went back, management address included.
    hal.apply(&Config::default(), &cfg).unwrap();
    l.rest_is_up();
    assert!(!l.exists("p2v20"), "no VLAN without its parent");
    assert_eq!(hal.absent_ports(), [l.p2()]);
    // The card shows up.
    l.add(&["p2"]);
    hal.poll();
    hal.apply(&cfg, &cfg).unwrap();
    l.p2_is_configured();
    l.rest_is_up();
    assert_eq!(hal.absent_ports(), NONE);
}

#[test]
fn a_port_that_goes_away_and_comes_back() {
    if !in_netns() {
        return;
    }
    let l = Lab { x: "ag", k: 62 };
    l.add(&["m1", "p2", "p3"]);
    let cfg = l.config();
    let mut hal = LinuxHal::new();
    hal.apply(&Config::default(), &cfg).unwrap();
    l.p2_is_configured();
    // Unplugged: the kernel takes its VLAN, addresses and routes along.
    l.del("p2");
    hal.poll();
    assert_eq!(hal.absent_ports(), [l.p2()]);
    // A commit that touches the absent port (its address changes, another
    // one comes on the management port): before G1.3b, "remove address
    // from p2" failed and the commit with it.
    let mut next = cfg.clone();
    next.ip.addresses.retain(|a| a.interface != l.p2());
    addr(&mut next, &l.name("p2"), &format!("{}/24", l.net(2, 9)));
    addr(&mut next, &l.name("m1"), &format!("{}/24", l.net(1, 2)));
    hal.apply(&cfg, &next).unwrap();
    assert!(l.has_addr("m1", &format!("{}/24", l.net(1, 2))));
    l.rest_is_up();
    // Back: the next apply (the engine's, on the poll that sees it) gives
    // it what the config says now.
    l.add(&["p2"]);
    hal.poll();
    hal.apply(&next, &next).unwrap();
    assert!(l.has_addr("p2", &format!("{}/24", l.net(2, 9))));
    assert!(!l.has_addr("p2", &format!("{}/24", l.net(2, 1))));
    assert!(l.exists("p2v20") && l.has_addr("p2v20", &format!("{}/24", l.net(20, 1))));
    assert!(l.link("p2").contains("mtu 1400"));
    assert_eq!(hal.absent_ports(), NONE);
    // Gone again and taken out of the config: nothing waits for it.
    l.del("p2");
    hal.poll();
    let (p2, v20) = (l.p2(), n(&l.name("p2v20")));
    let mut gone = next.clone();
    gone.interfaces.remove(&v20);
    gone.interfaces.remove(&p2);
    gone.ip
        .addresses
        .retain(|a| a.interface != p2 && a.interface != v20);
    let via_p2: ipnet::IpNet = format!("198.51.{}.0/24", l.k).parse().unwrap();
    gone.ip.routes.retain(|r| r.dst_address != via_p2);
    hal.apply(&next, &gone).unwrap();
    assert_eq!(hal.absent_ports(), NONE);
    l.rest_is_up();
}

#[test]
fn a_port_gone_between_polls_is_found_by_the_retry() {
    if !in_netns() {
        return;
    }
    let l = Lab { x: "ar", k: 63 };
    l.add(&["m1", "p2", "p3"]);
    let cfg = l.config();
    let mut hal = LinuxHal::new();
    hal.apply(&Config::default(), &cfg).unwrap();
    // Gone with no poll since: the apply below skips the link dump (the
    // interfaces did not change), fails adding the address to `p2` and
    // looks on the retry.
    l.del("p2");
    let mut next = cfg.clone();
    next.ip.addresses.retain(|a| a.interface != l.p2());
    addr(&mut next, &l.name("p2"), &format!("{}/24", l.net(2, 9)));
    addr(&mut next, &l.name("m1"), &format!("{}/24", l.net(1, 2)));
    hal.apply(&cfg, &next).unwrap();
    assert!(l.has_addr("m1", &format!("{}/24", l.net(1, 2))));
    l.rest_is_up();
    assert_eq!(
        hal.absent_ports(),
        [l.p2()],
        "found by the retry, before any poll"
    );
}
