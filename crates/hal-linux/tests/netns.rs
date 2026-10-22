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
use corerouter_model::{AddressEntry, Config, IfName, Interface, InterfaceKind, VlanId};

const ENV: &str = "COREROUTER_NETNS_TESTS";

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
    // Other tests share the namespace: look only at this test's links.
    let mine = |args: &[&str]| -> String {
        ip(args)
            .lines()
            .filter(|l| l.contains("b1"))
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
