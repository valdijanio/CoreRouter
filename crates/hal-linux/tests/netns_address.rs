//! G1.28 against a real kernel, in a throwaway network namespace (no root,
//! nothing reaches the host; `cargo xtask netns` runs it):
//!
//! - a disabled address leaves the kernel and comes back;
//! - IPv6 DAD (RFC 4862 §5.4) shows as tentative, then clears or fails;
//! - the ARP probe (RFC 5227) finds the host that holds an address.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use corerouter_hal::Hal;
use corerouter_hal::address_state::AddressState;
use corerouter_hal_linux::LinuxHal;
use corerouter_model::{AddressEntry, Config, IfName, Interface, InterfaceKind};

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
        let text = ip(&["-o", "link", "show"]);
        let first: Vec<&str> = text
            .lines()
            .filter_map(|l| l.split(':').nth(1))
            .map(str::trim)
            .collect();
        if first == ["lo"] {
            Ok(())
        } else {
            Err(format!(
                "{ENV}=1 but this network namespace has {first:?}, not just lo; refusing to \
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

fn n(s: &str) -> IfName {
    s.parse().unwrap()
}

/// `cfg` managing the ports `names`, each with no address.
fn ports(names: &[&str]) -> Config {
    let mut cfg = Config::default();
    for p in names {
        cfg.interfaces
            .insert(n(p), Interface::new(n(p), InterfaceKind::Ethernet));
    }
    cfg
}

fn addr(cfg: &mut Config, iface: &str, a: &str) -> usize {
    let id = cfg.ip.next_address_id();
    cfg.ip.addresses.push(AddressEntry {
        id,
        address: a.parse().unwrap(),
        interface: n(iface),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
    cfg.ip.addresses.len() - 1
}

/// A veth pair: `a` (ours) and `b` (the other host), both up.
fn veth(a: &str, b: &str) {
    ip(&["link", "add", a, "type", "veth", "peer", "name", b]);
    ip(&["link", "set", b, "up"]);
}

fn states_of(hal: &mut LinuxHal, a: &str) -> Option<AddressState> {
    hal.address_states()
        .unwrap()
        .into_iter()
        .find(|s| s.address.to_string() == a)
}

#[test]
fn a_disabled_address_leaves_the_kernel_and_comes_back() {
    if !in_netns() {
        return;
    }
    ip(&["link", "add", "a3d0", "type", "dummy"]);
    let mut hal = LinuxHal::new();
    let base = ports(&["a3d0"]);
    hal.apply(&Config::default(), &base).unwrap();
    let mut on = base.clone();
    let i = addr(&mut on, "a3d0", "10.3.0.1/24");
    hal.apply(&base, &on).unwrap();
    assert!(ip(&["-o", "addr", "show", "dev", "a3d0"]).contains("10.3.0.1/24"));

    let mut off = on.clone();
    off.ip.addresses.get_mut(i).unwrap().disabled = true;
    hal.apply(&on, &off).unwrap();
    assert!(!ip(&["-o", "addr", "show", "dev", "a3d0"]).contains("10.3.0.1"));
    hal.apply(&off, &on).unwrap();
    assert!(ip(&["-o", "addr", "show", "dev", "a3d0"]).contains("10.3.0.1/24"));
    hal.apply(&on, &base).unwrap();
}

#[test]
fn ipv6_dad_is_tentative_then_active_or_failed() {
    if !in_netns() {
        return;
    }
    veth("a3v0", "a3v1");
    // The other host already holds ::2 (no DAD of its own).
    ip(&["addr", "add", "2001:db8:3::2/64", "dev", "a3v1", "nodad"]);
    let mut hal = LinuxHal::new();
    let base = ports(&["a3v0"]);
    hal.apply(&Config::default(), &base).unwrap();
    let mut to = base.clone();
    addr(&mut to, "a3v0", "2001:db8:3::1/64");
    addr(&mut to, "a3v0", "2001:db8:3::2/64");
    hal.apply(&base, &to).unwrap();
    let fresh = states_of(&mut hal, "2001:db8:3::1/64").expect("DAD running");
    assert!(fresh.tentative && !fresh.dad_failed, "{fresh:?}");

    // RetransTimer is 1 s and one probe: settled within a few.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let free = states_of(&mut hal, "2001:db8:3::1/64");
        let dup = states_of(&mut hal, "2001:db8:3::2/64");
        if free.is_none() && dup.as_ref().is_some_and(|d| d.dad_failed) {
            break;
        }
        assert!(Instant::now() < deadline, "free {free:?}, duplicate {dup:?}");
        std::thread::sleep(Duration::from_millis(200));
    }
    hal.apply(&to, &base).unwrap();
}

#[test]
fn the_arp_probe_finds_who_holds_an_address() {
    if !in_netns() {
        return;
    }
    veth("a3p0", "a3p1");
    ip(&["addr", "add", "10.4.0.2/24", "dev", "a3p1"]);
    let mut hal = LinuxHal::new();
    let base = ports(&["a3p0"]);
    hal.apply(&Config::default(), &base).unwrap();
    let mac = ip(&["-o", "link", "show", "a3p1"]);

    let found = |hal: &mut LinuxHal, target: Ipv4Addr| {
        let mut port = hal.dhcp_port(&n("a3p0")).unwrap();
        assert!(port.probe(target).unwrap());
        let deadline = Instant::now() + Duration::from_millis(1500);
        let mut got = None;
        while got.is_none() && Instant::now() < deadline {
            got = port.conflict().unwrap();
            std::thread::sleep(Duration::from_millis(50));
        }
        port.end_probe();
        got
    };
    let taken = found(&mut hal, Ipv4Addr::new(10, 4, 0, 2)).expect("a3p1 answers");
    let text = taken
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    assert!(mac.contains(&text), "{text} not in {mac}");
    assert_eq!(found(&mut hal, Ipv4Addr::new(10, 4, 0, 3)), None, "nobody holds .3");
    hal.apply(&base, &Config::default()).unwrap();
}
