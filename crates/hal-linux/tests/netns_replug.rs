//! A port that goes and comes back between two polls (G1.3d): a fast
//! replug, a USB adapter whose driver was reset. The kernel took its
//! configuration along, and the 1 s poll never saw it gone. Inside a
//! throwaway network namespace; `dummy` links stand in for the NICs. Run
//! by `cargo xtask netns` (see `tests/netns.rs` for the guard).
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;
use std::sync::OnceLock;

use corerouter_hal::Hal;
use corerouter_hal_linux::LinuxHal;
use corerouter_model::{AddressEntry, Config, IfName, Interface, InterfaceKind};

const ENV: &str = "COREROUTER_NETNS_TESTS";

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

#[test]
fn a_port_back_before_the_next_poll_gets_its_configuration() {
    if !in_netns() {
        return;
    }
    for p in ["rp1", "rp2"] {
        ip(&["link", "add", p, "type", "dummy"]);
    }
    let mut cfg = Config::default();
    for p in ["rp1", "rp2"] {
        cfg.interfaces
            .insert(n(p), Interface::new(n(p), InterfaceKind::Ethernet));
    }
    cfg.interfaces.get_mut(&n("rp2")).unwrap().mtu = 1400;
    for (on, a) in [("rp1", "10.71.0.2/24"), ("rp2", "10.71.2.1/24")] {
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
    let mut hal = LinuxHal::new();
    hal.apply(&Config::default(), &cfg).unwrap();
    hal.poll();
    assert!(ip(&["-o", "addr", "show", "dev", "rp2"]).contains("10.71.2.1/24"));
    // Gone and back between two polls: same name, no configuration.
    ip(&["link", "del", "rp2"]);
    ip(&["link", "add", "rp2", "type", "dummy"]);
    assert!(!ip(&["-o", "addr", "show", "dev", "rp2"]).contains("10.71.2.1/24"));
    hal.poll();
    // The engine puts the configuration back on what the backend reports
    // absent (`absent_tick`): the port must be reported.
    assert_eq!(
        hal.absent_ports(),
        [n("rp2")],
        "the poll after the replug must see that rp2 is a new link"
    );
    hal.apply(&cfg, &cfg).unwrap();
    assert!(ip(&["-o", "addr", "show", "dev", "rp2"]).contains("10.71.2.1/24"));
    assert!(ip(&["-o", "link", "show", "dev", "rp2"]).contains("mtu 1400"));
    assert!(hal.absent_ports().is_empty());
}

#[test]
fn link_events_name_the_replugged_port() {
    use corerouter_hal_linux::link_events::{Events, LinkEvents};
    if !in_netns() {
        return;
    }
    ip(&["link", "add", "rq1", "type", "dummy"]);
    let mut feed = LinkEvents::open().unwrap();
    // The other test shares the namespace: only rq1 counts here.
    let rq1 = |e: &Events| matches!(e, Events::Names(n) if n.contains("rq1"));
    assert!(
        !rq1(&feed.wait(1).unwrap()),
        "nothing while nothing changes"
    );
    ip(&["link", "del", "rq1"]);
    ip(&["link", "add", "rq1", "type", "dummy"]);
    // Both already queued when `ip` returned (**medido**: < 1.5 ms).
    match feed.wait(1000).unwrap() {
        Events::Names(n) => assert!(n.contains("rq1"), "{n:?}"),
        other => panic!("{other:?}"),
    }
    assert!(!rq1(&feed.wait(1).unwrap()), "one wait took the burst");
}
