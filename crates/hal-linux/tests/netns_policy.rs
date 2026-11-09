//! G1.27e against a real kernel, in a throwaway network namespace (no root,
//! nothing reaches the host; `cargo xtask netns` runs it): routes in a named
//! `/routing table` land in its kernel table, through main's networks.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;
use std::sync::OnceLock;

use corerouter_hal::Hal;
use corerouter_hal::drift;
use corerouter_hal_linux::LinuxHal;
use corerouter_model::routing_table::NamedTable;
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

/// A dummy port `port` with `address`.
fn port(c: &mut Config, port: &str, address: &str) {
    ip(&["link", "add", port, "type", "dummy"]);
    c.interfaces
        .insert(n(port), Interface::new(n(port), InterfaceKind::Ethernet));
    let id = c.ip.next_address_id();
    c.ip.addresses.push(AddressEntry {
        id,
        address: address.parse().unwrap(),
        interface: n(port),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
}

fn table(c: &mut Config, name: &str, id: u32) {
    c.routing.tables.insert(
        n(name),
        NamedTable {
            name: n(name),
            table: id,
            comment: String::new(),
        },
    );
}

fn route(c: &mut Config, dst: &str, gw: &str, table: &str) {
    let id = c.ip.next_route_id();
    c.ip.routes.push(RouteEntry {
        id,
        dst_address: dst.parse().unwrap(),
        gateway: gw.parse().unwrap(),
        distance: 1,
        routing_table: table.parse::<RoutingTable>().unwrap(),
        disabled: false,
        comment: String::new(),
        check_gateway: Default::default(),
        bfd_profile: String::new(),
    });
}

#[test]
fn a_route_lands_in_the_kernel_table_of_its_named_table() {
    if !in_netns() {
        return;
    }
    let mut hal = LinuxHal::new();
    let mut base = Config::default();
    port(&mut base, "tbl0", "10.71.0.2/24");
    hal.apply(&Config::default(), &base).unwrap();

    let mut to = base.clone();
    table(&mut to, "isp2", 1000);
    route(&mut to, "0.0.0.0/0", "10.71.0.1", "isp2");
    route(&mut to, "203.0.113.0/24", "blackhole", "isp2");
    hal.apply(&base, &to).unwrap();

    let t = ip(&["route", "show", "table", "1000"]);
    assert!(t.contains("default via 10.71.0.1 dev tbl0"), "{t}");
    assert!(t.contains("blackhole 203.0.113.0/24"), "{t}");
    let main = ip(&["route", "show", "default"]);
    assert_eq!(main, "", "main stays without a default route");
    let have = hal.snapshot(&to).unwrap();
    assert_eq!(
        drift::diff(&drift::expected(&to), &have),
        vec![],
        "{have:?}"
    );

    hal.apply(&to, &base).unwrap();
    assert_eq!(ip(&["route", "show", "table", "1000"]), "");
}
