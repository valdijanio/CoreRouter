//! G3.4za: the FIB entry of a management session's replies when the
//! management port is in a VRF, read from the kernel in a throwaway network
//! namespace, no root (its own binary: each netns binary gets one fresh
//! namespace).
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_fib_match_vrf
//! ```
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::IpAddr;
use std::process::Command;

use corerouter_hal::route_get::{is_learned_protocol, protocol_name};
use corerouter_hal_linux::fib_match::lookup_in;

const ENV: &str = "COREROUTER_NETNS_TESTS";

/// Only in a fresh namespace (just `lo`): never on the host.
fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!(
            "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` (cargo xtask netns)"
        );
        return false;
    }
    let out = Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let names: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split(':').nth(1))
        .map(str::trim)
        .collect();
    assert_eq!(
        names,
        ["lo"],
        "{ENV}=1 but this namespace is not fresh; refusing to touch it"
    );
    true
}

fn ip(args: &[&str]) {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn a(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// G3.4za: a management port in a VRF. Without the VRF the lookup goes to
/// main and misses the cut; with it (`ip route get … vrf mgmt`) the l3mdev
/// rule takes it to the VRF's table, where zebra installs the VRF's routes.
#[test]
fn a_learned_host_route_inside_a_vrf_is_seen_in_its_table() {
    if !in_netns() {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", "mgmt", "type", "vrf", "table", "100"]);
    ip(&["link", "set", "mgmt", "up"]);
    for (name, addr) in [("mg0", "10.99.0.1/24"), ("lab0", "10.0.1.1/30")] {
        ip(&["link", "add", name, "type", "dummy"]);
        ip(&["link", "set", name, "master", "mgmt"]);
        ip(&["addr", "add", addr, "dev", name]);
        ip(&["link", "set", name, "up"]);
    }
    let vrf = || Some("mgmt".parse().unwrap());
    let me = (a("10.99.0.2"), Some(a("10.99.0.1")), vrf());
    let before = lookup_in(std::slice::from_ref(&me))
        .unwrap()
        .remove(0)
        .unwrap();
    assert_eq!(
        before.prefix.unwrap().to_string(),
        "10.99.0.0/24",
        "{before:?}"
    );
    assert_eq!(before.interface.as_ref().unwrap().as_str(), "mg0");
    // What zebra installs for a BGP route of the VRF (`proto bgp`, table 100).
    ip(&[
        "route",
        "add",
        "10.99.0.2/32",
        "via",
        "10.0.1.2",
        "dev",
        "lab0",
        "proto",
        "bgp",
        "table",
        "100",
    ]);
    let got = lookup_in(&[
        me,
        (a("10.99.0.2"), Some(a("10.99.0.1")), None),
        (
            a("10.99.0.2"),
            Some(a("10.99.0.1")),
            Some("nosuch".parse().unwrap()),
        ),
    ])
    .unwrap();
    let cut = got[0].as_ref().unwrap();
    assert_eq!(cut.prefix.unwrap().to_string(), "10.99.0.2/32");
    assert_eq!(protocol_name(cut.protocol), "bgp");
    assert!(is_learned_protocol(cut.protocol));
    assert_eq!(cut.interface.as_ref().unwrap().as_str(), "lab0");
    // In main (no VRF given) the address is not even reachable.
    assert_ne!(
        got[1]
            .as_ref()
            .ok()
            .and_then(|e| e.prefix)
            .map(|p| p.to_string()),
        Some("10.99.0.2/32".to_owned()),
        "main must not see the VRF's route: {:?}",
        got[1]
    );
    let e = got[2].as_ref().unwrap_err();
    assert!(e.contains("not in the kernel"), "{e}");
}
