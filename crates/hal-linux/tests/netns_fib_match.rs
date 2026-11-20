//! G3.4z: the FIB entry of a management session's replies, read from the
//! kernel in a throwaway network namespace, no root. The phase C case: an
//! OSPF `/32` (as zebra installs it, `proto ospf`) over the connected `/24`
//! of the management port takes the replies to the operator elsewhere.
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_fib_match
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
use std::time::Instant;

use corerouter_hal::route_get::{RouteKind, is_learned_protocol, protocol_name};
use corerouter_hal_linux::fib_match::lookup;

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

#[test]
fn a_learned_host_route_over_the_management_network_is_seen() {
    if !in_netns() {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    for (name, addr) in [("mg0", "192.168.0.1/24"), ("lab0", "10.0.1.1/30")] {
        ip(&["link", "add", name, "type", "dummy"]);
        ip(&["addr", "add", addr, "dev", name]);
        ip(&["link", "set", name, "up"]);
    }
    let me = (a("192.168.0.2"), Some(a("192.168.0.1")));
    let before = lookup(&[me]).unwrap().remove(0).unwrap();
    assert_eq!(before.kind, RouteKind::Unicast);
    assert_eq!(before.prefix.unwrap().to_string(), "192.168.0.0/24");
    assert_eq!(protocol_name(before.protocol), "kernel");
    assert!(!is_learned_protocol(before.protocol));
    assert_eq!(before.interface.unwrap().as_str(), "mg0");

    // What zebra installs for an OSPF route (`proto ospf`, metric 20).
    ip(&[
        "route",
        "add",
        "192.168.0.2/32",
        "via",
        "10.0.1.2",
        "dev",
        "lab0",
        "proto",
        "ospf",
        "metric",
        "20",
    ]);
    let after = lookup(&[me, (a("192.168.0.9"), Some(a("192.168.0.1")))]).unwrap();
    let cut = after[0].as_ref().unwrap();
    assert_eq!(cut.prefix.unwrap().to_string(), "192.168.0.2/32");
    assert_eq!(protocol_name(cut.protocol), "ospf");
    assert!(is_learned_protocol(cut.protocol));
    assert_eq!(cut.interface.as_ref().unwrap().as_str(), "lab0");
    assert_eq!(cut.gateway, Some(a("10.0.1.2")));
    let other = after[1].as_ref().unwrap();
    assert_eq!(
        other.prefix.unwrap().to_string(),
        "192.168.0.0/24",
        "another peer of the /24 is not covered"
    );

    // A static route of CoreRouter is the operator's own.
    ip(&[
        "route",
        "add",
        "192.168.0.7/32",
        "via",
        "10.0.1.2",
        "dev",
        "lab0",
        "proto",
        "static",
    ]);
    let st = lookup(&[(a("192.168.0.7"), None)])
        .unwrap()
        .remove(0)
        .unwrap();
    assert_eq!(
        (protocol_name(st.protocol), is_learned_protocol(st.protocol)),
        ("static", false)
    );

    // No route at all, and a blackhole.
    ip(&[
        "route",
        "add",
        "blackhole",
        "203.0.113.0/24",
        "proto",
        "bgp",
    ]);
    let got = lookup(&[(a("198.51.100.1"), None), (a("203.0.113.5"), None)]).unwrap();
    assert_eq!(got[0].as_ref().unwrap().kind, RouteKind::Unreachable);
    assert_eq!(got[1].as_ref().unwrap().kind, RouteKind::Blackhole);

    // The cost the service pays per tick: one request per distinct pair
    // (printed for the `## perf` of docs/changes/G3.4z.md).
    let many: Vec<_> = (0..256u32)
        .map(|i| {
            (
                IpAddr::from([192, 168, 0, (i % 250 + 2) as u8]),
                Some(a("192.168.0.1")),
            )
        })
        .collect();
    let t = Instant::now();
    let got = lookup(&many).unwrap();
    let took = t.elapsed();
    assert!(got.iter().all(Result::is_ok));
    eprintln!("fib_match: 256 lookups in {took:?} ({:?} each)", took / 256);
}
