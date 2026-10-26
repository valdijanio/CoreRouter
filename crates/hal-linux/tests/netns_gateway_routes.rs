//! G4.3cd: the kernel routes of blocks routed to IPoE subscribers
//! (`pppoe_io::gateway_routes`: `prefix via subscriber`) made and removed
//! for real, in a throwaway network namespace, no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_gateway_routes
//! ```
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::Ipv4Addr;
use std::process::Command;

use corerouter_hal_linux::pppoe_io::gateway_routes;

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

fn ip(args: &[&str]) -> String {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn routed_blocks_go_via_the_subscriber_and_leave() {
    if !in_netns() {
        return;
    }
    ip(&["link", "add", "acc9", "type", "dummy"]);
    ip(&["addr", "add", "192.168.88.1/24", "dev", "acc9"]);
    ip(&["link", "set", "acc9", "up"]);
    let sub = Ipv4Addr::new(192, 168, 88, 20);
    let block = Ipv4Addr::new(203, 0, 113, 8);
    gateway_routes(&[
        (block, 29, sub, true),
        (Ipv4Addr::new(198, 51, 100, 0), 30, sub, true),
    ])
    .unwrap();
    let r = ip(&["-4", "route", "show", "203.0.113.8/29"]);
    assert!(r.contains("via 192.168.88.20 dev acc9"), "{r}");
    // Made again (a session that comes back): replaced, no error.
    gateway_routes(&[(block, 29, sub, true)]).unwrap();
    gateway_routes(&[
        (block, 29, sub, false),
        (Ipv4Addr::new(198, 51, 100, 0), 30, sub, false),
    ])
    .unwrap();
    assert_eq!(ip(&["-4", "route", "show", "203.0.113.8/29"]), "");
    assert_eq!(ip(&["-4", "route", "show", "198.51.100.0/30"]), "");
    // Removing what is already gone is fine; an unreachable gateway is an
    // error, and the others in the round still run.
    gateway_routes(&[(block, 29, sub, false)]).unwrap();
    let e = gateway_routes(&[
        (block, 29, Ipv4Addr::new(10, 9, 9, 9), true),
        (Ipv4Addr::new(198, 51, 100, 4), 30, sub, true),
    ]);
    assert!(e.is_err());
    assert!(ip(&["-4", "route", "show", "198.51.100.4/30"]).contains("via 192.168.88.20"));
}
