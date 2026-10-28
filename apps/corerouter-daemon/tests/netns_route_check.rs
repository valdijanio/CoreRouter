//! G1.27f / G3.6g: check-gateway of static routes on a `--backend linux`
//! daemon, inside throwaway network namespaces (no root, nothing reaches
//! the host). Two uplinks to a second namespace B (the gateways); a
//! default route through each, distances 1 and 10. For `ping`, `arp` and
//! `bfd` (a second daemon in B runs our BFD engine as the peer): the
//! gateway goes quiet, the route leaves the kernel and the backup takes
//! over; it answers again, the route comes back.
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_route_check
//! ```
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::process::{Command, Stdio};

use common::*;
use serde_json::{Value, json};

/// The checks every 500 ms (RouterOS: 10 s) so the test takes seconds.
const INTERVAL_MS: &str = "500";

fn ip_out(args: &[&str]) -> String {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(out.status.success(), "ip {}", args.join(" "));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn run(command: &str, params: Value) -> Value {
    call(None, command, params).unwrap_or_else(|e| panic!("{command}: {e}"))
}

/// The default routes in the kernel, one `ip route` line each.
fn defaults() -> String {
    ip_out(&["route", "show", "default"])
}

fn route_row(id: &Value) -> Value {
    run("ip.route.list", json!({}))
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == *id)
        .cloned()
        .unwrap()
}

fn status(id: &Value) -> String {
    route_row(id)["check_gateway"]["status"].as_str().unwrap_or("").to_owned()
}

fn daemon(netns: Option<u32>, dir: &std::path::Path, log: &str, extra: &[&str]) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join(log)).unwrap();
    let mut c = in_ns(netns, DAEMON);
    c.args(extra)
        .args(["--no-discovery", "--control", "7979", "--config-dir"])
        .arg(dir)
        .arg("--token-file")
        .arg(common::token_file(netns, dir))
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(log);
    let k = Kill(c.spawn().unwrap());
    wait_for("the daemon", || call(netns, "interface.list", json!({})).is_ok());
    k
}

/// Not a test: run inside B's namespace by `call(Some(pid), …)`.
#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn linux_check_gateway_ping_arp_and_bfd() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    let b = namespace_b();
    let bpid = Some(b.0.id());
    let pid = b.0.id().to_string();
    for (here, there, mine, gw) in [
        ("wan0", "gw0", "10.0.0.2/24", "10.0.0.1/24"),
        ("wan1", "gw1", "10.9.0.2/24", "10.9.0.1/24"),
    ] {
        ip(None, &["link", "add", here, "type", "veth", "peer", "name", there]);
        ip(None, &["link", "set", there, "netns", &pid]);
        ip(bpid, &["addr", "add", gw, "dev", there]);
        ip(bpid, &["link", "set", there, "up"]);
        ip(None, &["link", "set", here, "up"]);
        let _ = mine;
    }
    ip(bpid, &["link", "set", "lo", "up"]);

    let dir = std::env::temp_dir().join(format!("g127f-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _a = daemon(
        None,
        &dir,
        "g127f-netns-a.log",
        &["--backend", "linux", "--manage", "wan0,wan1", "--route-check-interval", INTERVAL_MS],
    );
    run("ip.address.add", json!({"address": "10.0.0.2/24", "interface": "wan0"}));
    run("ip.address.add", json!({"address": "10.9.0.2/24", "interface": "wan1"}));
    run("ip.route.add", json!({"dst_address": "0.0.0.0/0", "gateway": "10.9.0.1", "distance": 10}));
    let main = run(
        "ip.route.add",
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1", "check_gateway": "ping"}),
    )["id"]
        .clone();
    wait_for("both default routes in the kernel", || {
        let d = defaults();
        d.contains("via 10.0.0.1") && d.contains("via 10.9.0.1")
    });

    for method in ["ping", "arp"] {
        run("ip.route.set", json!({"id": main, "check_gateway": method}));
        wait_for(&format!("{method}: the gateway answers"), || status(&main) == "reachable");
        // The gateway goes quiet (its address leaves gw0): two misses and
        // the route leaves the kernel; the backup is the default now.
        ip(bpid, &["addr", "del", "10.0.0.1/24", "dev", "gw0"]);
        wait_for(&format!("{method}: the gateway down"), || status(&main) == "unreachable");
        let d = defaults();
        assert!(!d.contains("via 10.0.0.1"), "{method}: {d}");
        assert!(d.contains("via 10.9.0.1"), "{method}: {d}");
        let r = route_row(&main);
        assert_eq!(r["state"], "inactive", "{r}");
        // Back: the route returns (the second down of the window waits a
        // hold-down of one interval).
        ip(bpid, &["addr", "add", "10.0.0.1/24", "dev", "gw0"]);
        wait_for(&format!("{method}: the route back"), || {
            status(&main) == "reachable" && defaults().contains("via 10.0.0.1")
        });
    }
    let h = run("ip.route.check.history", json!({}));
    let to: Vec<&str> = h.as_array().unwrap().iter().map(|e| e["to"].as_str().unwrap()).collect();
    assert_eq!(to, ["down", "up", "down", "up"], "{h}");

    // BFD: our own engine on both ends. B's daemon runs a peer to us.
    let bdir = std::env::temp_dir().join(format!("g127f-netns-b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&bdir);
    let peer = daemon(bpid, &bdir, "g127f-netns-b.log", &[]);
    call(
        bpid,
        "routing.bfd.peer.add",
        json!({"name": "a", "address": "10.0.0.2", "profile": "fast"}),
    )
    .unwrap();
    run("ip.route.set", json!({"id": main, "check_gateway": "bfd", "bfd_profile": "fast"}));
    wait_for("bfd: the session up", || status(&main) == "reachable");
    assert!(defaults().contains("via 10.0.0.1"));
    let s = run("routing.bfd.session.list", json!({}));
    let users = s["sessions"][0]["users"].to_string();
    assert!(users.contains("route 0.0.0.0/0"), "{s}");
    // B's engine stops: the session times out (150 ms) and the route goes.
    drop(peer);
    wait_for("bfd: the session down", || status(&main) == "unreachable");
    let d = defaults();
    assert!(!d.contains("via 10.0.0.1") && d.contains("via 10.9.0.1"), "bfd: {d}");
    // B is back: so is the route.
    let _peer = daemon(bpid, &bdir, "g127f-netns-b2.log", &[]);
    wait_for("bfd: the route back", || {
        status(&main) == "reachable" && defaults().contains("via 10.0.0.1")
    });

    drop(_peer);
    drop(_a);
    ip(None, &["link", "del", "wan0"]);
    ip(None, &["link", "del", "wan1"]);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&bdir);
}
