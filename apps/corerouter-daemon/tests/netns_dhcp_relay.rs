//! G4.2b: our client gets a lease from our server through our relay, with
//! option 82 on the way (the server sees the relay's port and the client's
//! MAC as remote id, and keeps who had the address in its history), and
//! renews straight to the server — three daemons in throwaway network
//! namespaces, no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_dhcp_relay
//! ```
//!
//! ```text
//!   B: client           A (this ns): relay               C: server
//!   cli0 ── veth ── lan0 10.88.0.1/24   up0 10.99.0.1/24 ── veth ── srv0 10.99.0.2/24
//! ```
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};

fn daemon(netns: Option<u32>, dir: &Path, ifaces: &str, log: &str) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join(log)).unwrap();
    let mut c = in_ns(netns, DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--manage",
        ifaces,
        "--control",
        "7979",
        "--config-dir",
    ])
    .arg(dir)
    .arg("--token-file")
    .arg(token_file(netns, dir))
    .env("RUST_LOG", "info")
    .stdout(Stdio::null())
    .stderr(log);
    let k = Kill(c.spawn().unwrap());
    wait_for("a daemon", || {
        call(netns, "interface.list", json!({})).is_ok()
    });
    k
}

fn ok(netns: Option<u32>, command: &str, params: Value) -> Value {
    call(netns, command, params).unwrap_or_else(|e| panic!("{command}: {e}"))
}

fn wait_long(what: &str, secs: u64, mut ok: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < until {
        if ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("timed out waiting for {what}");
}

#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn our_client_through_our_relay_to_our_server() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    let b = namespace_b();
    let c = namespace_b();
    let (bp, cp) = (Some(b.0.id()), Some(c.0.id()));
    ip(
        None,
        &[
            "link", "add", "lan0", "type", "veth", "peer", "name", "cli0",
        ],
    );
    ip(
        None,
        &["link", "set", "cli0", "netns", &b.0.id().to_string()],
    );
    ip(
        None,
        &["link", "add", "up0", "type", "veth", "peer", "name", "srv0"],
    );
    ip(
        None,
        &["link", "set", "srv0", "netns", &c.0.id().to_string()],
    );
    for (ns, link) in [(bp, "cli0"), (cp, "srv0"), (None, "lan0"), (None, "up0")] {
        ip(ns, &["link", "set", "lo", "up"]);
        ip(ns, &["link", "set", link, "up"]);
    }
    // The relay routes the renewals, which go straight to the server.
    let fwd = Command::new("sysctl")
        .args(["-qw", "net.ipv4.ip_forward=1"])
        .status()
        .unwrap();
    assert!(fwd.success());

    let base = std::env::temp_dir().join(format!("g42b-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let dirs: Vec<_> = ["a", "b", "c"].iter().map(|d| base.join(d)).collect();
    for d in &dirs {
        std::fs::create_dir_all(d).unwrap();
    }

    let _server = daemon(cp, &dirs[2], "srv0", "g42b-server.log");
    for (cmd, p) in [
        (
            "ip.address.add",
            json!({"address": "10.99.0.2/24", "interface": "srv0"}),
        ),
        (
            "ip.route.add",
            json!({"dst_address": "10.88.0.0/24", "gateway": "10.99.0.1"}),
        ),
        (
            "ip.pool.add",
            json!({"name": "far", "ranges": "10.88.0.10-10.88.0.20"}),
        ),
        (
            "ip.dhcp-server.add",
            json!({"name": "branch", "interface": "srv0", "address_pool": "far", "relay": "10.88.0.1", "lease_time": "1m"}),
        ),
        (
            "ip.dhcp-server.network.add",
            json!({"address": "10.88.0.0/24", "gateway": "10.88.0.1"}),
        ),
    ] {
        ok(cp, cmd, p);
    }

    let _relay = daemon(None, &dirs[0], "lan0,up0", "g42b-relay.log");
    for (cmd, p) in [
        (
            "ip.address.add",
            json!({"address": "10.88.0.1/24", "interface": "lan0"}),
        ),
        (
            "ip.address.add",
            json!({"address": "10.99.0.1/24", "interface": "up0"}),
        ),
        (
            "ip.dhcp-relay.add",
            json!({"interface": "lan0", "dhcp_server": "10.99.0.2", "add_relay_info": true}),
        ),
    ] {
        ok(None, cmd, p);
    }
    wait_for("the relay listening", || {
        ok(None, "ip.dhcp-relay.print", json!({}))[0]["status"] == "running"
    });

    let _client = daemon(bp, &dirs[1], "cli0", "g42b-client.log");
    ok(bp, "ip.dhcp-client.add", json!({"interface": "cli0"}));
    let client_row = || ok(bp, "ip.dhcp-client.list", json!({}))[0].clone();
    wait_long("a lease through the relay", 30, || {
        client_row()["status"] == "bound"
    });
    let row = client_row();
    assert_eq!(row["address"], "10.88.0.10/24", "{row}");
    assert_eq!(row["gateway"], "10.88.0.1");
    assert_eq!(row["dhcp_server"], "10.99.0.2");

    // The server saw the relay's port and the client's MAC (option 82).
    let leases = ok(cp, "ip.dhcp-server.lease.print", json!({"status": "bound"}));
    let l = &leases[0];
    assert_eq!(l["agent_circuit_id"], "lan0", "{l}");
    assert!(
        l["agent_remote_id"].as_str().unwrap().starts_with("0x"),
        "{l}"
    );
    let relay = ok(None, "ip.dhcp-relay.print", json!({}));
    assert!(relay[0]["requests"].as_u64().unwrap() >= 2, "{relay}");
    assert!(relay[0]["replies"].as_u64().unwrap() >= 2, "{relay}");

    // Renewal at T1 (30 s), unicast to the server through the router.
    let acks = || {
        ok(cp, "ip.dhcp-server.statistics.print", json!({}))["sent"]["ack"]
            .as_u64()
            .unwrap_or(0)
    };
    wait_long("a renewal", 45, || acks() >= 2);
    wait_long("the client bound again", 10, || {
        client_row()["status"] == "bound"
    });

    // The history: the client, its port, still open.
    let h = ok(
        cp,
        "ip.dhcp-server.history.print",
        json!({"address": "10.88.0.10"}),
    );
    assert_eq!(h["rows"][0]["circuit_id"], "lan0", "{h}");
    assert_eq!(h["rows"][0]["open"], true);
    let _ = std::fs::remove_dir_all(&base);
}
