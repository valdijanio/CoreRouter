//! G4.2c: our DHCPv6 server gives our DHCPv6 client (G4.7b, a second
//! daemon) an address (IA_NA) and a delegated prefix (IA_PD), routes the
//! prefix to it in the kernel, and keeps the bindings across its own
//! restart — inside throwaway network namespaces, no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_dhcp6_server
//! ```
//!
//! ```text
//!   this ns: daemon A (DHCPv6 server)     namespace B: daemon B (client)
//!   lan0 2001:db8:77::1/64 ──── veth ────── cli0 (address + /56 prefix)
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

fn daemon(netns: Option<u32>, dir: &Path, iface: &str, log: &str) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join(log)).unwrap();
    let mut c = in_ns(netns, DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--manage",
        iface,
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

fn bindings() -> Vec<Value> {
    ok(None, "ipv6.dhcp-server.binding.print", json!({}))
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn our_dhcpv6_client_gets_an_address_and_a_prefix() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    let b = namespace_b();
    let bp = Some(b.0.id());
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
    ip(bp, &["link", "set", "lo", "up"]);
    ip(bp, &["link", "set", "cli0", "up"]);
    ip(None, &["link", "set", "lan0", "up"]);

    let base = std::env::temp_dir().join(format!("g42c-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let (da, db) = (base.join("a"), base.join("b"));
    std::fs::create_dir_all(&da).unwrap();
    std::fs::create_dir_all(&db).unwrap();

    let a = daemon(None, &da, "lan0", "g42c-server.log");
    for (cmd, p) in [
        (
            "ip.address.add",
            json!({"address": "2001:db8:77::1/64", "interface": "lan0"}),
        ),
        (
            "ipv6.pool.add",
            json!({"name": "addrs", "prefix": "2001:db8:77::/64", "prefix_length": 128}),
        ),
        (
            "ipv6.pool.add",
            json!({"name": "cpe", "prefix": "2001:db8:7700::/48", "prefix_length": 56}),
        ),
        (
            "ipv6.dhcp-server.add",
            json!({"interface": "lan0", "address_pool": "addrs", "prefix_pool": "cpe", "lease_time": "1h", "dns_server": "2001:db8:77::1"}),
        ),
    ] {
        ok(None, cmd, p);
    }
    wait_for("the server listening", || {
        ok(None, "ipv6.dhcp-server.print", json!({}))[0]["status"] == "running"
    });

    let _client = daemon(bp, &db, "cli0", "g42c-client.log");
    ok(
        bp,
        "ipv6.dhcp-client.add",
        json!({"interface": "cli0", "request": "address,prefix", "pool_name": "wan-pd"}),
    );
    let row = || ok(bp, "ipv6.dhcp-client.list", json!({}))[0].clone();
    wait_long("a binding", 40, || row()["status"] == "bound");
    let r = row();
    let addr = r["address"].as_str().unwrap().to_owned();
    let prefix = r["prefix"].as_str().unwrap().to_owned();
    assert!(addr.starts_with("2001:db8:77:"), "{r}");
    assert!(
        prefix.starts_with("2001:db8:7700:") && prefix.ends_with("/56"),
        "{r}"
    );
    assert_eq!(r["primary_dns"], "2001:db8:77::1", "{r}");

    // The server's view and the route to the prefix in its kernel.
    let rows = bindings();
    let pd = rows.iter().find(|x| x["type"] == "prefix").unwrap();
    assert_eq!(pd["address"], prefix.as_str());
    assert!(pd["via"].as_str().unwrap().starts_with("fe80::"));
    let routes = Command::new("ip")
        .args(["-6", "route", "show", &prefix])
        .output()
        .unwrap();
    let routes = String::from_utf8_lossy(&routes.stdout).into_owned();
    assert!(
        routes.contains("via fe80::") && routes.contains("dev lan0"),
        "{routes}"
    );

    // Restart: the journal keeps the bindings and the route comes back.
    drop(a);
    let _a = daemon(None, &da, "lan0", "g42c-server2.log");
    let rows = bindings();
    assert!(
        rows.iter()
            .any(|x| x["address"] == prefix.as_str() && x["status"] == "bound"),
        "{rows:#?}"
    );
    wait_long("the route again", 10, || {
        let out = Command::new("ip")
            .args(["-6", "route", "show", &prefix])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).contains("dev lan0")
    });
    let _ = std::fs::remove_dir_all(&base);
}
