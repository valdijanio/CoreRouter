//! G1.6zh: the clock of a router on its first boot. A `--backend linux`
//! daemon with a config directory that never saved anything starts with the
//! NTP client on and no server of its own; the DHCP lease of its port brings
//! the network's NTP server (option 42, RFC 2132 §8.3) and the client asks
//! it at once. The network is our own stack: a second daemon serves DHCP
//! and NTP. Inside throwaway network namespaces, no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_ntp_first_boot
//! ```
//!
//! ```text
//!   this ns: daemon A (the network)          namespace B: daemon B (new router)
//!   lan0 10.78.0.1/24 ───────── veth ───────── cli0 (DHCP client, as the
//!   DHCP server (option 42 = 10.78.0.1)             first boot gives every port)
//!   NTP server (its own clock)
//! ```
//!
//! The clock itself cannot change in a user namespace (`CAP_SYS_TIME` is
//! checked against the initial one): there the client measures and says why
//! it does not correct. As real root (the lab VM) the same test sees the
//! clock being disciplined.
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
use std::process::Stdio;
use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};

fn daemon(netns: Option<u32>, dir: &Path, iface: &str, log: &str) -> Kill {
    let log = std::fs::File::create(dir.parent().unwrap_or(dir).join(log)).unwrap();
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
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("timed out waiting for {what}");
}

/// The `ntp` line of the health check of the daemon in `netns`.
fn health(netns: Option<u32>) -> Value {
    ok(netns, "system.health.check", json!({}))["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["key"] == "ntp")
        .cloned()
        .unwrap()
}

#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn a_new_router_sets_its_clock_from_the_dhcp_lease() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    let b = namespace_b();
    let bpid = Some(b.0.id());
    let bs = b.0.id().to_string();
    ip(
        None,
        &[
            "link", "add", "lan0", "type", "veth", "peer", "name", "cli0",
        ],
    );
    ip(None, &["link", "set", "cli0", "netns", &bs]);
    ip(bpid, &["link", "set", "lo", "up"]);
    ip(bpid, &["link", "set", "cli0", "up"]);
    ip(None, &["link", "set", "lan0", "up"]);

    let base = std::env::temp_dir().join(format!("g16zh-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let dir_a = base.join("a");
    let dir_b = base.join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();

    // The network: DHCP that names an NTP server, and that server.
    let _a = daemon(None, &dir_a, "lan0", "g16zh-network.log");
    for (cmd, p) in [
        (
            "ip.address.add",
            json!({"address": "10.78.0.1/24", "interface": "lan0"}),
        ),
        (
            "ip.pool.add",
            json!({"name": "lan", "ranges": "10.78.0.10-10.78.0.20"}),
        ),
        (
            "ip.dhcp-server.add",
            json!({"interface": "lan0", "address_pool": "lan", "lease_time": "10m"}),
        ),
        (
            "ip.dhcp-server.network.add",
            json!({"address": "10.78.0.0/24", "gateway": "10.78.0.1", "dns_none": true, "ntp_server": "10.78.0.1"}),
        ),
        (
            "system.ntp.server.set",
            json!({"enabled": true, "use_local_clock": true}),
        ),
    ] {
        ok(None, cmd, p);
    }
    wait_for("the DHCP server listening", || {
        ok(None, "ip.dhcp-server.print", json!({}))[0]["status"] == "running"
    });
    wait_for("the NTP server serving", || {
        ok(None, "system.ntp.server.get", json!({}))["serving"] != "no"
    });

    // The new router: nothing configured by anyone.
    let client = daemon(bpid, &dir_b, "cli0", "g16zh-router.log");
    let get = || ok(bpid, "system.ntp.client.get", json!({}));
    let first = get();
    assert_eq!(
        first["enabled"], true,
        "on in a config never saved: {first}"
    );
    assert_eq!(first["servers"], json!([]), "no server built in: {first}");
    wait_long("the empty round", 10, || {
        get()["last_error"] == "no server to ask"
    });
    assert_eq!(get()["status"], "waiting");
    // Nobody to ask: the health check says so, with what to do.
    let h = health(bpid);
    assert_eq!(h["severity"], "warning", "{h}");
    assert_eq!(h["value"], "no-server", "{h}");
    assert!(
        h["reason"]
            .as_str()
            .unwrap()
            .starts_with("relógio não ajustado"),
        "{h}"
    );
    assert!(
        h["action"]
            .as_str()
            .unwrap()
            .contains("system.ntp.client.set servers="),
        "{h}"
    );

    // What the first boot does to every port: a DHCP client. Nothing else.
    ok(
        bpid,
        "interface.set",
        json!({"name": "cli0", "disabled": false}),
    );
    let asked = Instant::now();
    ok(bpid, "ip.dhcp-client.add", json!({"interface": "cli0"}));
    wait_long("a lease", 30, || {
        ok(bpid, "ip.dhcp-client.list", json!({}))[0]["status"] == "bound"
    });
    let lease = ok(bpid, "ip.dhcp-client.list", json!({}))[0].clone();
    assert_eq!(lease["primary_ntp"], "10.78.0.1", "{lease}");
    // The server the lease brought is asked at once, not 64 s after the
    // round that had nobody to ask.
    wait_long("synchronized", 30, || get()["status"] == "synchronized");
    let took = asked.elapsed();
    assert!(took < Duration::from_secs(30), "{took:?}");
    let st = get();
    assert_eq!(st["dynamic_servers"], json!(["10.78.0.1"]), "{st}");
    assert_eq!(st["synced_address"], "10.78.0.1", "{st}");
    assert_eq!(st["servers"], json!([]), "still nothing configured: {st}");
    eprintln!(
        "G1.6zh: synchronized {took:?} after the DHCP client was added; clock {}, offset {} ms, \
         last adjustment {} ms",
        st["clock"], st["system_offset_ms"], st["last_adjustment_ms"]
    );
    // Both ends read the same clock here.
    assert!(
        st["system_offset_ms"].as_f64().unwrap().abs() < 500.0,
        "{st}"
    );
    match st["clock"].as_str().unwrap() {
        // A user namespace: measured, and it says why it is not corrected.
        "not-set" => assert!(
            st["clock_error"].as_str().unwrap().contains("CAP_SYS_TIME"),
            "{st}"
        ),
        // Real root (the lab VM): the clock is being disciplined.
        "slewing" | "stepped" => assert!(st["clock_error"].is_null(), "{st}"),
        other => panic!("clock {other}: {st}"),
    }
    let h = health(bpid);
    assert_eq!(h["severity"], "ok", "{h}");
    assert_eq!(h["reason"], "relógio sincronizado", "{h}");
    let log = ok(bpid, "log.print", json!({"topics": "ntp"}));
    let line = |needle: &str| {
        log.as_array()
            .unwrap()
            .iter()
            .find(|r| r["message"].as_str().unwrap().contains(needle))
            .unwrap_or_else(|| panic!("no '{needle}' in {log}"))
            .clone()
    };
    assert_eq!(
        line("NTP Client ligado: servidores do DHCP")["origin"],
        "local"
    );
    assert_eq!(
        line("sem servidor")["level"],
        "info",
        "waiting for the lease is not a warning"
    );
    line("NTP sincronizado com 10.78.0.1");

    // The operator turns it off; the config is saved, and the next boot
    // keeps what the file says.
    ok(bpid, "system.ntp.client.set", json!({"enabled": false}));
    drop(client);
    let _client = daemon(bpid, &dir_b, "cli0", "g16zh-router-2.log");
    let again = get();
    assert_eq!(again["enabled"], false, "{again}");
    assert_eq!(again["status"], "stopped", "{again}");
}
