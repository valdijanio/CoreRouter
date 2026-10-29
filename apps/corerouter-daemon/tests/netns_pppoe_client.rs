//! G3.9ga: CoreRouter as a PPPoE client (`/interface pppoe-client`) dials
//! CoreRouter's own BNG, each a `--backend linux` daemon in its own
//! throwaway network namespace, no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_pppoe_client -- --test-threads 1
//! ```
//!
//! ```text
//!   A: daemon (BNG)                       B: daemon (CPE)
//!   acc0 ──────────── veth ──────────── cpe0 ← pppoe-out1 (veth + relay)
//!   wan0 198.51.100.1/24
//! ```
//!
//! The session comes up with MS-CHAPv2 (the RouterOS default order), B
//! gets the address and the default route, pings A's wan0 through the
//! relay and the BNG's slow path; a wrong password is refused and backs
//! off; B killed with the session up and started again closes the stale
//! session with PADT (the BNG keeps one session, not two); disabling the
//! client ends the session on the BNG.
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

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};

fn daemon(netns: Option<u32>, dir: &Path, manage: &str, log: &str) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join(log)).unwrap();
    let mut c = in_ns(netns, DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--manage",
        manage,
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
    let port = format!("\"{manage}\"");
    wait_for("the daemon and its port", || {
        call(netns, "interface.list", json!({})).is_ok_and(|v| v.to_string().contains(&port))
    });
    k
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("g39ga-netns-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn ok(netns: Option<u32>, command: &str, params: Value) -> Value {
    call(netns, command, params).unwrap_or_else(|e| panic!("{command}: {e}"))
}

fn active() -> u64 {
    ok(None, "ppp.active.list", json!({"limit": 1}))["total"]
        .as_u64()
        .unwrap()
}

fn monitor(b: u32) -> Value {
    ok(
        Some(b),
        "interface.pppoe-client.monitor",
        json!({"name": "pppoe-out1"}),
    )
}

/// Wait up to `secs` for `f`, with what it last saw on failure.
fn until(what: &str, secs: u64, mut f: impl FnMut() -> Result<(), String>) {
    let t = Instant::now();
    let mut last = String::new();
    while t.elapsed() < Duration::from_secs(secs) {
        match f() {
            Ok(()) => return,
            Err(e) => last = e,
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("{what}: not within {secs} s; last: {last}");
}

fn connected(b: u32) -> Result<(), String> {
    let m = monitor(b);
    (m["status"] == "connected")
        .then_some(())
        .ok_or_else(|| m.to_string())
}

/// The only test: the namespaces are shared, so the stages run in order.
#[test]
fn pppoe_client_dials_corerouters_bng() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    let holder = namespace_b();
    let b = holder.0.id();
    ip(
        None,
        &[
            "link", "add", "acc0", "type", "veth", "peer", "name", "cpe0",
        ],
    );
    ip(None, &["link", "set", "cpe0", "netns", &b.to_string()]);
    ip(None, &["link", "set", "acc0", "up"]);
    ip(Some(b), &["link", "set", "lo", "up"]);
    ip(Some(b), &["link", "set", "cpe0", "up"]);
    ip(None, &["link", "add", "wan0", "type", "dummy"]);
    ip(None, &["addr", "add", "198.51.100.1/24", "dev", "wan0"]);
    ip(None, &["link", "set", "wan0", "up"]);

    // A: the provider's BNG.
    let dir_a = temp_dir("bng");
    let _bng = daemon(None, &dir_a, "acc0", "g39ga-bng.log");
    ok(
        None,
        "ip.pool.add",
        json!({"name": "clientes", "ranges": "100.64.0.0/24"}),
    );
    ok(
        None,
        "ppp.profile.set",
        json!({"id": "default", "local_address": "100.64.255.1", "remote_address": "clientes", "dns_server": "1.1.1.1"}),
    );
    ok(
        None,
        "ppp.secret.add",
        json!({"name": "cliente@isp", "password": "s3nh4"}),
    );
    ok(
        None,
        "interface.pppoe-server.server.add",
        json!({"interface": "acc0", "padi_limit": 0, "mac_padi_limit": 0, "new_session_rate": 0, "keepalive_timeout": 60}),
    );

    // B: CoreRouter dialing it.
    let dir_b = temp_dir("cpe");
    let mut cpe = daemon(Some(b), &dir_b, "cpe0", "g39ga-cpe.log");
    let t0 = Instant::now();
    let r = ok(
        Some(b),
        "interface.pppoe-client.add",
        json!({"name": "pppoe-out1", "interface": "cpe0", "user": "cliente@isp", "password": "s3nh4",
               "add_default_route": true, "use_peer_dns": true}),
    );
    assert_eq!(r["warnings"], json!([]), "{r}");
    until("the session", 20, || connected(b));
    let setup = t0.elapsed();
    let m = monitor(b);
    let local = m["local_address"].as_str().unwrap().to_owned();
    assert!(local.starts_with("100.64.0."), "{m}");
    assert_eq!(m["remote_address"], "100.64.255.1", "{m}");
    assert!(m["mtu"].as_u64().is_some_and(|v| v <= 1492), "{m}");
    assert_eq!(m["dns"], json!(["1.1.1.1"]), "{m}");
    eprintln!("session up in {setup:?} (add → connected, through the 250 ms clock)");
    let row = ok(None, "ppp.active.list", json!({}))["rows"][0].clone();
    assert_eq!(row["name"], "cliente@isp");
    assert_eq!(
        row["encoding"], "mschap2",
        "RouterOS order: MS-CHAPv2 first"
    );
    assert_eq!(m["encoding"], "mschap2", "{m}");
    // The address and the default route in B's tables, as dynamic entries.
    let addrs = ok(Some(b), "ip.address.list", json!({})).to_string();
    assert!(addrs.contains(&format!("{local}/32")), "{addrs}");
    let routes = ok(Some(b), "ip.route.list", json!({})).to_string();
    assert!(
        routes.contains("0.0.0.0/0") && routes.contains("pppoe-out1"),
        "{routes}"
    );
    let ifs = ok(Some(b), "interface.list", json!({})).to_string();
    assert!(ifs.contains("\"pppoe-out\""), "{ifs}");
    assert!(
        ifs.contains("relay end of PPPoE client"),
        "the veth's other end is not seeded as a port: {ifs}"
    );

    // Traffic: B pings A's wan0 through the relay and the BNG.
    let ping = in_ns(Some(b), "ping")
        .args(["-c", "3", "-i", "0.2", "-W", "2", "198.51.100.1"])
        .output()
        .unwrap();
    assert!(
        ping.status.success(),
        "ping through pppoe-out1: {}",
        String::from_utf8_lossy(&ping.stdout)
    );
    let m = monitor(b);
    assert!(
        m["tx_packets"].as_u64().unwrap() >= 3 && m["rx_packets"].as_u64().unwrap() >= 3,
        "{m}"
    );

    // Wrong password: refused, the BNG's words kept, 30 s back-off.
    ok(
        Some(b),
        "interface.pppoe-client.set",
        json!({"name": "pppoe-out1", "password": "errada"}),
    );
    until("the refusal", 20, || {
        let m = monitor(b);
        (m["last_down"]["reason"] == "auth-failed")
            .then_some(())
            .ok_or_else(|| m.to_string())
    });
    let m = monitor(b);
    let wait = m["retry_in_secs"].as_u64().unwrap();
    assert!(wait >= 20, "auth failures back off at least ~30 s: {m}");
    wait_for("the BNG to drop the refused session", || active() == 0);
    let addrs = ok(Some(b), "ip.address.list", json!({})).to_string();
    assert!(
        !addrs.contains(&local),
        "the session's address must go: {addrs}"
    );

    // Right password again; then B dies with the session up.
    ok(
        Some(b),
        "interface.pppoe-client.set",
        json!({"name": "pppoe-out1", "password": "s3nh4"}),
    );
    until("the session again", 20, || connected(b));
    wait_for("one session on the BNG", || active() == 1);
    let _ = cpe.0.kill();
    let _ = cpe.0.wait();
    drop(cpe);
    // B restarts: the PADT for the stale session frees it on the BNG at once
    // (keepalive_timeout is 60 s there), then it dials again.
    cpe = daemon(Some(b), &dir_b, "cpe0", "g39ga-cpe2.log");
    until("the session after the restart", 20, || connected(b));
    let h = ok(Some(b), "interface.pppoe-client.history", json!({})).to_string();
    assert!(
        h.contains("padt-stale"),
        "the stale session is closed with PADT: {h}"
    );
    wait_for("one session on the BNG, not two", || active() == 1);

    // Disable: PADT, the BNG has no session left.
    ok(
        Some(b),
        "interface.pppoe-client.disable",
        json!({"name": "pppoe-out1"}),
    );
    wait_for("the BNG to see the PADT", || active() == 0);
    assert_eq!(monitor(b)["status"], "disabled");
    drop(cpe);
    drop(holder);
}

/// Not a test: run inside B by `common::call`.
#[test]
fn query_helper() {
    common::query_helper();
}
