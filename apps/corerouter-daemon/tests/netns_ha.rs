//! G4.3h: two `--backend linux` daemons as a redundant BNG pair, each in
//! its own throwaway network namespace, no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_ha -- --test-threads 1
//! ```
//!
//! ```text
//!   A (here)                                B (namespace_b)
//!   sync0 10.9.0.1 ────── veth ────── sync0 10.9.0.2   (TLS sync link)
//!   acc0 ──────────────── veth ────── acc0              (access hellos)
//!   gw0 10.99.0.1 (dummy: the witness)    gw0 10.99.0.1
//! ```
//!
//! The pair elects A (priority 200), syncs over TLS with the shared secret,
//! hears itself on both paths; a switchover moves the role to B; killing B
//! gives it back to A within the dead interval; B comes back as standby;
//! A cut off from everything (both links down, witness gone) fences itself
//! while B takes over. Takeover times are printed (`docs/bng-ha.md`).
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

const SECRET: &str = "segredo-do-par-de-teste";

fn daemon(netns: Option<u32>, dir: &Path, log: &str) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join(log)).unwrap();
    let mut c = in_ns(netns, DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--manage",
        "acc0,sync0",
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
    wait_for("the daemon and its ports", || {
        call(netns, "interface.list", json!({})).is_ok_and(|v| v.to_string().contains("\"acc0\""))
    });
    k
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("g43h-netns-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn ok(netns: Option<u32>, command: &str, params: Value) -> Value {
    call(netns, command, params).unwrap_or_else(|e| panic!("{command} in {netns:?}: {e}"))
}

fn pair(netns: Option<u32>, peer: &str, priority: u32) {
    ok(
        netns,
        "ppp.redundancy.set",
        json!({
            "enabled": true, "peer": format!("{peer}:8730"), "secret": SECRET,
            "witness": ["10.99.0.1"], "interfaces": ["acc0"], "priority": priority,
            "init_hold": 2, "recover_hold": 1
        }),
    );
}

fn monitor(netns: Option<u32>) -> Value {
    call(netns, "ppp.redundancy.monitor", json!({})).unwrap_or(Value::Null)
}

fn role(netns: Option<u32>) -> String {
    monitor(netns)["role"].as_str().unwrap_or("").to_owned()
}

/// Waits until `f`, returns how long it took.
fn until(what: &str, secs: u64, mut f: impl FnMut() -> bool) -> Duration {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(secs) {
        if f() {
            return start.elapsed();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out waiting for {what}");
}

/// Not a test: run inside B by `call`.
#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn a_pair_elects_switches_over_fails_over_and_fences() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    let holder = namespace_b();
    let b = holder.0.id();
    let pid = b.to_string();
    ip(Some(b), &["link", "set", "lo", "up"]);
    for name in ["sync0", "acc0"] {
        ip(
            None,
            &[
                "link", "add", name, "type", "veth", "peer", "name", name, "netns", &pid,
            ],
        );
        ip(None, &["link", "set", name, "up"]);
        ip(Some(b), &["link", "set", name, "up"]);
    }
    ip(None, &["addr", "add", "10.9.0.1/24", "dev", "sync0"]);
    ip(Some(b), &["addr", "add", "10.9.0.2/24", "dev", "sync0"]);
    for ns in [None, Some(b)] {
        ip(ns, &["link", "add", "gw0", "type", "dummy"]);
        ip(ns, &["addr", "add", "10.99.0.1/24", "dev", "gw0"]);
        ip(ns, &["link", "set", "gw0", "up"]);
    }

    let (dir_a, dir_b) = (temp_dir("a"), temp_dir("b"));
    let _a = daemon(None, &dir_a, "g43h-ha-a.log");
    let mut b_daemon = Some(daemon(Some(b), &dir_b, "g43h-ha-b.log"));
    pair(None, "10.9.0.2", 200);
    pair(Some(b), "10.9.0.1", 100);

    // Election: A active, B standby, both paths heard, the link up.
    let t = until("A active, B standby", 30, || {
        role(None) == "active" && role(Some(b)) == "standby"
    });
    eprintln!("pair formed in {t:?}");
    until("both paths", 10, || {
        let m = monitor(None);
        m["peer"]["connected"] == true
            && m["peer"]["sync_path"] == true
            && m["peer"]["access_path"] == true
    });
    let m = monitor(Some(b));
    assert_eq!(m["peer"]["connected"], true, "{m}");
    assert!(
        m["drift"].as_array().unwrap().is_empty(),
        "same config: {m}"
    );
    assert!(
        dir_a.join("ppp-ha-peer.fingerprint").exists()
            || dir_b.join("ppp-ha-peer.fingerprint").exists(),
        "the dialer pinned the peer's certificate"
    );

    // Switchover: B takes the role; nobody both.
    ok(None, "ppp.redundancy.switchover", json!({"force": true}));
    let t = until("B active after the switchover", 10, || {
        role(Some(b)) == "active"
    });
    eprintln!("switchover in {t:?}");
    until("A standby", 10, || role(None) == "standby");

    // B dies: A takes over within the dead interval (1.2 s) and a tick.
    drop(b_daemon.take());
    let start = Instant::now();
    until("A active after B died", 10, || role(None) == "active");
    let t = start.elapsed();
    eprintln!("failover after a kill in {t:?}");
    assert!(t < Duration::from_secs(4), "{t:?}");
    let h = monitor(None)["history"][0].clone();
    assert_eq!(h["reason"], "peer-dead", "{h}");

    // B comes back: standby (no preemption).
    b_daemon = Some(daemon(Some(b), &dir_b, "g43h-ha-b2.log"));
    until("B standby again", 30, || role(Some(b)) == "standby");
    assert_eq!(role(None), "active");

    // A loses everything: both links down and its witness gone. It fences
    // itself; B (which still reaches its witness) takes over.
    ip(None, &["link", "set", "sync0", "down"]);
    ip(None, &["link", "set", "acc0", "down"]);
    ip(None, &["addr", "del", "10.99.0.1/24", "dev", "gw0"]);
    until("A fenced", 15, || role(None) == "fenced");
    until("B active", 15, || role(Some(b)) == "active");
    let h = monitor(None)["history"][0].clone();
    assert_eq!(h["reason"], "isolated", "{h}");
    drop(b_daemon);
}
