//! G3.6h: the redundant BNG pair of `netns_ha.rs` with BFD (`fast`, 50 ms ×
//! 3) on its two paths, each daemon in its own throwaway namespace, no
//! root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_ha_bfd -- --test-threads 1
//! ```
//!
//! ```text
//!   A (here)                                B (namespace_b)
//!   sync0 10.9.0.1 ────── veth ────── sync0 10.9.0.2   (TLS sync + BFD)
//!   acc0 10.8.0.1 ─────── veth ────── acc0 10.8.0.2    (hellos + BFD)
//!   gw0 10.99.0.1 (dummy: the witness)    gw0 10.99.0.1
//! ```
//!
//! The pair forms with BFD up on both paths; the takeover test from A
//! (`test-takeover`, method failure) makes B take over by BFD and A reads
//! the result from B; killing B gives the role back to A by BFD, well
//! inside the dead interval; the timeline is printed (`docs/bng-ha.md`).
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
    let dir = std::env::temp_dir().join(format!("g36h-netns-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn ok(netns: Option<u32>, command: &str, params: Value) -> Value {
    call(netns, command, params).unwrap_or_else(|e| panic!("{command} in {netns:?}: {e}"))
}

fn pair(netns: Option<u32>, peer: &str, access_peer: &str, priority: u32) {
    ok(
        netns,
        "ppp.redundancy.set",
        json!({
            "enabled": true, "peer": format!("{peer}:8730"), "secret": SECRET,
            "witness": ["10.99.0.1"], "interfaces": ["acc0"], "priority": priority,
            "init_hold": 2, "recover_hold": 1,
            "bfd": "fast", "access_bfd": "fast", "access_peer": access_peer
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

/// The BFD of both paths up with the fast timers, as the monitor of
/// `netns` shows it. `up` alone is not enough: a session comes up with the
/// slow timers (3 s detection) and only gets the fast ones after the Poll
/// Sequence, so a peer killed in between is caught by the dead interval.
fn bfd_up(netns: Option<u32>) -> bool {
    let m = monitor(netns);
    let p = m["bfd"].as_array().cloned().unwrap_or_default();
    p.len() == 2
        && p.iter()
            .all(|x| x["state"] == "up" && x["detect_ms"] == 150)
}

/// BFD up on both paths of both nodes for a whole second. A 150 ms
/// detection time is also lost for real when the machine starves a daemon
/// that long: the pair then falls back on its hellos (`dead-interval`),
/// rightly, and a takeover started in that moment cannot show BFD's
/// (flaked in the queue's batches). A bug that keeps BFD down never gets
/// a steady second.
fn steady_bfd(b: u32) {
    for attempt in 1..=10 {
        until("BFD up on both paths of both nodes", 20, || {
            bfd_up(None) && bfd_up(Some(b))
        });
        let start = Instant::now();
        let mut steady = true;
        while start.elapsed() < Duration::from_secs(1) {
            if !(bfd_up(None) && bfd_up(Some(b))) {
                steady = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if steady {
            return;
        }
        eprintln!("BFD window {attempt}: a path went down (the machine starved a daemon?)");
    }
    panic!("no steady second of BFD in 10 tries");
}

#[test]
fn bfd_takes_over_in_a_fraction_of_the_dead_interval() {
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
    ip(None, &["addr", "add", "10.8.0.1/24", "dev", "acc0"]);
    ip(Some(b), &["addr", "add", "10.8.0.2/24", "dev", "acc0"]);
    for ns in [None, Some(b)] {
        ip(ns, &["link", "add", "gw0", "type", "dummy"]);
        ip(ns, &["addr", "add", "10.99.0.1/24", "dev", "gw0"]);
        ip(ns, &["link", "set", "gw0", "up"]);
    }

    let (dir_a, dir_b) = (temp_dir("a"), temp_dir("b"));
    let _a = daemon(None, &dir_a, "g36h-ha-a.log");
    let mut b_daemon = Some(daemon(Some(b), &dir_b, "g36h-ha-b.log"));
    pair(None, "10.9.0.2", "10.8.0.2", 200);
    pair(Some(b), "10.9.0.1", "10.8.0.1", 100);
    let t = until("A active, B standby", 30, || {
        role(None) == "active" && role(Some(b)) == "standby"
    });
    eprintln!("pair formed in {t:?}");
    let t = until("BFD up on both paths of both nodes", 20, || {
        bfd_up(None) && bfd_up(Some(b))
    });
    eprintln!("BFD up in {t:?}");
    let g = ok(None, "ppp.redundancy.get", json!({}));
    assert_eq!(g["detection_ms"], 150, "{g}");

    // The checklist, then the test: A goes silent, B must take over by BFD.
    let c = ok(None, "ppp.redundancy.test-takeover", json!({}));
    assert_eq!(c["state"], "checked", "{c}");
    until("every check passes", 20, || {
        let c = ok(None, "ppp.redundancy.test-takeover", json!({}));
        c["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|x| x["ok"] == true)
    });
    steady_bfd(b);
    let r = ok(
        None,
        "ppp.redundancy.test-takeover",
        json!({"confirm": "takeover", "seconds": 5}),
    );
    assert_eq!(r["state"], "running", "{r}");
    until("B active after the test", 10, || role(Some(b)) == "active");
    let k = monitor(Some(b))["takeovers"][0].clone();
    eprintln!("test takeover on B: {k}");
    assert!(k["detected_by"].as_str().unwrap().starts_with("bfd"), "{k}");
    assert_eq!(k["lost"], 0, "{k}");
    until("A standby again", 30, || role(None) == "standby");
    let t = until("A reads the result from B", 20, || {
        monitor(None)["test"]["state"]
            .as_str()
            .is_some_and(|s| s != "running")
    });
    let m = monitor(None);
    eprintln!("test result on A after {t:?}: {}", m["test"]);
    assert_eq!(m["test"]["state"], "passed", "{}", m["test"]);
    steady_bfd(b);

    // B (active) dies: A detects it by BFD and takes over.
    let start = Instant::now();
    drop(b_daemon.take());
    until("A active after B died", 10, || role(None) == "active");
    let wall = start.elapsed();
    let k = monitor(None)["takeovers"][0].clone();
    eprintln!("kill of the active: A active within {wall:?} (polled every 50 ms); timeline {k}");
    assert!(k["detected_by"].as_str().unwrap().starts_with("bfd"), "{k}");
    let active_ms = k["active_ms"].as_u64().unwrap();
    assert!(
        active_ms < 400,
        "takeover {active_ms} ms after the last sign of life: {k}"
    );
    // Faster than the dead interval: BFD saw it (`detected_by`, not the
    // hellos) and A took over 0.4 s after the last sign of life. `wall`
    // also counts reaping B's process and every control round trip of the
    // polling: 1.58 s with `active_ms` 153 on a loaded machine (flaked in
    // the queue's batches), so it is printed, not checked.
    let h = monitor(None)["history"][0].clone();
    assert_eq!(h["reason"], "peer-dead", "{h}");
}
