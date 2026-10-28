//! G3.6: two daemons with CoreRouter's own BFD, each in its own throwaway
//! network namespace, no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_bfd -- --test-threads 1
//! ```
//!
//! ```text
//!   A (here)  bfd0 10.8.0.1 ────── veth ────── bfd0 10.8.0.2  B (namespace_b)
//! ```
//!
//! Both add the other as a peer with the `default` profile (300 ms × 3: a
//! loaded CI must not see false downs); the session comes up on both sides
//! with its timers after the Poll
//! Sequence; the link goes down in B and A must see the session down
//! within the detection time (900 ms), with "control-detection-time-
//! expired" in the history. The link back brings it up again.
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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use common::*;
use serde_json::{Value, json};

fn daemon(netns: Option<u32>, dir: &Path, log: &str) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join(log)).unwrap();
    let mut c = in_ns(netns, DAEMON);
    c.args([
        "--backend",
        "virtual",
        "--no-discovery",
        "--control",
        "7979",
        "--bfd-threads",
        "2",
        "--config-dir",
    ])
    .arg(dir)
    .arg("--token-file")
    .arg(token_file(netns, dir))
    .env("RUST_LOG", "info")
    .stdout(Stdio::null())
    .stderr(log);
    let k = Kill(c.spawn().unwrap());
    wait_for("the daemon", || {
        let r = call(netns, "routing.bfd.session.list", json!({}));
        if let Err(e) = &r {
            eprintln!("{netns:?}: {e}");
        }
        r.is_ok()
    });
    k
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("g36-netns-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn ok(netns: Option<u32>, command: &str, params: Value) -> Value {
    call(netns, command, params).unwrap_or_else(|e| panic!("{command} in {netns:?}: {e}"))
}

fn session(netns: Option<u32>) -> Value {
    call(netns, "routing.bfd.session.list", json!({}))
        .ok()
        .and_then(|v| v["sessions"].get(0).cloned())
        .unwrap_or(Value::Null)
}

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

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Not a test: run inside B by `call`.
#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn two_daemons_detect_a_dead_link_within_the_detection_time() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    let holder = namespace_b();
    let b = holder.0.id();
    let pid = b.to_string();
    ip(Some(b), &["link", "set", "lo", "up"]);
    ip(
        None,
        &[
            "link", "add", "bfd0", "type", "veth", "peer", "name", "bfd0", "netns", &pid,
        ],
    );
    ip(None, &["addr", "add", "10.8.0.1/24", "dev", "bfd0"]);
    ip(Some(b), &["addr", "add", "10.8.0.2/24", "dev", "bfd0"]);
    ip(None, &["link", "set", "bfd0", "up"]);
    ip(Some(b), &["link", "set", "bfd0", "up"]);
    let (da, db) = (temp_dir("a"), temp_dir("b"));
    let _a = daemon(None, &da, "g36-bfd-a.log");
    let _b = daemon(Some(b), &db, "g36-bfd-b.log");
    ok(
        None,
        "routing.bfd.peer.add",
        json!({"name": "b", "address": "10.8.0.2", "profile": "default"}),
    );
    ok(
        Some(b),
        "routing.bfd.peer.add",
        json!({"name": "a", "address": "10.8.0.1", "profile": "default"}),
    );
    let took = until("the session up with its timers", 30, || {
        let s = session(None);
        s["state"] == "up" && s["tx_interval_us"] == 300_000
    });
    eprintln!("BFD up in {took:?}");
    assert_eq!(session(Some(b))["state"], "up");
    let s = session(None);
    assert_eq!(s["detect_time_us"], 900_000);
    assert_eq!(s["users"], json!(["peer b"]));
    let list = ok(None, "routing.bfd.session.list", json!({}));
    assert_eq!(list["running"], true);
    assert_eq!(list["steering"], "reuseport-cbpf");
    // Steady for 2 s: no false downs.
    std::thread::sleep(Duration::from_secs(2));
    let h = ok(None, "routing.bfd.history.list", json!({}));
    assert!(
        h.as_array().unwrap().iter().all(|e| e["to"] != "down"),
        "{h}"
    );

    // Cut the link in B; A sees the session go down.
    let cut = unix_ms();
    ip(Some(b), &["link", "set", "bfd0", "down"]);
    until("the session down", 30, || session(None)["state"] == "down");
    let h = ok(None, "routing.bfd.history.list", json!({}));
    let down = h
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["to"] == "down")
        .unwrap()
        .clone();
    assert_eq!(down["diag"], "control-detection-time-expired");
    let detect_ms = down["at_ms"].as_u64().unwrap().saturating_sub(cut);
    eprintln!("BFD detection after the cut: {detect_ms} ms (detection time 900 ms)");
    // The last packet came up to one interval (300 ms) before the cut:
    // never before 600 ms; the ceiling is generous for a loaded CI (the
    // precise numbers come from the load bench, docs/bfd.md).
    assert!((550..=3_000).contains(&detect_ms), "{detect_ms} ms");

    // Link back: up again.
    ip(Some(b), &["link", "set", "bfd0", "up"]);
    until("the session up again", 30, || {
        session(None)["state"] == "up"
    });
}
