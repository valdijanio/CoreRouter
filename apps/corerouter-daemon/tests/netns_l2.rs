//! G5.2: two `corerouter-daemon --backend linux` on two veth pairs, each in
//! its own network namespace, list each other as CRDP **and** LLDP; a
//! synthetic MNDP announcement shows up as MNDP; a shutdown LLDPDU (TTL 0)
//! removes the row at once; and nothing is recorded on an interface without
//! discovery. No root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_l2
//! ```
//!
//! (`cargo xtask netns` runs it.) Router A lives in the namespace the test
//! runs in, router B in a child namespace (see `netns.rs`). The linux
//! backend lists links over netlink in its own namespace (G1.18). Each
//! veth's peer lives in the other namespace, which the ownership policy
//! takes for a container's link, so the daemons run with `--manage ether*`:
//! these veths are the lab's cables.
//!
//! Links: `ether1` (A) ↔ `ether1` (B) with 10.99.0.0/24, discovery on both
//! ends; `ether2` (A) ↔ `ether2` (B), discovery on B only.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};

/// Seconds between announcements: hold/TTL is 4 × this.
const INTERVAL: u64 = 5;
const MNDP_ENV: &str = "G52_MNDP_SEND";

fn daemon(netns: Option<u32>, dir: &Path, log: &str) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join(log)).unwrap();
    let mut c = in_ns(netns, DAEMON);
    c.args([
        "--backend",
        "linux",
        "--manage",
        "ether*",
        "--control",
        "7979",
        "--config-dir",
    ])
    .arg(dir)
    .arg("--token-file")
    .arg(common::token_file(netns, dir))
    .env("RUST_LOG", "info,corerouter_daemon=debug")
    .stdout(Stdio::null())
    .stderr(log);
    Kill(c.spawn().unwrap())
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("g52-netns-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Configure a running daemon over its control channel.
fn configure(netns: Option<u32>, identity: &str, address: &str, discovery: &[&str]) {
    wait_for(&format!("{identity}'s control channel"), || {
        call(netns, "system.identity.set", json!({ "name": identity })).is_ok()
    });
    for (cmd, params) in [
        (
            "ip.address.add",
            json!({"address": address, "interface": "ether1"}),
        ),
        (
            "ip.neighbor.discovery.set",
            json!({"interfaces": discovery, "interval_secs": INTERVAL}),
        ),
    ] {
        call(netns, cmd, params).unwrap_or_else(|e| panic!("{identity}: {cmd}: {e}"));
    }
}

fn row<'a>(rows: &'a [Value], identity: &str, protocol: &str) -> Option<&'a Value> {
    rows.iter()
        .find(|r| r["identity"] == identity && r["protocol"] == protocol)
}

/// A RouterOS-like MNDP announcement, built by hand (CoreRouter has no MNDP
/// encoder: it never sends MNDP).
fn mndp_packet() -> Vec<u8> {
    let mut p = vec![0, 0, 0, 7];
    let mut tlv = |t: u16, v: &[u8]| {
        p.extend_from_slice(&t.to_be_bytes());
        p.extend_from_slice(&u16::try_from(v.len()).unwrap().to_be_bytes());
        p.extend_from_slice(v);
    };
    tlv(1, &[0x4c, 0x5e, 0x0c, 0xaa, 0xbb, 0xcc]);
    tlv(5, b"mikrotik-test");
    tlv(7, b"7.16 (stable)");
    tlv(8, b"MikroTik");
    tlv(10, &4242u32.to_le_bytes());
    tlv(12, b"RB5009UG+S+");
    tlv(16, b"ether7");
    tlv(17, &[10, 99, 0, 2]);
    p
}

/// Not a test: run inside B to broadcast one MNDP packet on 10.99.0.0/24.
#[test]
fn mndp_send_helper() {
    if std::env::var_os(MNDP_ENV).is_none() {
        return;
    }
    let s = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::new(10, 99, 0, 2), 0)).unwrap();
    s.set_broadcast(true).unwrap();
    s.send_to(
        &mndp_packet(),
        SocketAddrV4::new(Ipv4Addr::new(10, 99, 0, 255), 5678),
    )
    .unwrap();
    println!("MNDP-SENT");
}

fn send_mndp_from(b: u32) {
    let out = in_ns(Some(b), &std::env::current_exe().unwrap().to_string_lossy())
        .args(["mndp_send_helper", "--exact", "--nocapture"])
        .env(MNDP_ENV, "1")
        .env_remove(ENV)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("MNDP-SENT"), "MNDP helper: {text}");
}

/// Not a test: run inside B by `call`.
#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn lldp_and_mndp_reach_the_neighbor_table() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    let holder = namespace_b();
    let b = holder.0.id();
    let pid = b.to_string();
    ip(Some(b), &["link", "set", "lo", "up"]);
    for name in ["ether1", "ether2"] {
        ip(
            None,
            &[
                "link", "add", name, "type", "veth", "peer", "name", name, "netns", &pid,
            ],
        );
        ip(None, &["link", "set", name, "up"]);
        ip(Some(b), &["link", "set", name, "up"]);
    }

    let (dir_a, dir_b) = (temp_dir("a"), temp_dir("b"));
    let a = daemon(None, &dir_a, "g52-netns-a.log");
    let b_daemon = daemon(Some(b), &dir_b, "g52-netns-b.log");
    configure(None, "g52-a", "10.99.0.1/24", &["ether1"]);
    configure(Some(b), "g52-b", "10.99.0.2/24", &["ether1", "ether2"]);

    // A lists B twice on ether1: once per protocol.
    wait_for("A to list B as crdp and lldp", || {
        let rows = neighbors(None);
        row(&rows, "g52-b", "crdp").is_some() && row(&rows, "g52-b", "lldp").is_some()
    });
    wait_for("B to list A as lldp", || {
        row(&neighbors(Some(b)), "g52-a", "lldp").is_some()
    });
    let rows = neighbors(None);
    let crdp = row(&rows, "g52-b", "crdp").unwrap();
    let lldp = row(&rows, "g52-b", "lldp").unwrap();
    assert_eq!(lldp["interface"], "ether1");
    assert_eq!(lldp["remote_interface"], "ether1");
    assert_eq!(lldp["platform"], "CoreRouter");
    assert_eq!(lldp["version"], crdp["version"]);
    // The chassis id is the CRDP node id: both rows name the same node.
    assert_eq!(lldp["node_id"], crdp["node_id"]);
    let saved = std::fs::read_to_string(dir_b.join("node-id")).unwrap();
    assert_eq!(lldp["node_id"].as_str().unwrap(), saved.trim());
    // Management Address = B's addresses on that interface.
    assert_eq!(lldp["address"], "10.99.0.2");

    // `protocol` filters.
    for p in ["lldp", "crdp"] {
        let only = neighbors_with(None, json!({ "protocol": p }));
        assert!(!only.is_empty(), "{p}");
        assert!(only.iter().all(|r| r["protocol"] == p), "{p}: {only:?}");
    }

    // Synthetic MNDP from B's side of ether1.
    send_mndp_from(b);
    wait_for("A to list the MikroTik as mndp", || {
        row(&neighbors(None), "mikrotik-test", "mndp").is_some()
    });
    let rows = neighbors_with(None, json!({"protocol": "mndp"}));
    assert_eq!(
        rows.len(),
        1,
        "only the synthetic one (CoreRouter never sends MNDP): {rows:?}"
    );
    let m = &rows[0];
    assert_eq!(m["interface"], "ether1");
    assert_eq!(m["platform"], "MikroTik");
    assert_eq!(m["board"], "RB5009UG+S+");
    assert_eq!(m["version"], "7.16 (stable)");
    assert_eq!(m["remote_interface"], "ether7");
    assert_eq!(m["uptime_secs"], 4242);
    assert_eq!(m["address"], "10.99.0.2");

    // B announces on ether2 too, but A has no discovery there: nothing is
    // recorded. Give B a full interval more than it needs.
    std::thread::sleep(Duration::from_secs(INTERVAL + 1));
    let on_ether2: Vec<Value> = neighbors(None)
        .into_iter()
        .filter(|r| r["interface"] == "ether2")
        .collect();
    assert!(on_ether2.is_empty(), "{on_ether2:?}");
    assert!(
        neighbors(Some(b))
            .iter()
            .all(|r| r["interface"] == "ether1"),
        "A never sends on ether2"
    );
    // B hears its own synthetic broadcast too (local delivery); nothing
    // else may be MNDP, since CoreRouter never sends it.
    let b_mndp = neighbors_with(Some(b), json!({"protocol": "mndp"}));
    assert!(
        b_mndp.iter().all(|r| r["identity"] == "mikrotik-test"),
        "A never sends MNDP: {b_mndp:?}"
    );

    // A stops discovery on ether1: its shutdown LLDPDU makes B drop the
    // row at once, well before the TTL (4 × INTERVAL) would run out.
    let off = Instant::now();
    call(None, "ip.neighbor.discovery.set", json!({"interfaces": []})).unwrap();
    wait_for("B to forget A's LLDP row", || {
        row(&neighbors(Some(b)), "g52-a", "lldp").is_none()
    });
    assert!(
        off.elapsed() < Duration::from_secs(2 * INTERVAL),
        "forgotten after {:?}: the shutdown LLDPDU did not arrive",
        off.elapsed()
    );

    drop((a, b_daemon));
    // Deleting one end of a veth deletes both; then B's namespace goes.
    for name in ["ether1", "ether2"] {
        ip(None, &["link", "del", name]);
    }
    drop(holder);
    for d in [dir_a, dir_b] {
        let _ = std::fs::remove_dir_all(d);
    }
}
