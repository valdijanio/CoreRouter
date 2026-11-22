//! Two `corerouter-daemon`s on the two ends of a veth pair, each in its own
//! network namespace, find each other with CRDP and list each other in
//! `ip.neighbor.list` — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns
//! ```
//!
//! (`cargo xtask netns` runs it.) Router A lives in the namespace the test
//! runs in; router B in a child namespace (`unshare --net`), reached with
//! `nsenter`. Both use the virtual backend, whose first port is `ether1`, so
//! each kernel end of the veth is named `ether1` too. Control channels stay
//! on each namespace's loopback; B is queried by re-running this test binary
//! inside B (`query_helper`).
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
use corerouter_engine::Session;
use corerouter_hal::VirtualHal;
use corerouter_storage_fs::FileStorage;
use serde_json::{Value, json};

/// Seconds between announcements: hold is 4 × this.
const INTERVAL: u64 = 2;

/// A config dir holding a committed config: identity, the veth's IPv4
/// address on ether1 (if any) and discovery on ether1 every `INTERVAL` s.
fn config_dir(name: &str, address: Option<&str>) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("crdp-netns-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut s = Session::with_storage(
        Box::new(VirtualHal::default()),
        Box::new(FileStorage::open(&dir).unwrap()),
    );
    s.execute("system.identity.set", &json!({ "name": name }))
        .unwrap();
    if let Some(address) = address {
        s.execute(
            "ip.address.add",
            &json!({"address": address, "interface": "ether1"}),
        )
        .unwrap();
    }
    s.execute(
        "ip.neighbor.discovery.set",
        &json!({"interfaces": ["ether1"], "interval_secs": INTERVAL}),
    )
    .unwrap();
    dir
}

fn daemon(netns: Option<u32>, dir: &Path, log: &str) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join(log)).unwrap();
    let mut c = in_ns(netns, DAEMON);
    // Virtual ports over real veths: the interfaces transport, not the
    // lab's loopback default (G5.4).
    c.args(["--discovery-transport", "interfaces"]);
    c.args(["--control", "7979", "--config-dir"])
        .arg(dir)
        .arg("--token-file")
        .arg(common::token_file(netns, dir))
        .env("RUST_LOG", "info,corerouter_discovery=debug")
        .stdout(Stdio::null())
        .stderr(log);
    Kill(c.spawn().unwrap())
}

/// Not a test: run inside B's namespace by `neighbors(Some(pid))`.
#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn two_daemons_see_each_other() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    // IPv6 ff02::1 alone first, then with IPv4 broadcast as well.
    exchange(false);
    exchange(true);
}

fn exchange(v4: bool) {
    let tag = if v4 { "dual" } else { "v6" };
    // B's namespace, held open by a sleeper; the daemon joins it later.
    let holder = namespace_b();
    let b = holder.0.id();

    let pid = b.to_string();
    ip(
        None,
        &[
            "link", "add", "ether1", "type", "veth", "peer", "name", "ether1", "netns", &pid,
        ],
    );
    ip(Some(b), &["link", "set", "lo", "up"]);
    if v4 {
        ip(None, &["addr", "add", "10.99.0.1/24", "dev", "ether1"]);
        ip(Some(b), &["addr", "add", "10.99.0.2/24", "dev", "ether1"]);
    }
    ip(None, &["link", "set", "ether1", "up"]);
    ip(Some(b), &["link", "set", "ether1", "up"]);

    let address = |a: &'static str| v4.then_some(a);
    let dir_a = config_dir(&format!("crdp-a-{tag}"), address("10.99.0.1/24"));
    let dir_b = config_dir(&format!("crdp-b-{tag}"), address("10.99.0.2/24"));
    let a_name = format!("crdp-a-{tag}");
    let b_name = format!("crdp-b-{tag}");
    let a = daemon(None, &dir_a, &format!("crdp-netns-a-{tag}.log"));
    let b_daemon = daemon(Some(b), &dir_b, &format!("crdp-netns-b-{tag}.log"));

    // Over IPv4 B may show up before its link-local address has passed
    // duplicate address detection; wait until it announces that too.
    let link_local = |row: &Value| {
        row["addresses"].as_array().is_some_and(|a| {
            a.iter()
                .any(|x| x.as_str().is_some_and(|x| x.starts_with("fe80::")))
        })
    };
    wait_for("A to list B with its link-local address", || {
        sees(&neighbors(None), &b_name).is_some_and(link_local)
    });
    wait_for("B to list A", || {
        sees(&neighbors(Some(b)), &a_name).is_some()
    });

    let rows = neighbors(None);
    let row = sees(&rows, &b_name).unwrap();
    assert_eq!(row["interface"], "ether1");
    assert_eq!(row["protocol"], "crdp");
    assert_eq!(row["remote_interface"], "ether1");
    assert_eq!(row["platform"], "CoreRouter");
    assert_eq!(row["mgmt"]["control"], 7979);
    let addresses: Vec<&str> = row["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        addresses.iter().any(|a| a.starts_with("fe80::")),
        "{addresses:?}"
    );
    if v4 {
        assert_eq!(row["address"], "10.99.0.2");
    }
    // One row per node and interface, though it arrives over IPv4 and IPv6.
    assert_eq!(rows.iter().filter(|r| r["identity"] == b_name).count(), 1);
    // The node id came from B's config dir.
    let saved = std::fs::read_to_string(dir_b.join("node-id")).unwrap();
    assert_eq!(row["node_id"].as_str().unwrap(), saved.trim());

    // A turns discovery off: its goodbye makes B forget it at once, well
    // before the hold time (4 × INTERVAL) would run out.
    let off = Instant::now();
    let mut c = common::client(
        CONTROL,
        std::fs::read_to_string(dir_a.join("local.token"))
            .ok()
            .map(|t| t.trim().to_owned()),
    )
    .unwrap();
    c.call(
        "engine.execute",
        json!({"command": "ip.neighbor.discovery.set", "params": {"enabled": false}}),
    )
    .unwrap();
    wait_for("B to forget A", || {
        sees(&neighbors(Some(b)), &a_name).is_none()
    });
    assert!(
        off.elapsed() < Duration::from_secs(3 * INTERVAL),
        "forgotten after {:?}: the goodbye did not arrive",
        off.elapsed()
    );
    assert!(
        neighbors(None).is_empty(),
        "A lists nothing with discovery off"
    );

    drop((a, b_daemon));
    // Deleting one end of the veth deletes both. Before B's namespace
    // goes: the kernel tears a namespace down later, in a workqueue, and
    // takes the veth with it, so after `drop(holder)` our end may be gone
    // already ("Cannot find device", CI 2026-10-26) or still there when the
    // next exchange adds its own.
    ip(None, &["link", "del", "ether1"]);
    drop(holder);
    for d in [dir_a, dir_b] {
        let _ = std::fs::remove_dir_all(d);
    }
}
