//! G4.2a: a `--backend linux` daemon's DHCP server hands a lease to our own
//! DHCP client (a second daemon, `ip.dhcp-client`) across a veth, finds the
//! address a squatter holds by its ARP probe, names the lease in the DNS,
//! renews it, keeps it across its own restart (the journal) and gives the
//! same address back after a release — inside throwaway network namespaces,
//! no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_dhcp_server
//! ```
//!
//! ```text
//!   this ns: daemon A (server)        namespace B: daemon B (client)
//!   lan0 10.77.0.1/24 ──── veth ────── cli0 (DHCP client)
//!                                      └ sq0 macvlan 10.77.0.10/24 (squatter)
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
use std::process::Stdio;
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

fn lease(address: &str) -> Option<Value> {
    ok(None, "ip.dhcp-server.lease.print", json!({}))
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["address"] == address)
        .cloned()
}

fn stats() -> Value {
    ok(None, "ip.dhcp-server.statistics.print", json!({}))
}

fn acks(st: &Value) -> u64 {
    st["sent"]["ack"].as_u64().unwrap_or(0)
}

/// Wait up to `secs` for `ok`.
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
fn linux_dhcp_server_serves_our_client() {
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
    // The squatter: another host on the link, already using .10.
    ip(
        bpid,
        &[
            "link", "add", "sq0", "link", "cli0", "type", "macvlan", "mode", "bridge",
        ],
    );
    ip(bpid, &["addr", "add", "10.77.0.10/24", "dev", "sq0"]);
    ip(bpid, &["link", "set", "sq0", "up"]);
    ip(None, &["link", "set", "lan0", "up"]);

    let base = std::env::temp_dir().join(format!("g42a-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let dir_a = base.join("a");
    let dir_b = base.join("b");
    std::fs::create_dir_all(&dir_a).unwrap();
    std::fs::create_dir_all(&dir_b).unwrap();

    let a = daemon(None, &dir_a, "lan0", "g42a-server.log");
    for (cmd, p) in [
        (
            "ip.address.add",
            json!({"address": "10.77.0.1/24", "interface": "lan0"}),
        ),
        ("ip.dns.zone.add", json!({"name": "lan.test"})),
        (
            "ip.pool.add",
            json!({"name": "lan", "ranges": "10.77.0.10-10.77.0.20"}),
        ),
        (
            "ip.dhcp-server.add",
            json!({"interface": "lan0", "address_pool": "lan", "lease_time": "1m"}),
        ),
        (
            "ip.dhcp-server.network.add",
            json!({"address": "10.77.0.0/24", "gateway": "10.77.0.1", "dns_server": "10.77.0.1", "dns_zone": "lan.test"}),
        ),
    ] {
        ok(None, cmd, p);
    }
    wait_for("the server listening", || {
        ok(None, "ip.dhcp-server.print", json!({}))[0]["status"] == "running"
    });

    let _client = daemon(bpid, &dir_b, "cli0", "g42a-client.log");
    ok(bpid, "ip.dhcp-client.add", json!({"interface": "cli0"}));
    let client_row = || ok(bpid, "ip.dhcp-client.list", json!({}))[0].clone();
    wait_long("a lease", 30, || client_row()["status"] == "bound");
    let row = client_row();
    // RFC 2131 §3.1: .10 answered the probe, so the client got .11.
    assert_eq!(row["address"], "10.77.0.11/24", "{row}");
    assert_eq!(row["gateway"], "10.77.0.1");
    assert_eq!(row["dhcp_server"], "10.77.0.1");
    let conflict = lease("10.77.0.10").expect("the squatter's address is held");
    assert_eq!(conflict["status"], "conflict", "{conflict}");
    assert!(
        conflict["reason"].as_str().unwrap().contains("ARP reply"),
        "{conflict}"
    );
    let bound = lease("10.77.0.11").unwrap();
    assert_eq!(bound["status"], "bound");
    assert!(
        bound["dns"].as_str().unwrap().ends_with(".lan.test"),
        "{bound}"
    );

    // Renewal at T1 (30 s): a unicast REQUEST, ACKed.
    wait_long("a renewal", 45, || acks(&stats()) >= 2);
    wait_long("the client bound again", 10, || {
        client_row()["status"] == "bound"
    });

    // The server restarts: the journal brings the lease back, the client
    // keeps renewing the same address.
    drop(a);
    assert!(
        std::fs::read_to_string(dir_a.join("journal-dhcp-leases.log"))
            .unwrap()
            .contains("10.77.0.11")
    );
    let _a = daemon(None, &dir_a, "lan0", "g42a-server2.log");
    let back = lease("10.77.0.11").expect("the lease after a restart");
    assert_eq!(back["status"], "bound", "{back}");
    wait_long("a renewal by the new server", 45, || acks(&stats()) >= 1);
    wait_long("the client bound again", 10, || {
        client_row()["status"] == "bound"
    });
    assert_eq!(client_row()["address"], "10.77.0.11/24");

    // RELEASE: the lease ends there and then. Our client (like RouterOS'
    // `release`) asks again at once, and gets its previous address back
    // (RFC 2131 §4.3.1), as a new binding.
    let before = acks(&stats());
    ok(bpid, "ip.dhcp-client.release", json!({"id": row["id"]}));
    wait_long("the release", 10, || {
        let st = stats();
        st["received"]["release"] == 1 && acks(&st) > before
    });
    wait_long("the client bound again", 10, || {
        client_row()["status"] == "bound"
    });
    assert_eq!(client_row()["address"], "10.77.0.11/24", "affinity");
    let _ = std::fs::remove_dir_all(&base);
}
