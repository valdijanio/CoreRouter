//! G4.4 — `system.metrics`: interface counters and the engine's own
//! counters in one query (what the daemon's Prometheus `/metrics` shows).
// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
use serde_json::{Value, json};

fn metrics(s: &mut Session) -> Value {
    s.execute("system.metrics", &json!({})).unwrap()
}

fn iface<'a>(m: &'a Value, name: &str) -> &'a Value {
    m["interfaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == name)
        .unwrap_or_else(|| panic!("no {name} in {m}"))
}

#[test]
fn every_lab_port_has_traffic_and_error_counters() {
    let mut s = Session::virtual_lab();
    let m = metrics(&mut s);
    let e1 = iface(&m, "ether1");
    assert_eq!(e1["type"], "ether");
    assert_eq!(e1["managed"], true);
    assert_eq!(e1["disabled"], false);
    for key in [
        "rx_bytes",
        "tx_bytes",
        "rx_packets",
        "tx_packets",
        "rx_errors",
        "tx_errors",
        "rx_dropped",
        "tx_dropped",
    ] {
        assert!(e1[key].is_u64(), "{key} in {e1}");
    }
    assert_eq!(m["interfaces"].as_array().unwrap().len(), 8);
}

#[test]
fn engine_counts_changes_queries_failures_and_commits() {
    let mut s = Session::virtual_lab();
    let before = metrics(&mut s)["engine"].clone();
    s.execute(
        "ip.address.add",
        &json!({"address": "10.0.0.1/24", "interface": "ether1"}),
    )
    .unwrap();
    s.execute(
        "ip.address.add",
        &json!({"address": "not-an-ip", "interface": "ether1"}),
    )
    .unwrap_err();
    s.execute("interface.list", &json!({"bogus": 1}))
        .unwrap_err();
    s.execute("no.such.command", &json!({})).unwrap_err();
    let e = metrics(&mut s)["engine"].clone();
    let delta = |k: &str| e[k].as_u64().unwrap() - before[k].as_u64().unwrap();
    assert_eq!(delta("changes_ok"), 1);
    assert_eq!(delta("changes_failed"), 1);
    // The second `system.metrics` counts itself only after it answers.
    assert_eq!(delta("queries_ok"), 1);
    assert_eq!(delta("queries_failed"), 1);
    assert_eq!(delta("unknown"), 1);
    assert_eq!(delta("commits_ok"), 1);
    assert_eq!(delta("commits_failed"), 0);
}

#[test]
fn a_transactional_commit_is_counted() {
    let mut s = Session::virtual_lab();
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    s.execute(
        "ip.address.add",
        &json!({"address": "10.0.0.1/24", "interface": "ether1"}),
    )
    .unwrap();
    s.execute("config.commit", &json!({})).unwrap();
    let m = metrics(&mut s);
    assert_eq!(m["engine"]["commits_ok"], 1);
    assert_eq!(m["mode"], "transactional");
    assert!(m["revision"].as_u64().unwrap() >= 1);
}

#[test]
fn a_disabled_interface_is_reported_as_such() {
    let mut s = Session::virtual_lab();
    s.execute(
        "interface.set",
        &json!({"name": "ether3", "disabled": true}),
    )
    .unwrap();
    let m = metrics(&mut s);
    let e3 = iface(&m, "ether3");
    assert_eq!(e3["disabled"], true);
    assert_eq!(e3["running"], false);
}
