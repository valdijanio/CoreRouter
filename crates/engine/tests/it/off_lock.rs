//! G0.31b: the big lists answer through `Session::defer`. Built after the
//! lock or in place, the answer is the same.
#![allow(clippy::unwrap_used)]

use corerouter_engine::off_lock::Reply;
use corerouter_engine::{Caller, Session};
use serde_json::json;

/// The queries that defer, with the parameters to call them with.
const DEFERRED: &[(&str, &str)] = &[
    ("ip.route.list", "{}"),
    ("ip.route.list", r#"{"family": "ipv4", "state": "active"}"#),
    ("ip.firewall.filter.list", "{}"),
    ("ip.firewall.filter.list", r#"{"chain": "input"}"#),
    ("ip.firewall.nat.list", "{}"),
    ("ip.firewall.mangle.list", "{}"),
    ("ip.firewall.raw.list", "{}"),
    ("ip.firewall.address-list.list", "{}"),
    ("ip.firewall.address-list.list", r#"{"list": "blocked"}"#),
    ("ip.firewall.preview", "{}"),
    ("config.drift.list", "{}"),
];

#[test]
fn deferred_queries_answer_as_in_place() {
    let mut s = Session::virtual_lab();
    for (id, params) in [
        (
            "ip.address.add",
            json!({"address": "192.0.2.1/24", "interface": "ether1"}),
        ),
        (
            "ip.route.add",
            json!({"dst_address": "198.51.100.0/24", "gateway": "192.0.2.254"}),
        ),
        (
            "ip.firewall.filter.add",
            json!({"chain": "input", "action": "accept"}),
        ),
        (
            "ip.firewall.nat.add",
            json!({"chain": "srcnat", "action": "masquerade"}),
        ),
        (
            "ip.firewall.address-list.add",
            json!({"list": "blocked", "address": "203.0.113.7"}),
        ),
        (
            "ip.firewall.address-list.add",
            json!({"list": "blocked", "address": "203.0.113.8", "timeout": "1h"}),
        ),
        ("config.mode.set", json!({"mode": "transactional"})),
        (
            "ip.firewall.filter.add",
            json!({"chain": "forward", "action": "drop"}),
        ),
    ] {
        s.execute(id, &params).unwrap();
    }
    for (id, params) in DEFERRED {
        let p: serde_json::Value = serde_json::from_str(params).unwrap();
        let now = s.execute(id, &p).unwrap();
        let reply = s.execute_reply_as(&Caller::local(), id, &p).unwrap();
        assert!(
            matches!(reply, Reply::Later(_)),
            "{id} {params} did not defer"
        );
        assert_eq!(reply.finish().unwrap(), now, "{id} {params}");
    }
}

/// Inside a batch every step answers in place (a later step may read it).
#[test]
fn a_batch_never_defers() {
    let mut s = Session::virtual_lab();
    let out = s
        .batch_as(
            &Caller::local(),
            &json!([{"command": "ip.route.list"}, {"command": "ip.firewall.filter.list"}]),
            false,
        )
        .unwrap();
    let steps = out["results"].as_array().unwrap();
    assert_eq!(steps.len(), 2);
    assert!(steps.iter().all(|v| !v.is_null()), "{out}");
}
