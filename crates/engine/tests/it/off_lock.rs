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
            matches!(reply, Reply::Later(_) | Reply::Stream(_)),
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

/// G0.31h: `ip.route.list` is written row by row, and the bytes are the
/// JSON the `Value` of each row had (same keys, same order), with the
/// gateway checks, reasons and ECMP notices of the page's rows.
#[test]
fn a_streamed_list_is_the_json_of_its_rows() {
    let mut s = Session::virtual_lab();
    for (id, params) in [
        (
            "ip.address.add",
            json!({"address": "192.0.2.1/24", "interface": "ether1"}),
        ),
        (
            "ip.route.add",
            json!({"dst_address": "0.0.0.0/0", "gateway": "192.0.2.254", "comment": "up \"1\""}),
        ),
        (
            "ip.route.add",
            json!({"dst_address": "0.0.0.0/0", "gateway": "192.0.2.253"}),
        ),
        (
            "ip.route.add",
            json!({"dst_address": "198.51.100.0/24", "gateway": "192.0.2.9", "distance": 5, "check_gateway": "ping"}),
        ),
        (
            "ip.route.add",
            json!({"dst_address": "198.51.100.0/24", "gateway": "192.0.2.8"}),
        ),
        (
            "ip.route.add",
            json!({"dst_address": "2001:db8::/32", "gateway": "ether2", "disabled": true}),
        ),
    ] {
        s.execute(id, &params).unwrap();
    }
    let reply = s
        .execute_reply_as(&Caller::local(), "ip.route.list", &json!({}))
        .unwrap();
    assert!(matches!(reply, Reply::Stream(_)), "{reply:?}");
    let mut bytes = Vec::new();
    reply.write(&mut bytes).unwrap();
    let list: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(String::from_utf8(bytes).unwrap(), list.to_string());
    let page = s.execute("ip.route.page", &json!({"limit": 5000})).unwrap();
    assert_eq!(list, page["rows"]);
    let rows = list.as_array().unwrap();
    assert!(rows.len() >= 6, "{list}");
    // Every key of the contract (`ip.route.list`'s params doc), in every row.
    const KEYS: &[&str] = &[
        "active",
        "changed_at",
        "changed_secs",
        "check_gateway",
        "comment",
        "connected",
        "disabled",
        "distance",
        "dst_address",
        "dynamic",
        "ecmp",
        "family",
        "flags",
        "gateway",
        "gateway_address",
        "gateway_interface",
        "gateway_status",
        "id",
        "immediate_gw",
        "interface",
        "key",
        "notice",
        "origin",
        "reason",
        "reason_args",
        "reason_id",
        "routing_table",
        "state",
        "static",
    ];
    for r in rows {
        let keys: Vec<&str> = r.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, KEYS, "{r}");
    }
    assert!(rows.iter().any(|r| !r["notice"].is_null()), "{list}");
    assert!(rows.iter().any(|r| !r["reason_args"].is_null()), "{list}");
    assert!(rows.iter().any(|r| !r["check_gateway"].is_null()), "{list}");
    // Filters apply to the stream as to the rows.
    let v6 = s
        .execute(
            "ip.route.list",
            &json!({"family": "ipv6", "origin": "static"}),
        )
        .unwrap();
    assert_eq!(v6.as_array().unwrap().len(), 1, "{v6}");
}

/// G0.31h: one list of 10 000+ routes at a time: while one is being
/// written the next is refused as busy (with what to do), small or
/// filtered lists still answer, and the slot comes back when the first is
/// written or dropped.
#[test]
fn one_large_list_at_a_time() {
    let mut s = Session::virtual_lab();
    s.execute(
        "ip.address.add",
        &json!({"address": "192.0.2.1/24", "interface": "ether1"}),
    )
    .unwrap();
    let steps: Vec<serde_json::Value> = (0..10_000)
        .map(|i| {
            json!({"command": "ip.route.add", "params": {
                "dst_address": format!("10.{}.{}.0/24", i / 256, i % 256),
                "gateway": "192.0.2.254",
            }})
        })
        .collect();
    s.batch(&serde_json::Value::Array(steps), true).unwrap();
    let list = |s: &mut Session, p: serde_json::Value| {
        s.execute_reply_as(&Caller::local(), "ip.route.list", &p)
    };
    let first = list(&mut s, json!({})).unwrap();
    let busy = list(&mut s, json!({})).unwrap_err().to_string();
    assert!(
        busy.contains("busy") && busy.contains("ip.route.page"),
        "{busy}"
    );
    // A filter that leaves a few routes is not large.
    let small = list(&mut s, json!({"origin": "connected"})).unwrap();
    assert_eq!(small.finish().unwrap().as_array().unwrap().len(), 1);
    let mut out = Vec::new();
    first.write(&mut out).unwrap();
    assert!(out.len() > 10_000 * 100, "{}", out.len());
    let again = list(&mut s, json!({})).unwrap();
    assert!(list(&mut s, json!({})).is_err());
    drop(again);
    assert!(list(&mut s, json!({})).is_ok());
}
