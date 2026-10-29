//! G2.1c — `/ip firewall raw`: commands, validation (no connection
//! matchers before conntrack, notrack only in raw), the lockout check in
//! raw and through a `notrack` that makes filter see `untracked`, the
//! bogons template and the render.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::{Caller, EngineError, Link, Principal, Session};
use serde_json::{Value, json};

fn router() -> Session {
    let mut s = Session::virtual_lab();
    for p in [
        json!({"address": "203.0.113.1/24", "interface": "ether1"}),
        json!({"address": "192.168.88.1/24", "interface": "ether2"}),
    ] {
        ok(&mut s, "ip.address.add", p);
    }
    for (list, iface) in [("WAN", "ether1"), ("LAN", "ether2")] {
        ok(
            &mut s,
            "interface.list.member.add",
            json!({"list": list, "interface": iface}),
        );
    }
    s
}

fn from_wan() -> Caller {
    Caller::new(9, "tls 198.51.100.7:50123".to_owned())
        .with_principal(Principal::Local)
        .with_link(Link {
            peer: "198.51.100.7:50123".parse().unwrap(),
            local: "203.0.113.1:8729".parse().unwrap(),
        })
}

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn err(s: &mut Session, id: &str, p: Value) -> String {
    match s.execute(id, &p) {
        Err(e) => e.to_string(),
        Ok(v) => panic!("{id} {p}: expected an error, got {v}"),
    }
}

fn raw(s: &mut Session) -> Vec<Value> {
    ok(s, "ip.firewall.raw.list", Value::Null)
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn raw_rules_add_list_move_and_render_before_conntrack() {
    let mut s = router();
    let a = ok(
        &mut s,
        "ip.firewall.raw.add",
        json!({"chain": "prerouting", "action": "notrack", "protocol": "udp", "dst_port": "53"}),
    );
    ok(
        &mut s,
        "ip.firewall.raw.add",
        json!({"action": "drop", "src_address": "192.0.2.0/24", "place_before": a["id"]}),
    );
    let list = raw(&mut s);
    assert_eq!(list.len(), 2);
    assert_eq!(list[0]["action"], "drop");
    assert_eq!(list[0]["chain"], "prerouting", "default chain");
    assert_eq!(list[1]["action"], "notrack");
    assert!(
        list[1]["description"]
            .as_str()
            .unwrap()
            .contains("Não rastreia"),
        "{}",
        list[1]
    );
    ok(&mut s, "ip.firewall.raw.move", json!({"id": a["id"]}));
    let script = corerouter_firewall::script(s.store().candidate(), &[]);
    assert!(script.contains("hook prerouting priority raw"), "{script}");
    assert!(script.contains("notrack accept"), "{script}");
    ok(&mut s, "ip.firewall.raw.remove", json!({"id": a["id"]}));
    assert_eq!(raw(&mut s).len(), 1);
}

#[test]
fn raw_refuses_what_needs_conntrack_and_notrack_elsewhere() {
    let mut s = router();
    let e = err(
        &mut s,
        "ip.firewall.raw.add",
        json!({"action": "drop", "connection_state": "invalid"}),
    );
    // Not even in the params contract of raw.add…
    assert!(e.contains("connection_state"), "{e}");
    // …and a config that has one anyway is refused by the validator.
    let mut cfg = corerouter_firewall::sample::sample();
    cfg.ip.firewall.raw = vec![
        corerouter_firewall::sample::rule(
            1,
            "prerouting",
            corerouter_firewall::sample::m(&[("connection_state", "invalid")]).unwrap(),
            corerouter_model::firewall::Action::Drop,
        )
        .unwrap(),
    ]
    .into();
    let issues = corerouter_firewall::validate(&cfg);
    assert!(
        issues
            .iter()
            .any(|i| i.to_string().contains("before connection tracking")),
        "{issues:?}"
    );
    let e = err(&mut s, "ip.firewall.raw.add", json!({"action": "reject"}));
    assert!(e.contains("not a raw action"), "{e}");
    let e = err(
        &mut s,
        "ip.firewall.filter.add",
        json!({"chain": "input", "action": "notrack"}),
    );
    assert!(e.contains("not a filter action"), "{e}");
    assert!(raw(&mut s).is_empty(), "nothing added");
}

#[test]
fn raw_drop_and_notrack_are_lockouts_from_the_wan() {
    let mut s = router();
    let wan = from_wan();
    let r = s.execute_as(
        &wan,
        "ip.firewall.raw.add",
        &json!({"action": "drop", "in_interface_list": "WAN"}),
    );
    let msg = match r {
        Err(e @ EngineError::Lockout(_)) => e.to_string(),
        other => panic!("expected a lockout, got {other:?}"),
    };
    assert!(msg.contains("raw rule"), "{msg}");
    assert!(msg.contains("before connection tracking"), "{msg}");

    // Filter accepts established and drops the WAN: fine while tracked…
    ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"chain": "input", "connection_state": "established,related"}),
    );
    ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"chain": "input", "protocol": "tcp", "dst_port": "8729", "connection_state": "new"}),
    );
    ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"chain": "input", "action": "drop", "in_interface_list": "WAN"}),
    );
    // …but a notrack makes the session `untracked`: the drop takes it.
    let r = s.execute_as(
        &wan,
        "ip.firewall.raw.add",
        &json!({"action": "notrack", "protocol": "tcp", "dst_port": "8729"}),
    );
    let msg = match r {
        Err(e @ EngineError::Lockout(_)) => e.to_string(),
        other => panic!("expected a lockout, got {other:?}"),
    };
    assert!(msg.contains("filter rule"), "{msg}");
    // Notrack on something else (DNS) does not touch the session.
    s.execute_as(
        &wan,
        "ip.firewall.raw.add",
        &json!({"action": "notrack", "protocol": "udp", "dst_port": "53"}),
    )
    .unwrap();
}

#[test]
fn bogons_template_drops_reserved_sources_from_the_wan() {
    let mut s = router();
    let out = ok(&mut s, "ip.firewall.template.raw-bogons", json!({}));
    assert_eq!(out["list"], "bogons");
    assert_eq!(out["rules"].as_array().unwrap().len(), 4, "section + 3");
    let entries = out["entries"].as_u64().unwrap();
    assert!(entries >= 15, "{entries}");
    let list = raw(&mut s);
    assert!(list[0]["section"].is_string());
    assert!(
        list.iter()
            .filter(|r| r["section"].is_null())
            .all(|r| r["chain"] == "prerouting")
    );
    let al = ok(
        &mut s,
        "ip.firewall.address-list.list",
        json!({"list": "bogons"}),
    );
    let addrs: Vec<&str> = al
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["address"].as_str().unwrap())
        .collect();
    assert!(addrs.contains(&"192.0.2.0/24") && addrs.contains(&"2001:db8::/32"));
    assert!(!addrs.contains(&"10.0.0.0/8"), "private only when asked");

    // Again: refused, then replaced with private space included.
    let e = err(&mut s, "ip.firewall.template.raw-bogons", json!({}));
    assert!(e.contains("replace=true"), "{e}");
    let out = ok(
        &mut s,
        "ip.firewall.template.raw-bogons",
        json!({"replace": true, "private": true}),
    );
    assert_eq!(raw(&mut s).len(), 4, "the old rules went");
    assert_eq!(out["entries"].as_u64().unwrap(), entries + 5);

    // An empty WAN list matches nothing: refused.
    let mut empty = Session::virtual_lab();
    let e = err(&mut empty, "ip.firewall.template.raw-bogons", json!({}));
    assert!(e.contains("empty"), "{e}");
}
