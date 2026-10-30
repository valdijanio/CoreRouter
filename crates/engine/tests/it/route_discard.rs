//! G1.5a — routes without next hop (`blackhole`, `unreachable`,
//! `prohibit`): the three ways to ask for one (RouterOS v6 `type`, v7
//! `blackhole`, the word as `gateway`), what `ip.route.list` shows, the
//! validation (no gateway, no check, no shared distance with a route of the
//! other kind) and that a failed command changes nothing.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn fails(s: &mut Session, id: &str, p: Value, needle: &str) {
    let before = s.store().candidate().clone();
    let rev = s.store().current_revision();
    let err = s.execute(id, &p).unwrap_err().to_string();
    assert!(err.contains(needle), "{id} {p}: '{err}' lacks '{needle}'");
    assert_eq!(s.store().candidate(), &before, "{id} left changes behind");
    assert_eq!(s.store().current_revision(), rev);
}

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "192.0.2.1/24", "interface": "ether1"}),
    );
    s
}

fn add(s: &mut Session, p: Value) -> String {
    ok(s, "ip.route.add", p)["id"].as_str().unwrap().to_owned()
}

fn row(s: &mut Session, id: &str) -> Value {
    ok(s, "ip.route.list", json!({}))
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("{id} not listed"))
}

#[test]
fn three_ways_to_ask_and_what_the_list_shows() {
    let mut s = lab();
    let a = add(
        &mut s,
        json!({"dst_address": "100.64.0.0/10", "blackhole": true}),
    );
    let b = add(
        &mut s,
        json!({"dst_address": "198.51.100.0/24", "type": "unreachable"}),
    );
    let c = add(
        &mut s,
        json!({"dst_address": "2001:db8:dead::/48", "gateway": "prohibit"}),
    );
    for (id, kind, flag) in [
        (&a, "blackhole", "ASB"),
        (&b, "unreachable", "ASU"),
        (&c, "prohibit", "ASP"),
    ] {
        let r = row(&mut s, id);
        assert_eq!(r["type"], kind, "{r}");
        assert_eq!(r["gateway"], kind, "{r}");
        assert_eq!(r["state"], "active", "{r}");
        assert_eq!(r["flags"], flag, "{r}");
        assert!(
            r["gateway_status"].is_null() && r["interface"].is_null(),
            "{r}"
        );
    }
    // A unicast route says so; the kernel side matches the config.
    let u = add(
        &mut s,
        json!({"dst_address": "0.0.0.0/0", "gateway": "192.0.2.254"}),
    );
    assert_eq!(row(&mut s, &u)["type"], "unicast");
    let drift = ok(&mut s, "config.drift.list", json!({}));
    assert!(
        drift.to_string().contains("[]") || drift["drift"].as_array().is_some_and(Vec::is_empty),
        "{drift}"
    );
}

#[test]
fn a_longer_unicast_prefix_still_wins_and_distance_decides_on_the_same_one() {
    let mut s = lab();
    // The pool is nulled, one /24 of it is routed (longest prefix match).
    let null = add(
        &mut s,
        json!({"dst_address": "100.64.0.0/10", "type": "blackhole"}),
    );
    let part = add(
        &mut s,
        json!({"dst_address": "100.64.1.0/24", "gateway": "192.0.2.9"}),
    );
    assert_eq!(row(&mut s, &null)["state"], "active");
    assert_eq!(row(&mut s, &part)["state"], "active");
    // The anchor of an announced prefix: the real path wins while it is up.
    let real = add(
        &mut s,
        json!({"dst_address": "203.0.113.0/24", "gateway": "192.0.2.9"}),
    );
    let anchor = add(
        &mut s,
        json!({"dst_address": "203.0.113.0/24", "blackhole": true, "distance": 254}),
    );
    assert_eq!(row(&mut s, &real)["state"], "active");
    let r = row(&mut s, &anchor);
    assert_eq!(r["state"], "standby", "{r}");
    assert_eq!(r["reason_id"], "loses-distance", "{r}");
    ok(
        &mut s,
        "ip.route.set",
        json!({"id": real, "disabled": true}),
    );
    assert_eq!(row(&mut s, &anchor)["state"], "active");
}

#[test]
fn set_turns_a_route_into_a_discard_and_back() {
    let mut s = lab();
    let id = add(
        &mut s,
        json!({"dst_address": "198.18.0.0/15", "gateway": "192.0.2.9"}),
    );
    ok(
        &mut s,
        "ip.route.set",
        json!({"id": id, "type": "prohibit"}),
    );
    assert_eq!(row(&mut s, &id)["type"], "prohibit");
    // Back to unicast needs a gateway.
    fails(
        &mut s,
        "ip.route.set",
        json!({"id": id, "type": "unicast"}),
        "required",
    );
    fails(
        &mut s,
        "ip.route.set",
        json!({"id": id, "blackhole": false}),
        "required",
    );
    ok(
        &mut s,
        "ip.route.set",
        json!({"id": id, "type": "unicast", "gateway": "192.0.2.9"}),
    );
    let r = row(&mut s, &id);
    assert_eq!(
        (r["type"].as_str(), r["gateway"].as_str()),
        (Some("unicast"), Some("192.0.2.9"))
    );
    // A gateway alone keeps working, and the words work as a gateway too.
    ok(
        &mut s,
        "ip.route.set",
        json!({"id": id, "gateway": "blackhole"}),
    );
    assert_eq!(row(&mut s, &id)["type"], "blackhole");
}

#[test]
fn what_is_refused() {
    let mut s = lab();
    let dst = "198.51.100.0/24";
    fails(
        &mut s,
        "ip.route.add",
        json!({"dst_address": dst}),
        "required",
    );
    fails(
        &mut s,
        "ip.route.add",
        json!({"dst_address": dst, "type": "unicast"}),
        "required",
    );
    fails(
        &mut s,
        "ip.route.add",
        json!({"dst_address": dst, "type": "blackhole", "gateway": "192.0.2.9"}),
        "no gateway",
    );
    fails(
        &mut s,
        "ip.route.add",
        json!({"dst_address": dst, "type": "unicast", "gateway": "unreachable"}),
        "needs a gateway",
    );
    fails(
        &mut s,
        "ip.route.add",
        json!({"dst_address": dst, "type": "prohibit", "blackhole": true}),
        "contradicts",
    );
    fails(
        &mut s,
        "ip.route.add",
        json!({"dst_address": dst, "type": "null0"}),
        "is not one of",
    );
    fails(
        &mut s,
        "ip.route.add",
        json!({"dst_address": dst, "blackhole": true, "check_gateway": "ping"}),
        "has none to check",
    );
    // Same distance as a route of the other kind: the kernel holds one.
    add(&mut s, json!({"dst_address": dst, "gateway": "192.0.2.9"}));
    fails(
        &mut s,
        "ip.route.add",
        json!({"dst_address": dst, "blackhole": true}),
        "cannot share a distance",
    );
    add(
        &mut s,
        json!({"dst_address": dst, "blackhole": true, "distance": 2}),
    );
    // Two of the same kind at one distance: the same next hop twice.
    fails(
        &mut s,
        "ip.route.add",
        json!({"dst_address": dst, "blackhole": true, "distance": 2}),
        "already goes",
    );
    fails(
        &mut s,
        "ip.route.add",
        json!({"dst_address": dst, "type": "unreachable", "distance": 2}),
        "cannot share a distance",
    );
}

#[test]
fn a_discard_route_survives_a_reload_of_the_config() {
    let mut s = lab();
    add(
        &mut s,
        json!({"dst_address": "100.64.0.0/10", "blackhole": true, "comment": "CGNAT"}),
    );
    let text = serde_json::to_string(s.store().running()).unwrap();
    assert!(text.contains(r#""gateway":"blackhole""#), "{text}");
    let back: corerouter_model::Config = serde_json::from_str(&text).unwrap();
    assert_eq!(&back, s.store().running());
}
