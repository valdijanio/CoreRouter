//! IP › Routes' check-gateway (G1.27f / G3.6g): the Check column's chips,
//! the form's chips and BFD profile, and the New Route dialog end to end.

use super::*;
use crate::routes::{Route, RouteForm};

fn route(v: Value) -> Route {
    Route::from_row(&v)
}

fn checked(check: Value) -> Route {
    route(json!({"key": "*1", "id": "*1", "dst_address": "0.0.0.0/0", "gateway": "10.0.0.1",
        "gateway_address": "10.0.0.1", "gateway_status": "reachable", "interface": "ether1",
        "distance": 1, "routing_table": "main", "state": "active", "active": true,
        "origin": "static", "check_gateway": check}))
}

#[test]
fn the_check_column_says_method_and_status() {
    let r = checked(json!({"method": "ping", "interval_secs": 10, "misses": 0, "state": "up",
        "status": "reachable"}));
    let cell = r.check.as_ref().unwrap().cell();
    let (_, chips) = chip::split(&cell);
    assert_eq!(chips, vec![(chip::Kind::Neutral, "ping"), (chip::Kind::Green, "reachable")]);
    let r = checked(json!({"method": "bfd", "interval_secs": 0, "misses": 0, "state": "up",
        "status": "checking", "bfd_profile": "fast"}));
    let cell = r.check.as_ref().unwrap().cell();
    let (_, chips) = chip::split(&cell);
    assert_eq!(chips, vec![(chip::Kind::Neutral, "bfd fast"), (chip::Kind::Amber, "checking")]);
    // An older daemon sends only up | down.
    let r = checked(json!({"method": "arp", "interval_secs": 10, "misses": 2, "state": "down"}));
    assert_eq!(r.check.as_ref().unwrap().chip(), ("unreachable", chip::Kind::Red));
    // The gateway column no longer carries it.
    let cell = r.gateway_cell();
    let (_, chips) = chip::split(&cell);
    assert!(chips.iter().all(|(_, t)| !t.starts_with("check")), "{chips:?}");
}

#[test]
fn the_form_sends_the_check_and_the_profile_only_when_it_counts() {
    let mut f = RouteForm::new();
    f.dst = "0.0.0.0/0".into();
    f.gateway = "10.0.0.1".into();
    let p = f.add_params();
    assert_eq!((&p["check_gateway"], &p["bfd_profile"]), (&Value::Null, &Value::Null));
    f.bfd_profile = "fast".into();
    assert_eq!(f.add_params()["bfd_profile"], Value::Null, "a profile only with bfd");
    f.check_gateway = "bfd".into();
    let p = f.add_params();
    assert_eq!((&p["check_gateway"], &p["bfd_profile"]), (&json!("bfd"), &json!("fast")));

    // Properties of a checked route: what changed only.
    let r = checked(json!({"method": "bfd", "status": "reachable", "bfd_profile": "fast"}));
    let base = RouteForm::of(&r);
    assert_eq!((base.check_gateway.as_str(), base.bfd_profile.as_str()), ("bfd", "fast"));
    let mut f = base.clone();
    assert_eq!(f.set_params("*1", &base), None);
    f.check_gateway = "ping".into();
    assert_eq!(f.set_params("*1", &base), Some(json!({"id": "*1", "check_gateway": "ping"})));
    // The built-in profile shows as empty (the engine's default).
    let r = checked(json!({"method": "bfd", "status": "reachable", "bfd_profile": "default"}));
    assert_eq!(RouteForm::of(&r).bfd_profile, "");
}

#[test]
fn new_route_with_check_gateway_ping() {
    let mut h = Harness::routes();
    h.click(h.route_tool(table::Icon::Add).rect.center());
    assert!(h.has_text("Check Gateway"));
    h.click(h.text("0.0.0.0/0"));
    h.type_text("0.0.0.0/0");
    h.click(h.text("10.0.0.1 or ether1"));
    h.type_text("10.0.0.1");
    // The BFD profile shows only with bfd.
    assert!(!h.has_text("BFD Profile"));
    h.click(h.text("bfd"));
    assert!(h.has_text("BFD Profile"));
    h.click(h.text("ping"));
    assert!(!h.has_text("BFD Profile"));
    h.click(h.text("OK"));
    assert!(h.app.route_dialogs.is_empty(), "OK closes on success");
    let r = h.route("*1").expect("route created");
    assert_eq!(r["check_gateway"]["method"], "ping", "{r}");
    // No daemon runs the checks in this GUI: the column says so.
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
    assert!(h.has_text("not-checked"));
}
