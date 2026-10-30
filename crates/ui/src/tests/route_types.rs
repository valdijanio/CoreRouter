//! IP › Routes' route type (G1.5a): the Gateway column's chip of a route
//! without next hop, the form's Type chips and what they send, and the New
//! Route dialog end to end.

use super::*;
use crate::routes::{Route, RouteForm, RouteType};

fn nulled(kind: &str) -> Route {
    Route::from_row(&json!({"key": "*1", "id": "*1", "dst_address": "100.64.0.0/10",
        "gateway": kind, "type": kind, "gateway_status": null, "distance": 1,
        "routing_table": "main", "state": "active", "active": true, "origin": "static",
        "flags": "ASB"}))
}

#[test]
fn the_gateway_column_shows_the_type_as_a_neutral_chip() {
    for kind in ["blackhole", "unreachable", "prohibit"] {
        let cell = nulled(kind).gateway_cell();
        let (text, chips) = chip::split(&cell);
        assert_eq!((text, chips), ("", vec![(chip::Kind::Neutral, kind)]));
    }
    // An older daemon sends no type: unicast.
    let r = Route::from_row(&json!({"key": "*2", "id": "*2", "dst_address": "0.0.0.0/0",
        "gateway": "10.0.0.1", "gateway_address": "10.0.0.1", "gateway_status": "reachable"}));
    assert_eq!(r.kind, RouteType::Unicast);
}

#[test]
fn the_form_sends_the_type_without_gateway_or_check() {
    let mut f = RouteForm::new();
    f.dst = "100.64.0.0/10".into();
    f.gateway = "10.0.0.1".into();
    f.check_gateway = "ping".into();
    f.kind = RouteType::Blackhole;
    let p = f.add_params();
    assert_eq!(p["type"], "blackhole", "{p}");
    assert!(p.get("gateway").is_none() && p.get("check_gateway").is_none(), "{p}");

    // Properties of a blackhole: the gateway field is empty; back to
    // unicast sends the type and the gateway typed.
    let base = RouteForm::of(&nulled("blackhole"));
    assert_eq!((base.kind, base.gateway.as_str()), (RouteType::Blackhole, ""));
    let mut f = base.clone();
    assert_eq!(f.set_params("*1", &base), None);
    f.kind = RouteType::Unicast;
    f.gateway = "192.0.2.9".into();
    assert_eq!(
        f.set_params("*1", &base),
        Some(json!({"id": "*1", "type": "unicast", "gateway": "192.0.2.9"}))
    );
    let mut f = base.clone();
    f.kind = RouteType::Prohibit;
    assert_eq!(f.set_params("*1", &base), Some(json!({"id": "*1", "type": "prohibit"})));
}

#[test]
fn new_blackhole_route() {
    let mut h = Harness::routes();
    h.click(h.route_tool(table::Icon::Add).rect.center());
    assert!(h.has_text("Type") && h.has_text("Check Gateway"));
    h.click(h.text("0.0.0.0/0"));
    h.type_text("100.64.0.0/10");
    h.click(h.text("blackhole"));
    // No gateway to type, nothing to check.
    assert!(!h.has_text("10.0.0.1 or ether1") && !h.has_text("Check Gateway"));
    h.click(h.text("OK"));
    assert!(h.app.route_dialogs.is_empty(), "OK closes on success");
    let r = h.route("*1").expect("route created");
    assert_eq!((r["type"].as_str(), r["state"].as_str()), (Some("blackhole"), Some("active")), "{r}");
}
