//! G1.5b: a discard route over what the router is connected to, and
//! `ip.route.lookup` saying what kind of route it found.

#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use corerouter_engine::{Caller, EngineError, Link, Principal, Session};
use serde_json::{Value, json};

/// ether1 = WAN 203.0.113.1/24 with a default route, ether2 = LAN.
fn router() -> Session {
    let mut s = Session::virtual_lab();
    for p in [
        json!({"address": "203.0.113.1/24", "interface": "ether1"}),
        json!({"address": "192.168.88.1/24", "interface": "ether2"}),
    ] {
        s.execute("ip.address.add", &p).unwrap();
    }
    s.execute(
        "ip.route.add",
        &json!({"dst_address": "0.0.0.0/0", "gateway": "203.0.113.254"}),
    )
    .unwrap();
    s
}

/// An operator on the WAN side, reached by the default route.
fn operator() -> Caller {
    Caller::new(9, "tls 198.51.100.7:50123")
        .with_principal(Principal::Local)
        .with_link(Link {
            peer: "198.51.100.7:50123".parse().unwrap(),
            local: "203.0.113.1:8729".parse().unwrap(),
        })
}

fn as_operator(s: &mut Session, id: &str, p: Value) -> corerouter_engine::Result<Value> {
    s.execute_as(&operator(), id, &p)
}

fn warnings(r: &Value) -> Vec<String> {
    r["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn a_discard_over_the_operator_is_refused() {
    for kind in ["blackhole", "unreachable", "prohibit"] {
        for dst in ["198.51.100.7/32", "198.51.100.0/24", "198.0.0.0/8"] {
            let mut s = router();
            let e = as_operator(
                &mut s,
                "ip.route.add",
                json!({"dst_address": dst, "type": kind}),
            )
            .unwrap_err();
            assert!(matches!(e, EngineError::Lockout(_)), "{e}");
            let text = e.to_string();
            assert!(
                text.contains(kind) && text.contains("198.51.100.7"),
                "{text}"
            );
            assert!(text.contains("force=true"), "{text}");
            assert!(s.store().running().ip.routes.len() == 1, "rolled back");
        }
    }
}

#[test]
fn over_ipv6_too() {
    let mut s = Session::virtual_lab();
    s.execute(
        "ip.address.add",
        &json!({"address": "2001:db8::1/64", "interface": "ether1"}),
    )
    .unwrap();
    let who = Caller::new(9, "tls [2001:db8::7]:50123")
        .with_principal(Principal::Local)
        .with_link(Link {
            peer: "[2001:db8::7]:50123".parse().unwrap(),
            local: "[2001:db8::1]:8729".parse().unwrap(),
        });
    let e = s
        .execute_as(
            &who,
            "ip.route.add",
            &json!({"dst_address": "2001:db8::7/128", "type": "prohibit"}),
        )
        .unwrap_err();
    assert!(matches!(e, EngineError::Lockout(_)), "{e}");
}

#[test]
fn force_and_safe_mode_let_it_through_and_it_warns() {
    let mut s = router();
    let r = as_operator(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "198.51.100.7", "blackhole": true, "force": true}),
    )
    .unwrap();
    assert!(
        warnings(&r)
            .iter()
            .any(|w| w.contains("drops the replies to 198.51.100.7")),
        "{r}"
    );

    let mut s = router();
    as_operator(&mut s, "config.safe-mode.enter", json!({})).unwrap();
    as_operator(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "198.51.100.7", "blackhole": true}),
    )
    .unwrap();
}

#[test]
fn only_what_wins_routing_counts() {
    let mut s = router();
    // Somewhere else.
    as_operator(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "100.64.0.0/10", "blackhole": true}),
    )
    .unwrap();
    // A more specific route still brings the replies back.
    as_operator(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "198.51.100.0/24", "gateway": "203.0.113.254"}),
    )
    .unwrap();
    as_operator(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "198.0.0.0/8", "blackhole": true}),
    )
    .unwrap();
    // A floating one, worse than the unicast of the same prefix.
    as_operator(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "198.51.100.0/24", "blackhole": true, "distance": 254}),
    )
    .unwrap();
    // Disabled.
    as_operator(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "198.51.100.7", "blackhole": true, "disabled": true}),
    )
    .unwrap();
    // Without a connection there is nothing to lose.
    s.execute(
        "ip.route.add",
        &json!({"dst_address": "198.51.100.8", "blackhole": true}),
    )
    .unwrap();
}

#[test]
fn enabling_setting_and_removing_are_checked_too() {
    let mut s = router();
    let id = as_operator(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "198.51.100.7", "blackhole": true, "disabled": true}),
    )
    .unwrap()["id"]
        .clone();
    let e = as_operator(&mut s, "ip.route.set", json!({"id": id, "disabled": false})).unwrap_err();
    assert!(matches!(e, EngineError::Lockout(_)), "{e}");

    // Removing the specific route that hides a wider discard.
    let mut s = router();
    let specific = as_operator(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "198.51.100.0/24", "gateway": "203.0.113.254"}),
    )
    .unwrap()["id"]
        .clone();
    as_operator(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "198.0.0.0/8", "blackhole": true}),
    )
    .unwrap();
    let e = as_operator(&mut s, "ip.route.remove", json!({"id": specific})).unwrap_err();
    assert!(matches!(e, EngineError::Lockout(_)), "{e}");
    as_operator(
        &mut s,
        "ip.route.remove",
        json!({"id": specific, "force": true}),
    )
    .unwrap();
}

#[test]
fn a_discard_inside_or_on_a_connected_network_warns() {
    let mut s = router();
    let r = s
        .execute(
            "ip.route.add",
            &json!({"dst_address": "192.168.88.128/25", "type": "prohibit"}),
        )
        .unwrap();
    assert_eq!(
        warnings(&r),
        [
            "this prohibit route drops 192.168.88.128/25, part of the connected network 192.168.88.0/24 on ether2: the hosts there stop being reachable"
        ]
    );
    let r = s
        .execute(
            "ip.route.add",
            &json!({"dst_address": "192.168.88.0/24", "blackhole": true}),
        )
        .unwrap();
    assert!(warnings(&r)[0].contains("has the same prefix"), "{r}");
    // Wider than the connected network: the anchor of a BGP prefix.
    let r = s
        .execute(
            "ip.route.add",
            &json!({"dst_address": "192.168.0.0/16", "blackhole": true}),
        )
        .unwrap();
    assert!(warnings(&r).is_empty(), "{r}");
    // Another table, a unicast route, a disabled one.
    let r = s
        .execute(
            "ip.route.add",
            &json!({"dst_address": "203.0.113.128/25", "gateway": "203.0.113.254"}),
        )
        .unwrap();
    assert!(warnings(&r).is_empty(), "{r}");
    let r = s
        .execute(
            "ip.route.add",
            &json!({"dst_address": "203.0.113.64/26", "blackhole": true, "disabled": true}),
        )
        .unwrap();
    assert!(warnings(&r).is_empty(), "{r}");
    // Set says the same.
    let id = r["id"].clone();
    let r = s
        .execute("ip.route.set", &json!({"id": id, "disabled": false}))
        .unwrap();
    assert!(
        warnings(&r)[0].contains("part of the connected network 203.0.113.0/24"),
        "{r}"
    );
}

#[test]
fn route_lookup_says_the_kind_and_agrees_with_the_data_plane() {
    let mut s = router();
    for (dst, kind) in [
        ("100.64.0.0/10", "blackhole"),
        ("100.128.0.0/10", "unreachable"),
        ("101.0.0.0/8", "prohibit"),
    ] {
        s.execute("ip.route.add", &json!({"dst_address": dst, "type": kind}))
            .unwrap();
    }
    for (ip, kind, dst) in [
        ("100.64.0.1", "blackhole", "100.64.0.0/10"),
        ("100.128.0.1", "unreachable", "100.128.0.0/10"),
        ("101.0.0.1", "prohibit", "101.0.0.0/8"),
    ] {
        let r = s
            .execute("ip.route.lookup", &json!({"address": ip}))
            .unwrap();
        assert_eq!(r["type"], kind, "{r}");
        assert_eq!(r["route"]["dst_address"], dst, "{r}");
        assert_eq!(r["prefix"], dst, "{r}");
        assert_eq!(r["nexthops"], json!([]), "{r}");
        assert_eq!(r["kernel"]["type"], kind, "{r}");
        assert_eq!(r["kernel"]["same"], true, "{r}");
    }
    // A distance worse than the unicast of the same prefix: unicast.
    s.execute(
        "ip.route.add",
        &json!({"dst_address": "198.51.100.0/24", "gateway": "203.0.113.254"}),
    )
    .unwrap();
    s.execute(
        "ip.route.add",
        &json!({"dst_address": "198.51.100.0/24", "blackhole": true, "distance": 254}),
    )
    .unwrap();
    let r = s
        .execute("ip.route.lookup", &json!({"address": "198.51.100.1"}))
        .unwrap();
    assert_eq!(r["type"], "unicast", "{r}");
    assert_eq!(r["kernel"]["same"], true, "{r}");
}
