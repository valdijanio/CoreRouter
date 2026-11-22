//! G1.31b, WireGuard extras end to end in the virtual lab: the firewall
//! assistant and the routes of the modals (one transaction), Safe Mode for
//! a session that comes through the tunnel, the endpoint by DNS name and
//! the health warning of a peer that never answers.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::{Caller, EngineError, Link, Principal, Session};
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

/// A WAN with a default route, wg0 at 10.9.0.1/24.
fn lab() -> Session {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "203.0.113.2/24", "interface": "ether1"}),
    );
    ok(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "0.0.0.0/0", "gateway": "203.0.113.1"}),
    );
    ok(&mut s, "interface.wireguard.add", json!({"name": "wg0"}));
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.9.0.1/24", "interface": "wg0"}),
    );
    s
}

fn commands(v: &Value) -> Vec<Value> {
    v["commands"].as_array().cloned().unwrap_or_default()
}

fn has_check(v: &Value, level: &str, text: &str) -> bool {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["level"] == level && c["message"].as_str().unwrap().contains(text))
}

#[test]
fn the_firewall_assistant_puts_an_accept_before_the_drop() {
    let mut s = lab();
    let drop = ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"chain": "input", "action": "drop", "in_interface": "ether1"}),
    )["id"]
        .clone();
    let v = ok(
        &mut s,
        "interface.wireguard.preview",
        json!({"id": "wg0", "accept_firewall": "no"}),
    );
    assert!(has_check(&v, "warning", "tick Accept in Firewall"), "{v}");
    let v = ok(
        &mut s,
        "interface.wireguard.preview",
        json!({"id": "wg0", "accept_firewall": "yes"}),
    );
    let steps = commands(&v);
    assert_eq!(steps.len(), 2, "{v}");
    assert_eq!(steps[1]["command"], "ip.firewall.filter.add");
    assert_eq!(steps[1]["params"]["place_before"], drop);
    assert_eq!(steps[1]["params"]["dst_port"], "13231");
    s.batch(&Value::Array(steps), true).unwrap();
    let v = ok(&mut s, "interface.wireguard.preview", json!({"id": "wg0"}));
    assert!(has_check(&v, "ok", "lets UDP 13231 in from ether1"), "{v}");
}

#[test]
fn create_routes_adds_them_in_the_same_transaction() {
    let mut s = lab();
    let rev = s.store().current_revision();
    let v = ok(
        &mut s,
        "interface.wireguard.peers.preview",
        json!({"interface": "wg0", "name": "filial", "allowed_address": "10.20.0.0/16, 10.9.0.5/32",
               "endpoint_address": "198.51.100.7", "endpoint_port": "13231", "create_routes": "yes"}),
    );
    let steps = commands(&v);
    let routes: Vec<&Value> = steps
        .iter()
        .filter(|c| c["command"] == "ip.route.add")
        .collect();
    assert_eq!(routes.len(), 1, "10.9.0.5/32 is wg0's own network: {v}");
    assert_eq!(routes[0]["params"]["dst_address"], "10.20.0.0/16");
    assert_eq!(routes[0]["params"]["gateway"], "wg0");
    assert!(v["risk"].is_null(), "{v}");
    // The MTU by the route to the endpoint: IPv4, 60 bytes.
    assert!(
        has_check(
            &v,
            "ok",
            "MTU 1420 fits 1500 on ether1 (the way to 198.51.100.7) minus the 60 bytes"
        ),
        "{v}"
    );
    s.batch(&Value::Array(steps), true).unwrap();
    let r = ok(&mut s, "ip.route.list", json!({}));
    assert!(r.to_string().contains("10.20.0.0/16"), "{r}");
    // A default route through the tunnel asks for a yes.
    let v = ok(
        &mut s,
        "interface.wireguard.peers.preview",
        json!({"interface": "wg0", "name": "full", "allowed_address": "0.0.0.0/0", "create_routes": true}),
    );
    assert!(
        v["risk"]
            .as_str()
            .is_some_and(|r| r.contains("all the router's traffic")),
        "{v}"
    );
    // And all of it rolls back.
    ok(&mut s, "config.rollback", json!({"revision": rev}));
    let r = ok(&mut s, "ip.route.list", json!({}));
    assert!(!r.to_string().contains("10.20.0.0/16"), "{r}");
}

/// An operator at 10.9.0.2 (peer notebook) connected to 10.9.0.1 on wg0.
fn through_the_tunnel() -> Caller {
    Caller::new(7, "tls 10.9.0.2:50000".to_owned())
        .with_principal(Principal::Local)
        .with_link(Link {
            peer: "10.9.0.2:50000".parse().unwrap(),
            local: "10.9.0.1:8729".parse().unwrap(),
        })
}

#[test]
fn a_session_through_the_tunnel_asks_before_it_is_cut() {
    let mut s = lab();
    ok(
        &mut s,
        "interface.wireguard.peers.add",
        json!({"interface": "wg0", "name": "notebook", "private_key": "auto", "allowed_address": "10.9.0.2/32"}),
    );
    ok(
        &mut s,
        "interface.wireguard.peers.add",
        json!({"interface": "wg0", "name": "celular", "private_key": "auto", "allowed_address": "10.9.0.3/32"}),
    );
    let me = through_the_tunnel();
    for (id, p, want) in [
        (
            "interface.wireguard.set",
            json!({"name": "wg0", "private_key": "auto"}),
            "new key pair",
        ),
        (
            "interface.wireguard.set",
            json!({"name": "wg0", "listen_port": 13300}),
            "UDP 13231 to 13300",
        ),
        (
            "interface.wireguard.peers.disable",
            json!({"name": "notebook"}),
            "peer 'notebook'",
        ),
        (
            "interface.wireguard.peers.remove",
            json!({"name": "notebook"}),
            "peer 'notebook'",
        ),
        (
            "interface.wireguard.peers.set",
            json!({"name": "notebook", "allowed_address": "10.9.0.20/32"}),
            "peer 'notebook'",
        ),
    ] {
        match s.execute_as(&me, id, &p) {
            Err(EngineError::Lockout(why)) => assert!(why.contains(want), "{id}: {why}"),
            other => panic!("{id} {p}: {other:?}"),
        }
    }
    // Another peer is not this session's.
    s.execute_as(
        &me,
        "interface.wireguard.peers.disable",
        &json!({"name": "celular"}),
    )
    .unwrap();
    // The modal says it before OK, and force goes through.
    let v = s
        .execute_as(
            &me,
            "interface.wireguard.peers.preview",
            &json!({"id": "notebook", "disabled": true}),
        )
        .unwrap();
    assert!(
        v["risk"].as_str().unwrap().contains("peer 'notebook'"),
        "{v}"
    );
    s.execute_as(
        &me,
        "interface.wireguard.peers.disable",
        &json!({"name": "notebook", "force": true}),
    )
    .unwrap();
}

#[test]
fn a_name_endpoint_is_resolved_and_asked_again_when_the_handshake_is_old() {
    let mut s = lab();
    ok(&mut s, "interface.wireguard.add", json!({"name": "wg1"}));
    let l = ok(&mut s, "interface.wireguard.list", json!({}));
    let (k0, k1) = (l[0]["public_key"].clone(), l[1]["public_key"].clone());
    ok(
        &mut s,
        "interface.wireguard.peers.add",
        json!({"interface": "wg0", "name": "to-wg1", "public_key": k1, "allowed_address": "10.99.0.2/32",
                                                        "endpoint_address": "LocalHost", "endpoint_port": 13232, "persistent_keepalive": 25}),
    );
    ok(
        &mut s,
        "interface.wireguard.peers.add",
        json!({"interface": "wg1", "name": "to-wg0", "public_key": k0, "allowed_address": "10.99.0.1/32"}),
    );
    s.tick(1_000);
    let p = ok(
        &mut s,
        "interface.wireguard.peers.list",
        json!({"interface": "wg0"}),
    );
    assert_eq!(p[0]["endpoint_address"], "localhost");
    assert!(p[0]["endpoint_resolved"].is_null());
    assert_eq!(s.wireguard_names_due(0), vec!["localhost".to_owned()]);
    // The daemon's resolver answers; the address goes to the data plane.
    s.wireguard_resolved("localhost", Ok(vec!["127.0.0.1".parse().unwrap()]), 0);
    let p = ok(
        &mut s,
        "interface.wireguard.peers.list",
        json!({"interface": "wg0"}),
    );
    assert_eq!(p[0]["endpoint_resolved"], "127.0.0.1", "{p}");
    assert_eq!(p[0]["state"], "up", "{p}");
    // A fresh handshake: not asked again, even past the retry time.
    assert!(s.wireguard_names_due(60_000).is_empty());
    // A failure keeps the old address and says why.
    s.wireguard_resolved("localhost", Err("timed out".into()), 60_000);
    let p = ok(
        &mut s,
        "interface.wireguard.peers.list",
        json!({"interface": "wg0"}),
    );
    assert_eq!(p[0]["endpoint_resolved"], "127.0.0.1");
    assert_eq!(p[0]["resolve_error"], "timed out");
}

#[test]
fn a_peer_that_never_answers_becomes_a_health_warning() {
    let mut s = lab();
    ok(
        &mut s,
        "interface.wireguard.peers.add",
        json!({"interface": "wg0", "name": "filial", "public_key": "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
                                                        "allowed_address": "10.20.0.0/16", "endpoint_address": "192.0.2.44", "endpoint_port": 13231, "persistent_keepalive": 25}),
    );
    // A road warrior that only waits is never a warning.
    ok(
        &mut s,
        "interface.wireguard.peers.add",
        json!({"interface": "wg0", "name": "notebook", "private_key": "auto", "allowed_address": "10.9.0.2/32"}),
    );
    let warned = |s: &mut Session| {
        let h = ok(s, "system.health.check", json!({}));
        h["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["key"] == "wireguard.handshake")
            .cloned()
    };
    s.tick(10_000);
    assert!(warned(&mut s).is_none(), "just configured");
    s.tick(10_000 + 299);
    assert!(warned(&mut s).is_none(), "under 5 min");
    s.tick(10_000 + 360);
    let c = warned(&mut s).expect("a warning after 6 min");
    assert_eq!(c["severity"], "warning");
    let reason = c["reason"].as_str().unwrap();
    assert!(
        reason.contains("filial (wg0) nunca respondeu, tentando há 6 min"),
        "{reason}"
    );
    assert!(!reason.contains("notebook"), "{reason}");
}
