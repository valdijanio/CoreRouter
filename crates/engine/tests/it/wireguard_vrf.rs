//! G1.31c, the VRF of WireGuard's encrypted packets (`vrf`, RouterOS 7.21)
//! in the virtual lab: the parameter, the rule it asks of the kernel (the
//! VRF's routing mark from the router itself, `iif lo`, to the VRF's
//! table), the preview's route check, the VRF that cannot go while a
//! tunnel uses it, and the rollback.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::{EngineError, Session};
use corerouter_firewall::nft::{MarkKind, mark_value};
use corerouter_hal::policy::{KernelRuleAction, expected_rules};
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn bad(s: &mut Session, id: &str, p: Value) -> (String, String) {
    match s.execute(id, &p) {
        Err(EngineError::BadParam { param, reason }) => (param, reason),
        other => panic!("{id} {p}: expected a parameter error, got {other:?}"),
    }
}

/// VRF `wan2` with ether2 in it, its address and default route.
fn lab() -> Session {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "ip.vrf.add",
        json!({"name": "wan2", "interfaces": "ether2"}),
    );
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "198.51.100.2/24", "interface": "ether2"}),
    );
    ok(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "0.0.0.0/0", "gateway": "198.51.100.1", "routing_table": "wan2"}),
    );
    s
}

/// The kernel rules for the router's own packets with `name`'s mark.
fn wg_rules(s: &Session, name: &str) -> Vec<(bool, Option<String>, KernelRuleAction)> {
    let mark = mark_value(MarkKind::Routing, &name.parse().unwrap());
    expected_rules(s.store().running())
        .into_iter()
        .filter(|r| r.mark == Some(mark))
        .map(|r| (r.v6, r.iif.map(|i| i.to_string()), r.action))
        .collect()
}

fn wan2_table(s: &mut Session) -> u32 {
    let l = ok(s, "ip.vrf.list", json!({}));
    l.as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "wan2")
        .unwrap()["table"]
        .as_u64()
        .unwrap() as u32
}

#[test]
fn the_tunnel_goes_by_its_vrf_and_back_to_main() {
    let mut s = lab();
    let table = wan2_table(&mut s);
    let v = ok(
        &mut s,
        "interface.wireguard.add",
        json!({"name": "wg0", "vrf": "wan2"}),
    );
    assert!(
        v["warnings"].to_string().contains("udp_l3mdev_accept"),
        "{v}"
    );
    let l = ok(&mut s, "interface.wireguard.list", json!({}));
    assert_eq!(l[0]["vrf"], "wan2");
    // One rule per family, only for the router's own packets.
    let rules = wg_rules(&s, "wan2");
    assert_eq!(rules.len(), 2, "{rules:?}");
    for (_, iif, action) in &rules {
        assert_eq!(iif.as_deref(), Some("lo"));
        assert_eq!(*action, KernelRuleAction::Table(table));
    }
    // The VRF stays while the tunnel sends by it.
    let e = s
        .execute("ip.vrf.remove", &json!({"name": "wan2"}))
        .unwrap_err()
        .to_string();
    assert!(e.contains("WireGuard wg0"), "{e}");

    let rev = s.store().current_revision();
    ok(
        &mut s,
        "interface.wireguard.set",
        json!({"name": "wg0", "vrf": "main"}),
    );
    assert_eq!(
        ok(&mut s, "interface.wireguard.list", json!({}))[0]["vrf"],
        "main"
    );
    assert!(wg_rules(&s, "wan2").is_empty());
    ok(&mut s, "config.rollback", json!({"revision": rev}));
    assert_eq!(wg_rules(&s, "wan2").len(), 2);
    // Disabled: the rule goes with it.
    ok(
        &mut s,
        "interface.wireguard.disable",
        json!({"name": "wg0"}),
    );
    assert!(wg_rules(&s, "wan2").is_empty());
}

#[test]
fn only_a_vrf_of_the_config() {
    let mut s = lab();
    let (param, why) = bad(
        &mut s,
        "interface.wireguard.add",
        json!({"name": "wg0", "vrf": "nope"}),
    );
    assert_eq!(param, "vrf");
    assert!(why.contains("no VRF 'nope'"), "{why}");
    let (param, _) = bad(
        &mut s,
        "interface.wireguard.add",
        json!({"name": "wg0", "vrf": "ether1"}),
    );
    assert_eq!(param, "vrf");
    assert!(
        s.store()
            .running()
            .interfaces
            .get(&"wg0".parse().unwrap())
            .is_none()
    );
}

#[test]
fn the_preview_looks_for_the_endpoint_in_the_vrf() {
    let mut s = lab();
    ok(
        &mut s,
        "ip.vrf.add",
        json!({"name": "empty", "interfaces": "ether3"}),
    );
    ok(
        &mut s,
        "interface.wireguard.add",
        json!({"name": "wg0", "vrf": "empty"}),
    );
    ok(
        &mut s,
        "interface.wireguard.peers.add",
        json!({"interface": "wg0", "public_key": "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=",
               "endpoint_address": "192.0.2.50", "endpoint_port": 13231, "allowed_address": "10.9.0.2/32"}),
    );
    let v = ok(
        &mut s,
        "interface.wireguard.preview",
        json!({"id": "wg0", "vrf": "empty"}),
    );
    assert!(
        v["checks"]
            .to_string()
            .contains("VRF empty has no route to the endpoint 192.0.2.50"),
        "{v}"
    );
    let v = ok(
        &mut s,
        "interface.wireguard.preview",
        json!({"id": "wg0", "vrf": "wan2"}),
    );
    assert!(!v["checks"].to_string().contains("has no route"), "{v}");
}
