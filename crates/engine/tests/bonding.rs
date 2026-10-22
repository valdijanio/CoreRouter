//! G1.8 — bonding: success, validation error and rollback for each command,
//! and the commit-time net for slaves.
// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::validate::validate_all;
use corerouter_engine::{EngineError, Session};
use corerouter_model::{BondMode, HashPolicy, Interface, InterfaceKind, LacpRate};
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

/// The command fails, the message contains `needle`, and nothing changed.
fn fails(s: &mut Session, id: &str, p: Value, needle: &str) {
    let before = s.store().candidate().clone();
    let rev = s.store().current_revision();
    let err = s.execute(id, &p).unwrap_err().to_string();
    assert!(err.contains(needle), "{id} {p}: '{err}' lacks '{needle}'");
    assert_eq!(s.store().candidate(), &before, "{id} left changes behind");
    assert_eq!(s.store().current_revision(), rev);
}

fn bond_row(s: &mut Session, name: &str) -> Value {
    ok(s, "interface.bonding.list", Value::Null)
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .cloned()
        .unwrap_or_else(|| panic!("{name} not in interface.bonding.list"))
}

fn iface<'a>(s: &'a Session, name: &str) -> &'a Interface {
    s.store()
        .running()
        .interfaces
        .get(&name.parse().unwrap())
        .unwrap()
}

fn lacp(s: &mut Session) {
    ok(
        s,
        "interface.bonding.add",
        json!({"name": "bond1", "slaves": ["ether1", "ether2"], "mode": "802.3ad",
               "transmit_hash_policy": "layer-3-and-4", "lacp_rate": "1sec", "min_links": 1,
               "comment": "uplink"}),
    );
}

#[test]
fn add_lacp_bond_lists_and_runs() {
    let mut s = Session::virtual_lab();
    lacp(&mut s);
    let r = bond_row(&mut s, "bond1");
    assert_eq!(r["mode"], "802.3ad");
    assert_eq!(r["slaves"], json!(["ether1", "ether2"]));
    assert_eq!(r["transmit_hash_policy"], "layer-3-and-4");
    assert_eq!(r["lacp_rate"], "1sec");
    assert_eq!(r["mii_interval"], 100, "RouterOS and kernel default");
    assert_eq!(r["min_links"], 1);
    assert_eq!(r["mtu"], 1500);
    assert_eq!(r["running"], true);
    assert_eq!(r["comment"], "uplink");
    assert_eq!(iface(&s, "ether1").bond, Some("bond1".parse().unwrap()));

    let all = ok(&mut s, "interface.list", json!({"type": "bonding"}));
    assert_eq!(all.as_array().unwrap().len(), 1);
    let list = ok(&mut s, "interface.list", Value::Null);
    let e1 = list
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "ether1")
        .unwrap();
    assert_eq!(e1["bond"], "bond1");

    // An address on the bond is the normal next step.
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.9.0.1/30", "interface": "bond1"}),
    );
}

#[test]
fn active_backup_with_primary_and_comma_slaves() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "interface.bonding.add",
        json!({"name": "wan", "slaves": "ether3, ether4", "mode": "active-backup", "primary": "ether4"}),
    );
    let r = bond_row(&mut s, "wan");
    assert_eq!(r["primary"], "ether4");
    assert_eq!(r["slaves"], json!(["ether3", "ether4"]));
    // `lacp` is accepted as a synonym of 802.3ad; the stale primary must go.
    fails(
        &mut s,
        "interface.bonding.set",
        json!({"name": "wan", "mode": "lacp"}),
        "has no primary slave",
    );
    ok(
        &mut s,
        "interface.bonding.set",
        json!({"name": "wan", "mode": "lacp", "primary": ""}),
    );
    assert_eq!(bond_row(&mut s, "wan")["mode"], "802.3ad");
}

#[test]
fn add_validates_slaves_and_settings() {
    let mut s = Session::virtual_lab();
    let add = |extra: Value| {
        let mut p = json!({"name": "bond1", "slaves": ["ether1", "ether2"], "mode": "802.3ad"});
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        p
    };
    fails(
        &mut s,
        "interface.bonding.add",
        json!({"name": "b", "mode": "802.3ad"}),
        "slaves",
    );
    fails(
        &mut s,
        "interface.bonding.add",
        add(json!({"slaves": []})),
        "at least one",
    );
    fails(
        &mut s,
        "interface.bonding.add",
        add(json!({"mode": "fast"})),
        "bonding mode",
    );
    fails(
        &mut s,
        "interface.bonding.add",
        add(json!({"slaves": ["nope"]})),
        "no interface 'nope'",
    );
    fails(
        &mut s,
        "interface.bonding.add",
        add(json!({"primary": "ether1"})),
        "mode 802.3ad has no primary",
    );
    fails(
        &mut s,
        "interface.bonding.add",
        add(json!({"mode": "active-backup", "primary": "ether5"})),
        "not one of the slaves",
    );
    fails(
        &mut s,
        "interface.bonding.add",
        add(json!({"mode": "active-backup", "lacp_rate": "1sec"})),
        "does not run LACP",
    );
    fails(
        &mut s,
        "interface.bonding.add",
        add(json!({"mode": "broadcast", "transmit_hash_policy": "layer-2"})),
        "does not hash",
    );
    fails(
        &mut s,
        "interface.bonding.add",
        add(json!({"min_links": 3})),
        "would never come up",
    );
    fails(
        &mut s,
        "interface.bonding.add",
        add(json!({"mii_interval": 60_001})),
        "0..=60000",
    );
    fails(
        &mut s,
        "interface.bonding.add",
        add(json!({"name": "ether1"})),
        "already exists",
    );

    // Ports in use elsewhere: address, bridge, VLAN, another bond, a VLAN as slave.
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.0.1/24", "interface": "ether5"}),
    );
    fails(
        &mut s,
        "interface.bonding.add",
        add(json!({"slaves": ["ether5"]})),
        "has address 10.0.0.1/24",
    );
    ok(&mut s, "interface.bridge.add", json!({"name": "br1"}));
    ok(
        &mut s,
        "interface.bridge.port.add",
        json!({"bridge": "br1", "interface": "ether6"}),
    );
    fails(
        &mut s,
        "interface.bonding.add",
        add(json!({"slaves": ["ether6"]})),
        "port of bridge 'br1'",
    );
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "v7", "parent": "ether7", "vlan_id": 7}),
    );
    fails(
        &mut s,
        "interface.bonding.add",
        add(json!({"slaves": ["ether7"]})),
        "VLAN v7 runs on",
    );
    fails(
        &mut s,
        "interface.bonding.add",
        add(json!({"slaves": ["v7"]})),
        "only ethernet ports",
    );
    lacp(&mut s);
    fails(
        &mut s,
        "interface.bonding.add",
        json!({"name": "bond2", "slaves": ["ether2"], "mode": "802.3ad"}),
        "already a slave of 'bond1'",
    );
}

#[test]
fn slaves_carry_nothing_of_their_own() {
    let mut s = Session::virtual_lab();
    lacp(&mut s);
    let err = s
        .execute(
            "ip.address.add",
            &json!({"address": "10.0.0.1/24", "interface": "ether1"}),
        )
        .unwrap_err();
    assert!(matches!(err, EngineError::Validation(_)), "{err}");
    assert!(err.to_string().contains("addresses go on 'bond1'"), "{err}");
    let err = s
        .execute(
            "interface.vlan.add",
            &json!({"name": "v9", "parent": "ether2", "vlan_id": 9}),
        )
        .unwrap_err();
    assert!(err.to_string().contains("put it on 'bond1'"), "{err}");
    ok(&mut s, "interface.bridge.add", json!({"name": "br1"}));
    let err = s
        .execute(
            "interface.bridge.port.add",
            &json!({"bridge": "br1", "interface": "ether1"}),
        )
        .unwrap_err();
    assert!(
        err.to_string().contains("add 'bond1' to the bridge"),
        "{err}"
    );
    // The bond itself can be a bridge port, and carry VLANs.
    ok(
        &mut s,
        "interface.bridge.port.add",
        json!({"bridge": "br1", "interface": "bond1"}),
    );
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "v10", "parent": "bond1", "vlan_id": 10}),
    );
}

#[test]
fn mtu_follows_the_bond() {
    let mut s = Session::virtual_lab();
    lacp(&mut s);
    ok(
        &mut s,
        "interface.set",
        json!({"name": "bond1", "mtu": 9000}),
    );
    assert_eq!(iface(&s, "ether1").mtu, 9000);
    assert_eq!(iface(&s, "ether2").mtu, 9000);
    fails(
        &mut s,
        "interface.set",
        json!({"name": "ether1", "mtu": 1500}),
        "set it on 'bond1'",
    );
    ok(
        &mut s,
        "interface.bonding.set",
        json!({"name": "bond1", "mtu": 1600}),
    );
    assert_eq!(iface(&s, "ether2").mtu, 1600);
    // Disabling a slave is fine: the bond carries on with the others.
    ok(
        &mut s,
        "interface.set",
        json!({"name": "ether2", "disabled": true}),
    );
}

#[test]
fn set_replaces_slaves_and_settings() {
    let mut s = Session::virtual_lab();
    lacp(&mut s);
    ok(
        &mut s,
        "interface.bonding.set",
        json!({"name": "bond1", "slaves": ["ether2", "ether3"], "lacp_rate": "30secs", "disabled": true}),
    );
    let r = bond_row(&mut s, "bond1");
    assert_eq!(r["slaves"], json!(["ether2", "ether3"]));
    assert_eq!(r["lacp_rate"], "30secs");
    assert_eq!(r["disabled"], true);
    assert_eq!(iface(&s, "ether1").bond, None, "released");
    fails(
        &mut s,
        "interface.bonding.set",
        json!({"name": "ether1"}),
        "no bond 'ether1'",
    );
    fails(
        &mut s,
        "interface.bonding.set",
        json!({"name": "bond1", "slaves": ["ether3"], "min_links": 2}),
        "would never come up",
    );
    fails(
        &mut s,
        "interface.bonding.set",
        json!({"name": "bond1", "slaves": ""}),
        "interface.remove",
    );
}

#[test]
fn remove_releases_slaves_and_rollback_restores_them() {
    let mut s = Session::virtual_lab();
    lacp(&mut s);
    let rev = s.store().current_revision();
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.9.0.1/30", "interface": "bond1"}),
    );
    fails(
        &mut s,
        "interface.remove",
        json!({"name": "bond1"}),
        "remove IP address",
    );
    ok(&mut s, "config.rollback", json!({"revision": rev}));
    ok(&mut s, "interface.remove", json!({"name": "bond1"}));
    assert_eq!(iface(&s, "ether1").bond, None);
    assert_eq!(iface(&s, "ether2").bond, None);
    // The freed port takes an address again.
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.0.1/24", "interface": "ether1"}),
    );

    ok(&mut s, "config.rollback", json!({"revision": rev}));
    assert_eq!(iface(&s, "ether1").bond, Some("bond1".parse().unwrap()));
    assert_eq!(
        bond_row(&mut s, "bond1")["slaves"],
        json!(["ether1", "ether2"])
    );

    ok(&mut s, "config.rollback", json!({"revision": 0}));
    assert!(
        ok(&mut s, "interface.bonding.list", Value::Null)
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn validator_catches_hand_built_bonds() {
    let s = Session::virtual_lab();
    let mut cfg = s.store().running().clone();
    let n = |x: &str| x.parse().unwrap();
    let bond = Interface::new(
        n("bond1"),
        InterfaceKind::Bonding {
            mode: BondMode::Lacp,
            primary: Some(n("ether3")),
            transmit_hash_policy: HashPolicy::Layer2,
            lacp_rate: LacpRate::Slow,
            mii_interval_ms: 100,
            min_links: 0,
        },
    );
    cfg.interfaces.insert(n("bond1"), bond);
    let e1 = cfg.interfaces.get_mut(&n("ether1")).unwrap();
    e1.bond = Some(n("bond1"));
    e1.bridge = Some(n("bond1"));
    e1.mtu = 9000;
    cfg.interfaces.get_mut(&n("ether2")).unwrap().bond = Some(n("nobond"));
    let issues: Vec<String> = validate_all(&cfg).iter().map(ToString::to_string).collect();
    let all = issues.join("\n");
    for needle in [
        "differs from the MTU 1500 of bond 'bond1'",
        "also a port of bridge",
        "bond 'nobond' does not exist",
        "mode 802.3ad has no primary slave",
    ] {
        assert!(all.contains(needle), "missing '{needle}' in:\n{all}");
    }
}

#[test]
fn config_with_bond_round_trips_through_json() {
    let mut s = Session::virtual_lab();
    lacp(&mut s);
    let cfg = s.store().running().clone();
    let text = serde_json::to_string(&cfg).unwrap();
    assert!(
        text.contains(r#""type":"bonding","mode":"802.3ad""#),
        "{text}"
    );
    let back: corerouter_model::Config = serde_json::from_str(&text).unwrap();
    assert_eq!(back, cfg);
}
