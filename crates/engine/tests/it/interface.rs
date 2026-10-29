//! G1.1 — VLAN, bridge, loopback and interface removal: success, validation
//! error and rollback for each command.
// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::validate::validate_all;
use corerouter_engine::{EngineError, Session};
use corerouter_model::{Interface, InterfaceKind, VlanId};
use serde_json::{Value, json};

fn lab() -> Session {
    Session::virtual_lab()
}

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

fn row(s: &mut Session, name: &str) -> Value {
    let list = ok(s, "interface.list", Value::Null);
    list.as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .cloned()
        .unwrap_or_else(|| panic!("{name} not in interface.list"))
}

fn has(s: &Session, name: &str) -> bool {
    s.store()
        .running()
        .interfaces
        .contains_key(&name.parse().unwrap())
}

// ---- interface.vlan.add ----

#[test]
fn vlan_add_creates_a_running_vlan_with_counters() {
    let mut s = lab();
    let r = ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "vlan100", "parent": "ether1", "vlan_id": 100, "comment": "customers"}),
    );
    assert_eq!(r, json!({"name": "vlan100"}));
    assert_eq!(s.store().current_revision(), 1);
    assert!(has(&s, "vlan100"));

    let first = row(&mut s, "vlan100");
    let second = row(&mut s, "vlan100");
    assert_eq!(second["type"], "vlan");
    assert_eq!(second["parent"], "ether1");
    assert_eq!(second["vlan_id"], 100);
    assert_eq!(second["mtu"], 1500, "inherits the parent MTU");
    assert_eq!(second["comment"], "customers");
    assert_eq!(second["running"], true);
    assert!(second["rx_bytes"].as_u64() > first["rx_bytes"].as_u64());

    // Same VLAN id on another parent is fine; QinQ on top of a VLAN too.
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "vlan100-e2", "parent": "ether2", "vlan_id": 100, "mtu": 1400}),
    );
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "qinq", "parent": "vlan100", "vlan_id": 7}),
    );
    let vlans = ok(&mut s, "interface.list", json!({"type": "vlan"}));
    assert_eq!(vlans.as_array().unwrap().len(), 3);
}

#[test]
fn vlan_add_validates_parent_id_name_and_mtu() {
    let mut s = lab();
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "vlan100", "parent": "ether1", "vlan_id": 100}),
    );
    ok(&mut s, "interface.loopback.add", json!({"name": "lo0"}));
    let v = |name: &str, parent: &str, id: Value| json!({"name": name, "parent": parent, "vlan_id": id});

    fails(
        &mut s,
        "interface.vlan.add",
        v("v1", "ether9", json!(1)),
        "no interface 'ether9'",
    );
    fails(
        &mut s,
        "interface.vlan.add",
        v("v1", "lo0", json!(1)),
        "is a loopback",
    );
    fails(
        &mut s,
        "interface.vlan.add",
        v("v1", "ether1", json!(100)),
        "VLAN 100 on ether1 already exists (vlan100)",
    );
    fails(
        &mut s,
        "interface.vlan.add",
        v("vlan100", "ether2", json!(5)),
        "already exists",
    );
    fails(
        &mut s,
        "interface.vlan.add",
        v("ether3", "ether2", json!(5)),
        "already exists",
    );
    for bad in [json!(0), json!(4095), json!(70_000), json!("10")] {
        fails(
            &mut s,
            "interface.vlan.add",
            v("v1", "ether1", bad),
            "vlan_id",
        );
    }
    fails(
        &mut s,
        "interface.vlan.add",
        v("bad name", "ether1", json!(5)),
        "interface name",
    );
    fails(
        &mut s,
        "interface.vlan.add",
        json!({"name": "v1", "parent": "ether1", "vlan_id": 5, "mtu": 9000}),
        "exceeds the MTU 1500 of 'ether1'",
    );
    fails(
        &mut s,
        "interface.vlan.add",
        json!({"name": "v1", "parent": "ether1"}),
        "'vlan_id': is required",
    );
}

/// G3.9h: QinQ as RouterOS builds it, an 802.1ad S-VLAN (`use-service-tag`)
/// with an 802.1Q C-VLAN on top. Seen against RouterOS 7.25: without the
/// S-tag the CoreRouter could only stack 0x8100 on 0x8100.
#[test]
fn vlan_add_service_tag_for_qinq() {
    let mut s = lab();
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "s100", "parent": "ether1", "vlan_id": 100, "use_service_tag": true}),
    );
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "c200", "parent": "s100", "vlan_id": 200}),
    );
    assert_eq!(row(&mut s, "s100")["use_service_tag"], true);
    assert_eq!(row(&mut s, "c200")["use_service_tag"], false);
    assert_eq!(row(&mut s, "ether1")["use_service_tag"], Value::Null);
    // The same id as a C-VLAN on the same port is another TPID: allowed
    // (Linux and RouterOS both take it); a second S-VLAN 100 is not.
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "v100", "parent": "ether1", "vlan_id": 100}),
    );
    fails(
        &mut s,
        "interface.vlan.add",
        json!({"name": "s100b", "parent": "ether1", "vlan_id": 100, "use_service_tag": true}),
        "S-VLAN 100 on ether1 already exists (s100)",
    );
    fails(
        &mut s,
        "interface.vlan.add",
        json!({"name": "s7", "parent": "ether1", "vlan_id": 7, "use_service_tag": "yes please"}),
        "use_service_tag",
    );
    assert!(validate_all(s.store().candidate()).is_empty());
    // Saved only when set: a plain VLAN's config stays as it was.
    let cfg = serde_json::to_value(&s.store().running().interfaces).unwrap();
    assert_eq!(cfg["s100"]["kind"]["service_tag"], true);
    assert!(cfg["c200"]["kind"].get("service_tag").is_none());
    ok(&mut s, "config.rollback", json!({"revision": 0}));
    assert!(!has(&s, "s100"));
}

#[test]
fn vlan_add_rolls_back() {
    let mut s = lab();
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "vlan100", "parent": "ether1", "vlan_id": 100}),
    );
    ok(&mut s, "config.rollback", json!({"revision": 0}));
    assert!(!has(&s, "vlan100"));
    assert_eq!(s.store().running().interfaces.len(), 8);

    // Transactional: discard drops the pending VLAN.
    ok(&mut s, "config.mode.set", json!({"mode": "transactional"}));
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "vlan200", "parent": "ether1", "vlan_id": 200}),
    );
    assert!(s.store().is_dirty());
    ok(&mut s, "config.discard", Value::Null);
    assert!(!s.store().is_dirty());
}

// ---- interface.bridge.add / interface.loopback.add ----

#[test]
fn bridge_and_loopback_add() {
    let mut s = lab();
    assert_eq!(
        ok(
            &mut s,
            "interface.bridge.add",
            json!({"name": "bridge1", "comment": "lan"})
        ),
        json!({"name": "bridge1"})
    );
    assert_eq!(
        ok(&mut s, "interface.loopback.add", json!({"name": "lo0"})),
        json!({"name": "lo0"})
    );
    assert_eq!(row(&mut s, "bridge1")["type"], "bridge");
    assert_eq!(row(&mut s, "bridge1")["comment"], "lan");
    assert_eq!(row(&mut s, "lo0")["type"], "loopback");
    assert_eq!(row(&mut s, "lo0")["running"], true);
    assert_eq!(s.store().current_revision(), 2);
}

#[test]
fn bridge_and_loopback_add_reject_bad_names() {
    let mut s = lab();
    ok(&mut s, "interface.bridge.add", json!({"name": "bridge1"}));
    for id in ["interface.bridge.add", "interface.loopback.add"] {
        fails(&mut s, id, json!({"name": "bridge1"}), "already exists");
        fails(&mut s, id, json!({"name": "ether1"}), "already exists");
        fails(&mut s, id, json!({"name": "x".repeat(16)}), "1..=15 bytes");
        fails(
            &mut s,
            id,
            json!({"name": "a", "comment": "\u{7}"}),
            "control characters",
        );
        fails(
            &mut s,
            id,
            json!({"name": "a", "vlan_id": 1}),
            "unknown parameter 'vlan_id'",
        );
    }
}

#[test]
fn bridge_and_loopback_add_roll_back() {
    let mut s = lab();
    ok(&mut s, "interface.bridge.add", json!({"name": "bridge1"}));
    ok(&mut s, "interface.loopback.add", json!({"name": "lo0"}));
    ok(&mut s, "config.rollback", json!({"revision": 1}));
    assert!(has(&s, "bridge1"));
    assert!(!has(&s, "lo0"));
    ok(&mut s, "config.rollback", json!({"revision": 0}));
    assert!(!has(&s, "bridge1"));
}

// ---- interface.bridge.port.add / remove / list ----

fn with_bridges() -> Session {
    let mut s = lab();
    ok(&mut s, "interface.bridge.add", json!({"name": "bridge1"}));
    ok(&mut s, "interface.bridge.add", json!({"name": "bridge2"}));
    s
}

fn port(bridge: &str, interface: &str) -> Value {
    json!({"bridge": bridge, "interface": interface})
}

#[test]
fn bridge_port_add_and_list() {
    let mut s = with_bridges();
    assert_eq!(
        ok(
            &mut s,
            "interface.bridge.port.add",
            port("bridge1", "ether2")
        ),
        port("bridge1", "ether2")
    );
    ok(
        &mut s,
        "interface.bridge.port.add",
        port("bridge1", "ether3"),
    );
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "vlan10", "parent": "ether4", "vlan_id": 10}),
    );
    ok(
        &mut s,
        "interface.bridge.port.add",
        port("bridge2", "vlan10"),
    );

    assert_eq!(row(&mut s, "ether2")["bridge"], "bridge1");
    assert_eq!(row(&mut s, "ether1")["bridge"], Value::Null);
    let all = ok(&mut s, "interface.bridge.port.list", Value::Null);
    assert_eq!(all.as_array().unwrap().len(), 3);
    let b1 = ok(
        &mut s,
        "interface.bridge.port.list",
        json!({"bridge": "bridge1"}),
    );
    assert_eq!(
        b1,
        json!([port("bridge1", "ether2"), port("bridge1", "ether3")])
    );
}

#[test]
fn bridge_port_add_validates_membership() {
    let mut s = with_bridges();
    ok(
        &mut s,
        "interface.bridge.port.add",
        port("bridge1", "ether2"),
    );
    ok(&mut s, "interface.loopback.add", json!({"name": "lo0"}));
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "vlan5", "parent": "bridge1", "vlan_id": 5}),
    );
    let add = "interface.bridge.port.add";

    fails(
        &mut s,
        add,
        port("bridge2", "ether2"),
        "already a port of bridge 'bridge1'",
    );
    fails(
        &mut s,
        add,
        port("bridge1", "ether2"),
        "already a port of 'bridge1'",
    );
    fails(
        &mut s,
        add,
        port("bridge1", "bridge1"),
        "cannot be a port of itself",
    );
    fails(
        &mut s,
        add,
        port("bridge1", "bridge2"),
        "is a bridge and cannot be a bridge port",
    );
    fails(
        &mut s,
        add,
        port("bridge1", "lo0"),
        "is a loopback and cannot be a bridge port",
    );
    fails(
        &mut s,
        add,
        port("ether1", "ether3"),
        "'ether1' is not a bridge (type ether)",
    );
    fails(
        &mut s,
        add,
        port("bridge9", "ether3"),
        "no interface 'bridge9'",
    );
    fails(
        &mut s,
        add,
        port("bridge1", "ether9"),
        "no interface 'ether9'",
    );
    fails(
        &mut s,
        add,
        port("bridge1", "vlan5"),
        "runs on top of 'bridge1'",
    );
    fails(
        &mut s,
        add,
        json!({"bridge": "bridge1"}),
        "'interface': is required",
    );
}

#[test]
fn bridge_port_remove_and_rollback() {
    let mut s = with_bridges();
    ok(
        &mut s,
        "interface.bridge.port.add",
        port("bridge1", "ether2"),
    );
    let rev = s.store().current_revision();

    fails(
        &mut s,
        "interface.bridge.port.remove",
        port("bridge2", "ether2"),
        "'ether2' is not a port of bridge 'bridge2'",
    );
    fails(
        &mut s,
        "interface.bridge.port.remove",
        port("bridge1", "ether3"),
        "not a port",
    );
    assert_eq!(
        ok(
            &mut s,
            "interface.bridge.port.remove",
            port("bridge1", "ether2")
        ),
        port("bridge1", "ether2")
    );
    assert_eq!(row(&mut s, "ether2")["bridge"], Value::Null);

    // Rolling back to the revision with the port restores the membership.
    ok(&mut s, "config.rollback", json!({"revision": rev}));
    assert_eq!(row(&mut s, "ether2")["bridge"], "bridge1");
    ok(&mut s, "config.rollback", json!({"revision": rev - 1}));
    assert_eq!(row(&mut s, "ether2")["bridge"], Value::Null);
}

#[test]
fn atomic_batch_builds_a_bridge_or_nothing() {
    let mut s = lab();
    let err = s
        .batch(
            &json!([
                {"command": "interface.bridge.add", "params": {"name": "bridge1"}},
                {"command": "interface.bridge.port.add", "params": {"bridge": "$1.name", "interface": "ether2"}},
                {"command": "interface.bridge.port.add", "params": {"bridge": "$1.name", "interface": "ether2"}},
            ]),
            true,
        )
        .unwrap_err();
    assert!(matches!(err, EngineError::Batch { step: 3, .. }), "{err}");
    assert!(!has(&s, "bridge1"));
    assert!(!s.store().is_dirty());

    s.batch(
        &json!([
            {"command": "interface.bridge.add", "params": {"name": "bridge1"}},
            {"command": "interface.bridge.port.add", "params": {"bridge": "$1.name", "interface": "ether2"}},
            {"command": "interface.bridge.port.add", "params": {"bridge": "$1.name", "interface": "ether3"}},
        ]),
        true,
    )
    .unwrap();
    assert_eq!(s.store().current_revision(), 1);
    let ports = ok(&mut s, "interface.bridge.port.list", Value::Null);
    assert_eq!(ports.as_array().unwrap().len(), 2);
}

// ---- interface.remove ----

#[test]
fn remove_vlan_bridge_and_loopback() {
    let mut s = with_bridges();
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "vlan100", "parent": "ether1", "vlan_id": 100}),
    );
    ok(&mut s, "interface.loopback.add", json!({"name": "lo0"}));
    for name in ["vlan100", "bridge1", "lo0"] {
        assert_eq!(
            ok(&mut s, "interface.remove", json!({"name": name})),
            json!({"name": name})
        );
        assert!(!has(&s, name));
    }
    assert_eq!(s.store().running().interfaces.len(), 9);
}

#[test]
fn remove_refuses_what_is_in_use_and_says_what_to_remove() {
    let mut s = with_bridges();
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "vlan100", "parent": "ether1", "vlan_id": 100}),
    );
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.0.1/24", "interface": "vlan100"}),
    );
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "vlan7", "parent": "vlan100", "vlan_id": 7}),
    );
    ok(
        &mut s,
        "interface.bridge.port.add",
        port("bridge1", "ether2"),
    );
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "vlan8", "parent": "ether3", "vlan_id": 8}),
    );
    ok(
        &mut s,
        "interface.bridge.port.add",
        port("bridge2", "vlan8"),
    );
    let rm = |n: &str| json!({"name": n});

    fails(
        &mut s,
        "interface.remove",
        rm("ether1"),
        "physical port and cannot be removed",
    );
    fails(
        &mut s,
        "interface.remove",
        rm("ether9"),
        "no interface 'ether9'",
    );
    fails(
        &mut s,
        "interface.remove",
        rm("vlan100"),
        "remove IP address *1 (10.0.0.1/24) first (ip.address.remove)",
    );
    fails(
        &mut s,
        "interface.remove",
        rm("vlan100"),
        "remove VLAN vlan7 first (interface.remove)",
    );
    fails(
        &mut s,
        "interface.remove",
        rm("bridge1"),
        "remove bridge port ether2 first (interface.bridge.port.remove)",
    );
    fails(
        &mut s,
        "interface.remove",
        rm("vlan8"),
        "remove it from bridge bridge2 first (interface.bridge.port.remove)",
    );

    // Follow the advice and it works.
    ok(&mut s, "interface.remove", rm("vlan7"));
    ok(&mut s, "ip.address.remove", json!({"id": "*1"}));
    ok(&mut s, "interface.remove", rm("vlan100"));
    ok(
        &mut s,
        "interface.bridge.port.remove",
        port("bridge2", "vlan8"),
    );
    ok(&mut s, "interface.remove", rm("vlan8"));
}

#[test]
fn remove_rolls_back() {
    let mut s = with_bridges();
    let rev = s.store().current_revision();
    ok(&mut s, "interface.remove", json!({"name": "bridge2"}));
    assert!(!has(&s, "bridge2"));
    ok(&mut s, "config.rollback", json!({"revision": rev}));
    assert!(has(&s, "bridge2"));
}

// ---- whole-config validation (commit net for transactional edits and loaded configs) ----

#[test]
fn shrinking_a_parent_mtu_below_its_vlan_fails_at_commit() {
    let mut s = lab();
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "vlan100", "parent": "ether1", "vlan_id": 100}),
    );
    let err = s
        .execute("interface.set", &json!({"name": "ether1", "mtu": 1400}))
        .unwrap_err();
    assert!(matches!(err, EngineError::Validation(_)), "{err}");
    assert!(
        err.to_string()
            .contains("exceeds the MTU 1400 of parent 'ether1'")
    );
    assert_eq!(row(&mut s, "ether1")["mtu"], 1500);
}

#[test]
fn validator_catches_hand_built_dependency_errors() {
    let s = lab();
    let mut cfg = s.store().running().clone();
    let name = |n: &str| n.parse().unwrap();
    let vlan = |n: &str, parent: &str, id: u16| {
        Interface::new(
            name(n),
            InterfaceKind::Vlan {
                parent: name(parent),
                vlan_id: VlanId::new(id).unwrap(),
                service_tag: false,
            },
        )
    };
    assert!(validate_all(&cfg).is_empty());

    cfg.interfaces.insert(name("a"), vlan("a", "ether1", 10));
    cfg.interfaces.insert(name("b"), vlan("b", "ether1", 10));
    // c ↔ d: a parent cycle a loaded config could contain.
    cfg.interfaces.insert(name("c"), vlan("c", "d", 1));
    cfg.interfaces.insert(name("d"), vlan("d", "c", 1));
    let mut port = Interface::new(name("ether2"), InterfaceKind::Ethernet);
    port.bridge = Some(name("nobridge"));
    cfg.interfaces.insert(name("ether2"), port);
    let mut port = Interface::new(name("ether3"), InterfaceKind::Ethernet);
    port.bridge = Some(name("ether4"));
    cfg.interfaces.insert(name("ether3"), port);

    let issues: Vec<String> = validate_all(&cfg).iter().map(ToString::to_string).collect();
    let find = |needle: &str| {
        assert!(
            issues.iter().any(|i| i.contains(needle)),
            "no issue with '{needle}' in {issues:#?}"
        );
    };
    find("VLAN 10 on ether1 is already used by a");
    find("interfaces.c.kind.parent: VLAN parent chain loops");
    find("bridge 'nobridge' does not exist");
    find("'ether4' is not a bridge (type ether)");
}
