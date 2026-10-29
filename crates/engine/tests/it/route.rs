//! G1.5 — static routes and VRFs: success, validation error and rollback
//! for each command, plus the connected routes and flags of `ip.route.list`.
// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::{EngineError, MemoryStorage, Session};
use corerouter_hal::VirtualHal;
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

/// Virtual lab with ether1 = 10.0.0.2/24 + 2001:db8::2/64 (the uplink) and
/// ether2 = 192.168.88.1/24.
fn lab() -> Session {
    let mut s = Session::virtual_lab();
    for (a, i) in [
        ("10.0.0.2/24", "ether1"),
        ("2001:db8::2/64", "ether1"),
        ("192.168.88.1/24", "ether2"),
    ] {
        ok(
            &mut s,
            "ip.address.add",
            json!({"address": a, "interface": i}),
        );
    }
    s
}

fn add(s: &mut Session, p: Value) -> String {
    ok(s, "ip.route.add", p)["id"].as_str().unwrap().to_owned()
}

fn routes(s: &mut Session) -> Vec<Value> {
    ok(s, "ip.route.list", Value::Null)
        .as_array()
        .unwrap()
        .clone()
}

/// The `ip.route.list` row of static route `id`.
fn row(s: &mut Session, id: &str) -> Value {
    routes(s)
        .into_iter()
        .find(|r| r["id"] == id)
        .unwrap_or_else(|| panic!("{id} not in ip.route.list"))
}

// ---- ip.route.add ----

#[test]
fn default_routes_v4_and_v6_become_active() {
    let mut s = lab();
    let v4 = add(
        &mut s,
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}),
    );
    let v6 = add(
        &mut s,
        json!({"dst_address": "::/0", "gateway": "2001:db8::1", "comment": "upstream"}),
    );
    assert_eq!((v4.as_str(), v6.as_str()), ("*1", "*2"));
    assert_eq!(s.store().current_revision(), 5, "3 addresses + 2 routes");
    assert_eq!(s.store().running().ip.routes.len(), 2);

    let r = row(&mut s, "*1");
    assert_eq!(r["flags"], "AS");
    assert_eq!(r["dst_address"], "0.0.0.0/0");
    assert_eq!(r["gateway"], "10.0.0.1");
    assert_eq!(r["distance"], 1);
    assert_eq!(r["routing_table"], "main");
    assert_eq!(r["immediate_gw"], "10.0.0.1%ether1");
    assert_eq!(r["reason"], Value::Null);
    let r = row(&mut s, "*2");
    assert_eq!(
        (&r["flags"], &r["comment"]),
        (&json!("AS"), &json!("upstream"))
    );
    assert_eq!(r["immediate_gw"], "2001:db8::1%ether1");
}

#[test]
fn list_derives_connected_routes_from_addresses() {
    let mut s = lab();
    add(
        &mut s,
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}),
    );
    let rows = routes(&mut s);
    let dsts: Vec<&str> = rows
        .iter()
        .map(|r| r["dst_address"].as_str().unwrap())
        .collect();
    // Sorted by destination; IPv4 before IPv6.
    assert_eq!(
        dsts,
        [
            "0.0.0.0/0",
            "10.0.0.0/24",
            "192.168.88.0/24",
            "2001:db8::/64"
        ]
    );
    let c = &rows[1];
    assert_eq!(c["flags"], "ADC", "RouterOS order: X A D C S");
    assert_eq!(c["id"], Value::Null);
    assert_eq!(c["gateway"], "ether1");
    assert_eq!(c["distance"], 0);
    assert_eq!(
        (&c["connected"], &c["static"]),
        (&json!(true), &json!(false))
    );

    // A disabled interface makes its connected route and the static route
    // through it inactive (but still listed).
    ok(
        &mut s,
        "interface.set",
        json!({"name": "ether1", "disabled": true}),
    );
    let rows = routes(&mut s);
    assert_eq!(rows[0]["flags"], "S");
    assert!(rows[0]["reason"].as_str().unwrap().contains("disabled"));
    assert_eq!(rows[1]["flags"], "DC");
    let only_main = ok(&mut s, "ip.route.list", json!({"routing_table": "main"}));
    assert_eq!(only_main.as_array().unwrap().len(), 4);
}

#[test]
fn every_gateway_form_is_accepted() {
    let mut s = lab();
    add(
        &mut s,
        json!({"dst_address": "198.51.100.0/24", "gateway": "ether3"}),
    );
    add(
        &mut s,
        json!({"dst_address": "2001:db8:99::/48", "gateway": "fe80::1%ether3"}),
    );
    add(
        &mut s,
        json!({"dst_address": "203.0.113.0/24", "gateway": "192.168.88.254%ether2"}),
    );
    // A bare address is a host route.
    let id = add(
        &mut s,
        json!({"dst_address": "192.0.2.7", "gateway": "10.0.0.1"}),
    );
    assert_eq!(row(&mut s, &id)["dst_address"], "192.0.2.7/32");
    assert_eq!(row(&mut s, "*1")["immediate_gw"], "ether3");
    assert!(routes(&mut s).iter().all(|r| r["active"] == true));
}

#[test]
fn backup_route_waits_behind_a_lower_distance() {
    let mut s = lab();
    add(
        &mut s,
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}),
    );
    let backup = add(
        &mut s,
        json!({"dst_address": "0.0.0.0/0", "gateway": "192.168.88.254", "distance": 10}),
    );
    let r = row(&mut s, &backup);
    assert_eq!(r["flags"], "S");
    assert_eq!(r["state"], "standby");
    assert_eq!(
        r["reason"],
        "loses to distance 1 (route *1 via 10.0.0.1%ether1)"
    );
    assert_eq!(r["reason_id"], "loses-distance");
    assert_eq!(r["reason_args"]["distance"], "1");
    // The primary goes down: the backup takes over.
    ok(
        &mut s,
        "ip.route.set",
        json!({"id": "*1", "disabled": true}),
    );
    assert_eq!(row(&mut s, "*1")["flags"], "XS");
    assert_eq!(row(&mut s, &backup)["flags"], "AS");
    // A static route to a connected network loses to it.
    let shadow = add(
        &mut s,
        json!({"dst_address": "10.0.0.0/24", "gateway": "ether3"}),
    );
    assert_eq!(
        row(&mut s, &shadow)["reason"],
        "the connected network on ether1 wins"
    );
}

/// G0.31d: the duplicate check reads the index of next hops, which every
/// add, set and remove keeps.
#[test]
fn the_same_hop_twice_is_refused_after_set_and_remove() {
    let mut s = lab();
    let a = add(
        &mut s,
        json!({"dst_address": "10.9.0.0/16", "gateway": "10.0.0.1"}),
    );
    let b = add(
        &mut s,
        json!({"dst_address": "10.8.0.0/16", "gateway": "10.0.0.1"}),
    );
    // Moving b onto a's hop is refused; on its own hop, a set goes through.
    fails(
        &mut s,
        "ip.route.set",
        json!({"id": b, "dst_address": "10.9.0.0/16"}),
        &format!("route {a} already goes to 10.9.0.0/16"),
    );
    ok(&mut s, "ip.route.set", json!({"id": b, "distance": 5}));
    // A set that leaves a hop frees it; a remove too.
    ok(
        &mut s,
        "ip.route.set",
        json!({"id": a, "dst_address": "10.7.0.0/16"}),
    );
    ok(
        &mut s,
        "ip.route.set",
        json!({"id": b, "dst_address": "10.9.0.0/16"}),
    );
    ok(&mut s, "ip.route.remove", json!({"id": b}));
    let c = add(
        &mut s,
        json!({"dst_address": "10.9.0.0/16", "gateway": "10.0.0.1"}),
    );
    // Another gateway to the same place is ECMP, not a duplicate.
    add(
        &mut s,
        json!({"dst_address": "10.9.0.0/16", "gateway": "10.0.0.3"}),
    );
    // The hop taken again is refused again.
    fails(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "10.9.0.0/16", "gateway": "10.0.0.1"}),
        &format!("route {c} already goes to"),
    );
}

#[test]
fn add_rejects_bad_routes_and_changes_nothing() {
    let mut s = lab();
    add(
        &mut s,
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}),
    );
    let cases = [
        (
            json!({"dst_address": "0.0.0.0/0", "gateway": "172.16.0.1", "distance": 2}),
            "not in any connected network of routing table 'main'",
        ),
        (
            json!({"dst_address": "0.0.0.0/0", "gateway": "2001:db8::1", "distance": 2}),
            "is IPv6 but dst-address 0.0.0.0/0 is IPv4",
        ),
        (
            json!({"dst_address": "::/0", "gateway": "10.0.0.1"}),
            "is IPv4",
        ),
        (
            json!({"dst_address": "10.1.1.1/16", "gateway": "10.0.0.1"}),
            "host bits set; did you mean 10.1.0.0/16?",
        ),
        (
            json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1", "distance": 9}),
            "route *1 already goes to 0.0.0.0/0 via 10.0.0.1",
        ),
        (
            json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.2", "distance": 3}),
            "is an address of this router",
        ),
        (
            json!({"dst_address": "::/0", "gateway": "fe80::1"}),
            "needs an interface",
        ),
        (
            json!({"dst_address": "10.9.0.0/16", "gateway": "ether9"}),
            "interface 'ether9' does not exist",
        ),
        (
            json!({"dst_address": "10.9.0.0/16", "gateway": "10.0.0.1%ether2"}),
            "not in a network of 'ether2'",
        ),
        (
            json!({"dst_address": "10.9.0.0/16", "gateway": "10.0.0.1", "distance": 0}),
            "must be 1..=255",
        ),
        (
            json!({"dst_address": "10.9.0.0/16", "gateway": "10.0.0.1", "distance": 256}),
            "must be 1..=255",
        ),
        (
            json!({"dst_address": "10.9.0.0/16", "gateway": "10.0.0.1", "routing_table": "blue"}),
            "routing table 'blue' does not exist",
        ),
        (
            json!({"dst_address": "10.9.0.0/33", "gateway": "10.0.0.1"}),
            "dst_address",
        ),
        (
            json!({"dst_address": "10.9.0.0/16", "gateway": "10.0.0.1%"}),
            "gateway",
        ),
        (
            json!({"dst_address": "10.9.0.0/16"}),
            "'gateway': is required",
        ),
        (
            json!({"dst_address": "10.9.0.0/16", "gateway": "10.0.0.1", "gw": "x"}),
            "unknown parameter 'gw'",
        ),
    ];
    for (p, needle) in cases {
        fails(&mut s, "ip.route.add", p, needle);
    }
}

#[test]
fn equal_distance_routes_share_the_traffic() {
    let mut s = lab();
    add(
        &mut s,
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}),
    );
    let second = add(
        &mut s,
        json!({"dst_address": "0.0.0.0/0", "gateway": "192.168.88.254"}),
    );
    for id in ["*1", second.as_str()] {
        let r = row(&mut s, id);
        assert_eq!(
            (&r["state"], &r["ecmp"]),
            (&json!("active"), &json!(2)),
            "{r}"
        );
        assert_eq!(r["flags"], "AS+");
    }
    // One path disabled: the other carries alone.
    ok(
        &mut s,
        "ip.route.set",
        json!({"id": second, "disabled": true}),
    );
    assert_eq!(row(&mut s, "*1")["ecmp"], 1);
    assert_eq!(row(&mut s, &second)["reason_id"], "disabled");
}

// ---- ip.route.set / remove ----

#[test]
fn set_changes_only_what_is_given_and_validates_the_result() {
    let mut s = lab();
    add(
        &mut s,
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1", "comment": "a"}),
    );
    add(
        &mut s,
        json!({"dst_address": "0.0.0.0/0", "gateway": "192.168.88.254", "distance": 5}),
    );
    ok(
        &mut s,
        "ip.route.set",
        json!({"id": "*1", "distance": 3, "comment": "primary"}),
    );
    let r = row(&mut s, "*1");
    assert_eq!(
        (&r["distance"], &r["comment"], &r["gateway"]),
        (&json!(3), &json!("primary"), &json!("10.0.0.1"))
    );

    fails(
        &mut s,
        "ip.route.set",
        json!({"id": "*1", "gateway": "172.16.0.1"}),
        "not in any connected",
    );
    fails(
        &mut s,
        "ip.route.set",
        json!({"id": "*9", "distance": 2}),
        "no static route *9",
    );
    fails(&mut s, "ip.route.set", json!({"id": "nope"}), "item id");
}

#[test]
fn remove_and_rollback() {
    let mut s = lab();
    add(
        &mut s,
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}),
    );
    let rev = s.store().current_revision();
    ok(&mut s, "ip.route.remove", json!({"id": "*1"}));
    assert!(s.store().running().ip.routes.is_empty());
    assert!(matches!(
        s.execute("ip.route.remove", &json!({"id": "*1"})),
        Err(EngineError::Disabled { .. })
    ));
    // config.rollback brings the route back, with its id.
    ok(&mut s, "config.rollback", json!({"revision": rev}));
    assert_eq!(row(&mut s, "*1")["flags"], "AS");
    fails(
        &mut s,
        "ip.route.remove",
        json!({"id": "*7"}),
        "no static route *7",
    );
    // Ids are never reused.
    assert_eq!(
        add(
            &mut s,
            json!({"dst_address": "10.9.0.0/16", "gateway": "ether3"})
        ),
        "*2"
    );
}

#[test]
fn atomic_batch_adds_routes_or_nothing() {
    let mut s = lab();
    let before = s.store().candidate().clone();
    let err = s
        .batch(
            &json!([
                {"command": "ip.route.add", "params": {"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}},
                {"command": "ip.route.add", "params": {"dst_address": "::/0", "gateway": "10.0.0.1"}},
            ]),
            true,
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("batch step 2"), "{err}");
    assert_eq!(s.store().candidate(), &before);
    // Renumbering the uplink is one atomic step with its route.
    s.batch(
        &json!([
            {"command": "ip.address.add", "params": {"address": "10.5.0.2/24", "interface": "ether3"}},
            {"command": "ip.route.add", "params": {"dst_address": "0.0.0.0/0", "gateway": "10.5.0.1"}},
        ]),
        true,
    )
    .unwrap();
    assert_eq!(row(&mut s, "*1")["immediate_gw"], "10.5.0.1%ether3");
}

#[test]
fn what_a_route_needs_cannot_be_removed_under_it() {
    let mut s = lab();
    add(
        &mut s,
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}),
    );
    add(
        &mut s,
        json!({"dst_address": "198.51.100.0/24", "gateway": "ether3"}),
    );
    let addr = ok(&mut s, "ip.address.list", json!({"interface": "ether1"}))[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    fails(
        &mut s,
        "ip.address.remove",
        json!({"id": addr}),
        "ip.routes[*1].gateway: 10.0.0.1 is not in any connected network",
    );
    ok(&mut s, "interface.loopback.add", json!({"name": "lo1"}));
    add(
        &mut s,
        json!({"dst_address": "192.0.2.0/24", "gateway": "lo1"}),
    );
    fails(
        &mut s,
        "interface.remove",
        json!({"name": "lo1"}),
        "remove route *3 (192.0.2.0/24) first",
    );
}

#[test]
fn routes_survive_a_reboot() {
    let storage = MemoryStorage::default();
    let boot = || Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()));
    let mut s = boot();
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.0.2/24", "interface": "ether1"}),
    );
    add(
        &mut s,
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1", "comment": "isp"}),
    );
    drop(s);
    let mut s = boot();
    let r = row(&mut s, "*1");
    assert_eq!((&r["flags"], &r["comment"]), (&json!("AS"), &json!("isp")));
    assert_eq!(
        add(
            &mut s,
            json!({"dst_address": "10.9.0.0/16", "gateway": "10.0.0.1"})
        ),
        "*2"
    );
}

// ---- ip.vrf.* ----

#[test]
fn vrf_groups_interfaces_into_its_own_table() {
    let mut s = lab();
    let r = ok(
        &mut s,
        "ip.vrf.add",
        json!({"name": "cust-a", "interfaces": ["ether3", "ether4"], "comment": "customer A"}),
    );
    assert_eq!(r, json!({"name": "cust-a", "table": 1000}));
    assert_eq!(
        ok(&mut s, "ip.vrf.add", json!({"name": "cust-b"}))["table"],
        1001
    );
    let list = ok(&mut s, "ip.vrf.list", Value::Null);
    assert_eq!(list[0]["interfaces"], json!(["ether3", "ether4"]));
    let ifaces = ok(&mut s, "interface.list", json!({"type": "vrf"}));
    assert_eq!(ifaces.as_array().unwrap().len(), 2);
    let e3 = ok(&mut s, "interface.list", Value::Null)
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "ether3")
        .cloned()
        .unwrap();
    assert_eq!(e3["vrf"], "cust-a");

    // The same network as main's uplink, in the VRF: no conflict.
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.0.2/24", "interface": "ether3"}),
    );
    let id = add(
        &mut s,
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1", "routing_table": "cust-a"}),
    );
    let r = row(&mut s, &id);
    assert_eq!(
        (&r["flags"], &r["immediate_gw"]),
        (&json!("AS"), &json!("10.0.0.1%ether3"))
    );
    let vrf_rows = ok(&mut s, "ip.route.list", json!({"routing_table": "cust-a"}));
    let dsts: Vec<_> = vrf_rows
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["dst_address"].clone())
        .collect();
    assert_eq!(dsts, [json!("0.0.0.0/0"), json!("10.0.0.0/24")]);
    // Main cannot route out of a VRF interface.
    fails(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "10.7.0.0/16", "gateway": "ether3"}),
        "'ether3' is in routing table 'cust-a', not 'main'",
    );
    // Disabling the VRF makes its routes inactive.
    ok(
        &mut s,
        "ip.vrf.set",
        json!({"name": "cust-a", "disabled": true}),
    );
    assert_eq!(row(&mut s, &id)["flags"], "S");
}

#[test]
fn vrf_membership_rules() {
    let mut s = lab();
    ok(&mut s, "interface.bridge.add", json!({"name": "br0"}));
    ok(
        &mut s,
        "interface.bridge.port.add",
        json!({"bridge": "br0", "interface": "ether5"}),
    );
    ok(
        &mut s,
        "ip.vrf.add",
        json!({"name": "blue", "interfaces": "ether3"}),
    );
    fails(
        &mut s,
        "ip.vrf.add",
        json!({"name": "main"}),
        "main routing table",
    );
    fails(
        &mut s,
        "ip.vrf.add",
        json!({"name": "ether1"}),
        "already exists",
    );
    fails(
        &mut s,
        "ip.vrf.add",
        json!({"name": "red", "interfaces": ["ether5"]}),
        "port of bridge 'br0'",
    );
    fails(
        &mut s,
        "ip.vrf.add",
        json!({"name": "red", "interfaces": ["ether3"]}),
        "already in VRF 'blue'",
    );
    fails(
        &mut s,
        "ip.vrf.add",
        json!({"name": "red", "interfaces": ["blue"]}),
        "a VRF cannot be a member",
    );
    fails(
        &mut s,
        "ip.vrf.add",
        json!({"name": "red", "interfaces": ["nope"]}),
        "no interface 'nope'",
    );
    fails(
        &mut s,
        "ip.vrf.add",
        json!({"name": "red", "interfaces": 7}),
        "list of interface names",
    );
    fails(
        &mut s,
        "interface.bridge.port.add",
        json!({"bridge": "br0", "interface": "ether3"}),
        "in VRF 'blue'",
    );
    fails(
        &mut s,
        "interface.vlan.add",
        json!({"name": "v9", "parent": "blue", "vlan_id": 9}),
        "is a vrf",
    );
    // Moving the uplink into a VRF would strand main's default route.
    add(
        &mut s,
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}),
    );
    fails(
        &mut s,
        "ip.vrf.set",
        json!({"name": "blue", "interfaces": ["ether1"]}),
        "not in any connected network of routing table 'main'",
    );
    // A bridge (not its ports) can join; set replaces the member list.
    ok(
        &mut s,
        "ip.vrf.set",
        json!({"name": "blue", "interfaces": ["br0", "ether4"]}),
    );
    let list = ok(&mut s, "ip.vrf.list", Value::Null);
    assert_eq!(list[0]["interfaces"], json!(["br0", "ether4"]));
    fails(
        &mut s,
        "ip.vrf.set",
        json!({"name": "nope"}),
        "no VRF 'nope'",
    );
}

#[test]
fn vrf_remove_releases_members_but_not_routes() {
    let mut s = lab();
    ok(
        &mut s,
        "ip.vrf.add",
        json!({"name": "blue", "interfaces": ["ether3"]}),
    );
    let id = add(
        &mut s,
        json!({"dst_address": "10.9.0.0/16", "gateway": "ether3", "routing_table": "blue"}),
    );
    fails(
        &mut s,
        "ip.vrf.remove",
        json!({"name": "blue"}),
        &format!("remove route {id}"),
    );
    fails(
        &mut s,
        "interface.remove",
        json!({"name": "blue"}),
        "ip.vrf.remove",
    );
    ok(&mut s, "ip.route.remove", json!({"id": id}));
    ok(&mut s, "ip.vrf.remove", json!({"name": "blue"}));
    let cfg = s.store().running();
    assert!(!cfg.interfaces.contains_key(&"blue".parse().unwrap()));
    assert!(cfg.interfaces.values().all(|i| i.vrf.is_none()));
    fails(
        &mut s,
        "ip.vrf.remove",
        json!({"name": "blue"}),
        "no VRF 'blue'",
    );
}
