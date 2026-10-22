//! G2.1b — firewall safety and ease of use: lockout check (with a simulated
//! control-channel connection), shadowed rules, Portuguese descriptions,
//! the safe defaults, the templates and the zone matrix.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::{Caller, CommitMode, EngineError, Link, Principal, Session};
use serde_json::{Value, json};

/// ether1 = WAN 203.0.113.1/24, ether2 = LAN 192.168.88.1/24.
fn router() -> Session {
    let mut s = Session::virtual_lab();
    for p in [
        json!({"address": "203.0.113.1/24", "interface": "ether1"}),
        json!({"address": "192.168.88.1/24", "interface": "ether2"}),
    ] {
        ok(&mut s, "ip.address.add", p);
    }
    ok(
        &mut s,
        "interface.list.member.add",
        json!({"list": "WAN", "interface": "ether1"}),
    );
    ok(
        &mut s,
        "interface.list.member.add",
        json!({"list": "LAN", "interface": "ether2"}),
    );
    s
}

/// An operator connected over the control channel from `peer` to `local`.
fn remote(peer: &str, local: &str) -> Caller {
    Caller::new(9, format!("tls {peer}"))
        .with_principal(Principal::Local)
        .with_link(Link {
            peer: peer.parse().unwrap(),
            local: local.parse().unwrap(),
        })
}

fn from_wan() -> Caller {
    remote("198.51.100.7:50123", "203.0.113.1:8729")
}

fn from_lan() -> Caller {
    remote("192.168.88.10:50123", "192.168.88.1:8729")
}

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn ok_as(s: &mut Session, who: &Caller, id: &str, p: Value) -> Value {
    s.execute_as(who, id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn lockout(s: &mut Session, who: &Caller, id: &str, p: Value) -> String {
    match s.execute_as(who, id, &p) {
        Err(e @ EngineError::Lockout(_)) => e.to_string(),
        other => panic!("{id} {p}: expected a lockout, got {other:?}"),
    }
}

fn rules(s: &mut Session, table: &str) -> Vec<Value> {
    ok(s, &format!("ip.firewall.{table}.list"), Value::Null)
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn a_change_that_cuts_the_management_connection_is_refused() {
    let mut s = router();
    let wan = from_wan();
    let rev = s.store().current_revision();
    let drop_wan = json!({"chain": "input", "action": "drop", "in_interface_list": "WAN"});
    let msg = lockout(&mut s, &wan, "ip.firewall.filter.add", drop_wan.clone());
    assert!(msg.starts_with("lockout: "), "{msg}");
    assert!(msg.contains("would drop this connection"), "{msg}");
    assert!(msg.contains("in-interface-list=WAN"), "the rule: {msg}");
    assert!(
        msg.contains("198.51.100.7:50123 -> 203.0.113.1:8729 on ether1"),
        "{msg}"
    );
    assert!(
        msg.contains("Safe Mode") && msg.contains("force=true"),
        "{msg}"
    );
    assert_eq!(s.store().current_revision(), rev, "nothing committed");
    assert!(rules(&mut s, "filter").is_empty(), "candidate rolled back");

    // The same rule from the LAN, or from inside the process, is fine.
    ok_as(
        &mut s,
        &from_lan(),
        "ip.firewall.filter.add",
        drop_wan.clone(),
    );
    ok(&mut s, "ip.firewall.filter.remove", json!({"id": "*1"}));
    ok(&mut s, "ip.firewall.filter.add", drop_wan.clone());
    ok(&mut s, "ip.firewall.filter.remove", json!({"id": "*2"}));

    // force=true: the operator said yes.
    let mut forced = drop_wan.clone();
    forced["force"] = json!(true);
    ok_as(&mut s, &wan, "ip.firewall.filter.add", forced);
    assert_eq!(rules(&mut s, "filter").len(), 1);
}

#[test]
fn established_accepted_but_new_logins_dropped_is_still_a_lockout() {
    let mut s = router();
    let wan = from_wan();
    ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"chain": "input", "connection_state": "established,related"}),
    );
    let msg = lockout(
        &mut s,
        &wan,
        "ip.firewall.filter.add",
        json!({"chain": "input", "action": "drop", "in_interface_list": "!LAN"}),
    );
    assert!(msg.contains("would refuse a new login"), "{msg}");
}

#[test]
fn redirecting_the_management_port_is_a_lockout() {
    let mut s = router();
    let msg = lockout(
        &mut s,
        &from_wan(),
        "ip.firewall.nat.add",
        json!({"chain": "dstnat", "action": "dst-nat", "protocol": "tcp",
               "dst_port": "8729", "to_addresses": "192.168.88.20"}),
    );
    assert!(msg.contains("redirect"), "{msg}");
}

#[test]
fn replies_dropped_in_output_are_a_lockout() {
    let mut s = router();
    let msg = lockout(
        &mut s,
        &from_wan(),
        "ip.firewall.filter.add",
        json!({"chain": "output", "action": "reject", "out_interface": "ether1"}),
    );
    assert!(msg.contains("replies"), "{msg}");
}

#[test]
fn safe_mode_transactions_batches_lists_and_rollback() {
    let mut s = router();
    let wan = from_wan();
    let drop_wan = json!({"chain": "input", "action": "drop", "in_interface_list": "WAN"});

    // Safe Mode: losing the connection undoes it, so no refusal.
    ok_as(&mut s, &wan, "config.safe-mode.enter", json!({}));
    ok_as(&mut s, &wan, "ip.firewall.filter.add", drop_wan.clone());
    ok_as(&mut s, &wan, "config.safe-mode.cancel", json!({}));
    assert!(rules(&mut s, "filter").is_empty(), "undone");

    // Transactional: the commit is what is checked; force there.
    ok_as(
        &mut s,
        &wan,
        "config.mode.set",
        json!({"mode": "transactional"}),
    );
    ok_as(&mut s, &wan, "ip.firewall.filter.add", drop_wan.clone());
    let msg = lockout(&mut s, &wan, "config.commit", json!({}));
    assert!(msg.contains("config.commit force=true"), "{msg}");
    ok_as(&mut s, &wan, "config.discard", json!({}));
    ok_as(
        &mut s,
        &wan,
        "config.mode.set",
        json!({"mode": "immediate"}),
    );
    assert_eq!(s.mode(), CommitMode::Immediate);

    // A batch is one commit: one step's force covers it.
    let steps = json!([
        {"command": "ip.firewall.filter.add", "params": {"chain": "input", "action": "accept", "in_interface_list": "LAN"}},
        {"command": "ip.firewall.filter.add", "params": {"chain": "input", "action": "drop", "force": true}},
    ]);
    s.batch_as(&wan, &steps, true).unwrap();
    assert_eq!(rules(&mut s, "filter").len(), 2);
    ok(&mut s, "ip.firewall.filter.remove", json!({"id": "*2"}));

    // The force does not outlive its command.
    lockout(&mut s, &wan, "ip.firewall.filter.add", drop_wan.clone());

    // Interface lists: putting ether1 into a list the firewall drops.
    ok(&mut s, "interface.list.add", json!({"name": "quarantine"}));
    ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"chain": "input", "action": "drop", "in_interface_list": "quarantine"}),
    );
    let msg = lockout(
        &mut s,
        &wan,
        "interface.list.member.add",
        json!({"list": "quarantine", "interface": "ether1"}),
    );
    assert!(msg.contains("in-interface-list=quarantine"), "{msg}");

    // A dynamic address-list entry (no commit) of the operator's address.
    ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"chain": "input", "action": "drop", "src_address_list": "blocked", "place_before": "*3"}),
    );
    let msg = lockout(
        &mut s,
        &wan,
        "ip.firewall.address-list.add",
        json!({"list": "blocked", "address": "198.51.100.0/24", "timeout": "1h"}),
    );
    assert!(msg.contains("src-address-list=blocked"), "{msg}");
    let entries = ok(&mut s, "ip.firewall.address-list.list", Value::Null);
    assert_eq!(entries, json!([]), "the entry did not reach the data plane");

    // Rolling back to a revision that locks out is refused too.
    let rev = s.store().current_revision();
    let id = ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"chain": "input", "action": "drop"}),
    )["id"]
        .clone();
    ok(&mut s, "ip.firewall.filter.remove", json!({"id": id}));
    let msg = lockout(
        &mut s,
        &wan,
        "config.rollback",
        json!({"revision": rev + 1}),
    );
    assert!(msg.contains("action=drop"), "{msg}");
    ok_as(
        &mut s,
        &wan,
        "config.rollback",
        json!({"revision": rev + 1, "force": true}),
    );
}

#[test]
fn shadowed_rules_and_descriptions_are_listed() {
    let mut s = router();
    for p in [
        json!({"chain": "input", "action": "drop", "src_address": "10.0.0.0/8"}),
        json!({"chain": "input", "src_address": "10.1.2.3", "protocol": "tcp", "dst_port": "22"}),
        json!({"chain": "input", "in_interface_list": "LAN", "protocol": "udp"}),
    ] {
        ok(&mut s, "ip.firewall.filter.add", p);
    }
    let list = rules(&mut s, "filter");
    assert_eq!(list[0]["shadowed_by"], Value::Null);
    assert_eq!(list[1]["shadowed_by"], "*1");
    assert_eq!(list[1]["flags"], "S");
    assert_eq!(list[2]["flags"], "");
    assert_eq!(
        list[0]["description"],
        "Descarta pacotes para o roteador, vindos de 10.0.0.0/8."
    );
    // Disabling the earlier rule clears the warning.
    ok(
        &mut s,
        "ip.firewall.filter.set",
        json!({"id": "*1", "disabled": true}),
    );
    assert_eq!(rules(&mut s, "filter")[1]["shadowed_by"], Value::Null);
}

#[test]
fn loopback_is_an_interface_matchers_may_name() {
    let mut s = router();
    ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"chain": "input", "in_interface": "lo"}),
    );
    match s.execute(
        "ip.firewall.filter.add",
        &json!({"chain": "input", "in_interface": "ether99"}),
    ) {
        Err(EngineError::BadParam { param, .. }) => assert_eq!(param, "in_interface"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn safe_defaults_need_lan_apply_once_and_replace() {
    let mut s = Session::virtual_lab();
    match s.execute("ip.firewall.defaults.apply", &json!({})) {
        Err(EngineError::BadParam { param, reason }) => {
            assert_eq!(param, "lan");
            assert!(reason.contains("LAN list is empty"), "{reason}");
        }
        other => panic!("{other:?}"),
    }
    let out = ok(
        &mut s,
        "ip.firewall.defaults.apply",
        json!({"lan": ["ether2", "ether3"], "wan": "ether1"}),
    );
    assert_eq!(out["lan"], json!(["ether2", "ether3"]));
    assert_eq!(out["wan"], json!(["ether1"]));
    let filter = rules(&mut s, "filter");
    assert_eq!(filter.len(), 11, "section + 10 rules");
    assert!(
        filter[0]["section"]
            .as_str()
            .unwrap()
            .starts_with("defconf")
    );
    assert!(
        filter
            .iter()
            .all(|r| r["comment"].as_str().unwrap().starts_with("defconf"))
    );
    assert!(filter.iter().all(|r| r["flags"] == ""), "{filter:#?}");
    let nat = rules(&mut s, "nat");
    assert_eq!(nat[0]["action"], "masquerade");
    assert_eq!(nat[0]["family"], "ipv4");

    // Again: refused, unless replace (no duplicates).
    match s.execute("ip.firewall.defaults.apply", &json!({})) {
        Err(EngineError::BadParam { param, .. }) => assert_eq!(param, "replace"),
        other => panic!("{other:?}"),
    }
    ok(
        &mut s,
        "ip.firewall.defaults.apply",
        json!({"replace": true}),
    );
    assert_eq!(rules(&mut s, "filter").len(), 11);
    assert_eq!(rules(&mut s, "nat").len(), 1);
}

#[test]
fn safe_defaults_from_the_wan_would_lock_out() {
    let mut s = router();
    let msg = lockout(&mut s, &from_wan(), "ip.firewall.defaults.apply", json!({}));
    assert!(msg.contains("in-interface-list=!LAN"), "{msg}");
    // From the LAN, or with loopback (the local CLI), it passes.
    ok_as(
        &mut s,
        &remote("127.0.0.1:40000", "127.0.0.1:7979"),
        "ip.firewall.defaults.apply",
        json!({}),
    );
}

#[test]
fn port_forward_template_goes_before_the_drops() {
    let mut s = router();
    ok(&mut s, "ip.firewall.defaults.apply", json!({}));
    let out = ok(
        &mut s,
        "ip.firewall.template.port-forward",
        json!({"dst_port": "8080", "to_addresses": "192.168.88.20", "to_ports": "80", "comment": "web"}),
    );
    let nat = rules(&mut s, "nat");
    let dnat = nat.iter().find(|r| r["id"] == out["nat"]).unwrap();
    assert_eq!(
        dnat["summary"],
        "chain=dstnat action=dst-nat protocol=tcp dst-port=8080 in-interface-list=WAN to-addresses=192.168.88.20 to-ports=80"
    );
    assert!(dnat["comment"].as_str().unwrap().contains("(web)"));
    let filter = rules(&mut s, "filter");
    let pos = |id: &Value| filter.iter().position(|r| r["id"] == *id).unwrap();
    let accept = pos(&out["filter"]);
    let first_forward_drop = filter
        .iter()
        .position(|r| r["chain"] == "forward" && r["action"] == "drop")
        .unwrap();
    assert!(accept < first_forward_drop, "{filter:#?}");
    assert_eq!(filter[accept]["dst_port"], "80");
    assert_eq!(filter[accept]["connection_nat_state"], "dstnat");

    // A bad step changes nothing (one command, one rollback).
    let before = (rules(&mut s, "nat").len(), rules(&mut s, "filter").len());
    assert!(s
        .execute(
            "ip.firewall.template.port-forward",
            &json!({"dst_port": "81", "to_addresses": "192.168.88.20", "in_interface_list": "nope"}),
        )
        .is_err());
    assert_eq!(
        before,
        (rules(&mut s, "nat").len(), rules(&mut s, "filter").len())
    );
}

#[test]
fn block_address_template_adds_the_drops_once() {
    let mut s = router();
    let out = ok(
        &mut s,
        "ip.firewall.template.block-address",
        json!({"address": "198.51.100.0/24"}),
    );
    assert_eq!(out["rules"].as_array().unwrap().len(), 2, "input + forward");
    let out = ok(
        &mut s,
        "ip.firewall.template.block-address",
        json!({"address": "192.0.2.66", "timeout": "1h"}),
    );
    assert_eq!(out["rules"], json!([]), "the drops exist already");
    let entries = ok(&mut s, "ip.firewall.address-list.list", Value::Null);
    let entries = entries.as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1]["dynamic"], true);
    // Blocking your own address is a lockout.
    let msg = lockout(
        &mut s,
        &remote("203.0.113.77:50000", "203.0.113.1:8729"),
        "ip.firewall.template.block-address",
        json!({"address": "203.0.113.77", "list": "other"}),
    );
    assert!(msg.contains("src-address-list=other"), "{msg}");
}

#[test]
fn brute_force_ping_and_lan_management_templates() {
    let mut s = router();
    let out = ok(
        &mut s,
        "ip.firewall.template.brute-force",
        json!({"dst_port": "22", "attempts": 3}),
    );
    assert_eq!(out["blacklist"], "bruteforce_blacklist");
    let filter = rules(&mut s, "filter");
    assert_eq!(filter.len(), 6, "section, drop, 3 stages, first try");
    assert_eq!(filter[1]["action"], "drop");
    assert_eq!(filter[1]["src_address_list"], "bruteforce_blacklist");
    assert_eq!(filter[2]["src_address_list"], "bruteforce_stage3");
    assert_eq!(filter[2]["address_list"], "bruteforce_blacklist");
    assert_eq!(filter[2]["address_list_timeout"], "10d");
    assert_eq!(filter[4]["address_list"], "bruteforce_stage2");
    assert_eq!(filter[5]["address_list"], "bruteforce_stage1");
    assert_eq!(filter[5]["address_list_timeout"], "1m");
    assert!(filter.iter().all(|r| r["flags"] == ""), "{filter:#?}");
    assert!(
        filter[2]["description"]
            .as_str()
            .unwrap()
            .contains("Põe na lista"),
        "{}",
        filter[2]["description"]
    );

    ok(&mut s, "ip.firewall.template.ping-limit", json!({}));
    let filter = rules(&mut s, "filter");
    assert_eq!(filter[1]["limit"], "5/1s,5");
    assert_eq!(filter[3]["icmp_options"], "128:0");

    // From the LAN, the connection's own port joins the default ports.
    let me = remote("192.168.88.10:50000", "192.168.88.1:9000");
    ok_as(
        &mut s,
        &me,
        "ip.firewall.template.lan-management",
        json!({}),
    );
    let filter = rules(&mut s, "filter");
    assert_eq!(
        filter[0]["section"],
        "Gerência só da LAN (tcp/22,8729,9000)"
    );
    assert_eq!(filter[1]["in_interface"], "lo");
    assert_eq!(filter[3]["action"], "drop");
    // From the WAN it would lock that operator out.
    lockout(
        &mut s,
        &remote("198.51.100.7:50000", "203.0.113.1:9001"),
        "ip.firewall.template.lan-management",
        json!({"dst_port": "9001"}),
    );
}

#[test]
fn zone_matrix_generates_a_managed_block() {
    let mut s = router();
    ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"chain": "input", "comment": "mine"}),
    );
    ok(
        &mut s,
        "ip.firewall.zone.set",
        json!({"from": "LAN", "to": "router", "action": "allow"}),
    );
    ok(
        &mut s,
        "ip.firewall.zone.set",
        json!({"from": "WAN", "to": "router", "action": "block"}),
    );
    let out = ok(
        &mut s,
        "ip.firewall.zone.set",
        json!({"from": "LAN", "to": "WAN", "action": "allow"}),
    );
    let generated = out["rules"].as_array().unwrap().clone();
    let filter = rules(&mut s, "filter");
    assert_eq!(
        filter.len(),
        1 + 1 + 2 + 2 + 2 + 1,
        "header, input 2+2, forward 2+1, mine"
    );
    assert_eq!(
        filter.last().unwrap()["comment"],
        "mine",
        "the block went on top"
    );
    assert!(filter[0]["section"].as_str().unwrap().starts_with("Zonas"));
    assert!(filter.iter().take(8).all(|r| r["zone"] == true));
    let wan_block = filter
        .iter()
        .find(|r| r["comment"] == "zona WAN -> router: bloquear")
        .unwrap();
    assert_eq!(wan_block["in_interface_list"], "WAN");
    assert_eq!(wan_block["action"], "drop");
    assert_eq!(wan_block["flags"], "Z");
    let zl = ok(&mut s, "ip.firewall.zone.list", Value::Null);
    assert_eq!(zl["zones"], json!(["router", "LAN", "WAN"]));
    assert_eq!(zl["cells"].as_array().unwrap().len(), 3);
    assert_eq!(zl["rules"], json!(generated));

    // Hand edits of generated rules are refused, and so is landing inside.
    let id = wan_block["id"].clone();
    for (cmd, p) in [
        (
            "ip.firewall.filter.set",
            json!({"id": id, "disabled": true}),
        ),
        ("ip.firewall.filter.remove", json!({"id": id})),
        ("ip.firewall.filter.move", json!({"id": id})),
    ] {
        match s.execute(cmd, &p) {
            Err(EngineError::BadParam { reason, .. }) => {
                assert!(reason.contains("zone matrix"), "{reason}");
            }
            other => panic!("{cmd}: {other:?}"),
        }
    }
    match s.execute(
        "ip.firewall.filter.add",
        &json!({"chain": "input", "place_before": id}),
    ) {
        Err(EngineError::BadParam { param, .. }) => assert_eq!(param, "place_before"),
        other => panic!("{other:?}"),
    }
    // Above the header is fine.
    ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"chain": "input", "comment": "top", "place_before": filter[0]["id"]}),
    );

    // Changing a cell rewrites the block in place, below "top".
    ok(
        &mut s,
        "ip.firewall.zone.set",
        json!({"from": "LAN", "to": "WAN", "action": "none"}),
    );
    let filter = rules(&mut s, "filter");
    assert_eq!(filter[0]["comment"], "top");
    assert_eq!(filter.len(), 1 + 1 + 4 + 1);
    assert!(filter.iter().all(|r| r["chain"] != "forward"));

    // From the WAN, blocking WAN → router is a lockout.
    ok(&mut s, "ip.firewall.zone.clear", json!({}));
    assert_eq!(rules(&mut s, "filter").len(), 2);
    lockout(
        &mut s,
        &from_wan(),
        "ip.firewall.zone.set",
        json!({"from": "WAN", "to": "router", "action": "block"}),
    );

    // Detach: the rules stay, now ordinary and editable.
    ok(
        &mut s,
        "ip.firewall.zone.set",
        json!({"from": "LAN", "to": "router", "action": "allow"}),
    );
    let out = ok(&mut s, "ip.firewall.zone.detach", json!({}));
    let id = out["rules"][1].clone();
    ok(
        &mut s,
        "ip.firewall.filter.set",
        json!({"id": id, "comment": "now mine"}),
    );
    assert_eq!(
        ok(&mut s, "ip.firewall.zone.list", Value::Null)["cells"],
        json!([])
    );

    // Bad cells.
    for (p, key) in [
        (json!({"from": "LAN", "to": "LAN", "action": "allow"}), "to"),
        (
            json!({"from": "nope", "to": "router", "action": "allow"}),
            "from",
        ),
        (
            json!({"from": "LAN", "to": "router", "action": "maybe"}),
            "action",
        ),
    ] {
        match s.execute("ip.firewall.zone.set", &p) {
            Err(EngineError::BadParam { param, .. }) => assert_eq!(param, key, "{p}"),
            other => panic!("{p}: {other:?}"),
        }
    }
}
