//! G1.24: the rule window takes the tables' chains and actions, and the
//! action parameters of each action, from the engine (`ip.firewall.actions`)
//! instead of a copy of its own. Contract: for every action of every table,
//! what the window sends is what the engine takes.

use super::*;
use crate::firewall::{FwTable, RuleForm, Schema};

fn schema(s: &mut Session) -> Vec<Value> {
    s.execute("ip.firewall.actions", &json!({})).unwrap().as_array().unwrap().clone()
}

const TABLES: [FwTable; 4] = [FwTable::Filter, FwTable::Nat, FwTable::Mangle, FwTable::Raw];

/// A value of the right shape for each action parameter.
fn sample(param: &str) -> &'static str {
    match param {
        "reject_with" => "icmp-admin-prohibited",
        "jump_target" => "mine",
        "to_addresses" => "192.0.2.10",
        "to_ports" => "8080",
        "new_mss" => "1400",
        "address_list_timeout" => "1m",
        _ => "x1",
    }
}

#[test]
fn the_window_sends_only_what_each_action_takes() {
    let mut s = Session::virtual_lab();
    let rows = schema(&mut s);
    let schema = Schema(&rows);
    let mut checked = 0;
    for t in TABLES {
        let actions = schema.actions(t);
        assert!(!actions.is_empty(), "{t:?}: no actions from the engine");
        for action in actions {
            let takes = schema.params(t, &action).expect("listed");
            let mut form = RuleForm::new(t, schema);
            form.set("action", &action);
            // Every action parameter of every action filled in: the window
            // keeps only this action's.
            for (ot, other) in TABLES.iter().flat_map(|t| schema.actions(*t).into_iter().map(move |a| (*t, a))) {
                for p in schema.params(ot, &other).unwrap_or_default() {
                    form.set(&p, sample(&p));
                }
            }
            // The window shows a field exactly when the action takes it.
            for p in ["reject_with", "new_mss", "to_addresses", "address_list"] {
                form.set(p, sample(p));
            }
            let sent = form.add_params(schema, t);
            for p in ["reject_with", "jump_target", "log_prefix", "to_addresses", "to_ports", "new_connection_mark",
                "new_packet_mark", "new_routing_mark", "new_mss", "address_list", "address_list_timeout"]
            {
                assert_eq!(sent.get(p).is_some(), takes.iter().any(|x| x == p), "{t:?} {action}: {p} in {sent}");
            }
            // The engine never refuses a key the window sent for this
            // action (a value may still be wrong for a rule like this one).
            let mut probe = Session::virtual_lab();
            let _ = probe.execute(&format!("ip.firewall.{}.add", t.name()), &json!({"chain": "mine"}));
            if let Err(e) = probe.execute(&format!("ip.firewall.{}.add", t.name()), &sent) {
                let e = e.to_string();
                assert!(!e.contains("only for action") && !e.contains("unknown parameter"), "{t:?} {action}: {e} ({sent})");
            }
            checked += 1;
        }
    }
    assert!(checked >= 30, "{checked} actions checked");
}

#[test]
fn switching_action_drops_the_old_action_parameters() {
    let mut s = Session::virtual_lab();
    let rows = schema(&mut s);
    let schema = Schema(&rows);
    let mut base = RuleForm::new(FwTable::Nat, schema);
    base.set("chain", "dstnat");
    base.set("action", "dst-nat");
    base.set("to_addresses", "192.0.2.10");
    let mut form = base.clone();
    form.set("action", "accept");
    let p = form.set_params("*1", &base, schema, FwTable::Nat).expect("changed");
    assert_eq!(p, json!({"id": "*1", "action": "accept"}));
    // The chains come from the engine too.
    assert_eq!(schema.chains(FwTable::Nat), ["dstnat", "srcnat"]);
    assert_eq!(RuleForm::new(FwTable::Raw, schema).get("chain"), "prerouting");
}

#[test]
fn the_engine_lists_no_parameter_the_window_has_no_field_for() {
    let mut s = Session::virtual_lab();
    let rows = schema(&mut s);
    let schema = Schema(&rows);
    for t in TABLES {
        for action in schema.actions(t) {
            for p in schema.params(t, &action).unwrap_or_default() {
                let has_field = p == "passthrough" || RuleForm::has_field(&p);
                assert!(has_field, "{t:?} {action}: the window has no field for {p}");
            }
        }
    }
}
