//! G1.24: contract between the engine and the GUI on what a row allows.
//! The engine's list rows say `removable` / `editable` / `fixed_reason`
//! (`crates/engine/tests/it/row_rules.rs` checks they tell the truth); the
//! GUI greys out its buttons with exactly that, and decides nothing of its
//! own. Rows come from a real engine here, not from hand-written JSON.

use super::*;
use crate::firewall::{Feed, refused};
use crate::interfaces::{Iface, can_remove};
use crate::list::{Cmds, Item, RowRules, Tools};

fn engine() -> Session {
    let mut s = Session::virtual_lab();
    for (id, p) in [
        ("interface.vlan.add", json!({"name": "v7", "parent": "ether7", "vlan_id": 7})),
        ("ip.address.add", json!({"address": "192.168.88.1/24", "interface": "ether2"})),
        ("ip.firewall.filter.add", json!({"chain": "input", "comment": "mine"})),
        ("ip.firewall.zone.set", json!({"from": "LAN", "to": "router", "action": "allow"})),
        ("ip.firewall.address-list.add", json!({"list": "ok", "address": "192.0.2.1"})),
        ("ip.firewall.address-list.add", json!({"list": "bad", "address": "192.0.2.7", "timeout": "1m"})),
    ] {
        s.execute(id, &p).unwrap_or_else(|e| panic!("{id} {p}: {e}"));
    }
    s
}

fn rows(s: &mut Session, list: &str) -> Vec<Value> {
    s.execute(list, &json!({})).unwrap().as_array().unwrap().clone()
}

/// What the engine says of `row`, as `(remove, edit)` results.
fn says(row: &Value) -> (Result<(), String>, Result<(), String>) {
    let r = RowRules::of(row).unwrap_or_else(|| panic!("the GUI cannot read the rules of {row}"));
    (r.removable, r.editable)
}

#[test]
fn every_list_row_the_gui_greys_carries_the_engine_rules() {
    let mut s = engine();
    for list in ["interface.list", "ip.address.list", "ip.firewall.filter.list", "ip.firewall.address-list.list"] {
        for row in rows(&mut s, list) {
            let _ = says(&row);
        }
    }
}

#[test]
fn interfaces_remove_is_greyed_with_the_engine_reason() {
    let mut s = engine();
    let mut fixed = 0;
    for row in rows(&mut s, "interface.list") {
        let iface = Iface::from_row(&row);
        let (remove, _) = says(&row);
        let gui = can_remove(&[&iface]);
        match remove {
            Ok(()) => assert_eq!(gui, Ok(()), "{row}"),
            Err(why) => {
                fixed += 1;
                let shown = gui.expect_err("greyed");
                assert!(shown.ends_with(&why), "{shown} / {why}");
            }
        }
    }
    assert!(fixed >= 8, "the lab's ports: {fixed}");
}

#[test]
fn list_windows_grey_with_the_engine_reason() {
    let mut s = engine();
    let cmds = Cmds {
        add: "ip.address.add",
        remove: "ip.address.remove",
        set: Some("ip.address.set"),
        what: "addresses",
    };
    let can = crate::avail::Avail::default();
    for row in rows(&mut s, "ip.address.list") {
        let (remove, edit) = says(&row);
        // No fallback text: what the row says is what the GUI shows.
        let tools = Tools::new(&can, &cmds, &[Item::of(&row, "id", "GUI's own words")]);
        assert_eq!(tools.remove, remove, "{row}");
        assert_eq!(tools.comment, edit, "{row}");
    }
}

#[test]
fn firewall_greys_with_the_engine_reason() {
    let mut s = engine();
    for (list, f) in [("ip.firewall.filter.list", Feed::Filter), ("ip.firewall.address-list.list", Feed::Addr)] {
        let all = rows(&mut s, list);
        let mut fixed = 0;
        for row in &all {
            let sel: table::Selection = [row["id"].as_str().unwrap().to_owned()].into_iter().collect();
            let (remove, edit) = says(row);
            fixed += usize::from(remove.is_err() || edit.is_err());
            assert_eq!(refused(&all, f, &sel, false), remove, "{row}");
            assert_eq!(refused(&all, f, &sel, true), edit, "{row}");
        }
        assert!(fixed > 0, "{list}: a fixed row to check");
    }
}
