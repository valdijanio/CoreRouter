//! G1.24: the `removable` / `editable` / `fixed_reason` of a list row tell
//! the truth. For every row of the lists that carry them, in a router with
//! one row of each kind, the list's `remove` and `set` succeed exactly when
//! the row says so, and refuse with the row's reason when it does not.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
use serde_json::{Value, json};

/// A router with a row of every kind: physical ports, a VLAN, a static
/// address, rules the zone matrix wrote and one by hand, a static and a
/// dynamic address-list entry.
fn router() -> Session {
    let mut s = Session::virtual_lab();
    for (id, p) in [
        (
            "interface.vlan.add",
            json!({"name": "v7", "parent": "ether7", "vlan_id": 7}),
        ),
        (
            "ip.address.add",
            json!({"address": "192.168.88.1/24", "interface": "ether2"}),
        ),
        (
            "ip.firewall.filter.add",
            json!({"chain": "input", "comment": "mine"}),
        ),
        (
            "ip.firewall.zone.set",
            json!({"from": "LAN", "to": "router", "action": "allow"}),
        ),
        (
            "ip.firewall.address-list.add",
            json!({"list": "ok", "address": "192.0.2.1"}),
        ),
        (
            "ip.firewall.address-list.add",
            json!({"list": "bad", "address": "192.0.2.7", "timeout": "1m"}),
        ),
    ] {
        s.execute(id, &p)
            .unwrap_or_else(|e| panic!("{id} {p}: {e}"));
    }
    s
}

/// A list, how its rows are named, and the commands acting on one row.
struct Feed {
    list: &'static str,
    key: &'static str,
    remove: &'static str,
    set: &'static str,
    /// A harmless change for `set`.
    change: Value,
}

const FEEDS: &[(&str, &str, &str, &str)] = &[
    (
        "interface.list",
        "name",
        "interface.remove",
        "interface.set",
    ),
    (
        "ip.address.list",
        "id",
        "ip.address.remove",
        "ip.address.set",
    ),
    (
        "ip.firewall.filter.list",
        "id",
        "ip.firewall.filter.remove",
        "ip.firewall.filter.set",
    ),
    (
        "ip.firewall.address-list.list",
        "id",
        "ip.firewall.address-list.remove",
        "ip.firewall.address-list.set",
    ),
];

fn feeds() -> Vec<Feed> {
    FEEDS
        .iter()
        .map(|&(list, key, remove, set)| Feed {
            list,
            key,
            remove,
            set,
            change: json!({"comment": "contract"}),
        })
        .collect()
}

fn rows(s: &mut Session, list: &str) -> Vec<Value> {
    s.execute(list, &json!({}))
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn every_row_says_what_remove_and_set_do() {
    let mut seen = (0, 0, 0);
    for f in feeds() {
        let listed = rows(&mut router(), f.list);
        assert!(!listed.is_empty(), "{}: no rows", f.list);
        for row in listed {
            let name = row[f.key].clone();
            let what = format!("{} {name}", f.list);
            let removable = row["removable"]
                .as_bool()
                .unwrap_or_else(|| panic!("{what}: no removable: {row}"));
            let editable = row["editable"]
                .as_bool()
                .unwrap_or_else(|| panic!("{what}: no editable: {row}"));
            let reason = row["fixed_reason"].as_str();
            assert_eq!(
                reason.is_some(),
                !(removable && editable),
                "{what}: a reason exactly when fixed: {row}"
            );
            seen.0 += 1;
            seen.1 += usize::from(!removable);
            seen.2 += usize::from(!editable);

            // Each command on a fresh router: one does not hide the other.
            let mut p = json!({});
            p[f.key] = name.clone();
            let got = router().execute(f.remove, &p);
            match (removable, got) {
                (true, Err(e)) => panic!("{what} says removable, {} refused: {e}", f.remove),
                (false, Ok(_)) => panic!("{what} says not removable, {} took it", f.remove),
                (false, Err(e)) => {
                    // The interface rules are the remove's own words.
                    if f.list == "interface.list" && row["managed"] != false {
                        assert!(e.to_string().contains(reason.unwrap_or("-")), "{what}: {e}");
                    }
                }
                (true, Ok(_)) => {}
            }
            let mut p = f.change.clone();
            p[f.key] = name;
            let got = router().execute(f.set, &p);
            match (editable, got) {
                (true, Err(e)) => panic!("{what} says editable, {} refused: {e}", f.set),
                (false, Ok(_)) => panic!("{what} says not editable, {} took it", f.set),
                _ => {}
            }
        }
    }
    // The router above has rows of every kind.
    assert!(
        seen.1 >= 8 && seen.2 >= 2,
        "rows, not removable, not editable: {seen:?}"
    );
}

#[test]
fn the_reasons_name_where_to_change_it() {
    let mut s = router();
    let ether = rows(&mut s, "interface.list")
        .into_iter()
        .find(|r| r["name"] == "ether1")
        .unwrap();
    assert_eq!(
        (ether["removable"].as_bool(), ether["editable"].as_bool()),
        (Some(false), Some(true))
    );
    assert!(
        ether["fixed_reason"]
            .as_str()
            .unwrap()
            .contains("disable it instead"),
        "{ether}"
    );
    let vlan = rows(&mut s, "interface.list")
        .into_iter()
        .find(|r| r["name"] == "v7")
        .unwrap();
    assert_eq!(vlan["fixed_reason"], Value::Null);

    let zone = rows(&mut s, "ip.firewall.filter.list")
        .into_iter()
        .find(|r| r["zone"] == true)
        .unwrap();
    assert!(
        zone["fixed_reason"]
            .as_str()
            .unwrap()
            .contains("zone matrix"),
        "{zone}"
    );

    let dynamic = rows(&mut s, "ip.firewall.address-list.list")
        .into_iter()
        .find(|r| r["dynamic"] == true)
        .unwrap();
    assert_eq!(
        (
            dynamic["removable"].as_bool(),
            dynamic["editable"].as_bool()
        ),
        (Some(true), Some(false))
    );
    assert!(
        dynamic["fixed_reason"]
            .as_str()
            .unwrap()
            .contains("timeout"),
        "{dynamic}"
    );
}
