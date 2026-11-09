//! G1.27e: `/routing rule` through the commands, in the virtual lab: the
//! kernel's list it asks for, the walk of `ip.route.lookup`, the lockout.

use corerouter_engine::lockout::Link;
use corerouter_engine::{Caller, Principal, Session};
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p).unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn err(s: &mut Session, id: &str, p: Value) -> String {
    match s.execute(id, &p) {
        Ok(v) => panic!("{id} {p} worked: {v}"),
        Err(e) => e.to_string(),
    }
}

/// `main` goes out of ether1, table `isp2` out of ether2; `empty` has nothing.
fn lab() -> Session {
    let mut s = Session::virtual_lab();
    for (a, i) in [("192.0.2.2/24", "ether1"), ("198.51.100.2/24", "ether2")] {
        ok(&mut s, "ip.address.add", json!({"address": a, "interface": i}));
    }
    ok(&mut s, "routing.table.add", json!({"name": "isp2"}));
    ok(&mut s, "routing.table.add", json!({"name": "empty"}));
    ok(&mut s, "ip.route.add", json!({"dst_address": "0.0.0.0/0", "gateway": "192.0.2.1"}));
    ok(&mut s, "ip.route.add", json!({
        "dst_address": "0.0.0.0/0", "gateway": "198.51.100.1", "routing_table": "isp2"
    }));
    s
}

fn from_lan(s: &mut Session, src: &str, dst: &str) -> Value {
    ok(s, "ip.route.lookup", json!({"address": dst, "src": src, "interface": "ether3"}))
}

#[test]
fn rules_choose_the_table_and_the_lookup_says_which() {
    let mut s = lab();
    let r = ok(&mut s, "routing.rule.add", json!({
        "src_address": "10.91.0.0/24", "action": "lookup", "table": "isp2", "comment": "via B"
    }));
    assert_eq!(r["summary"], "src-address=10.91.0.0/24 action=lookup table=isp2");
    let id = r["id"].as_str().unwrap().to_owned();

    let l = from_lan(&mut s, "10.91.0.7", "8.8.8.8");
    assert_eq!(l["routing_table"], "isp2", "{l}");
    assert_eq!(l["interface"], "ether2");
    assert_eq!(l["matched_rule"], id.as_str());
    assert_eq!(l["kernel"]["same"], true, "{l}");
    assert!(l["rule"].as_str().unwrap().contains(&id), "{l}");

    let l = from_lan(&mut s, "10.92.0.7", "8.8.8.8");
    assert_eq!(l["routing_table"], "main");
    assert_eq!(l["interface"], "ether1");
    assert_eq!(l["matched_rule"], Value::Null);
    assert_eq!(l["kernel"]["same"], true, "{l}");

    let rows = ok(&mut s, "routing.rule.list", json!({}));
    assert_eq!(rows[0]["priority"], 2000);
    assert_eq!(rows[0]["family"], "ipv4");
    assert_eq!(rows[0]["table"], "isp2");
    assert_eq!(rows[0]["comment"], "via B");
    let kernel = ok(&mut s, "routing.rule.kernel", json!({}));
    assert_eq!(kernel["available"], true);
    let mine: Vec<&Value> = kernel["rules"].as_array().unwrap().iter()
        .filter(|r| r["owner"] == "corerouter").collect();
    assert_eq!(mine.len(), 1, "{kernel}");
    assert_eq!(mine[0]["rule"], id.as_str());
    assert_eq!(kernel["drift"], json!([]));
}

#[test]
fn each_action_answers_in_the_lookup() {
    let mut s = lab();
    for (src, action, table) in [
        ("10.91.0.0/24", "lookup", "empty"),
        ("10.92.0.0/24", "lookup-only-in-table", "empty"),
        ("10.93.0.0/24", "drop", "main"),
        ("10.94.0.0/24", "unreachable", "main"),
    ] {
        ok(&mut s, "routing.rule.add", json!({"src_address": src, "action": action, "table": table}));
    }
    let t = |s: &mut Session, src: &str| {
        let l = from_lan(s, src, "8.8.8.8");
        assert_eq!(l["kernel"]["same"], true, "{src}: {l}");
        (l["type"].as_str().unwrap().to_owned(), l["trace"].as_array().unwrap().len())
    };
    assert_eq!(t(&mut s, "10.91.0.1"), ("unicast".to_owned(), 2), "falls through to main");
    assert_eq!(t(&mut s, "10.92.0.1"), ("unreachable".to_owned(), 2), "the miss, then stop");
    assert_eq!(t(&mut s, "10.93.0.1"), ("blackhole".to_owned(), 1));
    assert_eq!(t(&mut s, "10.94.0.1"), ("unreachable".to_owned(), 1));
    // The router's own address is rule 0: before any rule, as in the kernel.
    let l = from_lan(&mut s, "10.93.0.1", "192.0.2.2");
    assert_eq!((l["type"].as_str(), l["trace"][0]["priority"].as_u64()), (Some("local"), Some(0)));
}

#[test]
fn the_interface_and_the_mark_match() {
    let mut s = lab();
    ok(&mut s, "routing.rule.add", json!({
        "interface": "ether3", "dst_address": "203.0.113.0/24", "table": "isp2"
    }));
    ok(&mut s, "routing.rule.add", json!({"routing_mark": "guests", "table": "isp2"}));
    let l = from_lan(&mut s, "10.0.0.1", "203.0.113.9");
    assert_eq!(l["routing_table"], "isp2", "{l}");
    let l = ok(&mut s, "ip.route.lookup", json!({
        "address": "203.0.113.9", "src": "10.0.0.1", "interface": "ether4"
    }));
    assert_eq!(l["routing_table"], "main", "another interface: {l}");
    let l = ok(&mut s, "ip.route.lookup", json!({"address": "8.8.8.8", "routing_mark": "guests"}));
    assert_eq!(l["routing_table"], "isp2", "{l}");
    assert_eq!(l["kernel"]["same"], true, "{l}");
    let l = ok(&mut s, "ip.route.lookup", json!({"address": "8.8.8.8"}));
    assert_eq!(l["routing_table"], "main", "{l}");
}

#[test]
fn a_mark_of_the_mangle_goes_to_its_table_before_the_rules() {
    let mut s = lab();
    ok(&mut s, "ip.firewall.mangle.add", json!({
        "chain": "prerouting", "action": "mark-routing", "new_routing_mark": "isp2"
    }));
    ok(&mut s, "ip.firewall.mangle.add", json!({
        "chain": "prerouting", "action": "mark-routing", "new_routing_mark": "nothing"
    }));
    ok(&mut s, "routing.rule.add", json!({"action": "drop"}));
    let l = ok(&mut s, "ip.route.lookup", json!({"address": "8.8.8.8", "routing_mark": "isp2"}));
    assert_eq!(l["routing_table"], "isp2", "the mark wins over the rule: {l}");
    assert!(l["rule"].as_str().unwrap().contains("mangle"), "{l}");
    assert_eq!(l["matched_rule"], Value::Null);
    let k = ok(&mut s, "routing.rule.kernel", json!({}));
    assert_eq!(k["marks_without_table"], json!(["nothing"]));
    let e = err(&mut s, "routing.table.remove", json!({"name": "isp2"}));
    assert!(e.contains("in use"), "{e}");
}

#[test]
fn order_matters_and_move_changes_it() {
    let mut s = lab();
    let a = ok(&mut s, "routing.rule.add", json!({"src_address": "10.0.0.0/8", "table": "isp2"}));
    let b = ok(&mut s, "routing.rule.add", json!({"src_address": "10.1.0.0/16", "action": "drop"}));
    assert_eq!(from_lan(&mut s, "10.1.0.1", "8.8.8.8")["routing_table"], "isp2");
    ok(&mut s, "routing.rule.move", json!({"id": b["id"], "place_before": a["id"]}));
    assert_eq!(from_lan(&mut s, "10.1.0.1", "8.8.8.8")["type"], "blackhole");
    let c = ok(&mut s, "routing.rule.add", json!({
        "src_address": "10.1.1.0/24", "table": "main", "place_before": b["id"]
    }));
    let ids: Vec<Value> = ok(&mut s, "routing.rule.list", json!({})).as_array().unwrap().iter()
        .map(|r| r["id"].clone()).collect();
    assert_eq!(ids, [c["id"].clone(), b["id"].clone(), a["id"].clone()]);
    ok(&mut s, "routing.rule.move", json!({"id": c["id"]}));
    let ids: Vec<Value> = ok(&mut s, "routing.rule.list", json!({})).as_array().unwrap().iter()
        .map(|r| r["id"].clone()).collect();
    assert_eq!(ids.last(), Some(&c["id"]));
    let e = err(&mut s, "routing.rule.move", json!({"id": c["id"], "place_before": "*FF"}));
    assert!(e.contains("no routing rule"), "{e}");
}

#[test]
fn set_changes_and_clears_and_a_disabled_rule_does_nothing() {
    let mut s = lab();
    let r = ok(&mut s, "routing.rule.add", json!({
        "src_address": "10.0.0.0/8", "interface": "ether3", "table": "isp2", "min_prefix": 8
    }));
    ok(&mut s, "routing.rule.set", json!({"id": r["id"], "interface": null, "min_prefix": null}));
    let row = ok(&mut s, "routing.rule.list", json!({}))[0].clone();
    assert_eq!((row["interface"].clone(), row["min_prefix"].clone()), (Value::Null, Value::Null));
    assert_eq!(row["src_address"], "10.0.0.0/8");
    ok(&mut s, "routing.rule.set", json!({"id": r["id"], "src_address": "", "disabled": true}));
    let row = ok(&mut s, "routing.rule.list", json!({}))[0].clone();
    assert_eq!((row["src_address"].clone(), row["family"].as_str(), row["flags"].as_str()),
        (Value::Null, Some("both"), Some("X")));
    let l = ok(&mut s, "ip.route.lookup", json!({"address": "8.8.8.8"}));
    assert_eq!(l["routing_table"], "main");
    ok(&mut s, "routing.rule.remove", json!({"id": r["id"]}));
    assert_eq!(ok(&mut s, "routing.rule.list", json!({})), json!([]));
    // The id is not used again.
    let again = ok(&mut s, "routing.rule.add", json!({"action": "unreachable", "dst_address": "203.0.113.0/24"}));
    assert_ne!(again["id"], r["id"]);
}

#[test]
fn bad_rules_are_refused() {
    let mut s = lab();
    for (p, needle) in [
        (json!({"table": "nope"}), "does not exist"),
        (json!({"src_address": "10.0.0.1/24"}), "host bits"),
        (json!({"src_address": "10.0.0.0/8", "dst_address": "2001:db8::/32"}), "same family"),
        (json!({"action": "fly"}), "must be lookup"),
        (json!({"interface": "nope0"}), "no interface"),
        (json!({"src_address": "10.0.0.0/8", "min_prefix": 33}), "0..=32"),
        (json!({"min_prefix": 129}), "0..=128"),
        (json!({"action": "drop", "min_prefix": 0}), "means nothing"),
        (json!({"place_before": "*FF"}), "no routing rule"),
        (json!({"routing_mark": "a b"}), "routing_mark"),
    ] {
        let e = err(&mut s, "routing.rule.add", p.clone());
        assert!(e.contains(needle), "{p}: {e}");
    }
    assert_eq!(ok(&mut s, "routing.rule.list", json!({})), json!([]));
    // A member of a VRF: the VRF's table answers before any rule.
    ok(&mut s, "ip.vrf.add", json!({"name": "blue", "interfaces": ["ether4"]}));
    let e = err(&mut s, "routing.rule.add", json!({"interface": "ether4"}));
    assert!(e.contains("VRF"), "{e}");
    let e = err(&mut s, "routing.rule.add", json!({"interface": "blue"}));
    assert!(e.contains("VRF"), "{e}");
    // What a rule looks in stays until the rule goes.
    let r = ok(&mut s, "routing.rule.add", json!({"table": "blue"}));
    let e = err(&mut s, "ip.vrf.remove", json!({"name": "blue"}));
    assert!(e.contains("routing rule"), "{e}");
    ok(&mut s, "routing.rule.remove", json!({"id": r["id"]}));
    let r = ok(&mut s, "routing.rule.add", json!({"table": "empty"}));
    let e = err(&mut s, "routing.table.remove", json!({"name": "empty"}));
    assert!(e.contains("routing rule"), "{e}");
    ok(&mut s, "routing.rule.remove", json!({"id": r["id"]}));
    ok(&mut s, "routing.table.remove", json!({"name": "empty"}));
}

#[test]
fn a_vrf_miss_stays_in_the_vrf() {
    let mut s = lab();
    ok(&mut s, "ip.vrf.add", json!({"name": "blue", "interfaces": ["ether4"]}));
    ok(&mut s, "ip.address.add", json!({"address": "10.74.1.2/24", "interface": "ether4"}));
    ok(&mut s, "routing.rule.add", json!({"table": "isp2"}));
    let l = ok(&mut s, "ip.route.lookup", json!({"address": "8.8.8.8", "src": "10.74.1.2"}));
    assert_eq!(l["type"], "unreachable", "no leak to the rule nor main: {l}");
    assert_eq!(l["trace"].as_array().unwrap().len(), 2, "{l}");
    assert!(l["rule"].as_str().unwrap().contains("VRF"), "{l}");
    assert_eq!(l["kernel"]["same"], true, "{l}");
}

#[test]
fn the_list_says_what_does_nothing() {
    let mut s = lab();
    ok(&mut s, "routing.rule.add", json!({"src_address": "10.0.0.0/8", "action": "drop"}));
    ok(&mut s, "routing.rule.add", json!({"src_address": "10.1.0.0/16", "table": "isp2"}));
    ok(&mut s, "routing.rule.add", json!({"src_address": "192.168.0.0/16", "table": "empty"}));
    let rows = ok(&mut s, "routing.rule.list", json!({}));
    assert_eq!(rows[0]["notices"], json!([]));
    assert_eq!(rows[1]["notices"][0]["id"], "hidden", "{rows}");
    assert_eq!(rows[2]["notices"][0]["id"], "empty-table", "{rows}");
}

#[test]
fn transaction_rollback_takes_the_rule_away() {
    let mut s = lab();
    ok(&mut s, "config.mode.set", json!({"mode": "transactional"}));
    ok(&mut s, "routing.rule.add", json!({"action": "drop"}));
    assert_eq!(from_lan_running(&mut s), "unicast", "pending: nothing changed yet");
    ok(&mut s, "config.discard", json!({}));
    assert_eq!(ok(&mut s, "routing.rule.list", json!({})), json!([]));
    ok(&mut s, "routing.rule.add", json!({"action": "drop"}));
    ok(&mut s, "config.commit", json!({}));
    assert_eq!(from_lan_running(&mut s), "blackhole");
    let k = ok(&mut s, "routing.rule.kernel", json!({}));
    assert_eq!(k["drift"], json!([]));
}

fn from_lan_running(s: &mut Session) -> String {
    let l = ok(s, "ip.route.lookup", json!({"address": "8.8.8.8"}));
    l["type"].as_str().unwrap().to_owned()
}

/// A session from 203.0.113.50 to 192.0.2.2, on ether1 of [`lab`]'s main.
fn remote() -> Caller {
    Caller::new(9, "tls 203.0.113.50:50123".to_owned())
        .with_principal(Principal::Local)
        .with_link(Link {
            peer: "203.0.113.50:50123".parse().unwrap(),
            local: "192.0.2.2:8729".parse().unwrap(),
        })
}

#[test]
fn a_rule_that_stops_the_replies_asks_for_force() {
    let mut s = lab();
    let me = remote();
    let mut run = |s: &mut Session, id: &str, p: Value| s.execute_as(&me, id, &p);
    let stop = json!({"dst_address": "203.0.113.0/24", "action": "drop"});
    let e = run(&mut s, "routing.rule.add", stop.clone()).unwrap_err().to_string();
    assert!(e.contains("stop the replies") && e.contains("force"), "{e}");
    assert_eq!(ok(&mut s, "routing.rule.list", json!({})), json!([]), "refused: nothing stays");

    let other = json!({"src_address": "192.0.2.2/32", "action": "lookup-only-in-table", "table": "empty"});
    let e = run(&mut s, "routing.rule.add", other).unwrap_err().to_string();
    assert!(e.contains("stop the replies"), "{e}");

    let elsewhere = json!({"dst_address": "203.0.113.0/24", "action": "lookup", "table": "isp2"});
    let e = run(&mut s, "routing.rule.add", elsewhere).unwrap_err().to_string();
    assert!(e.contains("out of ether2 instead of ether1"), "{e}");

    // A rule that leaves this session alone goes in.
    let r = run(&mut s, "routing.rule.add", json!({"dst_address": "198.18.0.0/15", "action": "drop"})).unwrap();
    run(&mut s, "routing.rule.remove", json!({"id": r["id"]})).unwrap();

    let mut forced = stop.clone();
    forced["force"] = json!(true);
    let r = run(&mut s, "routing.rule.add", forced).unwrap();

    // Taking it away gives the way back: no question.
    run(&mut s, "routing.rule.remove", json!({"id": r["id"]})).unwrap();
}

#[test]
fn safe_mode_takes_the_rule_without_force() {
    let mut s = lab();
    let me = remote();
    s.execute_as(&me, "config.safe-mode.enter", &json!({})).unwrap();
    s.execute_as(
        &me,
        "routing.rule.add",
        &json!({"dst_address": "203.0.113.0/24", "action": "drop"}),
    )
    .unwrap();
}

#[test]
fn many_rules_say_what_they_cost() {
    let mut s = lab();
    let mut last = Value::Null;
    for i in 0..100 {
        last = ok(&mut s, "routing.rule.add", json!({"src_address": format!("10.0.{i}.0/24"), "table": "isp2"}));
        if i < 99 {
            assert_eq!(last.get("notice"), None);
        }
    }
    assert!(last["notice"].as_str().unwrap().contains("address list"), "{last}");
}
