//! G1.28 — IP › Addresses in the list pattern: `ip.address.set` (edit,
//! disable), the structured list (state, family, VRF, access), the preview
//! behind the add/edit modal (calculated fields, series, overlap, ARP) and
//! the access check for remove and disable.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::{Caller, CommitMode, EngineError, Link, Principal, Session};
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn rows(s: &mut Session) -> Vec<Value> {
    ok(s, "ip.address.list", Value::Null)
        .as_array()
        .unwrap()
        .clone()
}

fn row(s: &mut Session, address: &str) -> Value {
    rows(s)
        .into_iter()
        .find(|r| r["address"] == address)
        .unwrap_or_else(|| panic!("no {address}"))
}

fn preview(s: &mut Session, p: Value) -> Value {
    ok(s, "ip.address.check", p)
}

fn levels(p: &Value, check: &str) -> Vec<String> {
    p["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["check"] == check)
        .map(|c| c["level"].as_str().unwrap().to_owned())
        .collect()
}

fn computed(p: &Value, label: &str) -> String {
    p["computed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["label"] == label)
        .map(|c| c["value"].as_str().unwrap().to_owned())
        .unwrap_or_default()
}

#[test]
fn disable_keeps_it_in_the_config_and_out_of_the_data_plane() {
    let mut s = Session::virtual_lab();
    let id = ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.0.1/24", "interface": "ether1"}),
    )["id"]
        .clone();
    let r = row(&mut s, "10.0.0.1/24");
    assert_eq!(
        (r["state"].as_str(), r["family"].as_str(), r["vrf"].as_str()),
        (Some("active"), Some("ipv4"), Some("main"))
    );
    assert!(r["access"].is_null());

    ok(
        &mut s,
        "ip.address.set",
        json!({"id": id, "disabled": true, "comment": "spare"}),
    );
    let r = row(&mut s, "10.0.0.1/24");
    assert_eq!(r["state"], "disabled");
    assert_eq!(r["flags"], "X", "the terminal keeps its flags");
    assert_eq!(r["comment"], "spare");
    // Its connected route goes inactive (the kernel side: netns_address).
    let connected = |s: &mut Session| {
        ok(s, "ip.route.list", Value::Null)
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["dst_address"] == "10.0.0.0/24")
            .map(|r| r["active"].clone())
    };
    assert_eq!(connected(&mut s), Some(json!(false)));
    ok(
        &mut s,
        "ip.address.set",
        json!({"id": id, "disabled": false}),
    );
    assert_eq!(row(&mut s, "10.0.0.1/24")["state"], "active");
    assert_eq!(connected(&mut s), Some(json!(true)));

    // Edit: address and interface; a clash is refused and changes nothing.
    ok(
        &mut s,
        "ip.address.set",
        json!({"id": id, "address": "10.0.1.1/24", "interface": "ether2"}),
    );
    assert_eq!(row(&mut s, "10.0.1.1/24")["interface"], "ether2");
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.2.1/24", "interface": "ether2"}),
    );
    let err = s
        .execute(
            "ip.address.set",
            &json!({"id": id, "address": "10.0.2.1/24"}),
        )
        .unwrap_err();
    assert!(err.to_string().contains("already exists"), "{err}");
    assert_eq!(row(&mut s, "10.0.1.1/24")["interface"], "ether2");
    let err = s
        .execute("ip.address.set", &json!({"id": "*99", "disabled": true}))
        .unwrap_err();
    assert!(err.to_string().contains("no address"), "{err}");
}

#[test]
fn set_rolls_back_with_the_transaction() {
    let mut s = Session::virtual_lab();
    let id = ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.0.1/24", "interface": "ether1"}),
    )["id"]
        .clone();
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    ok(
        &mut s,
        "ip.address.set",
        json!({"id": id, "disabled": true}),
    );
    assert_eq!(s.mode(), CommitMode::Transactional);
    ok(&mut s, "config.discard", Value::Null);
    assert_eq!(row(&mut s, "10.0.0.1/24")["state"], "active");
    // And a failed step of an atomic batch leaves nothing behind.
    s.execute("config.mode.set", &json!({"mode": "immediate"}))
        .unwrap();
    let steps = json!([
        {"command": "ip.address.set", "params": {"id": id, "disabled": true}},
        {"command": "ip.address.set", "params": {"id": "*77", "disabled": true}},
    ]);
    assert!(s.batch(&steps, true).is_err());
    assert_eq!(row(&mut s, "10.0.0.1/24")["state"], "active");
}

#[test]
fn preview_calculates_and_builds_the_commands() {
    let mut s = Session::virtual_lab();
    let p = preview(
        &mut s,
        json!({"address": "10.20.0.1/24", "interface": "ether1", "arp": false}),
    );
    assert_eq!(computed(&p, "Network"), "10.20.0.0/24");
    assert_eq!(computed(&p, "Broadcast"), "10.20.0.255");
    assert_eq!(computed(&p, "Netmask"), "255.255.255.0");
    assert_eq!(computed(&p, "Hosts"), "254");
    assert_eq!(computed(&p, "Host range"), "10.20.0.1 – 10.20.0.254");
    assert_eq!(levels(&p, "overlap"), ["ok"]);
    assert_eq!(
        p["commands"],
        json!([{"command": "ip.address.add", "params": {"address": "10.20.0.1/24", "interface": "ether1"}}])
    );
    assert!(p["risk"].is_null());
    // RFC 3021: a /31 has two hosts and no broadcast.
    let p = preview(
        &mut s,
        json!({"address": "10.9.9.0/31", "interface": "ether1", "arp": false}),
    );
    assert_eq!(
        (
            computed(&p, "Hosts").as_str(),
            computed(&p, "Broadcast").as_str()
        ),
        ("2", "")
    );
    let p = preview(
        &mut s,
        json!({"address": "2001:db8::1/64", "interface": "ether1"}),
    );
    assert_eq!(computed(&p, "Hosts"), "2^64");
    assert_eq!(levels(&p, "dad"), ["info"]);

    // Bad input is a check by its field, never an error of the query.
    let p = preview(
        &mut s,
        json!({"address": "10.0.0.1", "interface": "ether1"}),
    );
    assert_eq!(p["checks"][0]["param"], "address");
    assert!(
        p["checks"][0]["message"]
            .as_str()
            .unwrap()
            .contains("prefix length")
    );
    assert_eq!(p["commands"], json!([]));
    let p = preview(&mut s, json!({"address": "10.0.0.1/24"}));
    assert_eq!(levels(&p, "interface"), ["error"]);
    let p = preview(
        &mut s,
        json!({"address": "10.0.0.0/24", "interface": "ether1", "arp": false}),
    );
    assert_eq!(levels(&p, "edge"), ["warning"]);
    // Nothing typed yet.
    assert_eq!(preview(&mut s, json!({}))["checks"][0]["level"], "info");
}

#[test]
fn a_series_by_range_is_one_transaction_with_a_cap() {
    let mut s = Session::virtual_lab();
    let p = preview(
        &mut s,
        json!({"address": "10.20.0.1/24", "to": "10.20.0.5", "interface": "ether1", "comment": "pool"}),
    );
    assert_eq!(p["count"], 5);
    let cmds = p["commands"].as_array().unwrap();
    assert_eq!(cmds.len(), 5);
    assert_eq!(
        cmds[4]["params"],
        json!({"address": "10.20.0.5/24", "interface": "ether1", "comment": "pool"})
    );
    assert_eq!(levels(&p, "arp"), ["info"], "no ARP for a series");
    // The commands as one atomic batch: all five or none.
    let r = s.batch(&json!(cmds), true).unwrap();
    assert_eq!(r["results"].as_array().unwrap().len(), 5);
    assert_eq!(rows(&mut s).len(), 5);
    // The sixth would repeat one: the whole series is refused.
    let p = preview(
        &mut s,
        json!({"address": "10.20.0.5/24", "to": "10.20.0.6", "interface": "ether1"}),
    );
    assert_eq!(levels(&p, "duplicate"), ["error"]);
    assert_eq!(p["commands"], json!([]));

    // The cap: 256 at most, with the count in the message.
    let p = preview(
        &mut s,
        json!({"address": "10.30.0.1/16", "to": "10.30.1.1", "interface": "ether1"}),
    );
    assert_eq!(p["count"], 257);
    let msg = p["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["check"] == "series")
        .unwrap()["message"]
        .clone();
    assert!(msg.as_str().unwrap().contains("at most 256"), "{msg}");
    assert_eq!(p["commands"], json!([]));
    let p = preview(
        &mut s,
        json!({"address": "10.30.0.1/16", "to": "10.30.1.0", "interface": "ether1"}),
    );
    assert_eq!(p["commands"].as_array().unwrap().len(), 256);
    // Outside the network, backwards, other family.
    for to in ["10.31.0.1", "10.29.255.255", "2001:db8::1"] {
        let p = preview(
            &mut s,
            json!({"address": "10.30.0.1/16", "to": to, "interface": "ether1"}),
        );
        assert_eq!(levels(&p, "series"), ["error"], "{to}");
    }
}

#[test]
fn overlap_with_another_interface_is_refused_but_not_across_vrfs() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.0.1/16", "interface": "ether2"}),
    );
    let p = preview(
        &mut s,
        json!({"address": "10.0.5.1/24", "interface": "ether1", "arp": false}),
    );
    assert_eq!(levels(&p, "overlap"), ["error"]);
    assert!(p["checks"].to_string().contains("10.0.0.1/16 on ether2"));
    assert_eq!(p["commands"], json!([]));
    // The same IP elsewhere.
    let p = preview(
        &mut s,
        json!({"address": "10.0.0.1/24", "interface": "ether3", "arp": false}),
    );
    assert_eq!(levels(&p, "duplicate"), ["error"]);
    // A secondary address on the same interface is fine.
    let p = preview(
        &mut s,
        json!({"address": "10.0.9.1/24", "interface": "ether2", "arp": false}),
    );
    assert_eq!(levels(&p, "overlap"), ["ok"]);
    // Another VRF has its own table.
    ok(
        &mut s,
        "ip.vrf.add",
        json!({"name": "cust", "interfaces": "ether3"}),
    );
    let p = preview(
        &mut s,
        json!({"address": "10.0.5.1/24", "interface": "ether3", "arp": false}),
    );
    assert_eq!(levels(&p, "overlap"), ["ok"], "{p}");
    assert_eq!(row(&mut s, "10.0.0.1/16")["vrf"], "main");
}

#[test]
fn preview_of_an_edit_sends_only_what_changed() {
    let mut s = Session::virtual_lab();
    let id = ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.0.1/24", "interface": "ether1", "comment": "a"}),
    )["id"]
        .clone();
    let p = preview(
        &mut s,
        json!({"id": id, "address": "10.0.0.1/24", "comment": "a"}),
    );
    assert_eq!(p["commands"], json!([]));
    assert_eq!(levels(&p, "change"), ["info"]);
    assert_eq!(
        levels(&p, "duplicate"),
        Vec::<String>::new(),
        "not a clash with itself"
    );
    let p = preview(
        &mut s,
        json!({"id": id, "address": "10.0.0.2/24", "comment": "b"}),
    );
    assert_eq!(
        p["commands"],
        json!([{"command": "ip.address.set", "params": {"id": id, "address": "10.0.0.2/24", "comment": "b"}}])
    );
    let p = preview(
        &mut s,
        json!({"id": id, "address": "10.0.0.1/24", "to": "10.0.0.3"}),
    );
    assert_eq!(levels(&p, "series"), ["error"]);
}

#[test]
fn the_arp_check_runs_in_the_background() {
    let mut s = Session::virtual_lab();
    s.tick(1_000);
    // The lab router answers for 100.64.1.1 behind ether1.
    let p = preview(
        &mut s,
        json!({"address": "100.64.1.1/24", "interface": "ether1"}),
    );
    let first = levels(&p, "arp");
    assert!(first == ["pending"] || first == ["warning"], "{p}");
    s.tick(1_003);
    let p = preview(
        &mut s,
        json!({"address": "100.64.1.1/24", "interface": "ether1"}),
    );
    assert_eq!(levels(&p, "arp"), ["warning"], "{p}");
    assert!(p["checks"].to_string().contains("in use on ether1"));
    assert_eq!(
        p["commands"].as_array().unwrap().len(),
        1,
        "a warning does not block"
    );
    // A free address: pending, then ok once the wait is over.
    let p = preview(
        &mut s,
        json!({"address": "100.64.1.77/24", "interface": "ether1"}),
    );
    assert_eq!(levels(&p, "arp"), ["pending"]);
    s.tick(1_006);
    let p = preview(
        &mut s,
        json!({"address": "100.64.1.77/24", "interface": "ether1"}),
    );
    assert_eq!(levels(&p, "arp"), ["ok"], "{p}");
    // Switched off.
    let p = preview(
        &mut s,
        json!({"address": "100.64.1.78/24", "interface": "ether1", "arp": false}),
    );
    assert_eq!(levels(&p, "arp"), Vec::<String>::new());
}

/// An operator connected from the LAN to 192.168.88.1.
fn from_lan() -> Caller {
    Caller::new(9, "tls 192.168.88.10:50123".to_owned())
        .with_principal(Principal::Local)
        .with_link(Link {
            peer: "192.168.88.10:50123".parse().unwrap(),
            local: "192.168.88.1:8729".parse().unwrap(),
        })
}

#[test]
fn the_access_address_asks_before_it_goes() {
    let mut s = Session::virtual_lab();
    let lan = ok(
        &mut s,
        "ip.address.add",
        json!({"address": "192.168.88.1/24", "interface": "ether2"}),
    )["id"]
        .clone();
    let other = ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.0.1/24", "interface": "ether1"}),
    )["id"]
        .clone();
    let who = from_lan();
    let list = s.execute_as(&who, "ip.address.list", &Value::Null).unwrap();
    let lan_row = list
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == lan)
        .unwrap()
        .clone();
    assert!(
        lan_row["access"]
            .as_str()
            .unwrap()
            .contains("connects to this address"),
        "{lan_row}"
    );
    let other_row = list
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == other)
        .unwrap()
        .clone();
    assert!(other_row["access"].is_null());

    // Disable and remove are refused as a lockout; force goes through.
    for (id, p) in [
        ("ip.address.set", json!({"id": lan, "disabled": true})),
        ("ip.address.remove", json!({"id": lan})),
    ] {
        match s.execute_as(&who, id, &p) {
            Err(EngineError::Lockout(m)) => assert!(m.contains("192.168.88.1"), "{m}"),
            other => panic!("{id}: {other:?}"),
        }
    }
    ok(
        &mut s,
        "ip.address.set",
        json!({"id": other, "disabled": true}),
    );
    // The preview of the edit says so before it is sent.
    let p = s
        .execute_as(
            &who,
            "ip.address.check",
            &json!({"id": lan, "disabled": true}),
        )
        .unwrap();
    assert!(p["risk"].as_str().unwrap().contains("192.168.88.1"), "{p}");
    let p = s
        .execute_as(
            &who,
            "ip.address.check",
            &json!({"id": lan, "comment": "mgmt"}),
        )
        .unwrap();
    assert!(p["risk"].is_null(), "a comment cuts nothing");
    s.execute_as(
        &who,
        "ip.address.set",
        &json!({"id": lan, "disabled": true, "force": true}),
    )
    .unwrap();
    assert_eq!(row(&mut s, "192.168.88.1/24")["state"], "disabled");
}

#[test]
fn the_network_the_session_arrives_through_is_protected_too() {
    // Management on a loopback /32, the operator on the LAN network.
    let mut s = Session::virtual_lab();
    ok(&mut s, "interface.loopback.add", json!({"name": "lo0"}));
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.255.0.1/32", "interface": "lo0"}),
    );
    let lan = ok(
        &mut s,
        "ip.address.add",
        json!({"address": "192.168.88.1/24", "interface": "ether2"}),
    )["id"]
        .clone();
    let who = Caller::new(9, "tls".to_owned())
        .with_principal(Principal::Local)
        .with_link(Link {
            peer: "192.168.88.10:50123".parse().unwrap(),
            local: "10.255.0.1:8729".parse().unwrap(),
        });
    let list = s.execute_as(&who, "ip.address.list", &Value::Null).unwrap();
    let r = list
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == lan)
        .unwrap()
        .clone();
    assert!(
        r["access"].as_str().unwrap().contains("arrives through"),
        "{r}"
    );
    match s.execute_as(&who, "ip.address.remove", &json!({"id": lan})) {
        Err(EngineError::Lockout(m)) => assert!(m.contains("way back"), "{m}"),
        other => panic!("{other:?}"),
    }
}
