//! G0.25 — `ip.identity.lookup`: the subscriber's name by the sources of the
//! config and the DHCP server, in order; the "+N" count; a public address
//! and port through CGNAT; `at` through the lease history; the index cache;
//! hostile names; validation.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::identity::IdentityCache;
use corerouter_engine::{EngineError, Session};
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn bad(s: &mut Session, p: Value) -> (String, String) {
    match s.execute("ip.identity.lookup", &p) {
        Err(EngineError::BadParam { param, reason }) => (param, reason),
        other => panic!("{p}: expected a parameter error, got {other:?}"),
    }
}

fn who(s: &mut Session, p: Value) -> Vec<Value> {
    ok(s, "ip.identity.lookup", p).as_array().unwrap().clone()
}

fn sources(r: &Value) -> Vec<String> {
    r["all"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["source"].as_str().unwrap().to_owned())
        .collect()
}

/// Maria's /30 on ether3, named in four places.
fn maria(s: &mut Session) {
    ok(
        s,
        "ip.address.add",
        json!({"address": "10.9.0.1/30", "interface": "ether3", "comment": "Link Maria"}),
    );
    ok(
        s,
        "ip.dhcp-server.lease.add",
        json!({"address": "10.9.0.2", "mac_address": "02:00:00:00:00:02", "comment": "Maria Souza"}),
    );
    ok(
        s,
        "ip.firewall.address-list.add",
        json!({"list": "clientes", "address": "10.9.0.2", "comment": "maria souza"}),
    );
    ok(s, "ip.dns.zone.add", json!({"name": "0.9.10.in-addr.arpa"}));
    ok(
        s,
        "ip.dns.zone.record.add",
        json!({"zone": "0.9.10.in-addr.arpa", "name": "2", "type": "PTR", "target": "maria.isp.example"}),
    );
}

#[test]
fn sources_in_order_and_the_others_counted() {
    let mut s = Session::virtual_lab();
    maria(&mut s);
    let r = &who(&mut s, json!({"addresses": ["10.9.0.2"]}))[0];
    assert_eq!(r["primary"]["source"], "dhcp-static", "{r}");
    assert_eq!(r["primary"]["name"], "Maria Souza");
    assert_eq!(r["primary"]["ref"]["window"], "dhcp-server");
    assert_eq!(r["primary"]["ref"]["id"], "10.9.0.2");
    assert_eq!(
        sources(r),
        ["dhcp-static", "address", "address-list", "dns-ptr"]
    );
    // The list's "maria souza" is the same name: +2 (the link, the PTR).
    assert_eq!(r["more"], 2, "{r}");
    assert_eq!(r["all"][2]["detail"], "clientes");
    assert_eq!(r["all"][3]["ref"]["zone"], "0.9.10.in-addr.arpa");

    // Another order, and only those sources.
    let r = &who(
        &mut s,
        json!({"addresses": "10.9.0.2", "sources": ["dns-ptr", "address"]}),
    )[0];
    assert_eq!(r["primary"]["name"], "maria.isp.example");
    assert_eq!(sources(r), ["dns-ptr", "address"]);
    assert_eq!(r["more"], 1);

    // The router's side of the /30 is named by the link only.
    let r = &who(&mut s, json!({"addresses": ["10.9.0.1"]}))[0];
    assert_eq!(r["primary"]["source"], "address");
    assert_eq!(r["more"], 0);

    // A disabled item names nobody.
    let id = r["primary"]["ref"]["id"].as_str().unwrap().to_owned();
    ok(&mut s, "ip.address.remove", json!({"id": id}));
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.9.0.1/30", "interface": "ether3", "comment": "Link Maria", "disabled": true}),
    );
    let r = &who(&mut s, json!({"addresses": ["10.9.0.1"]}))[0];
    assert!(r.get("primary").is_none(), "{r}");
}

#[test]
fn a_lan_comment_does_not_name_every_host() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "192.168.88.1/24", "interface": "ether2", "comment": "LAN escritório"}),
    );
    ok(
        &mut s,
        "ip.firewall.address-list.add",
        json!({"list": "bloco", "address": "100.64.0.0/16", "comment": "bloco CGNAT"}),
    );
    let r = who(
        &mut s,
        json!({"addresses": ["192.168.88.77", "192.168.88.1", "100.64.3.3", "2001:db8::1", "lixo"]}),
    );
    assert!(r[0].get("primary").is_none(), "{}", r[0]);
    assert_eq!(r[1]["primary"]["name"], "LAN escritório");
    assert!(r[2].get("primary").is_none(), "{}", r[2]);
    assert!(r[3].get("primary").is_none());
    assert_eq!(r[4]["error"], "not an address");
    assert_eq!(r[4]["address"], "lixo");
}

#[test]
fn hostile_names_are_cleaned_and_cut() {
    let mut s = Session::virtual_lab();
    let evil = format!("Ana\u{202E} {}", "x".repeat(200));
    ok(
        &mut s,
        "ip.dhcp-server.lease.add",
        json!({"address": "10.9.0.6", "mac_address": "02:00:00:00:00:06", "comment": evil}),
    );
    let r = &who(&mut s, json!({"addresses": ["10.9.0.6"]}))[0];
    let name = r["primary"]["name"].as_str().unwrap();
    assert!(name.starts_with("Ana x"), "{name}");
    assert!(!name.contains('\u{202E}'));
    assert_eq!(name.chars().count(), 65, "64 and the ellipsis");
}

#[test]
fn the_index_is_built_once_per_change() {
    let mut s = Session::virtual_lab();
    maria(&mut s);
    let many: Vec<String> = (0..2000)
        .map(|i| format!("10.9.{}.{}", i / 250, i % 250))
        .collect();
    let r = who(&mut s, json!({"addresses": many}));
    assert_eq!(r.len(), 2000);
    let builds = s.ext::<IdentityCache>().unwrap().builds();
    who(&mut s, json!({"addresses": ["10.9.0.2"]}));
    assert_eq!(s.ext::<IdentityCache>().unwrap().builds(), builds, "reused");
    ok(
        &mut s,
        "ip.firewall.address-list.add",
        json!({"list": "clientes", "address": "10.9.0.10", "comment": "Novo"}),
    );
    let r = &who(&mut s, json!({"addresses": ["10.9.0.10"]}))[0];
    assert_eq!(r["primary"]["name"], "Novo");
    assert_eq!(s.ext::<IdentityCache>().unwrap().builds(), builds + 1);
}

#[test]
fn a_public_address_and_port_go_through_cgnat() {
    let mut s = Session::virtual_lab();
    s.tick(1_780_000_000);
    ok(
        &mut s,
        "ip.firewall.cgnat.pool.add",
        json!({"name": "cgnat1", "inside": "100.64.0.0/22", "outside": "203.0.113.0/28"}),
    );
    ok(
        &mut s,
        "ip.dhcp-server.lease.add",
        json!({"address": "100.64.0.65", "mac_address": "02:00:00:00:00:65", "comment": "Pedro"}),
    );
    // 100.64.0.65 is 203.0.113.1 ports 2024–3023 (tests/cgnat.rs).
    let r = who(
        &mut s,
        json!({"addresses": ["203.0.113.1:2500", "203.0.113.1:80", "100.64.0.65"]}),
    );
    assert_eq!(r[0]["cgnat"]["subscriber"], "100.64.0.65", "{}", r[0]);
    assert_eq!(r[0]["cgnat"]["via"], "cgnat1");
    assert_eq!(r[0]["ip"], "100.64.0.65");
    assert_eq!(r[0]["primary"]["name"], "Pedro");
    // A port nobody had: named as itself, and why.
    assert_eq!(r[1]["ip"], "203.0.113.1");
    assert!(r[1].get("cgnat_error").is_some(), "{}", r[1]);
    assert!(r[1].get("primary").is_none());
    assert_eq!(r[2]["primary"]["name"], "Pedro");
}

/// A LAN with the lab hosts asking for leases.
fn lan(s: &mut Session) {
    ok(
        s,
        "ip.address.add",
        json!({"address": "192.168.88.1/24", "interface": "ether2"}),
    );
    ok(
        s,
        "ip.pool.add",
        json!({"name": "lan", "ranges": "192.168.88.10-192.168.88.50"}),
    );
    ok(
        s,
        "ip.dhcp-server.add",
        json!({"interface": "ether2", "address_pool": "lan", "lease_time": "10m"}),
    );
    ok(
        s,
        "ip.dhcp-server.network.add",
        json!({"address": "192.168.88.0/24", "gateway": "192.168.88.1"}),
    );
}

fn run(s: &mut Session, from_ms: u64, secs: u64) -> u64 {
    let mut ms = from_ms;
    for _ in 0..secs * 4 {
        ms += 250;
        s.tick(1_700_000_000 + ms / 1000);
        s.dhcp_service(ms);
    }
    ms
}

#[test]
fn host_names_now_and_at_a_past_time() {
    let mut s = Session::virtual_lab();
    lan(&mut s);
    let ms = run(&mut s, 0, 5);
    let leases = ok(
        &mut s,
        "ip.dhcp-server.lease.print",
        json!({"status": "bound"}),
    );
    let laptop = leases
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["host_name"] == "lab-laptop")
        .unwrap()
        .clone();
    let ip = laptop["address"].as_str().unwrap().to_owned();
    let r = &who(&mut s, json!({"addresses": [ip]}))[0];
    assert_eq!(r["primary"]["source"], "dhcp-dynamic", "{r}");
    assert_eq!(r["primary"]["name"], "lab-laptop");
    assert_eq!(r["all"][0]["detail"], laptop["mac_address"]);
    let bound_at = 1_700_000_002;

    // Released: nobody holds it now, but the history says who did.
    ok(
        &mut s,
        "ip.dhcp-server.lease.release",
        json!({"address": ip}),
    );
    run(&mut s, ms, 2);
    let now = &who(&mut s, json!({"addresses": [ip]}))[0];
    assert!(now.get("primary").is_none(), "{now}");
    let then = &who(&mut s, json!({"addresses": [ip], "at": bound_at}))[0];
    assert_eq!(then["primary"]["name"], "lab-laptop", "{then}");
    // Before any lease: nobody.
    let before = &who(&mut s, json!({"addresses": [ip], "at": 1_600_000_000}))[0];
    assert!(before.get("primary").is_none(), "{before}");

    // A static lease for another client names the address only when that
    // client held it: not at `bound_at`, when the laptop did.
    ok(
        &mut s,
        "ip.dhcp-server.lease.add",
        json!({"address": ip, "mac_address": "02:00:00:00:99:99", "comment": "Outro"}),
    );
    let then = &who(&mut s, json!({"addresses": [ip], "at": bound_at}))[0];
    assert_eq!(sources(then), ["dhcp-dynamic"], "{then}");
    let now = &who(&mut s, json!({"addresses": [ip]}))[0];
    assert_eq!(now["primary"]["name"], "Outro");

    // Many addresses at once read the history in one pass.
    let mut many: Vec<String> = (10..=50).map(|i| format!("192.168.88.{i}")).collect();
    many.push(ip.clone());
    let all = who(&mut s, json!({"addresses": many, "at": bound_at}));
    let named = all.iter().filter(|r| r.get("primary").is_some()).count();
    assert!(named >= 4, "the lab hosts: {all:#?}");
}

#[test]
fn mistakes_are_refused() {
    let mut s = Session::virtual_lab();
    let (p, _) = bad(&mut s, json!({}));
    assert_eq!(p, "addresses");
    let (p, _) = bad(&mut s, json!({"addresses": []}));
    assert_eq!(p, "addresses");
    let too_many: Vec<String> = (0..5000)
        .map(|i| format!("10.0.{}.{}", i / 250, i % 250))
        .collect();
    let (p, why) = bad(&mut s, json!({"addresses": too_many}));
    assert_eq!(
        (p.as_str(), why.as_str()),
        ("addresses", "at most 4096 items")
    );
    let (p, why) = bad(
        &mut s,
        json!({"addresses": "10.0.0.1", "sources": ["radius"]}),
    );
    assert_eq!(p, "sources");
    assert!(why.contains("dhcp-static"), "{why}");
    let (p, _) = bad(&mut s, json!({"addresses": "10.0.0.1", "at": "ontem"}));
    assert_eq!(p, "at");
}
