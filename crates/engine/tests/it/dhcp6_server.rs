//! G4.2c — `/ipv6 dhcp-server`, `/ipv6 pool` and `/ipv6 dhcp-relay` in the
//! lab: the lab's CPEs get an address and a delegated prefix, the router
//! routes each prefix to its CPE (a dynamic route), a relay brings another
//! port's CPEs to the router's own server, and mistakes are refused.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn err(s: &mut Session, id: &str, p: Value) -> String {
    s.execute(id, &p).unwrap_err().to_string()
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

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    for (id, p) in [
        (
            "ip.address.add",
            json!({"address": "2001:db8:1::1/64", "interface": "ether2"}),
        ),
        (
            "ipv6.pool.add",
            json!({"name": "addrs", "prefix": "2001:db8:1::/64", "prefix_length": 128}),
        ),
        (
            "ipv6.pool.add",
            json!({"name": "cpe", "prefix": "2001:db8:100::/48", "prefix_length": 56}),
        ),
        (
            "ipv6.dhcp-server.add",
            json!({"interface": "ether2", "address_pool": "addrs", "prefix_pool": "cpe", "dns_server": "2001:db8:1::1"}),
        ),
    ] {
        ok(&mut s, id, p);
    }
    s
}

fn bindings(s: &mut Session) -> Vec<Value> {
    ok(s, "ipv6.dhcp-server.binding.print", json!({}))
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn cpes_get_an_address_a_prefix_and_a_route() {
    let mut s = lab();
    run(&mut s, 0, 5);
    let rows = bindings(&mut s);
    let bound: Vec<&Value> = rows.iter().filter(|r| r["status"] == "bound").collect();
    assert_eq!(bound.len(), 4, "{rows:#?}");
    let prefix = bound.iter().find(|r| r["type"] == "prefix").unwrap();
    let p = prefix["address"].as_str().unwrap().to_owned();
    assert!(p.starts_with("2001:db8:100:") && p.ends_with("/56"), "{p}");
    assert!(prefix["via"].as_str().unwrap().starts_with("fe80::"));
    // The route to the delegated prefix, dynamic (flag D).
    let routes = ok(&mut s, "ip.route.list", json!({}));
    let r = routes
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["dst_address"] == p)
        .unwrap_or_else(|| panic!("{routes:#?}"));
    assert!(r["gateway"].as_str().unwrap().contains("ether2"), "{r}");
    let servers = ok(&mut s, "ipv6.dhcp-server.print", json!({}));
    assert_eq!(servers[0]["status"], "running", "{servers}");
    assert_eq!(servers[0]["bindings"], 4);
    let pools = ok(&mut s, "ipv6.pool.list", json!({}));
    let cpe = pools
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "cpe")
        .unwrap();
    assert_eq!(cpe["size"], 256);
    assert_eq!(cpe["leases"], 2);

    // Release one prefix: its route goes.
    ok(&mut s, "ipv6.dhcp-server.binding.remove", json!({"id": p}));
    let routes = ok(&mut s, "ip.route.list", json!({}));
    assert!(
        !routes
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["dst_address"] == p)
    );
}

#[test]
fn a_relay_brings_another_ports_cpes() {
    let mut s = lab();
    for (id, p) in [
        (
            "ip.address.add",
            json!({"address": "2001:db8:3::1/64", "interface": "ether3"}),
        ),
        (
            "ipv6.pool.add",
            json!({"name": "addrs3", "prefix": "2001:db8:3::/64", "prefix_length": 128}),
        ),
        (
            "ipv6.dhcp-server.add",
            json!({"name": "far", "interface": "ether2", "address_pool": "addrs3", "relay": "2001:db8:3::1"}),
        ),
        (
            "ipv6.dhcp-relay.add",
            json!({"interface": "ether3", "dhcp_server": "2001:db8:1::1"}),
        ),
    ] {
        ok(&mut s, id, p);
    }
    run(&mut s, 0, 5);
    let rows = bindings(&mut s);
    let far: Vec<&Value> = rows
        .iter()
        .filter(|r| r["server"] == "far" && r["status"] == "bound")
        .collect();
    assert_eq!(far.len(), 2, "{rows:#?}");
    assert!(
        far[0]["address"]
            .as_str()
            .unwrap()
            .starts_with("2001:db8:3:")
    );
    let relay = ok(&mut s, "ipv6.dhcp-relay.print", json!({}));
    assert!(relay[0]["requests"].as_u64().unwrap() >= 2, "{relay}");
    assert!(relay[0]["replies"].as_u64().unwrap() >= 2, "{relay}");
}

#[test]
fn mistakes_are_refused() {
    let mut s = lab();
    let before = s.store().running().clone();
    assert!(
        err(
            &mut s,
            "ipv6.pool.add",
            json!({"name": "x", "prefix": "2001:db8:100:100::/56", "prefix_length": 60})
        )
        .contains("overlaps")
    );
    assert!(
        err(
            &mut s,
            "ipv6.pool.add",
            json!({"name": "big", "prefix": "2001:db9::/16", "prefix_length": 64})
        )
        .contains("2^20")
    );
    assert!(
        err(
            &mut s,
            "ipv6.dhcp-server.set",
            json!({"id": "dhcp6-1", "address_pool": "cpe"})
        )
        .contains("prefix_length 128")
    );
    assert!(
        err(
            &mut s,
            "ipv6.dhcp-server.add",
            json!({"interface": "ether2"})
        )
        .contains("already serves")
    );
    assert!(
        err(
            &mut s,
            "ipv6.dhcp-server.binding.add",
            json!({"duid": "0x01"})
        )
        .contains("DUID")
    );
    assert!(err(&mut s, "ipv6.pool.remove", json!({"id": "cpe"})).contains("in use"));
    assert_eq!(s.store().running(), &before);
    let r = ok(
        &mut s,
        "ipv6.dhcp-server.binding.add",
        json!({"duid": "0x000300010200000000aa", "address": "2001:db8:1::aa"}),
    );
    assert!(r["id"].as_str().unwrap().starts_with('*'));
    let rows = bindings(&mut s);
    assert!(
        rows.iter()
            .any(|r| r["status"] == "waiting" && r["address"] == "2001:db8:1::aa")
    );
}
