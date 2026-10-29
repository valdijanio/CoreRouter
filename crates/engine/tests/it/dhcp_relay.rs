//! G4.2b — `/ip dhcp-relay`, option 82 in the server, and the lease
//! history, in the lab: a relay on ether3 passes the lab hosts' requests
//! to the router's own server (in memory), which sees the port in option
//! 82, matches a static lease by remote id, and records who had what.
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

/// The relay's clients are on ether3 (10.20.0.0/24); the server answers
/// requests relayed from 10.20.0.1.
fn relayed() -> Session {
    let mut s = Session::virtual_lab();
    for (id, p) in [
        (
            "ip.address.add",
            json!({"address": "192.168.88.1/24", "interface": "ether2"}),
        ),
        (
            "ip.address.add",
            json!({"address": "10.20.0.1/24", "interface": "ether3"}),
        ),
        (
            "ip.pool.add",
            json!({"name": "far", "ranges": "10.20.0.10-10.20.0.50"}),
        ),
        (
            "ip.dhcp-server.add",
            json!({"name": "branch", "interface": "ether2", "address_pool": "far", "relay": "10.20.0.1"}),
        ),
        (
            "ip.dhcp-server.network.add",
            json!({"address": "10.20.0.0/24", "gateway": "10.20.0.1"}),
        ),
        (
            "ip.dhcp-relay.add",
            json!({"interface": "ether3", "dhcp_server": "192.168.88.1", "add_relay_info": true}),
        ),
    ] {
        ok(&mut s, id, p);
    }
    s
}

fn leases(s: &mut Session) -> Vec<Value> {
    ok(s, "ip.dhcp-server.lease.print", json!({"status": "bound"}))
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn a_relay_brings_its_clients_to_the_server_with_option_82() {
    let mut s = relayed();
    // The laptop of ether3 (lab MAC 02:1A:B0:03:00:01) has a fixed address
    // by its remote id (the relay puts the client MAC there).
    ok(
        &mut s,
        "ip.dhcp-server.lease.add",
        json!({"address": "10.20.0.99", "agent_remote_id": "0x021ab0030001", "server": "branch"}),
    );
    run(&mut s, 0, 5);
    let rows = leases(&mut s);
    assert_eq!(rows.len(), 4, "{rows:#?}");
    for r in &rows {
        assert_eq!(r["agent_circuit_id"], "ether3", "{r}");
        assert!(r["address"].as_str().unwrap().starts_with("10.20.0."));
        assert_eq!(r["server"].as_str().unwrap_or("branch"), "branch");
    }
    let laptop = rows
        .iter()
        .find(|r| r["mac_address"] == "02:1A:B0:03:00:01")
        .unwrap();
    assert_eq!(laptop["address"], "10.20.0.99", "{laptop}");
    let relay = ok(&mut s, "ip.dhcp-relay.print", json!({}));
    assert_eq!(relay[0]["status"], "running", "{relay}");
    assert!(relay[0]["requests"].as_u64().unwrap() >= 8);
    assert!(relay[0]["replies"].as_u64().unwrap() >= 8);
    assert_eq!(relay[0]["giaddr"], "10.20.0.1");
}

#[test]
fn the_history_says_who_had_an_address() {
    let mut s = relayed();
    let ms = run(&mut s, 0, 5);
    let first = leases(&mut s)
        .into_iter()
        .find(|r| r["mac_address"] == "02:1A:B0:03:00:02")
        .unwrap();
    let ip = first["address"].as_str().unwrap().to_owned();
    ok(
        &mut s,
        "ip.dhcp-server.lease.release",
        json!({"address": ip}),
    );
    run(&mut s, ms, 2);
    let h = ok(
        &mut s,
        "ip.dhcp-server.history.print",
        json!({"address": ip}),
    );
    let rows = h["rows"].as_array().unwrap();
    assert!(!rows.is_empty(), "{h}");
    let closed = rows
        .iter()
        .find(|r| r["open"] == false)
        .unwrap_or_else(|| panic!("{h}"));
    assert_eq!(closed["mac"], "02:1A:B0:03:00:02");
    assert_eq!(closed["circuit_id"], "ether3");
    let at = closed["start_unix"].as_u64().unwrap();
    let who = ok(
        &mut s,
        "ip.dhcp-server.history.print",
        json!({"address": ip, "at": at}),
    );
    assert_eq!(who["rows"][0]["mac"], "02:1A:B0:03:00:02");
    let csv = ok(
        &mut s,
        "ip.dhcp-server.history.export",
        json!({"text": "ether3"}),
    );
    let text = csv["csv"].as_str().unwrap();
    assert!(text.starts_with("address,mac,client_id"), "{text}");
    assert!(text.contains("ether3") && text.contains("02:1A:B0:03:00:02"));
    assert!(
        err(
            &mut s,
            "ip.dhcp-server.history.print",
            json!({"at": "yesterday"})
        )
        .contains("a time")
    );
    // Retention 0: no history at all.
    ok(
        &mut s,
        "ip.dhcp-server.config.set",
        json!({"history_retention": 0}),
    );
    run(&mut s, ms + 2_000, 1);
    assert_eq!(
        ok(&mut s, "ip.dhcp-server.config.print", json!({}))["history_entries"],
        0
    );
    ok(
        &mut s,
        "ip.dhcp-server.config.set",
        json!({"history_retention": "52w"}),
    );
    assert_eq!(
        ok(&mut s, "ip.dhcp-server.config.print", json!({}))["history_retention_secs"],
        52 * 7 * 86_400
    );
}

#[test]
fn relay_mistakes_are_refused() {
    let mut s = relayed();
    let before = s.store().running().clone();
    assert!(
        err(
            &mut s,
            "ip.dhcp-relay.add",
            json!({"interface": "ether3", "dhcp_server": "10.0.0.2"})
        )
        .contains("another relay")
    );
    assert!(
        err(
            &mut s,
            "ip.dhcp-relay.add",
            json!({"interface": "nope0", "dhcp_server": "10.0.0.2"})
        )
        .contains("interface")
    );
    assert!(
        err(&mut s, "ip.dhcp-relay.add", json!({"interface": "ether4"})).contains("dhcp_server")
    );
    ok(
        &mut s,
        "ip.pool.add",
        json!({"name": "lan", "ranges": "192.168.88.10-192.168.88.20"}),
    );
    ok(
        &mut s,
        "ip.dhcp-server.add",
        json!({"interface": "ether4", "address_pool": "lan"}),
    );
    let e = err(
        &mut s,
        "ip.dhcp-relay.add",
        json!({"interface": "ether4", "dhcp_server": "10.0.0.2"}),
    );
    assert!(e.contains("already answers"), "{e}");
    assert!(
        err(
            &mut s,
            "ip.dhcp-relay.set",
            json!({"id": "relay1", "local_address": "10.9.9.9"})
        )
        .contains("not one of the router")
    );
    assert_ne!(s.store().running(), &before, "the pool and server went in");
    assert_eq!(
        s.store().running().ip.dhcp_relays,
        before.ip.dhcp_relays,
        "relays unchanged"
    );
    let r = ok(&mut s, "ip.dhcp-relay.remove", json!({"id": "relay1"}));
    assert_eq!(r["name"], "relay1");
}
