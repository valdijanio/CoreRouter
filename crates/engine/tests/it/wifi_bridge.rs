//! G1.30m — Wi-Fi station-bridge and peers: the lab's radio as a
//! four-address client (in a bridge), and as an access point that takes a
//! registered peer, whose link is an interface of its own; success,
//! validation and rollback.
// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
use corerouter_hal::VirtualHal;
use corerouter_hal::lab_wifi::{LAB_PASSPHRASE, LabWifi};
use corerouter_hal::wifi::{FourAddr, JoinSecurity};
use corerouter_model::IfName;
use serde_json::{Value, json};

fn n(s: &str) -> IfName {
    s.parse().unwrap()
}

fn run(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn fails(s: &mut Session, id: &str, p: Value, needle: &str) {
    let before = s.store().candidate().clone();
    let e = match s.execute(id, &p) {
        Ok(v) => panic!("{id} {p} should fail, got {v}"),
        Err(e) => e.to_string(),
    };
    assert!(e.contains(needle), "{id} {p}: '{e}' lacks '{needle}'");
    assert_eq!(
        s.store().candidate(),
        &before,
        "{id} {p} left changes behind"
    );
}

fn lab() -> (Session, LabWifi, u64) {
    let hal = VirtualHal::new(8).with_wifi(1);
    let air = hal.wifi();
    let mut s = Session::new(Box::new(hal));
    for t in 0..4 {
        s.tick(1_000 + t);
    }
    run(
        &mut s,
        "interface.wifi.country.set",
        json!({"country": "BR"}),
    );
    run(&mut s, "interface.bridge.add", json!({"name": "bridge1"}));
    (s, air, 10_000)
}

fn spin(s: &mut Session, from_ms: u64, n: u64) -> u64 {
    let mut ms = from_ms;
    for _ in 0..n {
        ms += 1_000;
        s.wifi_service(ms);
        s.tick(ms / 1_000);
    }
    ms
}

#[test]
fn a_station_bridge_joins_with_four_addresses_and_is_a_bridge_port() {
    let (mut s, air, ms) = lab();
    let r = run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "mode": "station-bridge", "ssid": "CoreRouter-Lab",
               "passphrase": LAB_PASSPHRASE, "disabled": false}),
    );
    assert!(
        r["warnings"].to_string().contains("put it in a bridge"),
        "{r}"
    );
    run(
        &mut s,
        "interface.bridge.port.add",
        json!({"bridge": "bridge1", "interface": "wifi1"}),
    );
    spin(&mut s, ms, 6);
    let w = air.wanted(&n("wifi1")).unwrap();
    assert_eq!(w.four_addr, Some(FourAddr::MultiAp));
    assert_eq!(w.bridge.as_deref(), Some("bridge1"));
    // `auto` is WPA3 on a backhaul.
    assert_eq!(w.security, JoinSecurity::Wpa3);
    let list = run(&mut s, "interface.wifi.list", json!({}));
    assert_eq!(list[0]["mode"], "station-bridge", "{list}");
    // WDS, for OpenWrt.
    let r = run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "bridge_protocol": "wds"}),
    );
    assert!(r["warnings"].to_string().contains("option wds 1"), "{r}");
    spin(&mut s, ms + 10_000, 3);
    assert_eq!(
        air.wanted(&n("wifi1")).unwrap().four_addr,
        Some(FourAddr::Wds)
    );
    // Back to a plain station while a bridge port: refused.
    fails(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "mode": "station"}),
        "take it out",
    );
}

#[test]
fn a_backhaul_is_wpa3_only() {
    let (mut s, _air, _) = lab();
    for sec in ["wpa2", "open"] {
        fails(
            &mut s,
            "interface.wifi.set",
            json!({"name": "wifi1", "mode": "station-bridge", "ssid": "x", "security": sec,
                   "passphrase": if sec == "open" { "" } else { "senha-boa-123" }}),
            "WPA3",
        );
        fails(
            &mut s,
            "interface.wifi.set",
            json!({"name": "wifi1", "mode": "ap", "ssid": "x", "security": sec,
                   "station_bridge": "yes",
                   "passphrase": if sec == "open" { "" } else { "senha-boa-123" }}),
            "WPA3",
        );
    }
    fails(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "bridge_protocol": "mesh"}),
        "multi-ap or wds",
    );
    fails(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "station_bridge": "talvez"}),
        "no, yes or only",
    );
}

#[test]
fn an_access_point_takes_its_registered_peer_as_an_interface() {
    let (mut s, air, ms) = lab();
    // No access point yet: refused.
    fails(
        &mut s,
        "interface.wifi.peer.add",
        json!({"radio": "wifi1", "name": "peer1", "mac_address": "02:00:00:00:b0:01"}),
        "not an access point",
    );
    let r = run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "mode": "ap", "ssid": "Backhaul", "passphrase": "senha-do-backhaul",
               "station_bridge": "yes", "disabled": false}),
    );
    assert!(
        r["warnings"].to_string().contains("no peer registered"),
        "{r}"
    );
    run(
        &mut s,
        "interface.wifi.peer.add",
        json!({"radio": "wifi1", "name": "peer1", "mac_address": "02:00:00:00:b0:01",
               "comment": "torre"}),
    );
    fails(
        &mut s,
        "interface.wifi.peer.add",
        json!({"radio": "wifi1", "name": "peer2", "mac_address": "02:00:00:00:b0:01"}),
        "already",
    );
    fails(
        &mut s,
        "interface.wifi.peer.add",
        json!({"radio": "wifi1", "name": "ether1", "mac_address": "02:00:00:00:b0:02"}),
        "already",
    );
    run(
        &mut s,
        "interface.bridge.port.add",
        json!({"bridge": "bridge1", "interface": "wifi1"}),
    );
    run(
        &mut s,
        "interface.bridge.port.add",
        json!({"bridge": "bridge1", "interface": "peer1"}),
    );
    let ms = spin(&mut s, ms, 10);
    let told = air.ap_told(&n("wifi1")).unwrap();
    let b = told.backhaul.unwrap();
    assert!(!b.only);
    assert_eq!(
        (b.peers[0].mac.as_str(), b.peers[0].name.as_str()),
        ("02:00:00:00:b0:01", "peer1")
    );
    let peers = run(&mut s, "interface.wifi.peer.print", json!({}));
    assert_eq!(peers[0]["state"], "up", "{peers}");
    assert_eq!(peers[0]["bridge"], "bridge1");
    assert_eq!(peers[0]["signal"], -55);
    let table = run(&mut s, "interface.wifi.registration-table.print", json!({}));
    assert!(
        table
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["peer"] == "peer1"),
        "{table}"
    );
    // The peer's link is an interface that is there, of its own type.
    let ifs = run(&mut s, "interface.list", json!({}));
    let p = ifs
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "peer1")
        .cloned()
        .unwrap();
    assert_eq!(p["type"], "wifi-peer", "{p}");
    let h = run(&mut s, "interface.wifi.history", json!({"name": "wifi1"})).to_string();
    assert!(
        h.contains("peer peer1 (02:00:00:00:b0:01): four-address link up"),
        "{h}"
    );
    let _ = ms;
    // The access point back to a station with a peer on it: the commit says
    // what is wrong.
    run(&mut s, "config.mode.set", json!({"mode": "transactional"}));
    run(
        &mut s,
        "interface.bridge.port.remove",
        json!({"bridge": "bridge1", "interface": "wifi1"}),
    );
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "mode": "station"}),
    );
    let e = s
        .execute("config.commit", &json!({}))
        .unwrap_err()
        .to_string();
    assert!(e.contains("not an access point"), "{e}");
    run(&mut s, "config.discard", json!({}));
}

#[test]
fn a_peer_goes_and_rollback_brings_it_back() {
    let (mut s, _air, ms) = lab();
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "mode": "ap", "ssid": "Backhaul", "passphrase": "senha-do-backhaul",
               "station_bridge": "only", "disabled": false}),
    );
    run(
        &mut s,
        "interface.wifi.peer.add",
        json!({"radio": "wifi1", "name": "peer1", "mac_address": "02:00:00:00:b0:01"}),
    );
    let with = s.store().current_revision();
    spin(&mut s, ms, 6);
    // `only`: no plain clients, just the peer.
    let table = run(&mut s, "interface.wifi.registration-table.print", json!({}));
    assert_eq!(table.as_array().unwrap().len(), 1, "{table}");
    fails(
        &mut s,
        "interface.wifi.peer.remove",
        json!({"name": "ether1"}),
        "not a Wi-Fi peer",
    );
    run(
        &mut s,
        "interface.wifi.peer.remove",
        json!({"name": "peer1"}),
    );
    assert!(!s.store().running().interfaces.contains_key(&n("peer1")));
    run(&mut s, "config.rollback", json!({"revision": with}));
    if s.store().is_dirty() {
        run(&mut s, "config.commit", json!({}));
    }
    assert!(s.store().running().interfaces.contains_key(&n("peer1")));
}

#[test]
fn two_backhaul_links_in_one_bridge_are_a_loop() {
    let (mut s, _air, _) = lab();
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "mode": "ap", "ssid": "Backhaul", "passphrase": "senha-do-backhaul",
               "station_bridge": "yes"}),
    );
    for (name, mac) in [
        ("peer1", "02:00:00:00:b0:01"),
        ("peer2", "02:00:00:00:b0:02"),
    ] {
        run(
            &mut s,
            "interface.wifi.peer.add",
            json!({"radio": "wifi1", "name": name, "mac_address": mac}),
        );
    }
    let r = run(
        &mut s,
        "interface.bridge.port.add",
        json!({"bridge": "bridge1", "interface": "peer1"}),
    );
    assert_eq!(r["warnings"], json!([]));
    let r = run(
        &mut s,
        "interface.bridge.port.add",
        json!({"bridge": "bridge1", "interface": "peer2"}),
    );
    assert!(r["warnings"].to_string().contains("loop"), "{r}");
}
