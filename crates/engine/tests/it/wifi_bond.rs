//! G1.30m part 2 — bonding over Wi-Fi backhaul links: station-bridge
//! radios and peers' links as slaves, the warnings, the airtime per peer; success,
//! validation and rollback. (802.3ad and balance-tlb/alb are refused: the
//! kernel needs a slave's speed and duplex, which Wi-Fi does not report.)
// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
use corerouter_hal::VirtualHal;
use corerouter_hal::lab_wifi::{LAB_PASSPHRASE, LabWifi};
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

/// Two lab radios, the country set.
fn lab() -> (Session, LabWifi) {
    let hal = VirtualHal::new(8).with_wifi(2);
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
    (s, air)
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
fn station_bridges_are_slaves_in_any_mode_with_the_warnings() {
    let (mut s, _air) = lab();
    for r in ["wifi1", "wifi2"] {
        run(
            &mut s,
            "interface.wifi.set",
            json!({"name": r, "mode": "station-bridge", "ssid": "CoreRouter-Lab",
                   "passphrase": LAB_PASSPHRASE, "disabled": false}),
        );
    }
    // LACP needs the slaves' speed and duplex; Wi-Fi reports none.
    for mode in ["802.3ad", "balance-tlb", "balance-alb"] {
        fails(
            &mut s,
            "interface.bonding.add",
            json!({"name": "bond1", "slaves": ["wifi1", "wifi2"], "mode": mode}),
            "speed and duplex",
        );
    }
    let r = run(
        &mut s,
        "interface.bonding.add",
        json!({"name": "bond1", "slaves": ["wifi1", "wifi2"], "mode": "balance-xor"}),
    );
    assert!(r["warnings"].to_string().contains("MAC to register"), "{r}");
    fails(
        &mut s,
        "interface.bonding.set",
        json!({"name": "bond1", "mode": "802.3ad"}),
        "speed and duplex",
    );
    let r = run(
        &mut s,
        "interface.bonding.set",
        json!({"name": "bond1", "mode": "balance-rr"}),
    );
    assert!(r["warnings"].to_string().contains("out of order"), "{r}");
    let r = run(
        &mut s,
        "interface.bonding.set",
        json!({"name": "bond1", "mode": "active-backup", "primary": "wifi1"}),
    );
    assert!(!r["warnings"].to_string().contains("out of order"), "{r}");
    let list = run(&mut s, "interface.bonding.list", json!({}));
    assert_eq!(list[0]["slaves"], json!(["wifi1", "wifi2"]), "{list}");
    // A slave's radio cannot go back to a plain station (the commit says so).
    run(&mut s, "config.mode.set", json!({"mode": "transactional"}));
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "mode": "station"}),
    );
    let e = s
        .execute("config.commit", &json!({}))
        .unwrap_err()
        .to_string();
    assert!(e.contains("can be bond slaves"), "{e}");
    run(&mut s, "config.discard", json!({}));
}

#[test]
fn a_plain_station_and_an_access_point_are_refused_with_the_reason() {
    let (mut s, _air) = lab();
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi2", "mode": "ap", "ssid": "x", "passphrase": "senha-boa-123"}),
    );
    fails(
        &mut s,
        "interface.bonding.add",
        json!({"name": "bond1", "slaves": ["ether1", "wifi1"], "mode": "active-backup"}),
        "use mode=station-bridge",
    );
    fails(
        &mut s,
        "interface.bonding.add",
        json!({"name": "bond1", "slaves": ["ether1", "wifi2"], "mode": "active-backup"}),
        "access point is not a bond slave",
    );
}

#[test]
fn the_peers_of_two_access_points_are_a_bond_with_their_airtime() {
    let (mut s, air) = lab();
    for (r, freq) in [("wifi1", "36"), ("wifi2", "149")] {
        run(
            &mut s,
            "interface.wifi.set",
            json!({"name": r, "mode": "ap", "ssid": format!("Backhaul-{r}"),
                   "passphrase": "senha-do-backhaul", "station_bridge": "only",
                   "frequency": freq, "disabled": false}),
        );
    }
    for (p, r) in [("peer1", "wifi1"), ("peer2", "wifi2")] {
        // With a bond at the other end, both peers have its MAC.
        run(
            &mut s,
            "interface.wifi.peer.add",
            json!({"radio": r, "name": p, "mac_address": "02:00:00:00:b0:01"}),
        );
    }
    let before = s.store().current_revision();
    run(
        &mut s,
        "interface.bonding.add",
        json!({"name": "bond1", "slaves": ["peer1", "peer2"], "mode": "active-backup"}),
    );
    run(
        &mut s,
        "ip.address.add",
        json!({"address": "10.9.0.1/30", "interface": "bond1"}),
    );
    spin(&mut s, 10_000, 12);
    assert!(air.ap_told(&n("wifi2")).unwrap().backhaul.unwrap().only);
    let peers = run(&mut s, "interface.wifi.peer.print", json!({}));
    for p in peers.as_array().unwrap() {
        assert_eq!(p["state"], "up", "{peers}");
        assert_eq!(p["bond"], "bond1", "{peers}");
        // The lab's peer takes 120 ms of air a read.
        assert!(
            p["airtime_percent"].as_f64().is_some_and(|a| a > 0.0),
            "{peers}"
        );
    }
    // Rollback: no bond.
    run(&mut s, "config.rollback", json!({"revision": before}));
    if s.store().is_dirty() {
        run(&mut s, "config.commit", json!({}));
    }
    spin(&mut s, 30_000, 4);
    assert!(!s.store().running().interfaces.contains_key(&n("bond1")));
}
