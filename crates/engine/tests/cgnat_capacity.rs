//! G2.7b: CGNAT capacity in the lab — the 7-day peaks the scan records, the
//! subscribers refused in 24 h, the distribution and the suggested
//! `ports_per_subscriber`, its preview (who moves, what is killed) and the
//! store across a restart.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use corerouter_engine::{MemoryStorage, Session};
use corerouter_hal::VirtualHal;
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

const T0: u64 = 1_780_000_000;

fn lab(storage: MemoryStorage) -> Session {
    let mut s = Session::with_storage(Box::new(VirtualHal::new(8)), Box::new(storage));
    s.tick(T0);
    ok(
        &mut s,
        "ip.firewall.cgnat.pool.add",
        json!({"name": "c1", "inside": "100.64.0.0/22", "outside": "203.0.113.0/27"}),
    );
    for t in 1..=12 {
        s.tick(T0 + t);
    }
    s
}

#[test]
fn capacity_reads_the_peaks_and_suggests_ports() {
    let mut s = lab(MemoryStorage::default());
    let c = ok(&mut s, "ip.firewall.cgnat.capacity", json!({"pool": "c1"}));
    // The lab gives connections to 300 of the 1024 subscribers; every 17th
    // is heavy (95 % of its 1000 ports), the rest light.
    assert_eq!(c["subscribers"], 1024);
    assert_eq!(c["ports"], 1000);
    assert_eq!(c["seen"], 300, "{c}");
    assert_eq!(c["p99"], 950, "{c}");
    assert_eq!(c["p99_percent"], 95);
    let bands = c["bands"].as_array().unwrap();
    let total: u64 = bands.iter().map(|b| b["count"].as_u64().unwrap()).sum();
    assert_eq!(total, 300, "every seen subscriber in one band");
    let heavy = bands.iter().find(|b| b["band"] == "90-100").unwrap()["count"]
        .as_u64()
        .unwrap();
    assert!(heavy >= 17, "{bands:?}");
    // The lab refuses some nearly full subscribers: more than 1 % in 24 h
    // asks for 1.5 × the ports.
    assert!(c["hit_24h"].as_u64().unwrap() > 3, "{c}");
    assert!(c["icmp_24h"].as_u64().unwrap() > 0);
    let sug = &c["suggestion"];
    assert_eq!(sug["ports_per_subscriber"], 1536, "{sug}");
    assert!(
        sug["gain_per_address"].as_i64().unwrap() < 0,
        "more ports, fewer per address"
    );
    assert_eq!(sug["fits"], true, "{sug}");
    assert_eq!(
        sug["public_needed"], 25,
        "1024 subscribers at 42 per address"
    );

    // The preview: everyone of the pool moves, their connections go.
    let pv = ok(
        &mut s,
        "ip.firewall.cgnat.capacity.preview",
        json!({"pool": "c1", "ports_per_subscriber": 1536}),
    );
    assert_eq!(pv["remapped"], 1024, "{pv}");
    assert!(pv["connections"].as_u64().unwrap() > 1000, "{pv}");
    assert_eq!(pv["per_address_now"], 64);
    assert_eq!(pv["per_address"], 42);
    assert_eq!(pv["command"]["command"], "ip.firewall.cgnat.pool.set");
    // Too many ports for the public addresses: says so, changes nothing.
    let pv = ok(
        &mut s,
        "ip.firewall.cgnat.capacity.preview",
        json!({"pool": "c1", "ports_per_subscriber": 30000}),
    );
    assert_eq!(pv["fits"], false);
    assert!(pv["error"].as_str().unwrap().contains("public"), "{pv}");
    assert_eq!(
        ok(&mut s, "ip.firewall.cgnat.pool.list", json!({}))[0]["ports_per_subscriber"],
        1000
    );
    // Bad input is a parameter error.
    assert!(
        s.execute("ip.firewall.cgnat.capacity", &json!({"pool": "nope"}))
            .is_err()
    );
    assert!(
        s.execute(
            "ip.firewall.cgnat.capacity.preview",
            &json!({"pool": "c1", "ports_per_subscriber": 70000})
        )
        .is_err()
    );
}

#[test]
fn the_peaks_survive_a_restart() {
    let storage = MemoryStorage::default();
    let before = {
        let mut s = lab(storage.clone());
        // The store is written every 10 min (at a scan).
        s.tick(T0 + corerouter_engine::cgnat_capacity::SAVE_SECS + 20);
        ok(&mut s, "ip.firewall.cgnat.capacity", json!({"pool": "c1"}))
    };
    let mut s = Session::with_storage(Box::new(VirtualHal::new(8)), Box::new(storage));
    // One tick for the clock; the lab's refusals only come every 10th, so
    // the 24 h counts are the journal's.
    s.tick(T0 + corerouter_engine::cgnat_capacity::SAVE_SECS + 21);
    let after = ok(&mut s, "ip.firewall.cgnat.capacity", json!({"pool": "c1"}));
    assert_eq!(after["seen"], before["seen"]);
    assert_eq!(after["p99"], before["p99"]);
    assert_eq!(after["hit_24h"], before["hit_24h"]);
}
