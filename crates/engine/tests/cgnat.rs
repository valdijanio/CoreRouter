//! G2.3 — /ip firewall cgnat: pools, exceptions, mapping, "who was" over
//! time, validation, rollback and the history surviving a restart.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::{EngineError, MemoryStorage, Session};
use corerouter_hal::VirtualHal;
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn bad(s: &mut Session, id: &str, p: Value) -> (String, String) {
    match s.execute(id, &p) {
        Err(EngineError::BadParam { param, reason }) => (param, reason),
        other => panic!("{id} {p}: expected a parameter error, got {other:?}"),
    }
}

/// 1024 subscribers, 16 public addresses, 1000 ports each: 64 per address.
fn pool(s: &mut Session) -> Value {
    ok(
        s,
        "ip.firewall.cgnat.pool.add",
        json!({"name": "cgnat1", "inside": "100.64.0.0/22", "outside": "203.0.113.0/28"}),
    )
}

const T0: u64 = 1_780_000_000;

#[test]
fn a_pool_maps_subscribers_and_answers_who_was() {
    let mut s = Session::virtual_lab();
    s.tick(T0);
    let r = pool(&mut s);
    assert_eq!(r["subscribers"], 1024);
    assert_eq!(r["per_address"], 64);
    assert_eq!(r["public_used"], 16);
    assert_eq!(r["warnings"], json!([]));
    let row = &ok(&mut s, "ip.firewall.cgnat.pool.list", json!({}))[0];
    assert_eq!(row["mode"], "deterministic");
    assert_eq!(row["capacity"], 1024);
    assert_eq!(row["checks"][0]["label"], "capacity");
    let l = ok(
        &mut s,
        "ip.firewall.cgnat.lookup",
        json!({"subscriber": "100.64.0.65"}),
    );
    assert_eq!(l["public"], "203.0.113.1");
    assert_eq!(
        (l["first_port"].as_u64(), l["last_port"].as_u64()),
        (Some(2024), Some(3023))
    );
    // RFC 7422 §2: the reverse of the forward, any port of the range.
    for port in [2024, 2500, 3023] {
        let w = ok(
            &mut s,
            "ip.firewall.cgnat.who-was",
            json!({"public": "203.0.113.1", "port": port}),
        );
        assert_eq!(w["subscriber"], "100.64.0.65", "{w}");
        assert_eq!(w["via"], "cgnat1");
    }
    let (param, why) = bad(
        &mut s,
        "ip.firewall.cgnat.who-was",
        json!({"public": "203.0.113.1", "port": 80}),
    );
    assert_eq!(param, "public");
    assert!(why.contains("belonged to no subscriber"), "{why}");
    // The mapping table, a page at a time, or one address's run.
    let m = ok(
        &mut s,
        "ip.firewall.cgnat.mapping.list",
        json!({"pool": "cgnat1", "offset": 1020, "count": 10}),
    );
    assert_eq!(m["total"], 1024);
    assert_eq!(m["rows"].as_array().unwrap().len(), 4);
    let m = ok(
        &mut s,
        "ip.firewall.cgnat.mapping.list",
        json!({"pool": "cgnat1", "public": "203.0.113.2", "count": 5000}),
    );
    assert_eq!(m["total"], 64);
    assert_eq!(m["rows"][0]["subscriber"], "100.64.0.128");
    let r = ok(&mut s, "ip.firewall.cgnat.rules", json!({}));
    assert_eq!(r["elements"], 1024 + 1, "the map and the public range");
    assert!(
        r["script"]
            .as_str()
            .unwrap()
            .contains("table ip corerouter_cgnat")
    );
}

#[test]
fn who_was_uses_the_definition_in_force_at_that_time() {
    let mut s = Session::virtual_lab();
    s.tick(T0);
    pool(&mut s);
    s.tick(T0 + 3600);
    // Halving the ports per subscriber moves everyone after the first.
    let r = ok(
        &mut s,
        "ip.firewall.cgnat.pool.set",
        json!({"id": "cgnat1", "ports_per_subscriber": 500}),
    );
    assert_eq!(r["remapped"], 1024);
    let at = |s: &mut Session, t: u64| {
        ok(
            s,
            "ip.firewall.cgnat.who-was",
            json!({"public": "203.0.113.0", "port": 2500, "time": t}),
        )
    };
    let before = at(&mut s, T0 + 10);
    assert_eq!(before["subscriber"], "100.64.0.1");
    assert_eq!(before["until"], "2026-05-28T21:26:40Z");
    let after = at(&mut s, T0 + 7200);
    assert_eq!(after["subscriber"], "100.64.0.2");
    assert!(after.get("until").is_none());
    // RFC 3339 with an offset is the same instant.
    let w = ok(
        &mut s,
        "ip.firewall.cgnat.who-was",
        json!({"public": "203.0.113.0", "port": 2500, "time": "2026-05-28T17:26:50-03:00"}),
    );
    assert_eq!(w["subscriber"], "100.64.0.1");
    // Before the first record there is no answer.
    let (_, why) = bad(
        &mut s,
        "ip.firewall.cgnat.who-was",
        json!({"public": "203.0.113.0", "port": 2500, "time": T0 - 1}),
    );
    assert!(why.contains("no CGNAT record before"), "{why}");
    assert_eq!(
        ok(&mut s, "ip.firewall.cgnat.history.list", json!({}))
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn exceptions_get_their_own_address() {
    let mut s = Session::virtual_lab();
    s.tick(T0);
    pool(&mut s);
    ok(
        &mut s,
        "ip.firewall.cgnat.exception.add",
        json!({"subscriber": "100.64.0.65", "public": "198.51.100.10", "comment": "empresa"}),
    );
    let l = ok(
        &mut s,
        "ip.firewall.cgnat.lookup",
        json!({"subscriber": "100.64.0.65"}),
    );
    assert_eq!(l["via"], "exception");
    assert_eq!(l["public"], "198.51.100.10");
    let w = ok(
        &mut s,
        "ip.firewall.cgnat.who-was",
        json!({"public": "198.51.100.10", "port": 443}),
    );
    assert_eq!(w["subscriber"], "100.64.0.65");
    // Its pool slot is left unused, so nobody else moves.
    let (_, why) = bad(
        &mut s,
        "ip.firewall.cgnat.who-was",
        json!({"public": "203.0.113.1", "port": 2500}),
    );
    assert!(why.contains("1:1 exception"), "{why}");
    let l = ok(
        &mut s,
        "ip.firewall.cgnat.lookup",
        json!({"subscriber": "100.64.0.66"}),
    );
    assert_eq!(l["first_port"], 3024);
    let list = ok(&mut s, "ip.firewall.cgnat.exception.list", json!({}));
    assert_eq!(list[0]["pool"], "cgnat1");
    // An exception on a pool's public address is refused.
    let (param, why) = bad(
        &mut s,
        "ip.firewall.cgnat.exception.add",
        json!({"subscriber": "100.64.0.70", "public": "203.0.113.5"}),
    );
    assert_eq!(param, "public");
    assert!(why.contains("pool 'cgnat1'"), "{why}");
}

#[test]
fn validation_refuses_before_anything_changes() {
    let mut s = Session::virtual_lab();
    let rev = s.store().current_revision();
    let (param, why) = bad(
        &mut s,
        "ip.firewall.cgnat.pool.add",
        json!({"name": "x", "inside": "100.64.0.0/22", "outside": "203.0.113.0/30"}),
    );
    assert_eq!(param, "outside");
    assert!(why.contains("16 public addresses needed"), "{why}");
    for (p, key) in [
        (
            json!({"name": "x", "inside": "100.64.0.1/22", "outside": "203.0.113.0/28"}),
            "inside",
        ),
        (
            json!({"name": "x", "inside": "100.64.0.0/22", "outside": "nope"}),
            "outside",
        ),
        (
            json!({"name": "x", "inside": "100.64.0.0/22", "outside": "203.0.113.0/28", "mode": "x"}),
            "mode",
        ),
        (
            json!({"name": "x", "inside": "100.64.0.0/22", "outside": "203.0.113.0/28", "ports_per_subscriber": 70000}),
            "ports_per_subscriber",
        ),
        (
            json!({"name": "x", "inside": "100.64.0.0/22", "outside": "203.0.113.0/28", "ports_per_subscriber": 10}),
            "ports_per_subscriber",
        ),
        (
            json!({"name": "x", "inside": "100.64.0.0/22", "outside": "203.0.113.0/28", "port_range": "9-1"}),
            "port_range",
        ),
        (
            json!({"name": "x", "inside": "100.64.0.0/22", "outside": "203.0.113.0/28", "alert_percent": 101}),
            "alert_percent",
        ),
        (
            json!({"name": "x", "inside": [], "outside": "203.0.113.0/28"}),
            "inside",
        ),
        (
            json!({"name": "", "inside": "100.64.0.0/22", "outside": "203.0.113.0/28"}),
            "name",
        ),
        (json!({"name": "x", "outside": "203.0.113.0/28"}), "inside"),
    ] {
        let (param, _) = bad(&mut s, "ip.firewall.cgnat.pool.add", p.clone());
        assert_eq!(param, key, "{p}");
    }
    assert_eq!(s.store().current_revision(), rev);
    pool(&mut s);
    let (param, why) = bad(
        &mut s,
        "ip.firewall.cgnat.pool.add",
        json!({"name": "two", "inside": "100.64.3.0/24", "outside": "198.51.100.0/28"}),
    );
    assert_eq!(param, "inside");
    assert!(why.contains("also in pool 'cgnat1'"), "{why}");
    let (param, _) = bad(
        &mut s,
        "ip.firewall.cgnat.who-was",
        json!({"public": "203.0.113.1", "port": 1, "time": "yesterday"}),
    );
    assert_eq!(param, "time");
    let (param, _) = bad(
        &mut s,
        "ip.firewall.cgnat.mapping.list",
        json!({"pool": "nope"}),
    );
    assert_eq!(param, "pool");
}

#[test]
fn rollback_restores_the_pools_and_the_history_follows() {
    let mut s = Session::virtual_lab();
    s.tick(T0);
    let rev = s.store().current_revision();
    pool(&mut s);
    s.tick(T0 + 60);
    ok(&mut s, "config.rollback", json!({"revision": rev}));
    assert!(s.store().running().ip.cgnat.pools.is_empty());
    s.tick(T0 + 120);
    // At T0+30 the pool was in force; now it is not.
    let w = ok(
        &mut s,
        "ip.firewall.cgnat.who-was",
        json!({"public": "203.0.113.1", "port": 2500, "time": T0 + 30}),
    );
    assert_eq!(w["subscriber"], "100.64.0.65");
    let (_, why) = bad(
        &mut s,
        "ip.firewall.cgnat.who-was",
        json!({"public": "203.0.113.1", "port": 2500}),
    );
    assert!(why.contains("not a public address"), "{why}");
}

#[test]
fn transactional_mode_records_at_commit() {
    let mut s = Session::virtual_lab();
    s.tick(T0);
    ok(&mut s, "config.mode.set", json!({"mode": "transactional"}));
    pool(&mut s);
    let (_, why) = bad(
        &mut s,
        "ip.firewall.cgnat.who-was",
        json!({"public": "203.0.113.1", "port": 2500}),
    );
    assert!(why.contains("has ever been configured"), "{why}");
    s.tick(T0 + 5);
    ok(&mut s, "config.commit", json!({}));
    let w = ok(
        &mut s,
        "ip.firewall.cgnat.who-was",
        json!({"public": "203.0.113.1", "port": 2500}),
    );
    assert_eq!(w["since"], "2026-05-28T20:26:45Z");
}

#[test]
fn the_history_survives_a_restart() {
    let storage = MemoryStorage::default();
    {
        let mut s = Session::with_storage(Box::new(VirtualHal::new(8)), Box::new(storage.clone()));
        s.tick(T0);
        pool(&mut s);
        s.tick(T0 + 100);
        ok(
            &mut s,
            "ip.firewall.cgnat.pool.set",
            json!({"id": "cgnat1", "ports_per_subscriber": 500}),
        );
    }
    let mut s = Session::with_storage(Box::new(VirtualHal::new(8)), Box::new(storage));
    s.tick(T0 + 200);
    let w = ok(
        &mut s,
        "ip.firewall.cgnat.who-was",
        json!({"public": "203.0.113.0", "port": 2500, "time": T0 + 50}),
    );
    assert_eq!(w["subscriber"], "100.64.0.1");
    assert_eq!(
        ok(&mut s, "ip.firewall.cgnat.get", json!({}))["history"]["epochs"],
        2
    );
}

#[test]
fn settings_are_bounded() {
    let mut s = Session::virtual_lab();
    assert_eq!(
        ok(&mut s, "ip.firewall.cgnat.get", json!({}))["history_days"],
        365
    );
    ok(
        &mut s,
        "ip.firewall.cgnat.set",
        json!({"history_days": 730}),
    );
    assert_eq!(
        ok(&mut s, "ip.firewall.cgnat.get", json!({}))["history_days"],
        730
    );
    let (param, _) = bad(&mut s, "ip.firewall.cgnat.set", json!({"history_days": 0}));
    assert_eq!(param, "history_days");
}
