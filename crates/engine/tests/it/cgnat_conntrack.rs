//! G2.3h: the CGNAT warns when `nf_conntrack_max` is small for its pools.
//! The lab's kernel has 262 144 entries (Linux's limit above 4 GB of RAM);
//! 1280 subscribers × 300 connections need 384 000, as on the notebook of
//! dev.595.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn health(s: &mut Session, key: &str) -> Option<Value> {
    let v = ok(s, "system.health.check", json!({}));
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["key"] == key)
        .cloned()
}

/// 1024 + 256 = 1280 subscribers.
fn pool_1280(s: &mut Session) -> Value {
    ok(
        s,
        "ip.firewall.cgnat.pool.add",
        json!({"name": "teste", "inside": ["100.64.0.0/22", "100.64.4.0/24"], "outside": "203.0.113.0/27"}),
    )
}

#[test]
fn a_pool_of_1280_subscribers_outgrows_the_kernels_262144() {
    let mut s = Session::virtual_lab();
    let add = pool_1280(&mut s);
    assert_eq!(add["subscribers"], 1280);
    let warnings: Vec<&str> = add["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let w = warnings
        .iter()
        .find(|w| w.starts_with("conntrack too small"))
        .unwrap_or_else(|| panic!("{add}"));
    assert!(
        w.contains(
            "1280 subscribers × 300 connections = 384 000 entries, above nf_conntrack_max 262 144"
        ),
        "{w}"
    );
    // The lab has 32 GiB: the balanced profile already holds it.
    assert!(
        w.contains("apply the balanced profile in System › Tuning (nf_conntrack_max 6 684 672)"),
        "{w}"
    );
    assert!(w.contains("max_entries=393216"), "{w}");

    // capacity.get: the same numbers, for the GUI.
    let c = ok(
        &mut s,
        "ip.firewall.cgnat.capacity.get",
        json!({"pool": "teste"}),
    );
    let ct = &c["conntrack"];
    assert_eq!(
        (
            &ct["needed"],
            &ct["max"],
            &ct["fits"],
            &ct["profile"],
            &ct["configured"]
        ),
        (
            &json!(384_000),
            &json!(262_144),
            &json!(false),
            &json!("balanced"),
            &json!(false)
        ),
        "{ct}"
    );
    // The health, in Portuguese, with what to do.
    let h = health(&mut s, "cgnat.conntrack").unwrap();
    assert_eq!(h["severity"], "warning", "{h}");
    assert!(
        h["reason"]
            .as_str()
            .unwrap()
            .contains("1280 assinantes × 300 conexões = 384000"),
        "{h}"
    );
    assert!(
        h["action"].as_str().unwrap().contains("perfil balanced"),
        "{h}"
    );
    // The pool's row and the modal's preview carry it too.
    let list = ok(&mut s, "ip.firewall.cgnat.pool.list", json!({}));
    assert!(
        list[0]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["label"] == "conntrack"),
        "{list}"
    );
    let pre = ok(
        &mut s,
        "ip.firewall.cgnat.pool.preview",
        json!({"id": "teste", "comment": "x"}),
    );
    assert!(
        pre["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["check"] == "conntrack" && c["level"] == "warning"),
        "{pre}"
    );

    // Fewer connections per subscriber fit: 1280 × 200 = 256 000.
    let set = ok(
        &mut s,
        "ip.firewall.cgnat.set",
        json!({"connections_per_subscriber": 200}),
    );
    assert_eq!(set["connections_per_subscriber"], 200);
    assert_eq!(
        ok(&mut s, "ip.firewall.cgnat.get", json!({}))["conntrack"]["fits"],
        true
    );
    assert_eq!(health(&mut s, "cgnat.conntrack").unwrap()["severity"], "ok");
    ok(
        &mut s,
        "ip.firewall.cgnat.set",
        json!({"connections_per_subscriber": 300}),
    );

    // The suggested profile clears it.
    ok(
        &mut s,
        "system.tuning.profile.apply",
        json!({"profile": "balanced"}),
    );
    let c = ok(
        &mut s,
        "ip.firewall.cgnat.capacity.get",
        json!({"pool": "teste"}),
    );
    assert_eq!(c["conntrack"]["fits"], true, "{}", c["conntrack"]);
    assert_eq!(health(&mut s, "cgnat.conntrack").unwrap()["severity"], "ok");
    let list = ok(&mut s, "ip.firewall.cgnat.pool.list", json!({}));
    assert!(
        !list[0]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["label"] == "conntrack")
    );
}

#[test]
fn the_configured_limit_counts_before_it_reaches_the_kernel() {
    let mut s = Session::virtual_lab();
    ok(&mut s, "config.mode.set", json!({"mode": "transactional"}));
    ok(
        &mut s,
        "system.tuning.set",
        json!({"name": "net.netfilter.nf_conntrack_max", "value": 524_288}),
    );
    let add = pool_1280(&mut s);
    assert!(
        !add["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().starts_with("conntrack")),
        "the candidate's 524 288 holds 384 000: {add}"
    );
    let get = ok(&mut s, "ip.firewall.cgnat.get", json!({}));
    assert_eq!(
        (&get["conntrack"]["max"], &get["conntrack"]["configured"]),
        (&json!(524_288), &json!(true))
    );
}

#[test]
fn no_pool_no_check_and_a_disabled_pool_does_not_count() {
    let mut s = Session::virtual_lab();
    assert!(health(&mut s, "cgnat.conntrack").is_none());
    assert!(ok(&mut s, "ip.firewall.cgnat.get", json!({}))["conntrack"].is_null());
    pool_1280(&mut s);
    ok(
        &mut s,
        "ip.firewall.cgnat.pool.set",
        json!({"id": "teste", "disabled": true}),
    );
    assert!(health(&mut s, "cgnat.conntrack").is_none());
}

#[test]
fn connections_per_subscriber_is_validated_and_rolls_back() {
    let mut s = Session::virtual_lab();
    for bad in [json!(0), json!(100_001), json!("many")] {
        let e = s
            .execute(
                "ip.firewall.cgnat.set",
                &json!({"connections_per_subscriber": bad}),
            )
            .unwrap_err()
            .to_string();
        assert!(e.contains("connections_per_subscriber"), "{e}");
    }
    assert_eq!(
        ok(&mut s, "ip.firewall.cgnat.get", json!({}))["connections_per_subscriber"],
        300
    );
    // A batch that fails after the change leaves it as it was.
    let e = s.batch(
        &json!([
            {"command": "ip.firewall.cgnat.set", "params": {"connections_per_subscriber": 50}},
            {"command": "ip.firewall.cgnat.set", "params": {"icmp_rate": 0}},
        ]),
        true,
    );
    assert!(e.is_err(), "{e:?}");
    assert_eq!(
        ok(&mut s, "ip.firewall.cgnat.get", json!({}))["connections_per_subscriber"],
        300
    );
}
