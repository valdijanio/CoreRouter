//! G2.2 — /ip firewall connection: list with filters and pages, the top
//! subscribers, kill (with the "no filter means all=true" guard) and the
//! tracking timeouts kept as Tuning parameters. The lab's table comes from
//! the applied CGNAT pools.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::{EngineError, Session};
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

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "ip.firewall.cgnat.pool.add",
        json!({"name": "c1", "inside": "100.64.0.0/22", "outside": "203.0.113.0/28"}),
    );
    s
}

#[test]
fn list_filters_and_pages() {
    let mut s = lab();
    let all = ok(&mut s, "ip.firewall.connection.list", json!({"count": 5}));
    let total = all["total"].as_u64().unwrap();
    assert!(total > 1000, "{total}");
    assert_eq!(all["rows"].as_array().unwrap().len(), 5);
    assert_eq!(all["table"]["count"], total);
    assert!(all["table"]["max"].as_u64().unwrap() > 0);
    // Each filter narrows; rows match it.
    let tcp = ok(
        &mut s,
        "ip.firewall.connection.list",
        json!({"protocol": "tcp", "count": 5000}),
    );
    assert!(tcp["total"].as_u64().unwrap() < total);
    assert!(
        tcp["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["protocol"] == "tcp")
    );
    let one = ok(
        &mut s,
        "ip.firewall.connection.list",
        json!({"subscriber": "100.64.0.5"}),
    );
    assert!(
        one["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["src"].as_str().unwrap().starts_with("100.64.0.5"))
    );
    // Its public address is the formula's.
    let slot = ok(
        &mut s,
        "ip.firewall.cgnat.lookup",
        json!({"subscriber": "100.64.0.5"}),
    );
    for r in one["rows"].as_array().unwrap() {
        assert!(
            r["nat"]
                .as_str()
                .unwrap()
                .starts_with(slot["public"].as_str().unwrap()),
            "{r}"
        );
        assert_eq!(r["pool"], "c1");
    }
    let sw = ok(
        &mut s,
        "ip.firewall.connection.list",
        json!({"via": "software", "count": 50}),
    );
    assert!(
        sw["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["via"] == "software" && r["flags"].as_str().unwrap().contains('F'))
    );
    let pfx = ok(
        &mut s,
        "ip.firewall.connection.list",
        json!({"src": "100.64.1.0/24", "count": 50}),
    );
    assert!(
        pfx["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["src"].as_str().unwrap().starts_with("100.64.1."))
    );
    let sorted = ok(
        &mut s,
        "ip.firewall.connection.list",
        json!({"sort": "timeout", "count": 20}),
    );
    let t: Vec<u64> = sorted["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["timeout"].as_u64().unwrap())
        .collect();
    assert!(t.windows(2).all(|w| w[0] >= w[1]), "{t:?}");
    // The last page.
    let last = ok(
        &mut s,
        "ip.firewall.connection.list",
        json!({"offset": total - 2, "count": 10}),
    );
    assert_eq!(last["rows"].as_array().unwrap().len(), 2);
    for (p, key) in [
        (json!({"count": 0}), "count"),
        (json!({"count": 6000}), "count"),
        (json!({"protocol": "bogus"}), "protocol"),
        (json!({"src": "nope"}), "src"),
        (json!({"via": "warp"}), "via"),
        (json!({"sort": "name"}), "sort"),
        (json!({"port": 70000}), "port"),
    ] {
        assert_eq!(
            bad(&mut s, "ip.firewall.connection.list", p.clone()).0,
            key,
            "{p}"
        );
    }
}

#[test]
fn the_top_subscribers_say_how_full_their_slot_is() {
    let mut s = lab();
    let top = ok(&mut s, "ip.firewall.connection.top", json!({"count": 5}));
    let rows = top.as_array().unwrap();
    assert_eq!(rows.len(), 5);
    let n: Vec<u64> = rows
        .iter()
        .map(|r| r["connections"].as_u64().unwrap())
        .collect();
    assert!(n.windows(2).all(|w| w[0] >= w[1]), "{n:?}");
    assert_eq!(rows[0]["pool"], "c1");
    assert_eq!(rows[0]["ports"], 1000);
    assert!(rows[0]["percent"].as_u64().unwrap() > 0);
    let sum = rows[0]["tcp"].as_u64().unwrap()
        + rows[0]["udp"].as_u64().unwrap()
        + rows[0]["icmp"].as_u64().unwrap();
    assert_eq!(sum, n[0]);
}

#[test]
fn kill_needs_a_filter_and_removes_what_it_matched() {
    let mut s = lab();
    let (param, why) = bad(&mut s, "ip.firewall.connection.kill", json!({}));
    assert_eq!(param, "all");
    assert!(why.contains("all=true"), "{why}");
    let before = ok(
        &mut s,
        "ip.firewall.connection.list",
        json!({"subscriber": "100.64.0.5"}),
    )["total"]
        .as_u64()
        .unwrap();
    assert!(before > 0);
    let k = ok(
        &mut s,
        "ip.firewall.connection.kill",
        json!({"subscriber": "100.64.0.5"}),
    );
    assert_eq!(k["matched"], before);
    assert_eq!(k["killed"], before);
    let after = ok(
        &mut s,
        "ip.firewall.connection.list",
        json!({"subscriber": "100.64.0.5"}),
    );
    assert_eq!(after["total"], 0);
    // By id.
    let row = ok(&mut s, "ip.firewall.connection.list", json!({"count": 1}))["rows"][0].clone();
    let k = ok(
        &mut s,
        "ip.firewall.connection.kill",
        json!({"id": row["id"]}),
    );
    assert_eq!(k["killed"], 1);
    // Everything, explicitly.
    let k = ok(&mut s, "ip.firewall.connection.kill", json!({"all": true}));
    assert!(k["killed"].as_u64().unwrap() > 0);
    assert_eq!(
        ok(&mut s, "ip.firewall.connection.list", json!({}))["total"],
        0
    );
    // Not configuration: no revision.
    assert!(!s.store().is_dirty());
}

#[test]
fn tracking_timeouts_are_tuning_parameters() {
    let mut s = lab();
    let t = ok(&mut s, "ip.firewall.connection.tracking.info", json!({}));
    assert_eq!(t["loaded"], true);
    assert!(t["udp_timeout"].as_i64().is_some(), "{t}");
    let r = ok(
        &mut s,
        "ip.firewall.connection.tracking.set",
        json!({"udp_timeout": "1m", "tcp_established_timeout": 7440}),
    );
    assert_eq!(r["changed"].as_array().unwrap().len(), 2);
    let sys = &s.store().running().system.tuning.sysctl;
    assert_eq!(sys.get("net.netfilter.nf_conntrack_udp_timeout"), Some(&60));
    assert_eq!(
        sys.get("net.netfilter.nf_conntrack_tcp_timeout_established"),
        Some(&7440)
    );
    // Out of the parameter's range: refused, named by our key.
    let (param, _) = bad(
        &mut s,
        "ip.firewall.connection.tracking.set",
        json!({"udp_timeout": 1}),
    );
    assert_eq!(param, "udp_timeout");
    let (param, _) = bad(
        &mut s,
        "ip.firewall.connection.tracking.set",
        json!({"icmp_timeout": "soon"}),
    );
    assert_eq!(param, "icmp_timeout");
}
