//! G2.3c — CGNAT blocks on demand (RFC 6888 §5) and port alerts, in the
//! lab: its pretend online subscribers get blocks, heavy ones a second,
//! idle ones release theirs (held back 120 s, REQ-8), every allocation and
//! release is logged, "who was" reads the block log, the blocks survive a
//! restart, and subscribers near their port limit raise an alert.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::{MemoryStorage, Session};
use corerouter_hal::VirtualHal;
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

const T0: u64 = 1_780_000_000;

fn blocks_pool(s: &mut Session, extra: Value) {
    let mut p = json!({"name": "pba", "mode": "blocks", "inside": "100.64.0.0/22", "outside": "203.0.113.0/30", "block_timeout": "1m"});
    for (k, v) in extra.as_object().unwrap() {
        p[k] = v.clone();
    }
    ok(s, "ip.firewall.cgnat.pool.add", p);
}

fn blocks(s: &mut Session) -> Vec<Value> {
    ok(s, "ip.firewall.cgnat.block.list", json!({"count": 5000}))["rows"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn online_subscribers_get_paired_blocks_and_the_log_says_so() {
    let mut s = Session::virtual_lab();
    s.tick(T0);
    blocks_pool(&mut s, json!({}));
    s.tick(T0 + 1);
    let rows = blocks(&mut s);
    // The lab's 40 online subscribers each got a block, spread over the 4
    // public addresses (the least used first); the heavy ones (every 17th)
    // filled theirs and got a second at the first scan.
    let subs: std::collections::BTreeSet<&str> = rows
        .iter()
        .map(|r| r["subscriber"].as_str().unwrap())
        .collect();
    assert_eq!(subs.len(), 40, "{rows:?}");
    let mut per: std::collections::BTreeMap<String, usize> = Default::default();
    for r in &rows {
        *per.entry(r["public"].as_str().unwrap().to_owned())
            .or_default() += 1;
        let (a, b) = (
            r["first_port"].as_u64().unwrap(),
            r["last_port"].as_u64().unwrap(),
        );
        assert_eq!(b - a + 1, 1000);
    }
    assert_eq!(per.len(), 4);
    assert!(per.values().all(|n| (10..=11).contains(n)), "{per:?}");
    let log = ok(
        &mut s,
        "log.print",
        json!({"topics": ["cgnat"], "limit": 2000}),
    );
    let allocs = log
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["message"].as_str().unwrap().starts_with("ALLOC "))
        .count();
    assert_eq!(allocs, rows.len());
    // "Who was" reads the block log.
    let r = &rows[3];
    let port = r["first_port"].as_u64().unwrap() + 7;
    let w = ok(
        &mut s,
        "ip.firewall.cgnat.who-was",
        json!({"public": r["public"], "port": port, "time": T0 + 5}),
    );
    assert_eq!(w["subscriber"], r["subscriber"]);
    assert_eq!(w["mode"], "blocks");
    // Before the allocation, nobody.
    assert!(
        s.execute(
            "ip.firewall.cgnat.who-was",
            &json!({"public": r["public"], "port": port, "time": T0})
        )
        .is_err()
    );
}

#[test]
fn a_full_block_gets_a_second_on_the_same_address_and_idle_ones_are_released() {
    let mut s = Session::virtual_lab();
    s.tick(T0);
    blocks_pool(&mut s, json!({"max_blocks": 2}));
    s.tick(T0 + 1);
    // The first scan: heavy users (95 % of their block) got a second block.
    let rows = blocks(&mut s);
    let mut by: std::collections::BTreeMap<String, Vec<&Value>> = Default::default();
    for r in &rows {
        by.entry(r["subscriber"].as_str().unwrap().to_owned())
            .or_default()
            .push(r);
    }
    let two: Vec<_> = by.values().filter(|v| v.len() == 2).collect();
    assert!(!two.is_empty(), "{rows:?}");
    for v in &two {
        assert_eq!(v[0]["public"], v[1]["public"], "paired: one public address");
        assert_eq!(v[1]["current"], true);
    }
    // Kill one light subscriber's connections: after block_timeout its
    // block goes, logged; the lab then asks again (it is "online") and the
    // freed block is held back: it gets another one.
    let light = by
        .iter()
        .find(|(_, v)| v.len() == 1)
        .map(|(k, v)| (k.clone(), v[0].clone()))
        .unwrap();
    ok(
        &mut s,
        "ip.firewall.connection.kill",
        json!({"subscriber": light.0}),
    );
    s.tick(T0 + 30);
    s.tick(T0 + 95);
    s.tick(T0 + 96);
    let hist = ok(
        &mut s,
        "ip.firewall.cgnat.block.history",
        json!({"subscriber": light.0}),
    );
    let closed: Vec<&Value> = hist
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r.get("until").is_some())
        .collect();
    assert_eq!(closed.len(), 1, "{hist}");
    assert_eq!(closed[0]["first_port"], light.1["first_port"]);
    let log = ok(
        &mut s,
        "log.print",
        json!({"topics": ["cgnat"], "find": "RELEASE", "limit": 2000}),
    );
    assert!(
        log.as_array()
            .unwrap()
            .iter()
            .any(|l| l["message"].as_str().unwrap().contains(&light.0))
    );
    let now = blocks(&mut s);
    let again = now
        .iter()
        .find(|r| r["subscriber"] == light.0.as_str())
        .unwrap();
    assert_ne!(
        (again["public"].clone(), again["first_port"].clone()),
        (light.1["public"].clone(), light.1["first_port"].clone()),
        "REQ-8: the released block is held back"
    );
}

#[test]
fn blocks_survive_a_restart() {
    let storage = MemoryStorage::default();
    let before = {
        let mut s = Session::with_storage(Box::new(VirtualHal::new(8)), Box::new(storage.clone()));
        s.tick(T0);
        blocks_pool(&mut s, json!({}));
        s.tick(T0 + 1);
        blocks(&mut s)
    };
    let mut s = Session::with_storage(Box::new(VirtualHal::new(8)), Box::new(storage));
    s.tick(T0 + 2);
    let after = blocks(&mut s);
    let key = |v: &Vec<Value>| -> Vec<(String, String, u64)> {
        let mut k: Vec<_> = v
            .iter()
            .map(|r| {
                (
                    r["subscriber"].as_str().unwrap().to_owned(),
                    r["public"].as_str().unwrap().to_owned(),
                    r["first_port"].as_u64().unwrap(),
                )
            })
            .collect();
        k.sort();
        k
    };
    let (after, before) = (key(&after), key(&before));
    assert!(
        before.iter().all(|b| after.contains(b)),
        "the journal rebuilds the same blocks"
    );
}

#[test]
fn an_exhausted_pool_refuses_and_a_changed_pool_releases() {
    let mut s = Session::virtual_lab();
    s.tick(T0);
    // One public address, two blocks of 32256 ports.
    ok(
        &mut s,
        "ip.firewall.cgnat.pool.add",
        json!({"name": "tiny", "mode": "blocks", "inside": "100.64.0.0/24", "outside": "203.0.113.9", "ports_per_subscriber": 32256}),
    );
    s.tick(T0 + 1);
    assert_eq!(blocks(&mut s).len(), 2);
    assert!(
        s.cgnat_block_for("100.64.0.200".parse().unwrap(), T0 + 2)
            .unwrap_err()
            .contains("no free block")
    );
    // Other ports per subscriber: the old blocks no longer exist.
    ok(
        &mut s,
        "ip.firewall.cgnat.pool.set",
        json!({"id": "tiny", "ports_per_subscriber": 16128}),
    );
    s.tick(T0 + 3);
    let log = ok(
        &mut s,
        "log.print",
        json!({"topics": ["cgnat"], "find": "pool changed", "limit": 100}),
    );
    assert_eq!(log.as_array().unwrap().len(), 2, "{log}");
    // RFC 6888 REQ-8: the old blocks' ports go to nobody for 120 s, even in
    // the new geometry (late packets of the killed connections must not
    // reach another subscriber).
    s.tick(T0 + 4);
    assert_eq!(blocks(&mut s).len(), 0, "every new block overlaps a held range");
    s.tick(T0 + 3 + 121);
    assert_eq!(blocks(&mut s).len(), 4, "new geometry, four blocks now");
}

/// G2.7: the nearly full subscribers go into the kernel's set `full`;
/// what the exhaustion queues refused lands in the alerts (refused, ICMP
/// sent) with one log line per subscriber; turned off, the set empties.
#[test]
fn refused_connections_reach_the_alerts_and_the_log() {
    let mut s = Session::virtual_lab();
    s.tick(T0);
    ok(
        &mut s,
        "ip.firewall.cgnat.pool.add",
        json!({"name": "c1", "inside": "100.64.0.0/22", "outside": "203.0.113.0/28"}),
    );
    for t in 1..=12 {
        s.tick(T0 + t);
    }
    let a = ok(&mut s, "ip.firewall.cgnat.alert.list", json!({}));
    let full = a["full"].as_u64().unwrap();
    assert!(full > 3, "the lab's heavy users (95 %) are nearly full: {a}");
    let refused: Vec<&Value> = a["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["refused"].as_u64().unwrap() > 0)
        .collect();
    assert!(!refused.is_empty(), "{a}");
    for r in &refused {
        assert_eq!(r["icmp"], 2);
        assert_eq!(r["refused"], 4);
        assert!(r.get("last_refused").is_some());
    }
    assert_eq!(a["refused"].as_u64().unwrap(), 4 * refused.len() as u64);
    assert_eq!(a["icmp_sent"].as_u64().unwrap(), 2 * refused.len() as u64);
    let log = ok(
        &mut s,
        "log.print",
        json!({"topics": ["cgnat"], "find": "no free port", "limit": 2000}),
    );
    assert_eq!(log.as_array().unwrap().len(), refused.len());
    // Refused again within a minute: counted, not logged again.
    for t in 13..=22 {
        s.tick(T0 + t);
    }
    let log = ok(
        &mut s,
        "log.print",
        json!({"topics": ["cgnat"], "find": "no free port", "limit": 2000}),
    );
    assert_eq!(log.as_array().unwrap().len(), refused.len());

    let set = ok(&mut s, "ip.firewall.cgnat.set", json!({"icmp_unreachable": false, "icmp_rate": 7}));
    assert_eq!(set, json!({"history_days": 365, "icmp_unreachable": false, "icmp_rate": 7}));
    s.tick(T0 + 40);
    let a = ok(&mut s, "ip.firewall.cgnat.alert.list", json!({}));
    assert_eq!(a["full"], 0, "{a}");
    let get = ok(&mut s, "ip.firewall.cgnat.get", json!({}));
    assert_eq!((get["icmp_unreachable"].clone(), get["icmp_rate"].clone()), (json!(false), json!(7)));
    // Out of range is a parameter error.
    assert!(s.execute("ip.firewall.cgnat.set", &json!({"icmp_rate": 0})).is_err());
    assert!(s.execute("ip.firewall.cgnat.set", &json!({"icmp_rate": 101})).is_err());
}

#[test]
fn subscribers_near_their_limit_raise_one_alert_per_crossing() {
    let mut s = Session::virtual_lab();
    s.tick(T0);
    // The lab's heavy users hold ~570 TCP ports of their 1000 (57 %).
    ok(
        &mut s,
        "ip.firewall.cgnat.pool.add",
        json!({"name": "c1", "inside": "100.64.0.0/22", "outside": "203.0.113.0/28", "alert_percent": 50}),
    );
    s.tick(T0 + 1);
    let a = ok(&mut s, "ip.firewall.cgnat.alert.list", json!({}));
    let rows = a["rows"].as_array().unwrap().clone();
    assert!(rows.len() > 3, "{a}");
    for r in &rows {
        assert_eq!(r["pool"], "c1");
        assert_eq!(r["ports"], 1000);
        assert!(r["percent"].as_u64().unwrap() >= 50);
        assert_eq!(r["crossings"], 1);
        assert_eq!(r["above"], true);
    }
    let warned = ok(
        &mut s,
        "log.print",
        json!({"topics": ["cgnat"], "find": "ports:", "limit": 2000}),
    );
    assert_eq!(warned.as_array().unwrap().len(), rows.len());
    // Still above at the next scan: no new crossing, no new log line.
    s.tick(T0 + 15);
    let again = ok(&mut s, "ip.firewall.cgnat.alert.list", json!({}));
    assert!(
        again["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["crossings"] == 1)
    );
    let warned = ok(
        &mut s,
        "log.print",
        json!({"topics": ["cgnat"], "find": "ports:", "limit": 2000}),
    );
    assert_eq!(warned.as_array().unwrap().len(), rows.len());
    // Below again (its connections killed), then above: a second crossing.
    let first = rows[0]["subscriber"].as_str().unwrap().to_owned();
    assert_eq!(
        ok(
            &mut s,
            "ip.firewall.cgnat.alert.clear",
            json!({"subscriber": first})
        )["cleared"],
        1
    );
    assert_eq!(
        ok(&mut s, "ip.firewall.cgnat.alert.clear", json!({}))["cleared"],
        rows.len() - 1
    );
    assert_eq!(
        ok(&mut s, "ip.firewall.cgnat.alert.list", json!({}))["rows"],
        json!([])
    );
}
