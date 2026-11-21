//! G0.31g — the route lines after a change. A commit that touches none of
//! the sections they read (the identity, the firewall) keeps them; one that
//! does makes `ip.route.page`/`ip.route.list` build them after the lock is
//! released, and the build is kept for the next read; the clock builds
//! stale lines before its tick the same way.
// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::off_lock::Reply;
use corerouter_engine::{Caller, Session};
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.0.2/24", "interface": "ether1"}),
    );
    for i in 0..20 {
        ok(
            &mut s,
            "ip.route.add",
            json!({"dst_address": format!("172.16.{i}.0/24"), "gateway": "10.0.0.1"}),
        );
    }
    s
}

fn generation(s: &mut Session) -> u64 {
    ok(s, "ip.route.page", json!({"limit": 1}))["generation"]
        .as_u64()
        .unwrap()
}

#[test]
fn a_change_the_lines_do_not_read_keeps_them() {
    let mut s = lab();
    let g = generation(&mut s);
    ok(&mut s, "system.identity.set", json!({"name": "edge-2"}));
    assert_eq!(generation(&mut s), g, "the identity");
    ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"chain": "input", "action": "accept"}),
    );
    assert_eq!(generation(&mut s), g, "a firewall rule");
    // Twice in a row: the second look compares with the newer config.
    ok(&mut s, "system.identity.set", json!({"name": "edge-3"}));
    assert_eq!(generation(&mut s), g);
    // An address does make new lines (a connected route).
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.9.0.1/24", "interface": "ether2"}),
    );
    assert_eq!(generation(&mut s), g + 1);
}

#[test]
fn stale_lines_are_built_after_the_lock_and_kept() {
    let mut s = lab();
    let g = generation(&mut s);
    ok(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "203.0.113.0/24", "gateway": "10.0.0.1"}),
    );
    // Through the control channel: the answer is built after the lock.
    let p = json!({"prefix": "203.0.113.0/24", "match": "exact"});
    let reply = s
        .execute_reply_as(&Caller::local(), "ip.route.page", &p)
        .unwrap();
    assert!(matches!(reply, Reply::Later(_)), "the page defers");
    let v = reply.finish().unwrap();
    assert_eq!(v["total"], 1, "{v}");
    assert_eq!(v["generation"], g + 1);
    // The next read takes that build: no other one.
    assert_eq!(generation(&mut s), g + 1);

    // The list the same way.
    ok(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "203.0.114.0/24", "gateway": "10.0.0.1"}),
    );
    let reply = s
        .execute_reply_as(&Caller::local(), "ip.route.list", &json!({}))
        .unwrap();
    assert!(matches!(reply, Reply::Stream(_)), "the list streams");
    let rows = reply.finish().unwrap();
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .any(|r| r["dst_address"] == "203.0.114.0/24"),
        "{rows}"
    );
    assert_eq!(generation(&mut s), g + 2);
}

#[test]
fn the_clock_builds_stale_lines_before_its_tick() {
    let mut s = lab();
    let t = 1_900_000_000;
    s.tick(t);
    let g = generation(&mut s);
    assert!(s.route_job(t + 1).is_none(), "fresh: nothing to build");
    ok(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "203.0.113.0/24", "gateway": "10.0.0.1"}),
    );
    let job = s.route_job(t + 1).expect("stale: a build to run");
    job.run();
    s.tick(t + 1);
    assert!(s.route_job(t + 2).is_none());
    assert_eq!(generation(&mut s), g + 1, "the tick took the clock's build");
}
