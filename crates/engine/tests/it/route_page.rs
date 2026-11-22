//! G1.27c — IP › Routes for a full table: `ip.route.page` filters,
//! searches by prefix (exact / longer / orlonger / covering), aggregates by
//! /16 and pages in the engine, from lines kept between reads, with the
//! counts of the whole table.
// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

/// ether1 = 10.0.0.2/24 + 2001:db8::2/64; routes: a default, 192.0.2.0/24
/// and its /25 halves, 198.51.100.0/24, 10 /24s inside 172.16.0.0/16 and
/// 172.16.0.0/16 itself, an IPv6 default and a /48.
fn lab() -> Session {
    let mut s = Session::virtual_lab();
    for a in ["10.0.0.2/24", "2001:db8::2/64"] {
        ok(
            &mut s,
            "ip.address.add",
            json!({"address": a, "interface": "ether1"}),
        );
    }
    let mut dsts: Vec<String> = [
        "0.0.0.0/0",
        "192.0.2.0/24",
        "192.0.2.0/25",
        "192.0.2.128/25",
        "198.51.100.0/24",
        "172.16.0.0/16",
    ]
    .iter()
    .map(|d| (*d).to_owned())
    .collect();
    dsts.extend((0..10).map(|i| format!("172.16.{i}.0/24")));
    for d in dsts {
        ok(
            &mut s,
            "ip.route.add",
            json!({"dst_address": d, "gateway": "10.0.0.1"}),
        );
    }
    for d in ["::/0", "2001:db8:aa::/48"] {
        ok(
            &mut s,
            "ip.route.add",
            json!({"dst_address": d, "gateway": "2001:db8::1"}),
        );
    }
    s
}

fn page(s: &mut Session, p: Value) -> Value {
    ok(s, "ip.route.page", p)
}

fn dsts(v: &Value) -> Vec<String> {
    v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["dst_address"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn prefix_search_like_junos_exact_longer_orlonger() {
    let mut s = lab();
    let p =
        |s: &mut Session, m: &str| dsts(&page(s, json!({"prefix": "192.0.2.0/24", "match": m})));
    assert_eq!(p(&mut s, "exact"), ["192.0.2.0/24"]);
    assert_eq!(p(&mut s, "longer"), ["192.0.2.0/25", "192.0.2.128/25"]);
    assert_eq!(
        p(&mut s, "orlonger"),
        ["192.0.2.0/24", "192.0.2.0/25", "192.0.2.128/25"]
    );
    assert_eq!(p(&mut s, "covering"), ["0.0.0.0/0", "192.0.2.0/24"]);
    // An address: the routes that contain it (a lookup's candidates).
    assert_eq!(
        dsts(&page(&mut s, json!({"prefix": "192.0.2.200"}))),
        ["0.0.0.0/0", "192.0.2.0/24", "192.0.2.128/25"]
    );
    // A prefix alone: what it contains.
    assert_eq!(
        page(&mut s, json!({"prefix": "172.16.0.0/16"}))["total"],
        11
    );
    // IPv6 never matches an IPv4 prefix and back.
    assert_eq!(
        dsts(&page(&mut s, json!({"prefix": "2001:db8:aa::1"}))),
        ["::/0", "2001:db8:aa::/48"]
    );
}

#[test]
fn aggregate_folds_what_is_longer_than_a_16_and_opens_on_demand() {
    let mut s = lab();
    let v = page(
        &mut s,
        json!({"aggregate": true, "family": "ipv4", "origin": "static"}),
    );
    let rows = v["rows"].as_array().unwrap();
    let b: Vec<&Value> = rows.iter().filter(|r| r["bucket"] == true).collect();
    let names: Vec<&str> = b
        .iter()
        .map(|r| r["dst_address"].as_str().unwrap())
        .collect();
    // 198.51.100.0/24 is alone in its /16: shown as itself.
    assert_eq!(names, ["172.16.0.0/16", "192.0.0.0/16"], "{v}");
    assert_eq!((&b[0]["routes"], &b[0]["active"]), (&json!(10), &json!(10)));
    assert_eq!(b[1]["routes"], 3);
    // 0.0.0.0/0 and 172.16.0.0/16 stay as routes; the /24s fold.
    assert_eq!(
        dsts(&v),
        [
            "0.0.0.0/0",
            "172.16.0.0/16",
            "172.16.0.0/16",
            "192.0.0.0/16",
            "198.51.100.0/24"
        ]
    );
    assert_eq!(v["total"], 5);
    // Opening a bucket: its routes, by asking for the prefix.
    let open = page(
        &mut s,
        json!({"prefix": "172.16.0.0/16", "match": "longer"}),
    );
    assert_eq!(open["total"], 10);
}

#[test]
fn pages_count_everything_and_cut_the_rows() {
    let mut s = lab();
    let all = page(&mut s, json!({"limit": 5000}));
    let total = all["total"].as_u64().unwrap();
    assert_eq!(total as usize, all["rows"].as_array().unwrap().len());
    let first = page(&mut s, json!({"limit": 4}));
    let second = page(&mut s, json!({"limit": 4, "offset": 4}));
    assert_eq!(
        (&first["total"], &first["offset"]),
        (&json!(total), &json!(0))
    );
    assert_eq!(first["rows"].as_array().unwrap().len(), 4);
    assert_eq!(
        dsts(&second)[..],
        dsts(&all)[4..8],
        "the second page follows the first"
    );
    let past = page(&mut s, json!({"offset": 1000}));
    assert_eq!(past["rows"], json!([]));
    assert_eq!(past["total"], json!(total));
    // Counts of the whole table, whatever the filter.
    let sum = &page(&mut s, json!({"family": "ipv6", "limit": 1}))["summary"];
    assert_eq!(sum["total"], json!(total));
    assert_eq!(sum["origins"]["static"], 18);
    assert_eq!(
        sum["ipv6"].as_u64().unwrap() + sum["ipv4"].as_u64().unwrap(),
        total
    );
    assert_eq!(sum["tables"]["main"], json!(total));
    // Several origins at once.
    let c = page(&mut s, json!({"origin": "connected,static"}))["total"].clone();
    assert_eq!(c, json!(total));
}

#[test]
fn the_kept_lines_follow_every_change() {
    let mut s = lab();
    let g1 = page(&mut s, json!({"limit": 1}))["generation"].clone();
    let g2 = page(&mut s, json!({"limit": 1}))["generation"].clone();
    assert_eq!(g1, g2, "nothing changed: the same lines");
    ok(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "203.0.113.0/24", "gateway": "10.0.0.1", "distance": 3}),
    );
    let v = page(
        &mut s,
        json!({"prefix": "203.0.113.0/24", "match": "exact"}),
    );
    assert_ne!(v["generation"], g2);
    assert_eq!(v["total"], 1);
    // A transaction's change shows at once too (the candidate changed).
    ok(&mut s, "config.mode.set", json!({"mode": "transactional"}));
    ok(
        &mut s,
        "ip.route.set",
        json!({"id": "*13", "disabled": true}),
    );
    let r = page(
        &mut s,
        json!({"prefix": "203.0.113.0/24", "match": "exact"}),
    );
    assert_eq!(r["rows"][0]["state"], "inactive");
    // And the list and the page agree.
    let list = ok(&mut s, "ip.route.list", json!({}));
    assert_eq!(
        list.as_array().unwrap().len() as u64,
        page(&mut s, json!({"limit": 1}))["total"].as_u64().unwrap()
    );
}

#[test]
fn page_refuses_bad_requests() {
    let mut s = lab();
    for (p, needle) in [
        (json!({"limit": 0}), "must be 1..=5000"),
        (json!({"limit": 5001}), "must be 1..=5000"),
        (json!({"match": "longer"}), "needs a prefix"),
        (
            json!({"prefix": "192.0.2.0/24", "match": "near"}),
            "not one of exact",
        ),
        (json!({"prefix": "300.0.0.0/8"}), "prefix"),
        (json!({"origin": "static,bgpx"}), "'bgpx' is not one of"),
        (json!({"state": "up"}), "not one of active"),
        (json!({"offset": -1}), "offset"),
        (json!({"page": 2}), "unknown parameter 'page'"),
    ] {
        let err = s.execute("ip.route.page", &p).unwrap_err().to_string();
        assert!(err.contains(needle), "{p}: '{err}' lacks '{needle}'");
    }
}
