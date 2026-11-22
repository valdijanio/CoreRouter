//! G6.9 — Tools › IP Calculator: subnets (IPv4 and IPv6, mask forms,
//! /31 and /32), overlaps with the config, split, summarize, range to
//! prefixes, IPv6 prefix delegation, and the CGNAT planner with its
//! suggestions and exports (the same formula the pools use).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::{EngineError, Session};
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn bad(s: &mut Session, id: &str, p: Value) -> String {
    match s.execute(id, &p) {
        Err(EngineError::BadParam { param, .. }) => param,
        other => panic!("{id} {p}: expected a parameter error, got {other:?}"),
    }
}

#[test]
fn subnets_in_every_form() {
    let mut s = Session::virtual_lab();
    let v = ok(
        &mut s,
        "tool.ip-calc.subnet",
        json!({"address": "192.168.10.77/24"}),
    );
    assert_eq!(v["network"], "192.168.10.0/24");
    assert_eq!(v["broadcast"], "192.168.10.255");
    assert_eq!(
        (v["first"].as_str(), v["last"].as_str()),
        (Some("192.168.10.1"), Some("192.168.10.254"))
    );
    assert_eq!(v["hosts"], 254);
    assert_eq!(v["mask"], "255.255.255.0");
    assert_eq!(v["wildcard"], "0.0.0.255");
    assert_eq!(v["scope"], "private (RFC 1918)");
    let v = ok(
        &mut s,
        "tool.ip-calc.subnet",
        json!({"address": "100.64.3.9 255.255.252.0"}),
    );
    assert_eq!(v["network"], "100.64.0.0/22");
    assert_eq!(v["scope"], "shared (RFC 6598, CGNAT)");
    // RFC 3021: a /31 has two usable addresses; a /32 one.
    assert_eq!(
        ok(
            &mut s,
            "tool.ip-calc.subnet",
            json!({"address": "10.0.0.0/31"})
        )["hosts"],
        2
    );
    assert_eq!(
        ok(
            &mut s,
            "tool.ip-calc.subnet",
            json!({"address": "10.0.0.1"})
        )["hosts"],
        1
    );
    let v = ok(
        &mut s,
        "tool.ip-calc.subnet",
        json!({"address": "2001:db8:1::5/64"}),
    );
    assert_eq!(v["family"], "ipv6");
    assert_eq!(v["hosts"], "18446744073709551616");
    for p in [
        "10.0.0.1/33",
        "10.0.0.1 255.0.255.0",
        "nope",
        &"9".repeat(80),
    ] {
        assert_eq!(
            bad(&mut s, "tool.ip-calc.subnet", json!({"address": p})),
            "address",
            "{p}"
        );
    }
}

#[test]
fn overlaps_with_what_is_configured() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "192.168.88.1/24", "interface": "ether1"}),
    );
    ok(
        &mut s,
        "ip.firewall.cgnat.pool.add",
        json!({"name": "c1", "inside": "100.64.0.0/22", "outside": "203.0.113.0/28"}),
    );
    let v = ok(
        &mut s,
        "tool.ip-calc.subnet",
        json!({"address": "192.168.88.128/25"}),
    );
    assert_eq!(v["overlaps"][0]["what"], "address", "{v}");
    let v = ok(
        &mut s,
        "tool.ip-calc.subnet",
        json!({"address": "203.0.113.8/29"}),
    );
    assert_eq!(v["overlaps"][0]["what"], "CGNAT outside", "{v}");
    assert_eq!(
        ok(
            &mut s,
            "tool.ip-calc.subnet",
            json!({"address": "8.8.8.0/24"})
        )["overlaps"],
        json!([])
    );
}

#[test]
fn split_summarize_and_ranges() {
    let mut s = Session::virtual_lab();
    let v = ok(
        &mut s,
        "tool.ip-calc.split",
        json!({"network": "10.0.0.0/22", "prefix": 24}),
    );
    assert_eq!(
        v["subnets"],
        json!(["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"])
    );
    let v = ok(
        &mut s,
        "tool.ip-calc.split",
        json!({"network": "10.0.0.0/16", "count": 5}),
    );
    assert_eq!(
        (v["prefix"].as_u64(), v["total"].as_str()),
        (Some(19), Some("8"))
    );
    assert_eq!(
        bad(
            &mut s,
            "tool.ip-calc.split",
            json!({"network": "10.0.0.0/16", "prefix": 8})
        ),
        "prefix"
    );
    let v = ok(
        &mut s,
        "tool.ip-calc.summarize",
        json!({"prefixes": "10.0.0.0/24,10.0.1.0/24,10.0.3.0/24"}),
    );
    assert_eq!(v["aggregated"], json!(["10.0.0.0/23", "10.0.3.0/24"]));
    assert_eq!(v["supernet"], "10.0.0.0/22");
    assert_eq!(v["extra"], "256");
    assert_eq!(
        bad(
            &mut s,
            "tool.ip-calc.summarize",
            json!({"prefixes": "10.0.0.0/24,2001:db8::/32"})
        ),
        "prefixes"
    );
    let v = ok(
        &mut s,
        "tool.ip-calc.range",
        json!({"first": "10.0.0.1", "last": "10.0.0.6"}),
    );
    assert_eq!(
        v["prefixes"],
        json!(["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"])
    );
    assert_eq!(v["addresses"], "6");
    let v = ok(
        &mut s,
        "tool.ip-calc.range",
        json!({"first": "0.0.0.0", "last": "255.255.255.255"}),
    );
    assert_eq!(v["prefixes"], json!(["0.0.0.0/0"]));
    assert_eq!(
        bad(
            &mut s,
            "tool.ip-calc.range",
            json!({"first": "10.0.0.9", "last": "10.0.0.1"})
        ),
        "last"
    );
}

#[test]
fn prefix_delegation_counts_and_lists() {
    let mut s = Session::virtual_lab();
    let v = ok(
        &mut s,
        "tool.ip-calc.pd",
        json!({"prefix": "2001:db8::/40", "length": 56, "show": 3}),
    );
    assert_eq!(v["count"], "65536");
    assert_eq!(v["customers_per"], "256", "a /56 holds 256 /64s");
    assert_eq!(
        v["first"],
        json!([
            "2001:db8::/56",
            "2001:db8:0:100::/56",
            "2001:db8:0:200::/56"
        ])
    );
    assert_eq!(v["last"], "2001:db8:ff:ff00::/56");
    assert_eq!(
        ok(
            &mut s,
            "tool.ip-calc.pd",
            json!({"prefix": "2001:db8::/40", "length": 60})
        )["count"],
        "1048576"
    );
    assert_eq!(
        bad(
            &mut s,
            "tool.ip-calc.pd",
            json!({"prefix": "10.0.0.0/8", "length": 56})
        ),
        "prefix"
    );
    assert_eq!(
        bad(
            &mut s,
            "tool.ip-calc.pd",
            json!({"prefix": "2001:db8::/40", "length": 32})
        ),
        "length"
    );
}

#[test]
fn the_cgnat_planner_says_what_fits_and_what_to_change() {
    let mut s = Session::virtual_lab();
    // The brief's example: 4096 subscribers, 32 public addresses, 500 ports.
    let v = ok(
        &mut s,
        "tool.ip-calc.cgnat.plan",
        json!({"inside": "4096", "outside": "32", "ports_per_subscriber": 500, "preview": 3}),
    );
    assert_eq!(
        (v["per_address"].as_u64(), v["capacity"].as_u64()),
        (Some(129), Some(4128))
    );
    assert_eq!(v["public_needed"], 32);
    assert_eq!(v["fits"], true);
    assert_eq!(v["preview"].as_array().unwrap().len(), 3);
    assert_eq!(v["preview"][1]["first_port"], 1524);
    assert_eq!(v["pool"]["inside"], json!(["100.64.0.0/20"]));
    // Too few public addresses: it says how many, or how many ports fit.
    let v = ok(
        &mut s,
        "tool.ip-calc.cgnat.plan",
        json!({"inside": "100.64.0.0/20", "outside": "203.0.113.0/28", "ports_per_subscriber": 1000}),
    );
    assert_eq!(v["fits"], false);
    assert!(v.get("pool").is_none());
    let w: Vec<String> = v["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|w| w["suggestion"].as_str().map(str::to_owned))
        .collect();
    assert!(
        w.iter()
            .any(|s| s.contains("add 48 public addresses") && s.contains("252 ports")),
        "{w:?}"
    );
    for p in [
        json!({"inside": "0", "outside": "1"}),
        json!({"inside": "100.64.0.0/22", "outside": "nope"}),
        json!({"inside": "1", "outside": "1", "preview": 5000}),
    ] {
        let key = bad(&mut s, "tool.ip-calc.cgnat.plan", p.clone());
        assert!(
            ["inside", "outside", "preview"].contains(&key.as_str()),
            "{p}"
        );
    }
}

#[test]
fn exports_are_the_pool_table() {
    let mut s = Session::virtual_lab();
    let base =
        json!({"inside": "100.64.0.0/30", "outside": "203.0.113.1", "ports_per_subscriber": 1000});
    let mut p = base.clone();
    p["format"] = json!("csv");
    let v = ok(&mut s, "tool.ip-calc.cgnat.export", p);
    assert_eq!(v["rows"], 4);
    let csv = v["text"].as_str().unwrap();
    assert!(
        csv.starts_with(
            "subscriber,public,first_port,last_port\r\n100.64.0.0,203.0.113.1,1024,2023\r\n"
        ),
        "{csv}"
    );
    let mut p = base.clone();
    p["format"] = json!("routeros");
    let ros = ok(&mut s, "tool.ip-calc.cgnat.export", p)["text"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(ros.contains("add chain=srcnat action=src-nat protocol=tcp src-address=100.64.0.1 to-addresses=203.0.113.1 to-ports=2024-3023"), "{ros}");
    assert_eq!(ros.lines().filter(|l| l.starts_with("add ")).count(), 12);
    let mut p = base.clone();
    p["format"] = json!("nft");
    assert!(
        ok(&mut s, "tool.ip-calc.cgnat.export", p)["text"]
            .as_str()
            .unwrap()
            .contains("snat ip to ip saddr map @d_1")
    );
    let mut p = base.clone();
    p["format"] = json!("text");
    assert!(
        ok(&mut s, "tool.ip-calc.cgnat.export", p)["text"]
            .as_str()
            .unwrap()
            .contains("100.64.0.3       203.0.113.1      4024-5023")
    );
    let mut p = base;
    p["format"] = json!("pdf");
    assert_eq!(bad(&mut s, "tool.ip-calc.cgnat.export", p), "format");
}
