//! G4.9: DHCP leases bound by the real server become dynamic queues
//! (RouterOS: a static lease's `rate-limit`; here also the network's), and
//! a fixed queue over them is warned.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use crate::support;

use std::sync::{Arc, Mutex};

use corerouter_engine::{MemoryStorage, Session};
use serde_json::{Value, json};
use support::dhcp_flood::{self as flood, Flood, FloodHal};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

#[test]
fn bound_leases_become_dynamic_queues() {
    let f: flood::Shared = Arc::new(Mutex::new(Flood {
        per_tick: 16,
        ..Flood::default()
    }));
    let mut s = Session::with_storage(
        Box::new(FloodHal::new(f)),
        Box::new(MemoryStorage::default()),
    );
    s.tick(1_800_000_000);
    for (id, p) in [
        (
            "ip.address.add",
            json!({"address": "10.0.0.1/16", "interface": "ether2"}),
        ),
        (
            "ip.pool.add",
            json!({"name": "subs", "ranges": "10.0.1.0-10.0.255.254"}),
        ),
        (
            "ip.dhcp-server.add",
            json!({"interface": "ether2", "address_pool": "subs", "conflict_detection": false, "client_rate_limit": 0}),
        ),
        (
            "ip.dhcp-server.network.add",
            json!({"address": "10.0.0.0/16", "gateway": "10.0.0.1", "rate_limit": "2M/10M"}),
        ),
        (
            "queue.simple.add",
            json!({"name": "all", "target": "10.0.0.0/16", "max_limit": "1G/1G"}),
        ),
    ] {
        ok(&mut s, id, p);
    }
    s.dhcp_server_driven(true);
    let mut ms = 0;
    for _ in 0..3 {
        ms += 5;
        s.dhcp_server_poll(ms, &|| 0);
    }
    let l = ok(
        &mut s,
        "queue.simple.list",
        json!({"origin": "dhcp-network"}),
    );
    let n = l["total"].as_u64().unwrap();
    assert!(n >= 16, "{l}");
    let row = &l["rows"][0];
    assert_eq!(row["dynamic"], true);
    assert_eq!(row["max_limit"], "2M/10M");
    assert_eq!(row["queue"], "fq-codel-default/fq-codel-default");
    assert!(
        row["name"].as_str().unwrap().starts_with("dhcp-ds<"),
        "{row}"
    );
    assert!(
        row["warnings"]
            .to_string()
            .contains("from fixed queue 'all'"),
        "{row}"
    );
    // A static lease's own rate wins over the network's.
    let ip = row["target"].as_str().unwrap().to_owned();
    ok(
        &mut s,
        "ip.dhcp-server.lease.make-static",
        json!({"address": ip}),
    );
    ok(
        &mut s,
        "ip.dhcp-server.lease.set",
        json!({"id": ip, "rate_limit": "7M/7M"}),
    );
    let l = ok(&mut s, "queue.simple.list", json!({"find": ip.clone()}));
    let mine = l["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["target"] == ip && r["dynamic"] == true)
        .unwrap();
    assert_eq!(mine["origin"], "dhcp-lease");
    assert_eq!(mine["max_limit"], "7M/7M");
    // The fixed queue hears of it too.
    let l = ok(&mut s, "queue.simple.list", json!({"origin": "fixed"}));
    assert!(
        l["rows"][0]["warnings"].to_string().contains("takes"),
        "{l}"
    );
}

/// G4.9c: the modals' previews say what `add`/`set` would do and refuse
/// what they would refuse, without changing anything.
#[test]
fn previews_check_without_changing() {
    let mut s = Session::virtual_lab();
    let p = ok(
        &mut s,
        "queue.simple.preview",
        json!({"name": "ana", "target": "10.0.0.5", "max_limit": "10M/50M"}),
    );
    assert!(p["commands"][0]["command"] == "queue.simple.add", "{p}");
    assert!(p["checks"].as_array().is_some(), "{p}");
    let bad = ok(
        &mut s,
        "queue.simple.preview",
        json!({"target": "10.0.0.5", "max_limit": "lots"}),
    );
    assert!(
        bad["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["level"] == "error"),
        "{bad}"
    );
    let t = ok(
        &mut s,
        "queue.type.preview",
        json!({"name": "pcq-x", "kind": "pcq", "pcq_rate": "5M"}),
    );
    assert!(t["commands"][0]["command"] == "queue.type.add", "{t}");
    let pip = ok(
        &mut s,
        "queue.per-ip.preview",
        json!({"target": "10.0.0.0/24", "rate": "5M"}),
    );
    assert!(pip["commands"].as_array().is_some(), "{pip}");
    assert!(
        s.store().running().queue.simple.is_empty(),
        "nothing applied"
    );
    assert!(
        s.execute("queue.simple.preview", &json!({"nope": 1}))
            .is_err()
    );
}
