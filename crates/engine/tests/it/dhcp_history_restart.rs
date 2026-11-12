//! G4.2l — the DHCP lease history (the legal record of who had an address)
//! after a restart. On the notebook (dev.595), after reboots with no client
//! asking, `ip.dhcp-server.history.print` answered `rows: []` with ~3000
//! bindings in the journal: the history loaded only once a binding made its
//! runtime. Now it loads for the first round, or for the command itself,
//! also with the server disabled; and a binding ended by RELEASE is closed.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
use corerouter_engine::storage::MemoryStorage;
use corerouter_hal::VirtualHal;
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn run(s: &mut Session, from_ms: u64, secs: u64) -> u64 {
    let mut ms = from_ms;
    for _ in 0..secs * 4 {
        ms += 250;
        s.tick(1_700_000_000 + ms / 1000);
        s.dhcp_service(ms);
    }
    ms
}

fn boot(storage: &MemoryStorage) -> Session {
    let mut s = Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()));
    s.tick(1_700_000_000);
    s
}

fn history(s: &mut Session) -> Vec<Value> {
    ok(s, "ip.dhcp-server.history.print", json!({"limit": 1000}))["rows"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn the_history_survives_a_restart_with_no_client() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    for (id, p) in [
        (
            "ip.address.add",
            json!({"address": "192.168.88.1/24", "interface": "ether2"}),
        ),
        (
            "ip.pool.add",
            json!({"name": "lan", "ranges": "192.168.88.10-192.168.88.50"}),
        ),
        (
            "ip.dhcp-server.add",
            json!({"interface": "ether2", "address_pool": "lan", "lease_time": "10m"}),
        ),
        (
            "ip.dhcp-server.network.add",
            json!({"address": "192.168.88.0/24", "gateway": "192.168.88.1"}),
        ),
    ] {
        ok(&mut s, id, p);
    }
    let ms = run(&mut s, 0, 5);
    let bound = ok(
        &mut s,
        "ip.dhcp-server.lease.print",
        json!({"status": "bound"}),
    );
    let first = bound[0]["address"].as_str().unwrap().to_owned();
    ok(
        &mut s,
        "ip.dhcp-server.lease.release",
        json!({"address": first}),
    );
    run(&mut s, ms, 2);
    let before = history(&mut s);
    assert!(before.len() >= 2, "{before:?}");
    assert!(
        before
            .iter()
            .any(|r| r["address"] == first.as_str() && r["open"] == false),
        "the released binding is closed: {before:?}"
    );
    drop(s);

    // Restarted, nobody asking yet: the command loads the journal.
    let mut s = boot(&storage);
    let after = history(&mut s);
    assert_eq!(after.len(), before.len(), "{after:?}");
    assert!(
        after
            .iter()
            .any(|r| r["address"] == first.as_str() && r["open"] == false)
    );
    drop(s);

    // Restarted with the server disabled: rounds run, still the record.
    let mut s = boot(&storage);
    ok(
        &mut s,
        "ip.dhcp-server.set",
        json!({"id": "dhcp1", "disabled": true}),
    );
    run(&mut s, 0, 2);
    let off = history(&mut s);
    assert_eq!(off.len(), before.len(), "{off:?}");
    let cfg = ok(&mut s, "ip.dhcp-server.config.print", json!({}));
    assert_eq!(
        cfg["history_entries"].as_u64().unwrap() as usize,
        before.len(),
        "{cfg}"
    );
}
