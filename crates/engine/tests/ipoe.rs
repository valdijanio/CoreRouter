//! G4.3f — IPoE in the engine, without the daemon: a DHCP server with
//! `ipoe=yes` serves the lab's hosts (`proto_dhcp::lab_hosts`) only as
//! `/ppp secret` with `service=ipoe` allows (`ipoe_unknown=reject`), with
//! the secret's fixed address; the commands validate the new fields.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
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

fn bound(s: &mut Session) -> Vec<Value> {
    ok(s, "ip.dhcp-server.lease.print", json!({"status": "bound"}))
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn only_the_secrets_hosts_are_served() {
    let mut s = Session::virtual_lab();
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
            json!({"interface": "ether2", "address_pool": "lan", "ipoe": true, "ipoe_unknown": "reject"}),
        ),
        (
            "ip.dhcp-server.network.add",
            json!({"address": "192.168.88.0/24", "gateway": "192.168.88.1"}),
        ),
        // The lab's first host behind ether2 (`lab_hosts`: 02:1a:b0:<port>:00:<n>).
        (
            "ppp.secret.add",
            json!({"name": "02:1A:B0:02:00:01", "service": "ipoe", "remote_address": "192.168.88.77"}),
        ),
    ] {
        ok(&mut s, id, p);
    }
    run(&mut s, 0, 10);
    let rows = bound(&mut s);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["address"], "192.168.88.77");
    let st = ok(&mut s, "ip.dhcp-server.statistics.print", json!({}));
    let text = st.to_string();
    assert!(text.contains("rejected"), "{text}");
    // Open the network: everyone is served (sessions for all).
    ok(
        &mut s,
        "ip.dhcp-server.set",
        json!({"id": "dhcp1", "ipoe_unknown": "accept"}),
    );
    run(&mut s, 10_000, 60);
    assert!(bound(&mut s).len() >= 3, "{:?}", bound(&mut s));
}

#[test]
fn the_new_fields_are_validated_and_printed() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.1.0.1/24", "interface": "ether3"}),
    );
    let r = ok(
        &mut s,
        "ip.dhcp-server.add",
        json!({"interface": "ether3", "use_radius": "yes"}),
    );
    // No /radius server with service=dhcp: warned, not refused.
    assert!(r["warnings"].to_string().contains("radius"), "{r}");
    for bad in [
        json!({"use_radius": "maybe"}),
        json!({"ipoe_username": "nickname"}),
        json!({"ipoe_unknown": "drop"}),
    ] {
        let mut p = bad.clone();
        p["id"] = json!("dhcp1");
        let e = s.execute("ip.dhcp-server.set", &p).unwrap_err().to_string();
        assert!(e.contains("expected"), "{bad}: {e}");
    }
    let rows = ok(&mut s, "ip.dhcp-server.print", json!({}));
    assert_eq!(rows[0]["use_radius"], "yes");
    assert_eq!(rows[0]["ipoe"], true, "use_radius implies sessions");
    assert_eq!(rows[0]["ipoe_username"], "mac");
    // A lease rate-limit is parsed as RouterOS' and warned off an ipoe server.
    let e = s
        .execute("ip.dhcp-server.lease.add", &json!({"address": "10.1.0.5", "mac_address": "02:00:00:00:00:05", "rate_limit": "fast"}))
        .unwrap_err()
        .to_string();
    assert!(e.contains("rate_limit"), "{e}");
    ok(
        &mut s,
        "ip.dhcp-server.lease.add",
        json!({"address": "10.1.0.5", "mac_address": "02:00:00:00:00:05", "rate_limit": "10M/50M"}),
    );
    let rows = ok(&mut s, "ip.dhcp-server.lease.print", json!({}));
    assert_eq!(rows[0]["rate_limit"], "10M/50M");
    // A secret for IPoE needs no password, and service=any does not match it.
    let r = ok(
        &mut s,
        "ppp.secret.add",
        json!({"name": "02:00:00:00:00:05", "service": "ipoe"}),
    );
    assert_eq!(r["warnings"], json!([]), "{r}");
    // Rollback: a discarded change leaves the field as it was.
    ok(&mut s, "config.mode.set", json!({"mode": "transactional"}));
    ok(
        &mut s,
        "ip.dhcp-server.set",
        json!({"id": "dhcp1", "use_radius": "no"}),
    );
    ok(&mut s, "config.discard", json!({}));
    let rows = ok(&mut s, "ip.dhcp-server.print", json!({}));
    assert_eq!(rows[0]["use_radius"], "yes");
}
