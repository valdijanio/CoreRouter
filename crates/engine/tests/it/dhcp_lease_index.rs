//! G0.18: `ip.dhcp-server.lease.add` keeps an index of the leases between
//! adds. Whatever else touches the candidate has to be seen by the next add.

use corerouter_engine::Session;
use serde_json::{Value, json};

fn add(s: &mut Session, ip: &str, mac: u8) -> Result<Value, String> {
    s.execute(
        "ip.dhcp-server.lease.add",
        &json!({"address": ip, "mac_address": format!("02:00:00:00:00:{mac:02x}")}),
    )
    .map_err(|e| e.to_string())
}

#[test]
fn a_duplicate_is_refused_and_leaves_the_list_as_it_was() {
    let mut s = Session::virtual_lab();
    let first = add(&mut s, "10.0.0.5", 1).unwrap();
    let e = add(&mut s, "10.0.0.5", 2).unwrap_err();
    assert!(
        e.contains(&format!(
            "10.0.0.5 is already static lease {}",
            first["id"].as_str().unwrap_or("")
        )),
        "{e}"
    );
    let e = add(&mut s, "10.0.0.6", 1).unwrap_err();
    assert!(e.contains("that client already has static lease"), "{e}");
    assert_eq!(s.store().candidate().ip.dhcp_server.leases.len(), 1);
    // The refused ones did not take the address or the client.
    add(&mut s, "10.0.0.6", 2).unwrap();
}

#[test]
fn the_warning_is_the_same() {
    let mut s = Session::virtual_lab();
    let r = add(&mut s, "10.0.0.5", 1).unwrap();
    assert_eq!(
        r["warnings"],
        json!(["no /ip dhcp-server network holds 10.0.0.5: the client gets no mask nor gateway"])
    );
}

#[test]
fn removing_setting_and_disabling_are_seen() {
    let mut s = Session::virtual_lab();
    let a = add(&mut s, "10.0.0.5", 1).unwrap()["id"].clone();
    s.execute("ip.dhcp-server.lease.remove", &json!({"id": a}))
        .unwrap();
    let b = add(&mut s, "10.0.0.5", 1).unwrap()["id"].clone();

    // Another client on the same lease: the old one is free, the new one taken.
    let c = add(&mut s, "10.0.0.6", 2).unwrap()["id"].clone();
    s.execute(
        "ip.dhcp-server.lease.set",
        &json!({"id": c, "mac_address": "02:00:00:00:00:03"}),
    )
    .unwrap();
    add(&mut s, "10.0.0.7", 2).unwrap();
    assert!(add(&mut s, "10.0.0.8", 3).is_err());

    s.execute(
        "ip.dhcp-server.lease.set",
        &json!({"id": b, "disabled": true}),
    )
    .unwrap();
    add(&mut s, "10.0.0.5", 1).unwrap();
}

#[test]
fn a_discarded_candidate_and_a_failed_batch_are_seen() {
    let mut s = Session::virtual_lab();
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    add(&mut s, "10.0.0.5", 1).unwrap();
    s.execute("config.discard", &json!({})).unwrap();
    add(&mut s, "10.0.0.5", 1).unwrap();
    s.execute("config.discard", &json!({})).unwrap();
    s.execute("config.mode.set", &json!({"mode": "immediate"}))
        .unwrap();

    let steps = json!([
        {"command": "ip.dhcp-server.lease.add", "params": {"address": "10.0.0.9", "mac_address": "02:00:00:00:00:09"}},
        {"command": "ip.dhcp-server.lease.add", "params": {"address": "10.0.0.9", "mac_address": "02:00:00:00:00:0a"}},
    ]);
    let _ = s.batch(&steps, true);
    assert!(s.store().candidate().ip.dhcp_server.leases.is_empty());
    add(&mut s, "10.0.0.9", 9).unwrap();
    add(&mut s, "10.0.0.10", 10).unwrap();
}

/// G0.18: the import the gap is about, as the whole batch. A loose bound
/// (the budget is 1 s in release; this is a dev build on a shared machine).
#[test]
fn ten_thousand_leases_do_not_walk_the_list_each() {
    let steps: Vec<Value> = (0..10_000u32)
        .map(|i| {
            json!({"command": "ip.dhcp-server.lease.add", "params": {
                "address": std::net::Ipv4Addr::from(0x0a00_0000 + i).to_string(),
                "mac_address": format!("02:00:00:{:02x}:{:02x}:{:02x}", (i >> 16) & 255, (i >> 8) & 255, i & 255),
            }})
        })
        .collect();
    let mut s = Session::virtual_lab();
    let t = std::time::Instant::now();
    s.batch(&Value::Array(steps), true).unwrap();
    assert!(t.elapsed().as_secs() < 30, "{:?}", t.elapsed());
    assert_eq!(s.store().running().ip.dhcp_server.leases.len(), 10_000);
}
