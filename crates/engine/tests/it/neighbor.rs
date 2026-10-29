//! G5.1: `ip.neighbor.*` and the neighbor table.
#![allow(clippy::unwrap_used)]

use corerouter_engine::{MemoryStorage, Session};
use corerouter_hal::VirtualHal;
use corerouter_model::{MgmtPorts, NeighborEntry, NeighborProtocol};
use serde_json::{Value, json};

fn heard(iface: &str, node: &str, protocol: NeighborProtocol, at: u64) -> NeighborEntry {
    NeighborEntry {
        interface: iface.parse().unwrap(),
        protocol,
        mac: Some("02:00:00:00:00:02".parse().unwrap()),
        addresses: vec!["10.0.0.2".parse().unwrap(), "fe80::2".parse().unwrap()],
        identity: format!("r-{node}"),
        version: "0.1.0".into(),
        platform: "CoreRouter".into(),
        board: "x86_64".into(),
        uptime_secs: Some(42),
        node_id: Some(node.into()),
        remote_interface: Some("ether9".into()),
        mgmt: Some(MgmtPorts {
            control: Some(7979),
            ..MgmtPorts::default()
        }),
        last_seen: at,
        hold_secs: 120,
    }
}

fn enable(s: &mut Session, ifaces: &[&str]) -> Value {
    s.execute(
        "ip.neighbor.discovery.set",
        &json!({ "interfaces": ifaces }),
    )
    .unwrap()
}

fn list(s: &mut Session, p: Value) -> Vec<Value> {
    s.execute("ip.neighbor.list", &p)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn defaults_listen_nowhere() {
    let mut s = Session::virtual_lab();
    let d = s
        .execute("ip.neighbor.discovery.get", &Value::Null)
        .unwrap();
    assert_eq!(
        d,
        json!({"enabled": true, "interfaces": [], "interval_secs": 30})
    );
    // Nothing is kept from an interface where discovery is off.
    assert!(!s.record_neighbor(heard("ether1", "a", NeighborProtocol::Crdp, 10)));
    assert!(list(&mut s, Value::Null).is_empty());
}

#[test]
fn set_commits_and_neighbors_follow_the_enabled_interfaces() {
    let mut s = Session::virtual_lab();
    let r = enable(&mut s, &["ether2", "ether1", "ether2"]);
    assert_eq!(r["interfaces"], json!(["ether1", "ether2"]));
    assert_eq!(s.store().current_revision(), 1, "immediate mode commits");

    assert!(s.record_neighbor(heard("ether1", "a", NeighborProtocol::Crdp, 10)));
    assert!(s.record_neighbor(heard("ether2", "b", NeighborProtocol::Lldp, 11)));
    assert!(!s.record_neighbor(heard("ether3", "c", NeighborProtocol::Crdp, 12)));

    let all = list(&mut s, Value::Null);
    assert_eq!(all.len(), 2);
    let a = &all[0];
    assert_eq!(a["interface"], "ether1");
    assert_eq!(a["protocol"], "crdp");
    assert_eq!(a["address"], "10.0.0.2");
    assert_eq!(a["identity"], "r-a");
    assert_eq!(a["mgmt"]["control"], 7979);
    assert_eq!(a["age_secs"], 1, "table clock is the newest record (11)");

    let by_if = list(&mut s, json!({"interface": "ether2"}));
    assert_eq!(by_if.len(), 1);
    assert_eq!(by_if[0]["identity"], "r-b");
    let by_proto = list(&mut s, json!({"protocol": "crdp"}));
    assert_eq!(by_proto.len(), 1);

    // Turning ether2 off hides its neighbors now and drops them on expiry.
    enable(&mut s, &["ether1"]);
    assert_eq!(list(&mut s, Value::Null).len(), 1);
    assert_eq!(s.expire_neighbors(12), 1);
    // And the switch turns everything off.
    s.execute("ip.neighbor.discovery.set", &json!({"enabled": false}))
        .unwrap();
    assert!(list(&mut s, Value::Null).is_empty());
}

#[test]
fn neighbors_expire() {
    let mut s = Session::virtual_lab();
    enable(&mut s, &["ether1"]);
    s.record_neighbor(heard("ether1", "a", NeighborProtocol::Crdp, 1000));
    assert_eq!(s.expire_neighbors(1119), 0);
    let row = &list(&mut s, Value::Null)[0];
    assert_eq!(
        (&row["age_secs"], &row["expires_in_secs"]),
        (&json!(119), &json!(1))
    );
    assert_eq!(s.expire_neighbors(1120), 1);
    assert!(list(&mut s, Value::Null).is_empty());
}

#[test]
fn bad_params_are_refused_and_change_nothing() {
    let mut s = Session::virtual_lab();
    let before = s.store().running().clone();
    for (p, needle) in [
        (json!({"interfaces": ["ether99"]}), "no interface 'ether99'"),
        (json!({"interfaces": "ether1"}), "list of interface names"),
        (json!({"interfaces": [1]}), "must be a string"),
        (json!({"interfaces": ["bad name"]}), "interface name"),
        (json!({"interval_secs": 0}), "1..=3600"),
        (json!({"interval_secs": 3601}), "1..=3600"),
        (json!({"enabled": "yes"}), "true or false"),
        (json!({"interval": 5}), "unknown parameter"),
    ] {
        let e = s
            .execute("ip.neighbor.discovery.set", &p)
            .unwrap_err()
            .to_string();
        assert!(e.contains(needle), "{p}: {e}");
    }
    let e = s
        .execute("ip.neighbor.list", &json!({"protocol": "cdp"}))
        .unwrap_err()
        .to_string();
    assert!(e.contains("crdp, lldp or mndp"), "{e}");
    assert_eq!(s.store().running(), &before);
    assert!(!s.store().is_dirty());
}

#[test]
fn transactional_set_rolls_back_with_discard() {
    let mut s = Session::virtual_lab();
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    enable(&mut s, &["ether1"]);
    // Not committed: the running settings (what the daemon uses) are unchanged.
    assert!(s.discovery_settings().interfaces.is_empty());
    assert!(!s.record_neighbor(heard("ether1", "a", NeighborProtocol::Crdp, 1)));
    s.execute("config.discard", &Value::Null).unwrap();
    let d = s
        .execute("ip.neighbor.discovery.get", &Value::Null)
        .unwrap();
    assert_eq!(d["interfaces"], json!([]));
}

#[test]
fn removing_an_interface_takes_it_off_the_list() {
    let mut s = Session::virtual_lab();
    s.execute("interface.loopback.add", &json!({"name": "lo1"}))
        .unwrap();
    enable(&mut s, &["lo1", "ether1"]);
    s.execute("interface.remove", &json!({"name": "lo1"}))
        .unwrap();
    assert_eq!(
        s.discovery_settings()
            .interfaces
            .iter()
            .map(|i| i.as_str())
            .collect::<Vec<_>>(),
        ["ether1"]
    );
}

#[test]
fn settings_are_saved_and_neighbors_are_not() {
    let storage = MemoryStorage::default();
    let boot = || Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()));
    let mut s = boot();
    s.execute(
        "ip.neighbor.discovery.set",
        &json!({"interfaces": ["ether1"], "interval_secs": 10}),
    )
    .unwrap();
    s.record_neighbor(heard("ether1", "a", NeighborProtocol::Crdp, 1));
    drop(s);
    let mut s = boot();
    assert_eq!(s.discovery_settings().interval_secs, 10);
    assert!(list(&mut s, Value::Null).is_empty());
}
