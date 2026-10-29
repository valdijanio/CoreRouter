//! G2.4 — the fast path: settings, what each port's card offers (the lab's
//! two simulated ConnectX-6 Dx ports), validation, rollback.
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

fn port<'a>(st: &'a Value, name: &str) -> &'a Value {
    st["ports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == name)
        .unwrap_or_else(|| panic!("{name}: {st}"))
}

#[test]
fn off_by_default_and_on_in_software_and_hardware() {
    let mut s = Session::virtual_lab();
    let st = ok(&mut s, "ip.firewall.fastpath.status", json!({}));
    assert_eq!(
        (st["enabled"].as_bool(), st["active"].as_bool()),
        (Some(false), Some(false))
    );
    assert_eq!(port(&st, "ether1")["offload"], "off");
    ok(&mut s, "ip.firewall.fastpath.set", json!({"enabled": true}));
    let st = ok(&mut s, "ip.firewall.fastpath.status", json!({}));
    assert_eq!(st["active"], true);
    assert_eq!(st["hardware"], true, "auto: the switchdev port takes it");
    // A virtual NIC: software only.
    assert_eq!(port(&st, "ether1")["offload"], "software");
    // The legacy ConnectX: software, with the command that switches it.
    let e7 = port(&st, "ether7");
    assert_eq!(
        (e7["offload"].as_str(), e7["eswitch"].as_str()),
        (Some("software"), Some("legacy"))
    );
    assert!(
        e7["fix"]
            .as_str()
            .unwrap()
            .contains("devlink dev eswitch set pci/0000:3b:00.0 mode switchdev"),
        "{e7}"
    );
    // The switchdev representor: hardware.
    let e8 = port(&st, "ether8");
    assert_eq!(
        (e8["offload"].as_str(), e8["representor"].as_bool()),
        (Some("hardware"), Some(true))
    );
    assert!(st["flows"]["software"].as_u64().is_some());
}

#[test]
fn only_named_ports_and_hardware_off() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "ip.firewall.fastpath.set",
        json!({"enabled": true, "interfaces": "ether1,ether2,ether1", "hw_offload": "no"}),
    );
    assert_eq!(
        ok(&mut s, "ip.firewall.fastpath.get", json!({}))["interfaces"],
        json!(["ether1", "ether2"])
    );
    let st = ok(&mut s, "ip.firewall.fastpath.status", json!({}));
    assert_eq!(st["hardware"], false);
    assert_eq!(port(&st, "ether8")["offload"], "off", "not named");
    assert_eq!(port(&st, "ether2")["offload"], "software");
    // Auto on ports without hardware: software, and the state says why.
    ok(
        &mut s,
        "ip.firewall.fastpath.set",
        json!({"hw_offload": "auto"}),
    );
    let st = ok(&mut s, "ip.firewall.fastpath.status", json!({}));
    assert!(
        st["note"].as_str().unwrap().contains("running in software"),
        "{st}"
    );
}

#[test]
fn validation() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "interface.vlan.add",
        json!({"name": "vlan10", "parent": "ether1", "vlan_id": 10}),
    );
    let (p, why) = bad(
        &mut s,
        "ip.firewall.fastpath.set",
        json!({"interfaces": "vlan10"}),
    );
    assert_eq!(p, "interfaces");
    assert!(why.contains("name its port 'ether1'"), "{why}");
    assert_eq!(
        bad(
            &mut s,
            "ip.firewall.fastpath.set",
            json!({"interfaces": "nope9"})
        )
        .0,
        "interfaces"
    );
    assert_eq!(
        bad(
            &mut s,
            "ip.firewall.fastpath.set",
            json!({"hw_offload": "maybe"})
        )
        .0,
        "hw_offload"
    );
    // Required hardware without a port that has it.
    let (p, why) = bad(
        &mut s,
        "ip.firewall.fastpath.set",
        json!({"enabled": true, "interfaces": "ether1", "hw_offload": "yes"}),
    );
    assert_eq!(p, "hw_offload");
    assert!(why.contains("use auto"), "{why}");
    assert!(
        !s.store().candidate().ip.fastpath.enabled,
        "nothing changed"
    );
    ok(
        &mut s,
        "ip.firewall.fastpath.set",
        json!({"enabled": true, "interfaces": "ether8", "hw_offload": "yes"}),
    );
}

#[test]
fn rollback_turns_it_off_again() {
    let mut s = Session::virtual_lab();
    let rev = s.store().current_revision();
    ok(&mut s, "ip.firewall.fastpath.set", json!({"enabled": true}));
    assert_eq!(
        ok(&mut s, "ip.firewall.fastpath.status", json!({}))["active"],
        true
    );
    ok(&mut s, "config.rollback", json!({"revision": rev}));
    let st = ok(&mut s, "ip.firewall.fastpath.status", json!({}));
    assert_eq!(
        (st["enabled"].as_bool(), st["active"].as_bool()),
        (Some(false), Some(false))
    );
}
