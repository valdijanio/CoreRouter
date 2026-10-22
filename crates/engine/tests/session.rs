use corerouter_engine::{EngineError, Session};
use serde_json::json;

fn lab() -> Session {
    Session::virtual_lab()
}

#[test]
fn immediate_mode_commits_each_command() {
    let mut s = lab();
    let r = s
        .execute(
            "ip.address.add",
            &json!({"address": "10.0.0.1/24", "interface": "ether1"}),
        )
        .unwrap();
    assert_eq!(r["id"], "*1");
    assert_eq!(s.store().current_revision(), 1);
    assert!(!s.store().is_dirty());
    assert_eq!(s.store().running().ip.addresses.len(), 1);
}

#[test]
fn transactional_mode_needs_commit() {
    let mut s = lab();
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    s.execute(
        "routing.bgp.instance.set",
        &json!({"asn": 65000, "router_id": "10.255.0.1"}),
    )
    .unwrap();
    assert!(s.store().is_dirty());
    assert!(s.store().running().routing.bgp.is_empty());
    // Cannot go back to immediate with pending changes.
    assert!(
        s.execute("config.mode.set", &json!({"mode": "immediate"}))
            .is_err()
    );
    let r = s
        .execute("config.commit", &json!({"comment": "bgp"}))
        .unwrap();
    assert_eq!(r["revision"], 1);
    assert_eq!(s.store().running().routing.bgp.len(), 1);
}

#[test]
fn failed_validation_leaves_state_untouched() {
    let mut s = lab();
    let err = s
        .execute(
            "routing.bgp.instance.set",
            &json!({"asn": 23456, "router_id": "10.0.0.1"}),
        )
        .unwrap_err();
    assert!(matches!(err, EngineError::Validation(_)), "{err}");
    assert!(s.store().candidate().routing.bgp.is_empty());
    assert_eq!(s.store().current_revision(), 0);
}

#[test]
fn unknown_param_suggests_fix() {
    let mut s = lab();
    let err = s
        .execute(
            "ip.address.add",
            &json!({"adress": "10.0.0.1/24", "interface": "ether1"}),
        )
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "unknown parameter 'adress'; did you mean 'address'?"
    );
    let err = s.execute("ip.adress.add", &json!({})).unwrap_err();
    assert!(err.to_string().contains("did you mean 'ip.address.add'"));
}

#[test]
fn disabled_reason_is_reported() {
    let mut s = lab();
    let err = s.execute("config.commit", &json!({})).unwrap_err();
    assert_eq!(
        err.to_string(),
        "command 'config.commit' is disabled: no pending changes"
    );
}

#[test]
fn rollback_restores_old_revision() {
    let mut s = lab();
    s.execute("system.identity.set", &json!({"name": "edge-1"}))
        .unwrap();
    s.execute("config.rollback", &json!({"revision": 0}))
        .unwrap();
    assert_eq!(s.store().running().system.identity, "CoreRouter");
    assert_eq!(s.store().current_revision(), 2);
}

#[test]
fn atomic_batch_with_refs() {
    let mut s = lab();
    let r = s
        .batch(
            &json!([
                {"command": "ip.address.add", "params": {"address": "10.0.0.1/24", "interface": "ether1"}},
                {"command": "ip.address.remove", "params": {"id": "$1.id"}},
                {"command": "ip.address.add", "params": {"address": "10.0.1.1/24", "interface": "ether2"}},
            ]),
            true,
        )
        .unwrap();
    assert_eq!(r["results"].as_array().unwrap().len(), 3);
    assert_eq!(s.store().running().ip.addresses.len(), 1);
    assert_eq!(s.store().current_revision(), 1, "one commit for the batch");

    let err = s
        .batch(
            &json!([
                {"command": "system.identity.set", "params": {"name": "x"}},
                {"command": "ip.address.add", "params": {"address": "bad", "interface": "ether1"}},
            ]),
            true,
        )
        .unwrap_err();
    assert!(matches!(err, EngineError::Batch { step: 2, .. }));
    assert_eq!(s.store().running().system.identity, "CoreRouter");
    assert!(!s.store().is_dirty());
}

#[test]
fn inspect_paths() {
    let s = lab();
    let summary = s.inspect(None).unwrap();
    assert_eq!(summary["counts"]["interfaces"], 8);
    assert!(s.inspect(Some("interfaces.ether1")).unwrap().is_object());
    assert!(s.inspect(Some("nope")).is_err());
}
