//! G4.6: `system.ntp.client.*` and `system.logging.*`: success, validation
//! errors and rollback.
#![allow(clippy::unwrap_used, clippy::panic)]

use corerouter_engine::Session;
use corerouter_engine::logging::routes;
use corerouter_model::ntp::{NtpState, NtpStatus};
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

/// The command fails, the message contains `needle`, and nothing changed.
fn fails(s: &mut Session, id: &str, p: Value, needle: &str) {
    let before = s.store().candidate().clone();
    let err = s.execute(id, &p).unwrap_err().to_string();
    assert!(err.contains(needle), "{id} {p}: {err}");
    assert_eq!(s.store().candidate(), &before);
}

#[test]
fn ntp_client_settings() {
    let mut s = Session::virtual_lab();
    let got = ok(&mut s, "system.ntp.client.get", Value::Null);
    assert_eq!(got["enabled"], false);
    assert_eq!(got["status"], "stopped");
    assert_eq!(got["min_poll"], 6);

    let set = ok(
        &mut s,
        "system.ntp.client.set",
        json!({"enabled": true, "servers": "pool.ntp.org, 192.0.2.1,pool.ntp.org"}),
    );
    assert_eq!(set["servers"], json!(["pool.ntp.org", "192.0.2.1"]));
    assert!(s.store().running().system.ntp_client.enabled);

    fails(
        &mut s,
        "system.ntp.client.set",
        json!({"min_poll": 4}),
        "RFC 4330 §5",
    );
    fails(
        &mut s,
        "system.ntp.client.set",
        json!({"min_poll": 12}),
        "must not be above max_poll",
    );
    fails(
        &mut s,
        "system.ntp.client.set",
        json!({"servers": ["bad host"]}),
        "not a valid DNS label",
    );
    fails(
        &mut s,
        "system.ntp.client.set",
        json!({"servers": []}),
        "at least one server",
    );
    fails(
        &mut s,
        "system.ntp.client.set",
        json!({"servers": (1..=9).map(|i| format!("192.0.2.{i}")).collect::<Vec<_>>()}),
        "at most 8",
    );
    fails(
        &mut s,
        "system.ntp.client.set",
        json!({"server": "x"}),
        "did you mean",
    );
}

#[test]
fn ntp_status_comes_from_the_daemon_and_stops_with_the_client() {
    let mut s = Session::virtual_lab();
    let synced = NtpStatus {
        status: NtpState::Synchronized,
        synced_server: Some("192.0.2.1".into()),
        synced_stratum: Some(2),
        system_offset_ms: Some(-3.25),
        ..NtpStatus::default()
    };
    // Disabled: a late report is ignored.
    s.set_ntp_status(synced.clone());
    assert_eq!(
        ok(&mut s, "system.ntp.client.get", Value::Null)["status"],
        "stopped"
    );
    ok(
        &mut s,
        "system.ntp.client.set",
        json!({"enabled": true, "servers": ["192.0.2.1"]}),
    );
    s.set_ntp_status(synced);
    let got = ok(&mut s, "system.ntp.client.get", Value::Null);
    assert_eq!(got["status"], "synchronized");
    assert_eq!(got["system_offset_ms"], -3.25);
    assert_eq!(got["synced_stratum"], 2);
    ok(&mut s, "system.ntp.client.set", json!({"enabled": false}));
    assert_eq!(
        ok(&mut s, "system.ntp.client.get", Value::Null)["status"],
        "stopped"
    );
}

#[test]
fn logging_actions_and_rules() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "system.logging.action.add",
        json!({"name": "siem", "remote": "192.0.2.10", "syslog_facility": "local3"}),
    );
    let list = ok(&mut s, "system.logging.action.list", Value::Null);
    assert_eq!(list[0]["name"], "memory");
    assert_eq!(list[0]["memory_lines"], 1000);
    assert_eq!(
        list[1],
        json!({"name": "siem", "target": "remote", "default": false, "memory_lines": null,
               "remote": "192.0.2.10", "remote_port": 514, "src_address": null,
               "syslog_facility": "local3", "syslog_severity": "auto", "comment": ""})
    );
    // The four default rules (RouterOS): info, error, warning, critical → memory.
    let rules = ok(&mut s, "system.logging.list", Value::Null);
    assert_eq!(rules.as_array().unwrap().len(), 4);
    assert_eq!(rules[0]["action"], "memory");
    let id = ok(
        &mut s,
        "system.logging.add",
        json!({"topics": "info,!debug", "action": "siem", "prefix": "r1"}),
    )["id"]
        .clone();
    assert_eq!(id, "*5");
    ok(
        &mut s,
        "system.logging.add",
        json!({"topics": ["error"], "action": "siem"}),
    );
    ok(
        &mut s,
        "system.logging.action.set",
        json!({"name": "siem", "remote_port": 5514, "syslog_severity": "warning"}),
    );
    let a = &s.store().running().system.logging.actions[0];
    assert_eq!(a.remote_port, 5514);

    // Every config change after that is an event the rules send once.
    let ev = s.log_since(0).pop().unwrap();
    assert_eq!(ev.detail["command"], "system.logging.action.set");
    let to = routes(&s.store().running().system.logging, &ev);
    assert_eq!(to.len(), 1, "two rules, one action: one datagram");
    assert_eq!(to[0].prefix, "r1");

    ok(
        &mut s,
        "system.logging.set",
        json!({"id": "*2", "disabled": true}),
    );
    assert!(s.store().running().system.logging.rules[1].disabled);
}

#[test]
fn logging_validation() {
    let mut s = Session::virtual_lab();
    fails(
        &mut s,
        "system.logging.action.add",
        json!({"name": "a", "remote": "0.0.0.0"}),
        "not 0.0.0.0",
    );
    fails(
        &mut s,
        "system.logging.action.add",
        json!({"name": "a b", "remote": "192.0.2.1"}),
        "letters, digits",
    );
    fails(
        &mut s,
        "system.logging.action.add",
        json!({"name": "a", "remote": "192.0.2.1", "src_address": "2001:db8::1"}),
        "different IP families",
    );
    fails(
        &mut s,
        "system.logging.action.add",
        json!({"name": "a", "remote": "192.0.2.1", "syslog_facility": "local9"}),
        "local0..local7",
    );
    fails(
        &mut s,
        "system.logging.action.add",
        json!({"name": "a", "remote": "192.0.2.1", "remote_port": 0}),
        "1..=65535",
    );
    fails(
        &mut s,
        "system.logging.add",
        json!({"topics": ["info"], "action": "nope"}),
        "no logging action 'nope'",
    );
    ok(
        &mut s,
        "system.logging.action.add",
        json!({"name": "a", "remote": "2001:db8::5"}),
    );
    fails(
        &mut s,
        "system.logging.action.add",
        json!({"name": "a", "remote": "192.0.2.1"}),
        "already exists",
    );
    fails(
        &mut s,
        "system.logging.add",
        json!({"topics": ["inf"], "action": "a"}),
        "unknown topic 'inf'",
    );
    fails(
        &mut s,
        "system.logging.add",
        json!({"topics": ["!debug"], "action": "a"}),
        "only exclusions",
    );
    ok(
        &mut s,
        "system.logging.add",
        json!({"topics": ["info"], "action": "a"}),
    );
    fails(
        &mut s,
        "system.logging.action.remove",
        json!({"name": "a"}),
        "used by logging rule *5",
    );
    fails(
        &mut s,
        "system.logging.remove",
        json!({"id": "*9"}),
        "no logging rule *9",
    );
}

#[test]
fn logging_remove_and_rollback() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "system.logging.action.add",
        json!({"name": "a", "remote": "192.0.2.1"}),
    );
    ok(
        &mut s,
        "system.logging.add",
        json!({"topics": ["info"], "action": "a"}),
    );
    let rev = s.store().current_revision();
    ok(&mut s, "system.logging.remove", json!({"id": "*5"}));
    ok(&mut s, "system.logging.action.remove", json!({"name": "a"}));
    assert!(s.store().running().system.logging.actions.is_empty());
    ok(&mut s, "config.rollback", json!({"revision": rev}));
    let l = &s.store().running().system.logging;
    assert_eq!(l.actions.len(), 1);
    assert_eq!(l.rules[4].action, "a");
    // Ids are never reused.
    ok(&mut s, "system.logging.remove", json!({"id": "*5"}));
    let id = ok(
        &mut s,
        "system.logging.add",
        json!({"topics": ["info"], "action": "a"}),
    );
    assert_eq!(id["id"], "*6");
}

#[test]
fn the_memory_action_is_built_in() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "system.logging.action.set",
        json!({"name": "memory", "memory_lines": 50}),
    );
    assert_eq!(s.store().running().system.logging.memory_lines, 50);
    fails(
        &mut s,
        "system.logging.action.set",
        json!({"name": "memory", "memory_lines": 0}),
        "1..=65535",
    );
    fails(
        &mut s,
        "system.logging.action.set",
        json!({"name": "memory", "remote": "192.0.2.1"}),
        "only takes memory_lines",
    );
    fails(
        &mut s,
        "system.logging.action.remove",
        json!({"name": "memory"}),
        "cannot be removed",
    );
    fails(
        &mut s,
        "system.logging.action.add",
        json!({"name": "memory", "remote": "192.0.2.1"}),
        "already exists",
    );
    ok(
        &mut s,
        "system.logging.action.add",
        json!({"name": "siem", "remote": "192.0.2.1"}),
    );
    fails(
        &mut s,
        "system.logging.action.set",
        json!({"name": "siem", "memory_lines": 10}),
        "only the memory action",
    );
    // A rule may send to memory; disabling the defaults empties the log.
    ok(
        &mut s,
        "system.logging.add",
        json!({"topics": ["dhcp", "debug"], "action": "memory"}),
    );
    for id in ["*1", "*2", "*3", "*4"] {
        ok(
            &mut s,
            "system.logging.set",
            json!({"id": id, "disabled": true}),
        );
    }
    ok(&mut s, "log.clear", json!({}));
    let rows = ok(&mut s, "log.print", json!({}));
    assert_eq!(rows, json!([]), "log.clear is info: no rule sends it now");
}

#[test]
fn settings_survive_a_save_and_reload() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "system.ntp.client.set",
        json!({"enabled": true, "servers": ["192.0.2.1"], "max_poll": 12}),
    );
    ok(
        &mut s,
        "system.logging.action.add",
        json!({"name": "a", "remote": "192.0.2.1"}),
    );
    let cfg = s.store().running().clone();
    let text = serde_json::to_string(&cfg).unwrap();
    let back: corerouter_model::Config = serde_json::from_str(&text).unwrap();
    assert_eq!(back, cfg);
    // A default config writes neither section (older files stay the same).
    let plain = serde_json::to_value(corerouter_model::Config::default()).unwrap();
    assert_eq!(plain["system"], json!({"identity": "CoreRouter"}));
}
