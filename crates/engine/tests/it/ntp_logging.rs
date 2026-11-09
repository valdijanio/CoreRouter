//! G4.6: `system.ntp.client.*` and `system.logging.*`: success, validation
//! errors and rollback.
#![allow(clippy::unwrap_used, clippy::panic)]

use corerouter_engine::Session;
use corerouter_engine::logging::routes;
use corerouter_model::ntp::{NtpClient, NtpState, NtpStatus};
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

/// G4.6b: `vrf`, `set_system_clock`, and what a config file can say.
#[test]
fn ntp_client_vrf_and_clock_switch() {
    let mut s = Session::virtual_lab();
    let got = ok(&mut s, "system.ntp.client.get", Value::Null);
    assert_eq!(got["vrf"], "main");
    assert_eq!(got["set_system_clock"], true);
    assert_eq!(got["clock"], "not-set");
    fails(
        &mut s,
        "system.ntp.client.set",
        json!({"vrf": "nope"}),
        "no VRF 'nope'",
    );
    fails(
        &mut s,
        "system.ntp.client.set",
        json!({"vrf": "ether1"}),
        "no VRF 'ether1'",
    );
    ok(&mut s, "ip.vrf.add", json!({"name": "red"}));
    let set = ok(
        &mut s,
        "system.ntp.client.set",
        json!({"vrf": "red", "set_system_clock": false}),
    );
    assert_eq!(set["vrf"], "red");
    assert_eq!(set["set_system_clock"], false);
    assert_eq!(s.store().running().system.ntp_client.vrf, "red");
    // A refused set changes nothing, whatever else it carried.
    fails(
        &mut s,
        "system.ntp.client.set",
        json!({"vrf": "main", "min_poll": 2}),
        "RFC 4330",
    );
    assert_eq!(s.store().running().system.ntp_client.vrf, "red");
    s.execute(
        "system.ntp.client.set",
        &json!({"vrf": "main", "set_system_clock": true}),
    )
    .unwrap();
    assert_eq!(s.store().running().system.ntp_client.vrf, "main");
    // Validation of a hand-edited file.
    let mut cfg = s.store().candidate().clone();
    cfg.system.ntp_client.vrf = "ghost".into();
    let issues = corerouter_engine::validate::validate_all(&cfg);
    assert!(
        issues.iter().any(|i| i.path == "system.ntp_client.vrf"),
        "{issues:?}"
    );
    // Default values stay out of the saved file.
    let saved = serde_json::to_value(NtpClient::default()).unwrap();
    assert!(
        saved.get("vrf").is_none() && saved.get("set_system_clock").is_none(),
        "{saved}"
    );
}

/// G4.6b: a client may rely on a DHCP client's servers.
#[test]
fn ntp_client_without_servers_needs_a_dhcp_client() {
    let mut s = Session::virtual_lab();
    fails(
        &mut s,
        "system.ntp.client.set",
        json!({"enabled": true}),
        "at least one server",
    );
    ok(&mut s, "ip.dhcp-client.add", json!({"interface": "ether1"}));
    ok(&mut s, "system.ntp.client.set", json!({"enabled": true}));
    assert!(s.store().running().system.ntp_client.enabled);
    assert_eq!(
        ok(&mut s, "system.ntp.client.get", Value::Null)["servers"],
        json!([])
    );
}

/// G4.6b: confirming needs something to confirm; the daemon takes it once.
#[test]
fn ntp_step_confirmation() {
    let mut s = Session::virtual_lab();
    fails(
        &mut s,
        "system.ntp.client.confirm-step",
        json!({}),
        "no clock step",
    );
    assert!(!s.take_ntp_step_confirmation());
    ok(
        &mut s,
        "system.ntp.client.set",
        json!({"enabled": true, "servers": ["192.0.2.1"]}),
    );
    s.set_ntp_status(NtpStatus {
        status: NtpState::Synchronized,
        pending_step_ms: Some(5_000_000.0),
        ..NtpStatus::default()
    });
    let got = ok(&mut s, "system.ntp.client.confirm-step", json!({}));
    assert_eq!(got["pending_step_ms"], 5_000_000.0);
    assert!(s.take_ntp_step_confirmation());
    assert!(!s.take_ntp_step_confirmation(), "once");
    // The client off: nothing is pending any more.
    ok(&mut s, "system.ntp.client.set", json!({"enabled": false}));
    fails(
        &mut s,
        "system.ntp.client.confirm-step",
        json!({}),
        "no clock step",
    );
}

/// The health check read a status nobody wrote: an enabled client always
/// said "no daemon".
#[test]
fn health_sees_the_client_state() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "system.ntp.client.set",
        json!({"enabled": true, "servers": ["192.0.2.1"]}),
    );
    s.set_ntp_status(NtpStatus {
        status: NtpState::Synchronized,
        ..NtpStatus::default()
    });
    assert_eq!(s.ntp_status().status, NtpState::Synchronized);
    let health = ok(&mut s, "system.health.check", json!({}));
    let text = health.to_string();
    assert!(text.contains("relógio sincronizado"), "{text}");
}

/// G4.6c: `system.ntp.server.*`.
#[test]
fn ntp_server_settings() {
    let mut s = Session::virtual_lab();
    let got = ok(&mut s, "system.ntp.server.get", Value::Null);
    assert_eq!(got["enabled"], false, "off by default");
    assert_eq!(got["local_clock_stratum"], 5);
    assert_eq!(got["rate_limit"], true);
    assert_eq!(got["listening"], false);
    assert_eq!(got["serving"], "no");
    assert!(got["allowed"].as_array().unwrap().iter().any(|n| n == "192.168.0.0/16"));

    let set = ok(
        &mut s,
        "system.ntp.server.set",
        json!({"enabled": true, "use_local_clock": true, "local_clock_stratum": 8, "allowed": "10.0.0.0/8, 2001:db8::/32"}),
    );
    assert_eq!(set["allowed"], json!(["10.0.0.0/8", "2001:db8::/32"]));
    assert!(s.store().running().system.ntp_server.enabled);

    for (p, needle) in [
        (json!({"local_clock_stratum": 0}), "1..=15"),
        (json!({"local_clock_stratum": 16}), "1..=15"),
        (json!({"allowed": ["not a net"]}), "allowed"),
        (json!({"allowed": (0..65).map(|i| format!("10.{i}.0.0/16")).collect::<Vec<_>>()}), "at most 64"),
        (json!({"broadcast": true}), "at least one address"),
        (json!({"broadcast_addresses": ["nope"]}), "broadcast_addresses"),
        (json!({"broadcast": true, "broadcast_addresses": ["ff02::1"]}), "only IPv4"),
        (json!({"vrf": "ghost"}), "no VRF"),
        (json!({"enable": true}), "did you mean"),
    ] {
        fails(&mut s, "system.ntp.server.set", p, needle);
    }
    ok(
        &mut s,
        "system.ntp.server.set",
        json!({"broadcast": true, "broadcast_addresses": ["192.168.88.255"]}),
    );
    // An empty list is allowed: it answers nobody, the VyOS way of saying no.
    ok(&mut s, "system.ntp.server.set", json!({"allowed": []}));
    let mut cfg = s.store().candidate().clone();
    cfg.system.ntp_server.local_clock_stratum = 0;
    cfg.system.ntp_server.vrf = "ghost".into();
    cfg.system.ntp_server.broadcast_addresses.clear();
    let issues = corerouter_engine::validate::validate_all(&cfg);
    for path in ["local_clock_stratum", "vrf", "broadcast_addresses"] {
        let path = format!("system.ntp_server.{path}");
        assert!(issues.iter().any(|i| i.path == path), "{path}: {issues:?}");
    }
}

/// RouterOS's `using-local-clock`: only with no good answer.
#[test]
fn the_client_reports_the_local_clock() {
    let mut s = Session::virtual_lab();
    ok(
        &mut s,
        "system.ntp.client.set",
        json!({"enabled": true, "servers": ["192.0.2.1"]}),
    );
    s.set_ntp_status(NtpStatus {
        status: NtpState::Waiting,
        ..NtpStatus::default()
    });
    assert_eq!(ok(&mut s, "system.ntp.client.get", Value::Null)["status"], "waiting");
    ok(
        &mut s,
        "system.ntp.server.set",
        json!({"enabled": true, "use_local_clock": true}),
    );
    assert_eq!(
        ok(&mut s, "system.ntp.client.get", Value::Null)["status"],
        "using-local-clock"
    );
    s.set_ntp_status(NtpStatus {
        status: NtpState::Synchronized,
        ..NtpStatus::default()
    });
    assert_eq!(ok(&mut s, "system.ntp.client.get", Value::Null)["status"], "synchronized");
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

/// audit-services #5: a saved file with min_poll > max_poll loaded as is
/// and crashed the NTP client; whole-config validation now names it.
#[test]
fn a_loaded_config_with_bad_poll_bounds_is_reported() {
    let mut cfg = corerouter_model::Config::default();
    assert!(corerouter_engine::validate::validate_all(&cfg).is_empty());
    cfg.system.ntp_client.min_poll = 10;
    cfg.system.ntp_client.max_poll = 6;
    cfg.system.ntp_client.servers = vec!["bad host!".into()];
    let issues: Vec<String> = corerouter_engine::validate::validate_all(&cfg)
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(issues.iter().any(|i| i.contains("max_poll")), "{issues:?}");
    assert!(issues.iter().any(|i| i.contains("servers")), "{issues:?}");
    cfg.system.ntp_client.min_poll = 2;
    cfg.system.ntp_client.max_poll = 6;
    cfg.system.ntp_client.servers.clear();
    let issues = corerouter_engine::validate::validate_all(&cfg);
    assert_eq!(issues.len(), 1, "{issues:?}");
}
