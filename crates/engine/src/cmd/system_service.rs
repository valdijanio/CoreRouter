//! `/system service` (G0.10): the daemon's services under its supervisor —
//! state, uptime, restarts, sockets, last event — and start, stop, restart,
//! reset-failures. Not RouterOS `/ip service` (management ports): closer to
//! pfSense's Status › Services and `systemctl`.
//!
//! The engine has no threads: the daemon's supervisor publishes its rows in
//! the session (`ServiceTable`, through `ext_mut`) every tick and takes the
//! requests these commands queue. Without a daemon (lab, browser) the list
//! is empty and an action says why. `stop` lasts until the daemon restarts
//! and never touches the config (the config command that turns a service
//! off is in the row's `enable`).

use corerouter_model::service::{MAX_REQUESTS, ServiceAction, ServiceRequest, ServiceTable};
use serde_json::{Value, json};

use super::args::{opt_str, req_str};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

/// Longest service name accepted (they are short words).
const MAX_NAME: usize = 64;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "system.service.print", "Services", ["System", "Services"], None,
        "{name?: string} → [{name, state: disabled|starting|running|restarting|stopped|failed, reason, restart_in_secs, uptime_secs, restarts, recent_failures, threads, heartbeat_age_ms, listen: [{proto, address, scope: all|local|lan|public}], last_event, last_error, depends, enable, topic, policy, protected}]",
        always, print)
    .positional("name"),
    cmd!("system.service.start", "Start Service", [], None,
        "{name: string} → {name, action, state}",
        always, start)
    .positional("name"),
    cmd!("system.service.stop", "Stop Service", [], None,
        "{name: string} → {name, action, state}",
        always, stop)
    .positional("name"),
    cmd!("system.service.restart", "Restart Service", [], None,
        "{name: string} → {name, action, state}",
        always, restart)
    .positional("name"),
    cmd!("system.service.reset-failures", "Reset Service Failures", [], None,
        "{name: string} → {name, action, state}",
        always, reset_failures)
    .positional("name"),
];

fn table(s: &Session) -> Option<&ServiceTable> {
    s.ext::<ServiceTable>().filter(|t| t.supervised)
}

fn print(s: &mut Session, p: &Value) -> Result<Value> {
    let name = opt_str(p, "name")?;
    let Some(t) = table(s) else {
        return Ok(json!([]));
    };
    let rows: Vec<_> = t
        .rows
        .iter()
        .filter(|r| name.is_none_or(|n| r.name == n))
        .collect();
    if let Some(n) = name
        && rows.is_empty()
    {
        return Err(unknown(t, n));
    }
    serde_json::to_value(rows).map_err(|e| EngineError::Internal(e.to_string()))
}

fn unknown(t: &ServiceTable, name: &str) -> EngineError {
    let names: Vec<&str> = t.rows.iter().map(|r| r.name.as_str()).collect();
    let shown: String = name.chars().take(MAX_NAME).collect();
    let hint = crate::error::suggest(name, names.iter().copied())
        .map(|s| format!("did you mean '{s}'? "))
        .unwrap_or_default();
    EngineError::bad(
        "name",
        format!("no service '{shown}'; {hint}services: {}", names.join(", ")),
    )
}

/// Queue `action` for the supervisor after checking the name and the
/// protection.
fn request(s: &mut Session, p: &Value, action: ServiceAction) -> Result<Value> {
    let name = req_str(p, "name")?;
    if name.len() > MAX_NAME {
        return Err(EngineError::bad("name", format!("at most {MAX_NAME} characters")));
    }
    let Some(t) = table(s) else {
        return Err(EngineError::bad(
            "name",
            "no daemon supervises services in this session (lab or browser): \
             run corerouter-daemon and connect to it",
        ));
    };
    let Some(row) = t.row(name) else {
        return Err(unknown(t, name));
    };
    if row.protected && matches!(action, ServiceAction::Stop | ServiceAction::Restart) {
        return Err(EngineError::bad(
            "name",
            format!(
                "'{}' is protected: it carries the management session that asks, so \
                 stopping or restarting it from here would lock you out. Change it in \
                 the config ({}) or restart the daemon from the host",
                row.name, row.enable
            ),
        ));
    }
    let state = row.state;
    let name = row.name.clone();
    let Some(t) = s.ext_mut::<ServiceTable>() else {
        return Err(EngineError::Internal("system.service".into()));
    };
    if t.requests.len() >= MAX_REQUESTS {
        return Err(EngineError::bad(
            "name",
            "too many service requests waiting for the supervisor; try again in a second",
        ));
    }
    t.requests.push(ServiceRequest {
        name: name.clone(),
        action,
    });
    Ok(json!({ "name": name, "action": action.as_str(), "state": state.as_str() }))
}

fn start(s: &mut Session, p: &Value) -> Result<Value> {
    request(s, p, ServiceAction::Start)
}

fn stop(s: &mut Session, p: &Value) -> Result<Value> {
    request(s, p, ServiceAction::Stop)
}

fn restart(s: &mut Session, p: &Value) -> Result<Value> {
    request(s, p, ServiceAction::Restart)
}

fn reset_failures(s: &mut Session, p: &Value) -> Result<Value> {
    request(s, p, ServiceAction::ResetFailures)
}

#[cfg(test)]
mod tests {
    use corerouter_model::service::{
        ServiceAction, ServiceRow, ServiceState, ServiceTable,
    };
    use serde_json::json;

    use crate::Session;

    fn supervised() -> Session {
        let mut s = Session::virtual_lab();
        if let Some(t) = s.ext_mut::<ServiceTable>() {
            t.supervised = true;
            t.rows = vec![
                ServiceRow {
                    name: "dns-resolver".into(),
                    state: ServiceState::Running,
                    enable: "always on".into(),
                    ..ServiceRow::default()
                },
                ServiceRow {
                    name: "control".into(),
                    state: ServiceState::Running,
                    protected: true,
                    enable: "corerouter-daemon --control <port>".into(),
                    ..ServiceRow::default()
                },
            ];
        }
        s
    }

    fn queued(s: &Session) -> Vec<(String, ServiceAction)> {
        s.ext::<ServiceTable>()
            .map(|t| t.requests.iter().map(|r| (r.name.clone(), r.action)).collect())
            .unwrap_or_default()
    }

    #[test]
    fn lab_lists_nothing_and_explains_actions() {
        let mut s = Session::virtual_lab();
        assert_eq!(s.execute("system.service.print", &json!({})).unwrap(), json!([]));
        let e = s
            .execute("system.service.stop", &json!({"name": "dns-resolver"}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("no daemon"), "{e}");
    }

    #[test]
    fn print_and_actions_reach_the_supervisor_queue() {
        let mut s = supervised();
        let rows = s.execute("system.service.print", &json!({})).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 2);
        assert_eq!(rows[0]["state"], "running");
        let one = s
            .execute("system.service.print", &json!({"name": "control"}))
            .unwrap();
        assert_eq!(one[0]["protected"], true);
        let r = s
            .execute("system.service.stop", &json!({"name": "dns-resolver"}))
            .unwrap();
        assert_eq!(r, json!({"name": "dns-resolver", "action": "stop", "state": "running"}));
        for id in ["start", "restart", "reset-failures"] {
            s.execute(&format!("system.service.{id}"), &json!({"name": "dns-resolver"}))
                .unwrap();
        }
        assert_eq!(
            queued(&s),
            [
                ("dns-resolver".into(), ServiceAction::Stop),
                ("dns-resolver".into(), ServiceAction::Start),
                ("dns-resolver".into(), ServiceAction::Restart),
                ("dns-resolver".into(), ServiceAction::ResetFailures),
            ]
        );
        assert_eq!(s.journal().len(), 4, "actions are journaled (who stopped what)");
    }

    #[test]
    fn bad_names_are_refused_with_a_hint() {
        let mut s = supervised();
        let e = s
            .execute("system.service.stop", &json!({"name": "dns-resolvr"}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("did you mean 'dns-resolver'"), "{e}");
        for p in [json!({}), json!({"name": 5}), json!({"name": "x".repeat(65)})] {
            assert!(s.execute("system.service.restart", &p).is_err(), "{p}");
        }
        let e = s
            .execute("system.service.print", &json!({"name": "nope"}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("services: dns-resolver, control"), "{e}");
        assert!(queued(&s).is_empty());
    }

    #[test]
    fn control_is_protected() {
        let mut s = supervised();
        for id in ["stop", "restart"] {
            let e = s
                .execute(&format!("system.service.{id}"), &json!({"name": "control"}))
                .unwrap_err()
                .to_string();
            assert!(e.contains("protected") && e.contains("lock you out"), "{e}");
        }
        assert!(queued(&s).is_empty());
        // Starting or clearing its counters cuts nobody off.
        s.execute("system.service.reset-failures", &json!({"name": "control"}))
            .unwrap();
    }

    #[test]
    fn stop_leaves_the_config_alone_and_rollback_has_nothing_to_undo() {
        let mut s = supervised();
        let rev = s.store().current_revision();
        let before = s.store().running().clone();
        s.execute("system.service.stop", &json!({"name": "dns-resolver"}))
            .unwrap();
        assert_eq!(s.store().current_revision(), rev);
        assert_eq!(s.store().running(), &before);
        assert!(!s.store().is_dirty());
    }

    #[test]
    fn the_queue_is_bounded() {
        let mut s = supervised();
        for _ in 0..corerouter_model::service::MAX_REQUESTS {
            s.execute("system.service.restart", &json!({"name": "dns-resolver"}))
                .unwrap();
        }
        let e = s
            .execute("system.service.restart", &json!({"name": "dns-resolver"}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("too many"), "{e}");
    }
}
