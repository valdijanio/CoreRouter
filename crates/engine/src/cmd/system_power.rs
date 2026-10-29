//! `/system reboot` and `/system shutdown` (G1.6qa). RouterOS asks
//! "Reboot, yes? [y/N]" in the terminal; here the question is `confirm:
//! true`, the same for the terminal, the GUI, scripts and the MCP. Refused
//! without `force` when work would be lost or undone behind the operator's
//! back: Safe Mode on (the reboot boots the config from its entry: an undo)
//! or uncommitted changes of a transaction (never saved). The request goes
//! to the daemon (`crate::power`); the journal and the log record it like
//! any other command.

use serde_json::{Value, json};

use super::CommandSpec;
use super::args::opt_bool;
use crate::power::{Action, Power, Request, unsupported};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "system.reboot",
        "Reboot",
        [],
        None,
        "{confirm?: bool (needed: the router restarts and every connection drops), force?: bool (even in Safe Mode, which a reboot undoes, or with uncommitted changes, which are lost)} → {action, requested_by, safe_mode_undone: bool, discarded_changes: bool}",
        supported,
        reboot
    ),
    cmd!(
        "system.shutdown",
        "Shutdown",
        [],
        None,
        "{confirm?: bool (needed: the router powers off and comes back only by hand), force?: bool (even in Safe Mode, which the next boot undoes, or with uncommitted changes, which are lost)} → {action, requested_by, safe_mode_undone: bool, discarded_changes: bool}",
        supported,
        shutdown
    ),
];

fn supported(s: &Session) -> std::result::Result<(), String> {
    unsupported(s).map_or(Ok(()), Err)
}

fn reboot(s: &mut Session, p: &Value) -> Result<Value> {
    request(s, p, Action::Reboot)
}

fn shutdown(s: &mut Session, p: &Value) -> Result<Value> {
    request(s, p, Action::Shutdown)
}

fn request(s: &mut Session, p: &Value, action: Action) -> Result<Value> {
    let what = action.as_str();
    if opt_bool(p, "confirm")? != Some(true) {
        return Err(EngineError::bad(
            "confirm",
            format!("{what} needs confirm=true: every connection to the router drops"),
        ));
    }
    let force = opt_bool(p, "force")?.unwrap_or(false);
    let safe_mode = s.in_safe_mode();
    if safe_mode && !force {
        return Err(EngineError::bad(
            "force",
            format!(
                "Safe Mode is on: the {what} would boot the config from its entry and undo the \
                 changes since; leave it first (config.safe-mode.exit keeps them) or force=true"
            ),
        ));
    }
    let dirty = s.store().is_dirty();
    if dirty && !force {
        return Err(EngineError::bad(
            "force",
            format!(
                "uncommitted changes would be lost by the {what}: config.commit (or \
                 config.discard) first, or force=true"
            ),
        ));
    }
    let by = s.caller().name.clone();
    let p = s
        .ext_mut::<Power>()
        .ok_or_else(|| EngineError::Internal("power state".into()))?;
    // A second request before the service took the first replaces it: the
    // last word wins, as a second `/system shutdown` after a reboot would.
    p.requested = Some(Request { action, by: by.clone() });
    Ok(json!({
        "action": what,
        "requested_by": by,
        "safe_mode_undone": safe_mode,
        "discarded_changes": dirty,
    }))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::Session;
    use crate::power::{self, Action};

    fn image() -> Session {
        let mut s = Session::virtual_lab();
        power::set_support(&mut s, Ok(()));
        s
    }

    #[test]
    fn reboot_and_shutdown_ask_the_daemon() {
        let mut s = image();
        let out = s.execute("system.reboot", &json!({"confirm": true})).unwrap();
        assert_eq!(out["action"], "reboot");
        assert_eq!(out["safe_mode_undone"], false);
        let r = power::take_request(&mut s).unwrap();
        assert_eq!(r.action, Action::Reboot);
        assert_eq!(r.by, "local");
        assert!(power::take_request(&mut s).is_none(), "taken once");

        s.execute("system.shutdown", &json!({"confirm": true})).unwrap();
        assert_eq!(power::take_request(&mut s).unwrap().action, Action::Shutdown);

        // In the journal and the router's log, as any command.
        let j = s.journal().last().unwrap();
        assert_eq!(j.command, "system.shutdown");
        let log = s.execute("log.print", &json!({})).unwrap().to_string();
        assert!(log.contains("system.shutdown"), "{log}");
    }

    #[test]
    fn refused_without_confirm_off_the_image_and_when_work_would_be_lost() {
        // Off the image (no daemon, or not under corerouter-init): disabled.
        let mut lab = Session::virtual_lab();
        let e = lab.execute("system.reboot", &json!({"confirm": true})).unwrap_err().to_string();
        assert!(e.contains("disabled") && e.contains("virtual lab"), "{e}");
        power::set_support(&mut lab, Err("PID 1 is systemd, not corerouter-init".into()));
        let e = lab.execute("system.shutdown", &json!({"confirm": true})).unwrap_err().to_string();
        assert!(e.contains("systemd"), "{e}");

        let mut s = image();
        for p in [json!({}), json!({"confirm": false}), json!({"confirm": "yes"})] {
            assert!(s.execute("system.reboot", &p).is_err(), "{p}");
        }
        assert!(s.execute("system.reboot", &json!({"confirm": true, "now": 1})).is_err());

        // Safe Mode: a reboot would undo it behind the operator's back.
        s.execute("config.safe-mode.enter", &json!({})).unwrap();
        let e = s.execute("system.reboot", &json!({"confirm": true})).unwrap_err().to_string();
        assert!(e.contains("Safe Mode"), "{e}");
        let out = s.execute("system.reboot", &json!({"confirm": true, "force": true})).unwrap();
        assert_eq!(out["safe_mode_undone"], true);
        power::take_request(&mut s).unwrap();
        s.execute("config.safe-mode.exit", &json!({})).unwrap();

        // A transaction's changes would be lost.
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        s.execute("system.identity.set", &json!({"name": "pending"})).unwrap();
        let e = s.execute("system.shutdown", &json!({"confirm": true})).unwrap_err().to_string();
        assert!(e.contains("uncommitted"), "{e}");
        assert!(power::take_request(&mut s).is_none(), "nothing asked");
        let out = s.execute("system.shutdown", &json!({"confirm": true, "force": true})).unwrap();
        assert_eq!(out["discarded_changes"], true);
    }

    /// Rollback: in an atomic batch nothing may happen until the whole
    /// batch holds, and a reboot cannot be taken back — refused there.
    #[test]
    fn refused_inside_an_atomic_batch() {
        let mut s = image();
        let steps = json!([
            {"command": "system.identity.set", "params": {"name": "x"}},
            {"command": "system.reboot", "params": {"confirm": true}},
        ]);
        assert!(s.batch(&steps, true).is_err());
        assert!(power::take_request(&mut s).is_none());
        assert_ne!(s.store().running().system.identity, "x", "the batch was undone");
    }
}
