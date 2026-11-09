//! `/system reboot` and `/system shutdown` (G1.6qa). RouterOS asks
//! "Reboot, yes? [y/N]" in the terminal; here the question is `confirm:
//! true`, the same for the terminal, the GUI, scripts and the MCP. Refused
//! without `force` when work would be lost or undone behind the operator's
//! back: Safe Mode on (the reboot boots the config from its entry: an undo)
//! or uncommitted changes of a transaction (never saved). The request goes
//! to the daemon (`crate::power`); the journal and the log record it like
//! any other command.

use serde_json::{Value, json};

use super::args::{opt_bool, opt_str};
use super::{CommandSpec, always};
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
    cmd!(query "system.power.preview", "Reboot or Shutdown: what it would do", [], None,
        "{action?: reboot|shutdown (default reboot)} → {action, supported, reason?, needs_force, safe_mode, pending_changes, blocks: [{check: safe-mode|uncommitted|install-challenge, message, forceable, fix?: {command, params}}], impact: [{what: ppp-sessions|bgp-sessions|ospf-neighbors, count}]}",
        always, preview),
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

const CHALLENGE_OPEN: &str = "a disk erase is waiting for its code: cancel it first (system.install.cancel)";

fn safe_mode_message(what: &str) -> String {
    format!(
        "Safe Mode is on: the {what} would boot the config from its entry and undo the changes \
         since; leave it first (config.safe-mode.exit keeps them) or force=true"
    )
}

fn uncommitted_message(what: &str) -> String {
    format!(
        "uncommitted changes would be lost by the {what}: config.commit (or config.discard) \
         first, or force=true"
    )
}

/// What `request` would refuse and what the machine would drop, for the
/// question before asking (the GUI's confirmation, a script). The refusals
/// are `request`'s own, with what clears each; a test keeps the two together.
fn preview(s: &mut Session, p: &Value) -> Result<Value> {
    let action = match opt_str(p, "action")? {
        None | Some("reboot") => Action::Reboot,
        Some("shutdown") => Action::Shutdown,
        Some(_) => return Err(EngineError::bad("action", "must be reboot or shutdown")),
    };
    let what = action.as_str();
    let safe_mode = s.in_safe_mode();
    let dirty = s.store().is_dirty();
    let mut blocks = Vec::new();
    if action == Action::Shutdown && crate::install::challenge_open(s) {
        blocks.push(json!({
            "check": "install-challenge",
            "message": CHALLENGE_OPEN,
            "forceable": false,
            "fix": {"command": "system.install.cancel", "params": {}},
        }));
    }
    if safe_mode {
        blocks.push(json!({
            "check": "safe-mode",
            "message": safe_mode_message(what),
            "forceable": true,
            "fix": {"command": "config.safe-mode.exit", "params": {}},
        }));
    }
    if dirty {
        blocks.push(json!({
            "check": "uncommitted",
            "message": uncommitted_message(what),
            "forceable": true,
            "fix": {"command": "config.commit", "params": {}},
        }));
    }
    let mut impact = Vec::new();
    let mut count = |what: &str, n: u64| {
        if n > 0 {
            impact.push(json!({"what": what, "count": n}));
        }
    };
    // Counters kept by the services: nothing here walks the sessions.
    count("ppp-sessions", s.ppp_backend().map_or(0, |b| b.stats().sessions));
    if let Some(r) = s.routing_status() {
        count("bgp-sessions", r.bgp_sessions.iter().filter(|b| b.established).count() as u64);
        count("ospf-neighbors", r.ospf_neighbors.len() as u64);
    }
    let reason = unsupported(s);
    let mut out = json!({
        "action": what,
        "supported": reason.is_none(),
        "needs_force": safe_mode || dirty,
        "safe_mode": safe_mode,
        "pending_changes": s.store().diff().len(),
        "blocks": blocks,
        "impact": impact,
    });
    if let (Some(r), Some(o)) = (reason, out.as_object_mut()) {
        o.insert("reason".into(), json!(r));
    }
    Ok(out)
}

fn request(s: &mut Session, p: &Value, action: Action) -> Result<Value> {
    let what = action.as_str();
    // G1.6y: PID 1 counts the power-off signal as the power button while a
    // challenge is open; a command must not stand in for someone at the machine.
    if action == Action::Shutdown && crate::install::challenge_open(s) {
        return Err(EngineError::Disabled {
            id: "system.shutdown".into(),
            reason: CHALLENGE_OPEN.into(),
        });
    }
    if opt_bool(p, "confirm")? != Some(true) {
        return Err(EngineError::bad(
            "confirm",
            format!("{what} needs confirm=true: every connection to the router drops"),
        ));
    }
    let force = opt_bool(p, "force")?.unwrap_or(false);
    let safe_mode = s.in_safe_mode();
    if safe_mode && !force {
        return Err(EngineError::bad("force", safe_mode_message(what)));
    }
    let dirty = s.store().is_dirty();
    if dirty && !force {
        return Err(EngineError::bad("force", uncommitted_message(what)));
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

    #[test]
    fn preview_says_what_the_command_would_refuse_and_clears_with_the_fix() {
        let ask = |s: &mut Session| s.execute("system.power.preview", &json!({})).unwrap();
        let mut lab = Session::virtual_lab();
        let v = ask(&mut lab);
        assert_eq!(v["supported"], false, "{v}");
        assert!(v["reason"].as_str().unwrap().contains("virtual lab"), "{v}");

        let mut s = image();
        let v = ask(&mut s);
        assert_eq!((&v["supported"], &v["needs_force"], &v["action"]), (&json!(true), &json!(false), &json!("reboot")));
        assert_eq!(v["blocks"], json!([]));
        assert!(v.get("reason").is_none());

        // Each block is what the command answers, and its fix clears it.
        s.execute("config.safe-mode.enter", &json!({})).unwrap();
        let v = ask(&mut s);
        assert_eq!(v["needs_force"], true);
        assert_eq!(v["blocks"][0]["check"], "safe-mode");
        let refused = s.execute("system.reboot", &json!({"confirm": true})).unwrap_err().to_string();
        assert!(refused.contains(v["blocks"][0]["message"].as_str().unwrap()), "{refused}");
        let fix = &v["blocks"][0]["fix"];
        s.execute(fix["command"].as_str().unwrap(), &fix["params"]).unwrap();
        assert_eq!(ask(&mut s)["needs_force"], false);

        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        s.execute("system.identity.set", &json!({"name": "pending"})).unwrap();
        let v = ask(&mut s);
        assert_eq!(v["blocks"][0]["check"], "uncommitted");
        assert_eq!(v["pending_changes"], 1);
        let fix = &v["blocks"][0]["fix"];
        s.execute(fix["command"].as_str().unwrap(), &fix["params"]).unwrap();
        s.execute("system.reboot", &json!({"confirm": true})).unwrap();

        let e = s.execute("system.power.preview", &json!({"action": "halt"})).unwrap_err().to_string();
        assert!(e.contains("reboot or shutdown"), "{e}");
    }

    #[test]
    fn preview_counts_only_what_is_up() {
        use corerouter_model::routing_state::{BgpSession, RoutingStatus};
        let mut s = image();
        assert_eq!(s.execute("system.power.preview", &json!({})).unwrap()["impact"], json!([]));
        let session = |established| BgpSession { established, ..Default::default() };
        if let Some(r) = s.ext_mut::<RoutingStatus>() {
            r.bgp_sessions = vec![session(true), session(false), session(true)];
        }
        let v = s.execute("system.power.preview", &json!({"action": "shutdown"})).unwrap();
        assert_eq!(v["action"], "shutdown");
        assert_eq!(v["impact"], json!([{"what": "bgp-sessions", "count": 2}]));
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
