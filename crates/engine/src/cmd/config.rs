//! Transaction control: commit, discard, rollback, history, diff, mode, Safe Mode.

use serde_json::{Value, json};

use super::args::{opt_bool, opt_text, opt_u32, req_str, req_u32};
use super::{CommandSpec, always};
use crate::{CommitMode, EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "config.commit",
        "Commit",
        ["System", "Configuration"],
        Some("Ctrl+Enter"),
        "{comment?: string, force?: bool (commit even if the firewall would cut your management connection)} → {revision}",
        dirty,
        commit
    ),
    cmd!(
        "config.discard",
        "Discard Changes",
        ["System", "Configuration"],
        None,
        "{} → {}",
        dirty,
        discard
    ),
    cmd!(
        "config.rollback",
        "Rollback",
        ["System", "History"],
        None,
        "{revision: u32, force?: bool} → {loaded, pending}",
        always,
        rollback
    ),
    cmd!(query "config.history", "History", ["System", "History"], None,
        "{} → [{number, comment, timestamp}]",
        always, history),
    cmd!(query "config.diff", "Pending Changes", ["System", "Configuration"], None,
        "{} → [{op: add|remove|change, path, value | from, to}]",
        always, diff),
    cmd!(query "config.mode.set", "Commit Mode", ["System", "Configuration"], None,
        "{mode: immediate|transactional} → {mode}",
        always, mode_set),
    cmd!(
        "config.safe-mode.enter",
        "Safe Mode",
        ["System", "Configuration"],
        None,
        "{timeout_secs?: u32} → {active, owner, since, entry_revision, timeout_secs, expires_in}",
        always,
        safe_mode_enter
    ),
    cmd!(
        "config.safe-mode.exit",
        "Leave Safe Mode (keep changes)",
        ["System", "Configuration"],
        None,
        "{force?: bool} → {active: false, last}",
        in_safe_mode,
        safe_mode_exit
    ),
    cmd!(
        "config.safe-mode.cancel",
        "Leave Safe Mode (undo changes)",
        ["System", "Configuration"],
        None,
        "{force?: bool} → {active: false, last}",
        in_safe_mode,
        safe_mode_cancel
    ),
];

fn dirty(s: &Session) -> std::result::Result<(), String> {
    if s.store().is_dirty() {
        Ok(())
    } else {
        Err("no pending changes".into())
    }
}

fn in_safe_mode(s: &Session) -> std::result::Result<(), String> {
    if s.in_safe_mode() {
        Ok(())
    } else {
        Err("not in Safe Mode".into())
    }
}

fn commit(s: &mut Session, p: &Value) -> Result<Value> {
    crate::lockout::take_force(s, p)?;
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let revision = s.commit_candidate(&comment)?;
    Ok(json!({ "revision": revision }))
}

fn discard(s: &mut Session, _: &Value) -> Result<Value> {
    s.store_mut().discard();
    Ok(json!({}))
}

fn rollback(s: &mut Session, p: &Value) -> Result<Value> {
    crate::lockout::take_force(s, p)?;
    let rev = req_u32(p, "revision")?;
    s.store_mut().rollback(rev)?;
    // In immediate mode `execute` commits right after this returns.
    Ok(json!({ "loaded": rev, "pending": s.mode() == CommitMode::Transactional }))
}

fn history(s: &mut Session, _: &Value) -> Result<Value> {
    serde_json::to_value(s.store().history()).map_err(|e| EngineError::Internal(e.to_string()))
}

fn diff(s: &mut Session, _: &Value) -> Result<Value> {
    serde_json::to_value(s.store().diff()).map_err(|e| EngineError::Internal(e.to_string()))
}

// A query (no journal, no auto-commit): it changes the session, not the config.
fn mode_set(s: &mut Session, p: &Value) -> Result<Value> {
    let mode = match req_str(p, "mode")? {
        "immediate" => CommitMode::Immediate,
        "transactional" => CommitMode::Transactional,
        _ => {
            return Err(EngineError::bad(
                "mode",
                "must be 'immediate' or 'transactional'",
            ));
        }
    };
    if mode == CommitMode::Immediate && s.store().is_dirty() {
        return Err(EngineError::bad(
            "mode",
            format!(
                "commit or discard the {} pending change(s) first (config.diff)",
                s.store().diff().len()
            ),
        ));
    }
    s.set_mode(mode);
    Ok(json!({ "mode": mode }))
}

// Safe Mode (G1.4): see `crate::safe_mode`. Journaled, so the history of who
// entered and left is in `state.inspect {path: journal}`; none of them edits
// the candidate, so `execute` never auto-commits after them.
fn safe_mode_enter(s: &mut Session, p: &Value) -> Result<Value> {
    s.safe_mode_enter(opt_u32(p, "timeout_secs")?)
}

fn safe_mode_exit(s: &mut Session, p: &Value) -> Result<Value> {
    s.safe_mode_exit(opt_bool(p, "force")?.unwrap_or(false))
}

fn safe_mode_cancel(s: &mut Session, p: &Value) -> Result<Value> {
    s.safe_mode_cancel(opt_bool(p, "force")?.unwrap_or(false))
}
