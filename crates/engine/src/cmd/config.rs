//! Transaction control: commit, discard, rollback, history, diff, mode.

use serde_json::{Value, json};

use super::args::{opt_text, req_str, req_u32};
use super::{CommandSpec, always};
use crate::{CommitMode, EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "config.commit",
        "Commit",
        ["System", "Configuration"],
        Some("Ctrl+Enter"),
        "{comment?: string} → {revision}",
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
        "{revision: u32} → {loaded, pending}",
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
];

fn dirty(s: &Session) -> std::result::Result<(), String> {
    if s.store().is_dirty() {
        Ok(())
    } else {
        Err("no pending changes".into())
    }
}

fn commit(s: &mut Session, p: &Value) -> Result<Value> {
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let revision = s.commit_candidate(&comment)?;
    Ok(json!({ "revision": revision }))
}

fn discard(s: &mut Session, _: &Value) -> Result<Value> {
    s.store_mut().discard();
    Ok(json!({}))
}

fn rollback(s: &mut Session, p: &Value) -> Result<Value> {
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
