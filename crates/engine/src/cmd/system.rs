//! /system

use serde_json::{Value, json};

use super::args::opt_text;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(
    "system.identity.set",
    "Identity",
    ["System", "Identity"],
    None,
    "{name: string} → {name}",
    always,
    identity_set
)];

fn identity_set(s: &mut Session, p: &Value) -> Result<Value> {
    let name = opt_text(p, "name", 64)?.unwrap_or_default();
    if name.trim().is_empty() {
        return Err(EngineError::bad("name", "must not be empty"));
    }
    s.store_mut().candidate_mut().system.identity = name.clone();
    Ok(json!({ "name": name }))
}
