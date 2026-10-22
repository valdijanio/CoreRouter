//! Bateria da fila de entrada (bench/queue): feature sintética 05.

use serde_json::{Value, json};

use super::{CommandSpec, always};
use crate::{Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "bench.f05.get", "Bench 05", [], None,
    "{} → {identity, n}",
    always, get)];

fn get(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(json!({ "identity": s.store().candidate().system.identity, "n": 5 }))
}
