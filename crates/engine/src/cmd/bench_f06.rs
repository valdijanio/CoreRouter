//! Bateria da fila de entrada (bench/queue): feature sintética 06.

use serde_json::{Value, json};

use super::{CommandSpec, always};
use crate::{Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "bench.f06.get", "Bench 06", [], None,
    "{} → {identity, n}",
    always, get)];

fn get(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(json!({ "identity": s.store().candidate().system.identity, "n": 6 }))
}
