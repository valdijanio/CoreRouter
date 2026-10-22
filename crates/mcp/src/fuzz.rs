//! Fuzz oracle for the MCP stdio server (G0.5); see
//! `corerouter_control::fuzz` for how panics are caught.

#![doc(hidden)]

use std::io::Cursor;

use corerouter_control::fuzz::panics;
use corerouter_engine::Session;
use serde_json::Value;

use crate::{Headless, serve};

/// Serve `data` (any number of lines) on a fresh virtual lab. Every reply
/// must be one JSON-RPC 2.0 object (or a batch of them) on its own line,
/// and nothing may panic, not even a panic the engine guard catches.
pub fn messages(data: &[u8]) -> Result<(), String> {
    let mut backend = Headless::new(Session::virtual_lab());
    let mut out = Vec::new();
    let (served, panicked) = panics(|| serve(&mut backend, Cursor::new(data), &mut out));
    if panicked > 0 {
        return Err(format!("{panicked} panic(s) serving the input"));
    }
    served.map_err(|e| e.to_string())?;
    let out = String::from_utf8(out).map_err(|e| format!("stdout is not UTF-8: {e}"))?;
    for line in out.lines() {
        let reply: Value =
            serde_json::from_str(line).map_err(|e| format!("reply is not JSON ({e}): {line}"))?;
        let replies = match &reply {
            Value::Array(batch) if !batch.is_empty() => batch.iter().collect(),
            Value::Object(_) => vec![&reply],
            _ => return Err(format!("reply is neither object nor batch: {line}")),
        };
        for r in replies {
            if r.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
                return Err(format!("reply without jsonrpc 2.0: {r}"));
            }
            if r.get("result").is_some() == r.get("error").is_some() {
                return Err(format!("reply needs exactly one of result/error: {r}"));
            }
        }
    }
    Ok(())
}
