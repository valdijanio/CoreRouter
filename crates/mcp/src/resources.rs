//! MCP resources: read-only views of the router an agent (or the user, in
//! the client's resource picker) attaches as context without a tool call.
//! They map onto the same control-channel methods as the tools.

use serde_json::{Value, json};

use crate::Backend;

pub const SCHEME: &str = "corerouter://";
const JSON: &str = "application/json";
/// Longest URI accepted; the rest of the message is never echoed back.
const MAX_URI: usize = 512;
/// Ids suggested when a command resource does not exist.
const SUGGESTIONS: usize = 5;

/// MCP 2025-06-18 "Resource not found". The 2026-07-28 revision moves it to
/// -32602, but says clients SHOULD keep accepting -32002.
pub const NOT_FOUND: i64 = -32002;

pub struct ReadError {
    pub code: i64,
    pub message: String,
    pub uri: String,
}

pub fn list() -> Value {
    json!({"resources": [
        {
            "uri": "corerouter://state",
            "name": "state",
            "title": "Router state summary",
            "description": "Identity, backend, commit mode, revision, pending changes, Safe Mode \
                and counts. The same as inspect_state without a path.",
            "mimeType": JSON,
        },
        {
            "uri": "corerouter://commands",
            "name": "commands",
            "title": "Command registry",
            "description": "Every command: id, params signature, enabled + reason.",
            "mimeType": JSON,
        },
        {
            "uri": "corerouter://diff",
            "name": "diff",
            "title": "Pending changes",
            "description": "config.diff: what config.commit would apply (empty in immediate mode).",
            "mimeType": JSON,
        },
    ]})
}

pub fn templates() -> Value {
    json!({"resourceTemplates": [
        {
            "uriTemplate": "corerouter://command/{id}",
            "name": "command",
            "title": "One command",
            "description": "Params signature, result and enabled state of one command id, \
                e.g. corerouter://command/ip.address.add.",
            "mimeType": JSON,
        },
        {
            "uriTemplate": "corerouter://state/{path}",
            "name": "state-path",
            "title": "State subtree",
            "description": "One subtree of the candidate config by dotted path: interfaces, \
                ip.addresses, routing.bgp, running.ip (the applied config), journal.",
            "mimeType": JSON,
        },
    ]})
}

/// `resources/read`.
pub fn read(backend: &mut dyn Backend, params: &Value) -> Result<Value, ReadError> {
    let raw = params.get("uri").and_then(Value::as_str).unwrap_or("");
    let uri: String = raw.chars().take(MAX_URI).collect();
    let fail = |code: i64, message: String| ReadError {
        code,
        message,
        uri: uri.clone(),
    };
    if raw.len() > MAX_URI {
        return Err(fail(-32602, format!("uri longer than {MAX_URI} bytes")));
    }
    let Some(rest) = uri.strip_prefix(SCHEME) else {
        return Err(fail(
            NOT_FOUND,
            format!("resource not found: {uri} (resources start with {SCHEME})"),
        ));
    };
    let internal = |e: String| fail(-32603, e);
    let value = match rest.split_once('/') {
        None if rest == "state" => backend.call("state.inspect", json!({})).map_err(internal)?,
        None if rest == "commands" => backend.call("engine.list", Value::Null).map_err(internal)?,
        None if rest == "diff" => backend
            .call(
                "engine.execute",
                json!({"command": "config.diff", "params": {}}),
            )
            .map_err(internal)?,
        // The usual failure is a path that does not exist.
        Some(("state", path)) if !path.is_empty() => backend
            .call("state.inspect", json!({"path": path}))
            .map_err(|e| fail(NOT_FOUND, format!("resource not found: {uri}: {e}")))?,
        Some(("command", id)) if !id.is_empty() => {
            let list = backend.call("engine.list", Value::Null).map_err(internal)?;
            let all = list.as_array().map(Vec::as_slice).unwrap_or_default();
            all.iter()
                .find(|c| c.get("id").and_then(Value::as_str) == Some(id))
                .cloned()
                .ok_or_else(|| fail(NOT_FOUND, unknown_command(id, all)))?
        }
        _ => {
            return Err(fail(
                NOT_FOUND,
                format!(
                    "resource not found: {uri}; resources: corerouter://state, \
                     corerouter://commands, corerouter://diff, corerouter://command/{{id}}, \
                     corerouter://state/{{path}}"
                ),
            ));
        }
    };
    // Secrets never reach the agent (as in `tools::text`).
    let value = corerouter_engine::auth::mask_secrets(&value);
    let text = serde_json::to_string_pretty(&value).map_err(|e| internal(e.to_string()))?;
    Ok(json!({"contents": [{"uri": uri, "mimeType": JSON, "text": text}]}))
}

/// "did you mean": ids under the same first segment that share the longest
/// prefix with `id`.
fn unknown_command(id: &str, all: &[Value]) -> String {
    let ids = all
        .iter()
        .filter_map(|c| c.get("id").and_then(Value::as_str));
    let common = |a: &str| {
        a.chars()
            .zip(id.chars())
            .take_while(|(x, y)| x == y)
            .count()
    };
    let mut near: Vec<(usize, &str)> = ids
        .map(|c| (common(c), c))
        .filter(|(n, _)| *n > 0)
        .collect();
    near.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(b.1)));
    let near: Vec<&str> = near.into_iter().take(SUGGESTIONS).map(|(_, c)| c).collect();
    let hint = if near.is_empty() {
        String::new()
    } else {
        format!("; closest: {}", near.join(", "))
    };
    format!(
        "resource not found: no command '{}'{hint}",
        id.chars().take(64).collect::<String>()
    )
}

/// Command ids starting with `prefix`, for completion.
pub fn command_ids(backend: &mut dyn Backend, prefix: &str) -> Vec<String> {
    let list = backend.call("engine.list", Value::Null).unwrap_or_default();
    list.as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| c.get("id").and_then(Value::as_str))
        .filter(|id| id.starts_with(prefix))
        .map(str::to_string)
        .collect()
}
