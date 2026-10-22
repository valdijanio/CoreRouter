//! Tool catalog. Few generic tools reach every command; aliases raise the
//! odds that a model gets the name right on the first try.

use serde_json::{Value, json};

use crate::Backend;

struct Tool {
    names: &'static [&'static str],
    description: &'static str,
    schema: fn() -> Value,
    read_only: bool,
    destructive: bool,
    idempotent: bool,
}

const TOOLS: &[Tool] = &[
    Tool {
        names: &["list_commands", "command_list"],
        description: "List every router command (id, params signature, enabled + reason). \
            Optional `prefix` filters by id, e.g. \"ip.address\".",
        schema: || json!({"type": "object", "properties": {"prefix": {"type": "string"}}}),
        read_only: true,
        destructive: false,
        idempotent: true,
    },
    Tool {
        names: &["run_command", "command_run"],
        description: "Run one command by id with JSON params, e.g. \
            {\"command\":\"ip.address.add\",\"params\":{\"address\":\"10.0.0.1/24\",\"interface\":\"ether1\"}}.",
        schema: || {
            json!({"type": "object", "required": ["command"], "properties": {
                "command": {"type": "string"},
                "params": {"type": "object"}}})
        },
        read_only: false,
        destructive: true,
        idempotent: false,
    },
    Tool {
        names: &["command_batch"],
        description: "Run up to 256 commands as one step. \"$N.key\" in params takes `key` from \
            step N's result (1-based). atomic (default true): all-or-nothing, one commit.",
        schema: || {
            json!({"type": "object", "required": ["steps"], "properties": {
                "steps": {"type": "array", "items": {"type": "object", "required": ["command"],
                    "properties": {"command": {"type": "string"}, "params": {"type": "object"}}}},
                "atomic": {"type": "boolean"}}})
        },
        read_only: false,
        destructive: true,
        idempotent: false,
    },
    Tool {
        names: &["inspect_state", "state_inspect"],
        description: "Without `path`: compact summary (identity, backend, mode, revision, \
            pending changes, counts). With `path` (\"interfaces\", \"ip.addresses\", \
            \"routing.bgp\", \"running.ip\", \"journal\"): that subtree only.",
        schema: || json!({"type": "object", "properties": {"path": {"type": "string"}}}),
        read_only: true,
        destructive: false,
        idempotent: true,
    },
    Tool {
        names: &["ui_screenshot", "screenshot"],
        description: "PNG of the live GUI window (needs corerouter-gui --control and the \
            remote backend). Use it to check what an operator would see.",
        schema: || json!({"type": "object", "properties": {}}),
        read_only: true,
        destructive: false,
        idempotent: true,
    },
];

pub fn definitions() -> Value {
    let mut out = Vec::new();
    for t in TOOLS {
        for name in t.names {
            out.push(json!({
                "name": name,
                "description": t.description,
                "inputSchema": (t.schema)(),
                "annotations": {
                    "readOnlyHint": t.read_only,
                    "destructiveHint": t.destructive,
                    "idempotentHint": t.idempotent,
                    "openWorldHint": false,
                },
            }));
        }
    }
    Value::Array(out)
}

fn text(v: Result<Value, String>) -> Value {
    match v {
        Ok(v) => json!({"content": [{"type": "text", "text": v.to_string()}], "isError": false}),
        Err(e) => json!({"content": [{"type": "text", "text": e}], "isError": true}),
    }
}

/// Tool errors come back as readable text (`isError`), not protocol errors,
/// so the agent can read them and retry.
pub fn call(backend: &mut dyn Backend, params: &Value) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let tool = TOOLS.iter().find(|t| t.names.contains(&name));
    let Some(tool) = tool else {
        let all: Vec<&str> = TOOLS.iter().flat_map(|t| t.names.iter().copied()).collect();
        return text(Err(format!(
            "unknown tool '{}'; tools: {}",
            name.chars().take(64).collect::<String>(),
            all.join(", ")
        )));
    };
    match tool.names.first().copied().unwrap_or("") {
        "list_commands" => {
            let prefix = args.get("prefix").and_then(Value::as_str).unwrap_or("");
            text(backend.call("engine.list", Value::Null).map(|list| {
                match list {
                    Value::Array(items) => Value::Array(
                        items
                            .into_iter()
                            .filter(|c| {
                                c.get("id")
                                    .and_then(Value::as_str)
                                    .is_some_and(|id| id.starts_with(prefix))
                            })
                            .collect(),
                    ),
                    other => other,
                }
            }))
        }
        "run_command" => text(backend.call("engine.execute", args)),
        "command_batch" => text(backend.call("engine.batch", args)),
        "inspect_state" => text(backend.call("state.inspect", args)),
        "ui_screenshot" => match backend.call("ui.screenshot", Value::Null) {
            Ok(img) => match (
                img.get("data").and_then(Value::as_str),
                img.get("mimeType").and_then(Value::as_str),
            ) {
                (Some(data), Some(mime)) => json!({
                    "content": [{"type": "image", "data": data, "mimeType": mime}],
                    "isError": false,
                }),
                _ => text(Err("screenshot reply had no image".into())),
            },
            Err(e) => text(Err(e)),
        },
        other => text(Err(format!("tool '{other}' has no handler"))),
    }
}
