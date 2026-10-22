//! Tool catalog. Few generic tools reach every command; aliases raise the
//! odds that a model gets the name right on the first try.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

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
        names: &["run_task", "task_run"],
        description: "Run a tool that works as a background task (tool.ping.start, tool.ping.mtu, \
            tool.mtr.start…) and wait for it: starts it, collects its events until it finishes or \
            `wait_secs` (default 10, max 60) pass, then stops it if still running. Returns the \
            summary (per target: sent, received, loss_pct, min/avg/max/jitter/p95 ms…) and the \
            last events. Example: {\"command\":\"tool.ping.start\",\"params\":{\"address\":\"8.8.8.8\",\"count\":5}}. \
            For long runs use run_command with tool.task.poll / tool.task.stop instead.",
        schema: || {
            json!({"type": "object", "required": ["command"], "properties": {
                "command": {"type": "string"},
                "params": {"type": "object"},
                "wait_secs": {"type": "integer", "minimum": 1, "maximum": 60}}})
        },
        read_only: true,
        destructive: false,
        idempotent: false,
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

/// Events `run_task` returns at most (the newest).
const TASK_EVENTS: usize = 50;
const TASK_WAIT_DEFAULT: u64 = 10;
const TASK_WAIT_MAX: u64 = 60;
const TASK_POLL: Duration = Duration::from_millis(200);
const TASK_STOP_GRACE: Duration = Duration::from_secs(10);

/// The log shows what an agent changed as `… · MCP` (G4.6d), whatever
/// `via` the arguments carried.
fn via_mcp(mut args: Value) -> Value {
    if let Some(o) = args.as_object_mut() {
        o.insert("via".into(), json!("mcp"));
    }
    args
}

fn run_task(backend: &mut dyn Backend, args: &Value) -> Result<Value, String> {
    let command = args
        .get("command")
        .and_then(Value::as_str)
        .ok_or("run_task needs {command, params?, wait_secs?}")?;
    let wait = args
        .get("wait_secs")
        .and_then(Value::as_u64)
        .unwrap_or(TASK_WAIT_DEFAULT)
        .clamp(1, TASK_WAIT_MAX);
    let params = args.get("params").cloned().unwrap_or(Value::Null);
    let started = backend.call(
        "engine.execute",
        json!({"command": command, "params": params, "via": "mcp"}),
    )?;
    let id = started
        .get("task_id")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{command} started no task (use run_command): {started}"))?;
    let poll = |b: &mut dyn Backend, after: u64| {
        b.call(
            "engine.execute",
            json!({"command": "tool.task.poll", "params": {"id": id, "after_seq": after}}),
        )
    };
    let deadline = Instant::now() + Duration::from_secs(wait);
    let mut events: VecDeque<Value> = VecDeque::new();
    let mut after = 0u64;
    let mut lost = 0u64;
    let mut stopped = false;
    loop {
        let p = poll(backend, after)?;
        lost += p.get("lost").and_then(Value::as_u64).unwrap_or(0);
        for ev in p
            .get("events")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            events.push_back(ev.clone());
            if events.len() > TASK_EVENTS {
                events.pop_front();
                lost += 1;
            }
        }
        after = p.get("next_seq").and_then(Value::as_u64).unwrap_or(after);
        if p.get("done").and_then(Value::as_bool) == Some(true) {
            return Ok(json!({
                "task_id": id,
                "state": p.get("state"),
                "reason": p.get("reason"),
                "stopped_after_wait": stopped,
                "summary": p.get("summary"),
                "events": events,
                "events_not_shown": lost,
            }));
        }
        // A task that ignores its stop must not hang the agent.
        if Instant::now() >= deadline + TASK_STOP_GRACE {
            return Err(format!("task {id} did not stop; see tool.task.list"));
        }
        if !stopped && Instant::now() >= deadline {
            stopped = true;
            backend.call(
                "engine.execute",
                json!({"command": "tool.task.stop", "params": {"id": id}}),
            )?;
        }
        if p.get("more") != Some(&Value::Bool(true)) {
            std::thread::sleep(TASK_POLL);
        }
    }
}

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
        "run_command" => text(backend.call("engine.execute", via_mcp(args))),
        "command_batch" => text(backend.call("engine.batch", via_mcp(args))),
        "inspect_state" => text(backend.call("state.inspect", args)),
        "run_task" => text(run_task(backend, &args)),
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
