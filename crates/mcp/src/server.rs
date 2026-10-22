use std::io::{self, BufRead, Write};

use corerouter_control::wire::{Line, MAX_REQUEST_LINE, read_line_bounded};
use serde_json::{Value, json};

use crate::{Backend, prompts, resources, tools};

pub const PROTOCOL_VERSION: &str = "2025-06-18";
const BATCH_REJECTED: &str = "invalid request: JSON-RPC batches are not supported \
(removed in MCP 2025-06-18); send one message per line";

const INSTRUCTIONS: &str = "CoreRouter is a router OS. Every action is a command with a \
RouterOS-style dotted id (interface.list, ip.address.add, routing.bgp.instance.set). \
Find ids and their params signature with list_commands (use `prefix`), run them with \
run_command, or several at once with command_batch (atomic by default). Check the result \
with inspect_state (pass `path` to read one subtree). Commit mode: `immediate` applies each \
change at once; switch to `transactional` (config.mode.set) for multi-step changes, review \
config.diff, then config.commit; config.rollback {revision} restores history. Errors are \
plain text that says what to fix. Resources: corerouter://state, corerouter://diff, \
corerouter://command/{id}, corerouter://state/{path}; prompts: configure_address, \
review_and_commit, diagnose_connectivity. With the GUI attached, ui_screenshot shows the screen.";

/// Serve until EOF on `input`.
pub fn serve<R: BufRead, W: Write>(
    backend: &mut dyn Backend,
    mut input: R,
    mut output: W,
) -> io::Result<()> {
    log::info!("mcp: serving on stdio, backend = {}", backend.describe());
    loop {
        let line = match read_line_bounded(&mut input, MAX_REQUEST_LINE)? {
            Line::Eof => return Ok(()),
            Line::TooLong => {
                emit(
                    &mut output,
                    &error(Value::Null, -32600, "message exceeds 16 MiB"),
                )?;
                continue;
            }
            Line::Text(t) => t,
        };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Err(_) => Some(error(Value::Null, -32700, "parse error")),
            // MCP 2025-06-18 removed JSON-RPC batching (changelog, PR #416), and
            // that is the only revision we negotiate. JSON-RPC 2.0 §6: a batch
            // the server does not accept gets one Response object, not an array.
            // No item is run, so a batch never half-applies.
            Ok(Value::Array(_)) => Some(error(Value::Null, -32600, BATCH_REJECTED)),
            Ok(msg) => handle_message(backend, &msg),
        };
        if let Some(reply) = reply {
            emit(&mut output, &reply)?;
        }
    }
}

fn emit<W: Write>(out: &mut W, v: &Value) -> io::Result<()> {
    writeln!(out, "{v}")?;
    out.flush()
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Handle one JSON-RPC message; `None` for notifications.
pub fn handle_message(backend: &mut dyn Backend, msg: &Value) -> Option<Value> {
    let id = msg.get("id").cloned();
    let Some(method) = msg.get("method").and_then(Value::as_str) else {
        return id.map(|id| error(id, -32600, "invalid request: missing method"));
    };
    let id = id?; // notification (e.g. notifications/initialized): no reply
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "initialize" => json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": {"listChanged": false},
                "resources": {"subscribe": false, "listChanged": false},
                "prompts": {"listChanged": false},
                "completions": {},
            },
            "serverInfo": {"name": "corerouter", "version": env!("CARGO_PKG_VERSION")},
            "instructions": format!("{INSTRUCTIONS} Active backend: {}.", backend.describe()),
        }),
        "ping" => json!({}),
        "tools/list" => json!({"tools": tools::definitions()}),
        "tools/call" => tools::call(backend, &params),
        "resources/list" => resources::list(),
        "resources/templates/list" => resources::templates(),
        "resources/read" => match resources::read(backend, &params) {
            Ok(r) => r,
            Err(e) => {
                return Some(json!({"jsonrpc": "2.0", "id": id, "error": {
                    "code": e.code, "message": e.message, "data": {"uri": e.uri}}}));
            }
        },
        "prompts/list" => prompts::list(),
        "prompts/get" => match prompts::get(backend, &params) {
            Ok(r) => r,
            Err(e) => return Some(error(id, -32602, &e)),
        },
        "completion/complete" => match prompts::complete(backend, &params) {
            Ok(r) => r,
            Err(e) => return Some(error(id, -32602, &e)),
        },
        other => {
            let name: String = other.chars().take(64).collect();
            return Some(error(id, -32601, &format!("method not found: {name}")));
        }
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}
