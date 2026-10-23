//! `ip.route.detail` (G1.27b): the panel under IP › Routes. The logic is
//! `crate::route_detail`.

use serde_json::Value;

use super::args::req_str;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "ip.route.detail", "Route Detail", [], None,
    "{key: string (a row's key from ip.route.list)} → {key, route (the ip.route.list row), source: {kind (static | dhcp | ra | connected), text, created: null | {revision, command, timestamp, ago_secs}, changed, interface, server, address}, chosen (why it is or is not the route in use), chosen_id (choice.<id> or route.<reason_id>), chosen_args, competitors: [{key, id, gateway, distance, origin, state, reason, reason_id, reason_args, this}], check_gateway: null | {method, interval_secs, misses, state, down_secs}, history: [{at, ago_secs, from, to, reason, reason_id, reason_args}] (last 24 h, newest first), watching_since_secs, kernel: {available, same (null: not compared), expected, present, missing, extra, note}}",
    always, run)
.positional("key")];

fn run(s: &mut Session, p: &Value) -> Result<Value> {
    let key = req_str(p, "key")?;
    if key.len() > 256 {
        return Err(EngineError::bad("key", "at most 256 bytes"));
    }
    s.route_detail(key).ok_or_else(|| {
        EngineError::bad(
            "key",
            format!(
                "no route '{}' (see ip.route.list, field key)",
                key.chars().take(64).collect::<String>()
            ),
        )
    })
}
