//! Helpers of the `ppp_*` areas (G4.3d): names, rate limits, hooks and the
//! "drops N sessions" guard of the config commands.

use corerouter_model::firewall::Name;
use corerouter_model::ppp::{ActiveSession, MAX_HOOKS, MAX_NAME, PppHook};
use corerouter_proto_radius::rate_limit::RateLimit;
use serde_json::Value;

use super::args::{opt_bool, opt_str};
use crate::{EngineError, Result, Session};

/// A PPP name (secret, profile, server): 1..=64 printable characters,
/// no spaces at the ends, no control characters (RFC 1334/1994 carry it
/// as bytes; RouterOS shows it unquoted).
pub(super) fn opt_name(p: &Value, key: &str) -> Result<Option<String>> {
    let Some(t) = opt_str(p, key)? else {
        return Ok(None);
    };
    let t = t.trim();
    if t.is_empty() || t.len() > MAX_NAME || t.chars().any(char::is_control) {
        return Err(EngineError::bad(
            key,
            format!("1..={MAX_NAME} bytes without control characters"),
        ));
    }
    Ok(Some(t.to_owned()))
}

/// `rate_limit`: RouterOS text, checked by the RADIUS parser (the same
/// `Mikrotik-Rate-Limit` syntax). `""` or `none` clears it.
pub(super) fn opt_rate_limit(p: &Value) -> Result<Option<Option<String>>> {
    match opt_str(p, "rate_limit")? {
        None => Ok(None),
        Some(t) if t.trim().is_empty() || t.trim() == "none" => Ok(Some(None)),
        Some(t) => t
            .trim()
            .parse::<RateLimit>()
            .map(|_| Some(Some(t.trim().to_owned())))
            .map_err(|e| {
                EngineError::bad(
                    "rate_limit",
                    format!("{e}: rx/tx [burst-rx/tx [threshold-rx/tx [time-rx/tx [priority [min-rx/tx]]]]], as 10M/50M"),
                )
            }),
    }
}

/// `address_list`: a firewall list name; `""` clears it.
pub(super) fn opt_address_list(p: &Value) -> Result<Option<Option<String>>> {
    match opt_str(p, "address_list")? {
        None => Ok(None),
        Some(t) if t.trim().is_empty() => Ok(Some(None)),
        Some(t) => t
            .trim()
            .parse::<Name>()
            .map(|n| Some(Some(n.as_str().to_owned())))
            .map_err(|e| EngineError::bad("address_list", e.to_string())),
    }
}

/// `on_up` / `on_down`: `[{command, params?}]` (or `""` to clear). Each
/// command must exist, not start a task, not be a PPP command (no loops),
/// and take the parameters given; `$user` and the other [`HOOK_VARS`] are
/// allowed inside string values.
pub(super) fn opt_hooks(p: &Value, key: &str) -> Result<Option<Vec<PppHook>>> {
    let parsed;
    let items = match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => return Ok(Some(Vec::new())),
        // The terminal (and `/export`) gives the list as JSON text.
        Some(Value::String(s)) if s.len() <= 16_384 => {
            parsed = serde_json::from_str::<Value>(s)
                .map_err(|_| EngineError::bad(key, "a list of {command, params} (JSON)"))?;
            parsed
                .as_array()
                .ok_or_else(|| EngineError::bad(key, "a list of {command, params}"))?
        }
        Some(Value::Array(a)) => a,
        Some(_) => return Err(EngineError::bad(key, "a list of {command, params}")),
    };
    if items.len() > MAX_HOOKS {
        return Err(EngineError::bad(key, format!("at most {MAX_HOOKS} commands")));
    }
    let mut out = Vec::new();
    for it in items {
        let Some(o) = it.as_object() else {
            return Err(EngineError::bad(key, "each item is {command, params}"));
        };
        if let Some(k) = o.keys().find(|k| *k != "command" && *k != "params") {
            let shown: String = k.chars().take(32).collect();
            return Err(EngineError::bad(key, format!("unknown key '{shown}' (command, params)")));
        }
        let id = o.get("command").and_then(Value::as_str).unwrap_or_default();
        let shown: String = id.chars().take(64).collect();
        let Some(spec) = super::find(id) else {
            return Err(EngineError::bad(key, format!("no command '{shown}'")));
        };
        if spec.task || id.starts_with("ppp.") || id.starts_with("interface.pppoe-server.") {
            return Err(EngineError::bad(
                key,
                format!("'{shown}' cannot run from a PPP hook (tasks and PPP commands are refused)"),
            ));
        }
        let params = match o.get("params") {
            None | Some(Value::Null) => serde_json::Map::new(),
            Some(Value::Object(m)) => m.clone(),
            Some(_) => return Err(EngineError::bad(key, "params must be an object")),
        };
        if serde_json::to_string(&params).map_or(0, |t| t.len()) > 4096 {
            return Err(EngineError::bad(key, "params at most 4096 bytes"));
        }
        super::check_params(spec, &Value::Object(params.clone()))
            .map_err(|e| EngineError::bad(key, format!("{shown}: {e}")))?;
        out.push(PppHook { command: id.to_owned(), params });
    }
    Ok(Some(out))
}

/// Refuse a change that would end `n` active sessions unless `force`
/// (RouterOS drops them silently; an ISP operator wants to know first).
pub(super) fn guard_drops(
    s: &Session,
    p: &Value,
    what: &str,
    hit: impl Fn(&ActiveSession) -> bool,
) -> Result<usize> {
    let n = s.ppp_active().iter().filter(|a| hit(a)).count();
    if n > 0 && !opt_bool(p, "force")?.unwrap_or(false) {
        return Err(EngineError::bad(
            "force",
            format!("{what} drops {n} active session(s): repeat with force=yes (in Safe Mode the change is undone if you lose the router)"),
        ));
    }
    Ok(n)
}
