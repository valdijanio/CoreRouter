//! ip.dhcp-server.history and ip.dhcp-server.config (G4.2b): who had an
//! address when (the bindings, with MAC, client id, name and the port of
//! option 82), kept for `history_retention` (a year by default: the
//! connection records of Brazil's Marco Civil), exported as CSV.

use std::net::Ipv4Addr;

use corerouter_model::MacAddr;
use corerouter_proto_dhcp::server::history::{self, Entry, Query, csv, parse_time, utc};
use serde_json::{Value, json};

use super::args::{opt_parse, opt_str, opt_u32};
use super::dhcp_server::{opt_secs, secs_text};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

/// Rows a print returns unless asked for fewer.
const DEFAULT_LIMIT: u32 = 200;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "ip.dhcp-server.history.print", "DHCP Lease History", [], None,
        "{address?: ipv4, mac?: mac, at?: time (who had it at that instant: 2026-10-03T14:02:00-03:00, a date, or Unix seconds), from?: time, to?: time (bindings that overlap the span), text?: string (in host name, client id, circuit or remote id), limit?: u32 (default 200, at most 10000)} → {rows: [{address, mac, client_id?, host_name?, server, circuit_id?, remote_id?, start, end, start_unix, end_unix, open}], total (entries kept), retention}",
        always, print),
    cmd!(query "ip.dhcp-server.history.export", "Export DHCP History", [], None,
        "{address?: ipv4, mac?: mac, at?: time, from?: time, to?: time, text?: string, limit?: u32 (default and most 10000)} → {csv (RFC 4180, UTC times), rows}",
        always, export),
    cmd!(query "ip.dhcp-server.config.print", "DHCP Server Config", [], None,
        "{} → {history_retention, history_retention_secs, history_entries, history_error?}",
        always, config_print),
    cmd!(
        "ip.dhcp-server.config.set",
        "Set DHCP Server Config",
        [],
        None,
        "{history_retention?: duration (how long the lease history is kept: 365d default, 0 = no history; seconds or 52w)} → {history_retention}",
        always,
        config_set
    ),
];

fn time(p: &Value, key: &str) -> Result<Option<u64>> {
    let v = match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Number(n)) => n.as_u64().map(|n| n.to_string()).unwrap_or_default(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => String::new(),
    };
    parse_time(&v).map(Some).ok_or_else(|| {
        EngineError::bad(
            key,
            "a time: 2026-10-03T14:02:00-03:00, 2026-10-03 (UTC midnight) or Unix seconds",
        )
    })
}

fn query(p: &Value) -> Result<(Query, usize)> {
    let q = Query {
        address: opt_parse::<Ipv4Addr>(p, "address")?,
        mac: opt_parse::<MacAddr>(p, "mac")?.map(|m| m.0),
        at: time(p, "at")?,
        from: time(p, "from")?,
        to: time(p, "to")?,
        text: opt_str(p, "text")?.map(|t| t.chars().take(64).collect()),
    };
    let limit = opt_u32(p, "limit")?.unwrap_or(DEFAULT_LIMIT);
    Ok((q, usize::try_from(limit).unwrap_or(usize::MAX).min(history::MAX_ROWS)))
}

fn row(e: &Entry) -> Value {
    let mut v = json!({
        "address": e.address,
        "mac": MacAddr(e.mac).to_string(),
        "server": e.server,
        "start": utc(e.start),
        "end": utc(e.until),
        "start_unix": e.start,
        "end_unix": e.until,
        "open": !e.closed,
    });
    if let Some(o) = v.as_object_mut() {
        for (k, val) in [
            ("client_id", e.client_id.clone().unwrap_or_default()),
            ("host_name", e.host_name.clone()),
            ("circuit_id", e.circuit_id.clone()),
            ("remote_id", e.remote_id.clone()),
        ] {
            if !val.is_empty() {
                o.insert(k.into(), json!(val));
            }
        }
    }
    v
}

fn print(s: &mut Session, p: &Value) -> Result<Value> {
    let (q, limit) = query(p)?;
    let retention = s.store().running().ip.dhcp_server.config.history_retention;
    let Some(h) = s.dhcp_lease_history() else {
        return Ok(json!({"rows": [], "total": 0, "retention": secs_text(retention)}));
    };
    let rows: Vec<Value> = h.query(&q, limit).into_iter().map(row).collect();
    Ok(json!({"rows": rows, "total": h.len(), "retention": secs_text(retention)}))
}

fn export(s: &mut Session, p: &Value) -> Result<Value> {
    let (q, _) = query(p)?;
    let limit = opt_u32(p, "limit")?
        .map_or(history::MAX_ROWS, |l| usize::try_from(l).unwrap_or(usize::MAX))
        .min(history::MAX_ROWS);
    let Some(h) = s.dhcp_lease_history() else {
        return Ok(json!({"csv": csv(&[]), "rows": 0}));
    };
    let rows = h.query(&q, limit);
    Ok(json!({"csv": csv(&rows), "rows": rows.len()}))
}

fn config_print(s: &mut Session, _: &Value) -> Result<Value> {
    let r = s.store().candidate().ip.dhcp_server.config.history_retention;
    let mut v = json!({
        "history_retention": secs_text(r),
        "history_retention_secs": r,
        "history_entries": s.dhcp_lease_history().map_or(0, history::History::len),
    });
    if let (Some(e), Some(o)) = (s.dhcp_lease_history_error(), v.as_object_mut()) {
        o.insert("history_error".into(), json!(e));
    }
    Ok(v)
}

fn config_set(s: &mut Session, p: &Value) -> Result<Value> {
    if let Some(t) = opt_secs(p, "history_retention")? {
        if t > 10 * 365 * 86_400 {
            return Err(EngineError::bad("history_retention", "at most 10 years"));
        }
        s.store_mut().candidate_mut().ip.dhcp_server.config.history_retention = t;
    }
    let r = s.store().candidate().ip.dhcp_server.config.history_retention;
    Ok(json!({"history_retention": secs_text(r)}))
}
