//! /system ntp client (G4.6): servers to ask and the client's status.

use corerouter_model::{IfName, InterfaceKind};
use corerouter_model::ntp::{MAIN_VRF, MAX_SERVERS, NtpClient, POLL_RANGE, valid_server};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_u32};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "system.ntp.client.set",
        "NTP Client",
        ["System", "NTP Client"],
        None,
        "{enabled?: bool, servers?: [string], min_poll?: int 6..17, max_poll?: int 6..17, vrf?: string (default main), set_system_clock?: bool (default yes; no only measures)} → {enabled, servers, min_poll, max_poll, vrf, set_system_clock}",
        always,
        set
    ),
    cmd!(query "system.ntp.client.get", "NTP Client", [], None,
        "{} → {enabled, servers, min_poll, max_poll, vrf, set_system_clock, status: stopped|waiting|synchronized, synced_server, synced_address, synced_stratum, system_offset_ms, round_trip_ms, last_sync, last_error, poll_secs, dynamic_servers, clock: not-set|slewing|stepped|holding-spike|awaiting-confirmation|refused, last_adjustment_ms, freq_drift_ppm, pending_step_ms, clock_error}",
        always, get),
    cmd!(
        "system.ntp.client.confirm-step",
        "Confirm Clock Step",
        [],
        None,
        "{} → {pending_step_ms}",
        always,
        confirm_step
    ),
];

fn settings_json(c: &NtpClient) -> Value {
    json!({
        "enabled": c.enabled,
        "servers": c.servers,
        "min_poll": c.min_poll,
        "max_poll": c.max_poll,
        "vrf": c.vrf,
        "set_system_clock": c.set_system_clock,
    })
}

fn poll(p: &Value, key: &str) -> Result<Option<u8>> {
    let Some(v) = opt_u32(p, key)? else {
        return Ok(None);
    };
    u8::try_from(v)
        .ok()
        .filter(|v| POLL_RANGE.contains(v))
        .map(Some)
        .ok_or_else(|| {
            EngineError::bad(
                key,
                format!(
                    "must be {}..={} (a power of two in seconds: 6 = 64 s, 10 = 17 min); \
                     RFC 4330 §5 forbids asking more than once a minute",
                    POLL_RANGE.start(),
                    POLL_RANGE.end()
                ),
            )
        })
}

/// A JSON array of strings or, for the CLI, one comma-separated string.
fn servers(p: &Value) -> Result<Option<Vec<String>>> {
    let raw: Vec<String> = match p.get("servers") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|s| s.trim().to_owned())
                    .ok_or_else(|| EngineError::bad("servers", "each item must be a string"))
            })
            .collect::<Result<_>>()?,
        Some(_) => {
            return Err(EngineError::bad(
                "servers",
                "must be a list, e.g. [\"pool.ntp.org\", \"192.0.2.1\"]",
            ));
        }
    };
    if raw.len() > MAX_SERVERS {
        return Err(EngineError::bad(
            "servers",
            format!("at most {MAX_SERVERS} servers"),
        ));
    }
    let mut out: Vec<String> = Vec::new();
    for s in raw {
        valid_server(&s).map_err(|e| EngineError::bad("servers", e))?;
        if !out.contains(&s) {
            out.push(s);
        }
    }
    Ok(Some(out))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let enabled = opt_bool(p, "enabled")?;
    let servers = servers(p)?;
    let min_poll = poll(p, "min_poll")?;
    let max_poll = poll(p, "max_poll")?;
    let vrf = vrf(s, p)?;
    let set_system_clock = opt_bool(p, "set_system_clock")?;
    let mut c = s.store().candidate().system.ntp_client.clone();
    if let Some(e) = enabled {
        c.enabled = e;
    }
    if let Some(list) = servers {
        c.servers = list;
    }
    if let Some(m) = min_poll {
        c.min_poll = m;
    }
    if let Some(m) = max_poll {
        c.max_poll = m;
    }
    if c.min_poll > c.max_poll {
        return Err(EngineError::bad(
            if max_poll.is_some() {
                "max_poll"
            } else {
                "min_poll"
            },
            format!(
                "min_poll ({}) must not be above max_poll ({})",
                c.min_poll, c.max_poll
            ),
        ));
    }
    if let Some(v) = vrf {
        c.vrf = v;
    }
    if let Some(v) = set_system_clock {
        c.set_system_clock = v;
    }
    // A DHCP client with use_peer_ntp may bring the servers (G4.6b).
    let dhcp_brings = s
        .store()
        .candidate()
        .ip
        .dhcp_clients
        .iter()
        .any(|d| d.use_peer_ntp && !d.disabled);
    if c.enabled && c.servers.is_empty() && !dhcp_brings {
        return Err(EngineError::bad(
            "servers",
            "an enabled NTP client needs at least one server (e.g. \"pool.ntp.org\"), \
             or a DHCP client with use_peer_ntp",
        ));
    }
    let out = settings_json(&c);
    s.store_mut().candidate_mut().system.ntp_client = c;
    Ok(out)
}

/// `main`, or a VRF interface that exists (`vrf.add` first).
fn vrf(s: &Session, p: &Value) -> Result<Option<String>> {
    let Some(v) = opt_str(p, "vrf")? else {
        return Ok(None);
    };
    if v == MAIN_VRF {
        return Ok(Some(v.to_owned()));
    }
    let name: IfName = v.parse().map_err(|e| EngineError::bad("vrf", format!("{e}")))?;
    match s.store().candidate().interfaces.get(&name).map(|i| &i.kind) {
        Some(InterfaceKind::Vrf { .. }) => Ok(Some(v.to_owned())),
        _ => Err(EngineError::bad(
            "vrf",
            format!("no VRF '{name}' (ip.vrf.add first)"),
        )),
    }
}

/// RFC 8633 §5.2: a step above the panic threshold takes a person. The
/// daemon measures again and steps only if the new offset is close to this.
fn confirm_step(s: &mut Session, _: &Value) -> Result<Value> {
    let Some(pending) = s.ntp_status().pending_step_ms else {
        return Err(EngineError::bad(
            "system.ntp.client.confirm-step",
            "no clock step is waiting for confirmation",
        ));
    };
    s.confirm_ntp_step();
    Ok(json!({"pending_step_ms": pending}))
}

fn get(s: &mut Session, _: &Value) -> Result<Value> {
    let mut out = settings_json(&s.store().candidate().system.ntp_client);
    let status = serde_json::to_value(s.ntp_status()).unwrap_or(Value::Null);
    if let (Some(o), Value::Object(st)) = (out.as_object_mut(), status) {
        o.extend(st);
    }
    Ok(out)
}
