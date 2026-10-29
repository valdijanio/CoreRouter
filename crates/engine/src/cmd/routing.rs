//! /routing bgp

use std::net::Ipv4Addr;

use corerouter_model::{Asn, BgpInstance};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text, req_parse};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "routing.bgp.instance.set",
        "BGP Instance",
        ["Routing", "BGP"],
        None,
        "{asn: u32 | asdot string, router_id: ipv4, name?: string (default \"default\"), disabled?: bool, comment?: string, graceful_restart_time?: u16 | null (RFC 4724 Restart Time we announce, 1..=4095 s; default 120; absent: kept), graceful_stale_time?: u16 | null (how long a restarted neighbor's routes stay stale, 1..=4095 s; default 360; absent: kept), graceful_defer_time?: u16 | null (after bgpd starts, how long the best path waits for the End-of-RIB of graceful-restart neighbors, 0..=3600 s; default 10; absent: kept)} → {name, frr}",
        always,
        instance_set
    ),
    cmd!(query "routing.bgp.instance.list", "BGP Instances", ["Routing", "BGP"], None,
        "{} → [{name, asn, router_id, disabled, comment, graceful_restart_time? (unset: 120 s), graceful_stale_time? (unset: 360 s), graceful_defer_time? (unset: 10 s)}]",
        always, instance_list),
];

fn parse_asn(p: &Value) -> Result<Asn> {
    match p.get("asn") {
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .map(Asn)
            .ok_or_else(|| EngineError::bad("asn", "must be 0..=4294967295")),
        Some(Value::String(s)) => s
            .parse()
            .map_err(|e: corerouter_model::ParseError| EngineError::bad("asn", e.to_string())),
        _ => Err(EngineError::bad(
            "asn",
            "is required (number or asdot string)",
        )),
    }
}

fn instance_set(s: &mut Session, p: &Value) -> Result<Value> {
    let asn = parse_asn(p)?;
    let router_id: Ipv4Addr = req_parse(p, "router_id")?;
    let name = opt_str(p, "name")?.unwrap_or("default").to_owned();
    if name.is_empty()
        || name.len() > 32
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(EngineError::bad("name", "1..=32 chars of [A-Za-z0-9_-]"));
    }
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    // G3.9ff: absent keeps what the instance had, null goes back to FRR's
    // default.
    let prev = s.store().candidate().routing.bgp.get(&name).cloned();
    let gr_time = |key: &str, had: Option<u16>| -> Result<Option<u16>> {
        match p.get(key) {
            None => Ok(had),
            Some(Value::Null) => Ok(None),
            Some(v) => v
                .as_u64()
                .and_then(|t| u16::try_from(t).ok())
                .filter(|t| (1..=corerouter_proto_bgp::GR_MAX_TIME).contains(t))
                .map(Some)
                .ok_or_else(|| EngineError::bad(key, "1..=4095 seconds (RFC 4724 §3: the Restart Time is 12 bits), or null for the default")),
        }
    };
    let graceful_restart_time = gr_time("graceful_restart_time", prev.as_ref().and_then(|i| i.graceful_restart_time))?;
    let graceful_stale_time = gr_time("graceful_stale_time", prev.as_ref().and_then(|i| i.graceful_stale_time))?;
    let graceful_defer_time = match p.get("graceful_defer_time") {
        None => prev.as_ref().and_then(|i| i.graceful_defer_time),
        Some(Value::Null) => None,
        Some(v) => Some(
            v.as_u64()
                .and_then(|t| u16::try_from(t).ok())
                .filter(|t| *t <= corerouter_proto_bgp::GR_MAX_DEFER)
                .ok_or_else(|| EngineError::bad("graceful_defer_time", "0..=3600 seconds, or null for the default (10)"))?,
        ),
    };
    let inst = BgpInstance {
        name: name.clone(),
        asn,
        router_id,
        disabled,
        comment,
        graceful_restart_time,
        graceful_stale_time,
        graceful_defer_time,
    };
    let frr = corerouter_proto_bgp::render_frr(&inst);
    s.store_mut()
        .candidate_mut()
        .routing
        .bgp
        .insert(name.clone(), inst);
    Ok(json!({ "name": name, "frr": frr }))
}

fn instance_list(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(Value::Array(
        s.store()
            .candidate()
            .routing
            .bgp
            .values()
            .map(|b| {
                json!({
                    "name": b.name,
                    "asn": b.asn,
                    "router_id": b.router_id.to_string(),
                    "disabled": b.disabled,
                    "comment": b.comment,
                    "graceful_restart_time": b.graceful_restart_time,
                    "graceful_stale_time": b.graceful_stale_time,
                    "graceful_defer_time": b.graceful_defer_time,
                })
            })
            .collect(),
    ))
}
