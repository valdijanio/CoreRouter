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
        "{asn: u32 | asdot string, router_id: ipv4, name?: string (default \"default\"), disabled?: bool, comment?: string} → {name, frr}",
        always,
        instance_set
    ),
    cmd!(query "routing.bgp.instance.list", "BGP Instances", ["Routing", "BGP"], None,
        "{} → [{name, asn, router_id, disabled, comment}]",
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
    let inst = BgpInstance {
        name: name.clone(),
        asn,
        router_id,
        disabled,
        comment,
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
                })
            })
            .collect(),
    ))
}
