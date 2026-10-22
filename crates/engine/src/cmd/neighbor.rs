//! /ip neighbor: routers heard by CRDP, LLDP and MNDP, and where discovery runs.

use std::collections::BTreeSet;

use corerouter_model::neighbor::INTERVAL_RANGE;
use corerouter_model::{IfName, NeighborDiscovery, NeighborEntry, NeighborProtocol};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_u32};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "ip.neighbor.list", "Neighbors", ["IP", "Neighbors"], None,
        "{interface?: string, protocol?: crdp|lldp|mndp} → [{interface, protocol, address, mac, addresses, identity, version, platform, board, uptime_secs, node_id, remote_interface, mgmt: {control, ws}, age_secs, expires_in_secs}]",
        always, list),
    cmd!(
        "ip.neighbor.discovery.set",
        "Discovery Settings",
        ["IP", "Neighbors"],
        None,
        "{enabled?: bool, interfaces?: [string], interval_secs?: int 1..3600} → {enabled, interfaces, interval_secs}",
        always,
        discovery_set
    ),
    cmd!(query "ip.neighbor.discovery.get", "Discovery Settings", [], None,
        "{} → {enabled, interfaces, interval_secs}",
        always, discovery_get),
];

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let interface: Option<IfName> = opt_parse(p, "interface")?;
    let protocol: Option<NeighborProtocol> = opt_parse(p, "protocol")?;
    let settings = s.discovery_settings();
    let now = s.neighbors().now();
    let rows = s
        .neighbors()
        .iter()
        .filter(|e| settings.active_on(&e.interface))
        .filter(|e| interface.as_ref().is_none_or(|i| *i == e.interface))
        .filter(|e| protocol.is_none_or(|p| p == e.protocol))
        .map(|e| row(e, now))
        .collect();
    Ok(Value::Array(rows))
}

fn row(e: &NeighborEntry, now: u64) -> Value {
    let expires = e.last_seen.saturating_add(u64::from(e.hold_secs));
    json!({
        "interface": e.interface,
        "protocol": e.protocol,
        // What the Neighbors table shows in its Address column.
        "address": e.addresses.first().map(ToString::to_string),
        "mac": e.mac,
        "addresses": e.addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "identity": e.identity,
        "version": e.version,
        "platform": e.platform,
        "board": e.board,
        "uptime_secs": e.uptime_secs,
        "node_id": e.node_id,
        "remote_interface": e.remote_interface,
        "mgmt": e.mgmt,
        "age_secs": now.saturating_sub(e.last_seen),
        "expires_in_secs": expires.saturating_sub(now),
    })
}

fn settings_json(d: &NeighborDiscovery) -> Value {
    json!({
        "enabled": d.enabled,
        "interfaces": d.interfaces,
        "interval_secs": d.interval_secs,
    })
}

fn discovery_set(s: &mut Session, p: &Value) -> Result<Value> {
    let enabled = opt_bool(p, "enabled")?;
    let interval = opt_u32(p, "interval_secs")?;
    let interfaces = match p.get("interfaces") {
        None | Some(Value::Null) => None,
        Some(Value::Array(list)) => Some(interface_list(s, list)?),
        Some(_) => {
            return Err(EngineError::bad(
                "interfaces",
                "must be a list of interface names, e.g. [\"ether2\", \"bridge1\"]",
            ));
        }
    };
    if let Some(i) = interval
        && !INTERVAL_RANGE.contains(&i)
    {
        return Err(EngineError::bad(
            "interval_secs",
            format!(
                "must be {}..={} seconds",
                INTERVAL_RANGE.start(),
                INTERVAL_RANGE.end()
            ),
        ));
    }
    let d = &mut s.store_mut().candidate_mut().ip.neighbor_discovery;
    if let Some(e) = enabled {
        d.enabled = e;
    }
    if let Some(i) = interval {
        d.interval_secs = i;
    }
    if let Some(list) = interfaces {
        d.interfaces = list;
    }
    Ok(settings_json(d))
}

fn interface_list(s: &Session, list: &[Value]) -> Result<BTreeSet<IfName>> {
    let cfg = s.store().candidate();
    if list.len() > cfg.interfaces.len() {
        return Err(EngineError::bad(
            "interfaces",
            format!("at most {} names (one per interface)", cfg.interfaces.len()),
        ));
    }
    let mut out = BTreeSet::new();
    for v in list {
        let name: IfName = v
            .as_str()
            .ok_or_else(|| EngineError::bad("interfaces", "each item must be a string"))?
            .parse()
            .map_err(|e: corerouter_model::ParseError| {
                EngineError::bad("interfaces", e.to_string())
            })?;
        if !cfg.interfaces.contains_key(&name) {
            return Err(EngineError::bad(
                "interfaces",
                format!("no interface '{name}' (see interface.list)"),
            ));
        }
        out.insert(name);
    }
    Ok(out)
}

fn discovery_get(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(settings_json(&s.store().candidate().ip.neighbor_discovery))
}
