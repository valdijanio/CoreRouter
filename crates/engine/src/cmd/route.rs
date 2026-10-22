//! /ip route — static routes, plus the connected routes derived from IP
//! addresses in `ip.route.list` (flagged dynamic/connected, as in RouterOS).

use std::cmp::Ordering;

use corerouter_model::route::{self, Reach};
use corerouter_model::{
    Config, DEFAULT_DISTANCE, Gateway, ItemId, RouteEntry, RoutingTable, parse_destination,
};
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32, req_parse, req_str};
use super::{CommandSpec, always};
use crate::dhcp_client::is_dynamic;
use crate::validate::route_issues;
use crate::{EngineError, Result, Session};

/// Hostile-input bound on static routes (a full BGP table belongs to BGP,
/// not to static routes; **estimado**).
pub const MAX_ROUTES: usize = 65_536;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.route.add",
        "Add Route",
        ["IP", "Routes"],
        None,
        "{dst_address: cidr | ip (0.0.0.0/0, ::/0, 10.1.0.0/16, 192.0.2.7), gateway: ip | interface | ip%interface, distance?: u32 (1..=255, default 1), routing_table?: string (main | VRF name, default main), disabled?: bool, comment?: string} → {id}",
        always,
        add
    ),
    cmd!(
        "ip.route.set",
        "Set Route",
        [],
        None,
        "{id: *hex, dst_address?: cidr | ip, gateway?: ip | interface | ip%interface, distance?: u32 (1..=255), routing_table?: string, disabled?: bool, comment?: string} → {id}",
        has_routes,
        set
    ),
    cmd!(
        "ip.route.remove",
        "Remove Route",
        [],
        None,
        "{id: *hex (a static route; connected ones go with their address)} → {id}",
        has_routes,
        remove
    ),
    cmd!(query "ip.route.list", "Routes", ["IP", "Routes"], None,
        "{routing_table?: string} → [{id (null if connected), dst_address, gateway, distance, routing_table, flags (X disabled, A active, D dynamic, C connected, S static), active, static, connected, dynamic (from a DHCP lease or connected), disabled, immediate_gw, reason, comment}]",
        always, list),
];

fn has_routes(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.routes.is_empty() {
        Err("there are no static routes".into())
    } else {
        Ok(())
    }
}

fn opt_dst(p: &Value) -> Result<Option<IpNet>> {
    opt_str(p, "dst_address")?
        .map(|s| parse_destination(s).map_err(|e| EngineError::bad("dst_address", e.to_string())))
        .transpose()
}

fn opt_distance(p: &Value) -> Result<Option<u8>> {
    opt_u32(p, "distance")?
        .map(|d| {
            u8::try_from(d)
                .ok()
                .filter(|d| *d >= 1)
                .ok_or_else(|| EngineError::bad("distance", "must be 1..=255"))
        })
        .transpose()
}

/// Refuse `r` with the first problem the validator sees in it.
fn check(cfg: &Config, r: &RouteEntry) -> Result<()> {
    match route_issues(cfg, r, cfg.ip.routes.iter())
        .into_iter()
        .next()
    {
        Some((field, why)) => Err(EngineError::bad(field, why)),
        None => Ok(()),
    }
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let dst = parse_destination(req_str(p, "dst_address")?)
        .map_err(|e| EngineError::bad("dst_address", e.to_string()))?;
    let gateway: Gateway = req_parse(p, "gateway")?;
    let distance = opt_distance(p)?.unwrap_or(DEFAULT_DISTANCE);
    let routing_table: RoutingTable = opt_parse(p, "routing_table")?.unwrap_or_default();
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();

    let cfg = s.store_mut().candidate_mut();
    if cfg.ip.routes.len() >= MAX_ROUTES {
        return Err(EngineError::bad(
            "dst_address",
            format!("at most {MAX_ROUTES} static routes"),
        ));
    }
    let id = cfg.ip.next_route_id();
    let route = RouteEntry {
        id,
        dst_address: dst,
        gateway,
        distance,
        routing_table,
        disabled,
        comment,
    };
    check(cfg, &route)?;
    cfg.ip.routes.push(route);
    Ok(json!({ "id": id }))
}

/// Parse `id` as a static route of the candidate.
fn existing(cfg: &Config, p: &Value) -> Result<(usize, ItemId)> {
    let id: ItemId = req_parse(p, "id")?;
    if is_dynamic(id) {
        return Err(EngineError::bad(
            "id",
            format!(
                "{id} is dynamic (a DHCP client's route); change the client instead \
                 (ip.dhcp-client.set add_default_route, default_route_distance)"
            ),
        ));
    }
    let pos = cfg
        .ip
        .routes
        .iter()
        .position(|r| r.id == id)
        .ok_or_else(|| {
            EngineError::bad(
                "id",
                format!(
                    "no static route {id} (see ip.route.list; connected routes come and go with \
                 their IP address)"
                ),
            )
        })?;
    Ok((pos, id))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let dst = opt_dst(p)?;
    let gateway: Option<Gateway> = opt_parse(p, "gateway")?;
    let distance = opt_distance(p)?;
    let table: Option<RoutingTable> = opt_parse(p, "routing_table")?;
    let disabled = opt_bool(p, "disabled")?;
    let comment = opt_text(p, "comment", 256)?;

    let cfg = s.store_mut().candidate_mut();
    let (pos, id) = existing(cfg, p)?;
    let mut route = cfg
        .ip
        .routes
        .get(pos)
        .cloned()
        .ok_or_else(|| EngineError::bad("id", format!("no static route {id}")))?;
    if let Some(d) = dst {
        route.dst_address = d;
    }
    if let Some(g) = gateway {
        route.gateway = g;
    }
    if let Some(d) = distance {
        route.distance = d;
    }
    if let Some(t) = table {
        route.routing_table = t;
    }
    if let Some(d) = disabled {
        route.disabled = d;
    }
    if let Some(c) = comment {
        route.comment = c;
    }
    check(cfg, &route)?;
    if let Some(slot) = cfg.ip.routes.get_mut(pos) {
        *slot = route;
    }
    Ok(json!({ "id": id }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let cfg = s.store_mut().candidate_mut();
    let (pos, id) = existing(cfg, p)?;
    cfg.ip.routes.remove(pos);
    Ok(json!({ "id": id }))
}

/// One line of `ip.route.list` before it becomes JSON.
struct Line {
    id: Option<ItemId>,
    dst: IpNet,
    gateway: String,
    distance: u8,
    table: RoutingTable,
    usable: bool,
    connected: bool,
    disabled: bool,
    immediate: Option<String>,
    reason: Option<String>,
    comment: String,
}

/// Main table first, then VRFs by name; inside a table by destination,
/// then distance (the winner first).
fn order(a: &Line, b: &Line) -> Ordering {
    (!a.table.is_main(), &a.table, a.dst, a.distance, a.id).cmp(&(
        !b.table.is_main(),
        &b.table,
        b.dst,
        b.distance,
        b.id,
    ))
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let filter: Option<RoutingTable> = opt_parse(p, "routing_table")?;
    // With the routes DHCP clients installed (flags DS, as in RouterOS v6).
    let cfg = s.effective(s.store().candidate());
    let cfg = cfg.as_ref();
    let mut lines: Vec<Line> = cfg
        .ip
        .routes
        .iter()
        .map(|r| {
            let (usable, immediate, reason) = match route::reach(cfg, r) {
                Reach::Active { link, gateway } => {
                    let via = match gateway {
                        Some(g) => format!("{g}%{link}"),
                        None => link.to_string(),
                    };
                    (true, Some(via), None)
                }
                Reach::Inactive(why) => (false, None, Some(why)),
                Reach::Invalid { why, .. } => (false, None, Some(why)),
            };
            Line {
                id: Some(r.id),
                dst: r.dst_address,
                gateway: r.gateway.to_string(),
                distance: r.distance,
                table: r.routing_table.clone(),
                usable,
                connected: false,
                disabled: r.disabled,
                immediate,
                reason,
                comment: r.comment.clone(),
            }
        })
        .collect();
    lines.extend(route::connected(cfg).into_iter().map(|c| Line {
        id: None,
        dst: c.dst,
        gateway: c.interface.to_string(),
        distance: 0,
        table: c.table,
        usable: c.active,
        connected: true,
        disabled: false,
        immediate: c.active.then(|| c.interface.to_string()),
        reason:
            (!c.active).then(|| format!("interface '{}' or its address is disabled", c.interface)),
        comment: String::new(),
    }));
    lines.sort_by(order);

    let mut rows = Vec::with_capacity(lines.len());
    for (i, l) in lines.iter().enumerate() {
        if filter.as_ref().is_some_and(|t| *t != l.table) {
            continue;
        }
        // Lines are sorted by distance inside (table, dst): the first usable
        // one is the active route, as the kernel picks the lowest metric.
        let winner = lines
            .iter()
            .take(i)
            .find(|o| o.usable && o.table == l.table && o.dst == l.dst);
        let active = l.usable && winner.is_none();
        let reason = match (&l.reason, winner) {
            (Some(why), _) => Some(why.clone()),
            (None, Some(w)) if l.usable => Some(match w.id {
                Some(id) => format!("route {id} has a lower distance"),
                None => format!("connected network on {} wins", w.gateway),
            }),
            (None, _) => None,
        };
        let dynamic = l.connected || l.id.is_some_and(is_dynamic);
        let mut flags = String::new();
        if l.disabled {
            flags.push('X');
        }
        if active {
            flags.push('A');
        }
        flags.push_str(match (l.connected, dynamic) {
            (true, _) => "DC",
            (false, true) => "DS",
            (false, false) => "S",
        });
        rows.push(json!({
            "id": l.id,
            "dst_address": l.dst.to_string(),
            "gateway": l.gateway,
            "distance": l.distance,
            "routing_table": l.table,
            "flags": flags,
            "active": active,
            "static": !l.connected,
            "connected": l.connected,
            "dynamic": dynamic,
            "disabled": l.disabled,
            "immediate_gw": l.immediate,
            "reason": reason,
            "comment": l.comment,
        }));
    }
    Ok(Value::Array(rows))
}
