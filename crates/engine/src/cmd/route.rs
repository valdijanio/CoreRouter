//! /ip route — static routes, plus the connected routes derived from IP
//! addresses in `ip.route.list` (flagged dynamic/connected, as in RouterOS).

use corerouter_model::dhcp_client::CheckGateway;
use corerouter_model::{
    Config, DEFAULT_DISTANCE, Gateway, ItemId, RouteEntry, RoutingTable, parse_destination,
};
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32, req_parse, req_str};
use super::{CommandSpec, always};
use crate::dhcp_client::is_dynamic;
use crate::route_table::{Line, Origin, RouteWatch, State};
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
        "{dst_address: cidr | ip (0.0.0.0/0, ::/0, 10.1.0.0/16, 192.0.2.7), gateway: ip | interface | ip%interface, distance?: u32 (1..=255, default 1), routing_table?: string (main | VRF name, default main), check_gateway?: none | ping | arp | bfd (default none; ping/arp every 10 s, down after 2 misses: the route leaves the kernel and the next distance wins), bfd_profile?: string (check_gateway=bfd; default 'default'), disabled?: bool, comment?: string} → {id}",
        always,
        add
    ),
    cmd!(
        "ip.route.set",
        "Set Route",
        [],
        None,
        "{id: *hex, dst_address?: cidr | ip, gateway?: ip | interface | ip%interface, distance?: u32 (1..=255), routing_table?: string, check_gateway?: none | ping | arp | bfd, bfd_profile?: string (check_gateway=bfd; empty: default), disabled?: bool, comment?: string} → {id}",
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
    cmd!(query "ip.route.check.list", "Gateway Checks", [], None,
        "{} → [{gateway, method (arp | ping | bfd), routing_table, bfd_profile (bfd; null), routes (static routes sharing this check), status (checking | reachable | unreachable), misses, down_secs (null: up), hold_down_secs (null: no hold-down), flaps_15m}]",
        always, check_list),
    cmd!(query "ip.route.check.history", "Gateway Check History", [], None,
        "{gateway?: ip} → [{time (Unix s; null: no clock), gateway, method, to (up | down), routes, message}]",
        always, check_history),
    cmd!(query "ip.route.list", "Routes", ["IP", "Routes"], None,
        "{routing_table?: string, family?: string (ipv4 | ipv6), state?: string (active | standby | inactive), origin?: string (connected | static | dhcp | ra)} → [{key (stable row key), id (null if connected), dst_address, family, gateway (as configured), gateway_address, gateway_interface, gateway_status (reachable | unreachable | incomplete: the gateway does not answer ARP/ND; null if connected), check_gateway (null | {method (arp | ping | bfd), interval_secs (0: bfd), misses, state (up | down), status (checking | reachable | unreachable | not-checked), hold_down_secs (answers again, held for flapping; null), bfd_profile (bfd; null)}), distance, routing_table, flags (X disabled, A active, D dynamic, C connected, S static, + ECMP), state (active | standby: a lower distance wins | inactive), active, static, connected, dynamic (from a DHCP lease, a Router Advertisement or connected), origin (connected | static | dhcp | ra), disabled, immediate_gw, interface, ecmp (paths of its ECMP group), reason (why standby or inactive), reason_id, reason_args, changed_at (Unix s it took its state; null: before watching), changed_secs, comment}]",
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
    let check_gateway: CheckGateway = opt_parse(p, "check_gateway")?.unwrap_or_default();
    let bfd_profile = opt_text(p, "bfd_profile", 48)?.unwrap_or_default();

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
        check_gateway,
        bfd_profile,
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
                "{id} is dynamic (a DHCP client's route or a Router Advertisement); change the \
                 client instead (ip.dhcp-client.set / ipv6.dhcp-client.set add_default_route, \
                 default_route_distance) or stop accepting RA (ipv6.settings.set)"
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
    let check_gateway: Option<CheckGateway> = opt_parse(p, "check_gateway")?;
    let bfd_profile = opt_text(p, "bfd_profile", 48)?;

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
    if let Some(m) = check_gateway {
        route.check_gateway = m;
        // Leaving bfd drops its profile, unless one is given anyway.
        if m != CheckGateway::Bfd && bfd_profile.is_none() {
            route.bfd_profile.clear();
        }
    }
    if let Some(b) = bfd_profile {
        route.bfd_profile = b;
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

/// A filter value of `ip.route.list`, checked against its choices.
fn opt_choice<'a>(p: &'a Value, key: &str, choices: &[&str]) -> Result<Option<&'a str>> {
    match opt_str(p, key)? {
        Some(v) if choices.contains(&v) => Ok(Some(v)),
        Some(v) => Err(EngineError::bad(
            key,
            format!(
                "'{}' is not one of {}",
                v.chars().take(32).collect::<String>(),
                choices.join(", ")
            ),
        )),
        None => Ok(None),
    }
}

/// G1.27d: a gateway whose neighbor entry did not resolve (RFC 4861
/// §7.3.2 INCOMPLETE, or FAILED: nothing answered the ARP request or the
/// Neighbor Solicitation) is `incomplete`: routed, but the packets go
/// nowhere. No entry: not asked yet, so still `reachable`.
pub(crate) fn layer2(row: &mut Value, l: &Line, t: &crate::neigh_table::NeighTable) {
    let Some(crate::route_table::Via {
        link,
        gateway: Some(gw),
    }) = &l.via
    else {
        return;
    };
    if t.get(link, *gw).is_some_and(|r| !r.state.resolved())
        && let Some(o) = row.as_object_mut()
    {
        o.insert("gateway_status".into(), json!("incomplete"));
    }
}

/// `ip.route.list`'s view of one route.
pub(crate) fn row(l: &Line, watch: Option<&RouteWatch>, now: Option<u64>) -> Value {
    let (reason, reason_id, reason_args) = match &l.why {
        Some(w) => (
            Some(w.text.clone()),
            Some(w.id),
            Some(
                w.args
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), Value::String(v.clone())))
                    .collect::<serde_json::Map<_, _>>(),
            ),
        ),
        None => (None, None, None),
    };
    let changed_at = watch.and_then(|w| w.changed_at(&l.key));
    let gateway_status = match l.origin {
        Origin::Connected => None,
        _ if l.via.is_some() => Some("reachable"),
        _ => Some("unreachable"),
    };
    let check = l.check.as_ref().map(|c| {
        json!({
            "method": c.method,
            "interval_secs": c.interval_secs,
            "misses": c.misses,
            "state": if c.down { "down" } else { "up" },
            "status": c.status,
            "hold_down_secs": c.hold_secs,
            "bfd_profile": c.profile,
        })
    });
    json!({
        "key": l.key,
        "id": l.id,
        "dst_address": l.dst.to_string(),
        "family": if l.dst.addr().is_ipv4() { "ipv4" } else { "ipv6" },
        "gateway": l.gateway,
        "gateway_address": l.gateway_address,
        "gateway_interface": l.gateway_interface,
        "gateway_status": gateway_status,
        "check_gateway": check,
        "distance": l.distance,
        "routing_table": l.table,
        "flags": l.flags(),
        "state": l.state.as_str(),
        "active": l.state == State::Active,
        "static": matches!(l.origin, Origin::Static | Origin::Dhcp),
        "origin": l.origin.as_str(),
        "connected": l.origin == Origin::Connected,
        "dynamic": l.origin != Origin::Static,
        "disabled": l.disabled,
        "immediate_gw": l.immediate_gw(),
        "interface": l.via.as_ref().map(|v| &v.link),
        "ecmp": l.ecmp,
        "reason": reason,
        "reason_id": reason_id,
        "reason_args": reason_args,
        "changed_at": changed_at,
        "changed_secs": changed_at.zip(now).map(|(at, now)| now.saturating_sub(at)),
        "comment": l.comment,
    })
}

fn check_list(s: &mut Session, _p: &Value) -> Result<Value> {
    Ok(Value::Array(s.route_check_rows()))
}

fn check_history(s: &mut Session, p: &Value) -> Result<Value> {
    let gateway: Option<std::net::IpAddr> = opt_parse(p, "gateway")?;
    Ok(Value::Array(s.route_check_history(gateway)))
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let table: Option<RoutingTable> = opt_parse(p, "routing_table")?;
    let family = opt_choice(p, "family", &["ipv4", "ipv6"])?;
    let state = opt_choice(p, "state", &["active", "standby", "inactive"])?;
    let origin = opt_choice(p, "origin", &["connected", "static", "dhcp", "ra"])?;
    let (lines, now) = s.watched_route_lines();
    let neigh = s.neigh_fresh();
    let neigh = neigh.lock();
    let watch = s.ext::<RouteWatch>();
    let rows = lines
        .iter()
        .filter(|l| table.as_ref().is_none_or(|t| *t == l.table))
        .filter(|l| family.is_none_or(|f| (f == "ipv4") == l.dst.addr().is_ipv4()))
        .filter(|l| state.is_none_or(|st| st == l.state.as_str()))
        .filter(|l| origin.is_none_or(|o| o == l.origin.as_str()))
        .map(|l| {
            let mut r = row(l, watch, now);
            layer2(&mut r, l, &neigh);
            r
        })
        .collect::<Vec<_>>();
    drop(neigh);
    let mut rows = rows;
    crate::mpls::annotate_routes(s, &mut rows);
    Ok(Value::Array(rows))
}
