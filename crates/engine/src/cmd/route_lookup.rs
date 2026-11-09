//! `ip.route.lookup` (G1.27): which route a packet to an address takes,
//! as Linux's `ip route get` and RouterOS' `/ip route check`. The logic is
//! `crate::route_lookup`.

use std::net::IpAddr;

use corerouter_model::RoutingTable;
use serde_json::{Value, json};

use super::args::{opt_parse, req_parse};
use super::{CommandSpec, always};
use corerouter_firewall::nft::{MarkKind, mark_value};
use corerouter_hal::route_get::PolicyQuery;
use corerouter_model::IfName;
use corerouter_model::firewall::Name;

use crate::route_lookup::{Flow, choose_table, differences, lookup, lookup_by_rules, query, vrf_of};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "ip.route.lookup", "Route Lookup", [], None,
    "{address: ip (where the packet goes), table?: string (main | VRF | routing.table name; default: what the rule list chooses), src?: ip (one of the router's addresses, or any with interface), interface?: string (incoming: a forwarded packet; needs src), routing_mark?: string (as the mangle would set it)} → {address, routing_table, rule (how the table was chosen), matched_rule (id of the routing rule that decided; null), trace: [{priority, rule, what, result}], type (unicast | local | unreachable | blackhole | prohibit; unreachable with route null: no route), route (null | {key, id, dst_address, gateway, distance, origin, flags}), prefix, nexthops: [{gateway, interface}], interface, gateway, src, ecmp, kernel: {available, reason, type, prefix, nexthops, src, same, differences: [string]}}",
    always, run)
.positional("address")];

pub(super) fn run(s: &mut Session, p: &Value) -> Result<Value> {
    let dst: IpAddr = req_parse(p, "address")?;
    let table: Option<RoutingTable> = opt_parse(p, "table")?;
    let src: Option<IpAddr> = opt_parse(p, "src")?;
    let iif: Option<IfName> = opt_parse(p, "interface")?;
    let mark_name: Option<Name> = opt_parse(p, "routing_mark")?;
    if iif.is_some() && src.is_none() {
        return Err(EngineError::bad(
            "src",
            "a forwarded packet needs its source (the kernel refuses to route one without)",
        ));
    }
    if table.is_some() && (iif.is_some() || mark_name.is_some()) {
        return Err(EngineError::bad(
            "table",
            "with a table given no rule is walked: interface and routing_mark mean nothing",
        ));
    }
    if let Some(src) = src
        && src.is_ipv4() != dst.is_ipv4()
    {
        return Err(EngineError::bad(
            "src",
            format!("{src} and {dst} are not of the same family"),
        ));
    }
    // What forwards now: the running config, not a transaction's candidate.
    // Without a transaction pending they are the same, and the lines kept
    // for the list (G1.27c) answer: no rebuild of a full table per lookup.
    let base = s.store().running().clone();
    let (cfg, lines) = if s.store().is_dirty() {
        let (cfg, lines) = s.route_lines_of(&base);
        (cfg, std::sync::Arc::new(lines))
    } else {
        let lines = s.route_lines();
        (s.effective(&base).into_owned(), lines)
    };
    if let Some(i) = &iif
        && !cfg.interfaces.contains_key(i)
    {
        return Err(EngineError::bad(
            "interface",
            format!("no interface '{i}' (see interface.list)"),
        ));
    }
    let mark = mark_name
        .as_ref()
        .map_or(0, |m| mark_value(MarkKind::Routing, m));
    let (chosen, why) = choose_table(&cfg, table.as_ref(), src, iif.is_some())
        .map_err(|(field, why)| EngineError::bad(field, why))?;
    // A table asked for is `ip route get … table t`; otherwise the kernel's
    // own walk, which the data plane is asked for as well.
    let (found, trace, policy) = if table.is_some() {
        (lookup(&cfg, &lines, dst, chosen, why, src), Vec::new(), None)
    } else {
        let flow = Flow {
            iif: iif.as_ref(),
            mark,
        };
        let (found, trace) = lookup_by_rules(&cfg, &lines, dst, src, &flow);
        let policy = PolicyQuery {
            iif: iif.clone(),
            mark,
            vrf: vrf_of(&cfg, iif.as_ref(), src),
        };
        (found, trace, Some(policy))
    };
    let matched_rule = trace.last().and_then(|t| t.rule);
    let route = found
        .route
        .as_ref()
        .and_then(|k| lines.iter().find(|l| l.key == *k))
        .map(|l| {
            json!({
                "key": l.key,
                "id": l.id,
                "dst_address": l.dst.to_string(),
                "gateway": l.gateway,
                "distance": l.distance,
                "origin": l.origin.as_str(),
                "flags": l.flags(),
            })
        });
    let kernel = match s.hal_mut().route_get(&cfg, &query(&found, dst, src, policy)) {
        Ok(k) => {
            let diff = differences(&found, &k);
            json!({
                "available": true,
                "reason": null,
                "type": k.kind.as_str(),
                "prefix": k.prefix.map(|p| p.to_string()),
                "nexthops": k.hops,
                "src": k.src,
                "same": diff.is_empty(),
                "differences": diff,
            })
        }
        Err(e) => json!({
            "available": false,
            "reason": e.to_string(),
            "same": null,
            "differences": [],
        }),
    };
    let first = found.hops.first();
    Ok(json!({
        "address": dst,
        "routing_table": found.table,
        "rule": found.rule,
        "matched_rule": matched_rule,
        "trace": trace,
        "type": found.kind.as_str(),
        "route": route,
        "prefix": found.prefix.map(|p| p.to_string()),
        "nexthops": found.hops,
        "interface": first.map(|h| &h.interface),
        "gateway": first.and_then(|h| h.gateway),
        "src": found.src,
        "ecmp": found.hops.len() > 1,
        "kernel": kernel,
    }))
}
