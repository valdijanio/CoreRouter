//! `ip.route.lookup` (G1.27): which route a packet to an address takes,
//! as Linux's `ip route get` and RouterOS' `/ip route check`. The logic is
//! `crate::route_lookup`.

use std::net::IpAddr;

use corerouter_model::RoutingTable;
use serde_json::{Value, json};

use super::args::{opt_parse, req_parse};
use super::{CommandSpec, always};
use crate::route_lookup::{choose_table, differences, lookup, query};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "ip.route.lookup", "Route Lookup", [], None,
    "{address: ip (where the packet goes), table?: string (main | VRF name; default: the VRF of src, else main), src?: ip (one of the router's addresses)} → {address, routing_table, rule (how the table was chosen), type (unicast | local | unreachable), route (null | {key, id, dst_address, gateway, distance, origin, flags}), prefix, nexthops: [{gateway, interface}], interface, gateway, src, ecmp, kernel: {available, reason, type, prefix, nexthops, src, same, differences: [string]}}",
    always, run)
.positional("address")];

fn run(s: &mut Session, p: &Value) -> Result<Value> {
    let dst: IpAddr = req_parse(p, "address")?;
    let table: Option<RoutingTable> = opt_parse(p, "table")?;
    let src: Option<IpAddr> = opt_parse(p, "src")?;
    if let Some(src) = src
        && src.is_ipv4() != dst.is_ipv4()
    {
        return Err(EngineError::bad(
            "src",
            format!("{src} and {dst} are not of the same family"),
        ));
    }
    // What forwards now: the running config, not a transaction's candidate.
    let base = s.store().running().clone();
    let (cfg, lines) = s.route_lines_of(&base);
    let (table, rule) =
        choose_table(&cfg, table.as_ref(), src).map_err(|(field, why)| EngineError::bad(field, why))?;
    let found = lookup(&cfg, &lines, dst, table, rule, src);
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
    let kernel = match s.hal_mut().route_get(&cfg, &query(&found, dst, src)) {
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
