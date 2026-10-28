//! OSPF state (G3.4b): `/routing ospf neighbor` and `lsa` of RouterOS v7,
//! the routes, the interfaces as the daemon runs them, the topology drawn
//! from the LSDB, "why this path?" (the cost added hop by hop) and the
//! Diagnose of a neighbor that does not reach Full (with the RFC section).
//!
//! Neighbors and interfaces come with every routing poll; the LSDB is read
//! on demand outside the session lock (`crate::ospf_state`), so the first
//! answer may say `pending`. In the virtual lab all of it is a sample made
//! up from the config (`source`).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use corerouter_model::ospf::{AreaType, Version};
use corerouter_model::ospf_state::{Lsa, OspfNeighbor, ip};
use corerouter_proto_ospf::diagnose::{self, Local, Seen};
use corerouter_proto_ospf::topology::{self, Node};
use corerouter_proto_ospf::{bind, layout};
use serde_json::{Value, json};

use super::args::{opt_str, opt_u32, req_str};
use super::routing_ospf::cut;
use super::{CommandSpec, always};
use crate::ospf_state::DbView;
use crate::{EngineError, Result, Session};

/// Most rows of one page.
pub const MAX_PAGE: u32 = 1_000;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "routing.ospf.neighbor.list", "OSPF Neighbors", ["Routing", "OSPF"], None,
        "{instance?: string} → {source, rows: [{instance, version, router_id, address, interface, area, state (RFC 2328 §10.1: Down … Full), role (DR, Backup, DROther, ptp), label (\"Full · DR\"), priority, state_secs, dead_secs, bfd, retransmit, request, summary}]}",
        always, neighbor_list),
    cmd!(query "routing.ospf.interface.list", "OSPF Interfaces", ["Routing", "OSPF"], None,
        "{instance?: string} → {source, rows: [{instance, version, interface, area, template, network_type, state, address, cost, mtu, hello, dead, dr, bdr, passive, neighbors, adjacent, auth}]}",
        always, interface_list),
    cmd!(query "routing.ospf.lsa.list", "OSPF LSAs", ["Routing", "OSPF"], None,
        "{instance: string, type?: string (router, network, summary, asbr-summary, external, nssa-external), area?: string, find?: string (id or originator), offset?: u32, limit?: u32 (default 200, at most 1000)} → {source, pending, error?, total, by_type: {type: n}, rows: [{type, area, id, originator, age, sequence, self, links?, metric?, prefix?}]}",
        always, lsa_list),
    cmd!(query "routing.ospf.route.list", "OSPF Routes", ["Routing", "OSPF"], None,
        "{instance: string, find?: string} → {source, pending, error?, rows: [{prefix, kind (intra-area, inter-area, ext-1, ext-2), cost, type2_cost?, area?, nexthops: [{address?, interface}]}]}",
        always, route_list),
    cmd!(query "routing.ospf.topology", "OSPF Topology", ["Routing", "OSPF"], None,
        "{instance: string, area?: string (default: the first)} → {source, pending, area, areas: [string], nodes: [{key, kind (router | network), id, label, x, y (0..1), abr, asbr, self, neighbor?}], edges: [{a, b, cost, back_cost?}], layout_ms, threads}",
        always, topology_cmd),
    cmd!(query "routing.ospf.path", "Why This Path (OSPF)", ["Routing", "OSPF"], None,
        "{instance: string, to: ipv4 (an address or a router id)} → {source, pending, area?, hops: [{key, kind, id, cost, total}], total?, route?: {prefix, kind, cost, nexthops}, agrees?: bool (our SPF over the LSDB gives the daemon's cost)}",
        always, path_cmd),
    cmd!(query "routing.ospf.neighbor.diagnose", "Diagnose OSPF Neighbor", ["Routing", "OSPF"], None,
        "{interface: string, instance?: string} → {interface, instance, source, local: {area, network_type, hello, dead, mtu, auth, passive}, findings: [{level (error | warning | ok | info), check, message, rfc}]}",
        always, diagnose_cmd),
];

fn instance_arg(s: &Session, p: &Value) -> Result<String> {
    let name = req_str(p, "instance")?.trim().to_owned();
    if !s.store().running().routing.ospf.instances.contains_key(&name) {
        return Err(EngineError::bad("instance", format!("no OSPF instance {:?}", cut(&name))));
    }
    Ok(name)
}

/// "Full · DR", "Full · ptp", "ExStart" (the state chip of the window).
fn label(n: &OspfNeighbor) -> String {
    let role = match n.role.as_str() {
        "PointToPoint" | "Point-To-Point" | "ptp" => "ptp",
        "Backup" | "BDR" => "BDR",
        "" | "-" => "",
        r => r,
    };
    if n.state == "Full" && !role.is_empty() {
        format!("Full · {role}")
    } else {
        n.state.clone()
    }
}

fn neighbor_list(s: &mut Session, p: &Value) -> Result<Value> {
    let only = opt_str(p, "instance")?.map(str::to_owned);
    let (nbrs, _, source) = s.ospf_live();
    let rows: Vec<Value> = nbrs
        .iter()
        .filter(|n| only.as_deref().is_none_or(|i| i == n.instance))
        .map(|n| {
            let mut v = serde_json::to_value(n).unwrap_or_else(|_| json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("label".into(), json!(label(n)));
            }
            v
        })
        .collect();
    Ok(json!({"source": source, "rows": rows}))
}

fn interface_list(s: &mut Session, p: &Value) -> Result<Value> {
    let only = opt_str(p, "instance")?.map(str::to_owned);
    let (_, ifs, source) = s.ospf_live();
    let cfg = s.store().running();
    let binds = bind::bindings(cfg);
    let rows: Vec<Value> = ifs
        .iter()
        .filter(|i| only.as_deref().is_none_or(|x| x == i.instance))
        .map(|i| {
            let b = binds.iter().find(|b| b.instance.name == i.instance && b.interface.as_str() == i.interface);
            json!({
                "instance": i.instance,
                "version": i.version,
                "interface": i.interface,
                "area": i.area,
                "template": b.map(|b| b.template.id.to_string()),
                "network_type": i.network_type,
                "state": i.state,
                "address": i.address,
                "cost": i.cost,
                "mtu": i.mtu,
                "hello": i.hello,
                "dead": i.dead,
                "dr": i.dr,
                "bdr": i.bdr,
                "passive": i.passive,
                "neighbors": i.neighbors,
                "adjacent": i.adjacent,
                "auth": b.and_then(|b| b.template.auth).map_or("none", |a| a.name()),
            })
        })
        .collect();
    Ok(json!({"source": source, "rows": rows}))
}

fn kind_name(k: u8) -> &'static str {
    match k {
        1 => "router",
        2 => "network",
        3 => "summary",
        4 => "asbr-summary",
        5 => "external",
        7 => "nssa-external",
        _ => "other",
    }
}

fn area_text(a: u32) -> Option<String> {
    (a != u32::MAX).then(|| ip(a).to_string())
}

/// The answer when the LSDB is not there (yet).
fn not_ready(view: &DbView) -> Option<Value> {
    match view {
        DbView::Pending => Some(json!({"source": "frr", "pending": true, "total": 0, "rows": []})),
        DbView::Error(e) => Some(json!({"source": "frr", "pending": false, "error": e, "total": 0, "rows": []})),
        _ => None,
    }
}

fn lsa_list(s: &mut Session, p: &Value) -> Result<Value> {
    let instance = instance_arg(s, p)?;
    let want_type = match opt_str(p, "type")? {
        None | Some("") => None,
        Some(t) => Some(match t {
            "router" => 1,
            "network" => 2,
            "summary" => 3,
            "asbr-summary" => 4,
            "external" => 5,
            "nssa-external" | "nssa" => 7,
            _ => return Err(EngineError::bad("type", "router, network, summary, asbr-summary, external or nssa-external")),
        }),
    };
    let area: Option<u32> = match opt_str(p, "area")? {
        None | Some("") => None,
        Some(a) => Some(a.parse::<corerouter_model::ospf::AreaId>().map_err(|e| EngineError::bad("area", e))?.0),
    };
    let find = opt_str(p, "find")?.map(|f| f.trim().to_owned()).filter(|f| !f.is_empty());
    let offset = opt_u32(p, "offset")?.unwrap_or(0) as usize;
    let limit = opt_u32(p, "limit")?.unwrap_or(200).clamp(1, MAX_PAGE) as usize;
    let view = s.ospf_db(&instance);
    if let Some(v) = not_ready(&view) {
        return Ok(v);
    }
    let Some(db) = view.db() else { return Ok(json!({"rows": []})) };
    let (lsdb, _) = db.as_ref();
    let me = lsdb.router_id;
    let keep = |l: &&Lsa| {
        want_type.is_none_or(|t| l.kind == t)
            && area.is_none_or(|a| l.area == a)
            && find.as_deref().is_none_or(|f| ip(l.id).to_string().contains(f) || ip(l.adv).to_string().contains(f))
    };
    let mut by_type: HashMap<&str, usize> = HashMap::new();
    for l in &lsdb.lsas {
        *by_type.entry(kind_name(l.kind)).or_default() += 1;
    }
    let matching: Vec<&Lsa> = lsdb.lsas.iter().filter(keep).collect();
    let rows: Vec<Value> = matching
        .iter()
        .skip(offset)
        .take(limit)
        .map(|l| {
            let mut v = json!({
                "type": kind_name(l.kind),
                "area": area_text(l.area),
                "id": ip(l.id).to_string(),
                "originator": ip(l.adv).to_string(),
                "age": l.age,
                "sequence": format!("{:08x}", l.seq),
                "self": me == Some(l.adv),
            });
            if let Some(o) = v.as_object_mut() {
                match l.kind {
                    1 => {
                        o.insert("links".into(), json!(l.link_count));
                        o.insert("abr".into(), json!(l.flags & 1 != 0));
                        o.insert("asbr".into(), json!(l.flags & 2 != 0));
                    }
                    2 => {
                        o.insert("prefix".into(), json!(format!("{}/{}", ip(l.id), l.plen)));
                        o.insert("routers".into(), json!(l.link_count));
                    }
                    _ => {
                        o.insert("prefix".into(), json!(format!("{}/{}", ip(l.id), l.plen)));
                        o.insert("metric".into(), json!(l.metric & 0x00FF_FFFF));
                        if l.kind >= 5 {
                            o.insert("metric_type".into(), json!(if l.metric >> 31 == 1 { 2 } else { 1 }));
                        }
                    }
                }
            }
            v
        })
        .collect();
    Ok(json!({
        "source": view.source(),
        "pending": matches!(view, DbView::Daemon { stale: true, .. }),
        "total": matching.len(),
        "by_type": by_type,
        "rows": rows,
    }))
}

fn route_list(s: &mut Session, p: &Value) -> Result<Value> {
    let instance = instance_arg(s, p)?;
    let find = opt_str(p, "find")?.map(|f| f.trim().to_owned()).filter(|f| !f.is_empty());
    let view = s.ospf_db(&instance);
    if let Some(v) = not_ready(&view) {
        return Ok(v);
    }
    let Some(db) = view.db() else { return Ok(json!({"rows": []})) };
    let rows: Vec<Value> = db
        .1
        .iter()
        .filter(|r| find.as_deref().is_none_or(|f| r.prefix.contains(f)))
        .take(MAX_PAGE as usize * 10)
        .map(|r| {
            json!({
                "prefix": r.prefix,
                "kind": r.kind,
                "cost": r.cost,
                "type2_cost": r.type2_cost,
                "area": r.area,
                "nexthops": r.nexthops.iter().map(|(a, i)| json!({"address": a, "interface": i})).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(json!({"source": view.source(), "pending": false, "rows": rows}))
}

fn node_key(n: Node) -> String {
    match n {
        Node::Router(r) => format!("r:{}", ip(r)),
        Node::Network(x) => format!("n:{}", ip(x)),
    }
}

/// A layout made for one LSDB copy and area, kept while that copy is the
/// one in use (a refresh of the window does not lay it out again).
#[derive(Default)]
struct LayoutCache {
    key: Option<(usize, u32)>,
    pos: Arc<Vec<layout::Pos>>,
}

fn topology_cmd(s: &mut Session, p: &Value) -> Result<Value> {
    let instance = instance_arg(s, p)?;
    let view = s.ospf_db(&instance);
    if let Some(v) = not_ready(&view) {
        return Ok(v);
    }
    let Some(db) = view.db().cloned() else { return Ok(json!({"nodes": [], "edges": []})) };
    let (lsdb, _) = db.as_ref();
    let graphs = topology::graphs(lsdb);
    let areas: Vec<String> = graphs.keys().map(|a| ip(*a).to_string()).collect();
    let area = match opt_str(p, "area")? {
        Some(a) if !a.is_empty() => a.parse::<corerouter_model::ospf::AreaId>().map_err(|e| EngineError::bad("area", e))?.0,
        _ => graphs.keys().next().copied().unwrap_or(0),
    };
    let Some(g) = graphs.get(&area) else {
        return Ok(json!({"source": view.source(), "pending": false, "area": ip(area).to_string(), "areas": areas, "nodes": [], "edges": []}));
    };
    let ids: Vec<u64> = g
        .nodes
        .iter()
        .map(|n| match n {
            Node::Router(r) => u64::from(*r),
            Node::Network(x) => u64::from(*x) | 1 << 40,
        })
        .collect();
    let edges = g.edges();
    let pairs: Vec<(usize, usize)> = edges.iter().map(|e| (e.0, e.1)).collect();
    let ptr = Arc::as_ptr(&db) as usize;
    let threads = layout::threads_for(ids.len());
    let started = Instant::now();
    let cached = s.ext::<LayoutCache>().filter(|c| c.key == Some((ptr, area))).map(|c| Arc::clone(&c.pos));
    let pos = match cached {
        Some(p) if !matches!(view, DbView::Sample(_)) => p,
        _ => {
            let p = Arc::new(layout::layout(&ids, &pairs, threads));
            if let Some(c) = s.ext_mut::<LayoutCache>() {
                c.key = Some((ptr, area));
                c.pos = Arc::clone(&p);
            }
            p
        }
    };
    let layout_ms = started.elapsed().as_secs_f64() * 1000.0;
    let (nbrs, _, _) = s.ospf_live();
    let me = lsdb.router_id;
    let nodes: Vec<Value> = g
        .nodes
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let at = pos.get(i).copied().unwrap_or_default();
            let flags = g.flags.get(i).copied().unwrap_or(0);
            let (kind, id) = match n {
                Node::Router(r) => ("router", ip(*r).to_string()),
                Node::Network(x) => ("network", format!("{}/{}", ip(*x), flags)),
            };
            let nb = match n {
                Node::Router(r) => nbrs.iter().find(|x| x.router_id == ip(*r).to_string()).map(label),
                Node::Network(_) => None,
            };
            json!({
                "key": node_key(*n),
                "kind": kind,
                "id": id,
                "label": id,
                "x": at.x,
                "y": at.y,
                "abr": matches!(n, Node::Router(_)) && flags & 1 != 0,
                "asbr": matches!(n, Node::Router(_)) && flags & 2 != 0,
                "self": matches!(n, Node::Router(r) if Some(*r) == me),
                "neighbor": nb,
            })
        })
        .collect();
    let edge_rows: Vec<Value> = edges
        .iter()
        .filter_map(|(a, b, c, r)| {
            Some(json!({"a": node_key(*g.nodes.get(*a)?), "b": node_key(*g.nodes.get(*b)?), "cost": c, "back_cost": r}))
        })
        .collect();
    Ok(json!({
        "source": view.source(),
        "pending": false,
        "area": ip(area).to_string(),
        "areas": areas,
        "nodes": nodes,
        "edges": edge_rows,
        "layout_ms": (layout_ms * 100.0).round() / 100.0,
        "threads": threads,
    }))
}

fn path_cmd(s: &mut Session, p: &Value) -> Result<Value> {
    let instance = instance_arg(s, p)?;
    let to: Ipv4Addr = req_str(p, "to")?
        .trim()
        .parse()
        .map_err(|_| EngineError::bad("to", "an IPv4 address or router id"))?;
    let view = s.ospf_db(&instance);
    if let Some(v) = not_ready(&view) {
        return Ok(v);
    }
    let Some(db) = view.db().cloned() else { return Ok(json!({"hops": []})) };
    let (lsdb, routes) = db.as_ref();
    let Some(me) = lsdb.router_id else {
        return Ok(json!({"source": view.source(), "pending": false, "hops": [], "error": "the daemon reports no router id"}));
    };
    // The daemon's route for it: the longest prefix holding the address.
    let route = routes
        .iter()
        .filter_map(|r| r.prefix.parse::<ipnet::Ipv4Net>().ok().map(|n| (n, r)))
        .filter(|(n, _)| n.contains(&to))
        .max_by_key(|(n, _)| n.prefix_len())
        .map(|(_, r)| r);
    for (area, g) in topology::graphs(lsdb) {
        let Some(hops) = topology::path(&g, me, to) else { continue };
        let total = hops.last().map_or(0, |h| h.total);
        let rows: Vec<Value> = hops
            .iter()
            .map(|h| {
                let (kind, id) = match h.node {
                    Node::Router(r) => ("router", ip(r).to_string()),
                    Node::Network(x) => ("network", ip(x).to_string()),
                };
                json!({"key": node_key(h.node), "kind": kind, "id": id, "cost": h.cost, "total": h.total})
            })
            .collect();
        return Ok(json!({
            "source": view.source(),
            "pending": false,
            "area": ip(area).to_string(),
            "hops": rows,
            "total": total,
            "route": route.map(|r| json!({"prefix": r.prefix, "kind": r.kind, "cost": r.cost, "nexthops": r.nexthops.iter().map(|(a, i)| json!({"address": a, "interface": i})).collect::<Vec<_>>()})),
            "agrees": route.map(|r| r.kind != "intra-area" || r.cost == total),
        }));
    }
    Ok(json!({
        "source": view.source(),
        "pending": false,
        "hops": [],
        "route": route.map(|r| json!({"prefix": r.prefix, "kind": r.kind, "cost": r.cost})),
        "error": format!("{to} is not inside an area this router knows (an external or inter-area route: the ABR/ASBR is the last hop the LSDB shows)"),
    }))
}

fn diagnose_cmd(s: &mut Session, p: &Value) -> Result<Value> {
    let iface = req_str(p, "interface")?.trim().to_owned();
    let cfg = s.store().running().clone();
    let binds = bind::bindings(&cfg);
    let want = opt_str(p, "instance")?;
    let Some(b) = binds
        .iter()
        .find(|b| b.interface.as_str() == iface && want.is_none_or(|w| w == b.instance.name))
    else {
        let known = cfg.interfaces.keys().any(|k| k.as_str() == iface);
        let msg = if known {
            format!("{iface} runs no OSPF: no interface template matches it (routing.ospf.interface-template.check shows which would)")
        } else {
            format!("no interface {:?}", cut(&iface))
        };
        return Ok(json!({
            "interface": iface,
            "findings": [{"level": "error", "check": "not-in-ospf", "message": msg, "rfc": ""}],
        }));
    };
    let (nbrs, ifs, source) = s.ospf_live();
    let st = ifs.iter().find(|i| i.interface == iface && i.instance == b.instance.name);
    let t = b.template;
    let v3 = b.instance.version == Version::V3;
    let mask = bind::addresses(&cfg, false)
        .get(&b.interface)
        .and_then(|v| v.first())
        .and_then(|a| match a {
            ipnet::IpNet::V4(n) => Some(n.netmask()),
            ipnet::IpNet::V6(_) => None,
        });
    let key_id = match &t.keychain {
        Some(k) => {
            let now = s.hal_mut().now_unix().unwrap_or(0);
            cfg.routing.ospf.keychains.get(k).and_then(|kc| kc.keys.iter().find(|k| k.sends_at(now)).map(|k| k.id))
        }
        None => t.auth.filter(|a| a.is_crypto()).map(|_| t.auth_id.unwrap_or(1)),
    };
    let local = Local {
        version: b.instance.version.number(),
        interface: iface.clone(),
        router_id: b.instance.router_id,
        area: b.area.area_id.0,
        stub: b.area.kind == AreaType::Stub,
        nssa: b.area.kind == AreaType::Nssa,
        mask: if v3 { None } else { mask },
        network_type: t.kind.name().to_owned(),
        hello: st.and_then(|i| i.hello).unwrap_or(u32::from(t.hello_interval.unwrap_or(10))),
        dead: st.and_then(|i| i.dead).unwrap_or(u32::from(t.dead_interval.unwrap_or(40))),
        mtu: st.and_then(|i| i.mtu),
        mtu_ignore: t.mtu_ignore,
        auth: t.auth.map_or("none", |a| a.name()).to_owned(),
        key_id,
        passive: t.passive,
        state: st.and_then(|i| i.state.clone()),
    };
    let seen: Vec<Seen> = nbrs
        .iter()
        .filter(|n| n.interface == iface && n.instance == b.instance.name)
        .map(|n| Seen { router_id: n.router_id.clone(), state: n.state.clone(), state_secs: n.state_secs })
        .collect();
    let findings = diagnose::diagnose(&local, &seen, &[]);
    Ok(json!({
        "interface": iface,
        "instance": b.instance.name,
        "source": source,
        "local": {
            "area": b.area.area_id.to_string(),
            "network_type": local.network_type,
            "hello": local.hello,
            "dead": local.dead,
            "mtu": local.mtu,
            "auth": local.auth,
            "passive": local.passive,
        },
        "findings": findings.iter().map(|f| json!({"level": f.level, "check": f.check, "message": f.message, "rfc": f.rfc})).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use corerouter_hal::VirtualHal;
    use serde_json::json;

    use crate::Session;

    fn lab() -> Session {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        for (a, i) in [("10.0.1.1/24", "ether1"), ("10.0.2.1/30", "ether2")] {
            s.execute("ip.address.add", &json!({"address": a, "interface": i})).unwrap();
        }
        s.execute("routing.ospf.instance.add", &json!({"name": "v2", "router_id": "10.255.0.1"})).unwrap();
        s.execute("routing.ospf.area.add", &json!({"name": "backbone", "instance": "v2", "area_id": "0"})).unwrap();
        s.execute("routing.ospf.interface-template.add", &json!({"area": "backbone", "networks": "10.0.0.0/16", "auth_key": "k"}))
            .unwrap();
        s
    }

    #[test]
    fn neighbors_lsas_routes_topology_and_path_in_the_lab() {
        let mut s = lab();
        let n = s.execute("routing.ospf.neighbor.list", &json!({})).unwrap();
        assert_eq!(n["source"], "virtual lab sample");
        assert_eq!(n["rows"][0]["label"], "Full · DR");
        let l = s.execute("routing.ospf.lsa.list", &json!({"instance": "v2", "type": "router"})).unwrap();
        assert!(l["total"].as_u64().unwrap() >= 4, "{l}");
        assert_eq!(l["rows"][0]["self"], true);
        let r = s.execute("routing.ospf.route.list", &json!({"instance": "v2"})).unwrap();
        assert!(!r["rows"].as_array().unwrap().is_empty());
        let t = s.execute("routing.ospf.topology", &json!({"instance": "v2"})).unwrap();
        assert!(t["nodes"].as_array().unwrap().len() >= 5, "{t}");
        assert!(t["nodes"].as_array().unwrap().iter().any(|n| n["self"] == true));
        let p = s.execute("routing.ospf.path", &json!({"instance": "v2", "to": "172.16.0.9"})).unwrap();
        let hops = p["hops"].as_array().unwrap();
        assert!(hops.len() >= 3, "{p}");
        assert_eq!(p["agrees"], true, "{p}");
        let e = s.execute("routing.ospf.lsa.list", &json!({"instance": "nope"})).unwrap_err();
        assert!(e.to_string().contains("no OSPF instance"));
    }

    #[test]
    fn diagnose_explains_exstart_with_the_rfc() {
        let mut s = lab();
        let d = s.execute("routing.ospf.neighbor.diagnose", &json!({"interface": "ether2"})).unwrap();
        let f = serde_json::to_string(&d["findings"]).unwrap();
        assert!(f.contains("stuck-exstart") && f.contains("RFC 2328 §10.6"), "{d}");
        let d = s.execute("routing.ospf.neighbor.diagnose", &json!({"interface": "ether3"})).unwrap();
        assert_eq!(d["findings"][0]["check"], "not-in-ospf");
    }
}
