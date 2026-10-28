//! /routing ospf fast-reroute (G3.4d): TI-LFA (RFC 9855) coverage, each
//! route with its primary and backup next hop (label stack and SIDs, as
//! zebra installed them), and "simulate a link cut": the backup each
//! affected route takes and the path after convergence, computed as FRR's
//! `ospfd` does (`netsim::tilfa`), without touching the network.
//! RouterOS has no TI-LFA; the views follow IOS-XR's `show ... fast-reroute
//! prefix-summary` and Junos' backup next hop.

use std::net::Ipv4Addr;

use corerouter_model::ospf::{MAIN_VRF, Version};
use corerouter_model::ospf_sr::{SrDb, TiLfa};
use corerouter_model::ospf_state::{FrrHop, OspfRoute};
use corerouter_netsim::tilfa::{Protection, Repair, Segment};
use serde_json::{Value, json};

use super::args::opt_str;
use super::{CommandSpec, always};
use crate::ospf_frr::{Graph, coverage, neighbor_of, protection, repair_of};
use crate::ospf_state::DbView;
use crate::{EngineError, Result, Session};

/// Most route rows one answer carries (the coverage counts them all).
pub const MAX_ROWS: usize = 5_000;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "routing.ospf.fast-reroute", "OSPF Fast Reroute", ["Routing", "OSPF"], None,
        "{instance?: string (default: the SR instance), find?: string (prefix contains), limit?: u32 (1..=5000, default 2000)} → {instance, ti_lfa (off, link, node), source, pending, error?, coverage: {total, protected, percent}, unprotected: [{prefix, reason}], rows: [{prefix, kind, cost, primary: {via, interface, labels}, backup?: {via, interface, labels, segments}, computed (the virtual lab's, not a daemon's), protected}], neighbors: [{router_id, address, interface}]}",
        always, frr_list),
    cmd!(query "routing.ospf.fast-reroute.simulate", "Simulate Link Cut", [], None,
        "{neighbor: string (router id, address or interface of the link that is cut), node?: bool (the router fails, not only the link), instance?: string} → {neighbor, protection, affected: [{prefix, before: {via, cost}, backup?: {nexthop, segments, labels, installed}, after: {path, cost}}], lost: [{prefix, reason}], kept, note}",
        always, simulate),
];

fn instance(s: &Session, p: &Value) -> Result<String> {
    let ospf = &s.store().running().routing.ospf;
    if let Some(i) = opt_str(p, "instance")?.map(str::trim).filter(|i| !i.is_empty()) {
        return if ospf.instances.contains_key(i) {
            Ok(i.to_owned())
        } else {
            Err(EngineError::bad("instance", format!("no OSPF instance {:?}", crate::logging::cut(i, 64))))
        };
    }
    ospf.segment_routing
        .as_ref()
        .map(|sr| sr.instance.clone())
        .or_else(|| ospf.instances.values().find(|i| i.version == Version::V2 && i.vrf == MAIN_VRF).map(|i| i.name.clone()))
        .ok_or_else(|| EngineError::bad("instance", "no OSPFv2 instance"))
}

fn hop(h: &FrrHop) -> Value {
    json!({"via": h.via, "interface": h.interface, "labels": h.labels})
}

fn seg_text(s: &Segment) -> String {
    match s {
        Segment::Adjacency { from, to } => format!("adj {from}→{to}"),
        Segment::Node { router } => format!("node {router}"),
    }
}

/// The label of `router`'s prefix SID on `via` (its SRGB start + index).
fn node_label(db: &SrDb, via: Ipv4Addr, router: Ipv4Addr) -> Option<u32> {
    let base = db.nodes.iter().find(|n| n.router_id == u32::from(via))?.srgb_start;
    let sid = db
        .nodes
        .iter()
        .find(|n| n.router_id == u32::from(router))?
        .prefixes
        .iter()
        .find(|p| p.plen == 32 && p.prefix == u32::from(router))
        .or_else(|| db.nodes.iter().find(|n| n.router_id == u32::from(router))?.prefixes.first())?
        .sid;
    Some(base + sid)
}

/// The labels of a computed repair, where they are known (an adjacency SID
/// is local to its router and not in the database: left out).
fn labels_of(db: &SrDb, rep: &Repair) -> Vec<u32> {
    let Some(nh) = rep.nexthop else { return Vec::new() };
    let mut out: Vec<u32> = rep
        .segments
        .iter()
        .filter_map(|s| match s {
            Segment::Node { router } => node_label(db, nh, *router),
            Segment::Adjacency { .. } => None,
        })
        .collect();
    if rep.dest != nh
        && let Some(l) = node_label(db, nh, rep.dest)
    {
        out.push(l);
    }
    out
}

struct Ctx {
    instance: String,
    ti_lfa: TiLfa,
    view: DbView,
    nbrs: Vec<corerouter_model::ospf_state::OspfNeighbor>,
}

fn ctx(s: &mut Session, p: &Value) -> Result<Ctx> {
    let instance = instance(s, p)?;
    let ti_lfa = corerouter_model::ospf_sr::active(&s.store().running().routing.ospf).filter(|sr| sr.instance == instance).map_or(TiLfa::Off, |sr| sr.ti_lfa);
    let view = s.ospf_db(&instance);
    let nbrs = s.ospf_live().0.into_iter().filter(|n| n.instance == instance).collect();
    Ok(Ctx { instance, ti_lfa, view, nbrs })
}

/// The routes with their backups: the daemon's, or, in the virtual lab,
/// computed (`computed` true).
fn routes_with_backups(c: &Ctx, g: &Graph) -> (Vec<OspfRoute>, bool) {
    let Some(db) = c.view.db() else { return (Vec::new(), false) };
    let mut routes = db.1.clone();
    let sample = matches!(c.view, DbView::Sample(_));
    if sample && c.ti_lfa != TiLfa::Off {
        let p = protection(c.ti_lfa);
        for r in &mut routes {
            let Some(n) = neighbor_of(r, &c.nbrs) else { continue };
            let Some(rep) = repair_of(g, r, n, p).filter(|x| x.reason.is_none()) else { continue };
            let Some(nh) = rep.nexthop else { continue };
            let Some(nb) = c.nbrs.iter().find(|x| x.router_id == nh.to_string()) else { continue };
            r.fast_reroute = Some(corerouter_model::ospf_state::RouteFrr {
                primary: r.nexthops.iter().map(|(v, i)| FrrHop { via: v.clone(), interface: i.clone(), labels: Vec::new() }).collect(),
                backup: vec![FrrHop { via: Some(nb.address.clone()), interface: nb.interface.clone(), labels: labels_of(&db.0.sr, &rep) }],
            });
        }
    }
    (routes, sample)
}

fn frr_list(s: &mut Session, p: &Value) -> Result<Value> {
    let c = ctx(s, p)?;
    let find = opt_str(p, "find")?.map(|f| f.trim().to_owned()).filter(|f| !f.is_empty());
    let limit = match p.get("limit") {
        None | Some(Value::Null) => 2000,
        Some(v) => usize::try_from(super::routing_ospf::number("limit", v, 1, MAX_ROWS as u64)?).unwrap_or(2000),
    };
    let base = json!({"instance": c.instance, "ti_lfa": c.ti_lfa.name(), "source": c.view.source()});
    match &c.view {
        DbView::Pending => return Ok(merge(base, json!({"pending": true, "rows": [], "unprotected": [], "coverage": {"total": 0, "protected": 0, "percent": 0.0}, "neighbors": []}))),
        DbView::Error(e) => return Ok(merge(base, json!({"pending": false, "error": e, "rows": [], "unprotected": [], "coverage": {"total": 0, "protected": 0, "percent": 0.0}, "neighbors": []}))),
        _ => {}
    }
    let Some(db) = c.view.db() else { return Ok(base) };
    let g = Graph::of(&db.0);
    let (routes, computed) = routes_with_backups(&c, &g);
    let cov = if c.ti_lfa == TiLfa::Off {
        corerouter_netsim::tilfa::Coverage { total: routes.len(), ..Default::default() }
    } else {
        coverage(&g, &routes, &c.nbrs, protection(c.ti_lfa))
    };
    let rows: Vec<Value> = routes
        .iter()
        .filter(|r| find.as_deref().is_none_or(|f| r.prefix.contains(f)))
        .take(limit)
        .map(|r| {
            let f = r.fast_reroute.as_ref();
            let primary = f.and_then(|f| f.primary.first()).map(hop).unwrap_or_else(|| {
                let (v, i) = r.nexthops.first().cloned().unwrap_or_default();
                json!({"via": v, "interface": i, "labels": []})
            });
            let backup = f.and_then(|f| f.backup.first()).map(hop);
            json!({
                "prefix": r.prefix, "kind": r.kind, "cost": r.cost,
                "primary": primary, "backup": backup,
                "computed": computed && backup.is_some(),
                "protected": backup.is_some(),
            })
        })
        .collect();
    let unprotected: Vec<Value> = cov.unprotected.iter().take(MAX_ROWS).map(|u| json!({"prefix": u.prefix, "reason": u.reason})).collect();
    let neighbors: Vec<Value> = c.nbrs.iter().filter(|n| n.state == "Full").map(|n| json!({"router_id": n.router_id, "address": n.address, "interface": n.interface})).collect();
    Ok(merge(
        base,
        json!({
            "pending": false,
            "coverage": {"total": cov.total, "protected": cov.protected, "percent": (cov.percent() * 10.0).round() / 10.0},
            "unprotected": unprotected,
            "rows": rows,
            "neighbors": neighbors,
        }),
    ))
}

fn merge(mut a: Value, b: Value) -> Value {
    if let (Some(x), Value::Object(y)) = (a.as_object_mut(), b) {
        x.extend(y);
    }
    a
}

fn simulate(s: &mut Session, p: &Value) -> Result<Value> {
    let c = ctx(s, p)?;
    let want = super::args::req_str(p, "neighbor")?.trim().to_owned();
    let node = super::routing_ospf::opt_boolean(p, "node")?.unwrap_or(false);
    let nb = c
        .nbrs
        .iter()
        .find(|n| n.router_id == want || n.address == want || n.interface == want)
        .cloned()
        .ok_or_else(|| EngineError::bad("neighbor", format!("no OSPF neighbor {:?} (a router id, address or interface)", crate::logging::cut(&want, 64))))?;
    let Some(db) = c.view.db() else {
        return Ok(json!({"neighbor": nb.router_id, "pending": true, "affected": [], "lost": [], "kept": 0}));
    };
    let g = Graph::of(&db.0);
    let (routes, _) = routes_with_backups(&c, &g);
    let rid: Ipv4Addr = nb.router_id.parse().map_err(|_| EngineError::bad("neighbor", "the neighbor has no router id"))?;
    let prot = if node { Protection::Node } else { Protection::Link };
    let mut affected = Vec::new();
    let mut lost = Vec::new();
    let mut kept = 0usize;
    for r in &routes {
        if neighbor_of(r, &c.nbrs) != Some(rid) {
            kept += 1;
            continue;
        }
        let rep = repair_of(&g, r, rid, prot);
        let installed = r.fast_reroute.as_ref().and_then(|f| f.backup.first());
        let after = rep.as_ref().filter(|x| x.reason.is_none());
        match (after, installed) {
            (None, None) => lost.push(json!({
                "prefix": r.prefix,
                "reason": rep.as_ref().and_then(|x| x.reason).unwrap_or("not announced by a router of the area: no repair computed"),
            })),
            _ => affected.push(json!({
                "prefix": r.prefix,
                "before": {"via": r.nexthops.first().and_then(|n| n.0.clone()), "cost": r.cost},
                "backup": after.map(|x| json!({
                    "nexthop": x.nexthop.map(|n| n.to_string()),
                    "segments": x.segments.iter().map(seg_text).collect::<Vec<_>>(),
                    "labels": installed.map_or_else(|| labels_of(&db.0.sr, x), |h| h.labels.clone()),
                    "installed": installed.is_some(),
                })),
                "after": {"path": after.map(|x| x.path.iter().map(ToString::to_string).collect::<Vec<_>>()), "cost": after.and_then(|x| x.cost)},
            })),
        }
    }
    let note = if c.ti_lfa == TiLfa::Off {
        "simulated, nothing changed. TI-LFA is off: these routes wait for OSPF to converge (BFD, then the SPF) and the backups shown are what TI-LFA would install"
    } else {
        "simulated, nothing changed: the backup is used from the moment the cut is detected until OSPF converges onto the path after"
    };
    Ok(json!({
        "neighbor": nb.router_id, "interface": nb.interface, "protection": if node { "node" } else { "link" },
        "affected": affected, "lost": lost, "kept": kept, "note": note, "source": c.view.source(),
    }))
}

#[cfg(test)]
mod tests {
    use corerouter_hal::VirtualHal;
    use serde_json::json;

    use crate::Session;

    fn lab() -> Session {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        for (id, p) in [
            ("interface.loopback.add", json!({"name": "lo0"})),
            ("ip.address.add", json!({"address": "10.255.0.1/32", "interface": "lo0"})),
            ("ip.address.add", json!({"address": "10.0.1.1/30", "interface": "ether1"})),
            ("ip.address.add", json!({"address": "10.0.2.1/30", "interface": "ether2"})),
            ("ip.address.add", json!({"address": "10.0.3.1/30", "interface": "ether3"})),
            ("routing.ospf.instance.add", json!({"name": "v2", "router_id": "10.255.0.1"})),
            ("routing.ospf.area.add", json!({"name": "bb", "instance": "v2", "area_id": "0"})),
            ("routing.ospf.interface-template.add", json!({"area": "bb", "interfaces": "lo0", "passive": true})),
            ("routing.ospf.interface-template.add", json!({"area": "bb", "interfaces": "ether1,ether2,ether3", "type": "ptp"})),
            ("routing.ospf.segment-routing.set", json!({"ti_lfa": "link"})),
        ] {
            s.execute(id, &p).unwrap_or_else(|e| panic!("{id}: {e}"));
        }
        s
    }

    #[test]
    fn the_lab_has_coverage_backups_and_reasons() {
        let mut s = lab();
        let v = s.execute("routing.ospf.fast-reroute", &json!({})).unwrap();
        assert_eq!(v["ti_lfa"], "link", "{v}");
        let total = v["coverage"]["total"].as_u64().unwrap();
        let protected = v["coverage"]["protected"].as_u64().unwrap();
        assert!(total > 0 && protected > 0, "{v}");
        assert_eq!(total - protected, v["unprotected"].as_array().unwrap().len() as u64, "{v}");
        let row = v["rows"].as_array().unwrap().iter().find(|r| r["protected"] == true).unwrap();
        assert_eq!(row["computed"], true);
        assert!(!row["backup"]["via"].is_null(), "{row}");
        // The lab's neighbor through ether1 is in a ring: cutting it has a
        // way around for the ring's routers.
        let nb = v["neighbors"][0]["router_id"].as_str().unwrap().to_owned();
        let sim = s.execute("routing.ospf.fast-reroute.simulate", &json!({"neighbor": nb})).unwrap();
        assert!(sim["note"].as_str().unwrap().contains("nothing changed"), "{sim}");
        assert!(!sim["affected"].as_array().unwrap().is_empty() || !sim["lost"].as_array().unwrap().is_empty(), "{sim}");
        assert!(s.execute("routing.ospf.fast-reroute.simulate", &json!({"neighbor": "nobody"})).is_err());
    }
}
