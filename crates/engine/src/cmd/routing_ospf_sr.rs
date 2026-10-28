//! /routing ospf segment-routing and prefix-sid (G3.4f): Segment Routing
//! MPLS over OSPFv2 (RFC 8665), rendered for FRR's `ospfd` by
//! `proto_ospf::sr`. RouterOS has none; the names are IOS-XR's and FRR's.
//!
//! Safe by default: switching SR on moves the internal traffic from IP to
//! labels, so `routing.ospf.segment-routing.check` (the modal) shows the
//! prefixes that start going by label, the MTU that is short by the label,
//! the interfaces without MPLS input and the SID clashes, and suggests Safe
//! Mode. A SID that another router already uses for another prefix is
//! refused before the commit (`force` takes it anyway, for anycast).

use std::net::Ipv4Addr;

use corerouter_model::ospf::{MAIN_VRF, Version};
use corerouter_model::ospf_sr::{
    LabelBlock, MAX_INDEX, MAX_MSD, MAX_PREFIX_SIDS, PrefixSid, SegmentRouting, SidBehavior, SrDb, TiLfa,
};
use corerouter_model::types::ItemId;
use corerouter_model::{Config, Routing};
use corerouter_proto_ospf::sr;
use ipnet::{IpNet, Ipv4Net};
use serde_json::{Value, json};

use super::args::{opt_text, req_str};
use super::mpls::mpls_supported;
use super::routing_ospf::{Given, given, number, opt_boolean, parse_id, text};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("routing.ospf.segment-routing.set", "Set OSPF Segment Routing", ["Routing", "OSPF"], None,
        "{instance?: string (the OSPFv2 instance in VRF main; default: the only one), srgb?: string (labels for prefix SIDs, default 16000-23999, outside LDP's range), srlb?: string (local labels, default 15000-15999), node_msd?: u8 | null (deepest label stack pushed, 1..=16), ti_lfa?: string (off, link, node: TI-LFA, RFC 9855), auto_sid?: bool (default yes: a SID for every loopback /32 of the instance without one), force?: bool (the forwarding change was confirmed: the modal sends it), disabled?: bool, comment?: string} → {instance, added: [{prefix, index, label}]}",
        mpls_supported, sr_set),
    cmd!("routing.ospf.segment-routing.unset", "Remove OSPF Segment Routing", [], None,
        "{} → {removed_sids}",
        has_sr, sr_unset),
    cmd!(query "routing.ospf.segment-routing.check", "Check OSPF Segment Routing", [], None,
        "{id?: string (the instance, when editing), instance?: string, srgb?: string, srlb?: string, node_msd?: u8 | string | null, ti_lfa?: string, auto_sid?: bool | yes | no, disabled?: bool | yes | no, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}], risk, preview: {by_label, maybe, own, mtu, no_mpls_input, conflicts, ldp_block, switches}, available, why?}",
        always, sr_check),
    cmd!(query "routing.ospf.segment-routing.database", "OSPF Segment Routing", ["Routing", "OSPF"], None,
        "{} → {configured, active, instance?, srgb?, srlb?, node_msd?, ti_lfa?, disabled, comment?, ldp_block?, source, stale, error?, router_id?, nodes: [{router_id, srgb, srlb, msd, adjacencies, prefixes, same_srgb, me}], sids: [{prefix, router, index, label, in_label, out_label?, interface?, nexthop?, own}], conflicts: [{index, prefix, router, other_prefix, kind, detail}], issues: [string], available, why?}",
        always, sr_database),
    cmd!("routing.ospf.prefix-sid.add", "Add OSPF Prefix SID", ["Routing", "OSPF"], None,
        "{prefix?: prefix (a /32 of a loopback), interface?: string (a loopback: its /32), index?: u32 (0..=65535, below the SRGB size; default: the last octet when free, else the lowest free), behavior?: string (php, no-php, explicit-null; default php), force?: bool (take an index another router uses: anycast), disabled?: bool, comment?: string} → {id, prefix, index, label}",
        has_sr, sid_add),
    cmd!("routing.ospf.prefix-sid.set", "Set OSPF Prefix SID", [], None,
        "{id: string (*N), index?: u32, behavior?: string, force?: bool, disabled?: bool, comment?: string} → {id, prefix, index, label}",
        has_sids, sid_set),
    cmd!("routing.ospf.prefix-sid.remove", "Remove OSPF Prefix SID", [], None,
        "{id: string (*N)} → {id}",
        has_sids, sid_remove),
    cmd!(query "routing.ospf.prefix-sid.check", "Check OSPF Prefix SID", [], None,
        "{id?: string (*N, the SID being edited), prefix?: string, interface?: string, index?: u32 | string (empty or auto: picked), behavior?: string, force?: bool | yes | no, disabled?: bool | yes | no, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}], risk}",
        always, sid_check),
    cmd!(query "routing.ospf.prefix-sid.list", "OSPF Prefix SIDs", ["Routing", "OSPF"], None,
        "{} → [{id, prefix, interface?, index, label?, behavior, announced, disabled, comment}]",
        always, sid_list),
];

fn has_sr(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.ospf.segment_routing.is_some() {
        Ok(())
    } else {
        Err("Segment Routing is off (routing.ospf.segment-routing.set)".into())
    }
}

fn has_sids(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.ospf.prefix_sids.is_empty() {
        Err("there are no prefix SIDs".into())
    } else {
        Ok(())
    }
}

fn block(key: &str, v: &Value) -> Result<LabelBlock> {
    text(key, v)?
        .parse()
        .map_err(|e: String| EngineError::bad(key, e))
}

/// The SR database last read for `instance` (`None`: not known yet).
fn network_db(s: &mut Session, instance: &str) -> Option<SrDb> {
    s.ospf_db(instance).db().map(|d| d.0.sr.clone())
}

/// `cfg` with the parameters of `segment-routing.set` applied; the SIDs
/// added for the loopbacks.
fn apply(cfg: &mut Config, p: &Value, db: Option<&SrDb>) -> Result<Vec<(Ipv4Net, u32)>> {
    let routing: &mut Routing = &mut cfg.routing;
    let ospf = &mut routing.ospf;
    let fresh = ospf.segment_routing.is_none();
    let instance = match given(p, "instance") {
        Given::Value(v) => text("instance", v)?.to_owned(),
        _ => match &ospf.segment_routing {
            Some(sr) => sr.instance.clone(),
            None => {
                let v2: Vec<&String> = ospf
                    .instances
                    .values()
                    .filter(|i| i.version == Version::V2 && i.vrf == MAIN_VRF)
                    .map(|i| &i.name)
                    .collect();
                match v2.as_slice() {
                    [one] => (*one).clone(),
                    [] => return Err(EngineError::bad("instance", "no OSPFv2 instance in VRF main (routing.ospf.instance.add)")),
                    _ => return Err(EngineError::bad("instance", "several OSPFv2 instances: name one")),
                }
            }
        },
    };
    if !ospf.instances.contains_key(&instance) {
        return Err(EngineError::bad("instance", format!("no OSPF instance {:?}", super::routing_ospf::cut(&instance))));
    }
    let mut sr = ospf.segment_routing.clone().unwrap_or_else(|| SegmentRouting::new(instance.clone()));
    sr.instance = instance;
    match given(p, "srgb") {
        Given::Value(v) => sr.srgb = block("srgb", v)?,
        Given::Unset => sr.srgb = corerouter_model::ospf_sr::DEFAULT_SRGB,
        Given::Absent => {}
    }
    match given(p, "srlb") {
        Given::Value(v) => sr.srlb = block("srlb", v)?,
        Given::Unset => sr.srlb = corerouter_model::ospf_sr::DEFAULT_SRLB,
        Given::Absent => {}
    }
    super::routing_ospf::opt_number(p, "node_msd", 1, u64::from(MAX_MSD), &mut sr.node_msd)?;
    if let Given::Value(v) = given(p, "ti_lfa") {
        sr.ti_lfa = TiLfa::parse(text("ti_lfa", v)?).ok_or_else(|| EngineError::bad("ti_lfa", "off, link or node"))?;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        sr.comment = c;
    }
    if let Some(d) = opt_boolean(p, "disabled")? {
        sr.disabled = d;
    }
    let srgb = sr.srgb;
    let inst = sr.instance.clone();
    ospf.segment_routing = Some(sr);
    let auto = opt_boolean(p, "auto_sid")?.unwrap_or(fresh);
    let mut added = Vec::new();
    if auto {
        let empty = SrDb::default();
        for (prefix, _) in sr::announced_loopbacks(cfg, &inst) {
            let ospf = &mut cfg.routing.ospf;
            if ospf.prefix_sids.iter().any(|s| s.prefix == prefix) || ospf.prefix_sids.len() >= MAX_PREFIX_SIDS {
                continue;
            }
            let Some(index) = sr::propose_index(prefix, srgb, &ospf.prefix_sids, db.unwrap_or(&empty)) else {
                continue;
            };
            let id = ospf.next_id();
            ospf.prefix_sids.push(PrefixSid {
                id,
                prefix,
                index,
                behavior: SidBehavior::Php,
                disabled: false,
                comment: "auto: loopback".into(),
            });
            added.push((prefix, index));
        }
    }
    Ok(added)
}

fn sr_set(s: &mut Session, p: &Value) -> Result<Value> {
    let inst = s
        .store()
        .candidate()
        .routing
        .ospf
        .segment_routing
        .as_ref()
        .map(|sr| sr.instance.clone())
        .or_else(|| p.get("instance").and_then(Value::as_str).map(str::to_owned));
    let db = inst.and_then(|i| network_db(s, &i));
    let mut cfg = s.store().candidate().clone();
    let added = apply(&mut cfg, p, db.as_ref())?;
    let srgb = cfg.routing.ospf.segment_routing.as_ref().map(|s| s.srgb);
    let instance = cfg.routing.ospf.segment_routing.as_ref().map(|s| s.instance.clone()).unwrap_or_default();
    let routing = cfg.routing.clone();
    s.store_mut().candidate_mut().routing = routing;
    Ok(json!({
        "instance": instance,
        "added": added.iter().map(|(p, i)| json!({"prefix": p.to_string(), "index": i, "label": srgb.and_then(|b| b.label(*i))})).collect::<Vec<_>>(),
    }))
}

fn sr_unset(s: &mut Session, _: &Value) -> Result<Value> {
    let ospf = &mut s.store_mut().candidate_mut().routing.ospf;
    let n = ospf.prefix_sids.len();
    ospf.segment_routing = None;
    ospf.prefix_sids.clear();
    Ok(json!({ "removed_sids": n }))
}

/// FRR takes a prefix SID only on an IFF_LOOPBACK interface (Linux's
/// `lo`); a CoreRouter loopback interface is a dummy there, which ospfd
/// refuses (lab VM, FRR 10.7.1). Said where a real FRR runs (G3.4i).
fn lo_warning(s: &Session, cfg: &Config, sids: &[PrefixSid]) -> Option<String> {
    if !s.has_routing() {
        return None;
    }
    let lo = sr::loopback_addresses(cfg);
    let off: Vec<String> = sids
        .iter()
        .filter(|x| !x.disabled)
        .filter_map(|x| lo.get(&x.prefix).filter(|i| i.as_str() != "lo").map(|i| format!("{} on {i}", x.prefix)))
        .collect();
    (!off.is_empty()).then(|| {
        format!(
            "{}: FRR's ospfd takes a prefix SID only on the kernel's lo, and a loopback interface is a dummy on Linux, so the commit would be refused (G3.4i); put the /32 on lo",
            off.join(", ")
        )
    })
}

fn check(level: &str, what: &str, message: String, param: &str) -> Value {
    json!({"level": level, "check": what, "message": message, "param": param})
}

/// The form's texts as the command wants them (yes/no → bool).
fn normalize(raw: &Value) -> Value {
    let mut p = raw.clone();
    if let Some(o) = p.as_object_mut() {
        for (k, v) in o.iter_mut() {
            if let Value::String(t) = v
                && matches!(k.as_str(), "disabled" | "auto_sid" | "force")
            {
                *v = Value::Bool(t == "yes" || t == "true");
            }
        }
    }
    p
}

/// The modal's preview: never an error for bad input, a check instead.
fn sr_check(s: &mut Session, raw: &Value) -> Result<Value> {
    let mut p = normalize(raw);
    if let Some(o) = p.as_object_mut() {
        o.remove("id");
    }
    let mut checks = Vec::new();
    let mut computed = Vec::new();
    let why = mpls_supported(s).err();
    if let Some(w) = &why {
        checks.push(check("error", "mpls", format!("unavailable: {w}. Segment Routing forwards by label, so the kernel must switch MPLS (modprobe mpls_router mpls_iptunnel)"), ""));
    }
    let inst = s
        .store()
        .candidate()
        .routing
        .ospf
        .segment_routing
        .as_ref()
        .map(|sr| sr.instance.clone())
        .or_else(|| p.get("instance").and_then(Value::as_str).map(str::to_owned))
        .or_else(|| {
            s.store()
                .candidate()
                .routing
                .ospf
                .instances
                .values()
                .find(|i| i.version == Version::V2 && i.vrf == MAIN_VRF)
                .map(|i| i.name.clone())
        });
    let view = inst.as_deref().map(|i| s.ospf_db(i));
    let (db, routes) = match view.as_ref().and_then(|v| v.db()) {
        Some(d) => (Some(d.0.sr.clone()), d.1.clone()),
        None => (None, Vec::new()),
    };
    let mut cfg = s.store().candidate().clone();
    let added = match apply(&mut cfg, &p, db.as_ref()) {
        Ok(a) => a,
        Err(e) => {
            let (param, msg) = match &e {
                EngineError::BadParam { param, reason } => (param.clone(), reason.clone()),
                other => (String::new(), other.to_string()),
            };
            checks.push(check("error", "params", msg, &param));
            return Ok(json!({"computed": computed, "checks": checks, "commands": [], "risk": null, "preview": null, "available": why.is_none(), "why": why}));
        }
    };
    for issue in corerouter_proto_ospf::validate(&cfg) {
        if let Some(rest) = issue.path.strip_prefix("routing.ospf.segment_routing") {
            checks.push(check("error", "validate", issue.message, rest.trim_start_matches('.')));
        } else if issue.path.starts_with("routing.ospf.prefix_sids") || issue.path.starts_with("routing.mpls") {
            checks.push(check("error", "validate", issue.message, ""));
        }
    }
    // TI-LFA pushes up to two repair labels over the prefix SID (RFC 9855
    // §6: P node and adjacency P→Q).
    let ti_lfa = cfg.routing.ospf.segment_routing.as_ref().is_some_and(|x| x.ti_lfa != TiLfa::Off);
    let labels = if ti_lfa { sr::SR_LABELS + 2 } else { sr::SR_LABELS };
    let pv = sr::preview(&cfg, s.store().running(), db.as_ref().filter(|d| !d.is_empty()), &routes, labels);
    if ti_lfa && cfg.routing.ospf.segment_routing.as_ref().is_some_and(|x| x.ti_lfa == TiLfa::Node) {
        checks.push(check("info", "ti-lfa", "node protection: a route to the next hop itself has no backup (the router is what fails); link protection covers it".into(), "ti_lfa"));
    }
    if ti_lfa && cfg.routing.ospf.templates.iter().all(|t| t.bfd.is_none()) {
        checks.push(check("warning", "bfd", "TI-LFA repairs from the moment the failure is seen: without BFD on the OSPF links a silent cut waits for the dead interval (set a BFD profile in the interface templates)".into(), "ti_lfa"));
    }
    if let Some(sr) = &cfg.routing.ospf.segment_routing {
        computed.push(json!({"label": "Instance", "value": sr.instance}));
        computed.push(json!({"label": "SRGB", "value": format!("{} ({} labels)", sr.srgb, sr.srgb.size())}));
        computed.push(json!({"label": "SRLB", "value": sr.srlb.to_string()}));
        computed.push(json!({"label": "TI-LFA", "value": sr.ti_lfa.name()}));
    }
    if let Some(b) = &pv.ldp_block {
        computed.push(json!({"label": "LDP labels", "value": b}));
    }
    let own: Vec<String> = pv.own.iter().map(|(p, i, l)| format!("{p} index {i} → label {l}")).collect();
    computed.push(json!({"label": "Prefix SIDs", "value": if own.is_empty() { "none".to_owned() } else { own.join(", ") }}));
    for (p, i) in &added {
        checks.push(check("info", "auto-sid", format!("{p} gets index {i} (its loopback, picked automatically)"), "auto_sid"));
    }
    if own.is_empty() {
        checks.push(check("warning", "sid", "no prefix SID: other routers cannot reach this one by label (add one with routing.ospf.prefix-sid.add or auto_sid)".into(), "auto_sid"));
    }
    for m in &pv.mtu {
        checks.push(check("warning", "mtu", format!("{}: MTU {} is short of {} (the IP packet + {} bytes per label): labeled packets that size are dropped", m.interface, m.mtu, m.needed, corerouter_model::mpls::LABEL_BYTES), ""));
    }
    if !pv.no_mpls_input.is_empty() {
        checks.push(check("warning", "mpls-input", format!("no MPLS input on {}: the kernel drops the labeled packets that come in there (mpls.interface.add)", pv.no_mpls_input.join(", ")), ""));
    }
    for c in &pv.conflicts {
        checks.push(check("error", "conflict", c.detail.clone(), ""));
    }
    if let Some(w) = lo_warning(s, &cfg, &cfg.routing.ospf.prefix_sids) {
        checks.push(check("warning", "loopback", w, "auto_sid"));
    }
    if cfg.routing.mpls.ldp_running().is_some() && pv.switches == Some("on") {
        checks.push(check("info", "ldp", "LDP keeps running; for a prefix with both, zebra keeps the label it got first (RFC 8661 leaves the choice to the router)".into(), ""));
    }
    let risk = match pv.switches {
        Some("on") if pv.by_label.is_empty() && pv.maybe.is_empty() => Some(
            "the traffic to the other routers' loopbacks moves from IP to labels as they announce a SID. Use Safe Mode to roll back on its own if this cuts the session".into(),
        ),
        Some("on") => Some(format!(
            "the traffic inside OSPF moves from IP to labels: {} loopbacks now, {} more once their routers have a SID. Use Safe Mode to roll back on its own if this cuts the session",
            pv.by_label.len(),
            pv.maybe.len()
        )),
        Some("off") => Some("the traffic that goes by SR label goes back to IP (or to LDP). Use Safe Mode to roll back on its own if this cuts the session".into()),
        _ => None,
    };
    let ok = why.is_none() && !checks.iter().any(|c| c.get("level").and_then(Value::as_str) == Some("error"));
    Ok(json!({
        "computed": computed,
        "checks": checks,
        "commands": if ok { vec![json!({"command": "routing.ospf.segment-routing.set", "params": p})] } else { Vec::new() },
        "risk": risk,
        "preview": pv,
        "available": why.is_none(),
        "why": why,
    }))
}

fn ip(v: u32) -> String {
    Ipv4Addr::from(v).to_string()
}

fn sr_database(s: &mut Session, _: &Value) -> Result<Value> {
    let why = mpls_supported(s).err();
    let cfg = s.store().candidate().clone();
    let ospf = &cfg.routing.ospf;
    let issues: Vec<String> = corerouter_proto_ospf::validate(&cfg)
        .into_iter()
        .filter(|i| i.path.starts_with("routing.ospf.segment_routing") || i.path.starts_with("routing.ospf.prefix_sids"))
        .map(|i| i.message)
        .collect();
    let Some(sr_cfg) = &ospf.segment_routing else {
        return Ok(json!({"configured": false, "active": false, "disabled": false, "source": "config", "stale": false, "nodes": [], "sids": [], "conflicts": [], "issues": issues, "available": why.is_none(), "why": why}));
    };
    let active = corerouter_model::ospf_sr::active(ospf).is_some();
    let view = s.ospf_db(&sr_cfg.instance);
    let source = view.source();
    let stale = matches!(view, crate::ospf_state::DbView::Daemon { stale: true, .. });
    let error = match &view {
        crate::ospf_state::DbView::Error(e) => Some(e.clone()),
        _ => None,
    };
    let db = view.db().map(|d| d.0.sr.clone()).unwrap_or_default();
    let me = db.router_id;
    let own_srgb = (sr_cfg.srgb.start, sr_cfg.srgb.size());
    let nodes: Vec<Value> = db
        .nodes
        .iter()
        .map(|n| {
            json!({
                "router_id": ip(n.router_id),
                "srgb": LabelBlock { start: n.srgb_start, end: n.srgb_start.saturating_add(n.srgb_size).saturating_sub(1) }.to_string(),
                "srlb": LabelBlock { start: n.srlb_start, end: n.srlb_start.saturating_add(n.srlb_size).saturating_sub(1) }.to_string(),
                "msd": n.msd,
                "adjacencies": n.adjacencies,
                "prefixes": n.prefixes.len(),
                "same_srgb": (n.srgb_start, n.srgb_size) == own_srgb,
                "me": Some(n.router_id) == me,
            })
        })
        .collect();
    let mut sids = Vec::new();
    for n in &db.nodes {
        for p in &n.prefixes {
            let first = p.out.first();
            sids.push(json!({
                "prefix": format!("{}/{}", ip(p.prefix), p.plen),
                "router": ip(n.router_id),
                "index": p.sid,
                "label": sr_cfg.srgb.label(p.sid),
                "in_label": p.in_label,
                "out_label": first.map(|h| h.label),
                "interface": first.map(|h| h.interface.clone()),
                "nexthop": first.filter(|h| h.nexthop != 0).map(|h| ip(h.nexthop)),
                "own": Some(n.router_id) == me,
            }));
        }
    }
    // This router's SIDs from the config when the daemon has none yet.
    if db.nodes.is_empty() {
        for p in ospf.prefix_sids.iter().filter(|p| !p.disabled) {
            sids.push(json!({"prefix": p.prefix.to_string(), "router": "this router", "index": p.index, "label": sr_cfg.srgb.label(p.index), "in_label": 0, "own": true}));
        }
    }
    let conflicts = sr::conflicts(&db, &ospf.prefix_sids);
    Ok(json!({
        "configured": true,
        "active": active,
        "instance": sr_cfg.instance,
        "srgb": sr_cfg.srgb.to_string(),
        "srlb": sr_cfg.srlb.to_string(),
        "node_msd": sr_cfg.node_msd,
        "ti_lfa": sr_cfg.ti_lfa.name(),
        "disabled": sr_cfg.disabled,
        "comment": sr_cfg.comment,
        "ldp_block": sr::dynamic_block(&cfg).map(|b| b.to_string()),
        "source": source,
        "stale": stale,
        "error": error,
        "router_id": me.map(ip),
        "nodes": nodes,
        "sids": sids,
        "conflicts": conflicts,
        "issues": issues,
        "available": why.is_none(),
        "why": why,
    }))
}

/// The /32 a `prefix` or `interface` names.
fn sid_prefix(cfg: &Config, p: &Value) -> Result<Ipv4Net> {
    if let Some(t) = p.get("prefix").and_then(Value::as_str).map(str::trim).filter(|t| !t.is_empty()) {
        let net: IpNet = if t.contains('/') {
            t.parse().map_err(|_| EngineError::bad("prefix", "an IPv4 /32 (10.255.0.1/32)"))?
        } else {
            let a: Ipv4Addr = t.parse().map_err(|_| EngineError::bad("prefix", "an IPv4 /32 (10.255.0.1/32)"))?;
            IpNet::V4(Ipv4Net::from(a))
        };
        return match net {
            IpNet::V4(n) => Ok(n),
            IpNet::V6(_) => Err(EngineError::bad("prefix", "SR-MPLS over OSPFv2 takes IPv4 prefixes")),
        };
    }
    let lo = sr::loopback_addresses(cfg);
    if let Some(i) = p.get("interface").and_then(Value::as_str).map(str::trim) {
        let mut on: Vec<Ipv4Net> = lo.iter().filter(|(_, n)| n.as_str() == i).map(|(p, _)| *p).collect();
        return match on.len() {
            1 => Ok(on.remove(0)),
            0 => Err(EngineError::bad("interface", format!("{:?} is not a loopback with a /32", super::routing_ospf::cut(i)))),
            _ => Err(EngineError::bad("interface", "it has several /32s: give the prefix")),
        };
    }
    let inst = cfg.routing.ospf.segment_routing.as_ref().map(|s| s.instance.as_str()).unwrap_or("");
    let free: Vec<Ipv4Net> = sr::announced_loopbacks(cfg, inst)
        .into_iter()
        .map(|(p, _)| p)
        .filter(|p| !cfg.routing.ospf.prefix_sids.iter().any(|s| s.prefix == *p))
        .collect();
    match free.as_slice() {
        [one] => Ok(*one),
        [] => Err(EngineError::bad("prefix", "is required (no loopback /32 of the SR instance is without a SID)")),
        _ => Err(EngineError::bad("prefix", "is required (several loopbacks have no SID)")),
    }
}

/// Refuse an index that another router uses for another prefix (unless
/// `force`).
fn clash(db: &SrDb, prefix: Ipv4Net, index: u32, force: bool) -> Result<()> {
    if force {
        return Ok(());
    }
    for n in db.nodes.iter().filter(|n| Some(n.router_id) != db.router_id) {
        for p in &n.prefixes {
            let theirs = Ipv4Net::new(Ipv4Addr::from(p.prefix), p.plen).ok();
            if p.sid == index && theirs != Some(prefix) {
                return Err(EngineError::bad(
                    "index",
                    format!(
                        "index {index} is already {} on router {} (RFC 8402 §3.2: one index, one prefix); pick another or force: true",
                        theirs.map(|t| t.to_string()).unwrap_or_default(),
                        ip(n.router_id)
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn behavior(p: &Value, slot: &mut SidBehavior) -> Result<()> {
    if let Given::Value(v) = given(p, "behavior") {
        *slot = SidBehavior::parse(text("behavior", v)?).ok_or_else(|| EngineError::bad("behavior", "php, no-php or explicit-null"))?;
    }
    Ok(())
}

fn sid_row(cfg: &Config, sid: &PrefixSid) -> Value {
    let srgb = cfg.routing.ospf.segment_routing.as_ref().map(|s| s.srgb);
    let lo = sr::loopback_addresses(cfg);
    let inst = cfg.routing.ospf.segment_routing.as_ref().map(|s| s.instance.as_str()).unwrap_or("");
    let announced = sr::announced_loopbacks(cfg, inst).iter().any(|(p, _)| *p == sid.prefix);
    json!({
        "id": sid.id.to_string(),
        "prefix": sid.prefix.to_string(),
        "interface": lo.get(&sid.prefix).map(ToString::to_string),
        "index": sid.index,
        "label": srgb.and_then(|b| b.label(sid.index)),
        "behavior": sid.behavior.name(),
        "announced": announced,
        "disabled": sid.disabled,
        "comment": sid.comment,
    })
}

/// The network's SR database of the SR instance (empty when not known).
fn sr_db_of(s: &mut Session) -> SrDb {
    let inst = s.store().candidate().routing.ospf.segment_routing.as_ref().map(|x| x.instance.clone());
    inst.and_then(|i| network_db(s, &i)).unwrap_or_default()
}

/// `prefix-sid.add` (`id` None) or `set` on `cfg`: the SID as it ends up.
fn sid_apply(cfg: &mut Config, db: &SrDb, p: &Value, id: Option<ItemId>) -> Result<PrefixSid> {
    let srgb = cfg.routing.ospf.segment_routing.as_ref().map_or(corerouter_model::ospf_sr::DEFAULT_SRGB, |s| s.srgb);
    let force = opt_boolean(p, "force")?.unwrap_or(false);
    let pos = match id {
        Some(id) => Some(
            cfg.routing
                .ospf
                .prefix_sids
                .iter()
                .position(|x| x.id == id)
                .ok_or_else(|| EngineError::bad("id", format!("no prefix SID {id}")))?,
        ),
        None => None,
    };
    let mut sid = match pos.and_then(|i| cfg.routing.ospf.prefix_sids.get(i)) {
        Some(x) => x.clone(),
        None => {
            let prefix = sid_prefix(cfg, p)?;
            if prefix.prefix_len() != 32 {
                return Err(EngineError::bad("prefix", "a prefix SID names a /32 (the loopback address)"));
            }
            if cfg.routing.ospf.prefix_sids.iter().any(|x| x.prefix == prefix) {
                return Err(EngineError::bad("prefix", format!("{prefix} already has a SID")));
            }
            if cfg.routing.ospf.prefix_sids.len() >= MAX_PREFIX_SIDS {
                return Err(EngineError::bad("prefix", format!("at most {MAX_PREFIX_SIDS} prefix SIDs")));
            }
            let index = sr::propose_index(prefix, srgb, &cfg.routing.ospf.prefix_sids, db)
                .ok_or_else(|| EngineError::bad("index", "no free index in the SRGB"))?;
            PrefixSid { id: ItemId(0), prefix, index, behavior: SidBehavior::Php, disabled: false, comment: String::new() }
        }
    };
    if let Given::Value(v) = given(p, "index") {
        sid.index = u32::try_from(number("index", v, 0, u64::from(MAX_INDEX))?).unwrap_or(0);
    }
    if let Some(other) = cfg.routing.ospf.prefix_sids.iter().find(|x| x.index == sid.index && Some(x.id) != id) {
        return Err(EngineError::bad("index", format!("index {} is already the SID of {}", sid.index, other.prefix)));
    }
    clash(db, sid.prefix, sid.index, force)?;
    behavior(p, &mut sid.behavior)?;
    if let Some(d) = opt_boolean(p, "disabled")? {
        sid.disabled = d;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        sid.comment = c;
    }
    let ospf = &mut cfg.routing.ospf;
    match pos.and_then(|i| ospf.prefix_sids.get_mut(i)) {
        Some(slot) => *slot = sid.clone(),
        None => {
            sid.id = ospf.next_id();
            ospf.prefix_sids.push(sid.clone());
        }
    }
    Ok(sid)
}

fn sid_out(cfg: &Config, sid: &PrefixSid) -> Value {
    let srgb = cfg.routing.ospf.segment_routing.as_ref().map(|s| s.srgb);
    json!({"id": sid.id.to_string(), "prefix": sid.prefix.to_string(), "index": sid.index, "label": srgb.and_then(|b| b.label(sid.index))})
}

fn sid_add(s: &mut Session, p: &Value) -> Result<Value> {
    let db = sr_db_of(s);
    let mut cfg = s.store().candidate().clone();
    let sid = sid_apply(&mut cfg, &db, p, None)?;
    let out = sid_out(&cfg, &sid);
    s.store_mut().candidate_mut().routing.ospf = cfg.routing.ospf.clone();
    Ok(out)
}

fn sid_set(s: &mut Session, p: &Value) -> Result<Value> {
    let id = parse_id("id", req_str(p, "id")?)?;
    let db = sr_db_of(s);
    let mut cfg = s.store().candidate().clone();
    let sid = sid_apply(&mut cfg, &db, p, Some(id))?;
    let out = sid_out(&cfg, &sid);
    s.store_mut().candidate_mut().routing.ospf = cfg.routing.ospf.clone();
    Ok(out)
}

/// The modal's preview of a prefix SID: never an error, a check instead.
fn sid_check(s: &mut Session, raw: &Value) -> Result<Value> {
    let mut p = normalize(raw);
    let id = match given(&p, "id") {
        Given::Value(v) => text("id", v).ok().and_then(|i| i.parse::<ItemId>().ok()),
        _ => None,
    };
    if let Some(o) = p.as_object_mut() {
        for k in ["index", "prefix", "interface"] {
            if o.get(k).and_then(Value::as_str).is_some_and(|v| v.trim().is_empty() || v.trim() == "auto") {
                o.remove(k);
            }
        }
        if id.is_none() {
            o.remove("id");
        }
    }
    let db = sr_db_of(s);
    let mut cfg = s.store().candidate().clone();
    let mut checks = Vec::new();
    let mut computed = Vec::new();
    match sid_apply(&mut cfg, &db, &p, id) {
        Ok(sid) => {
            let srgb = cfg.routing.ospf.segment_routing.as_ref().map(|x| x.srgb);
            computed.push(json!({"label": "Prefix", "value": sid.prefix.to_string()}));
            computed.push(json!({"label": "Index", "value": sid.index.to_string()}));
            computed.push(json!({"label": "Label", "value": srgb.and_then(|b| b.label(sid.index)).map_or("outside the SRGB".to_owned(), |l| format!("{l} (on routers with the same SRGB)"))}));
            for issue in corerouter_proto_ospf::validate(&cfg) {
                if issue.path.starts_with("routing.ospf.prefix_sids") {
                    checks.push(check("error", "validate", issue.message, ""));
                }
            }
            if let Some(w) = lo_warning(s, &cfg, std::slice::from_ref(&sid)) {
                checks.push(check("warning", "loopback", w, "prefix"));
            }
            if db.nodes.is_empty() {
                checks.push(check("info", "network", "the SR database is not read yet: a clash with another router shows once it is".into(), "index"));
            }
            // What the add/set gets: the index picked is made explicit.
            if let Some(o) = p.as_object_mut() {
                o.insert("index".into(), json!(sid.index));
                if id.is_none() {
                    o.insert("prefix".into(), json!(sid.prefix.to_string()));
                    o.remove("interface");
                }
            }
        }
        Err(e) => {
            let (param, msg) = match &e {
                EngineError::BadParam { param, reason } => (param.clone(), reason.clone()),
                other => (String::new(), other.to_string()),
            };
            checks.push(check("error", "params", msg, &param));
        }
    }
    let ok = !checks.iter().any(|c| c.get("level").and_then(Value::as_str) == Some("error"));
    if let Some(o) = p.as_object_mut()
        && id.is_some()
    {
        o.remove("prefix");
        o.remove("interface");
    }
    Ok(json!({
        "computed": computed,
        "checks": checks,
        "commands": if ok { vec![json!({"command": if id.is_some() { "routing.ospf.prefix-sid.set" } else { "routing.ospf.prefix-sid.add" }, "params": p})] } else { Vec::new() },
        "risk": null,
    }))
}

fn sid_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id = parse_id("id", req_str(p, "id")?)?;
    let ospf = &mut s.store_mut().candidate_mut().routing.ospf;
    let before = ospf.prefix_sids.len();
    ospf.prefix_sids.retain(|x| x.id != id);
    if ospf.prefix_sids.len() == before {
        return Err(EngineError::bad("id", format!("no prefix SID {id}")));
    }
    Ok(json!({ "id": id.to_string() }))
}

fn sid_list(s: &mut Session, _: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    Ok(Value::Array(cfg.routing.ospf.prefix_sids.iter().map(|x| sid_row(cfg, x)).collect()))
}

#[cfg(test)]
mod tests {
    use corerouter_hal::VirtualHal;
    use serde_json::json;

    use crate::Session;

    /// v2 in the backbone: ether1 and the loopback lo0 (10.255.0.1/32).
    fn lab() -> Session {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        for (id, p) in [
            ("interface.loopback.add", json!({"name": "lo0"})),
            ("ip.address.add", json!({"address": "10.255.0.1/32", "interface": "lo0"})),
            ("ip.address.add", json!({"address": "10.0.1.1/30", "interface": "ether1"})),
            ("routing.ospf.instance.add", json!({"name": "v2", "router_id": "10.255.0.1"})),
            ("routing.ospf.area.add", json!({"name": "bb", "instance": "v2", "area_id": "0"})),
            ("routing.ospf.interface-template.add", json!({"area": "bb", "interfaces": "lo0", "passive": true})),
            ("routing.ospf.interface-template.add", json!({"area": "bb", "interfaces": "ether1", "type": "ptp"})),
        ] {
            s.execute(id, &p).unwrap_or_else(|e| panic!("{id}: {e}"));
        }
        s
    }

    #[test]
    fn switching_sr_on_previews_then_gives_the_loopback_a_sid() {
        let mut s = lab();
        let c = s.execute("routing.ospf.segment-routing.check", &json!({})).unwrap();
        assert_eq!(c["available"], true, "{c}");
        assert_eq!(c["commands"][0]["command"], "routing.ospf.segment-routing.set", "{c}");
        assert!(c["risk"].as_str().unwrap().contains("Safe Mode"), "{c}");
        assert_eq!(c["preview"]["switches"], "on");
        let text = c.to_string();
        assert!(text.contains("10.255.0.1/32 gets index 1"), "{text}");
        assert!(text.contains("no MPLS input on ether1"), "{text}");
        let r = s.execute("routing.ospf.segment-routing.set", &json!({})).unwrap();
        assert_eq!(r["instance"], "v2");
        assert_eq!(r["added"][0]["index"], 1);
        assert_eq!(r["added"][0]["label"], 16_001);
        let l = s.execute("routing.ospf.prefix-sid.list", &json!({})).unwrap();
        assert_eq!(l[0]["interface"], "lo0");
        assert_eq!(l[0]["announced"], true);
        let db = s.execute("routing.ospf.segment-routing.database", &json!({})).unwrap();
        assert_eq!(db["active"], true, "{db}");
        assert_eq!(db["ldp_block"], "24000-1048575");
        assert_eq!(db["source"], "virtual lab sample");
        assert!(db["sids"].as_array().unwrap().iter().any(|x| x["own"] == true && x["index"] == 1), "{db}");
        assert!(db["conflicts"].as_array().unwrap().is_empty(), "{db}");
    }

    #[test]
    fn bad_blocks_and_duplicate_sids_are_refused_and_nothing_changes() {
        let mut s = lab();
        let before = s.store().running().clone();
        assert!(s.execute("routing.ospf.segment-routing.set", &json!({"srgb": "10-20"})).is_err());
        assert!(s.execute("routing.ospf.segment-routing.set", &json!({"srgb": "nonsense"})).is_err());
        assert!(s.execute("routing.ospf.segment-routing.set", &json!({"instance": "nope"})).is_err());
        assert_eq!(s.store().running(), &before, "rolled back");
        s.execute("routing.ospf.segment-routing.set", &json!({})).unwrap();
        let e = s.execute("routing.ospf.prefix-sid.add", &json!({"prefix": "10.255.0.1/32", "index": 5})).unwrap_err();
        assert!(e.to_string().contains("already has a SID"), "{e}");
        s.execute("interface.loopback.add", &json!({"name": "lo1"})).unwrap();
        s.execute("ip.address.add", &json!({"address": "10.255.0.9/32", "interface": "lo1"})).unwrap();
        let e = s.execute("routing.ospf.prefix-sid.add", &json!({"interface": "lo1", "index": 1})).unwrap_err();
        assert!(e.to_string().contains("already the SID of"), "{e}");
        // lo1 is in no template: the commit refuses it.
        let e = s.execute("routing.ospf.prefix-sid.add", &json!({"interface": "lo1"})).unwrap_err();
        assert!(e.to_string().contains("does not announce"), "{e}");
        // The lab's network has index 100 on another router: a clash.
        s.execute("routing.ospf.interface-template.add", &json!({"area": "bb", "interfaces": "lo1", "passive": true})).unwrap();
        let e = s.execute("routing.ospf.prefix-sid.add", &json!({"interface": "lo1", "index": 100})).unwrap_err();
        assert!(e.to_string().contains("RFC 8402"), "{e}");
        let r = s.execute("routing.ospf.prefix-sid.add", &json!({"interface": "lo1", "index": 100, "force": true})).unwrap();
        assert_eq!(r["label"], 16_100);
        let id = r["id"].as_str().unwrap().to_owned();
        s.execute("routing.ospf.prefix-sid.set", &json!({"id": id, "index": 9, "behavior": "explicit-null"})).unwrap();
        assert!(s.execute("routing.ospf.prefix-sid.set", &json!({"id": id, "behavior": "x"})).is_err());
        s.execute("routing.ospf.prefix-sid.remove", &json!({"id": id})).unwrap();
        let r = s.execute("routing.ospf.segment-routing.unset", &json!({})).unwrap();
        assert_eq!(r["removed_sids"], 1);
        assert!(s.store().running().routing.ospf.segment_routing.is_none());
    }

    #[test]
    fn the_prefix_sid_preview_picks_the_index_and_flags_a_clash() {
        let mut s = lab();
        s.execute("routing.ospf.segment-routing.set", &json!({"auto_sid": false})).unwrap();
        let c = s.execute("routing.ospf.prefix-sid.check", &json!({"interface": "lo0", "index": "auto", "force": "no"})).unwrap();
        assert_eq!(c["commands"][0]["command"], "routing.ospf.prefix-sid.add", "{c}");
        assert_eq!(c["commands"][0]["params"]["index"], 1, "{c}");
        assert_eq!(c["commands"][0]["params"]["prefix"], "10.255.0.1/32", "{c}");
        let cmd = c["commands"][0]["params"].clone();
        s.execute("routing.ospf.prefix-sid.add", &cmd).unwrap();
        // Index 100 is another router's in the lab's network.
        let c = s.execute("routing.ospf.prefix-sid.check", &json!({"id": "*9", "index": 100})).unwrap();
        assert!(c["commands"].as_array().unwrap().is_empty(), "{c}");
        let id = s.store().running().routing.ospf.prefix_sids[0].id.to_string();
        let c = s.execute("routing.ospf.prefix-sid.check", &json!({"id": id, "index": 100})).unwrap();
        assert!(c.to_string().contains("RFC 8402"), "{c}");
        let c = s.execute("routing.ospf.prefix-sid.check", &json!({"id": id, "index": 100, "force": "yes"})).unwrap();
        assert_eq!(c["commands"][0]["command"], "routing.ospf.prefix-sid.set", "{c}");
        assert!(c["commands"][0]["params"].get("prefix").is_none(), "{c}");
    }

    #[test]
    fn the_instance_carries_sr_through_a_rename_and_cannot_go_while_used() {
        let mut s = lab();
        s.execute("routing.ospf.segment-routing.set", &json!({"auto_sid": false})).unwrap();
        assert!(s.store().running().routing.ospf.prefix_sids.is_empty());
        s.execute("routing.ospf.instance.set", &json!({"id": "v2", "name": "core"})).unwrap();
        assert_eq!(s.store().running().routing.ospf.segment_routing.as_ref().unwrap().instance, "core");
        s.execute("routing.ospf.area.remove", &json!({"id": "bb"})).ok();
        let e = s.execute("routing.ospf.instance.remove", &json!({"id": "core"}));
        assert!(e.is_err());
    }
}
