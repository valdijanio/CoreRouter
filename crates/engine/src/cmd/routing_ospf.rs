//! /routing ospf instance, area, area range, static-neighbor (G3.4): OSPF
//! in the RouterOS v7 model. `proto-ospf` validates and renders; the
//! commit takes the result to FRR's `ospfd`/`ospf6d` (`hal-frr`), typing
//! only the difference. The interface templates and key chains are in
//! `routing_ospf_template.rs` and `routing_ospf_keychain.rs`.
//!
//! As in the BGP commands, a parameter left out of `set` is kept and one
//! given as `null` (or `""` from a form) is unset again.

use std::net::Ipv4Addr;

use corerouter_model::Routing;
use corerouter_model::ospf::{
    AreaId, AreaType, MAX_AREAS, MAX_INSTANCES, MAX_NEIGHBORS, MAX_RANGES, NssaTranslate, OriginateDefault,
    OspfArea, OspfAreaRange, OspfInstance, OspfStaticNeighbor, Redistribute, Version,
};
use corerouter_model::types::ItemId;
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_text, req_str};
use super::dhcp_client::opt_list;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("routing.ospf.instance.add", "Add OSPF Instance", ["Routing", "OSPF"], None,
        "{name: string, version?: u8 (2: IPv4, RFC 2328; 3: IPv6, RFC 5340; default 2), vrf?: string (default main), router_id?: ipv4 | null (unique in the AS; default: picked by the daemon), redistribute?: [string] | string (connected, static, bgp, kernel), out_filter_chain?: string | null (the /routing filter chain of redistributed routes), originate_default?: string (never, if-installed, always), subscriber_pools?: bool (announce the PPPoE/IPoE pools, summarized; v2), disabled?: bool, comment?: string} → {name}",
        always, instance_add),
    cmd!("routing.ospf.instance.set", "Set OSPF Instance", [], None,
        "{id: string (the name), name?: string, version?: u8, vrf?: string, router_id?: ipv4 | null, redistribute?: [string] | string, out_filter_chain?: string | null, originate_default?: string, subscriber_pools?: bool, disabled?: bool, comment?: string} → {name}",
        has_instances, instance_set),
    cmd!("routing.ospf.instance.remove", "Remove OSPF Instance", [], None,
        "{id: string (the name)} → {name}",
        has_instances, instance_remove),
    cmd!(query "routing.ospf.instance.list", "OSPF Instances", ["Routing", "OSPF"], None,
        "{} → [{name, version, vrf, router_id, redistribute, out_filter_chain, originate_default, subscriber_pools, pools: [prefix] (announced), areas, interfaces (matched now), disabled, comment}]",
        always, instance_list),
    cmd!("routing.ospf.area.add", "Add OSPF Area", ["Routing", "OSPF"], None,
        "{name: string, instance: string, area_id: string (dotted 0.0.0.1 or a number; 0.0.0.0 is the backbone), type?: string (default, stub, nssa), no_summaries?: bool (stub/NSSA: only a default route from the ABR), default_cost?: u32 | null, nssa_translate?: string (candidate, yes, no), disabled?: bool, comment?: string} → {name}",
        always, area_add),
    cmd!("routing.ospf.area.set", "Set OSPF Area", [], None,
        "{id: string (the name), name?: string, instance?: string, area_id?: string, type?: string, no_summaries?: bool, default_cost?: u32 | null, nssa_translate?: string, disabled?: bool, comment?: string} → {name}",
        has_areas, area_set),
    cmd!("routing.ospf.area.remove", "Remove OSPF Area", [], None,
        "{id: string (the name)} → {name}",
        has_areas, area_remove),
    cmd!(query "routing.ospf.area.list", "OSPF Areas", ["Routing", "OSPF"], None,
        "{} → [{name, instance, version, area_id, type, no_summaries, default_cost, nssa_translate, backbone, interfaces, ranges, disabled, comment}]",
        always, area_list),
    cmd!("routing.ospf.area.range.add", "Add OSPF Area Range", ["Routing", "OSPF"], None,
        "{area: string, prefix: prefix (summarizes the area's networks inside it, RFC 2328 §12.4.3), advertise?: bool (default yes; no: hide them), cost?: u32 | null, disabled?: bool, comment?: string} → {id}",
        has_areas, range_add),
    cmd!("routing.ospf.area.range.set", "Set OSPF Area Range", [], None,
        "{id: string (*N), area?: string, prefix?: prefix, advertise?: bool, cost?: u32 | null, disabled?: bool, comment?: string} → {id}",
        has_ranges, range_set),
    cmd!("routing.ospf.area.range.remove", "Remove OSPF Area Range", [], None,
        "{id: string (*N)} → {id}",
        has_ranges, range_remove),
    cmd!(query "routing.ospf.area.range.list", "OSPF Area Ranges", ["Routing", "OSPF"], None,
        "{} → [{id, area, instance, prefix, advertise, cost, disabled, comment}]",
        always, range_list),
    cmd!("routing.ospf.static-neighbor.add", "Add OSPF Static Neighbor", ["Routing", "OSPF"], None,
        "{instance: string, address: ipv4 (a neighbor on an NBMA link, RFC 2328 §9.5.1), poll_interval?: u16 | null, disabled?: bool, comment?: string} → {id}",
        has_instances, neighbor_add),
    cmd!("routing.ospf.static-neighbor.remove", "Remove OSPF Static Neighbor", [], None,
        "{id: string (*N)} → {id}",
        has_neighbors, neighbor_remove),
    cmd!(query "routing.ospf.static-neighbor.list", "OSPF Static Neighbors", ["Routing", "OSPF"], None,
        "{} → [{id, instance, address, poll_interval, disabled, comment}]",
        always, neighbor_list),
];

fn has_instances(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.ospf.instances.is_empty() {
        Err("there are no OSPF instances (routing.ospf.instance.add)".into())
    } else {
        Ok(())
    }
}

fn has_areas(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.ospf.areas.is_empty() {
        Err("there are no OSPF areas (routing.ospf.area.add)".into())
    } else {
        Ok(())
    }
}

fn has_ranges(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.ospf.ranges.is_empty() {
        Err("there are no OSPF area ranges".into())
    } else {
        Ok(())
    }
}

fn has_neighbors(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.ospf.static_neighbors.is_empty() {
        Err("there are no OSPF static neighbors".into())
    } else {
        Ok(())
    }
}

// ---- shared parameter helpers (also used by the template and key chain
// commands) ----

/// A parameter of `add`/`set`: absent (keep), unset (`null` or `""`, what
/// a form sends for an empty field) or a value.
pub(super) enum Given<'a> {
    Absent,
    Unset,
    Value(&'a Value),
}

pub(super) fn given<'a>(p: &'a Value, key: &str) -> Given<'a> {
    match p.get(key) {
        None => Given::Absent,
        Some(Value::Null) => Given::Unset,
        Some(Value::String(s)) if s.trim().is_empty() => Given::Unset,
        Some(v) => Given::Value(v),
    }
}

/// A whole number in `lo..=hi`, as a JSON number or a form's text.
pub(super) fn number(key: &str, v: &Value, lo: u64, hi: u64) -> Result<u64> {
    let n = match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    };
    n.filter(|n| (lo..=hi).contains(n))
        .ok_or_else(|| EngineError::bad(key, format!("an integer {lo}..={hi}")))
}

/// `slot` from `key`: kept when absent, `None` when unset.
pub(super) fn opt_number<T: TryFrom<u64>>(p: &Value, key: &str, lo: u64, hi: u64, slot: &mut Option<T>) -> Result<()> {
    match given(p, key) {
        Given::Absent => {}
        Given::Unset => *slot = None,
        Given::Value(v) => {
            let n = number(key, v, lo, hi)?;
            *slot = Some(T::try_from(n).map_err(|_| EngineError::bad(key, "out of range"))?);
        }
    }
    Ok(())
}

/// A bool from JSON or a form (`yes`/`no`).
pub(super) fn boolean(key: &str, v: &Value) -> Result<bool> {
    match v {
        Value::Bool(b) => Ok(*b),
        Value::String(s) if matches!(s.as_str(), "yes" | "true") => Ok(true),
        Value::String(s) if matches!(s.as_str(), "no" | "false") => Ok(false),
        _ => Err(EngineError::bad(key, "must be true or false")),
    }
}

pub(super) fn opt_boolean(p: &Value, key: &str) -> Result<Option<bool>> {
    match given(p, key) {
        Given::Absent | Given::Unset => Ok(None),
        Given::Value(v) => boolean(key, v).map(Some),
    }
}

pub(super) fn text<'a>(key: &str, v: &'a Value) -> Result<&'a str> {
    v.as_str().map(str::trim).ok_or_else(|| EngineError::bad(key, "must be a string"))
}

/// A name that goes on FRR's vty.
pub(super) fn check_name(key: &str, name: &str) -> Result<()> {
    if corerouter_proto_ospf::name_ok(name) {
        Ok(())
    } else {
        Err(EngineError::bad(key, "1..=48 characters of [A-Za-z0-9_.-]"))
    }
}

pub(super) fn cut(s: &str) -> String {
    crate::logging::cut(s, 64)
}

pub(super) fn parse_id(key: &str, s: &str) -> Result<ItemId> {
    s.parse().map_err(|_| EngineError::bad(key, format!("{:?} is not an item id (*N)", cut(s))))
}

fn comment_and_disabled(p: &Value, comment: &mut String, disabled: &mut bool) -> Result<()> {
    if let Some(c) = opt_text(p, "comment", 256)? {
        *comment = c;
    }
    if let Some(d) = opt_boolean(p, "disabled")? {
        *disabled = d;
    }
    Ok(())
}

// ---- instances ----

fn apply_instance(routing: &mut Routing, p: &Value, id: Option<&str>) -> Result<String> {
    let ospf = &mut routing.ospf;
    let mut inst = match id {
        Some(id) => ospf
            .instances
            .get(id)
            .cloned()
            .ok_or_else(|| EngineError::bad("id", format!("no OSPF instance {:?}", cut(id))))?,
        None => OspfInstance {
            name: String::new(),
            version: Version::V2,
            vrf: corerouter_model::ospf::MAIN_VRF.to_owned(),
            router_id: None,
            redistribute: Vec::new(),
            out_filter_chain: None,
            originate_default: OriginateDefault::Never,
            subscriber_pools: false,
            disabled: false,
            comment: String::new(),
        },
    };
    match given(p, "name") {
        Given::Value(v) => {
            let n = text("name", v)?;
            check_name("name", n)?;
            inst.name = n.to_owned();
        }
        _ if id.is_none() => return Err(EngineError::bad("name", "is required")),
        _ => {}
    }
    if let Given::Value(v) = given(p, "version") {
        inst.version = Version::parse(number("version", v, 2, 3)?)
            .ok_or_else(|| EngineError::bad("version", "2 or 3"))?;
    }
    if let Given::Value(v) = given(p, "vrf") {
        let n = text("vrf", v)?;
        if n.is_empty() || n.len() > 64 || n.bytes().any(|b| !b.is_ascii_graphic()) {
            return Err(EngineError::bad("vrf", "main or a VRF interface name"));
        }
        inst.vrf = n.to_owned();
    }
    match given(p, "router_id") {
        Given::Absent => {}
        Given::Unset => inst.router_id = None,
        Given::Value(v) => {
            let t = text("router_id", v)?;
            inst.router_id = Some(
                t.parse::<Ipv4Addr>()
                    .map_err(|_| EngineError::bad("router_id", "an IPv4 address (a 32-bit id, RFC 2328 §C.1)"))?,
            );
        }
    }
    if let Some(list) = opt_list(p, "redistribute")? {
        let mut out = Vec::new();
        for r in list {
            let k = Redistribute::parse(r.trim())
                .ok_or_else(|| EngineError::bad("redistribute", format!("{:?}: connected, static, bgp or kernel", cut(&r))))?;
            if !out.contains(&k) {
                out.push(k);
            }
        }
        out.sort();
        inst.redistribute = out;
    }
    match given(p, "out_filter_chain") {
        Given::Absent => {}
        Given::Unset => inst.out_filter_chain = None,
        Given::Value(v) => {
            let c = text("out_filter_chain", v)?;
            corerouter_proto_bgp::filter::parse::check_chain(c).map_err(|e| EngineError::bad("out_filter_chain", e))?;
            inst.out_filter_chain = Some(c.to_owned());
        }
    }
    if let Given::Value(v) = given(p, "originate_default") {
        inst.originate_default = OriginateDefault::parse(text("originate_default", v)?)
            .ok_or_else(|| EngineError::bad("originate_default", "never, if-installed or always"))?;
    }
    if let Some(b) = opt_boolean(p, "subscriber_pools")? {
        inst.subscriber_pools = b;
    }
    comment_and_disabled(p, &mut inst.comment, &mut inst.disabled)?;
    let name = inst.name.clone();
    if id != Some(name.as_str()) && ospf.instances.contains_key(&name) {
        return Err(EngineError::bad("name", format!("instance {name:?} already exists")));
    }
    if id.is_none() && ospf.instances.len() >= MAX_INSTANCES {
        return Err(EngineError::bad("name", format!("at most {MAX_INSTANCES} instances")));
    }
    if let Some(old) = id.filter(|old| *old != name) {
        ospf.instances.remove(old);
        for a in ospf.areas.values_mut().filter(|a| a.instance == old) {
            a.instance = name.clone();
        }
        for n in ospf.static_neighbors.iter_mut().filter(|n| n.instance == old) {
            n.instance = name.clone();
        }
    }
    ospf.instances.insert(name.clone(), inst);
    Ok(name)
}

fn instance_add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = apply_instance(&mut s.store_mut().candidate_mut().routing, p, None)?;
    Ok(json!({ "name": name }))
}

fn instance_set(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?.to_owned();
    let name = apply_instance(&mut s.store_mut().candidate_mut().routing, p, Some(&id))?;
    Ok(json!({ "name": name }))
}

fn instance_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?;
    let ospf = &mut s.store_mut().candidate_mut().routing.ospf;
    if !ospf.instances.contains_key(id) {
        return Err(EngineError::bad("id", format!("no OSPF instance {:?}", cut(id))));
    }
    let areas: Vec<&str> = ospf.areas.values().filter(|a| a.instance == id).map(|a| a.name.as_str()).collect();
    if !areas.is_empty() {
        return Err(EngineError::bad(
            "id",
            format!("instance {id:?} has areas ({}): remove them first", areas.join(", ")),
        ));
    }
    ospf.static_neighbors.retain(|n| n.instance != id);
    ospf.instances.remove(id);
    Ok(json!({ "name": id }))
}

fn instance_list(s: &mut Session, _: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    let binds = corerouter_proto_ospf::bind::bindings(cfg);
    let pools = corerouter_proto_ospf::pools::cidrs(cfg);
    let ospf = &cfg.routing.ospf;
    let rows = ospf
        .instances
        .values()
        .map(|i| {
            json!({
                "name": i.name,
                "version": i.version.number(),
                "vrf": i.vrf,
                "router_id": i.router_id.map(|r| r.to_string()),
                "redistribute": i.redistribute.iter().map(|r| r.name()).collect::<Vec<_>>(),
                "out_filter_chain": i.out_filter_chain,
                "originate_default": i.originate_default.name(),
                "subscriber_pools": i.subscriber_pools,
                "pools": if i.subscriber_pools && i.version == Version::V2 {
                    pools.iter().map(ToString::to_string).collect::<Vec<_>>()
                } else {
                    Vec::new()
                },
                "areas": ospf.areas.values().filter(|a| a.instance == i.name).count(),
                "interfaces": binds.iter().filter(|b| b.instance.name == i.name).count(),
                "disabled": i.disabled,
                "comment": i.comment,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

// ---- areas ----

fn apply_area(routing: &mut Routing, p: &Value, id: Option<&str>) -> Result<String> {
    let ospf = &mut routing.ospf;
    let mut a = match id {
        Some(id) => ospf
            .areas
            .get(id)
            .cloned()
            .ok_or_else(|| EngineError::bad("id", format!("no OSPF area {:?}", cut(id))))?,
        None => OspfArea {
            name: String::new(),
            instance: String::new(),
            area_id: AreaId::BACKBONE,
            kind: AreaType::Default,
            no_summaries: false,
            default_cost: None,
            nssa_translate: NssaTranslate::Candidate,
            disabled: false,
            comment: String::new(),
        },
    };
    match given(p, "name") {
        Given::Value(v) => {
            let n = text("name", v)?;
            check_name("name", n)?;
            a.name = n.to_owned();
        }
        _ if id.is_none() => return Err(EngineError::bad("name", "is required")),
        _ => {}
    }
    match given(p, "instance") {
        Given::Value(v) => {
            let n = text("instance", v)?;
            if !ospf.instances.contains_key(n) {
                return Err(EngineError::bad("instance", format!("no OSPF instance {:?}", cut(n))));
            }
            a.instance = n.to_owned();
        }
        _ if id.is_none() => return Err(EngineError::bad("instance", "is required")),
        _ => {}
    }
    match given(p, "area_id") {
        Given::Value(v) => {
            a.area_id = match v {
                Value::Number(_) => AreaId(u32::try_from(number("area_id", v, 0, u64::from(u32::MAX))?).unwrap_or(0)),
                _ => text("area_id", v)?.parse().map_err(|e: String| EngineError::bad("area_id", e))?,
            };
        }
        _ if id.is_none() => return Err(EngineError::bad("area_id", "is required (0.0.0.0 for the backbone)")),
        _ => {}
    }
    if let Given::Value(v) = given(p, "type") {
        a.kind = AreaType::parse(text("type", v)?).ok_or_else(|| EngineError::bad("type", "default, stub or nssa"))?;
    }
    if let Some(b) = opt_boolean(p, "no_summaries")? {
        a.no_summaries = b;
    }
    opt_number(p, "default_cost", 0, u64::from(corerouter_proto_ospf::MAX_METRIC), &mut a.default_cost)?;
    if let Given::Value(v) = given(p, "nssa_translate") {
        a.nssa_translate = NssaTranslate::parse(text("nssa_translate", v)?)
            .ok_or_else(|| EngineError::bad("nssa_translate", "candidate, yes or no"))?;
    }
    comment_and_disabled(p, &mut a.comment, &mut a.disabled)?;
    let name = a.name.clone();
    if id != Some(name.as_str()) && ospf.areas.contains_key(&name) {
        return Err(EngineError::bad("name", format!("area {name:?} already exists")));
    }
    if id.is_none() && ospf.areas.len() >= MAX_AREAS {
        return Err(EngineError::bad("name", format!("at most {MAX_AREAS} areas")));
    }
    if let Some(old) = id.filter(|old| *old != name) {
        ospf.areas.remove(old);
        for t in ospf.templates.iter_mut() {
            if t.area == old {
                t.area = name.clone();
            }
            if t.vlink_transit_area.as_deref() == Some(old) {
                t.vlink_transit_area = Some(name.clone());
            }
        }
        for r in ospf.ranges.iter_mut().filter(|r| r.area == old) {
            r.area = name.clone();
        }
    }
    ospf.areas.insert(name.clone(), a);
    Ok(name)
}

fn area_add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = apply_area(&mut s.store_mut().candidate_mut().routing, p, None)?;
    Ok(json!({ "name": name }))
}

fn area_set(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?.to_owned();
    let name = apply_area(&mut s.store_mut().candidate_mut().routing, p, Some(&id))?;
    Ok(json!({ "name": name }))
}

fn area_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?;
    let ospf = &mut s.store_mut().candidate_mut().routing.ospf;
    if !ospf.areas.contains_key(id) {
        return Err(EngineError::bad("id", format!("no OSPF area {:?}", cut(id))));
    }
    let used = ospf
        .templates
        .iter()
        .filter(|t| t.area == id || t.vlink_transit_area.as_deref() == Some(id))
        .count();
    if used > 0 {
        return Err(EngineError::bad(
            "id",
            format!("area {id:?} is used by {used} interface template(s): remove or move them first"),
        ));
    }
    ospf.ranges.retain(|r| r.area != id);
    ospf.areas.remove(id);
    Ok(json!({ "name": id }))
}

fn area_list(s: &mut Session, _: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    let binds = corerouter_proto_ospf::bind::bindings(cfg);
    let ospf = &cfg.routing.ospf;
    let rows = ospf
        .areas
        .values()
        .map(|a| {
            let version = ospf.instances.get(&a.instance).map(|i| i.version.number());
            json!({
                "name": a.name,
                "instance": a.instance,
                "version": version,
                "area_id": a.area_id.to_string(),
                "type": a.kind.name(),
                "no_summaries": a.no_summaries,
                "default_cost": a.default_cost,
                "nssa_translate": a.nssa_translate.name(),
                "backbone": a.area_id.is_backbone(),
                "interfaces": binds.iter().filter(|b| b.area.name == a.name).map(|b| b.interface.to_string()).collect::<Vec<_>>(),
                "ranges": ospf.ranges.iter().filter(|r| r.area == a.name).count(),
                "disabled": a.disabled,
                "comment": a.comment,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

// ---- ranges ----

fn apply_range(routing: &mut Routing, p: &Value, id: Option<ItemId>) -> Result<ItemId> {
    let ospf = &mut routing.ospf;
    let mut r = match id {
        Some(id) => ospf
            .ranges
            .iter()
            .find(|r| r.id == id)
            .cloned()
            .ok_or_else(|| EngineError::bad("id", format!("no OSPF area range {id}")))?,
        None => OspfAreaRange {
            id: ItemId(0),
            area: String::new(),
            prefix: IpNet::default(),
            advertise: true,
            cost: None,
            disabled: false,
            comment: String::new(),
        },
    };
    match given(p, "area") {
        Given::Value(v) => {
            let n = text("area", v)?;
            if !ospf.areas.contains_key(n) {
                return Err(EngineError::bad("area", format!("no OSPF area {:?}", cut(n))));
            }
            r.area = n.to_owned();
        }
        _ if id.is_none() => return Err(EngineError::bad("area", "is required")),
        _ => {}
    }
    match given(p, "prefix") {
        Given::Value(v) => {
            let t = text("prefix", v)?;
            r.prefix = t
                .parse()
                .map_err(|_| EngineError::bad("prefix", format!("{:?} is not a prefix (10.0.0.0/16)", cut(t))))?;
        }
        _ if id.is_none() => return Err(EngineError::bad("prefix", "is required")),
        _ => {}
    }
    if let Some(b) = opt_boolean(p, "advertise")? {
        r.advertise = b;
    }
    opt_number(p, "cost", 0, u64::from(corerouter_proto_ospf::MAX_METRIC), &mut r.cost)?;
    comment_and_disabled(p, &mut r.comment, &mut r.disabled)?;
    match id {
        Some(id) => {
            if let Some(slot) = ospf.ranges.iter_mut().find(|x| x.id == id) {
                *slot = r;
            }
            Ok(id)
        }
        None => {
            if ospf.ranges.len() >= MAX_RANGES {
                return Err(EngineError::bad("prefix", format!("at most {MAX_RANGES} ranges")));
            }
            r.id = ospf.next_id();
            let new = r.id;
            ospf.ranges.push(r);
            Ok(new)
        }
    }
}

fn range_add(s: &mut Session, p: &Value) -> Result<Value> {
    let id = apply_range(&mut s.store_mut().candidate_mut().routing, p, None)?;
    Ok(json!({ "id": id.to_string() }))
}

fn range_set(s: &mut Session, p: &Value) -> Result<Value> {
    let id = parse_id("id", req_str(p, "id")?)?;
    let id = apply_range(&mut s.store_mut().candidate_mut().routing, p, Some(id))?;
    Ok(json!({ "id": id.to_string() }))
}

fn range_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id = parse_id("id", req_str(p, "id")?)?;
    let ospf = &mut s.store_mut().candidate_mut().routing.ospf;
    let before = ospf.ranges.len();
    ospf.ranges.retain(|r| r.id != id);
    if ospf.ranges.len() == before {
        return Err(EngineError::bad("id", format!("no OSPF area range {id}")));
    }
    Ok(json!({ "id": id.to_string() }))
}

fn range_list(s: &mut Session, _: &Value) -> Result<Value> {
    let ospf = &s.store().candidate().routing.ospf;
    let rows = ospf
        .ranges
        .iter()
        .map(|r| {
            json!({
                "id": r.id.to_string(),
                "area": r.area,
                "instance": ospf.areas.get(&r.area).map(|a| a.instance.clone()),
                "prefix": r.prefix.to_string(),
                "advertise": r.advertise,
                "cost": r.cost,
                "disabled": r.disabled,
                "comment": r.comment,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

// ---- static neighbors ----

fn neighbor_add(s: &mut Session, p: &Value) -> Result<Value> {
    let ospf = &mut s.store_mut().candidate_mut().routing.ospf;
    let instance = req_str(p, "instance")?.trim().to_owned();
    if !ospf.instances.contains_key(&instance) {
        return Err(EngineError::bad("instance", format!("no OSPF instance {:?}", cut(&instance))));
    }
    let address: Ipv4Addr = req_str(p, "address")?
        .trim()
        .parse()
        .map_err(|_| EngineError::bad("address", "an IPv4 address"))?;
    let mut n = OspfStaticNeighbor {
        id: ItemId(0),
        instance,
        address,
        poll_interval: None,
        disabled: false,
        comment: String::new(),
    };
    opt_number(p, "poll_interval", 1, 65_535, &mut n.poll_interval)?;
    comment_and_disabled(p, &mut n.comment, &mut n.disabled)?;
    if ospf.static_neighbors.len() >= MAX_NEIGHBORS {
        return Err(EngineError::bad("address", format!("at most {MAX_NEIGHBORS} static neighbors")));
    }
    n.id = ospf.next_id();
    let id = n.id;
    ospf.static_neighbors.push(n);
    Ok(json!({ "id": id.to_string() }))
}

fn neighbor_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id = parse_id("id", req_str(p, "id")?)?;
    let ospf = &mut s.store_mut().candidate_mut().routing.ospf;
    let before = ospf.static_neighbors.len();
    ospf.static_neighbors.retain(|n| n.id != id);
    if ospf.static_neighbors.len() == before {
        return Err(EngineError::bad("id", format!("no OSPF static neighbor {id}")));
    }
    Ok(json!({ "id": id.to_string() }))
}

fn neighbor_list(s: &mut Session, _: &Value) -> Result<Value> {
    let ospf = &s.store().candidate().routing.ospf;
    Ok(Value::Array(
        ospf.static_neighbors
            .iter()
            .map(|n| {
                json!({
                    "id": n.id.to_string(),
                    "instance": n.instance,
                    "address": n.address.to_string(),
                    "poll_interval": n.poll_interval,
                    "disabled": n.disabled,
                    "comment": n.comment,
                })
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use corerouter_hal::VirtualHal;
    use serde_json::json;

    use crate::Session;

    pub(crate) fn lab() -> Session {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        s.execute("routing.ospf.instance.add", &json!({"name": "v2", "router_id": "10.255.0.1", "redistribute": "connected"}))
            .unwrap();
        s.execute("routing.ospf.area.add", &json!({"name": "backbone", "instance": "v2", "area_id": "0.0.0.0"}))
            .unwrap();
        s
    }

    #[test]
    fn instance_and_area_round_trip() {
        let mut s = lab();
        s.execute("routing.ospf.area.add", &json!({"name": "edge", "instance": "v2", "area_id": 1, "type": "stub", "no_summaries": "yes"}))
            .unwrap();
        let areas = s.execute("routing.ospf.area.list", &json!({})).unwrap();
        let edge = areas.as_array().unwrap().iter().find(|a| a["name"] == "edge").unwrap();
        assert_eq!(edge["area_id"], "0.0.0.1");
        assert_eq!(edge["type"], "stub");
        assert_eq!(edge["no_summaries"], true);
        // Rename the instance: its areas follow.
        s.execute("routing.ospf.instance.set", &json!({"id": "v2", "name": "core"})).unwrap();
        let areas = s.execute("routing.ospf.area.list", &json!({})).unwrap();
        assert!(areas.as_array().unwrap().iter().all(|a| a["instance"] == "core"));
    }

    #[test]
    fn validation_errors() {
        let mut s = lab();
        let e = s.execute("routing.ospf.instance.add", &json!({"name": "bad name"})).unwrap_err();
        assert!(e.to_string().contains("[A-Za-z0-9_.-]"), "{e}");
        let e = s.execute("routing.ospf.area.add", &json!({"name": "x", "instance": "nope", "area_id": "1"})).unwrap_err();
        assert!(e.to_string().contains("no OSPF instance"), "{e}");
        let e = s.execute("routing.ospf.area.add", &json!({"name": "x", "instance": "v2", "area_id": "a.b"})).unwrap_err();
        assert!(e.to_string().contains("area id"), "{e}");
        // The backbone as a stub area is refused (immediate mode commits).
        let e = s.execute("routing.ospf.area.set", &json!({"id": "backbone", "type": "stub"})).unwrap_err();
        assert!(e.to_string().contains("RFC 2328 §3.6"), "{e}");
        // An instance with areas is not removed.
        let e = s.execute("routing.ospf.instance.remove", &json!({"id": "v2"})).unwrap_err();
        assert!(e.to_string().contains("has areas"), "{e}");
    }

    #[test]
    fn ranges_and_rollback() {
        let mut s = lab();
        let r = s.execute("routing.ospf.area.range.add", &json!({"area": "backbone", "prefix": "10.0.0.0/16", "cost": "20"})).unwrap();
        let id = r["id"].as_str().unwrap().to_owned();
        s.execute("routing.ospf.area.range.set", &json!({"id": id, "advertise": false})).unwrap();
        let l = s.execute("routing.ospf.area.range.list", &json!({})).unwrap();
        assert_eq!(l[0]["advertise"], false);
        assert_eq!(l[0]["cost"], 20);
        s.execute("routing.ospf.area.range.remove", &json!({"id": id})).unwrap();
        assert!(s.execute("routing.ospf.area.range.remove", &json!({"id": id})).is_err());
    }
}
