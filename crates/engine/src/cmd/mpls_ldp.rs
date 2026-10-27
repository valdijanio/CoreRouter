//! /mpls ldp (G3.5), RouterOS v7 names, run by FRR's `ldpd`: the instance
//! (one: `ldpd` runs in the main table only), `interface` and `neighbor`.
//! The lists join the config with what the routing service read (state of
//! each session and interface, LDP-IGP sync, the MTU check).
//!
//! Additions to RouterOS, on by default: LDP-IGP synchronization (RFC
//! 5443) and GTSM (RFC 6720); per-neighbor TCP MD5 (RFC 5036 §2.9), sealed
//! like a BGP key.

use std::net::{IpAddr, Ipv4Addr};

use corerouter_model::mpls::{
    Afi, LdpInstance, LdpInterface, LdpNeighbor, MAX_LDP_INTERFACES, MAX_LDP_NEIGHBORS, Mpls,
};
use corerouter_model::sealed::Sealed;
use corerouter_model::{Config, IfName};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text, opt_u32, req_str};
use super::mpls::{mpls_supported, normalize, preview_on};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("mpls.ldp.add", "Add LDP Instance", ["MPLS", "LDP"], None,
        "{lsr_id: ipv4 (the loopback address), afi?: [string] | string (ip, ipv6; default ip), transport_addresses?: [ip] | string (one per family; IPv4 default: lsr_id), preferred_afi?: string (ip | ipv6; RFC 7552 default ipv6), use_explicit_null?: bool, igp_sync?: bool (RFC 5443, default yes), igp_sync_holddown?: u32 (s, 1..=10000; unset: wait for LDP), gtsm?: bool (RFC 6720, default yes), disabled?: bool, comment?: string} → {lsr_id}",
        no_instance, add),
    cmd!("mpls.ldp.set", "Set LDP Instance", [], None,
        "{lsr_id?: ipv4, afi?: [string] | string, transport_addresses?: [ip] | string, preferred_afi?: string | null, use_explicit_null?: bool, igp_sync?: bool, igp_sync_holddown?: u32 | null, gtsm?: bool, disabled?: bool, comment?: string} → {lsr_id}",
        has_instance, set),
    cmd!("mpls.ldp.remove", "Remove LDP Instance", [], None,
        "{} → {lsr_id} (the LDP interfaces and neighbors stay, unused)",
        has_instance, remove),
    cmd!(query "mpls.ldp.list", "LDP Instances", ["MPLS", "LDP"], None,
        "{} → [{lsr_id, afi, transport_addresses, transport_ipv4?, transport_ipv6?, preferred_afi?, use_explicit_null, igp_sync, igp_sync_holddown?, gtsm, disabled, comment, state (running | disabled | no daemon | error), neighbors, operational, error?}]",
        always, list),
    cmd!("mpls.ldp.interface.add", "Add LDP Interface", ["MPLS", "LDP", "Interface"], None,
        "{interface: string, hello_interval?: u32 (s, default 5), hold_time?: u32 (s, default 15; RFC 5036 §3.5.2), afi?: [string] | string (default: the instance's), disabled?: bool, comment?: string} → {interface}",
        mpls_supported, interface_add),
    cmd!("mpls.ldp.interface.set", "Set LDP Interface", [], None,
        "{id: string (the interface), hello_interval?: u32, hold_time?: u32, afi?: [string] | string, disabled?: bool, comment?: string} → {interface}",
        always, interface_set),
    cmd!("mpls.ldp.interface.remove", "Remove LDP Interface", [], None,
        "{id: string (the interface)} → {interface}",
        always, interface_remove),
    cmd!(query "mpls.ldp.interface.list", "LDP Interfaces", ["MPLS", "LDP", "Interface"], None,
        "{} → [{interface, hello_interval, hold_time, afi, disabled, comment, state (active | down | disabled | no daemon | unknown), adjacencies, igp_sync? (achieved | waiting), mtu, mtu_warning?}]",
        always, interface_list),
    cmd!(query "mpls.ldp.interface.preview", "Check LDP Interface", [], None,
        "{id?: string (the interface being edited), interface?: string, hello_interval?: u32 | string, hold_time?: u32 | string, afi?: string, disabled?: bool | yes | no, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}]} (form texts accepted; never an error: bad input is a check)",
        always, interface_preview),
    cmd!("mpls.ldp.neighbor.add", "Add LDP Neighbor", ["MPLS", "LDP", "Neighbor"], None,
        "{lsr_id: ipv4, targeted?: ip (send targeted Hellos there: a session to a router that is not adjacent), password?: string (TCP MD5, sealed at once), keepalive_hold?: u32 (s, 15..=65535), disabled?: bool, comment?: string} → {lsr_id}",
        mpls_supported, neighbor_add),
    cmd!("mpls.ldp.neighbor.set", "Set LDP Neighbor", [], None,
        "{id: ipv4 (the LSR id), targeted?: ip | null, password?: string (empty: none), keepalive_hold?: u32 | null, disabled?: bool, comment?: string} → {lsr_id}",
        always, neighbor_set),
    cmd!("mpls.ldp.neighbor.remove", "Remove LDP Neighbor", [], None,
        "{id: ipv4 (the LSR id)} → {lsr_id}",
        always, neighbor_remove),
    cmd!(query "mpls.ldp.neighbor.preview", "Check LDP Neighbor", [], None,
        "{id?: string (the LSR id being edited), lsr_id?: string, targeted?: string, password?: string, keepalive_hold?: u32 | string, disabled?: bool | yes | no, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}]} (form texts accepted; never an error: bad input is a check)",
        always, neighbor_preview),
    cmd!(query "mpls.ldp.neighbor.list", "LDP Neighbors", ["MPLS", "LDP", "Neighbor"], None,
        "{} → [{lsr_id, dynamic (discovered, not configured), state, operational, afi?, transport?, uptime?, targeted?, password (set or not), keepalive_hold?, labels (FECs it sent a label for), in_use (of them, used), disabled, comment}]",
        always, neighbor_list),
];

fn no_instance(s: &Session) -> std::result::Result<(), String> {
    mpls_supported(s)?;
    if s.store().candidate().routing.mpls.ldp.is_some() {
        Err("LDP already has its instance (FRR's ldpd runs one, in the main table): mpls.ldp.set".into())
    } else {
        Ok(())
    }
}

fn has_instance(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.mpls.ldp.is_none() {
        Err("there is no LDP instance (mpls.ldp.add)".into())
    } else {
        Ok(())
    }
}

fn afis(p: &Value, key: &str) -> Result<Option<Vec<Afi>>> {
    let raw: Vec<String> = match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_owned()).filter(|x| !x.is_empty()).collect(),
        Some(Value::Array(a)) => a.iter().map(|v| v.as_str().unwrap_or("?").to_owned()).collect(),
        Some(_) => return Err(EngineError::bad(key, "ip, ipv6 or both")),
    };
    let mut out = Vec::new();
    for r in raw.iter().take(4) {
        let a = Afi::parse(r).ok_or_else(|| EngineError::bad(key, format!("'{}' is not ip or ipv6", r.chars().take(16).collect::<String>())))?;
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out.sort();
    Ok(Some(out))
}

fn ip_of(p: &Value, key: &str) -> Result<Option<IpAddr>> {
    opt_str(p, key)?
        .map(|t| t.trim().parse::<IpAddr>().map_err(|_| EngineError::bad(key, "an IPv4 or IPv6 address")))
        .transpose()
}

fn v4_of(p: &Value, key: &str) -> Result<Option<Ipv4Addr>> {
    opt_str(p, key)?
        .map(|t| t.trim().parse::<Ipv4Addr>().map_err(|_| EngineError::bad(key, "an IPv4 address (the LSR id)")))
        .transpose()
}

fn addresses(p: &Value, key: &str) -> Result<Option<Vec<IpAddr>>> {
    let raw: Vec<String> = match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_owned()).filter(|x| !x.is_empty()).collect(),
        Some(Value::Array(a)) => a.iter().map(|v| v.as_str().unwrap_or("?").to_owned()).collect(),
        Some(_) => return Err(EngineError::bad(key, "a list of addresses")),
    };
    if raw.len() > 2 {
        return Err(EngineError::bad(key, "one address per family (RFC 5036 §2.5.2)"));
    }
    raw.iter()
        .map(|r| r.parse::<IpAddr>().map_err(|_| EngineError::bad(key, format!("'{}' is not an address", r.chars().take(40).collect::<String>()))))
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn holddown(p: &Value) -> Result<Option<Option<u16>>> {
    match p.get("igp_sync_holddown") {
        None => Ok(None),
        Some(Value::Null) => Ok(Some(None)),
        Some(_) => {
            let v = opt_u32(p, "igp_sync_holddown")?.unwrap_or(0);
            if !(1..=10_000).contains(&v) {
                return Err(EngineError::bad("igp_sync_holddown", "1..=10000 s (FRR), or null to wait for LDP as long as it takes"));
            }
            Ok(Some(u16::try_from(v).ok()))
        }
    }
}

/// The instance fields of `p` onto `l`.
fn apply(l: &mut LdpInstance, p: &Value) -> Result<()> {
    if let Some(v) = v4_of(p, "lsr_id")? {
        l.lsr_id = v;
    }
    if let Some(v) = afis(p, "afi")? {
        if v.is_empty() {
            return Err(EngineError::bad("afi", "at least one of ip, ipv6"));
        }
        l.afi = v;
    }
    if let Some(v) = addresses(p, "transport_addresses")? {
        if v.iter().filter(|a| a.is_ipv4()).count() > 1 || v.iter().filter(|a| a.is_ipv6()).count() > 1 {
            return Err(EngineError::bad("transport_addresses", "one address per family (RFC 5036 §2.5.2)"));
        }
        l.transport_addresses = v;
    }
    match p.get("preferred_afi") {
        Some(Value::Null) => l.preferred_afi = None,
        Some(_) => {
            let t = req_str(p, "preferred_afi")?;
            l.preferred_afi = Some(Afi::parse(t).ok_or_else(|| EngineError::bad("preferred_afi", "ip or ipv6"))?);
        }
        None => {}
    }
    if let Some(v) = opt_bool(p, "use_explicit_null")? {
        l.use_explicit_null = v;
    }
    if let Some(v) = opt_bool(p, "igp_sync")? {
        l.igp_sync = v;
    }
    if let Some(v) = holddown(p)? {
        l.igp_sync_holddown = v;
    }
    if let Some(v) = opt_bool(p, "gtsm")? {
        l.gtsm = v;
    }
    if let Some(v) = opt_bool(p, "disabled")? {
        l.disabled = v;
    }
    if let Some(v) = opt_text(p, "comment", 256)? {
        l.comment = v;
    }
    Ok(())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let id = v4_of(p, "lsr_id")?.ok_or_else(|| EngineError::bad("lsr_id", "is required"))?;
    let mut l = LdpInstance::new(id);
    apply(&mut l, p)?;
    let m = &mut s.store_mut().candidate_mut().routing.mpls;
    if m.ldp.is_some() {
        return Err(EngineError::bad("lsr_id", "LDP already has its instance: mpls.ldp.set"));
    }
    m.ldp = Some(l);
    Ok(json!({ "lsr_id": id }))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let m = &mut s.store_mut().candidate_mut().routing.mpls;
    let l = m.ldp.as_mut().ok_or_else(|| EngineError::bad("lsr_id", "there is no LDP instance (mpls.ldp.add)"))?;
    apply(l, p)?;
    Ok(json!({ "lsr_id": l.lsr_id }))
}

fn remove(s: &mut Session, _: &Value) -> Result<Value> {
    let m = &mut s.store_mut().candidate_mut().routing.mpls;
    let l = m.ldp.take().ok_or_else(|| EngineError::bad("lsr_id", "there is no LDP instance"))?;
    Ok(json!({ "lsr_id": l.lsr_id }))
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    let st = crate::mpls::ldp(s);
    let Some(l) = s.store().candidate().routing.mpls.ldp.clone() else {
        return Ok(json!([]));
    };
    let nbrs = st.state.as_ref().map_or(0, |x| x.neighbors.len());
    let up = st.state.as_ref().map_or(0, |x| x.neighbors.iter().filter(|n| n.operational()).count());
    let state = if l.disabled {
        "disabled"
    } else if st.error.is_some() {
        "error"
    } else if st.state.is_some() {
        "running"
    } else {
        "no daemon"
    };
    let mut v = serde_json::to_value(&l).unwrap_or_else(|_| json!({}));
    if let Some(o) = v.as_object_mut() {
        o.insert("afi".into(), json!(l.afi.iter().map(|a| a.name()).collect::<Vec<_>>()));
        o.insert("transport_ipv4".into(), json!(l.transport(Afi::Ip)));
        o.insert("transport_ipv6".into(), json!(l.transport(Afi::Ipv6)));
        o.insert("state".into(), json!(state));
        o.insert("neighbors".into(), json!(nbrs));
        o.insert("operational".into(), json!(up));
        o.insert("error".into(), json!(st.error));
    }
    Ok(json!([v]))
}

// ---- interfaces ----

fn timer(p: &Value, key: &str) -> Result<Option<u16>> {
    opt_u32(p, key)?
        .map(|v| u16::try_from(v).ok().filter(|v| *v >= 1).ok_or_else(|| EngineError::bad(key, "1..=65535 s")))
        .transpose()
}

fn apply_if(i: &mut LdpInterface, p: &Value) -> Result<()> {
    if let Some(v) = timer(p, "hello_interval")? {
        i.hello_interval = v;
    }
    if let Some(v) = timer(p, "hold_time")? {
        i.hold_time = v;
    }
    if i.hello_interval >= i.hold_time {
        return Err(EngineError::bad(
            "hold_time",
            format!("{} must be over hello_interval {} (RFC 5036 §3.5.2.1: three Hellos per hold time)", i.hold_time, i.hello_interval),
        ));
    }
    if let Some(v) = afis(p, "afi")? {
        i.afi = v;
    }
    if let Some(v) = opt_bool(p, "disabled")? {
        i.disabled = v;
    }
    if let Some(v) = opt_text(p, "comment", 256)? {
        i.comment = v;
    }
    Ok(())
}

fn if_name(cfg: &Config, p: &Value, key: &str) -> Result<IfName> {
    let n: IfName = req_str(p, key)?
        .parse()
        .map_err(|e: corerouter_model::ParseError| EngineError::bad(key, e.to_string()))?;
    if !cfg.interfaces.contains_key(&n) {
        return Err(EngineError::bad(key, format!("no interface '{n}' (see interface.list)")));
    }
    Ok(n)
}

fn interface_add(s: &mut Session, p: &Value) -> Result<Value> {
    interface_add_cfg(s.store_mut().candidate_mut(), p)
}

fn interface_add_cfg(cfg: &mut Config, p: &Value) -> Result<Value> {
    let name = if_name(cfg, p, "interface")?;
    let m = &mut cfg.routing.mpls;
    if m.ldp_interfaces.contains_key(&name) {
        return Err(EngineError::bad("interface", format!("LDP already runs on '{name}' (mpls.ldp.interface.set)")));
    }
    if m.ldp_interfaces.len() >= MAX_LDP_INTERFACES {
        return Err(EngineError::bad("interface", format!("at most {MAX_LDP_INTERFACES} LDP interfaces")));
    }
    let mut i = LdpInterface::default();
    apply_if(&mut i, p)?;
    m.ldp_interfaces.insert(name.clone(), i);
    Ok(json!({ "interface": name }))
}

fn existing_ldp_if(m: &mut Mpls, p: &Value) -> Result<IfName> {
    let n: IfName = req_str(p, "id")?
        .parse()
        .map_err(|e: corerouter_model::ParseError| EngineError::bad("id", e.to_string()))?;
    if !m.ldp_interfaces.contains_key(&n) {
        return Err(EngineError::bad("id", format!("LDP does not run on '{n}' (see mpls.ldp.interface.list)")));
    }
    Ok(n)
}

fn interface_set(s: &mut Session, p: &Value) -> Result<Value> {
    interface_set_cfg(s.store_mut().candidate_mut(), p)
}

fn interface_set_cfg(cfg: &mut Config, p: &Value) -> Result<Value> {
    let m = &mut cfg.routing.mpls;
    let n = existing_ldp_if(m, p)?;
    if let Some(i) = m.ldp_interfaces.get_mut(&n) {
        apply_if(i, p)?;
    }
    Ok(json!({ "interface": n }))
}

fn interface_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let m = &mut s.store_mut().candidate_mut().routing.mpls;
    let n = existing_ldp_if(m, p)?;
    m.ldp_interfaces.remove(&n);
    Ok(json!({ "interface": n }))
}

fn interface_list(s: &mut Session, _: &Value) -> Result<Value> {
    let st = crate::mpls::ldp(s);
    let cfg = s.store().candidate();
    let m = &cfg.routing.mpls;
    let payload = m.settings.payload_mtu;
    Ok(Value::Array(
        m.ldp_interfaces
            .iter()
            .map(|(n, i)| {
                let live: Vec<_> = st.state.iter().flat_map(|x| x.interfaces.iter()).filter(|x| x.name == n.as_str()).collect();
                let state = if i.disabled || m.ldp_running().is_none() {
                    "disabled".to_owned()
                } else if st.state.is_none() {
                    "no daemon".to_owned()
                } else if live.iter().any(|x| x.state.eq_ignore_ascii_case("active")) {
                    "active".to_owned()
                } else if live.is_empty() {
                    "unknown".to_owned()
                } else {
                    "down".to_owned()
                };
                let sync = st
                    .state
                    .iter()
                    .flat_map(|x| x.igp_sync.iter())
                    .find(|x| x.interface == n.as_str())
                    .map(|x| if x.achieved { "achieved" } else { "waiting" });
                let mtu = cfg.interfaces.get(n).map_or(0, |x| u32::from(x.mtu));
                json!({
                    "interface": n,
                    "hello_interval": i.hello_interval,
                    "hold_time": i.hold_time,
                    "afi": i.afi.iter().map(|a| a.name()).collect::<Vec<_>>(),
                    "disabled": i.disabled,
                    "comment": i.comment,
                    "state": state,
                    "adjacencies": live.iter().map(|x| x.adjacencies).sum::<u32>(),
                    "igp_sync": sync,
                    "mtu": mtu,
                    // One label: what plain LDP pushes (RFC 3032 §3).
                    "mtu_warning": corerouter_proto_mpls::mtu_warning(payload, 1, mtu),
                })
            })
            .collect(),
    ))
}

// ---- neighbors ----

fn password(s: &mut Session, p: &Value) -> Result<Option<Option<Sealed>>> {
    let Some(k) = opt_str(p, "password")? else {
        return Ok(None);
    };
    if k.is_empty() {
        return Ok(Some(None));
    }
    if k.len() > 80 || !k.bytes().all(|b| b.is_ascii_graphic()) {
        // Never echo the key back.
        return Err(EngineError::bad("password", "1..=80 printable characters without spaces (RFC 2385)"));
    }
    let key = crate::sealing::key(s).map_err(EngineError::Internal)?;
    key.seal(k).map(|x| Some(Some(x))).map_err(EngineError::Internal)
}

fn hold(p: &Value) -> Result<Option<Option<u16>>> {
    match p.get("keepalive_hold") {
        None => Ok(None),
        Some(Value::Null) => Ok(Some(None)),
        Some(_) => {
            let v = opt_u32(p, "keepalive_hold")?.unwrap_or(0);
            if !(15..=65_535).contains(&v) {
                return Err(EngineError::bad("keepalive_hold", "15..=65535 s (FRR's range)"));
            }
            Ok(Some(u16::try_from(v).ok()))
        }
    }
}

fn apply_nbr(n: &mut LdpNeighbor, p: &Value, pw: Option<Option<Sealed>>) -> Result<()> {
    match p.get("targeted") {
        Some(Value::Null) => n.targeted = None,
        Some(_) => n.targeted = ip_of(p, "targeted")?,
        None => {}
    }
    if let Some(v) = pw {
        n.password = v;
    }
    if let Some(v) = hold(p)? {
        n.keepalive_hold = v;
    }
    if let Some(v) = opt_bool(p, "disabled")? {
        n.disabled = v;
    }
    if let Some(v) = opt_text(p, "comment", 256)? {
        n.comment = v;
    }
    Ok(())
}

fn neighbor_add(s: &mut Session, p: &Value) -> Result<Value> {
    let pw = password(s, p)?;
    neighbor_add_cfg(s.store_mut().candidate_mut(), p, pw)
}

fn neighbor_add_cfg(cfg: &mut Config, p: &Value, pw: Option<Option<Sealed>>) -> Result<Value> {
    let id = v4_of(p, "lsr_id")?.ok_or_else(|| EngineError::bad("lsr_id", "is required"))?;
    let m = &mut cfg.routing.mpls;
    if m.ldp_neighbors.contains_key(&id) {
        return Err(EngineError::bad("lsr_id", format!("{id} is already configured (mpls.ldp.neighbor.set)")));
    }
    if m.ldp_neighbors.len() >= MAX_LDP_NEIGHBORS {
        return Err(EngineError::bad("lsr_id", format!("at most {MAX_LDP_NEIGHBORS} configured neighbors")));
    }
    let mut n = LdpNeighbor { targeted: None, password: None, keepalive_hold: None, disabled: false, comment: String::new() };
    apply_nbr(&mut n, p, pw)?;
    m.ldp_neighbors.insert(id, n);
    Ok(json!({ "lsr_id": id }))
}

fn nbr_id(m: &Mpls, p: &Value) -> Result<Ipv4Addr> {
    let id: Ipv4Addr = req_str(p, "id")?
        .trim()
        .parse()
        .map_err(|_| EngineError::bad("id", "the neighbor's LSR id (an IPv4 address)"))?;
    if !m.ldp_neighbors.contains_key(&id) {
        return Err(EngineError::bad("id", format!("{id} is not configured (see mpls.ldp.neighbor.list; discovered ones are added with mpls.ldp.neighbor.add)")));
    }
    Ok(id)
}

fn neighbor_set(s: &mut Session, p: &Value) -> Result<Value> {
    nbr_id(&s.store().candidate().routing.mpls, p)?;
    let pw = password(s, p)?;
    neighbor_set_cfg(s.store_mut().candidate_mut(), p, pw)
}

fn neighbor_set_cfg(cfg: &mut Config, p: &Value, pw: Option<Option<Sealed>>) -> Result<Value> {
    let id = nbr_id(&cfg.routing.mpls, p)?;
    let m = &mut cfg.routing.mpls;
    if let Some(n) = m.ldp_neighbors.get_mut(&id) {
        apply_nbr(n, p, pw)?;
    }
    Ok(json!({ "lsr_id": id }))
}

fn neighbor_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let m = &mut s.store_mut().candidate_mut().routing.mpls;
    let id = nbr_id(m, p)?;
    m.ldp_neighbors.remove(&id);
    Ok(json!({ "lsr_id": id }))
}

fn neighbor_list(s: &mut Session, _: &Value) -> Result<Value> {
    let st = crate::mpls::ldp(s);
    let m = &s.store().candidate().routing.mpls;
    let live = st.state.as_ref().map(|x| x.neighbors.as_slice()).unwrap_or(&[]);
    let bindings = st.state.as_ref().map(|x| x.bindings.as_slice()).unwrap_or(&[]);
    let mut ids: Vec<Ipv4Addr> = m.ldp_neighbors.keys().copied().chain(live.iter().map(|n| n.lsr_id)).collect();
    ids.sort();
    ids.dedup();
    Ok(Value::Array(
        ids.into_iter()
            .map(|id| {
                let conf = m.ldp_neighbors.get(&id);
                let l = live.iter().find(|n| n.lsr_id == id);
                let labels = bindings.iter().filter(|b| b.remote.iter().any(|r| r.neighbor == id)).count();
                let in_use = bindings.iter().filter(|b| b.remote.iter().any(|r| r.neighbor == id && r.in_use)).count();
                let state = match (conf, l) {
                    (Some(c), _) if c.disabled => "disabled".to_owned(),
                    (_, Some(l)) => l.state.to_ascii_lowercase(),
                    _ if st.state.is_none() => "no daemon".to_owned(),
                    _ => "not found".to_owned(),
                };
                json!({
                    "lsr_id": id,
                    "dynamic": conf.is_none(),
                    "state": state,
                    "operational": l.is_some_and(|l| l.operational()),
                    "afi": l.map(|l| l.afi.clone()),
                    "transport": l.and_then(|l| l.transport),
                    "uptime": l.and_then(|l| l.uptime.clone()),
                    "targeted": conf.and_then(|c| c.targeted),
                    "password": conf.is_some_and(|c| c.password.as_ref().is_some_and(|k| !k.is_empty())),
                    "keepalive_hold": conf.and_then(|c| c.keepalive_hold),
                    "labels": labels,
                    "in_use": in_use,
                    "disabled": conf.is_some_and(|c| c.disabled),
                    "comment": conf.map(|c| c.comment.clone()).unwrap_or_default(),
                })
            })
            .collect(),
    ))
}

// ---- previews (the list modals) ----

fn interface_preview(s: &mut Session, raw: &Value) -> Result<Value> {
    let p = normalize(raw, &["hello_interval", "hold_time"], &[]);
    let editing = raw.get("id").is_some_and(|v| !v.is_null());
    let mut out = if editing {
        let mut p = p;
        if let Some(o) = p.as_object_mut() {
            o.remove("interface");
        }
        preview_on(s, p, "mpls.ldp.interface.set", &interface_set_cfg)
    } else {
        preview_on(s, p, "mpls.ldp.interface.add", &interface_add_cfg)
    };
    // RFC 3032 §3: one label more on every packet out of it.
    let cfg = s.store().candidate();
    let name = raw.get("id").or_else(|| raw.get("interface")).and_then(Value::as_str).and_then(|n| n.parse::<IfName>().ok());
    if let Some(i) = name.as_ref().and_then(|n| cfg.interfaces.get(n)) {
        let payload = cfg.routing.mpls.settings.payload_mtu;
        let mtu = u32::from(i.mtu);
        let (level, message) = match corerouter_proto_mpls::mtu_warning(payload, 1, mtu) {
            Some(w) => ("warning", w),
            None => ("ok", format!("MTU {mtu} carries a {payload}-byte IP packet with one label")),
        };
        if let Some(c) = out.get_mut("checks").and_then(Value::as_array_mut) {
            c.push(json!({"level": level, "check": "mtu", "message": message, "param": "interface"}));
        }
    }
    Ok(out)
}

fn neighbor_preview(s: &mut Session, raw: &Value) -> Result<Value> {
    let p = normalize(raw, &["keepalive_hold"], &["targeted"]);
    let editing = raw.get("id").is_some_and(|v| !v.is_null());
    let has_pw = p.get("password").and_then(Value::as_str).is_some_and(|k| !k.is_empty());
    // A stand-in: the preview never seals (nor shows) the key.
    let pw = has_pw.then(|| Some(Sealed::from_box(format!("{}preview", corerouter_model::sealed::PREFIX))));
    if let Some(k) = p.get("password").and_then(Value::as_str)
        && (k.len() > 80 || !k.bytes().all(|b| b.is_ascii_graphic()))
        && !k.is_empty()
    {
        return Ok(json!({"computed": [], "commands": [], "checks": [{"level": "error", "check": "param", "param": "password", "message": "1..=80 printable characters without spaces (RFC 2385)"}]}));
    }
    Ok(if editing {
        let mut p = p;
        if let Some(o) = p.as_object_mut() {
            o.remove("lsr_id");
        }
        preview_on(s, p, "mpls.ldp.neighbor.set", &|c, p| neighbor_set_cfg(c, p, pw.clone()))
    } else {
        preview_on(s, p, "mpls.ldp.neighbor.add", &|c, p| neighbor_add_cfg(c, p, pw.clone()))
    })
}
