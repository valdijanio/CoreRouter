//! /routing bgp template, /routing bgp connection (G3.2a): the BGP
//! neighbors in the RouterOS v7 model, and the actions on a live session
//! (`clear`, `refresh`, `resend`). `proto-bgp` validates and renders them;
//! the commit takes them to FRR (`hal-frr`), changing only what changed.
//!
//! A parameter left out of `add` is unset (inherited from the templates,
//! then the default); in `set` a parameter given as `null` is unset again.
//! The TCP MD5 key arrives in clear and is sealed at once (`sealing`): the
//! config, its history, the journal and every answer hold the box or
//! `***`, never the key.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use corerouter_hal::routing::BgpClear;
use corerouter_model::bgp::{
    Afi, BgpConnection, BgpParams, BgpTemplate, LocalRole, MAX_TEMPLATES_LISTED, MaxPrefixAction,
    NexthopChoice, ResolveError, resolve_templates,
};
use corerouter_model::routing_state::BgpSession;
use corerouter_model::sealed::Sealed;
use corerouter_model::{Asn, Config, Routing};
use serde_json::{Map, Value, json};

use super::args::{opt_bool, opt_str, opt_text, req_str};
use super::dhcp_client::opt_list;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

/// Most connections and templates (a large IXP route server has ~2 000
/// neighbors, **estimado**).
pub const MAX_CONNECTIONS: usize = 10_000;
pub const MAX_TEMPLATES: usize = 1_000;


pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("routing.bgp.template.add", "Add BGP Template", ["Routing", "BGP"], None,
        "{name: string, templates?: [string] | string (parents, first wins), comment?: string, remote_as?: u32 | asdot string | null, local_role?: string | null, multihop?: bool | null, hold_time?: u16 | null, keepalive_time?: u16 | null, tcp_md5_key?: string | null, afi?: [string] | string | null, max_prefix_ipv4?: u32 | null, max_prefix_ipv6?: u32 | null, max_prefix_action?: string | null, max_prefix_restart?: u16 | null, update_source?: string | null, nexthop_choice?: string | null, input_filter?: string | null (the /routing filter chain of received routes), output_filter?: string | null (of sent routes), keep_received?: bool | null (keep received routes before the input chain; default yes), bfd?: string | null (a BFD profile, routing.bfd.profile: the session goes down with BFD)} → {name}",
        always, template_add),
    cmd!("routing.bgp.template.set", "Set BGP Template", [], None,
        "{id: string (the name), name?: string, templates?: [string] | string, comment?: string, remote_as?: u32 | asdot string | null, local_role?: string | null, multihop?: bool | null, hold_time?: u16 | null, keepalive_time?: u16 | null, tcp_md5_key?: string | null, afi?: [string] | string | null, max_prefix_ipv4?: u32 | null, max_prefix_ipv6?: u32 | null, max_prefix_action?: string | null, max_prefix_restart?: u16 | null, update_source?: string | null, nexthop_choice?: string | null, input_filter?: string | null (the /routing filter chain of received routes), output_filter?: string | null (of sent routes), keep_received?: bool | null (keep received routes before the input chain; default yes), bfd?: string | null (a BFD profile, routing.bfd.profile: the session goes down with BFD)} → {name}",
        has_templates, template_set),
    cmd!("routing.bgp.template.remove", "Remove BGP Template", [], None,
        "{id: string (the name)} → {name}",
        has_templates, template_remove),
    cmd!(query "routing.bgp.template.list", "BGP Templates", ["Routing", "BGP"], None,
        "{} → [{name, templates, params (own values; tcp_md5_key as \"***\"), effective (with the parents' values), used_by (connections and templates listing it), error?, comment}]",
        always, template_list),
    cmd!(query "routing.bgp.template.check", "Check BGP Template", [], None,
        "{id?: string (the template being edited), name?: string, templates?: [string] | string, comment?: string, remote_as?: u32 | string | null, local_role?: string | null, multihop?: bool | yes | no | null, hold_time?: u16 | string | null, keepalive_time?: u16 | string | null, tcp_md5_key?: string | null, afi?: [string] | string | null, max_prefix_ipv4?: u32 | string | null, max_prefix_ipv6?: u32 | string | null, max_prefix_action?: string | null, max_prefix_restart?: u16 | string | null, update_source?: string | null, nexthop_choice?: string | null, input_filter?: string | null (the /routing filter chain of received routes), output_filter?: string | null (of sent routes), keep_received?: bool | null (keep received routes before the input chain; default yes), bfd?: string | null (a BFD profile, routing.bfd.profile: the session goes down with BFD)} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}], risk} (form texts accepted: \"90\", yes/no, empty = unset)",
        always, template_check),
    cmd!("routing.bgp.connection.add", "Add BGP Connection", ["Routing", "BGP"], None,
        "{name: string, remote_address: ip, instance?: string (default \"default\"), templates?: [string] | string, disabled?: bool, comment?: string, remote_as?: u32 | asdot string | null, local_role?: string | null, multihop?: bool | null, hold_time?: u16 | null, keepalive_time?: u16 | null, tcp_md5_key?: string | null, afi?: [string] | string | null, max_prefix_ipv4?: u32 | null, max_prefix_ipv6?: u32 | null, max_prefix_action?: string | null, max_prefix_restart?: u16 | null, update_source?: string | null, nexthop_choice?: string | null, input_filter?: string | null (the /routing filter chain of received routes), output_filter?: string | null (of sent routes), keep_received?: bool | null (keep received routes before the input chain; default yes), bfd?: string | null (a BFD profile, routing.bfd.profile: the session goes down with BFD)} → {name}",
        always, connection_add),
    cmd!("routing.bgp.connection.set", "Set BGP Connection", [], None,
        "{id: string (the name), name?: string, remote_address?: ip, instance?: string, templates?: [string] | string, disabled?: bool (true: shutdown, the session closes and stays in the config), comment?: string, remote_as?: u32 | asdot string | null, local_role?: string | null, multihop?: bool | null, hold_time?: u16 | null, keepalive_time?: u16 | null, tcp_md5_key?: string | null, afi?: [string] | string | null, max_prefix_ipv4?: u32 | null, max_prefix_ipv6?: u32 | null, max_prefix_action?: string | null, max_prefix_restart?: u16 | null, update_source?: string | null, nexthop_choice?: string | null, input_filter?: string | null (the /routing filter chain of received routes), output_filter?: string | null (of sent routes), keep_received?: bool | null (keep received routes before the input chain; default yes), bfd?: string | null (a BFD profile, routing.bfd.profile: the session goes down with BFD)} → {name}",
        has_connections, connection_set),
    cmd!("routing.bgp.connection.remove", "Remove BGP Connection", [], None,
        "{id: string (the name)} → {name}",
        has_connections, connection_remove),
    cmd!(query "routing.bgp.connection.list", "BGP Connections", ["Routing", "BGP"], None,
        "{find?: string (in name, address, AS or comment)} → [{name, instance, remote_address, templates, disabled, comment, kind (ibgp | ebgp), local_as, params (own; tcp_md5_key \"***\"), effective (in force), inherited: [param] (from a template), key_set: bool (a TCP MD5 key is in force), state (the session's, or disabled | unknown), established, uptime_secs?, prefix_count?, prefix_sent?, error?}]",
        always, connection_list),
    cmd!(query "routing.bgp.connection.check", "Check BGP Connection", [], None,
        "{id?: string (the connection being edited), name?: string, remote_address?: string, instance?: string, templates?: [string] | string, disabled?: bool, comment?: string, remote_as?: u32 | string | null, local_role?: string | null, multihop?: bool | yes | no | null, hold_time?: u16 | string | null, keepalive_time?: u16 | string | null, tcp_md5_key?: string | null, afi?: [string] | string | null, max_prefix_ipv4?: u32 | string | null, max_prefix_ipv6?: u32 | string | null, max_prefix_action?: string | null, max_prefix_restart?: u16 | string | null, update_source?: string | null, nexthop_choice?: string | null, input_filter?: string | null (the /routing filter chain of received routes), output_filter?: string | null (of sent routes), keep_received?: bool | null (keep received routes before the input chain; default yes), bfd?: string | null (a BFD profile, routing.bfd.profile: the session goes down with BFD)} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}], risk} (form texts accepted: \"90\", yes/no, empty = unset)",
        always, connection_check),
    cmd!("routing.bgp.session.clear", "Clear BGP Session", [], None,
        "{connection: string} → {connection, remote_address, action: \"clear\"} (closes the session and opens it again: NOTIFICATION Cease, administrative reset)",
        has_connections, session_clear),
    cmd!("routing.bgp.session.refresh", "Refresh BGP Session", [], None,
        "{connection: string} → {connection, remote_address, action: \"refresh\"} (asks the neighbor to send its routes again, RFC 2918 ROUTE-REFRESH: new inbound policy without a reset)",
        has_connections, session_refresh),
    cmd!("routing.bgp.session.resend", "Resend BGP Session", [], None,
        "{connection: string} → {connection, remote_address, action: \"resend\"} (sends our routes again: new outbound policy without a reset)",
        has_connections, session_resend),
];

fn has_templates(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.bgp_templates.is_empty() {
        Err("there are no BGP templates (routing.bgp.template.add)".into())
    } else {
        Ok(())
    }
}

fn has_connections(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.bgp_connections.is_empty() {
        Err("there are no BGP connections (routing.bgp.connection.add)".into())
    } else {
        Ok(())
    }
}

/// 1..=64 of [A-Za-z0-9_.-]: it goes on FRR's vty as the neighbor's
/// description, so no spaces.
fn check_name(key: &str, name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(EngineError::bad(key, "1..=64 characters of [A-Za-z0-9_.-]"));
    }
    Ok(())
}

/// A parameter of `set`: absent (keep), `null` (unset) or a value.
enum Given<'a> {
    Absent,
    Null,
    Value(&'a Value),
}

fn given<'a>(p: &'a Value, key: &str) -> Given<'a> {
    match p.get(key) {
        None => Given::Absent,
        Some(Value::Null) => Given::Null,
        Some(v) => Given::Value(v),
    }
}

/// Apply `parse` to `key` of `p` onto `slot`.
fn field<T>(
    p: &Value,
    key: &str,
    slot: &mut Option<T>,
    parse: impl FnOnce(&Value) -> Result<T>,
) -> Result<()> {
    match given(p, key) {
        Given::Absent => {}
        Given::Null => *slot = None,
        Given::Value(v) => *slot = Some(parse(v)?),
    }
    Ok(())
}

fn u16_of(key: &'static str) -> impl FnOnce(&Value) -> Result<u16> {
    move |v| {
        v.as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| EngineError::bad(key, "must be an integer 0..=65535"))
    }
}

fn u32_of(key: &'static str) -> impl FnOnce(&Value) -> Result<u32> {
    move |v| {
        v.as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| EngineError::bad(key, "must be an integer 0..=4294967295"))
    }
}

fn str_of<'a>(key: &str, v: &'a Value) -> Result<&'a str> {
    v.as_str()
        .ok_or_else(|| EngineError::bad(key, "must be a string"))
}

pub(crate) fn asn_of(key: &str, v: &Value) -> Result<Asn> {
    match v {
        Value::Number(n) => n
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .map(Asn)
            .ok_or_else(|| EngineError::bad(key, "must be 0..=4294967295")),
        Value::String(s) => s
            .parse()
            .map_err(|e: corerouter_model::ParseError| EngineError::bad(key, e.to_string())),
        _ => Err(EngineError::bad(key, "must be a number or an asdot string")),
    }
}

/// How the key is sealed: the session's key, or a stand-in (the preview).
type Sealer<'a> = &'a mut dyn FnMut(&str) -> Result<Sealed>;

fn parse_key(v: &Value, seal: Sealer<'_>) -> Result<Sealed> {
    let k = str_of("tcp_md5_key", v)?;
    if k.is_empty() {
        return Ok(Sealed::default());
    }
    if k.len() > corerouter_proto_bgp::MAX_KEY_LEN || !k.bytes().all(|b| b.is_ascii_graphic()) {
        // Never echo the key back.
        return Err(EngineError::bad(
            "tcp_md5_key",
            "1..=80 printable characters without spaces (RFC 2385; Linux TCP_MD5SIG_MAXKEYLEN)",
        ));
    }
    seal(k)
}

/// The shared parameters of `p` onto `out`.
fn parse_params(p: &Value, out: &mut BgpParams, seal: Sealer<'_>) -> Result<()> {
    field(p, "remote_as", &mut out.remote_as, |v| asn_of("remote_as", v))?;
    field(p, "local_role", &mut out.local_role, |v| {
        let s = str_of("local_role", v)?;
        LocalRole::parse(s).ok_or_else(|| {
            EngineError::bad(
                "local_role",
                "one of ibgp, ebgp, ebgp-provider, ebgp-customer, ebgp-peer, ebgp-rs, ebgp-rs-client",
            )
        })
    })?;
    field(p, "multihop", &mut out.multihop, |v| {
        v.as_bool()
            .ok_or_else(|| EngineError::bad("multihop", "must be true or false"))
    })?;
    field(p, "hold_time", &mut out.hold_time, u16_of("hold_time"))?;
    field(p, "keepalive_time", &mut out.keepalive_time, u16_of("keepalive_time"))?;
    field(p, "tcp_md5_key", &mut out.tcp_md5_key, |v| parse_key(v, seal))?;
    if let Given::Null = given(p, "afi") {
        out.afi = None;
    } else if let Some(list) = opt_list(p, "afi")? {
        let mut fams = Vec::new();
        for f in list {
            let afi = Afi::parse(f.trim())
                .ok_or_else(|| EngineError::bad("afi", format!("{:?}: ip or ipv6", crate::logging::cut(&f, 16))))?;
            if !fams.contains(&afi) {
                fams.push(afi);
            }
        }
        out.afi = Some(fams);
    }
    field(p, "max_prefix_ipv4", &mut out.max_prefix_ipv4, u32_of("max_prefix_ipv4"))?;
    field(p, "max_prefix_ipv6", &mut out.max_prefix_ipv6, u32_of("max_prefix_ipv6"))?;
    field(p, "max_prefix_action", &mut out.max_prefix_action, |v| {
        MaxPrefixAction::parse(str_of("max_prefix_action", v)?)
            .ok_or_else(|| EngineError::bad("max_prefix_action", "shutdown, warning or restart"))
    })?;
    field(p, "max_prefix_restart", &mut out.max_prefix_restart, u16_of("max_prefix_restart"))?;
    field(p, "update_source", &mut out.update_source, |v| {
        let s = str_of("update_source", v)?.trim();
        if s.is_empty() || s.len() > 64 || s.bytes().any(|b| !b.is_ascii_graphic()) {
            return Err(EngineError::bad("update_source", "an address or an interface name"));
        }
        Ok(s.to_owned())
    })?;
    field(p, "nexthop_choice", &mut out.nexthop_choice, |v| {
        NexthopChoice::parse(str_of("nexthop_choice", v)?)
            .ok_or_else(|| EngineError::bad("nexthop_choice", "default, force-self or propagate"))
    })?;
    // G3.2b: the chains (checked against the rules at commit).
    for key in ["input_filter", "output_filter"] {
        let slot = if key == "input_filter" { &mut out.input_filter } else { &mut out.output_filter };
        field(p, key, slot, |v| {
            let c = str_of(key, v)?.trim();
            corerouter_proto_bgp::filter::parse::check_chain(c).map_err(|e| EngineError::bad(key, e))?;
            Ok(c.to_owned())
        })?;
    }
    field(p, "keep_received", &mut out.keep_received, |v| {
        v.as_bool().ok_or_else(|| EngineError::bad("keep_received", "must be true or false"))
    })?;
    // G3.6b: checked against the profiles at commit (routing.bfd).
    field(p, "bfd", &mut out.bfd, |v| {
        let b = str_of("bfd", v)?.trim();
        corerouter_model::bfd::check_profile_name(b).map_err(|e| EngineError::bad("bfd", e))?;
        Ok(b.to_owned())
    })?;
    Ok(())
}

fn parse_templates(p: &Value) -> Result<Option<Vec<String>>> {
    let Some(list) = opt_list(p, "templates")? else {
        return Ok(None);
    };
    if list.len() > MAX_TEMPLATES_LISTED {
        return Err(EngineError::bad("templates", "at most 8"));
    }
    let mut out = Vec::new();
    for t in list {
        let t = t.trim().to_owned();
        check_name("templates", &t)?;
        if !out.contains(&t) {
            out.push(t);
        }
    }
    Ok(Some(out))
}

/// The session's sealer.
fn sealer(s: &mut Session) -> Result<impl FnMut(&str) -> Result<Sealed> + use<>> {
    let key = crate::sealing::key(s).map_err(EngineError::Internal)?;
    Ok(move |clear: &str| key.seal(clear).map_err(EngineError::Internal))
}

/// Only what the preview needs: a key is a key.
fn fake_seal(_: &str) -> Result<Sealed> {
    Ok(Sealed::from_box(format!("{}preview", corerouter_model::sealed::PREFIX)))
}

// ---- templates ----

fn apply_template(routing: &mut Routing, p: &Value, id: Option<&str>, seal: Sealer<'_>) -> Result<String> {
    let mut t = match id {
        Some(id) => routing
            .bgp_templates
            .get(id)
            .cloned()
            .ok_or_else(|| EngineError::bad("id", format!("no BGP template {:?}", crate::logging::cut(id, 64))))?,
        None => BgpTemplate {
            name: String::new(),
            templates: Vec::new(),
            params: BgpParams::default(),
            comment: String::new(),
        },
    };
    if let Some(name) = opt_str(p, "name")? {
        check_name("name", name)?;
        t.name = name.to_owned();
    } else if id.is_none() {
        return Err(EngineError::bad("name", "is required"));
    }
    if let Some(list) = parse_templates(p)? {
        t.templates = list;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        t.comment = c;
    }
    parse_params(p, &mut t.params, seal)?;
    let name = t.name.clone();
    if id != Some(name.as_str()) && routing.bgp_templates.contains_key(&name) {
        return Err(EngineError::bad("name", format!("template {name:?} already exists")));
    }
    if let Some(old) = id.filter(|old| *old != name) {
        // Renamed: whoever listed it follows.
        routing.bgp_templates.remove(old);
        for x in routing.bgp_templates.values_mut() {
            rename_in(&mut x.templates, old, &name);
        }
        for c in routing.bgp_connections.values_mut() {
            rename_in(&mut c.templates, old, &name);
        }
    }
    if id.is_none() && routing.bgp_templates.len() >= MAX_TEMPLATES {
        return Err(EngineError::bad("name", format!("at most {MAX_TEMPLATES} templates")));
    }
    routing.bgp_templates.insert(name.clone(), t);
    Ok(name)
}

fn rename_in(list: &mut [String], old: &str, new: &str) {
    for t in list.iter_mut().filter(|t| *t == old) {
        *t = new.to_owned();
    }
}

fn template_add(s: &mut Session, p: &Value) -> Result<Value> {
    let mut seal = sealer(s)?;
    let name = apply_template(&mut s.store_mut().candidate_mut().routing, p, None, &mut seal)?;
    Ok(json!({ "name": name }))
}

fn template_set(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?.to_owned();
    let mut seal = sealer(s)?;
    let name = apply_template(&mut s.store_mut().candidate_mut().routing, p, Some(&id), &mut seal)?;
    Ok(json!({ "name": name }))
}

/// Who lists template `name`.
fn users_of(routing: &Routing, name: &str) -> Vec<String> {
    let mut out: Vec<String> = routing
        .bgp_connections
        .values()
        .filter(|c| c.templates.iter().any(|t| t == name))
        .map(|c| c.name.clone())
        .collect();
    out.extend(
        routing
            .bgp_templates
            .values()
            .filter(|t| t.templates.iter().any(|x| x == name))
            .map(|t| format!("template {}", t.name)),
    );
    out
}

fn template_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?;
    let routing = &mut s.store_mut().candidate_mut().routing;
    if !routing.bgp_templates.contains_key(id) {
        return Err(EngineError::bad("id", format!("no BGP template {:?}", crate::logging::cut(id, 64))));
    }
    let users = users_of(routing, id);
    if !users.is_empty() {
        return Err(EngineError::bad(
            "id",
            format!(
                "template {id:?} is used by {}{}: remove it from them first",
                users.iter().take(5).cloned().collect::<Vec<_>>().join(", "),
                if users.len() > 5 { format!(" and {} more", users.len() - 5) } else { String::new() }
            ),
        ));
    }
    routing.bgp_templates.remove(id);
    Ok(json!({ "name": id }))
}

/// Params as JSON with the key masked.
fn params_json(p: &BgpParams) -> Value {
    let mut v = serde_json::to_value(p).unwrap_or_else(|_| json!({}));
    if let Some(o) = v.as_object_mut()
        && let Some(k) = o.get_mut("tcp_md5_key")
    {
        *k = if p.has_key() { json!("***") } else { json!("") };
    }
    v
}

fn template_list(s: &mut Session, _: &Value) -> Result<Value> {
    let routing = &s.store().candidate().routing;
    let resolved = resolve_templates(&routing.bgp_templates);
    let rows = routing
        .bgp_templates
        .values()
        .map(|t| {
            let (effective, error) = match resolved.get(&t.name) {
                Some(Ok(e)) => (params_json(e), None),
                Some(Err(e)) => (Value::Null, Some(e.to_string())),
                None => (Value::Null, None),
            };
            json!({
                "name": t.name,
                "templates": t.templates,
                "params": params_json(&t.params),
                "effective": effective,
                "used_by": users_of(routing, &t.name),
                "error": error,
                "comment": t.comment,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

// ---- connections ----

fn apply_connection(routing: &mut Routing, p: &Value, id: Option<&str>, seal: Sealer<'_>) -> Result<String> {
    let mut c = match id {
        Some(id) => routing
            .bgp_connections
            .get(id)
            .cloned()
            .ok_or_else(|| EngineError::bad("id", format!("no BGP connection {:?}", crate::logging::cut(id, 64))))?,
        None => {
            let addr = opt_str(p, "remote_address")?
                .ok_or_else(|| EngineError::bad("remote_address", "is required"))?;
            BgpConnection {
                name: String::new(),
                instance: corerouter_proto_bgp::DEFAULT_INSTANCE.to_owned(),
                remote_address: parse_addr(addr)?,
                templates: Vec::new(),
                params: BgpParams::default(),
                disabled: false,
                comment: String::new(),
            }
        }
    };
    if let Some(name) = opt_str(p, "name")? {
        check_name("name", name)?;
        c.name = name.to_owned();
    } else if id.is_none() {
        return Err(EngineError::bad("name", "is required"));
    }
    if let Some(a) = opt_str(p, "remote_address")? {
        c.remote_address = parse_addr(a)?;
    }
    if let Some(i) = opt_str(p, "instance")? {
        check_name("instance", i)?;
        c.instance = i.to_owned();
    }
    if let Some(list) = parse_templates(p)? {
        c.templates = list;
    }
    if let Some(d) = opt_bool(p, "disabled")? {
        c.disabled = d;
    }
    if let Some(note) = opt_text(p, "comment", 256)? {
        c.comment = note;
    }
    parse_params(p, &mut c.params, seal)?;
    let name = c.name.clone();
    if id != Some(name.as_str()) && routing.bgp_connections.contains_key(&name) {
        return Err(EngineError::bad("name", format!("connection {name:?} already exists")));
    }
    if id.is_none() && routing.bgp_connections.len() >= MAX_CONNECTIONS {
        return Err(EngineError::bad("name", format!("at most {MAX_CONNECTIONS} connections")));
    }
    if let Some(old) = id.filter(|old| *old != name) {
        routing.bgp_connections.remove(old);
    }
    routing.bgp_connections.insert(name.clone(), c);
    Ok(name)
}

fn parse_addr(a: &str) -> Result<IpAddr> {
    a.trim().parse().map_err(|_| {
        EngineError::bad(
            "remote_address",
            format!("{:?} is not an IPv4 or IPv6 address", crate::logging::cut(a, 64)),
        )
    })
}

fn connection_add(s: &mut Session, p: &Value) -> Result<Value> {
    let mut seal = sealer(s)?;
    let name = apply_connection(&mut s.store_mut().candidate_mut().routing, p, None, &mut seal)?;
    Ok(json!({ "name": name }))
}

fn connection_set(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?.to_owned();
    let mut seal = sealer(s)?;
    let name = apply_connection(&mut s.store_mut().candidate_mut().routing, p, Some(&id), &mut seal)?;
    Ok(json!({ "name": name }))
}

fn connection_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?;
    let routing = &mut s.store_mut().candidate_mut().routing;
    if routing.bgp_connections.remove(id).is_none() {
        return Err(EngineError::bad("id", format!("no BGP connection {:?}", crate::logging::cut(id, 64))));
    }
    Ok(json!({ "name": id }))
}

/// The parameter names a connection takes from a template.
fn inherited(own: &BgpParams, eff: &BgpParams) -> Vec<&'static str> {
    let own = serde_json::to_value(own).unwrap_or_default();
    let eff = serde_json::to_value(eff).unwrap_or_default();
    let (Some(own), Some(eff)) = (own.as_object(), eff.as_object()) else {
        return Vec::new();
    };
    PARAM_NAMES
        .iter()
        .copied()
        .filter(|k| eff.contains_key(*k) && !own.contains_key(*k))
        .collect()
}

const PARAM_NAMES: &[&str] = &[
    "remote_as",
    "local_role",
    "multihop",
    "hold_time",
    "keepalive_time",
    "tcp_md5_key",
    "afi",
    "max_prefix_ipv4",
    "max_prefix_ipv6",
    "max_prefix_action",
    "max_prefix_restart",
    "update_source",
    "nexthop_choice",
    "input_filter",
    "output_filter",
    "keep_received",
    "bfd",
];

fn kind_of(local_as: Option<Asn>, p: &BgpParams) -> &'static str {
    match (p.local_role, p.remote_as) {
        (Some(r), _) if r.is_ibgp() => "ibgp",
        (Some(_), _) => "ebgp",
        (None, Some(a)) if Some(a) == local_as => "ibgp",
        _ => "ebgp",
    }
}

/// One row of `connection.list`: the connection, what it inherits and the
/// session FRR runs for it.
fn connection_row(
    c: &BgpConnection,
    resolved: &BTreeMap<String, std::result::Result<BgpParams, ResolveError>>,
    local_as: Option<Asn>,
    session: Option<&BgpSession>,
) -> Value {
    let (eff, error) = match c.effective(resolved) {
        Ok(e) => (e, None),
        Err(e) => (c.params.clone(), Some(e.to_string())),
    };
    let state = match (c.disabled, session) {
        (true, _) => "disabled".to_owned(),
        (false, Some(s)) => s.state.clone(),
        (false, None) => "unknown".to_owned(),
    };
    let mut row = json!({
        "name": c.name,
        "instance": c.instance,
        "remote_address": c.remote_address.to_string(),
        "templates": c.templates,
        "disabled": c.disabled,
        "comment": c.comment,
        "kind": kind_of(local_as, &eff),
        "local_as": local_as.map(|a| a.0),
        "params": params_json(&c.params),
        "effective": params_json(&eff),
        "inherited": inherited(&c.params, &eff),
        "key_set": eff.has_key(),
        "state": state,
        "established": session.is_some_and(|s| s.established),
        "error": error,
    });
    if let (Some(s), Some(o)) = (session, row.as_object_mut()) {
        o.insert("uptime_secs".into(), json!(s.uptime_secs));
        o.insert("prefix_count".into(), json!(s.prefix_count));
        o.insert("prefix_sent".into(), json!(s.prefix_sent));
    }
    row
}

fn connection_list(s: &mut Session, p: &Value) -> Result<Value> {
    let find = opt_text(p, "find", 128)?.map(|f| f.to_lowercase());
    let routing = &s.store().candidate().routing;
    let resolved = resolve_templates(&routing.bgp_templates);
    // One pass over the sessions, then O(1) per connection.
    let sessions: HashMap<(&str, &str), &BgpSession> = s
        .routing_status()
        .map(|st| {
            st.bgp_sessions
                .iter()
                .map(|b| ((b.instance.as_str(), b.remote_address.as_str()), b))
                .collect()
        })
        .unwrap_or_default();
    let mut rows = Vec::new();
    for c in routing.bgp_connections.values() {
        if let Some(f) = &find {
            let hay = format!(
                "{} {} {} {}",
                c.name,
                c.remote_address,
                c.params.remote_as.map(|a| a.0.to_string()).unwrap_or_default(),
                c.comment
            )
            .to_lowercase();
            if !hay.contains(f.as_str()) {
                continue;
            }
        }
        let addr = c.remote_address.to_string();
        let session = sessions.get(&(c.instance.as_str(), addr.as_str())).copied();
        let local_as = routing.bgp.get(&c.instance).map(|i| i.asn);
        rows.push(connection_row(c, &resolved, local_as, session));
    }
    Ok(Value::Array(rows))
}

/// Fields a form sends as text that `add`/`set` take typed.
const NUMBERS: &[&str] = &[
    "hold_time",
    "keepalive_time",
    "max_prefix_ipv4",
    "max_prefix_ipv6",
    "max_prefix_restart",
];
/// Fields whose empty text means "unset" (inherit).
const UNSET_WHEN_EMPTY: &[&str] = &[
    "remote_as",
    "local_role",
    "multihop",
    "hold_time",
    "keepalive_time",
    "afi",
    "max_prefix_ipv4",
    "max_prefix_ipv6",
    "max_prefix_action",
    "max_prefix_restart",
    "update_source",
    "nexthop_choice",
    "input_filter",
    "output_filter",
    "keep_received",
    "bfd",
];

/// The parameters of a form (texts) as `add`/`set` take them: numbers as
/// numbers, `yes`/`no` as bools, an empty field left out of an `add` and
/// unset (`null`) by a `set`. Anything that does not parse stays as it
/// is, for the command to refuse with its own message.
fn normalize(p: &Value, editing: bool) -> Value {
    let Some(o) = p.as_object() else {
        return p.clone();
    };
    let mut out = Map::new();
    for (k, v) in o {
        let text = v.as_str().map(str::trim);
        let v = match text {
            Some("") if UNSET_WHEN_EMPTY.contains(&k.as_str()) => {
                if editing {
                    Value::Null
                } else {
                    continue;
                }
            }
            Some(t) if NUMBERS.contains(&k.as_str()) => {
                t.parse::<u64>().map_or_else(|_| v.clone(), Value::from)
            }
            Some("yes") if k == "multihop" || k == "keep_received" => Value::Bool(true),
            Some("no") if k == "multihop" || k == "keep_received" => Value::Bool(false),
            _ => v.clone(),
        };
        out.insert(k.clone(), v);
    }
    if !editing {
        out.remove("id");
    }
    Value::Object(out)
}

#[derive(Clone, Copy, PartialEq)]
enum What {
    Connection,
    Template,
}

fn connection_check(s: &mut Session, p: &Value) -> Result<Value> {
    preview(s, p, What::Connection)
}

fn template_check(s: &mut Session, p: &Value) -> Result<Value> {
    preview(s, p, What::Template)
}

/// The modal's preview: the change applied to a copy, validated, with the
/// values in force. Never an error for bad input: it becomes a check.
fn preview(s: &mut Session, raw: &Value, what: What) -> Result<Value> {
    let mut checks: Vec<Value> = Vec::new();
    let mut computed: Vec<Value> = Vec::new();
    let check = |level: &str, check: &str, message: String, param: &str| {
        json!({"level": level, "check": check, "message": message, "param": param})
    };
    let id = opt_str(raw, "id").ok().flatten().map(str::to_owned);
    let p = normalize(raw, id.is_some());
    let mut cfg: Config = s.store().candidate().clone();
    let mut fake = fake_seal;
    let applied = match what {
        What::Connection => apply_connection(&mut cfg.routing, &p, id.as_deref(), &mut fake),
        What::Template => apply_template(&mut cfg.routing, &p, id.as_deref(), &mut fake),
    };
    let name = match applied {
        Ok(n) => n,
        Err(e) => {
            let (param, msg) = match &e {
                EngineError::BadParam { param, reason } => (param.clone(), reason.clone()),
                other => (String::new(), other.to_string()),
            };
            checks.push(check("error", "params", msg, &param));
            return Ok(json!({"computed": computed, "checks": checks, "commands": [], "risk": null}));
        }
    };
    let prefix = match what {
        What::Connection => format!("routing.bgp_connections.{name}"),
        What::Template => format!("routing.bgp_templates.{name}"),
    };
    for issue in corerouter_proto_bgp::validate(&cfg) {
        // This item's issues, and those its change causes in the
        // connections that inherit from it.
        let mine = issue.path.strip_prefix(&prefix);
        let param = mine
            .and_then(|rest| rest.rsplit('.').next())
            .filter(|p| {
                PARAM_NAMES.contains(p) || matches!(*p, "templates" | "instance" | "remote_address")
            })
            .unwrap_or("");
        let inherited = what == What::Template
            && issue.path.starts_with("routing.bgp_connections.")
            && !corerouter_proto_bgp::validate(s.store().candidate())
                .iter()
                .any(|i| i == &issue);
        if mine.is_some() {
            checks.push(check("error", "validate", issue.message.clone(), param));
        } else if inherited {
            let who = issue.path.trim_start_matches("routing.bgp_connections.");
            checks.push(check("error", "inherited", format!("{who}: {}", issue.message), ""));
        }
    }
    let routing = &cfg.routing;
    let resolved = resolve_templates(&routing.bgp_templates);
    match what {
        What::Connection => {
            if let Some(c) = routing.bgp_connections.get(&name)
                && let Ok(eff) = c.effective(&resolved)
            {
                let local_as = routing.bgp.get(&c.instance).map(|i| i.asn);
                describe(&eff, kind_of(local_as, &eff), &inherited(&c.params, &eff), &mut computed, &mut checks);
            }
        }
        What::Template => {
            if let Some(Ok(eff)) = resolved.get(&name) {
                let kind = match eff.local_role {
                    Some(r) if r.is_ibgp() => "ibgp",
                    Some(_) => "ebgp",
                    None => "",
                };
                let own = routing.bgp_templates.get(&name).map(|t| t.params.clone()).unwrap_or_default();
                describe(eff, kind, &inherited(&own, eff), &mut computed, &mut checks);
                let users = users_of(routing, &name);
                if !users.is_empty() {
                    computed.push(json!({"label": "Used by", "value": users.join(", ")}));
                }
            }
        }
    }
    // Changes that restart the session (a warning, not a risk: the other
    // sessions stay up, and `set` takes no `force`).
    if let Some(item) = &id {
        let resets = ["remote_address", "remote_as", "tcp_md5_key", "local_role", "update_source", "multihop", "instance"];
        let hit: Vec<&str> = resets
            .iter()
            .copied()
            .filter(|k| raw.get(*k).is_some_and(|v| v != &Value::String(String::new())))
            .filter(|k| changed(s.store().candidate(), &cfg, what, item, &name, k))
            .collect();
        if !hit.is_empty() {
            checks.push(check(
                "warning",
                "reset",
                format!(
                    "changing {} restarts {} (routes are withdrawn and learned again); the other sessions stay up",
                    hit.join(", "),
                    if what == What::Connection { "this BGP session" } else { "the sessions of the connections using it" }
                ),
                hit.first().copied().unwrap_or(""),
            ));
        }
    }
    let ok = !checks.iter().any(|c| c.get("level").and_then(Value::as_str) == Some("error"));
    let command = match (what, id.is_some()) {
        (What::Connection, true) => "routing.bgp.connection.set",
        (What::Connection, false) => "routing.bgp.connection.add",
        (What::Template, true) => "routing.bgp.template.set",
        (What::Template, false) => "routing.bgp.template.add",
    };
    let mut params = p;
    if let Some(o) = params.as_object_mut() {
        // A secret left empty keeps the router's (the form's write-only field).
        if o.get("tcp_md5_key").is_some_and(|v| v.as_str() == Some("")) && id.is_some() {
            o.remove("tcp_md5_key");
        }
        // A rename keeps the name; an unchanged name is not sent.
        if id.as_deref() == o.get("name").and_then(Value::as_str) {
            o.remove("name");
        }
    }
    Ok(json!({
        "computed": computed,
        "checks": checks,
        "commands": if ok { vec![json!({"command": command, "params": params})] } else { Vec::new() },
        "risk": null,
    }))
}

/// Whether parameter `k` of the item differs between the two configs.
fn changed(before: &Config, after: &Config, what: What, id: &str, name: &str, k: &str) -> bool {
    match what {
        What::Connection => {
            let (a, b) = (before.routing.bgp_connections.get(id), after.routing.bgp_connections.get(name));
            match (a, b) {
                (Some(a), Some(b)) => match k {
                    "remote_address" => a.remote_address != b.remote_address,
                    "instance" => a.instance != b.instance,
                    _ => serde_json::to_value(&a.params).ok().and_then(|v| v.get(k).cloned())
                        != serde_json::to_value(&b.params).ok().and_then(|v| v.get(k).cloned()),
                },
                _ => false,
            }
        }
        What::Template => {
            let (a, b) = (before.routing.bgp_templates.get(id), after.routing.bgp_templates.get(name));
            match (a, b) {
                (Some(a), Some(b)) => serde_json::to_value(&a.params).ok().and_then(|v| v.get(k).cloned())
                    != serde_json::to_value(&b.params).ok().and_then(|v| v.get(k).cloned()),
                _ => false,
            }
        }
    }
}

/// The values in force, for the preview.
fn describe(eff: &BgpParams, kind: &str, from: &[&str], computed: &mut Vec<Value>, checks: &mut Vec<Value>) {
    let check = |level: &str, check: &str, message: &str, param: &str| {
        json!({"level": level, "check": check, "message": message, "param": param})
    };
    if !kind.is_empty() {
        computed.push(json!({"label": "Kind", "value": kind}));
    }
    let remote = eff.remote_as.map_or_else(
        || match kind {
            "ibgp" => "ours (internal)".to_owned(),
            "ebgp" => "any other (external)".to_owned(),
            _ => "unset".to_owned(),
        },
        |a| a.to_string(),
    );
    computed.push(json!({"label": "Remote AS", "value": remote}));
    let (k, h) = corerouter_proto_bgp::timers(eff);
    computed.push(json!({"label": "Timers", "value": format!("keepalive {k} s, hold {h} s")}));
    let fams: Vec<&str> = eff.families().iter().map(|f| f.name()).collect();
    computed.push(json!({"label": "Families", "value": fams.join(", ")}));
    if !from.is_empty() {
        computed.push(json!({"label": "Inherited", "value": from.join(", ")}));
    }
    if kind == "ebgp" {
        // G3.2b: name what is missing and where it is set.
        match (&eff.input_filter, &eff.output_filter) {
            (Some(_), Some(_)) => {}
            (None, None) => checks.push(check("warning", "rfc8212", "eBGP without input_filter and output_filter: no route is accepted or sent (RFC 8212); set the chains (Routing › Filters)", "input_filter")),
            (None, Some(_)) => checks.push(check("warning", "rfc8212", "eBGP without input_filter: no route is accepted (RFC 8212)", "input_filter")),
            (Some(_), None) => checks.push(check("warning", "rfc8212", "eBGP without output_filter: no route is sent (RFC 8212)", "output_filter")),
        }
    }
    if eff.hold_time.is_some_and(|h| h != 0 && h < 9) {
        checks.push(check(
            "warning",
            "hold",
            "a hold time under 9 s drops the session on a short loss; BFD detects failures faster",
            "hold_time",
        ));
    }
    if !eff.has_key() && kind == "ebgp" {
        checks.push(check("info", "md5", "no TCP MD5 key: many IXPs and transit providers ask for one (RFC 2385)", "tcp_md5_key"));
    }
}

// ---- session actions ----

fn session_action(s: &mut Session, p: &Value, how: BgpClear, action: &str) -> Result<Value> {
    let name = req_str(p, "connection")?;
    let c = s
        .store()
        .running()
        .routing
        .bgp_connections
        .get(name)
        .cloned()
        .ok_or_else(|| {
            EngineError::bad(
                "connection",
                format!("no committed BGP connection {:?}", crate::logging::cut(name, 64)),
            )
        })?;
    if c.disabled {
        return Err(EngineError::bad("connection", format!("{name:?} is disabled (shutdown)")));
    }
    s.routing_bgp_clear(&c.instance, &c.remote_address.to_string(), how)?;
    Ok(json!({"connection": name, "remote_address": c.remote_address.to_string(), "action": action}))
}

fn session_clear(s: &mut Session, p: &Value) -> Result<Value> {
    session_action(s, p, BgpClear::Hard, "clear")
}

fn session_refresh(s: &mut Session, p: &Value) -> Result<Value> {
    session_action(s, p, BgpClear::SoftIn, "refresh")
}

fn session_resend(s: &mut Session, p: &Value) -> Result<Value> {
    session_action(s, p, BgpClear::SoftOut, "resend")
}

#[cfg(test)]
mod tests {
    use corerouter_hal::VirtualHal;

    use super::*;

    fn session() -> Session {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        s.execute(
            "routing.bgp.instance.set",
            &json!({"asn": 65000, "router_id": "10.0.0.1"}),
        )
        .unwrap();
        s
    }

    #[test]
    fn connections_inherit_from_templates_and_validate() {
        let mut s = session();
        s.execute(
            "routing.bgp.template.add",
            &json!({"name": "transit", "local_role": "ebgp", "hold_time": 90, "afi": "ip,ipv6", "max_prefix_ipv4": 1000}),
        )
        .unwrap();
        s.execute(
            "routing.bgp.connection.add",
            &json!({"name": "up1", "remote_address": "192.0.2.1", "remote_as": "64500", "templates": ["transit"]}),
        )
        .unwrap();
        let rows = s.execute("routing.bgp.connection.list", &json!({})).unwrap();
        let r = &rows[0];
        assert_eq!(r["kind"], "ebgp");
        assert_eq!(r["effective"]["hold_time"], 90);
        assert_eq!(r["effective"]["afi"], json!(["ip", "ipv6"]));
        assert_eq!(r["inherited"], json!(["local_role", "hold_time", "afi", "max_prefix_ipv4"]));
        assert_eq!(r["state"], "unknown");
        let cfg = s.store().running().clone();
        let text = corerouter_proto_bgp::render_all(&cfg.routing, &|_| None).unwrap();
        assert!(text.contains(" neighbor 192.0.2.1 timers 30 90\n"), "{text}");
        assert!(text.contains("  neighbor 192.0.2.1 maximum-prefix 1000\n"));

        // `null` unsets (back to the template's value); a template in use
        // is not removed.
        s.execute("routing.bgp.connection.set", &json!({"id": "up1", "hold_time": 30})).unwrap();
        s.execute("routing.bgp.connection.set", &json!({"id": "up1", "hold_time": null})).unwrap();
        let rows = s.execute("routing.bgp.connection.list", &json!({})).unwrap();
        assert_eq!(rows[0]["effective"]["hold_time"], 90);
        let e = s.execute("routing.bgp.template.remove", &json!({"id": "transit"})).unwrap_err();
        assert!(e.to_string().contains("used by up1"), "{e}");

        // Validation refuses the commit, and nothing changes (rollback).
        let before = s.store().running().routing.clone();
        let e = s
            .execute("routing.bgp.connection.add", &json!({"name": "bad", "remote_address": "192.0.2.9", "remote_as": 23456}))
            .unwrap_err();
        assert!(e.to_string().contains("reserved"), "{e}");
        let e = s
            .execute("routing.bgp.connection.add", &json!({"name": "ghost", "remote_address": "192.0.2.8", "remote_as": 1, "templates": "nope"}))
            .unwrap_err();
        assert!(e.to_string().contains("does not exist"), "{e}");
        let e = s
            .execute("routing.bgp.connection.add", &json!({"name": "nofam", "remote_address": "192.0.2.7", "remote_as": 1, "afi": ""}))
            .unwrap_err();
        assert!(e.to_string().contains("no address family"), "{e}");
        assert_eq!(s.store().running().routing, before);
    }

    #[test]
    fn template_loops_are_refused() {
        let mut s = session();
        s.execute("routing.bgp.template.add", &json!({"name": "a"})).unwrap();
        s.execute("routing.bgp.template.add", &json!({"name": "b", "templates": "a"})).unwrap();
        let e = s
            .execute("routing.bgp.template.set", &json!({"id": "a", "templates": "b"}))
            .unwrap_err();
        assert!(e.to_string().contains("loop"), "{e}");
        // Renaming a template renames it where it is listed.
        s.execute("routing.bgp.template.set", &json!({"id": "a", "name": "base"})).unwrap();
        let t = s.execute("routing.bgp.template.list", &json!({})).unwrap();
        let b = t.as_array().unwrap().iter().find(|r| r["name"] == "b").unwrap();
        assert_eq!(b["templates"], json!(["base"]));
    }

    #[test]
    fn the_key_is_sealed_and_never_shown() {
        let mut s = session();
        s.execute(
            "routing.bgp.connection.add",
            &json!({"name": "ix", "remote_address": "2001:db8::2", "remote_as": 64501, "tcp_md5_key": "Sup3rS3cret"}),
        )
        .unwrap();
        let key = s.store().running().routing.bgp_connections["ix"].params.tcp_md5_key.clone().unwrap();
        assert!(key.is_sealed());
        let everywhere = [
            serde_json::to_string(s.store().running()).unwrap(),
            s.execute("routing.bgp.connection.list", &json!({})).unwrap().to_string(),
            serde_json::to_string(&s.journal()).unwrap(),
            format!("{:?}", s.store().running()),
            s.execute("config.diff", &json!({})).map(|v| v.to_string()).unwrap_or_default(),
        ];
        for text in everywhere {
            assert!(!text.contains("Sup3rS3cret"), "{text}");
        }
        // The render (what goes to FRR) opens it with the session's key.
        let k = crate::sealing::key(&mut s).unwrap();
        let text = corerouter_proto_bgp::render_all(&s.store().running().routing, &|x| k.open(x)).unwrap();
        assert!(text.contains(" neighbor 2001:db8::2 password Sup3rS3cret\n"));
        // A bad key is refused without echoing it.
        let e = s
            .execute("routing.bgp.connection.set", &json!({"id": "ix", "tcp_md5_key": "has space"}))
            .unwrap_err();
        assert!(!e.to_string().contains("has space"), "{e}");
        // "" clears it.
        s.execute("routing.bgp.connection.set", &json!({"id": "ix", "tcp_md5_key": ""})).unwrap();
        let rows = s.execute("routing.bgp.connection.list", &json!({})).unwrap();
        assert_eq!(rows[0]["key_set"], false);
    }

    #[test]
    fn the_preview_validates_without_changing_anything() {
        let mut s = session();
        let v = s
            .execute("routing.bgp.connection.check", &json!({"name": "up1", "remote_address": "192.0.2.1", "remote_as": 64500, "hold_time": 6}))
            .unwrap();
        assert_eq!(v["commands"][0]["command"], "routing.bgp.connection.add");
        assert!(v["computed"].to_string().contains("keepalive 2 s, hold 6 s"), "{v}");
        assert!(v["checks"].to_string().contains("hold"), "{v}");
        let v = s
            .execute("routing.bgp.connection.check", &json!({"name": "up1", "remote_address": "192.0.2.1", "remote_as": 23456}))
            .unwrap();
        assert_eq!(v["commands"], json!([]));
        assert!(v["checks"].to_string().contains("reserved"), "{v}");
        let v = s
            .execute("routing.bgp.connection.check", &json!({"name": "up1", "remote_address": "nope"}))
            .unwrap();
        assert_eq!(v["checks"][0]["param"], "remote_address");
        assert!(s.store().candidate().routing.bgp_connections.is_empty());
    }

    #[test]
    fn the_preview_takes_form_texts_and_gives_typed_commands() {
        let mut s = session();
        let v = s
            .execute(
                "routing.bgp.connection.check",
                &json!({"name": "up1", "remote_address": "192.0.2.1", "remote_as": "64500", "hold_time": "90", "multihop": "yes", "afi": "", "comment": ""}),
            )
            .unwrap();
        let step = &v["commands"][0];
        assert_eq!(step["params"]["hold_time"], 90, "{v}");
        assert_eq!(step["params"]["multihop"], true);
        assert!(step["params"].get("afi").is_none());
        s.execute(step["command"].as_str().unwrap(), &step["params"]).unwrap();
        // Editing: an emptied field unsets it, an unchanged name is not sent.
        let v = s
            .execute("routing.bgp.connection.check", &json!({"id": "up1", "name": "up1", "hold_time": "", "remote_as": "64501"}))
            .unwrap();
        let step = &v["commands"][0];
        assert_eq!(step["params"]["hold_time"], Value::Null);
        assert!(step["params"].get("name").is_none());
        assert!(v["checks"].to_string().contains("restarts this BGP session"), "{v}");
        s.execute(step["command"].as_str().unwrap(), &step["params"]).unwrap();
        // A template change that breaks a connection using it is caught.
        s.execute("routing.bgp.template.add", &json!({"name": "t"})).unwrap();
        s.execute("routing.bgp.connection.set", &json!({"id": "up1", "templates": "t", "remote_as": null, "local_role": "ebgp"}))
            .unwrap();
        let v = s
            .execute("routing.bgp.template.check", &json!({"id": "t", "name": "t", "hold_time": "2"}))
            .unwrap();
        assert_eq!(v["commands"], json!([]), "{v}");
        assert!(v["checks"].to_string().contains("RFC 4271"), "{v}");
        let v = s.execute("routing.bgp.template.check", &json!({"id": "t", "hold_time": "30"})).unwrap();
        assert_eq!(v["commands"][0]["command"], "routing.bgp.template.set");
        assert!(v["computed"].to_string().contains("up1"), "{v}");
    }

    #[test]
    fn session_actions_need_a_backend() {
        let mut s = session();
        s.execute(
            "routing.bgp.connection.add",
            &json!({"name": "up1", "remote_address": "192.0.2.1", "remote_as": 64500}),
        )
        .unwrap();
        let e = s.execute("routing.bgp.session.refresh", &json!({"connection": "up1"})).unwrap_err();
        assert!(e.to_string().contains("no routing daemon"), "{e}");
        let e = s.execute("routing.bgp.session.clear", &json!({"connection": "x"})).unwrap_err();
        assert!(e.to_string().contains("no committed"), "{e}");
    }
}
