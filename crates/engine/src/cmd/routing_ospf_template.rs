//! /routing ospf interface-template (G3.4): which interfaces run OSPF, in
//! which area, how. A template matches interfaces by name (or interface
//! list) and by network; the first matching template wins, so the order
//! matters (`move`).
//!
//! The modal's preview (`check`) shows what the change does before it is
//! applied: the interfaces the template takes now, the network type each
//! one suggests (a /30, /31 or PPP link: `ptp`), `passive` on interfaces
//! facing subscribers, missing or weak authentication, and the adjacencies
//! that drop (`risk`, with Safe Mode offered).
//!
//! `auth_key` arrives in clear and is sealed at once (`sealing`); given
//! without `auth`, it means `sha256` (RFC 5709).

use std::collections::HashMap;
use std::net::Ipv4Addr;

use corerouter_model::Routing;
use corerouter_model::ospf::{AuthType, MAX_MATCHES, MAX_TEMPLATES, NetworkType, OspfTemplate};
use corerouter_model::sealed::Sealed;
use corerouter_model::types::ItemId;
use corerouter_model::Config;
use corerouter_proto_ospf::bind::{self, bindings};
use corerouter_proto_ospf::impact;
use ipnet::IpNet;
use serde_json::{Map, Value, json};

use super::args::{opt_text, req_str};
use super::dhcp_client::opt_list;
use super::routing_ospf::{Given, check_name, cut, given, opt_boolean, opt_number, parse_id, text};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};


pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("routing.ospf.interface-template.add", "Add OSPF Interface Template", ["Routing", "OSPF"], None,
        "{area: string, interfaces?: [string] | string (names or interface lists), networks?: [prefix] | string (an interface with an address inside one matches), type?: string (broadcast, ptp, nbma, ptmp, virtual-link), cost?: u16 | null, priority?: u8 | null, hello_interval?: u16 | null, dead_interval?: u16 | null, retransmit_interval?: u16 | null, transmit_delay?: u16 | null, passive?: bool, mtu_ignore?: bool, auth?: string | null (simple, md5, sha1, sha256, sha384, sha512; sha256 when a key is given alone), auth_id?: u16 | null, auth_key?: string | null (sealed at once; never shown back), keychain?: string | null (a /routing ospf keychain: rotation without a drop), bfd?: string | null (BFD profile), instance_id?: u8 | null (v3), vlink_neighbor_id?: ipv4 | null, vlink_transit_area?: string | null, disabled?: bool, comment?: string, place_before?: string (*N: before that template; the first match wins)} → {id}",
        has_areas, template_add),
    cmd!("routing.ospf.interface-template.set", "Set OSPF Interface Template", [], None,
        "{id: string (*N), area?: string, interfaces?: [string] | string (names or interface lists), networks?: [prefix] | string (an interface with an address inside one matches), type?: string (broadcast, ptp, nbma, ptmp, virtual-link), cost?: u16 | null, priority?: u8 | null, hello_interval?: u16 | null, dead_interval?: u16 | null, retransmit_interval?: u16 | null, transmit_delay?: u16 | null, passive?: bool, mtu_ignore?: bool, auth?: string | null (simple, md5, sha1, sha256, sha384, sha512; sha256 when a key is given alone), auth_id?: u16 | null, auth_key?: string | null (sealed at once; never shown back), keychain?: string | null (a /routing ospf keychain: rotation without a drop), bfd?: string | null (BFD profile), instance_id?: u8 | null (v3), vlink_neighbor_id?: ipv4 | null, vlink_transit_area?: string | null, disabled?: bool, comment?: string} → {id}",
        has_templates, template_set),
    cmd!("routing.ospf.interface-template.remove", "Remove OSPF Interface Template", [], None,
        "{id: string (*N)} → {id}",
        has_templates, template_remove),
    cmd!("routing.ospf.interface-template.move", "Move OSPF Interface Template", [], None,
        "{id: string (*N), before?: string (*N; absent: to the end)} → {id}",
        has_templates, template_move),
    cmd!(query "routing.ospf.interface-template.list", "OSPF Interface Templates", ["Routing", "OSPF"], None,
        "{} → [{id, area, instance, version, area_id, interfaces, networks, type, cost, priority, hello_interval, dead_interval, retransmit_interval, transmit_delay, passive, mtu_ignore, auth, auth_id, key_set, keychain, bfd, instance_id, vlink_neighbor_id, vlink_transit_area, matched: [{interface, why, suggested_type?}], warnings: [string], disabled, comment}]",
        always, template_list),
    cmd!(query "routing.ospf.interface-template.check", "Check OSPF Interface Template", [], None,
        "{id?: string (the template being edited), area?: string, interfaces?: [string] | string, networks?: [prefix] | string, type?: string, cost?: u16 | string | null, priority?: u8 | string | null, hello_interval?: u16 | string | null, dead_interval?: u16 | string | null, retransmit_interval?: u16 | string | null, transmit_delay?: u16 | string | null, passive?: bool | yes | no, mtu_ignore?: bool | yes | no, auth?: string | null, auth_id?: u16 | string | null, auth_key?: string | null, keychain?: string | null, bfd?: string | null, instance_id?: u8 | string | null, vlink_neighbor_id?: string | null, vlink_transit_area?: string | null, disabled?: bool, comment?: string, place_before?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}], risk, matched: [{interface, why, suggested_type?}], dropping: [interface]} (form texts accepted: \"10\", yes/no, empty = unset)",
        always, template_check),
    cmd!(query "routing.ospf.impact", "OSPF Commit Impact", ["Routing", "OSPF"], None,
        "{} → {changes: [{instance, interface, what, message, drops}], dropping: [interface], safe_mode: bool (an adjacency drops: commit in Safe Mode)}",
        always, impact_cmd),
];

fn has_areas(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.ospf.areas.is_empty() {
        Err("there are no OSPF areas (routing.ospf.area.add)".into())
    } else {
        Ok(())
    }
}

fn has_templates(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.ospf.templates.is_empty() {
        Err("there are no OSPF interface templates".into())
    } else {
        Ok(())
    }
}

/// How the key is sealed: the session's key, or a stand-in (the preview).
type Sealer<'a> = &'a mut dyn FnMut(&str) -> Result<Sealed>;

fn sealer(s: &mut Session) -> Result<impl FnMut(&str) -> Result<Sealed> + use<>> {
    let key = crate::sealing::key(s).map_err(EngineError::Internal)?;
    Ok(move |clear: &str| key.seal(clear).map_err(EngineError::Internal))
}

fn fake_seal(_: &str) -> Result<Sealed> {
    Ok(Sealed::from_box(format!("{}preview", corerouter_model::sealed::PREFIX)))
}

/// An OSPF key as given: printable, no spaces (FRR's `key-string` and
/// `authentication-key` take one word), the length the algorithm allows.
pub(super) fn check_key(key: &str, k: &str, auth: Option<AuthType>) -> Result<()> {
    let max = if auth == Some(AuthType::Simple) {
        corerouter_proto_ospf::MAX_SIMPLE_KEY
    } else {
        corerouter_proto_ospf::MAX_KEY
    };
    if k.is_empty() || k.len() > max || !k.bytes().all(|b| b.is_ascii_graphic()) {
        // Never echo the key back.
        return Err(EngineError::bad(
            key,
            format!("1..={max} printable characters without spaces{}", if max == 8 { " (simple: 64 bits, RFC 2328 §D.3)" } else { "" }),
        ));
    }
    Ok(())
}

fn opt_name_field(p: &Value, key: &str, slot: &mut Option<String>) -> Result<()> {
    match given(p, key) {
        Given::Absent => {}
        Given::Unset => *slot = None,
        Given::Value(v) => {
            let n = text(key, v)?;
            check_name(key, n)?;
            *slot = Some(n.to_owned());
        }
    }
    Ok(())
}

fn apply(routing: &mut Routing, p: &Value, id: Option<ItemId>, seal: Sealer<'_>) -> Result<ItemId> {
    let ospf = &mut routing.ospf;
    let mut t = match id {
        Some(id) => ospf
            .templates
            .iter()
            .find(|t| t.id == id)
            .cloned()
            .ok_or_else(|| EngineError::bad("id", format!("no OSPF interface template {id}")))?,
        None => OspfTemplate::default(),
    };
    match given(p, "area") {
        Given::Value(v) => {
            let n = text("area", v)?;
            if !ospf.areas.contains_key(n) {
                return Err(EngineError::bad("area", format!("no OSPF area {:?}", cut(n))));
            }
            t.area = n.to_owned();
        }
        _ if id.is_none() => return Err(EngineError::bad("area", "is required")),
        _ => {}
    }
    if let Some(list) = opt_list(p, "interfaces")? {
        let mut out: Vec<String> = Vec::new();
        for i in list {
            let i = i.trim();
            if i.is_empty() || i.len() > 64 || !i.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(EngineError::bad("interfaces", format!("{:?} is not an interface or list name", cut(i))));
            }
            if !out.iter().any(|x| x == i) {
                out.push(i.to_owned());
            }
        }
        if out.len() > MAX_MATCHES {
            return Err(EngineError::bad("interfaces", format!("at most {MAX_MATCHES}")));
        }
        t.interfaces = out;
    }
    if let Some(list) = opt_list(p, "networks")? {
        let mut out: Vec<IpNet> = Vec::new();
        for n in list {
            let net: IpNet = n
                .trim()
                .parse()
                .map_err(|_| EngineError::bad("networks", format!("{:?} is not a prefix", cut(&n))))?;
            if !out.contains(&net) {
                out.push(net);
            }
        }
        if out.len() > MAX_MATCHES {
            return Err(EngineError::bad("networks", format!("at most {MAX_MATCHES}")));
        }
        t.networks = out;
    }
    if let Given::Value(v) = given(p, "type") {
        t.kind = NetworkType::parse(text("type", v)?)
            .ok_or_else(|| EngineError::bad("type", "broadcast, ptp, nbma, ptmp or virtual-link"))?;
    }
    opt_number(p, "cost", 1, 65_535, &mut t.cost)?;
    opt_number(p, "priority", 0, 255, &mut t.priority)?;
    opt_number(p, "hello_interval", 1, 65_535, &mut t.hello_interval)?;
    opt_number(p, "dead_interval", 1, 65_535, &mut t.dead_interval)?;
    opt_number(p, "retransmit_interval", 1, 65_535, &mut t.retransmit_interval)?;
    opt_number(p, "transmit_delay", 1, 65_535, &mut t.transmit_delay)?;
    if let Some(b) = opt_boolean(p, "passive")? {
        t.passive = b;
    }
    if let Some(b) = opt_boolean(p, "mtu_ignore")? {
        t.mtu_ignore = b;
    }
    let auth_given = !matches!(given(p, "auth"), Given::Absent);
    match given(p, "auth") {
        Given::Absent => {}
        Given::Value(v) if text("auth", v)? == "none" => t.auth = None,
        Given::Unset => t.auth = None,
        Given::Value(v) => {
            let a = text("auth", v)?;
            t.auth = Some(AuthType::parse(a).ok_or_else(|| {
                EngineError::bad("auth", "none, simple, md5, sha1, sha256, sha384 or sha512")
            })?);
        }
    }
    opt_number(p, "auth_id", 0, 65_535, &mut t.auth_id)?;
    opt_name_field(p, "keychain", &mut t.keychain)?;
    match given(p, "auth_key") {
        Given::Absent => {}
        Given::Unset => t.auth_key = Sealed::default(),
        Given::Value(v) => {
            let k = v.as_str().ok_or_else(|| EngineError::bad("auth_key", "must be a string"))?;
            if !auth_given && t.auth.is_none() {
                t.auth = Some(AuthType::DEFAULT);
            }
            check_key("auth_key", k, t.auth)?;
            t.auth_key = seal(k)?;
        }
    }
    if t.keychain.is_some() && !auth_given && t.auth.is_none() {
        t.auth = Some(AuthType::DEFAULT);
    }
    opt_name_field(p, "bfd", &mut t.bfd)?;
    opt_number(p, "instance_id", 0, 255, &mut t.instance_id)?;
    match given(p, "vlink_neighbor_id") {
        Given::Absent => {}
        Given::Unset => t.vlink_neighbor_id = None,
        Given::Value(v) => {
            t.vlink_neighbor_id = Some(
                text("vlink_neighbor_id", v)?
                    .parse::<Ipv4Addr>()
                    .map_err(|_| EngineError::bad("vlink_neighbor_id", "the router id at the far end (IPv4)"))?,
            );
        }
    }
    opt_name_field(p, "vlink_transit_area", &mut t.vlink_transit_area)?;
    if let Some(c) = opt_text(p, "comment", 256)? {
        t.comment = c;
    }
    if let Some(d) = opt_boolean(p, "disabled")? {
        t.disabled = d;
    }
    match id {
        Some(id) => {
            if let Some(slot) = ospf.templates.iter_mut().find(|x| x.id == id) {
                *slot = t;
            }
            Ok(id)
        }
        None => {
            if ospf.templates.len() >= MAX_TEMPLATES {
                return Err(EngineError::bad("area", format!("at most {MAX_TEMPLATES} templates")));
            }
            let at = match given(p, "place_before") {
                Given::Value(v) => {
                    let b = parse_id("place_before", text("place_before", v)?)?;
                    Some(
                        ospf.templates
                            .iter()
                            .position(|x| x.id == b)
                            .ok_or_else(|| EngineError::bad("place_before", format!("no OSPF interface template {b}")))?,
                    )
                }
                _ => None,
            };
            t.id = ospf.next_id();
            let new = t.id;
            match at {
                Some(i) => ospf.templates.insert(i, t),
                None => ospf.templates.push(t),
            }
            Ok(new)
        }
    }
}

fn template_add(s: &mut Session, p: &Value) -> Result<Value> {
    let mut seal = sealer(s)?;
    let id = apply(&mut s.store_mut().candidate_mut().routing, p, None, &mut seal)?;
    Ok(json!({ "id": id.to_string() }))
}

fn template_set(s: &mut Session, p: &Value) -> Result<Value> {
    let id = parse_id("id", req_str(p, "id")?)?;
    let mut seal = sealer(s)?;
    let id = apply(&mut s.store_mut().candidate_mut().routing, p, Some(id), &mut seal)?;
    Ok(json!({ "id": id.to_string() }))
}

fn template_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id = parse_id("id", req_str(p, "id")?)?;
    let ospf = &mut s.store_mut().candidate_mut().routing.ospf;
    let before = ospf.templates.len();
    ospf.templates.retain(|t| t.id != id);
    if ospf.templates.len() == before {
        return Err(EngineError::bad("id", format!("no OSPF interface template {id}")));
    }
    Ok(json!({ "id": id.to_string() }))
}

fn template_move(s: &mut Session, p: &Value) -> Result<Value> {
    let id = parse_id("id", req_str(p, "id")?)?;
    let before = match given(p, "before") {
        Given::Value(v) => Some(parse_id("before", text("before", v)?)?),
        _ => None,
    };
    let ospf = &mut s.store_mut().candidate_mut().routing.ospf;
    let from = ospf
        .templates
        .iter()
        .position(|t| t.id == id)
        .ok_or_else(|| EngineError::bad("id", format!("no OSPF interface template {id}")))?;
    let t = ospf.templates.remove(from);
    let to = match before {
        Some(b) => match ospf.templates.iter().position(|x| x.id == b) {
            Some(i) => i,
            None => {
                ospf.templates.insert(from, t);
                return Err(EngineError::bad("before", format!("no OSPF interface template {b}")));
            }
        },
        None => ospf.templates.len(),
    };
    ospf.templates.insert(to, t);
    Ok(json!({ "id": id.to_string() }))
}

/// A template as JSON, the key masked.
fn row(cfg: &Config, t: &OspfTemplate, matched: Vec<Value>, warnings: Vec<String>) -> Value {
    let ospf = &cfg.routing.ospf;
    let area = ospf.areas.get(&t.area);
    let inst = area.and_then(|a| ospf.instances.get(&a.instance));
    json!({
        "id": t.id.to_string(),
        "area": t.area,
        "instance": area.map(|a| a.instance.clone()),
        "version": inst.map(|i| i.version.number()),
        "area_id": area.map(|a| a.area_id.to_string()),
        "interfaces": t.interfaces,
        "networks": t.networks.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "type": t.kind.name(),
        "cost": t.cost,
        "priority": t.priority,
        "hello_interval": t.hello_interval,
        "dead_interval": t.dead_interval,
        "retransmit_interval": t.retransmit_interval,
        "transmit_delay": t.transmit_delay,
        "passive": t.passive,
        "mtu_ignore": t.mtu_ignore,
        "auth": t.auth.map(|a| a.name()),
        "auth_id": t.auth_id,
        "key_set": t.has_key(),
        "keychain": t.keychain,
        "bfd": t.bfd,
        "instance_id": t.instance_id,
        "vlink_neighbor_id": t.vlink_neighbor_id.map(|r| r.to_string()),
        "vlink_transit_area": t.vlink_transit_area,
        "matched": matched,
        "warnings": warnings,
        "disabled": t.disabled,
        "comment": t.comment,
    })
}

/// What the list and the preview look up per template, built once (per
/// template it would be O(templates × interfaces)).
struct Index<'a> {
    binds: Vec<bind::Binding<'a>>,
    /// Template → its bindings.
    by_template: HashMap<ItemId, Vec<usize>>,
    /// (instance, interface) → the binding.
    by_iface: HashMap<(&'a str, String), usize>,
    /// Template → its position (the first match wins).
    pos: HashMap<ItemId, usize>,
    v4: std::collections::BTreeMap<&'a corerouter_model::types::IfName, Vec<IpNet>>,
}

impl<'a> Index<'a> {
    fn new(cfg: &'a Config) -> Self {
        let binds = bindings(cfg);
        let mut by_template: HashMap<ItemId, Vec<usize>> = HashMap::new();
        let mut by_iface = HashMap::new();
        for (i, b) in binds.iter().enumerate() {
            by_template.entry(b.template.id).or_default().push(i);
            by_iface.insert((b.instance.name.as_str(), b.interface.to_string()), i);
        }
        let pos = cfg.routing.ospf.templates.iter().enumerate().map(|(i, x)| (x.id, i)).collect();
        Index { binds, by_template, by_iface, pos, v4: bind::addresses(cfg, false) }
    }
}

/// What a template takes now and what to say about it: the matched
/// interfaces (with the suggested network type) and the warnings.
fn assess(cfg: &Config, ix: &Index<'_>, t: &OspfTemplate) -> (Vec<Value>, Vec<(String, &'static str, &'static str)>) {
    let mut matched = Vec::new();
    let mut warn: Vec<(String, &'static str, &'static str)> = Vec::new();
    let mine: Vec<&bind::Binding<'_>> = ix
        .by_template
        .get(&t.id)
        .map(|v| v.iter().filter_map(|i| ix.binds.get(*i)).collect())
        .unwrap_or_default();
    for b in &mine {
        let suggested = bind::suggest_type_in(cfg, &ix.v4, &b.interface);
        let mut m = Map::new();
        m.insert("interface".into(), json!(b.interface.to_string()));
        m.insert("why".into(), json!(b.why));
        if let Some((st, why)) = &suggested {
            m.insert("suggested_type".into(), json!(st.name()));
            if *st != t.kind && t.kind != NetworkType::VirtualLink {
                warn.push((
                    format!("{}: type {} suggested ({why}): no DR election, the adjacency comes up sooner", b.interface, st.name()),
                    "type",
                    "suggest-type",
                ));
            }
        }
        if !t.passive
            && let Some(why) = bind::client_facing(cfg, &b.interface)
        {
            warn.push((
                format!("{} faces subscribers ({why}): passive suggested, so no customer can form an adjacency and inject routes", b.interface),
                "passive",
                "suggest-passive",
            ));
        }
        matched.push(Value::Object(m));
    }
    if !t.passive && t.kind != NetworkType::VirtualLink && !mine.is_empty() {
        match t.auth {
            None => warn.push((
                "no authentication on an active interface: anyone on the link can form an adjacency and inject routes (sha256 recommended, RFC 5709)".into(),
                "auth",
                "no-auth",
            )),
            Some(a) if a.is_weak() => warn.push((
                format!("{} is weak (the key travels in clear or MD5 is broken): sha256 recommended (RFC 5709, RFC 6039)", a.name()),
                "auth",
                "weak-auth",
            )),
            _ => {}
        }
    }
    // Interfaces it names that an earlier template already took.
    if let Some((inst, _)) = bind::area_of(cfg, t) {
        for name in &t.interfaces {
            let Some(b) = ix.by_iface.get(&(inst.name.as_str(), name.clone())).and_then(|i| ix.binds.get(*i)) else {
                continue;
            };
            if b.template.id != t.id && ix.pos.get(&b.template.id) < ix.pos.get(&t.id) {
                warn.push((
                    format!("{} is taken by template {} (the first match wins; move this one up)", b.interface, b.template.id),
                    "interfaces",
                    "shadowed",
                ));
            }
        }
    }
    (matched, warn)
}

fn template_list(s: &mut Session, _: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    let ix = Index::new(cfg);
    let rows = cfg
        .routing
        .ospf
        .templates
        .iter()
        .map(|t| {
            let (matched, warn) = assess(cfg, &ix, t);
            row(cfg, t, matched, warn.into_iter().map(|w| w.0).collect())
        })
        .collect();
    Ok(Value::Array(rows))
}

/// The modal's preview: the change applied to a copy, validated, with the
/// interfaces it takes and the adjacencies that drop. Never an error for
/// bad input: it becomes a check.
fn template_check(s: &mut Session, raw: &Value) -> Result<Value> {
    let mut checks: Vec<Value> = Vec::new();
    let mut computed: Vec<Value> = Vec::new();
    let check = |level: &str, check: &str, message: String, param: &str| {
        json!({"level": level, "check": check, "message": message, "param": param})
    };
    let id = match given(raw, "id") {
        Given::Value(v) => text("id", v).ok().and_then(|i| i.parse::<ItemId>().ok()),
        _ => None,
    };
    let mut cfg: Config = s.store().candidate().clone();
    let mut fake = fake_seal;
    let tid = match apply(&mut cfg.routing, raw, id, &mut fake) {
        Ok(t) => t,
        Err(e) => {
            let (param, msg) = match &e {
                EngineError::BadParam { param, reason } => (param.clone(), reason.clone()),
                other => (String::new(), other.to_string()),
            };
            checks.push(check("error", "params", msg, &param));
            return Ok(json!({"computed": computed, "checks": checks, "commands": [], "risk": null, "matched": [], "dropping": []}));
        }
    };
    let prefix = format!("routing.ospf.templates[{tid}]");
    for issue in corerouter_proto_ospf::validate(&cfg) {
        if let Some(rest) = issue.path.strip_prefix(&prefix) {
            let param = rest.trim_start_matches('.');
            checks.push(check("error", "validate", issue.message, param));
        }
    }
    let Some(t) = cfg.routing.ospf.templates.iter().find(|t| t.id == tid).cloned() else {
        return Ok(json!({"computed": computed, "checks": checks, "commands": [], "risk": null, "matched": [], "dropping": []}));
    };
    let ix = Index::new(&cfg);
    let (matched, warn) = assess(&cfg, &ix, &t);
    if t.auth.is_some_and(AuthType::is_crypto) && t.keychain.is_none() && t.auth_id.is_none() {
        checks.push(check(
            "info",
            "auth-id",
            "key id 1 is used (RouterOS 7 sends 0 when auth-id is unset): set auth_id to what the neighbors use".into(),
            "auth_id",
        ));
    }
    let names: Vec<String> = matched
        .iter()
        .filter_map(|m| m.get("interface").and_then(Value::as_str).map(str::to_owned))
        .collect();
    if let Some((inst, area)) = bind::area_of(&cfg, &t) {
        computed.push(json!({"label": "Instance", "value": format!("{} (OSPFv{})", inst.name, inst.version.number())}));
        computed.push(json!({"label": "Area", "value": format!("{} ({}, {})", area.name, area.area_id, area.kind.name())}));
    }
    computed.push(json!({
        "label": "Interfaces",
        "value": if names.is_empty() { "none match yet".to_owned() } else { names.join(", ") },
    }));
    if names.is_empty() && t.kind != NetworkType::VirtualLink && !t.disabled {
        checks.push(check("warning", "matches", "no interface matches this template now".into(), "interfaces"));
    }
    for (msg, param, what) in warn {
        checks.push(check("warning", what, msg, param));
    }
    if let Some(b) = &t.bfd {
        // G3.6 owns the profiles and the sessions; tying a session's fall
        // to the adjacency is G3.6b.
        if let Some(p) = cfg.routing.bfd.profile(b) {
            checks.push(check(
                "info",
                "bfd",
                format!(
                    "BFD profile {b}: detection in {} ms (the adjacency follows the BFD session once G3.6b ties them)",
                    p.detect_ms()
                ),
                "bfd",
            ));
        }
    }
    // What the commit does to the adjacencies (against the running config:
    // other pending changes count too).
    let changes = impact::changes(s.store().running(), &cfg);
    let dropping = impact::dropping(&changes);
    for c in changes.iter().filter(|c| c.what == "enters" || !c.drops) {
        checks.push(check("info", c.what, c.message.clone(), ""));
    }
    let risk = (!dropping.is_empty()).then(|| {
        let msgs: Vec<&str> = changes.iter().filter(|c| c.drops).map(|c| c.message.as_str()).take(6).collect();
        format!(
            "the OSPF adjacencies on {} go down: {}. Routes through them are withdrawn until both ends match; use Safe Mode to roll back on its own if this cuts the session",
            dropping.join(", "),
            msgs.join("; ")
        )
    });
    let ok = !checks.iter().any(|c| c.get("level").and_then(Value::as_str) == Some("error"));
    let mut params = raw.clone();
    if let Some(o) = params.as_object_mut() {
        // A key left empty while editing keeps the router's (write-only field).
        if id.is_some() && o.get("auth_key").is_some_and(|v| v.as_str() == Some("")) {
            o.remove("auth_key");
        }
        if id.is_none() {
            o.remove("id");
        }
        // Form texts as the command wants them.
        for (k, v) in o.iter_mut() {
            if let Value::String(t) = v
                && matches!(k.as_str(), "passive" | "mtu_ignore" | "disabled")
            {
                *v = Value::Bool(t == "yes" || t == "true");
            }
        }
    }
    let command = if id.is_some() {
        "routing.ospf.interface-template.set"
    } else {
        "routing.ospf.interface-template.add"
    };
    Ok(json!({
        "computed": computed,
        "checks": checks,
        "commands": if ok { vec![json!({"command": command, "params": params})] } else { Vec::new() },
        "risk": risk,
        "matched": matched,
        "dropping": dropping,
    }))
}

fn impact_cmd(s: &mut Session, _: &Value) -> Result<Value> {
    let changes = impact::changes(s.store().running(), s.store().candidate());
    let dropping = impact::dropping(&changes);
    Ok(json!({
        "changes": changes.iter().map(|c| json!({
            "instance": c.instance,
            "interface": c.interface,
            "what": c.what,
            "message": c.message,
            "drops": c.drops,
        })).collect::<Vec<_>>(),
        "safe_mode": !dropping.is_empty(),
        "dropping": dropping,
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
        s
    }

    #[test]
    fn a_key_alone_means_sha256_and_never_comes_back() {
        let mut s = lab();
        let r = s
            .execute("routing.ospf.interface-template.add", &json!({"area": "backbone", "interfaces": "ether1", "auth_key": "s3cretkey"}))
            .unwrap();
        let id = r["id"].as_str().unwrap().to_owned();
        let l = s.execute("routing.ospf.interface-template.list", &json!({})).unwrap();
        assert_eq!(l[0]["auth"], "sha256");
        assert_eq!(l[0]["key_set"], true);
        let text = serde_json::to_string(&l).unwrap();
        assert!(!text.contains("s3cretkey"));
        let cfg = serde_json::to_string(s.store().running()).unwrap();
        assert!(!cfg.contains("s3cretkey"), "the key is sealed in the config");
        assert!(!serde_json::to_string(&s.journal()).unwrap().contains("s3cretkey"));
        assert_eq!(l[0]["matched"][0]["interface"], "ether1");
        s.execute("routing.ospf.interface-template.remove", &json!({"id": id})).unwrap();
    }

    #[test]
    fn check_previews_matches_suggestions_and_drops() {
        let mut s = lab();
        let c = s
            .execute("routing.ospf.interface-template.check", &json!({"area": "backbone", "networks": "10.0.0.0/16"}))
            .unwrap();
        assert_eq!(c["matched"].as_array().unwrap().len(), 2, "{c}");
        let msgs = serde_json::to_string(&c["checks"]).unwrap();
        assert!(msgs.contains("no-auth"), "{msgs}");
        assert!(msgs.contains("type ptp suggested"), "{msgs}");
        assert!(c["risk"].is_null());
        assert_eq!(c["commands"][0]["command"], "routing.ospf.interface-template.add");
        // Apply, then preview a change of area: the adjacency drops.
        let r = s
            .execute("routing.ospf.interface-template.add", &json!({"area": "backbone", "networks": "10.0.0.0/16", "auth": "sha256", "auth_key": "k1"}))
            .unwrap();
        s.execute("routing.ospf.area.add", &json!({"name": "a1", "instance": "v2", "area_id": "1"})).unwrap();
        let c = s
            .execute("routing.ospf.interface-template.check", &json!({"id": r["id"], "area": "a1"}))
            .unwrap();
        assert!(c["risk"].as_str().unwrap().contains("ether1"), "{c}");
        assert_eq!(c["dropping"], json!(["ether1", "ether2"]));
        // Bad input becomes a check, not an error.
        let c = s
            .execute("routing.ospf.interface-template.check", &json!({"area": "backbone", "cost": "x"}))
            .unwrap();
        assert_eq!(c["checks"][0]["level"], "error");
        assert_eq!(c["checks"][0]["param"], "cost");
    }

    #[test]
    fn errors_and_rollback() {
        let mut s = lab();
        let e = s
            .execute("routing.ospf.interface-template.add", &json!({"area": "backbone", "interfaces": "ether1", "auth": "simple", "auth_key": "way-too-long"}))
            .unwrap_err();
        assert!(e.to_string().contains("RFC 2328 §D.3"), "{e}");
        assert!(!e.to_string().contains("way-too-long"));
        let e = s
            .execute("routing.ospf.interface-template.add", &json!({"area": "nope"}))
            .unwrap_err();
        assert!(e.to_string().contains("no OSPF area"), "{e}");
        // Refused at commit: matches nothing; the candidate is left as it was.
        let before = s.store().running().routing.ospf.templates.len();
        let e = s.execute("routing.ospf.interface-template.add", &json!({"area": "backbone"})).unwrap_err();
        assert!(e.to_string().contains("matches nothing"), "{e}");
        assert_eq!(s.store().running().routing.ospf.templates.len(), before);
        assert_eq!(s.store().candidate().routing.ospf.templates.len(), before);
    }

    #[test]
    fn order_and_move() {
        let mut s = lab();
        let a = s.execute("routing.ospf.interface-template.add", &json!({"area": "backbone", "interfaces": "ether1"})).unwrap();
        let b = s
            .execute("routing.ospf.interface-template.add", &json!({"area": "backbone", "interfaces": "ether1", "passive": true, "place_before": a["id"]}))
            .unwrap();
        let l = s.execute("routing.ospf.interface-template.list", &json!({})).unwrap();
        assert_eq!(l[0]["id"], b["id"]);
        assert_eq!(l[0]["matched"][0]["interface"], "ether1");
        assert!(l[1]["warnings"][0].as_str().unwrap().contains("taken by template"), "{l}");
        s.execute("routing.ospf.interface-template.move", &json!({"id": b["id"]})).unwrap();
        let l = s.execute("routing.ospf.interface-template.list", &json!({})).unwrap();
        assert_eq!(l[1]["id"], b["id"]);
        let i = s.execute("routing.ospf.impact", &json!({})).unwrap();
        assert_eq!(i["safe_mode"], false);
    }
}
