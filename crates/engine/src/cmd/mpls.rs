//! /mpls (G3.5), RouterOS v7 names: `settings`, `interface`, the
//! `forwarding-table`, and `static` (label switching entries CoreRouter
//! programs itself: Cisco `mpls static binding`, Junos static LSPs).
//! LDP is in `mpls_ldp.rs`.
//!
//! Without MPLS in the kernel (Linux: no `mpls_router`) the commands that
//! add are disabled with the reason, as `ip.vrf.add` is without VRF.

use std::net::IpAddr;

use corerouter_model::mpls::{
    ALL, FIRST_UNRESERVED, MAX_LABEL, MAX_PUSH, MAX_STATIC, MplsInterface, StaticLsp,
};
use corerouter_model::{Config, IfName};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text, opt_u32, req_str};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

/// Rows of one forwarding-table page at most (the GUI asks for 500).
pub const MAX_LIMIT: u32 = 5_000;
const DEFAULT_LIMIT: u32 = 500;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "mpls.settings.get", "MPLS Settings", ["MPLS", "Settings"], None,
        "{} → {dynamic_label_range, propagate_ttl, payload_mtu, lsp_ping_responder, lsp_ping_rate, lsp_ping_counters (null without a responder: {running, heard, replied, rate_limited, ignored, codes, error, failed}), icmp_ttl_exceeded, icmp_too_big, icmp_rate, icmp_rate_per_source, icmp_counters (null without a responder: {expired, too_big, sent, too_big_sent, rate_limited, rate_limited_source, dropped, reasons, error}), platform_labels (Linux table size), available, why?}",
        always, settings_get),
    cmd!("mpls.settings.set", "Set MPLS Settings", [], None,
        "{dynamic_label_range?: string (\"16-1048575\": the labels LDP hands out; /mpls static uses labels above it), propagate_ttl?: bool (copy the IP TTL into labels, RFC 3032 §2.4.3), payload_mtu?: u32 (576..=65535, the IP packet size the MTU check assumes; default 1500), lsp_ping_responder?: bool (answer MPLS echo requests, RFC 8029; default yes), lsp_ping_rate?: u32 (1..=10000 echo replies per second, default 100), icmp_ttl_exceeded?: bool (ICMP time exceeded with the label stack for labeled packets whose TTL expires here, RFC 4950; default yes), icmp_too_big?: bool (ICMP fragmentation needed / packet too big for labeled packets larger than the MTU of their way out, RFC 3032 §3.4; default yes), icmp_rate?: u32 (1..=10000 of those ICMP errors per second in all, default 100), icmp_rate_per_source?: u32 (1..=10000 per second to one source, default 10)} → {dynamic_label_range, propagate_ttl, payload_mtu, lsp_ping_responder, lsp_ping_rate, icmp_ttl_exceeded, icmp_too_big, icmp_rate, icmp_rate_per_source}",
        mpls_supported, settings_set),
    cmd!("mpls.interface.add", "Add MPLS Interface", ["MPLS", "Interface"], None,
        "{interface: string (a name, or all), input?: bool (accept labeled packets; default yes), disabled?: bool, comment?: string} → {interface}",
        mpls_supported, interface_add),
    cmd!("mpls.interface.set", "Set MPLS Interface", [], None,
        "{id: string (the interface, or all), input?: bool, disabled?: bool, comment?: string} → {interface}",
        always, interface_set),
    cmd!("mpls.interface.remove", "Remove MPLS Interface", [], None,
        "{id: string (the interface, or all)} → {interface}",
        always, interface_remove),
    cmd!(query "mpls.interface.list", "MPLS Interfaces", ["MPLS", "Interface"], None,
        "{} → [{interface, input, disabled, comment, mtu?, input_now (labeled packets accepted there now, from this and LDP)}]",
        always, interface_list),
    cmd!("mpls.static.add", "Add Static LSP", ["MPLS", "Static"], None,
        "{label: u32 (incoming, 16..=1048575, outside the dynamic range), nexthop: ip, interface?: string, out_labels?: [u32] | string (\"100 200\", top first; empty or implicit-null: pop), disabled?: bool, comment?: string} → {label}",
        mpls_supported, static_add),
    cmd!("mpls.static.set", "Set Static LSP", [], None,
        "{id: u32 | string (the incoming label), nexthop?: ip, interface?: string | null, out_labels?: [u32] | string, disabled?: bool, comment?: string} → {label}",
        always, static_set),
    cmd!("mpls.static.remove", "Remove Static LSP", [], None,
        "{id: u32 | string (the incoming label)} → {label}",
        always, static_remove),
    cmd!(query "mpls.static.list", "Static LSPs", ["MPLS", "Static"], None,
        "{} → [{label, nexthop, interface?, out_labels, out_label (text), disabled, comment}]",
        always, static_list),
    cmd!(query "mpls.static.preview", "Check Static LSP", [], None,
        "{id?: string (the label being edited), label?: u32 | string, nexthop?: string, interface?: string, out_labels?: [u32] | string, disabled?: bool | yes | no, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}]} (form texts accepted; never an error: bad input is a check)",
        always, static_preview),
    cmd!(query "mpls.forwarding-table.page", "MPLS Forwarding Table", ["MPLS", "Forwarding Table"], None,
        "{find?: string (FEC, label, next hop or interface contains it), origin?: string (ldp | static | bgp | other), unlabeled?: bool (only FECs without an outgoing label), offset?: u32, limit?: u32 (1..=5000, default 500)} → {total, offset, rows: [{fec?, in_label?, out_label, out_labels, nexthop?, interface?, peer?, origin, installed, igp_sync?, reason?, mtu?}], summary: {rows, fecs, labeled, unlabeled, egress, static, mtu_warnings, labels (kernel entries)}, ldp: {running, daemon (a routing daemon reports), error?}, note?, available, why?}",
        always, forwarding_page),
];

/// The platform switches labels (Linux: `mpls_router`).
pub(super) fn mpls_supported(s: &Session) -> std::result::Result<(), String> {
    if s.hal().features().mpls {
        Ok(())
    } else {
        Err(corerouter_hal::mpls::NO_MPLS.to_owned())
    }
}

/// `"16-1048575"` or `[16, 1048575]`.
fn range(p: &Value, key: &str) -> Result<Option<(u32, u32)>> {
    let bad = || EngineError::bad(key, "a range \"16-1048575\" (two labels, start ≤ end)");
    let (lo, hi) = match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => {
            let (a, b) = s.split_once('-').ok_or_else(bad)?;
            (a.trim().parse::<u32>().map_err(|_| bad())?, b.trim().parse::<u32>().map_err(|_| bad())?)
        }
        Some(Value::Array(a)) => match a.as_slice() {
            [a, b] => (
                a.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(bad)?,
                b.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(bad)?,
            ),
            _ => return Err(bad()),
        },
        Some(_) => return Err(bad()),
    };
    if lo < FIRST_UNRESERVED || lo > hi || hi > MAX_LABEL {
        return Err(EngineError::bad(
            key,
            format!("{lo}-{hi}: within {FIRST_UNRESERVED}-{MAX_LABEL} (RFC 3032 §2.1: 0-15 are reserved), start ≤ end"),
        ));
    }
    Ok(Some((lo, hi)))
}

/// A label stack: `[100, 200]`, `"100 200"`, `"100,200"`; empty,
/// `implicit-null` or `pop`: no label (pop).
pub(super) fn stack(p: &Value, key: &str) -> Result<Option<Vec<u32>>> {
    let bad = |what: &str| EngineError::bad(key, format!("{what}: labels top first, e.g. \"100 200\" or [100, 200]; empty pops"));
    let raw: Vec<String> = match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() || matches!(t, "implicit-null" | "impl-null" | "pop" | "implicit-null (pop)") {
                return Ok(Some(Vec::new()));
            }
            t.split([' ', ',', '/']).filter(|x| !x.is_empty()).map(str::to_owned).collect()
        }
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| v.as_u64().map(|n| n.to_string()).ok_or_else(|| bad("not a number")))
            .collect::<Result<_>>()?,
        Some(_) => return Err(bad("not a label stack")),
    };
    if raw.len() > MAX_PUSH {
        return Err(EngineError::bad(key, format!("at most {MAX_PUSH} labels (Linux MAX_NEW_LABELS)")));
    }
    let mut out = Vec::with_capacity(raw.len());
    for r in raw {
        let l = match r.as_str() {
            "explicit-null" | "expl-null" => 0,
            "expl-null6" | "ipv6-explicit-null" => 2,
            n => n.parse::<u32>().map_err(|_| bad(&format!("'{}' is not a label", n.chars().take(16).collect::<String>())))?,
        };
        if !corerouter_proto_mpls::out_label_ok(l) {
            return Err(EngineError::bad(
                key,
                format!("label {l}: use 0, 2 or {FIRST_UNRESERVED}..{MAX_LABEL} (RFC 3032 §2.1; 3 is implicit NULL: leave the stack empty to pop)"),
            ));
        }
        out.push(l);
    }
    Ok(Some(out))
}

fn interface_of(cfg: &Config, key: &str, name: &str) -> Result<IfName> {
    let n: IfName = name
        .parse()
        .map_err(|e: corerouter_model::ParseError| EngineError::bad(key, e.to_string()))?;
    if !cfg.interfaces.contains_key(&n) {
        return Err(EngineError::bad(key, format!("no interface '{n}' (see interface.list)")));
    }
    Ok(n)
}

// ---- settings ----

fn settings_get(s: &mut Session, _: &Value) -> Result<Value> {
    let st = s.store().candidate().routing.mpls.settings.clone();
    let why = mpls_supported(s).err();
    Ok(json!({
        "dynamic_label_range": format!("{}-{}", st.dynamic_label_range.0, st.dynamic_label_range.1),
        "propagate_ttl": st.propagate_ttl,
        "payload_mtu": st.payload_mtu,
        "lsp_ping_responder": st.lsp_ping_responder,
        "lsp_ping_rate": st.lsp_ping_rate,
        "lsp_ping_counters": crate::lsp_responder::counters_json(s),
        "icmp_ttl_exceeded": st.icmp_ttl_exceeded,
        "icmp_too_big": st.icmp_too_big,
        "icmp_rate": st.icmp_rate,
        "icmp_rate_per_source": st.icmp_rate_per_source,
        "icmp_counters": crate::lsp_responder::icmp_json(s),
        "platform_labels": st.platform_labels(),
        "available": why.is_none(),
        "why": why,
    }))
}

fn settings_set(s: &mut Session, p: &Value) -> Result<Value> {
    let r = range(p, "dynamic_label_range")?;
    let ttl = opt_bool(p, "propagate_ttl")?;
    let payload = opt_u32(p, "payload_mtu")?;
    if let Some(m) = payload
        && !(576..=65_535).contains(&m)
    {
        return Err(EngineError::bad("payload_mtu", "576..=65535 bytes"));
    }
    let responder = opt_bool(p, "lsp_ping_responder")?;
    let rate = opt_u32(p, "lsp_ping_rate")?;
    if let Some(r) = rate
        && !(1..=corerouter_model::mpls::MAX_LSP_PING_RATE).contains(&r)
    {
        return Err(EngineError::bad(
            "lsp_ping_rate",
            format!("1..={} replies per second", corerouter_model::mpls::MAX_LSP_PING_RATE),
        ));
    }
    let icmp = opt_bool(p, "icmp_ttl_exceeded")?;
    let too_big = opt_bool(p, "icmp_too_big")?;
    let mut rates = [None; 2];
    for (slot, key) in rates.iter_mut().zip(["icmp_rate", "icmp_rate_per_source"]) {
        *slot = opt_u32(p, key)?;
        if let Some(r) = *slot
            && !(1..=corerouter_model::mpls::MAX_ICMP_RATE).contains(&r)
        {
            return Err(EngineError::bad(
                key,
                format!("1..={} errors per second", corerouter_model::mpls::MAX_ICMP_RATE),
            ));
        }
    }
    let [icmp_rate, per_source] = rates;
    let st = &mut s.store_mut().candidate_mut().routing.mpls.settings;
    if let Some(v) = icmp {
        st.icmp_ttl_exceeded = v;
    }
    if let Some(r) = icmp_rate {
        st.icmp_rate = r;
    }
    if let Some(r) = per_source {
        st.icmp_rate_per_source = r;
    }
    if let Some(v) = too_big {
        st.icmp_too_big = v;
    }
    if let Some(v) = responder {
        st.lsp_ping_responder = v;
    }
    if let Some(r) = rate {
        st.lsp_ping_rate = r;
    }
    if let Some(r) = r {
        st.dynamic_label_range = r;
    }
    if let Some(t) = ttl {
        st.propagate_ttl = t;
    }
    if let Some(m) = payload {
        st.payload_mtu = m;
    }
    Ok(json!({
        "dynamic_label_range": format!("{}-{}", st.dynamic_label_range.0, st.dynamic_label_range.1),
        "propagate_ttl": st.propagate_ttl,
        "payload_mtu": st.payload_mtu,
        "lsp_ping_responder": st.lsp_ping_responder,
        "lsp_ping_rate": st.lsp_ping_rate,
        "icmp_ttl_exceeded": st.icmp_ttl_exceeded,
        "icmp_too_big": st.icmp_too_big,
        "icmp_rate": st.icmp_rate,
        "icmp_rate_per_source": st.icmp_rate_per_source,
    }))
}

// ---- /mpls interface ----

fn mpls_if_key(cfg: &Config, key: &str, p: &Value) -> Result<String> {
    let name = req_str(p, key)?;
    if name == ALL {
        return Ok(ALL.to_owned());
    }
    Ok(interface_of(cfg, key, name)?.to_string())
}

fn interface_add(s: &mut Session, p: &Value) -> Result<Value> {
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let input = opt_bool(p, "input")?.unwrap_or(true);
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let cfg = s.store_mut().candidate_mut();
    let key = mpls_if_key(cfg, "interface", p)?;
    let m = &mut cfg.routing.mpls;
    if m.interfaces.contains_key(&key) {
        return Err(EngineError::bad("interface", format!("'{key}' already has an entry (mpls.interface.set)")));
    }
    m.interfaces.insert(key.clone(), MplsInterface { input, disabled, comment });
    Ok(json!({ "interface": key }))
}

fn existing_if<'a>(m: &'a mut corerouter_model::mpls::Mpls, p: &Value) -> Result<(String, &'a mut MplsInterface)> {
    let id = req_str(p, "id")?.to_owned();
    let e = m
        .interfaces
        .get_mut(&id)
        .ok_or_else(|| EngineError::bad("id", format!("no MPLS interface '{}' (see mpls.interface.list)", id.chars().take(32).collect::<String>())))?;
    Ok((id, e))
}

fn interface_set(s: &mut Session, p: &Value) -> Result<Value> {
    let comment = opt_text(p, "comment", 256)?;
    let input = opt_bool(p, "input")?;
    let disabled = opt_bool(p, "disabled")?;
    let (id, e) = existing_if(&mut s.store_mut().candidate_mut().routing.mpls, p)?;
    if let Some(v) = input {
        e.input = v;
    }
    if let Some(v) = disabled {
        e.disabled = v;
    }
    if let Some(v) = comment {
        e.comment = v;
    }
    Ok(json!({ "interface": id }))
}

fn interface_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let m = &mut s.store_mut().candidate_mut().routing.mpls;
    let (id, _) = existing_if(m, p)?;
    m.interfaces.remove(&id);
    Ok(json!({ "interface": id }))
}

fn interface_list(s: &mut Session, _: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    let m = &cfg.routing.mpls;
    Ok(Value::Array(
        m.interfaces
            .iter()
            .map(|(k, e)| {
                let name = k.parse::<IfName>().ok();
                json!({
                    "interface": k,
                    "input": e.input,
                    "disabled": e.disabled,
                    "comment": e.comment,
                    "mtu": name.as_ref().and_then(|n| cfg.interfaces.get(n)).map(|i| i.mtu),
                    "input_now": name.as_ref().map_or(!e.disabled && e.input, |n| m.input_on(n)),
                })
            })
            .collect(),
    ))
}

// ---- /mpls static ----

fn label_id(p: &Value) -> Result<u32> {
    let bad = || EngineError::bad("id", "the incoming label (see mpls.static.list)");
    match p.get("id") {
        Some(Value::Number(n)) => n.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(bad),
        Some(Value::String(s)) => s.trim().parse().map_err(|_| bad()),
        None | Some(Value::Null) => Err(EngineError::bad("id", "is required")),
        Some(_) => Err(bad()),
    }
}

fn nexthop(p: &Value) -> Result<Option<IpAddr>> {
    match opt_str(p, "nexthop")? {
        None => Ok(None),
        Some(t) => t
            .trim()
            .parse::<IpAddr>()
            .map(Some)
            .map_err(|_| EngineError::bad("nexthop", "an IPv4 or IPv6 address")),
    }
}

fn static_add(s: &mut Session, p: &Value) -> Result<Value> {
    static_add_cfg(s.store_mut().candidate_mut(), p)
}

pub(super) fn static_add_cfg(cfg: &mut Config, p: &Value) -> Result<Value> {
    let label = opt_u32(p, "label")?.ok_or_else(|| EngineError::bad("label", "is required"))?;
    let nh = nexthop(p)?.ok_or_else(|| EngineError::bad("nexthop", "is required"))?;
    let out = stack(p, "out_labels")?.unwrap_or_default();
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let interface = match opt_str(p, "interface")? {
        Some(n) => Some(interface_of(cfg, "interface", n)?),
        None => None,
    };
    let m = &mut cfg.routing.mpls;
    check_label(m, label)?;
    if m.statics.contains_key(&label) {
        return Err(EngineError::bad("label", format!("label {label} already has an entry (mpls.static.set)")));
    }
    if m.statics.len() >= MAX_STATIC {
        return Err(EngineError::bad("label", format!("at most {MAX_STATIC} static entries")));
    }
    m.statics.insert(label, StaticLsp { nexthop: nh, interface, out_labels: out, disabled, comment });
    Ok(json!({ "label": label }))
}

/// An incoming label a static entry may take: unreserved and outside the
/// range LDP hands out (they would collide).
fn check_label(m: &corerouter_model::mpls::Mpls, label: u32) -> Result<()> {
    if !(FIRST_UNRESERVED..=MAX_LABEL).contains(&label) {
        return Err(EngineError::bad("label", format!("{FIRST_UNRESERVED}..={MAX_LABEL} (RFC 3032 §2.1: 0-15 are reserved)")));
    }
    let (lo, hi) = m.settings.dynamic_label_range;
    if (lo..=hi).contains(&label) {
        let suggest = if hi < MAX_LABEL { format!("use {}..={MAX_LABEL}", hi + 1) } else { "shrink it first: mpls.settings.set dynamic_label_range=16-99999".to_owned() };
        return Err(EngineError::bad(
            "label",
            format!("{label} is inside the dynamic range {lo}-{hi} that LDP hands out; {suggest}"),
        ));
    }
    Ok(())
}

fn static_set(s: &mut Session, p: &Value) -> Result<Value> {
    static_set_cfg(s.store_mut().candidate_mut(), p)
}

pub(super) fn static_set_cfg(cfg: &mut Config, p: &Value) -> Result<Value> {
    let label = label_id(p)?;
    let nh = nexthop(p)?;
    let out = stack(p, "out_labels")?;
    let comment = opt_text(p, "comment", 256)?;
    let disabled = opt_bool(p, "disabled")?;
    let interface = match p.get("interface") {
        None => None,
        Some(Value::Null) => Some(None),
        Some(_) => Some(Some(interface_of(cfg, "interface", super::args::req_str(p, "interface")?)?)),
    };
    let e = cfg
        .routing
        .mpls
        .statics
        .get_mut(&label)
        .ok_or_else(|| EngineError::bad("id", format!("no static entry for label {label} (see mpls.static.list)")))?;
    if let Some(v) = nh {
        e.nexthop = v;
    }
    if let Some(v) = interface {
        e.interface = v;
    }
    if let Some(v) = out {
        e.out_labels = v;
    }
    if let Some(v) = disabled {
        e.disabled = v;
    }
    if let Some(v) = comment {
        e.comment = v;
    }
    Ok(json!({ "label": label }))
}

fn static_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let label = label_id(p)?;
    if s.store_mut().candidate_mut().routing.mpls.statics.remove(&label).is_none() {
        return Err(EngineError::bad("id", format!("no static entry for label {label} (see mpls.static.list)")));
    }
    Ok(json!({ "label": label }))
}

fn static_list(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(Value::Array(
        s.store()
            .candidate()
            .routing
            .mpls
            .statics
            .iter()
            .map(|(l, e)| {
                json!({
                    "label": l,
                    "nexthop": e.nexthop,
                    "interface": e.interface,
                    "out_labels": e.out_labels,
                    "out_label": corerouter_model::mpls::stack_text(&e.out_labels),
                    "disabled": e.disabled,
                    "comment": e.comment,
                })
            })
            .collect(),
    ))
}

/// A form's texts as the commands take them: numbers from text, `yes`/`no`
/// as booleans; an empty number is left out, an empty `nullable` is null.
pub(super) fn normalize(raw: &Value, numeric: &[&str], nullable: &[&str]) -> Value {
    let mut out = serde_json::Map::new();
    if let Some(o) = raw.as_object() {
        for (k, v) in o {
            let v = match v {
                Value::String(t) if numeric.contains(&k.as_str()) => {
                    let t = t.trim();
                    if t.is_empty() {
                        continue;
                    }
                    t.parse::<u64>().map_or_else(|_| json!(t), |n| json!(n))
                }
                Value::String(t) if nullable.contains(&k.as_str()) && t.trim().is_empty() => Value::Null,
                Value::String(t) if t == "yes" || t == "no" => json!(t == "yes"),
                v => v.clone(),
            };
            out.insert(k.clone(), v);
        }
    }
    Value::Object(out)
}

/// The preview of a list modal: `run` on a copy of the candidate, its
/// error as a check under the field, then `/mpls` validation and what
/// FRR would get; the command to send.
pub(super) fn preview_on(
    s: &Session,
    p: Value,
    command: &str,
    run: &dyn Fn(&mut Config, &Value) -> Result<Value>,
) -> Value {
    let check = |level: &str, check: &str, message: String, param: &str| {
        json!({"level": level, "check": check, "message": message, "param": param})
    };
    let mut cfg = s.store().candidate().clone();
    let mut checks = Vec::new();
    let mut computed = Vec::new();
    let mut commands = Vec::new();
    match run(&mut cfg, &p) {
        Err(EngineError::BadParam { param, reason }) => checks.push(check("error", "param", reason, &param)),
        Err(e) => checks.push(check("error", "param", e.to_string(), "")),
        Ok(_) => {
            // Only what this change brings (the candidate's own issues are
            // not this form's).
            let before = corerouter_proto_mpls::validate(s.store().candidate());
            for i in corerouter_proto_mpls::validate(&cfg) {
                if before.contains(&i) {
                    continue;
                }
                checks.push(check("error", "mpls", i.message, ""));
            }
            if let Ok(frr) = corerouter_proto_mpls::render_frr(&cfg.routing.mpls, &|_| Some("•••".into()))
                && !frr.is_empty()
            {
                computed.push(json!({"label": "FRR ldpd", "value": frr.trim_end()}));
            }
            commands.push(json!({"command": command, "params": p}));
        }
    }
    json!({"computed": computed, "checks": checks, "commands": commands})
}

fn static_preview(s: &mut Session, raw: &Value) -> Result<Value> {
    let editing = raw.get("id").is_some_and(|v| !v.is_null());
    let p = normalize(raw, &["label"], &["interface"]);
    Ok(if editing {
        let mut p = p;
        if let Some(o) = p.as_object_mut() {
            o.remove("label");
        }
        preview_on(s, p, "mpls.static.set", &static_set_cfg)
    } else {
        preview_on(s, p, "mpls.static.add", &static_add_cfg)
    })
}

// ---- forwarding table ----

fn forwarding_page(s: &mut Session, p: &Value) -> Result<Value> {
    let find = opt_text(p, "find", 64)?.map(|f| f.trim().to_ascii_lowercase()).filter(|f| !f.is_empty());
    let origin = opt_str(p, "origin")?;
    if let Some(o) = origin
        && !["ldp", "static", "bgp", "other"].contains(&o)
    {
        return Err(EngineError::bad("origin", "one of ldp, static, bgp, other"));
    }
    let unlabeled = opt_bool(p, "unlabeled")?.unwrap_or(false);
    let offset = opt_u32(p, "offset")?.unwrap_or(0);
    let limit = opt_u32(p, "limit")?.unwrap_or(DEFAULT_LIMIT);
    if limit == 0 || limit > MAX_LIMIT {
        return Err(EngineError::bad("limit", format!("1..={MAX_LIMIT}")));
    }
    let why = mpls_supported(s).err();
    let (kernel, note) = crate::mpls::labels(s);
    let ldp = crate::mpls::ldp(s);
    let lines = crate::mpls::lines(s, &kernel);
    let mpls = &s.store().running().routing.mpls;
    let keep = |(r, hay): &(&corerouter_proto_mpls::FecRow, &String)| {
        origin.is_none_or(|o| r.origin == o)
            && (!unlabeled || r.unlabeled())
            && find.as_deref().is_none_or(|f| hay.contains(f))
    };
    let skip = usize::try_from(offset).unwrap_or(usize::MAX);
    let take = usize::try_from(limit).unwrap_or(0);
    let mut total = 0usize;
    let mut page = Vec::with_capacity(take.min(lines.rows.len()));
    for pair in lines.rows.iter().zip(&lines.hay) {
        if !keep(&pair) {
            continue;
        }
        if total >= skip && page.len() < take {
            page.push(serde_json::to_value(pair.0).unwrap_or(Value::Null));
        }
        total += 1;
    }
    let summary = serde_json::to_value(lines.counts).unwrap_or(Value::Null);
    Ok(json!({
        "total": total,
        "offset": offset,
        "rows": page,
        "summary": summary,
        "ldp": {
            "running": mpls.ldp_running().is_some(),
            "daemon": ldp.state.is_some(),
            "error": ldp.error,
        },
        "note": note,
        "available": why.is_none(),
        "why": why,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stacks_and_ranges_parse_like_routeros() {
        assert_eq!(stack(&json!({"s": "100 200"}), "s").unwrap(), Some(vec![100, 200]));
        assert_eq!(stack(&json!({"s": [100, 0]}), "s").unwrap(), Some(vec![100, 0]));
        assert_eq!(stack(&json!({"s": "implicit-null"}), "s").unwrap(), Some(vec![]));
        assert!(stack(&json!({"s": "3"}), "s").is_err());
        assert!(stack(&json!({"s": "x"}), "s").is_err());
        assert_eq!(range(&json!({"r": "16-9999"}), "r").unwrap(), Some((16, 9999)));
        assert!(range(&json!({"r": "15-9999"}), "r").is_err());
        assert!(range(&json!({"r": "99-16"}), "r").is_err());
    }
}
