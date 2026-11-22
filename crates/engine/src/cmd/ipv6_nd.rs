//! /ipv6 nd and /ipv6 nd prefix (G3.9ha): `ipv6.nd.*` configures where
//! Router Advertisements go out and with which values (RFC 4861 §6.2.1),
//! `ipv6.nd.prefix.*` the static prefixes. The dynamic prefixes (the
//! interfaces' global /64 addresses) and which interfaces really advertise
//! come from [`crate::ipv6_nd::plan`]; the daemon's sender follows the same
//! plan.

use std::collections::BTreeSet;

use corerouter_model::ipv6_nd::{
    ALL, dns_lifetime, MAX_INTERFACES, MAX_PREFIXES, NdInterface, NdPrefix, RaPreference, interval_text,
    lifetime_text, parse_interval, parse_lifetime,
};
use corerouter_model::{Config, IfName, ItemId};
use ipnet::Ipv6Net;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32, req_parse, req_str};
use super::{CommandSpec, always};
use crate::ipv6_nd::{Live, NdStatus, Origin, plan_live};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("ipv6.nd.add", "Add ND Interface", ["IPv6", "ND"], None,
        "{interface: string (an interface, or all: every LAN-looking interface with a prefix; WAN, PPPoE server, bridge and bond ports are left out), ra_interval?: string (min-max, default 3m20s-10m; RFC 4861 §6.2.1: min ≥ 3s and ≤ 0.75 × max), ra_delay?: string (least time between multicast RAs, default 3s), ra_lifetime?: string (router lifetime, default 30m; 0 = not a default router), ra_preference?: low | medium | high, hop_limit?: u32 (0..255, default 64; 0 = unspecified), mtu?: int 1280..65535 | unspecified (default: no MTU option), reachable_time?: u32 (ms, 0 = unspecified), retransmit_interval?: u32 (ms, 0 = unspecified), managed_address_configuration?: bool (M: addresses by DHCPv6), other_configuration?: bool (O: other settings by DHCPv6), advertise_mac_address?: bool (default yes), advertise_dns?: bool (RDNSS/DNSSL, RFC 8106: dns, else this router when ip.dns allow_remote_requests, else the IPv6 servers of ip.dns and DHCPv6), dns?: [string (IPv6 address)] | string (at most 8; empty: automatic), dnssl?: [string (search domain)] | string (at most 8), disabled?: bool, comment?: string} → {id, warnings}",
        always, add),
    cmd!("ipv6.nd.set", "Set ND Interface", [], None,
        "{id: *hex | interface, interface?: string, ra_interval?: string, ra_delay?: string, ra_lifetime?: string, ra_preference?: low | medium | high, hop_limit?: u32, mtu?: int 1280..65535 | unspecified, reachable_time?: u32, retransmit_interval?: u32, managed_address_configuration?: bool, other_configuration?: bool, advertise_mac_address?: bool, advertise_dns?: bool, dns?: [string] | string, dnssl?: [string] | string, disabled?: bool, comment?: string} → {id, warnings}",
        has_entries, set),
    cmd!("ipv6.nd.remove", "Remove ND Interface", [], None,
        "{id: *hex | interface} → {id}", has_entries, remove),
    cmd!("ipv6.nd.enable", "Enable ND Interface", [], None,
        "{id: *hex | interface} → {id}", has_entries, enable),
    cmd!("ipv6.nd.disable", "Disable ND Interface", [], None,
        "{id: *hex | interface} → {id}", has_entries, disable),
    cmd!(query "ipv6.nd.list", "ND", ["IPv6", "ND"], None,
        "{} → {entries: [{id, interface, flags (X disabled), ra_interval, ra_delay, ra_lifetime, ra_preference, hop_limit, mtu, reachable_time, retransmit_interval, managed_address_configuration, other_configuration, advertise_mac_address, advertise_dns, dns, dnssl, disabled, comment, advertising: [string], skipped: [{interface, reason}], warnings: [string]}], interfaces: [{interface, entry, state (sending | waiting | failed | skipped), reason?, prefixes: [string], rdnss: [string], dnssl: [string], ra_sent, rs_received, last_ra?, error?, conflict?, warnings}], sender (running | stopped: no --backend linux)}",
        always, list),
    cmd!(query "ipv6.nd.check", "Check ND Interface", [], None,
        "{id?: string (the entry being edited), interface?: string, ra_interval?: string, ra_delay?: string, ra_lifetime?: string, ra_preference?: string, hop_limit?: u32 | string, mtu?: u32 | string, reachable_time?: u32 | string, retransmit_interval?: u32 | string, managed_address_configuration?: bool | yes | no, other_configuration?: bool | yes | no, advertise_mac_address?: bool | yes | no, advertise_dns?: bool | yes | no, dns?: [string] | string, dnssl?: [string] | string, disabled?: bool | yes | no, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}]} (form texts accepted; never an error: bad input is a check)",
        always, preview),
    cmd!(query "ipv6.nd.prefix.check", "Check ND Prefix", [], None,
        "{id?: string (the prefix being edited), prefix?: string, interface?: string, valid_lifetime?: string, preferred_lifetime?: string, on_link?: bool | yes | no, autonomous?: bool | yes | no, disabled?: bool | yes | no, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}]} (form texts accepted; never an error: bad input is a check)",
        always, prefix_preview),
    cmd!("ipv6.nd.prefix.add", "Add ND Prefix", ["IPv6", "ND"], None,
        "{prefix: string (2001:db8:1::/64), interface: string, valid_lifetime?: string (default 4w2d; infinity), preferred_lifetime?: string (default 1w; at most valid_lifetime), on_link?: bool (L, default yes), autonomous?: bool (A: SLAAC, default yes), disabled?: bool (a disabled entry also hides the address's dynamic prefix), comment?: string} → {id}",
        always, prefix_add),
    cmd!("ipv6.nd.prefix.set", "Set ND Prefix", [], None,
        "{id: *hex, prefix?: string, interface?: string, valid_lifetime?: string, preferred_lifetime?: string, on_link?: bool, autonomous?: bool, disabled?: bool, comment?: string} → {id}",
        has_prefixes, prefix_set),
    cmd!("ipv6.nd.prefix.remove", "Remove ND Prefix", [], None,
        "{id: *hex} → {id}", has_prefixes, prefix_remove),
    cmd!("ipv6.nd.prefix.enable", "Enable ND Prefix", [], None,
        "{id: *hex} → {id}", has_prefixes, prefix_enable),
    cmd!("ipv6.nd.prefix.disable", "Disable ND Prefix", [], None,
        "{id: *hex} → {id}", has_prefixes, prefix_disable),
    cmd!(query "ipv6.nd.prefix.list", "ND Prefixes", ["IPv6", "ND"], None,
        "{interface?: string} → [{id?, prefix, interface, flags (D dynamic, X disabled, I not advertised), origin (address | static | dhcp-pd | deprecated), valid_lifetime, preferred_lifetime, on_link, autonomous, advertised, disabled, comment}]",
        always, prefix_list),
];

fn has_entries(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ipv6.nd.interfaces.is_empty() {
        Err("there are no ND entries (ipv6.nd.add)".into())
    } else {
        Ok(())
    }
}

fn has_prefixes(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ipv6.nd.prefixes.is_empty() {
        Err("there are no static ND prefixes (ipv6.nd.prefix.add)".into())
    } else {
        Ok(())
    }
}

fn clip(s: &str) -> String {
    s.chars().take(48).collect()
}

fn opt_secs(p: &Value, key: &str) -> Result<Option<u32>> {
    let Some(t) = opt_str(p, key)? else {
        return Ok(None);
    };
    match corerouter_model::dhcp_server::parse_duration(t).and_then(|s| u32::try_from(s).ok()) {
        Some(s) => Ok(Some(s)),
        None => Err(EngineError::bad(key, format!("'{}': a duration like 30m or 1800", clip(t)))),
    }
}

fn opt_lifetime(p: &Value, key: &str) -> Result<Option<u32>> {
    let Some(t) = opt_str(p, key)? else {
        return Ok(None);
    };
    parse_lifetime(t)
        .map(Some)
        .ok_or_else(|| EngineError::bad(key, format!("'{}': infinity or a duration like 4w2d", clip(t))))
}

/// `all` or an interface the config has.
fn target(cfg: &Config, name: &IfName) -> Result<()> {
    if name.as_str() == ALL || cfg.interfaces.contains_key(name) {
        Ok(())
    } else {
        Err(EngineError::bad(
            "interface",
            format!("no interface '{name}' (see interface.list), or all"),
        ))
    }
}

fn edit(e: &mut NdInterface, p: &Value) -> Result<()> {
    if let Some(i) = opt_parse::<IfName>(p, "interface")? {
        e.interface = i;
    }
    if let Some(t) = opt_str(p, "ra_interval")? {
        let (min, max) = parse_interval(t).ok_or_else(|| {
            EngineError::bad("ra_interval", format!("'{}': min-max, like 3m20s-10m or 3s-5s", clip(t)))
        })?;
        (e.ra_interval_min, e.ra_interval_max) = (min, max);
    }
    if let Some(v) = opt_secs(p, "ra_delay")? {
        e.ra_delay = v;
    }
    if let Some(v) = opt_secs(p, "ra_lifetime")? {
        e.ra_lifetime = v;
    }
    if let Some(v) = opt_parse::<RaPreference>(p, "ra_preference")? {
        e.ra_preference = v;
    }
    if let Some(v) = opt_u32(p, "hop_limit")? {
        e.hop_limit = u8::try_from(v).map_err(|_| EngineError::bad("hop_limit", "0..255"))?;
    }
    match p.get("mtu") {
        None => {}
        Some(Value::String(t)) if t == "unspecified" || t.is_empty() => e.mtu = None,
        Some(_) => {
            let v = match opt_u32(p, "mtu") {
                Ok(v) => v,
                Err(_) => opt_str(p, "mtu")?.and_then(|t| t.trim().parse().ok()),
            };
            e.mtu = Some(v.ok_or_else(|| EngineError::bad("mtu", "1280..65535 or unspecified"))?);
        }
    }
    if let Some(v) = opt_u32(p, "reachable_time")? {
        e.reachable_time = v;
    }
    if let Some(v) = opt_u32(p, "retransmit_interval")? {
        e.retransmit_interval = v;
    }
    if let Some(v) = opt_bool(p, "managed_address_configuration")? {
        e.managed_address_configuration = v;
    }
    if let Some(v) = opt_bool(p, "other_configuration")? {
        e.other_configuration = v;
    }
    if let Some(v) = opt_bool(p, "advertise_mac_address")? {
        e.advertise_mac_address = v;
    }
    if let Some(v) = opt_bool(p, "advertise_dns")? {
        e.advertise_dns = v;
    }
    if let Some(items) = super::dhcp_client::opt_list(p, "dns")? {
        let mut out = Vec::new();
        for t in items {
            let a: std::net::Ipv6Addr = t.trim().parse().map_err(|_| {
                EngineError::bad("dns", format!("'{}': an IPv6 address", clip(&t)))
            })?;
            if !out.contains(&a) {
                out.push(a);
            }
        }
        e.dns = out;
    }
    if let Some(items) = super::dhcp_client::opt_list(p, "dnssl")? {
        e.dnssl = items.into_iter().map(|d| d.trim().trim_end_matches('.').to_owned()).filter(|d| !d.is_empty()).collect();
    }
    if let Some(v) = opt_bool(p, "disabled")? {
        e.disabled = v;
    }
    if let Some(v) = opt_text(p, "comment", 256)? {
        e.comment = v;
    }
    Ok(())
}

fn check(cfg: &Config, e: &NdInterface) -> Result<()> {
    target(cfg, &e.interface)?;
    if let Some(other) = cfg
        .ipv6
        .nd
        .interfaces
        .iter()
        .find(|o| o.id != e.id && o.interface == e.interface)
    {
        return Err(EngineError::bad(
            "interface",
            format!("'{}' already has ND entry {} (one per interface)", e.interface, other.id),
        ));
    }
    // The BNG answers Router Solicitations on its PPPoE ports itself: a
    // second sender there would advertise this router to the access
    // network's CPEs outside any session.
    if let Some(srv) = cfg
        .ppp
        .pppoe_servers
        .iter()
        .find(|s| !s.disabled && s.interface == e.interface)
    {
        return Err(EngineError::bad(
            "interface",
            format!(
                "'{}' is the port of PPPoE server '{}': the BNG sends each session its own RA",
                e.interface, srv.name
            ),
        ));
    }
    match e.issues() {
        Some((field, why)) => Err(EngineError::bad(field, why)),
        None => Ok(()),
    }
}

/// The plan's warnings for entry `id`, on the candidate.
fn warnings(s: &Session, id: ItemId) -> Vec<String> {
    let cfg = s.store().candidate();
    let p = plan_live(cfg, &Live::of(s, cfg));
    p.adverts
        .iter()
        .filter(|a| a.entry.id == id)
        .flat_map(|a| a.warnings.iter().map(move |w| format!("{}: {w}", a.interface)))
        .collect()
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let interface: IfName = req_parse(p, "interface")?;
    if interface.as_str() != ALL {
        super::interface::refuse_unmanaged(s, p, &["interface"])?;
    }
    let cfg = s.store_mut().candidate_mut();
    if cfg.ipv6.nd.interfaces.len() >= MAX_INTERFACES {
        return Err(EngineError::bad("interface", format!("at most {MAX_INTERFACES} ND entries")));
    }
    let id = cfg.ipv6.nd.next_id();
    let mut e = NdInterface::new(id, interface);
    edit(&mut e, p)?;
    check(cfg, &e)?;
    cfg.ipv6.nd.interfaces.push(e);
    Ok(json!({"id": id, "warnings": warnings(s, id)}))
}

/// The entry `id` names: `*hex` or an interface name (or `all`).
fn position(cfg: &Config, p: &Value) -> Result<usize> {
    let t = req_str(p, "id")?;
    let found = if t.starts_with('*') {
        let id: ItemId = req_parse(p, "id")?;
        cfg.ipv6.nd.interfaces.iter().position(|e| e.id == id)
    } else {
        cfg.ipv6.nd.interfaces.iter().position(|e| e.interface.as_str() == t)
    };
    found.ok_or_else(|| {
        EngineError::bad("id", format!("no ND entry '{}' (see ipv6.nd.list)", clip(t)))
    })
}

fn update(s: &mut Session, p: &Value, change: impl Fn(&mut NdInterface, &Value) -> Result<()>) -> Result<ItemId> {
    if p.get("interface").and_then(Value::as_str).is_some_and(|i| i != ALL) {
        super::interface::refuse_unmanaged(s, p, &["interface"])?;
    }
    let cfg = s.store_mut().candidate_mut();
    let pos = position(cfg, p)?;
    let mut e = cfg
        .ipv6
        .nd
        .interfaces
        .get(pos)
        .cloned()
        .ok_or_else(|| EngineError::bad("id", "no such ND entry"))?;
    change(&mut e, p)?;
    check(cfg, &e)?;
    let id = e.id;
    if let Some(slot) = cfg.ipv6.nd.interfaces.get_mut(pos) {
        *slot = e;
    }
    Ok(id)
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let id = update(s, p, edit)?;
    Ok(json!({"id": id, "warnings": warnings(s, id)}))
}

fn enable(s: &mut Session, p: &Value) -> Result<Value> {
    let id = update(s, p, |e, _| {
        e.disabled = false;
        Ok(())
    })?;
    Ok(json!({"id": id}))
}

fn disable(s: &mut Session, p: &Value) -> Result<Value> {
    let id = update(s, p, |e, _| {
        e.disabled = true;
        Ok(())
    })?;
    Ok(json!({"id": id}))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let cfg = s.store_mut().candidate_mut();
    let pos = position(cfg, p)?;
    let e = cfg.ipv6.nd.interfaces.remove(pos);
    Ok(json!({"id": e.id}))
}

fn entry_json(e: &NdInterface) -> Value {
    json!({
        "id": e.id,
        "interface": e.interface,
        "flags": if e.disabled { "X" } else { "" },
        "ra_interval": interval_text(e.ra_interval_min, e.ra_interval_max),
        "ra_delay": lifetime_text(e.ra_delay),
        "ra_lifetime": lifetime_text(e.ra_lifetime),
        "ra_preference": e.ra_preference.as_str(),
        "hop_limit": e.hop_limit,
        "mtu": e.mtu.map_or_else(|| json!("unspecified"), |m| json!(m)),
        "reachable_time": e.reachable_time,
        "retransmit_interval": e.retransmit_interval,
        "managed_address_configuration": e.managed_address_configuration,
        "other_configuration": e.other_configuration,
        "advertise_mac_address": e.advertise_mac_address,
        "advertise_dns": e.advertise_dns,
        "dns": e.dns.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "dnssl": e.dnssl,
        "disabled": e.disabled,
        "comment": e.comment,
    })
}

fn list(s: &mut Session, _p: &Value) -> Result<Value> {
    let cfg = s.store().running();
    let pl = plan_live(cfg, &Live::of(s, cfg));
    let status = s.ext::<NdStatus>().cloned().unwrap_or_default();
    let entries: Vec<Value> = cfg
        .ipv6
        .nd
        .interfaces
        .iter()
        .map(|e| {
            let mut v = entry_json(e);
            let adv: Vec<&IfName> = pl.adverts.iter().filter(|a| a.entry.id == e.id).map(|a| &a.interface).collect();
            let skipped: Vec<Value> = pl
                .skipped
                .iter()
                .filter(|k| k.entry == e.id)
                .map(|k| json!({"interface": k.interface, "reason": k.reason}))
                .collect();
            let warns: Vec<String> = pl
                .adverts
                .iter()
                .filter(|a| a.entry.id == e.id)
                .flat_map(|a| a.warnings.iter().map(move |w| format!("{}: {w}", a.interface)))
                .collect();
            if let Some(o) = v.as_object_mut() {
                o.insert("advertising".into(), json!(adv));
                o.insert("skipped".into(), json!(skipped));
                o.insert("warnings".into(), json!(warns));
            }
            v
        })
        .collect();
    let mut rows: Vec<Value> = Vec::new();
    for a in &pl.adverts {
        let st = status.interfaces.get(&a.interface).cloned().unwrap_or_default();
        let state = if !status.running {
            "waiting"
        } else if st.error.is_some() {
            "failed"
        } else if st.ra_sent > 0 {
            "sending"
        } else {
            "waiting"
        };
        rows.push(json!({
            "interface": a.interface,
            "entry": a.entry.id,
            "state": state,
            "prefixes": a.prefixes.iter().map(|x| x.prefix.to_string()).collect::<Vec<_>>(),
            "rdnss": a.rdnss.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "dnssl": a.dnssl,
            "ra_sent": st.ra_sent,
            "rs_received": st.rs_received,
            "last_ra": st.last_ra,
            "error": st.error,
            "conflict": st.conflict,
            "warnings": a.warnings,
        }));
    }
    for k in &pl.skipped {
        rows.push(json!({
            "interface": k.interface,
            "entry": k.entry,
            "state": "skipped",
            "reason": k.reason,
            "prefixes": [],
            "ra_sent": 0,
            "rs_received": 0,
            "warnings": [],
        }));
    }
    Ok(json!({
        "entries": entries,
        "interfaces": rows,
        "sender": if status.running { "running" } else { "stopped" },
    }))
}

// ---- previews (the G0.24 modal) ------------------------------------------

const NUMBERS: &[&str] = &["hop_limit", "reachable_time", "retransmit_interval"];
const BOOLS: &[&str] = &[
    "managed_address_configuration",
    "other_configuration",
    "advertise_mac_address",
    "advertise_dns",
    "on_link",
    "autonomous",
    "disabled",
];

/// The modal's texts as the commands take them: numbers as numbers,
/// yes/no as bools, empty fields left out (the current value stays).
fn normalize(p: &Value, editing: bool) -> Value {
    let Some(o) = p.as_object() else {
        return p.clone();
    };
    let mut out = serde_json::Map::new();
    for (k, v) in o {
        let text = v.as_str().map(str::trim);
        let v = match text {
            Some("") if k != "comment" => continue,
            Some(t) if NUMBERS.contains(&k.as_str()) => t.parse::<u64>().map_or_else(|_| v.clone(), Value::from),
            Some("yes") if BOOLS.contains(&k.as_str()) => Value::Bool(true),
            Some("no") if BOOLS.contains(&k.as_str()) => Value::Bool(false),
            Some(t) => Value::from(t),
            None => v.clone(),
        };
        out.insert(k.clone(), v);
    }
    if !editing {
        out.remove("id");
    }
    Value::Object(out)
}

fn check_row(level: &str, check: &str, message: impl Into<String>, param: &str) -> Value {
    json!({"level": level, "check": check, "message": message.into(), "param": param})
}

fn error_check(e: EngineError) -> Value {
    match e {
        EngineError::BadParam { param, reason } => check_row("error", "param", reason, &param),
        e => check_row("error", "param", e.to_string(), ""),
    }
}

/// `ipv6.nd.check`: what an add or a set would do, on a copy of the
/// candidate: where RAs go, with what, and why not elsewhere.
fn preview(s: &mut Session, raw: &Value) -> Result<Value> {
    let editing = raw.get("id").and_then(Value::as_str).is_some_and(|t| !t.is_empty());
    let p = normalize(raw, editing);
    let mut cfg = s.store().candidate().clone();
    let live = Live::of(s, &cfg);
    let mut checks = Vec::new();
    let mut computed = Vec::new();
    let mut commands = Vec::new();
    let built = (|| -> Result<NdInterface> {
        let mut e = if editing {
            let pos = position(&cfg, &p)?;
            cfg.ipv6.nd.interfaces.remove(pos)
        } else {
            let i: IfName = req_parse(&p, "interface")?;
            NdInterface::new(cfg.ipv6.nd.next_id(), i)
        };
        edit(&mut e, &p)?;
        check(&cfg, &e)?;
        Ok(e)
    })();
    match built {
        Err(e) => checks.push(error_check(e)),
        Ok(e) => {
            let id = e.id;
            let sched = format!(
                "3 RAs at most 16 s apart, then one every {} (RFC 4861 §6.2.4); an RS is answered within 0.5 s",
                interval_text(e.ra_interval_min, e.ra_interval_max)
            );
            cfg.ipv6.nd.interfaces.push(e.clone());
            let pl = plan_live(&cfg, &live);
            let mine: Vec<_> = pl.adverts.iter().filter(|a| a.entry.id == id).collect();
            let on: Vec<String> = mine
                .iter()
                .map(|a| {
                    let pre: Vec<String> = a.prefixes.iter().map(|x| x.prefix.to_string()).collect();
                    if pre.is_empty() {
                        format!("{} (no prefix)", a.interface)
                    } else {
                        format!("{} ({})", a.interface, pre.join(", "))
                    }
                })
                .collect();
            computed.push(json!({"label": "Advertises on", "value": if on.is_empty() { "nothing".to_owned() } else { on.join("; ") }}));
            if !e.disabled {
                computed.push(json!({"label": "Schedule", "value": sched}));
            }
            let role = if e.ra_lifetime == 0 {
                "not a default router (lifetime 0)".to_owned()
            } else {
                format!("default router for {}", lifetime_text(e.ra_lifetime))
            };
            computed.push(json!({"label": "Hosts see", "value": role}));
            if e.advertise_dns {
                let dns: Vec<String> = mine.iter().flat_map(|a| a.rdnss.iter().map(ToString::to_string)).collect::<BTreeSet<_>>().into_iter().collect();
                computed.push(json!({"label": "DNS (RDNSS)", "value": if dns.is_empty() { "none found".to_owned() } else { format!("{} for {} (RFC 8106: 3 × the maximum interval)", dns.join(", "), lifetime_text(dns_lifetime(e.ra_interval_max))) }}));
            }
            for a in &mine {
                for w in &a.warnings {
                    checks.push(check_row("warning", "lan", format!("{}: {w}", a.interface), "interface"));
                }
            }
            for k in pl.skipped.iter().filter(|k| k.entry == id) {
                checks.push(check_row("info", "skipped", format!("{}: {}", k.interface, k.reason), "interface"));
            }
            if !e.disabled && mine.is_empty() && !e.is_all() {
                checks.push(check_row("warning", "lan", "no RA goes out with this entry", "interface"));
            }
            let command = if editing { "ipv6.nd.set" } else { "ipv6.nd.add" };
            commands.push(json!({"command": command, "params": p}));
        }
    }
    Ok(json!({"computed": computed, "checks": checks, "commands": commands}))
}

/// `ipv6.nd.prefix.check`.
fn prefix_preview(s: &mut Session, raw: &Value) -> Result<Value> {
    let editing = raw.get("id").and_then(Value::as_str).is_some_and(|t| !t.is_empty());
    let p = normalize(raw, editing);
    let mut cfg = s.store().candidate().clone();
    let live = Live::of(s, &cfg);
    let mut checks = Vec::new();
    let mut computed = Vec::new();
    let mut commands = Vec::new();
    let built = (|| -> Result<NdPrefix> {
        let mut x = if editing {
            let pos = prefix_position(&cfg, &p)?;
            cfg.ipv6.nd.prefixes.remove(pos)
        } else {
            let i: IfName = req_parse(&p, "interface")?;
            let t = req_str(&p, "prefix")?;
            let net: Ipv6Net = t.trim().parse().map_err(|_| {
                EngineError::bad("prefix", format!("'{}': an IPv6 prefix like 2001:db8:1::/64", clip(t)))
            })?;
            NdPrefix::new(cfg.ipv6.nd.next_prefix_id(), net, i)
        };
        prefix_edit(&mut x, &p)?;
        prefix_check(&cfg, &x)?;
        Ok(x)
    })();
    match built {
        Err(e) => checks.push(error_check(e)),
        Ok(x) => {
            computed.push(json!({"label": "Valid / preferred", "value": format!("{} / {}", lifetime_text(x.valid_lifetime), lifetime_text(x.preferred_lifetime))}));
            if x.autonomous && x.prefix.prefix_len() != 64 {
                checks.push(check_row(
                    "warning",
                    "slaac",
                    "SLAAC needs a /64 on Ethernet (RFC 4862 §5.5.3, RFC 2464 §4): hosts ignore the A flag",
                    "prefix",
                ));
            }
            if x.valid_lifetime < 7200 {
                checks.push(check_row(
                    "info",
                    "two-hours",
                    "hosts never shorten a known prefix below 2h (RFC 4862 §5.5.3 e)",
                    "valid_lifetime",
                ));
            }
            let id = x.id;
            let iface = x.interface.clone();
            cfg.ipv6.nd.prefixes.push(x);
            let pl = plan_live(&cfg, &live);
            let out = pl
                .advert(&iface)
                .is_some_and(|a| a.prefixes.iter().any(|q| q.origin == Origin::Static(id)));
            computed.push(json!({"label": "Advertised", "value": if out { format!("yes, on {iface}") } else { format!("no: {iface} sends no RA (ipv6.nd.add)") }}));
            let command = if editing { "ipv6.nd.prefix.set" } else { "ipv6.nd.prefix.add" };
            commands.push(json!({"command": command, "params": p}));
        }
    }
    Ok(json!({"computed": computed, "checks": checks, "commands": commands}))
}

// ---- prefixes ----------------------------------------------------------

fn prefix_edit(x: &mut NdPrefix, p: &Value) -> Result<()> {
    if let Some(t) = opt_str(p, "prefix")? {
        let net: Ipv6Net = t.trim().parse().map_err(|_| {
            EngineError::bad("prefix", format!("'{}': an IPv6 prefix like 2001:db8:1::/64", clip(t)))
        })?;
        x.prefix = net.trunc();
    }
    if let Some(i) = opt_parse::<IfName>(p, "interface")? {
        x.interface = i;
    }
    if let Some(v) = opt_lifetime(p, "valid_lifetime")? {
        x.valid_lifetime = v;
    }
    if let Some(v) = opt_lifetime(p, "preferred_lifetime")? {
        x.preferred_lifetime = v;
    }
    if let Some(v) = opt_bool(p, "on_link")? {
        x.on_link = v;
    }
    if let Some(v) = opt_bool(p, "autonomous")? {
        x.autonomous = v;
    }
    if let Some(v) = opt_bool(p, "disabled")? {
        x.disabled = v;
    }
    if let Some(v) = opt_text(p, "comment", 256)? {
        x.comment = v;
    }
    Ok(())
}

fn prefix_check(cfg: &Config, x: &NdPrefix) -> Result<()> {
    if !cfg.interfaces.contains_key(&x.interface) {
        return Err(EngineError::bad(
            "interface",
            format!("no interface '{}' (see interface.list)", x.interface),
        ));
    }
    if let Some(o) = cfg
        .ipv6
        .nd
        .prefixes
        .iter()
        .find(|o| o.id != x.id && o.prefix == x.prefix && o.interface == x.interface)
    {
        return Err(EngineError::bad(
            "prefix",
            format!("{} on {} is already ND prefix {}", x.prefix, x.interface, o.id),
        ));
    }
    match x.issues() {
        Some((field, why)) => Err(EngineError::bad(field, why)),
        None => Ok(()),
    }
}

fn prefix_add(s: &mut Session, p: &Value) -> Result<Value> {
    let interface: IfName = req_parse(p, "interface")?;
    let prefix: Ipv6Net = {
        let t = req_str(p, "prefix")?;
        t.trim().parse().map_err(|_| {
            EngineError::bad("prefix", format!("'{}': an IPv6 prefix like 2001:db8:1::/64", clip(t)))
        })?
    };
    super::interface::refuse_unmanaged(s, p, &["interface"])?;
    let cfg = s.store_mut().candidate_mut();
    if cfg.ipv6.nd.prefixes.len() >= MAX_PREFIXES {
        return Err(EngineError::bad("prefix", format!("at most {MAX_PREFIXES} ND prefixes")));
    }
    let id = cfg.ipv6.nd.next_prefix_id();
    let mut x = NdPrefix::new(id, prefix, interface);
    prefix_edit(&mut x, p)?;
    prefix_check(cfg, &x)?;
    cfg.ipv6.nd.prefixes.push(x);
    Ok(json!({"id": id}))
}

fn prefix_position(cfg: &Config, p: &Value) -> Result<usize> {
    let id: ItemId = req_parse(p, "id")?;
    cfg.ipv6
        .nd
        .prefixes
        .iter()
        .position(|x| x.id == id)
        .ok_or_else(|| EngineError::bad("id", format!("no static ND prefix {id} (see ipv6.nd.prefix.list)")))
}

fn prefix_update(s: &mut Session, p: &Value, change: impl Fn(&mut NdPrefix, &Value) -> Result<()>) -> Result<Value> {
    if p.get("interface").is_some() {
        super::interface::refuse_unmanaged(s, p, &["interface"])?;
    }
    let cfg = s.store_mut().candidate_mut();
    let pos = prefix_position(cfg, p)?;
    let mut x = cfg
        .ipv6
        .nd
        .prefixes
        .get(pos)
        .cloned()
        .ok_or_else(|| EngineError::bad("id", "no such ND prefix"))?;
    change(&mut x, p)?;
    prefix_check(cfg, &x)?;
    let id = x.id;
    if let Some(slot) = cfg.ipv6.nd.prefixes.get_mut(pos) {
        *slot = x;
    }
    Ok(json!({"id": id}))
}

fn prefix_set(s: &mut Session, p: &Value) -> Result<Value> {
    prefix_update(s, p, prefix_edit)
}

fn prefix_enable(s: &mut Session, p: &Value) -> Result<Value> {
    prefix_update(s, p, |x, _| {
        x.disabled = false;
        Ok(())
    })
}

fn prefix_disable(s: &mut Session, p: &Value) -> Result<Value> {
    prefix_update(s, p, |x, _| {
        x.disabled = true;
        Ok(())
    })
}

fn prefix_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let cfg = s.store_mut().candidate_mut();
    let pos = prefix_position(cfg, p)?;
    let x = cfg.ipv6.nd.prefixes.remove(pos);
    Ok(json!({"id": x.id}))
}

fn prefix_list(s: &mut Session, p: &Value) -> Result<Value> {
    let only: Option<IfName> = opt_parse(p, "interface")?;
    let cfg = s.store().running();
    let pl = plan_live(cfg, &Live::of(s, cfg));
    let status = s.ext::<NdStatus>().cloned().unwrap_or_default();
    let mut rows: Vec<Value> = Vec::new();
    let keep = |i: &IfName| only.as_ref().is_none_or(|o| o == i);
    for x in cfg.ipv6.nd.prefixes.iter().filter(|x| keep(&x.interface)) {
        let advertised = pl
            .advert(&x.interface)
            .is_some_and(|a| a.prefixes.iter().any(|q| q.origin == Origin::Static(x.id)));
        let mut flags = String::new();
        if x.disabled {
            flags.push('X');
        } else if !advertised {
            flags.push('I');
        }
        rows.push(json!({
            "id": x.id,
            "prefix": x.prefix.to_string(),
            "interface": x.interface,
            "flags": flags,
            "origin": "static",
            "valid_lifetime": lifetime_text(x.valid_lifetime),
            "preferred_lifetime": lifetime_text(x.preferred_lifetime),
            "on_link": x.on_link,
            "autonomous": x.autonomous,
            "advertised": advertised,
            "disabled": x.disabled,
            "comment": x.comment,
        }));
    }
    for a in pl.adverts.iter().filter(|a| keep(&a.interface)) {
        for q in a.prefixes.iter().filter(|q| matches!(q.origin, Origin::Address(_) | Origin::Pool(_))) {
            rows.push(json!({
                "prefix": q.prefix.to_string(),
                "interface": a.interface,
                "flags": "D",
                "origin": q.origin.as_str(),
                "valid_lifetime": lifetime_text(q.valid),
                "preferred_lifetime": lifetime_text(q.preferred),
                "on_link": q.on_link,
                "autonomous": q.autonomous,
                "advertised": true,
                "disabled": false,
                "comment": "",
            }));
        }
    }
    for (i, nets) in status.deprecated.iter().filter(|(i, _)| keep(i)) {
        for n in nets {
            rows.push(json!({
                "prefix": n.to_string(),
                "interface": i,
                "flags": "D",
                "origin": "deprecated",
                "valid_lifetime": "0s",
                "preferred_lifetime": "0s",
                "on_link": true,
                "autonomous": true,
                "advertised": true,
                "disabled": false,
                "comment": "",
            }));
        }
    }
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.execute("ip.address.add", &json!({"address": "2001:db8:2::1/64", "interface": "ether2"}))
            .unwrap();
        s
    }

    #[test]
    fn add_list_set_and_remove() {
        let mut s = lab();
        let r = s
            .execute("ipv6.nd.add", &json!({"interface": "ether2", "ra_interval": "3s-5s", "other_configuration": true}))
            .unwrap();
        assert_eq!(r["warnings"], json!([]));
        let l = s.execute("ipv6.nd.list", &json!({})).unwrap();
        let e = &l["entries"][0];
        assert_eq!(e["ra_interval"], "3s-5s");
        assert_eq!(e["ra_lifetime"], "30m");
        assert_eq!(e["advertising"], json!(["ether2"]));
        assert_eq!(l["sender"], "stopped");
        assert_eq!(l["interfaces"][0]["prefixes"], json!(["2001:db8:2::/64"]));
        let pl = s.execute("ipv6.nd.prefix.list", &json!({})).unwrap();
        assert_eq!(pl[0]["origin"], "address");
        assert_eq!(pl[0]["flags"], "D");
        assert_eq!(pl[0]["valid_lifetime"], "4w2d");
        s.execute("ipv6.nd.set", &json!({"id": "ether2", "ra_lifetime": "0", "mtu": 1480})).unwrap();
        let l = s.execute("ipv6.nd.list", &json!({})).unwrap();
        assert_eq!(l["entries"][0]["ra_lifetime"], "0s");
        assert_eq!(l["entries"][0]["mtu"], 1480);
        s.execute("ipv6.nd.disable", &json!({"id": r["id"]})).unwrap();
        let l = s.execute("ipv6.nd.list", &json!({})).unwrap();
        assert_eq!(l["entries"][0]["flags"], "X");
        assert_eq!(l["interfaces"], json!([]));
        s.execute("ipv6.nd.remove", &json!({"id": r["id"]})).unwrap();
        assert!(s.store().candidate().ipv6.nd.is_empty());
    }

    #[test]
    fn validation_follows_rfc_4861() {
        let mut s = lab();
        let bad = |s: &mut Session, p: Value, key: &str| {
            let e = s.execute("ipv6.nd.add", &p).unwrap_err().to_string();
            assert!(e.contains(key), "{p}: {e}");
        };
        bad(&mut s, json!({"interface": "ether2", "ra_interval": "2s-10s"}), "ra_interval");
        bad(&mut s, json!({"interface": "ether2", "ra_interval": "5s-5s"}), "ra_interval");
        bad(&mut s, json!({"interface": "ether2", "ra_interval": "10m"}), "ra_interval");
        bad(&mut s, json!({"interface": "ether2", "ra_lifetime": "1m"}), "ra_lifetime");
        bad(&mut s, json!({"interface": "ether2", "mtu": 1000}), "mtu");
        bad(&mut s, json!({"interface": "ether2", "hop_limit": 256}), "hop_limit");
        bad(&mut s, json!({"interface": "ether2", "ra_preference": "max"}), "ra-preference");
        bad(&mut s, json!({"interface": "nope0"}), "interface");
        s.execute("ipv6.nd.add", &json!({"interface": "ether2"})).unwrap();
        bad(&mut s, json!({"interface": "ether2"}), "one per interface");
        assert_eq!(s.store().candidate().ipv6.nd.interfaces.len(), 1);
    }

    #[test]
    fn pppoe_server_port_is_refused() {
        let mut s = lab();
        s.execute("interface.pppoe-server.server.add", &json!({"interface": "ether3"})).unwrap();
        let e = s.execute("ipv6.nd.add", &json!({"interface": "ether3"})).unwrap_err();
        assert!(e.to_string().contains("BNG"), "{e}");
        // `all` is fine, and leaves the port out.
        s.execute("ip.address.add", &json!({"address": "2001:db8:3::1/64", "interface": "ether3"}))
            .unwrap();
        s.execute("ipv6.nd.add", &json!({"interface": "all"})).unwrap();
        let l = s.execute("ipv6.nd.list", &json!({})).unwrap();
        let skipped = &l["entries"][0]["skipped"];
        assert!(
            skipped.as_array().unwrap().iter().any(|k| k["interface"] == "ether3" && k["reason"].as_str().unwrap().contains("PPPoE")),
            "{skipped}"
        );
        assert_eq!(l["entries"][0]["advertising"], json!(["ether2"]));
    }

    #[test]
    fn explicit_wan_entry_warns() {
        let mut s = lab();
        s.execute("ip.route.add", &json!({"dst_address": "::/0", "gateway": "2001:db8:2::ff"})).unwrap();
        let r = s.execute("ipv6.nd.add", &json!({"interface": "ether2"})).unwrap();
        let w = r["warnings"][0].as_str().unwrap();
        assert!(w.contains("WAN") && w.contains("default route"), "{w}");
    }

    #[test]
    fn static_prefixes() {
        let mut s = lab();
        s.execute("ipv6.nd.add", &json!({"interface": "ether2"})).unwrap();
        let r = s
            .execute(
                "ipv6.nd.prefix.add",
                &json!({"prefix": "2001:db8:2::/64", "interface": "ether2", "valid_lifetime": "2h", "preferred_lifetime": "1h"}),
            )
            .unwrap();
        let pl = s.execute("ipv6.nd.prefix.list", &json!({})).unwrap();
        assert_eq!(pl.as_array().unwrap().len(), 1, "{pl}");
        assert_eq!(pl[0]["origin"], "static");
        assert_eq!(pl[0]["valid_lifetime"], "2h");
        assert_eq!(pl[0]["advertised"], true);
        let e = s
            .execute("ipv6.nd.prefix.set", &json!({"id": r["id"], "preferred_lifetime": "3h"}))
            .unwrap_err();
        assert!(e.to_string().contains("preferred_lifetime"));
        let e = s
            .execute("ipv6.nd.prefix.add", &json!({"prefix": "2001:db8:2::/64", "interface": "ether2"}))
            .unwrap_err();
        assert!(e.to_string().contains("already"));
        let e = s
            .execute("ipv6.nd.prefix.add", &json!({"prefix": "fe80::/64", "interface": "ether2"}))
            .unwrap_err();
        assert!(e.to_string().contains("link-local"));
        s.execute("ipv6.nd.prefix.disable", &json!({"id": r["id"]})).unwrap();
        let l = s.execute("ipv6.nd.list", &json!({})).unwrap();
        assert_eq!(l["interfaces"][0]["prefixes"], json!([]));
        s.execute("ipv6.nd.prefix.remove", &json!({"id": r["id"]})).unwrap();
        let l = s.execute("ipv6.nd.list", &json!({})).unwrap();
        assert_eq!(l["interfaces"][0]["prefixes"], json!(["2001:db8:2::/64"]));
    }

    #[test]
    fn previews_take_form_texts_and_never_fail() {
        let mut s = lab();
        let r = s
            .execute(
                "ipv6.nd.check",
                &json!({"interface": "ether2", "ra_interval": "3s-5s", "hop_limit": "", "other_configuration": "yes", "comment": ""}),
            )
            .unwrap();
        assert_eq!(r["commands"][0]["command"], "ipv6.nd.add");
        assert_eq!(r["commands"][0]["params"]["other_configuration"], true);
        assert!(r["computed"][0]["value"].as_str().unwrap().contains("2001:db8:2::/64"), "{r}");
        // Applying what the preview says works.
        let c = r["commands"][0].clone();
        s.execute(c["command"].as_str().unwrap(), &c["params"]).unwrap();
        let bad = s.execute("ipv6.nd.check", &json!({"interface": "ether2", "ra_interval": "1s-2s"})).unwrap();
        assert_eq!(bad["checks"][0]["level"], "error");
        assert_eq!(bad["commands"], json!([]));
        // Editing: the entry is itself, no "one per interface".
        let e = s.execute("ipv6.nd.check", &json!({"id": "ether2", "ra_lifetime": "0", "hop_limit": "32"})).unwrap();
        assert_eq!(e["commands"][0]["command"], "ipv6.nd.set");
        assert_eq!(e["commands"][0]["params"]["hop_limit"], 32);
        assert!(e["checks"].as_array().unwrap().iter().all(|c| c["level"] != "error"), "{e}");
        let pr = s.execute("ipv6.nd.prefix.check", &json!({"prefix": "2001:db8:7::/56", "interface": "ether2", "valid_lifetime": "1h", "preferred_lifetime": "30m"})).unwrap();
        let checks: Vec<&str> = pr["checks"].as_array().unwrap().iter().map(|c| c["check"].as_str().unwrap()).collect();
        assert_eq!(checks, ["slaac", "two-hours"], "{pr}");
        assert!(pr["computed"][1]["value"].as_str().unwrap().starts_with("yes"), "{pr}");
        assert!(s.store().candidate().ipv6.nd.prefixes.is_empty(), "a preview changes nothing");
    }

    #[test]
    fn dns_options_are_set_listed_and_checked() {
        let mut s = lab();
        let r = s
            .execute(
                "ipv6.nd.add",
                &json!({"interface": "ether2", "advertise_dns": true, "dns": "2001:db8::53, 2001:db8::54", "dnssl": ["isp.example."]}),
            )
            .unwrap();
        assert_eq!(r["warnings"], json!([]));
        let l = s.execute("ipv6.nd.list", &json!({})).unwrap();
        assert_eq!(l["entries"][0]["dns"], json!(["2001:db8::53", "2001:db8::54"]));
        assert_eq!(l["entries"][0]["dnssl"], json!(["isp.example"]));
        assert_eq!(l["interfaces"][0]["rdnss"], json!(["2001:db8::53", "2001:db8::54"]));
        let e = s.execute("ipv6.nd.set", &json!({"id": "ether2", "dns": "8.8.8.8"})).unwrap_err();
        assert!(e.to_string().contains("dns"), "{e}");
        let e = s.execute("ipv6.nd.set", &json!({"id": "ether2", "dnssl": "a b"})).unwrap_err();
        assert!(e.to_string().contains("dnssl"), "{e}");
        // Automatic: none configured, a warning in the result.
        let r = s.execute("ipv6.nd.set", &json!({"id": "ether2", "dns": ""})).unwrap();
        assert!(r["warnings"][0].as_str().unwrap().contains("advertise_dns"), "{r}");
        let pv = s.execute("ipv6.nd.check", &json!({"id": "ether2", "advertise_dns": "yes", "dns": "2001:db8::9"})).unwrap();
        let dns = pv["computed"].as_array().unwrap().iter().find(|c| c["label"] == "DNS (RDNSS)").unwrap();
        assert!(dns["value"].as_str().unwrap().starts_with("2001:db8::9 for 30m"), "{pv}");
    }

    #[test]
    fn rollback_drops_the_entries() {
        let mut s = lab();
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        s.execute("ipv6.nd.add", &json!({"interface": "all"})).unwrap();
        s.execute("ipv6.nd.prefix.add", &json!({"prefix": "2001:db8:9::/64", "interface": "ether2"})).unwrap();
        s.execute("config.discard", &json!({})).unwrap();
        assert!(s.store().candidate().ipv6.nd.is_empty());
        // A refused command leaves nothing behind either.
        s.execute("config.mode.set", &json!({"mode": "immediate"})).unwrap();
        s.execute("ipv6.nd.add", &json!({"interface": "ether2", "ra_interval": "1s-2s"})).unwrap_err();
        assert!(s.store().running().ipv6.nd.is_empty());
    }
}
