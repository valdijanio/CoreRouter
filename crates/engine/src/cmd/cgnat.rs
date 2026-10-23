//! /ip firewall cgnat (G2.3): CGNAT pools, 1:1 exceptions, the mapping
//! table and "who was" (public address + port + time → subscriber).
//!
//! The mapping is `corerouter_model::cgnat::Layout` (RFC 7422 §2), the
//! same function the kernel backend loads and the XDP path will use; the
//! history of definitions is `crate::cgnat_history`.

use std::net::Ipv4Addr;

use corerouter_model::cgnat::{Exception, MAX_EXCEPTIONS, MAX_POOLS, MAX_RANGES, Mode, Pool, Range};
use corerouter_model::firewall::PortRange;
use corerouter_model::{IfName, ItemId};
use corerouter_proto_cgnat::checks::{self, Check, Level};
use corerouter_proto_dhcp::server::history::{Query, parse_time, utc};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32, req_parse, req_str};
use super::dhcp_client::opt_list;
use super::dhcp_server::{find, opt_secs};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

/// Rows of one `mapping.list` page.
pub const MAX_PAGE: u64 = 5000;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.firewall.cgnat.pool.add",
        "Add CGNAT Pool",
        ["IP", "Firewall"],
        None,
        "{name: string, inside: [string] | string (subscriber ranges in mapping order: 100.64.0.0/22, 100.64.4.0-100.64.4.99 or one address; comma-separated), outside: [string] | string (public ranges in mapping order), mode?: deterministic | blocks (deterministic: RFC 7422 formula, nothing logged; blocks: port blocks on demand, one log line each), ports_per_subscriber?: u16 (64..; ports of each subscriber or block; default 1000), port_range?: string (ports handed out on each public address; default 1024-65535), max_blocks?: u8 (blocks mode: 1..32 per subscriber; default 4), block_timeout?: duration (blocks mode: idle block kept this long; default 2m), out_interface?: string (translate only leaving here; empty: any), endpoint_independent_mapping?: bool (RFC 4787 REQ-1, UDP; default true), endpoint_independent_filtering?: bool (RFC 4787 REQ-8, full cone; default false), hairpin?: bool (RFC 4787 REQ-9; default true), alert_percent?: u8 (0..100: share of a subscriber's ports in use that raises the alert; 0 never; default 90), disabled?: bool, comment?: string} → {id, name, subscribers, per_address, public_used, warnings}",
        always,
        pool_add
    ),
    cmd!(
        "ip.firewall.cgnat.pool.set",
        "Set CGNAT Pool",
        [],
        None,
        "{id: *hex | name, name?: string, inside?: [string] | string, outside?: [string] | string, mode?: string, ports_per_subscriber?: u16, port_range?: string, max_blocks?: u8, block_timeout?: duration, out_interface?: string, endpoint_independent_mapping?: bool, endpoint_independent_filtering?: bool, hairpin?: bool, alert_percent?: u8, disabled?: bool, comment?: string} → {id, name, subscribers, per_address, public_used, remapped (subscribers whose public address or ports change), warnings}",
        has_pools,
        pool_set
    ),
    cmd!(
        "ip.firewall.cgnat.pool.remove",
        "Remove CGNAT Pool",
        [],
        None,
        "{id: *hex | name} → {id, name}",
        has_pools,
        pool_remove
    ),
    cmd!(query "ip.firewall.cgnat.pool.list", "CGNAT Pools", ["IP", "Firewall"], None,
        "{} → [{id, name, mode, disabled, inside: [string], outside: [string], ports_per_subscriber, port_range, max_blocks, block_timeout, out_interface?, endpoint_independent_mapping, endpoint_independent_filtering, hairpin, alert_percent, comment?, subscribers, public_addresses, per_address (subscribers or blocks per public address), capacity, public_used, checks: [{label, level, text}]}]",
        always, pool_list),
    cmd!(
        "ip.firewall.cgnat.exception.add",
        "Add CGNAT Exception",
        [],
        None,
        "{subscriber: ipv4, public: ipv4 (a public address of its own, outside every pool), disabled?: bool, comment?: string} → {id, warnings}",
        always,
        exception_add
    ),
    cmd!(
        "ip.firewall.cgnat.exception.set",
        "Set CGNAT Exception",
        [],
        None,
        "{id: *hex, subscriber?: ipv4, public?: ipv4, disabled?: bool, comment?: string} → {id, warnings}",
        has_exceptions,
        exception_set
    ),
    cmd!(
        "ip.firewall.cgnat.exception.remove",
        "Remove CGNAT Exception",
        [],
        None,
        "{id: *hex} → {id}",
        has_exceptions,
        exception_remove
    ),
    cmd!(query "ip.firewall.cgnat.exception.list", "CGNAT Exceptions", [], None,
        "{} → [{id, subscriber, public, disabled, comment?, pool? (the pool the subscriber would otherwise use), checks: [{label, level, text}]}]",
        always, exception_list),
    cmd!(
        "ip.firewall.cgnat.set",
        "CGNAT Settings",
        [],
        None,
        "{history_days?: u32 (1..3650: days the mapping history and block log are kept; Marco Civil asks 365)} → {history_days}",
        always,
        settings_set
    ),
    cmd!(query "ip.firewall.cgnat.get", "CGNAT Settings", [], None,
        "{} → {history_days, pools, exceptions, subscribers, history: {epochs, since?, error?}}",
        always, settings_get),
    cmd!(query "ip.firewall.cgnat.lookup", "CGNAT Lookup", [], None,
        "{subscriber: ipv4} → {subscriber, via (pool name or exception), mode, public, first_port, last_port, ports} (the running config)",
        always, lookup),
    cmd!(query "ip.firewall.cgnat.who-was", "Who Was", [], None,
        "{public: ipv4, port: u16 (0..65535), time?: string (unix seconds or RFC 3339: 2026-05-03T14:02:00-03:00; a bare date-time is UTC; default now)} → {subscriber, via, mode, public, first_port, last_port, time (UTC), since (UTC), until? (UTC, when the mapping changed), dhcp?: [{mac, host_name?, client_id?, circuit_id?, remote_id?, server, from, until}]}",
        always, who_was),
    cmd!(query "ip.firewall.cgnat.mapping.list", "CGNAT Mapping", [], None,
        "{pool: *hex | name, offset?: u32 (first row), count?: u32 (1..5000; default 100), subscriber?: ipv4 (only this one), public?: ipv4 (only subscribers on this address)} → {pool, mode, total, offset, rows: [{index, subscriber, public, first_port, last_port, exception? (its 1:1 public address)}]}",
        always, mapping_list),
    cmd!(query "ip.firewall.cgnat.history.list", "CGNAT History", [], None,
        "{} → [{since (UTC), until? (UTC), pools: [{name, mode, inside, outside, ports_per_subscriber, port_range}], exceptions}] (newest first; RFC 7422 §3)",
        always, history_list),
    cmd!(query "ip.firewall.cgnat.rules", "CGNAT Rules", [], None,
        "{pool?: *hex | name} → {script (the nftables the kernel gets, as text), elements (map entries), rules}",
        always, rules),
];

fn has_pools(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.cgnat.pools.is_empty() {
        Err("there are no CGNAT pools (ip.firewall.cgnat.pool.add)".into())
    } else {
        Ok(())
    }
}

fn has_exceptions(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.cgnat.exceptions.is_empty() {
        Err("there are no CGNAT exceptions (ip.firewall.cgnat.exception.add)".into())
    } else {
        Ok(())
    }
}

fn ranges(p: &Value, key: &str) -> Result<Option<Vec<Range>>> {
    let Some(items) = opt_list(p, key)? else {
        return Ok(None);
    };
    if items.is_empty() || items.len() > MAX_RANGES {
        return Err(EngineError::bad(key, format!("1..={MAX_RANGES} ranges")));
    }
    items
        .iter()
        .map(|t| t.parse::<Range>().map_err(|e| EngineError::bad(key, e.to_string())))
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn opt_small(p: &Value, key: &str, lo: u32, hi: u32) -> Result<Option<u32>> {
    match opt_u32(p, key)? {
        Some(n) if !(lo..=hi).contains(&n) => {
            Err(EngineError::bad(key, format!("must be {lo}..={hi}")))
        }
        other => Ok(other),
    }
}

fn apply_pool(pool: &mut Pool, p: &Value) -> Result<()> {
    if let Some(n) = opt_text(p, "name", 63)? {
        pool.name = n.trim().to_owned();
    }
    if let Some(r) = ranges(p, "inside")? {
        pool.inside = r;
    }
    if let Some(r) = ranges(p, "outside")? {
        pool.outside = r;
    }
    if let Some(m) = opt_parse::<Mode>(p, "mode")? {
        pool.mode = m;
    }
    if let Some(n) = opt_small(p, "ports_per_subscriber", 1, 65535)? {
        pool.ports_per_subscriber = u16::try_from(n).unwrap_or(u16::MAX);
    }
    if let Some(r) = opt_parse::<PortRange>(p, "port_range")? {
        pool.port_range = r;
    }
    if let Some(n) = opt_small(p, "max_blocks", 0, 255)? {
        pool.max_blocks = u8::try_from(n).unwrap_or(u8::MAX);
    }
    if let Some(t) = opt_secs(p, "block_timeout")? {
        pool.block_timeout = t;
    }
    match opt_str(p, "out_interface")? {
        None => {}
        Some(t) if t.trim().is_empty() => pool.out_interface = None,
        Some(t) => {
            pool.out_interface = Some(
                t.trim()
                    .parse::<IfName>()
                    .map_err(|e| EngineError::bad("out_interface", e.to_string()))?,
            );
        }
    }
    if let Some(b) = opt_bool(p, "endpoint_independent_mapping")? {
        pool.endpoint_independent_mapping = b;
    }
    if let Some(b) = opt_bool(p, "endpoint_independent_filtering")? {
        pool.endpoint_independent_filtering = b;
    }
    if let Some(b) = opt_bool(p, "hairpin")? {
        pool.hairpin = b;
    }
    if let Some(n) = opt_small(p, "alert_percent", 0, 100)? {
        pool.alert_percent = u8::try_from(n).unwrap_or(100);
    }
    if let Some(b) = opt_bool(p, "disabled")? {
        pool.disabled = b;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        pool.comment = c;
    }
    Ok(())
}

/// Whether check `c` is about list `kind` (`pools`, `exceptions`) item `id`.
fn about(kind: &str, id: ItemId) -> impl Fn(&Check) -> bool {
    let tag = format!("ip.cgnat.{kind}[{id}]");
    move |c: &Check| c.item == id && c.path.starts_with(&tag)
}

/// Refuse the change on an error about this item; else its warnings.
fn verdict(s: &Session, kind: &str, id: ItemId) -> Result<Vec<String>> {
    let all = checks::checks(s.store().candidate());
    let mine = about(kind, id);
    if let Some(e) = all.iter().find(|c| mine(c) && c.level == Level::Error) {
        let field = e.path.rsplit('.').next().unwrap_or("id");
        return Err(EngineError::bad(field, e.text.clone()));
    }
    // Errors that are not this item's (too many subscribers in all pools)
    // are the commit's to report.
    Ok(all
        .into_iter()
        .filter(|c| mine(c) && c.level == Level::Warn)
        .map(|c| c.text)
        .collect())
}

fn check_rows(all: &[Check], kind: &str, id: ItemId) -> Vec<Value> {
    let mine = about(kind, id);
    all.iter()
        .filter(|c| mine(c))
        .map(|c| json!({"label": c.label, "level": c.level, "text": c.text}))
        .collect()
}

fn pool_reply(s: &Session, id: ItemId, extra: Option<u64>) -> Result<Value> {
    let warnings = verdict(s, "pools", id)?;
    let c = &s.store().candidate().ip.cgnat;
    let pool = c
        .pools
        .iter()
        .find(|p| p.id == id)
        .ok_or_else(|| EngineError::bad("id", "no such pool"))?;
    let layout = pool.layout().ok();
    let mut v = json!({
        "id": pool.id,
        "name": pool.name,
        "subscribers": pool.subscribers(),
        "per_address": layout.as_ref().map(|l| l.per_address()),
        "public_used": layout.as_ref().map(|l| l.public_used()),
        "warnings": warnings,
    });
    if let (Some(n), Some(o)) = (extra, v.as_object_mut()) {
        o.insert("remapped".into(), json!(n));
    }
    Ok(v)
}

fn pool_add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = opt_str(p, "name")?
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .ok_or_else(|| EngineError::bad("name", "is required"))?
        .to_owned();
    for key in ["inside", "outside"] {
        if p.get(key).is_none() {
            return Err(EngineError::bad(key, "is required"));
        }
    }
    let c = &mut s.store_mut().candidate_mut().ip.cgnat;
    if c.pool(&name).is_some() {
        return Err(EngineError::bad("name", format!("pool '{name}' exists")));
    }
    if c.pools.len() >= MAX_POOLS {
        return Err(EngineError::bad("name", format!("at most {MAX_POOLS} pools")));
    }
    let defaults: Pool = serde_json::from_value(json!({
        "id": "*0", "name": name, "inside": [], "outside": []
    }))
    .map_err(|e| EngineError::bad("name", e.to_string()))?;
    let mut pool = Pool { id: c.next_id(), ..defaults };
    apply_pool(&mut pool, p)?;
    let id = pool.id;
    s.store_mut().candidate_mut().ip.cgnat.pools.push(pool);
    pool_reply(s, id, None)
}

fn pool_index(s: &Session, p: &Value) -> Result<usize> {
    find(
        &s.store().candidate().ip.cgnat.pools,
        p,
        |x| x.id,
        |x| Some(x.name.as_str()),
        "CGNAT pool",
    )
}

/// Subscribers of `old` whose slot differs in `new` (or who left it).
fn remapped(old: &Pool, new: &Pool) -> u64 {
    let (Ok(a), Ok(b)) = (old.layout(), new.layout()) else {
        return old.subscribers();
    };
    if old.mode == Mode::Blocks && new.mode == Mode::Blocks {
        return 0;
    }
    a.entries()
        .filter(|(sub, slot)| b.forward(*sub) != Some(*slot))
        .count() as u64
}

fn pool_set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = pool_index(s, p)?;
    let Some(mut pool) = s.store().candidate().ip.cgnat.pools.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such pool"));
    };
    let old = pool.clone();
    apply_pool(&mut pool, p)?;
    if pool.name != old.name
        && s.store()
            .candidate()
            .ip
            .cgnat
            .pools
            .iter()
            .any(|q| q.id != pool.id && q.name == pool.name)
    {
        return Err(EngineError::bad("name", format!("pool '{}' exists", pool.name)));
    }
    let moved = remapped(&old, &pool);
    let id = pool.id;
    if let Some(slot) = s.store_mut().candidate_mut().ip.cgnat.pools.get_mut(i) {
        *slot = pool;
    }
    pool_reply(s, id, Some(moved))
}

fn pool_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = pool_index(s, p)?;
    let pool = s.store_mut().candidate_mut().ip.cgnat.pools.remove(i);
    Ok(json!({"id": pool.id, "name": pool.name}))
}

fn pool_list(s: &mut Session, _: &Value) -> Result<Value> {
    let cand = s.store().candidate();
    let all = checks::checks(cand);
    let rows: Vec<Value> = cand
        .ip
        .cgnat
        .pools
        .iter()
        .map(|p| {
            let layout = p.layout().ok();
            let mut v = json!({
                "id": p.id,
                "name": p.name,
                "mode": p.mode.as_str(),
                "disabled": p.disabled,
                "inside": p.inside.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "outside": p.outside.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "ports_per_subscriber": p.ports_per_subscriber,
                "port_range": p.port_range.to_string(),
                "max_blocks": p.max_blocks,
                "block_timeout": p.block_timeout,
                "endpoint_independent_mapping": p.endpoint_independent_mapping,
                "endpoint_independent_filtering": p.endpoint_independent_filtering,
                "hairpin": p.hairpin,
                "alert_percent": p.alert_percent,
                "subscribers": p.subscribers(),
                "public_addresses": p.public_addresses(),
                "per_address": layout.as_ref().map(|l| l.per_address()),
                "capacity": layout.as_ref().map(|l| l.capacity()),
                "public_used": layout.as_ref().map(|l| l.public_used()),
                "checks": check_rows(&all, "pools", p.id),
            });
            if let Some(o) = v.as_object_mut() {
                if let Some(i) = &p.out_interface {
                    o.insert("out_interface".into(), json!(i));
                }
                if !p.comment.is_empty() {
                    o.insert("comment".into(), json!(p.comment));
                }
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}

fn exception_apply(e: &mut Exception, p: &Value) -> Result<()> {
    if let Some(a) = opt_parse::<Ipv4Addr>(p, "subscriber")? {
        e.subscriber = a;
    }
    if let Some(a) = opt_parse::<Ipv4Addr>(p, "public")? {
        e.public = a;
    }
    if let Some(b) = opt_bool(p, "disabled")? {
        e.disabled = b;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        e.comment = c;
    }
    Ok(())
}

fn exception_add(s: &mut Session, p: &Value) -> Result<Value> {
    let subscriber: Ipv4Addr = req_parse(p, "subscriber")?;
    let public: Ipv4Addr = req_parse(p, "public")?;
    let c = &mut s.store_mut().candidate_mut().ip.cgnat;
    if c.exceptions.len() >= MAX_EXCEPTIONS {
        return Err(EngineError::bad("subscriber", format!("at most {MAX_EXCEPTIONS} exceptions")));
    }
    let mut e = Exception {
        id: c.next_id(),
        subscriber,
        public,
        disabled: false,
        comment: String::new(),
    };
    exception_apply(&mut e, p)?;
    let id = e.id;
    c.exceptions.push(e);
    let warnings = verdict(s, "exceptions", id)?;
    Ok(json!({"id": id, "warnings": warnings}))
}

fn exception_index(s: &Session, p: &Value) -> Result<usize> {
    find(&s.store().candidate().ip.cgnat.exceptions, p, |x| x.id, |_| None, "CGNAT exception")
}

fn exception_set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = exception_index(s, p)?;
    let Some(e) = s.store_mut().candidate_mut().ip.cgnat.exceptions.get_mut(i) else {
        return Err(EngineError::bad("id", "no such exception"));
    };
    exception_apply(e, p)?;
    let id = e.id;
    let warnings = verdict(s, "exceptions", id)?;
    Ok(json!({"id": id, "warnings": warnings}))
}

fn exception_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = exception_index(s, p)?;
    let e = s.store_mut().candidate_mut().ip.cgnat.exceptions.remove(i);
    Ok(json!({"id": e.id}))
}

fn exception_list(s: &mut Session, _: &Value) -> Result<Value> {
    let cand = s.store().candidate();
    let all = checks::checks(cand);
    let c = &cand.ip.cgnat;
    Ok(Value::Array(
        c.exceptions
            .iter()
            .map(|e| {
                let mut v = json!({
                    "id": e.id,
                    "subscriber": e.subscriber,
                    "public": e.public,
                    "disabled": e.disabled,
                    "checks": check_rows(&all, "exceptions", e.id),
                });
                if let Some(o) = v.as_object_mut() {
                    if !e.comment.is_empty() {
                        o.insert("comment".into(), json!(e.comment));
                    }
                    if let Some(pool) = c.pool_of(e.subscriber) {
                        o.insert("pool".into(), json!(pool.name));
                    }
                }
                v
            })
            .collect(),
    ))
}

fn settings_set(s: &mut Session, p: &Value) -> Result<Value> {
    let days = opt_small(p, "history_days", 1, 3650)?;
    let set = &mut s.store_mut().candidate_mut().ip.cgnat.settings;
    if let Some(d) = days {
        set.history_days = d;
    }
    Ok(json!({"history_days": set.history_days}))
}

fn settings_get(s: &mut Session, _: &Value) -> Result<Value> {
    let c = s.store().candidate().ip.cgnat.clone();
    let subscribers: u64 = c.pools.iter().filter(|p| !p.disabled).map(Pool::subscribers).sum();
    let mut history = json!({});
    if let Some(h) = s.cgnat_history() {
        history = json!({"epochs": h.epochs().len()});
        if let Some(o) = history.as_object_mut() {
            if let Some(first) = h.epochs().first() {
                o.insert("since".into(), json!(utc(first.t)));
            }
            if let Some(e) = h.error() {
                o.insert("error".into(), json!(e));
            }
        }
    }
    Ok(json!({
        "history_days": c.settings.history_days,
        "pools": c.pools.len(),
        "exceptions": c.exceptions.len(),
        "subscribers": subscribers,
        "history": history,
    }))
}

fn lookup(s: &mut Session, p: &Value) -> Result<Value> {
    let sub: Ipv4Addr = req_parse(p, "subscriber")?;
    let c = &s.store().running().ip.cgnat;
    if let Some(e) = c.exception_of(sub) {
        return Ok(json!({
            "subscriber": sub, "via": "exception", "mode": "1:1", "public": e.public,
            "first_port": 0, "last_port": 65535, "ports": 65536,
        }));
    }
    let pool = c
        .pool_of(sub)
        .ok_or_else(|| EngineError::bad("subscriber", format!("{sub} is in no enabled pool")))?;
    if pool.mode == Mode::Blocks {
        return Err(EngineError::bad(
            "subscriber",
            format!("pool '{}' hands out blocks on demand: see ip.firewall.cgnat.block.list subscriber={sub}", pool.name),
        ));
    }
    let slot = pool
        .layout()
        .ok()
        .and_then(|l| l.forward(sub))
        .ok_or_else(|| EngineError::bad("subscriber", format!("pool '{}' cannot be laid out", pool.name)))?;
    Ok(json!({
        "subscriber": sub, "via": pool.name, "mode": pool.mode.as_str(), "public": slot.public,
        "first_port": slot.first_port, "last_port": slot.last_port, "ports": slot.ports(),
    }))
}

fn who_was(s: &mut Session, p: &Value) -> Result<Value> {
    let public: Ipv4Addr = req_parse(p, "public")?;
    let port = opt_small(p, "port", 0, 65535)?.ok_or_else(|| EngineError::bad("port", "is required"))?;
    let port = u16::try_from(port).unwrap_or(u16::MAX);
    let at = match p.get("time") {
        None | Some(Value::Null) => None,
        Some(Value::Number(n)) => Some(n.as_u64().ok_or_else(|| EngineError::bad("time", "unix seconds"))?),
        Some(Value::String(t)) => Some(parse_time(t).ok_or_else(|| {
            EngineError::bad("time", "unix seconds or like 2026-05-03T14:02:00-03:00")
        })?),
        Some(_) => return Err(EngineError::bad("time", "unix seconds or an RFC 3339 string")),
    };
    let w = s
        .cgnat_who_was(public, port, at)
        .map_err(|e| EngineError::bad("public", e))?;
    let t = at.unwrap_or_else(|| s.now().unwrap_or(0));
    let mut v = json!({
        "subscriber": w.subscriber,
        "via": w.via,
        "mode": w.mode,
        "public": w.slot.public,
        "first_port": w.slot.first_port,
        "last_port": w.slot.last_port,
        "time": utc(t),
        "since": utc(w.since),
    });
    if let Some(o) = v.as_object_mut() {
        if let Some(u) = w.until {
            o.insert("until".into(), json!(utc(u)));
        }
        // Who held the subscriber address by DHCP then (MAC, Option 82).
        if let Some(h) = s.dhcp_lease_history() {
            let q = Query {
                address: Some(w.subscriber),
                at: Some(t),
                ..Default::default()
            };
            let leases: Vec<Value> = h
                .query(&q, 4)
                .into_iter()
                .map(|e| {
                    json!({
                        "mac": corerouter_model::MacAddr(e.mac).to_string(),
                        "host_name": e.host_name,
                        "client_id": e.client_id,
                        "circuit_id": e.circuit_id,
                        "remote_id": e.remote_id,
                        "server": e.server,
                        "from": utc(e.start),
                        "until": utc(e.until),
                    })
                })
                .collect();
            if !leases.is_empty() {
                o.insert("dhcp".into(), Value::Array(leases));
            }
        }
    }
    Ok(v)
}

fn mapping_list(s: &mut Session, p: &Value) -> Result<Value> {
    let key = req_str(p, "pool")?;
    let c = &s.store().candidate().ip.cgnat;
    let pool = find(&c.pools, &json!({"id": key}), |x| x.id, |x| Some(x.name.as_str()), "CGNAT pool")
        .map_err(|e| match e {
            EngineError::BadParam { reason, .. } => EngineError::bad("pool", reason),
            other => other,
        })
        .and_then(|i| c.pools.get(i).ok_or_else(|| EngineError::bad("pool", "no such pool")))?;
    let layout = pool
        .layout()
        .map_err(|e| EngineError::bad("pool", format!("'{}' cannot be laid out: {e}", pool.name)))?;
    let offset = u64::from(opt_u32(p, "offset")?.unwrap_or(0));
    let count = u64::from(opt_small(p, "count", 1, u32::try_from(MAX_PAGE).unwrap_or(5000))?.unwrap_or(100));
    let row = |i: u64| -> Option<Value> {
        let sub = layout.subscriber(i)?;
        let slot = layout.slot(i)?;
        let mut v = json!({
            "index": i, "subscriber": sub, "public": slot.public,
            "first_port": slot.first_port, "last_port": slot.last_port,
        });
        if let (Some(e), Some(o)) = (c.exception_of(sub), v.as_object_mut()) {
            o.insert("exception".into(), json!(e.public));
        }
        Some(v)
    };
    let (total, rows): (u64, Vec<Value>) = if let Some(sub) = opt_parse::<Ipv4Addr>(p, "subscriber")? {
        let rows: Vec<Value> = layout.subscriber_index(sub).and_then(row).into_iter().collect();
        (rows.len() as u64, rows)
    } else if let Some(public) = opt_parse::<Ipv4Addr>(p, "public")? {
        // The subscribers of one public address are one contiguous run.
        match layout.locate(public, pool.port_range.first) {
            Some((a, _)) => {
                let per = u64::from(layout.per_address());
                let first = a * per;
                let last = (first + per).min(layout.subscribers());
                let n = last.saturating_sub(first);
                let rows = (first + offset.min(n)..last).take(count as usize).filter_map(row).collect();
                (n, rows)
            }
            None => (0, Vec::new()),
        }
    } else {
        let n = layout.subscribers();
        (n, (offset.min(n)..n).take(count as usize).filter_map(row).collect())
    };
    Ok(json!({
        "pool": pool.name, "mode": pool.mode.as_str(), "total": total, "offset": offset, "rows": rows,
    }))
}

fn history_list(s: &mut Session, _: &Value) -> Result<Value> {
    let Some(h) = s.cgnat_history() else {
        return Ok(json!([]));
    };
    let epochs = h.epochs();
    let rows: Vec<Value> = epochs
        .iter()
        .enumerate()
        .rev()
        .take(1000)
        .map(|(i, e)| {
            let pools: Vec<Value> = e
                .cgnat
                .pools
                .iter()
                .map(|p| {
                    json!({
                        "name": p.name, "mode": p.mode.as_str(), "disabled": p.disabled,
                        "inside": p.inside.iter().map(ToString::to_string).collect::<Vec<_>>(),
                        "outside": p.outside.iter().map(ToString::to_string).collect::<Vec<_>>(),
                        "ports_per_subscriber": p.ports_per_subscriber,
                        "port_range": p.port_range.to_string(),
                    })
                })
                .collect();
            let mut v = json!({
                "since": utc(e.t), "pools": pools, "exceptions": e.cgnat.exceptions.len(),
            });
            if let (Some(n), Some(o)) = (epochs.get(i + 1), v.as_object_mut()) {
                o.insert("until".into(), json!(utc(n.t)));
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}

fn rules(s: &mut Session, p: &Value) -> Result<Value> {
    let c = &s.store().candidate().ip.cgnat;
    let only = match opt_str(p, "pool")? {
        None => None,
        Some(key) => {
            let i = find(&c.pools, &json!({"id": key}), |x| x.id, |x| Some(x.name.as_str()), "CGNAT pool")?;
            c.pools.get(i).map(|x| x.id)
        }
    };
    let r = corerouter_firewall::cgnat::render(c, only);
    Ok(json!({"script": r.script, "elements": r.elements, "rules": r.rules}))
}
