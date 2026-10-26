//! /ip pool (G4.2a): address pools, and `/ip pool used` (who holds which
//! address, from the DHCP server's leases).

use corerouter_model::ip_pool::{IpPool, MAX_POOLS, MAX_RANGES, PoolRange};
use corerouter_proto_dhcp::server::checks;
use serde_json::{Value, json};

use super::args::{opt_str, opt_text};
use super::dhcp_client::opt_list;
use super::dhcp_server::{check_rows, find, opt_ref, verdict};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.pool.add",
        "Add Pool",
        ["IP", "Pool"],
        None,
        "{name: string, ranges: [string] | string (10.0.0.10-10.0.0.200, 10.0.0.0/24 or one address; comma-separated), next_pool?: string (tried when this one is full; empty: none), comment?: string} → {id, name, size, warnings}",
        always,
        add
    ),
    cmd!(
        "ip.pool.set",
        "Set Pool",
        [],
        None,
        "{id: *hex | name, name?: string, ranges?: [string] | string, next_pool?: string, comment?: string} → {id, name, size, warnings}",
        has_pools,
        set
    ),
    cmd!(
        "ip.pool.remove",
        "Remove Pool",
        [],
        None,
        "{id: *hex | name} → {id, name}",
        has_pools,
        remove
    ),
    cmd!(query "ip.pool.print", "Pool", ["IP", "Pool"], None,
        "{} → [{id, name, ranges, next_pool?, comment?, size (addresses), used (bound or offered), available, percent, checks: [{label, level, text}]}]",
        always, print),
    cmd!(query "ip.pool.used.print", "Pool Used", [], None,
        "{pool?: string} → [{pool, address, owner (the DHCP server), info (MAC and host name), state (offered | bound | conflict | declined)}]",
        always, used),
];

fn has_pools(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.pools.pools.is_empty() {
        Err("there are no pools (ip.pool.add)".into())
    } else {
        Ok(())
    }
}

fn ranges(p: &Value) -> Result<Option<Vec<PoolRange>>> {
    let Some(items) = opt_list(p, "ranges")? else {
        return Ok(None);
    };
    if items.is_empty() || items.len() > MAX_RANGES {
        return Err(EngineError::bad("ranges", format!("1..={MAX_RANGES} ranges")));
    }
    items
        .iter()
        .map(|t| {
            t.parse::<PoolRange>()
                .map_err(|e| EngineError::bad("ranges", e.to_string()))
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn apply(pool: &mut IpPool, p: &Value) -> Result<()> {
    if let Some(n) = opt_text(p, "name", 63)? {
        pool.name = n.trim().to_owned();
    }
    if let Some(r) = ranges(p)? {
        pool.ranges = r;
    }
    if let Some(n) = opt_ref(p, "next_pool", &["none"])? {
        pool.next_pool = n;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        pool.comment = c;
    }
    Ok(())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = opt_str(p, "name")?
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .ok_or_else(|| EngineError::bad("name", "is required"))?
        .to_owned();
    if p.get("ranges").is_none() {
        return Err(EngineError::bad("ranges", "is required"));
    }
    let pools = &mut s.store_mut().candidate_mut().ip.pools;
    if pools.get(&name).is_some() {
        return Err(EngineError::bad("name", format!("pool '{name}' exists")));
    }
    if pools.pools.len() >= MAX_POOLS {
        return Err(EngineError::bad("name", "too many pools"));
    }
    let mut pool = IpPool {
        id: pools.next_id(),
        name,
        ranges: Vec::new(),
        next_pool: None,
        comment: String::new(),
    };
    apply(&mut pool, p)?;
    routed(s, &pool)?;
    let (id, name, size) = (pool.id, pool.name.clone(), pool.size());
    s.store_mut().candidate_mut().ip.pools.pools.push(pool);
    let warnings = verdict(s, "pools", id)?;
    Ok(json!({"id": id, "name": name, "size": size, "warnings": warnings}))
}

/// G4.3cd: a pool must not lend addresses of a block routed to a secret.
fn routed(s: &Session, pool: &IpPool) -> Result<()> {
    for g in &pool.ranges {
        if let Some(why) = super::ppp_secret::routed_in(s, g.start.into(), g.end.into()) {
            return Err(EngineError::bad("ranges", format!("{g} {why}")));
        }
    }
    Ok(())
}

fn index(s: &Session, p: &Value) -> Result<usize> {
    find(&s.store().candidate().ip.pools.pools, p, |x| x.id, |x| Some(x.name.as_str()), "pool")
}

/// Who uses pool `name`.
fn users(s: &Session, name: &str) -> Vec<String> {
    let c = s.store().candidate();
    c.ip.dhcp_server
        .servers
        .iter()
        .filter(|d| d.address_pool.as_deref() == Some(name))
        .map(|d| format!("server {}", d.name))
        .chain(
            c.ip.dhcp_server
                .matchers
                .iter()
                .filter(|m| m.address_pool.as_deref() == Some(name))
                .map(|m| format!("matcher {}", m.name)),
        )
        .chain(
            c.ip.pools
                .pools
                .iter()
                .filter(|q| q.next_pool.as_deref() == Some(name))
                .map(|q| format!("pool {} (next_pool)", q.name)),
        )
        .chain(c.ppp.profiles.iter().filter(|pr| {
            [&pr.local_address, &pr.remote_address].into_iter().any(|a| {
                matches!(a, Some(corerouter_model::ppp::AddrOrPool::Pool(n)) if n == name)
            })
        })
        .map(|pr| format!("ppp profile {}", pr.name)))
        .collect()
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let Some(mut pool) = s.store().candidate().ip.pools.pools.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such pool"));
    };
    let old = pool.name.clone();
    apply(&mut pool, p)?;
    if pool.name != old {
        let used = users(s, &old);
        if !used.is_empty() {
            return Err(EngineError::bad(
                "name",
                format!("{} use it by name: rename there first", used.join(", ")),
            ));
        }
    }
    routed(s, &pool)?;
    let (id, name, size) = (pool.id, pool.name.clone(), pool.size());
    if let Some(slot) = s.store_mut().candidate_mut().ip.pools.pools.get_mut(i) {
        *slot = pool;
    }
    let warnings = verdict(s, "pools", id)?;
    Ok(json!({"id": id, "name": name, "size": size, "warnings": warnings}))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let Some(pool) = s.store().candidate().ip.pools.pools.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such pool"));
    };
    let used = users(s, &pool.name);
    if !used.is_empty() {
        return Err(EngineError::bad("id", format!("in use by {}", used.join(", "))));
    }
    s.store_mut().candidate_mut().ip.pools.pools.remove(i);
    Ok(json!({"id": pool.id, "name": pool.name}))
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let cand = s.store().candidate();
    let all = checks::checks(cand);
    let uses = s.dhcp_server().map(|c| c.pool_use()).unwrap_or_default();
    let rows: Vec<Value> = cand
        .ip
        .pools
        .pools
        .iter()
        .map(|p| {
            let u = uses.iter().find(|u| u.pool == p.name);
            let used = u.map_or(0, |u| u.bound + u.offered);
            let size = p.size();
            let mut v = json!({
                "id": p.id,
                "name": p.name,
                "ranges": p.ranges.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "size": size,
                "used": used,
                "available": size.saturating_sub(used + u.map_or(0, |u| u.held)),
                "percent": u.map_or(0, |u| u.percent()),
                "checks": check_rows(&all, "pools", p.id),
            });
            if let Some(o) = v.as_object_mut() {
                if let Some(n) = &p.next_pool {
                    o.insert("next_pool".into(), json!(n));
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

fn used(s: &mut Session, p: &Value) -> Result<Value> {
    let only = opt_str(p, "pool")?.map(str::to_owned);
    let pools = &s.store().candidate().ip.pools.pools;
    let Some(core) = s.dhcp_server() else {
        return Ok(json!([]));
    };
    let mut rows: Vec<(u32, Value)> = core
        .leases()
        .iter()
        .filter(|l| !l.state.free())
        .filter_map(|l| {
            let pool = pools.iter().find(|p| p.contains(l.address))?;
            if only.as_deref().is_some_and(|o| o != pool.name) {
                return None;
            }
            let mac = corerouter_model::MacAddr(l.mac).to_string();
            let info = if l.host_name.is_empty() { mac } else { format!("{mac} {}", l.host_name) };
            Some((
                u32::from(l.address),
                json!({
                    "pool": pool.name,
                    "address": l.address,
                    "owner": l.server,
                    "info": info,
                    "state": l.state.as_str(),
                }),
            ))
        })
        .collect();
    rows.sort_by_key(|(k, _)| *k);
    Ok(Value::Array(rows.into_iter().map(|(_, v)| v).collect()))
}
