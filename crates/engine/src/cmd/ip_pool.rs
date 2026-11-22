//! /ip pool (G4.2a): address pools, and `/ip pool used` (who holds which
//! address: the DHCP server's leases and, G4.2i, the PPP sessions that took
//! theirs from a pool, as in RouterOS, where a pool serves both).

use corerouter_model::ip_pool::{IpPool, MAX_POOLS, MAX_RANGES, PoolRange};
use corerouter_proto_dhcp::server::checks;
use serde_json::{Value, json};

use super::args::{opt_str, opt_text, opt_u32};
use super::dhcp_client::opt_list;
use super::dhcp_server::{check_rows, find, opt_ref, verdict};
use super::{CommandSpec, always};
use crate::ppp::first_by;
use crate::{EngineError, Result, Session};
use corerouter_model::ppp::ActiveSession;
use corerouter_proto_dhcp::server::leases::Lease;

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
        "{} → [{id, name, ranges, next_pool?, comment?, size (addresses), used (DHCP bound or offered, plus PPP sessions), ppp (of used: PPP sessions), available, percent, checks: [{label, level, text}]}]",
        always, print),
    cmd!(query "ip.pool.used.print", "Pool Used", [], None,
        "{pool?: string, owner?: dhcp | ppp (dhcp: the DHCP server's leases, IPoE ones too; ppp: PPP sessions), find?: string (in address, owner, MAC, host name or user), limit?: int 1..100000 (default 10000)} → {total, rows: [{pool, address, owner (the DHCP or PPP server), service (dhcp | ipoe | ppp), info (DHCP: MAC and host name; PPP: user and MAC), user? (PPP or IPoE login), mac?, interface? (PPP: where it came in), vlan?, session? (PPP: the ppp.active id), state (offered | bound | declined | active | conflict), conflict? (the other holder of the address)}]} in address order",
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
    // G4.2i: one pass over the PPP sessions, not one per pool.
    let ppp = s.ppp_backend().map(|b| b.pool_use()).unwrap_or_default();
    let rows: Vec<Value> = cand
        .ip
        .pools
        .pools
        .iter()
        .map(|p| {
            let u = uses.iter().find(|u| u.pool == p.name);
            let by_ppp = ppp.get(&p.name).copied().unwrap_or(0);
            let used = u.map_or(0, |u| u.bound + u.offered) + by_ppp;
            let held = u.map_or(0, |u| u.held);
            let size = p.size();
            let mut v = json!({
                "id": p.id,
                "name": p.name,
                "ranges": p.ranges.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "size": size,
                "used": used,
                "ppp": by_ppp,
                "available": size.saturating_sub(used + held),
                "percent": used.saturating_mul(100).checked_div(size).unwrap_or(0),
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

/// Which owners `ip.pool.used.print` lists.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Owner {
    All,
    Dhcp,
    Ppp,
}

/// One row of the page before it is written: a lease copied out of the
/// DHCP server's lock, with its pool (the PPP session at its address is
/// asked after the lock is let go), or a PPP session with the lease that
/// holds its address too (read under the lock).
enum Held {
    Lease(Lease, String),
    Ppp(Box<ActiveSession>, Option<Lease>),
}

impl Held {
    fn address(&self) -> u32 {
        match self {
            Held::Lease(l, _) => u32::from(l.address),
            Held::Ppp(a, _) => a.address.map_or(0, u32::from),
        }
    }
}

fn lease_matches(l: &Lease, needle: &str) -> bool {
    l.address.to_string().contains(needle)
        || l.server.to_lowercase().contains(needle)
        || corerouter_model::MacAddr(l.mac).to_string().to_lowercase().contains(needle)
        || l.host_name.to_lowercase().contains(needle)
}

fn session_matches(a: &ActiveSession, needle: &str) -> bool {
    a.address.is_some_and(|ip| ip.to_string().contains(needle))
        || a.server.to_lowercase().contains(needle)
        || a.name.to_lowercase().contains(needle)
        || a.caller_id.to_lowercase().contains(needle)
}

/// `/ip pool used` (G4.2i): the DHCP leases (offered, bound, held) and the
/// PPP sessions that took their address from a pool, in address order.
/// Only the page is written out: the leases are walked by reference and
/// cut with `select_nth` (O(n)), the PPP service copies only its page, and
/// the conflict and IPoE lookups run for the page rows alone (O(1) each).
fn used(s: &mut Session, p: &Value) -> Result<Value> {
    let only = opt_str(p, "pool")?.map(str::to_owned);
    let owner = match opt_str(p, "owner")? {
        None => Owner::All,
        Some("dhcp") => Owner::Dhcp,
        Some("ppp") => Owner::Ppp,
        Some(o) => {
            let shown: String = o.chars().take(32).collect();
            return Err(EngineError::bad("owner", format!("dhcp or ppp, not '{shown}'")));
        }
    };
    let needle = opt_text(p, "find", 128)?.map(|t| t.to_lowercase());
    let limit = opt_u32(p, "limit")?.unwrap_or(10_000);
    if !(1..=100_000).contains(&limit) {
        return Err(EngineError::bad("limit", "1..=100000"));
    }
    let limit = limit as usize;
    if let Some(n) = &only
        && s.store().candidate().ip.pools.get(n).is_none()
    {
        let shown: String = n.chars().take(64).collect();
        return Err(EngineError::bad("pool", format!("no pool '{shown}'")));
    }
    let pools = &s.store().candidate().ip.pools.pools;
    let ppp = s.ppp_backend();

    // The PPP page first: the DHCP server's lock is never held while the
    // PPP service's is taken.
    let (total_ppp, sessions) = match (&ppp, owner) {
        (Some(b), Owner::All | Owner::Ppp) => {
            let keep = |a: &ActiveSession| {
                only.as_deref().is_none_or(|o| a.pool.as_deref() == Some(o))
                    && needle.as_deref().is_none_or(|n| session_matches(a, n))
            };
            b.pool_page(&keep, limit)
        }
        _ => (0, Vec::new()),
    };

    // Under the DHCP server's lock: the leases walked by reference, the
    // page copied out, the leases at the sessions' addresses looked up.
    let (total_leases, mut page) = {
        let core = s.dhcp_server();
        let mut hits: Vec<(&Lease, &str)> = Vec::new();
        if owner != Owner::Ppp
            && let Some(core) = core.as_deref()
        {
            for l in core.leases().iter().filter(|l| !l.state.free()) {
                let Some(pool) = pools.iter().find(|p| p.contains(l.address)) else {
                    continue;
                };
                if only.as_deref().is_some_and(|o| o != pool.name)
                    || needle.as_deref().is_some_and(|n| !lease_matches(l, n))
                {
                    continue;
                }
                hits.push((l, pool.name.as_str()));
            }
        }
        let total = hits.len();
        first_by(&mut hits, limit, |(l, _)| u32::from(l.address));
        let mut page: Vec<Held> = hits
            .into_iter()
            .map(|(l, pool)| Held::Lease(l.clone(), pool.to_owned()))
            .collect();
        page.extend(sessions.into_iter().map(|a| {
            let lease = a
                .address
                .and_then(|ip| core.as_deref().and_then(|c| c.leases().get(ip)))
                .filter(|l| !l.state.free())
                .cloned();
            Held::Ppp(Box::new(a), lease)
        }));
        (total, page)
    };
    first_by(&mut page, limit, Held::address);

    let rows: Vec<Value> = page
        .into_iter()
        .map(|h| match h {
            Held::Lease(l, pool) => {
                let mac = corerouter_model::MacAddr(l.mac).to_string();
                let ipoe = s.ipoe_server(&l.server);
                let mut v = json!({
                    "pool": pool,
                    "address": l.address,
                    "owner": l.server,
                    "service": if ipoe { "ipoe" } else { "dhcp" },
                    "info": if l.host_name.is_empty() { mac.clone() } else { format!("{mac} {}", l.host_name) },
                    "mac": mac,
                    "state": l.state.as_str(),
                });
                if let Some(o) = v.as_object_mut() {
                    let holder = ppp.as_ref().and_then(|b| b.pool_holder(l.address));
                    if let Some(a) = holder {
                        o.insert("state".into(), json!("conflict"));
                        o.insert(
                            "conflict".into(),
                            json!(format!("also PPP session '{}' on {} (pool {})", a.name, a.server, a.pool.unwrap_or_default())),
                        );
                    } else if let Some(name) = ppp.as_ref().and_then(|b| b.who(l.address)) {
                        if ipoe {
                            o.insert("user".into(), json!(name));
                        } else {
                            // A PPP session with this address fixed (secret
                            // or RADIUS) while a lease holds it.
                            o.insert("state".into(), json!("conflict"));
                            o.insert("conflict".into(), json!(format!("also PPP session '{name}' (fixed address)")));
                        }
                    }
                }
                v
            }
            Held::Ppp(a, lease) => {
                let mut v = json!({
                    "pool": a.pool,
                    "address": a.address,
                    "owner": a.server,
                    "service": "ppp",
                    "info": format!("{} {}", a.name, a.caller_id).trim().to_owned(),
                    "user": a.name,
                    "mac": a.caller_id,
                    "interface": a.interface,
                    "session": a.id,
                    "state": "active",
                });
                if let Some(o) = v.as_object_mut() {
                    if let Some(vlan) = a.vlan {
                        o.insert("vlan".into(), json!(vlan));
                    }
                    if let Some(l) = lease {
                        o.insert("state".into(), json!("conflict"));
                        o.insert(
                            "conflict".into(),
                            json!(format!(
                                "also DHCP lease of {} on {} ({})",
                                corerouter_model::MacAddr(l.mac),
                                l.server,
                                l.state.as_str()
                            )),
                        );
                    }
                }
                v
            }
        })
        .collect();
    Ok(json!({"total": total_leases + total_ppp, "rows": rows}))
}
