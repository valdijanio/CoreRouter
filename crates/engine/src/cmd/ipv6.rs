//! /ipv6 (G4.7b): `ipv6.dhcp-client.*` (config like `/ip dhcp-client`,
//! lease as operational state), `ipv6.pool.list` (the delegated prefixes)
//! and `ipv6.settings.*` (which interfaces accept Router Advertisements).

use corerouter_model::firewall::Name;
use corerouter_model::ipv6::{self, AcceptRa, AllowedServer6, MAX_ALLOWED, ra_mode};
use corerouter_model::{Config, Dhcp6Client, IfName, ItemId, Request6};
use corerouter_proto_dhcp::v6;
use ipnet::{IpNet, Ipv6Net};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32, req_parse};
use super::dhcp_client::opt_list;
use super::{CommandSpec, always};
use crate::dhcp_client::duration_text;
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ipv6.dhcp-client.add",
        "Add DHCPv6 Client",
        ["IPv6", "DHCP Client"],
        None,
        "{interface: string, request: string (address | prefix | address,prefix), disabled?: bool, comment?: string, pool_name?: string (where the delegated prefix goes; required with prefix), prefix_hint?: string (::/56 asks for a /56; a whole prefix asks for it; ::/0 = none), accept_prefix_without_address?: bool (default true), add_default_route?: bool (default false: ::/0 via the server's link-local), default_route_distance?: u32 (1..=255, default 1), use_peer_dns?: bool (default true), rapid_commit?: bool (default true), custom_duid?: string (0x…; empty = DUID-LL of the interface MAC), allowed_servers?: [string (IPv6 address, DUID 0x… or MAC; empty = any server)] | string} → {id}",
        always,
        add
    ),
    cmd!(
        "ipv6.dhcp-client.set",
        "Set DHCPv6 Client",
        [],
        None,
        "{id: *hex, interface?: string, request?: string (address | prefix | address,prefix), disabled?: bool, comment?: string, pool_name?: string (where the delegated prefix goes; required with prefix), prefix_hint?: string (::/56 asks for a /56; a whole prefix asks for it; ::/0 = none), accept_prefix_without_address?: bool (default true), add_default_route?: bool (default false: ::/0 via the server's link-local), default_route_distance?: u32 (1..=255, default 1), use_peer_dns?: bool (default true), rapid_commit?: bool (default true), custom_duid?: string (0x…; empty = DUID-LL of the interface MAC), allowed_servers?: [string (IPv6 address, DUID 0x… or MAC; empty = any server)] | string} → {id}",
        has_clients,
        set
    ),
    cmd!(
        "ipv6.dhcp-client.remove",
        "Remove DHCPv6 Client",
        [],
        None,
        "{id: *hex} → {id}",
        has_clients,
        remove
    ),
    cmd!(
        "ipv6.dhcp-client.renew",
        "Renew",
        [],
        None,
        "{id: *hex} → {id, status}",
        has_clients,
        renew
    ),
    cmd!(
        "ipv6.dhcp-client.release",
        "Release",
        [],
        None,
        "{id: *hex} → {id, status}",
        has_clients,
        release
    ),
    cmd!(query "ipv6.dhcp-client.list", "DHCPv6 Client", ["IPv6", "DHCP Client"], None,
        "{interface?: string} → [{id, flags (X disabled, I invalid), interface, request, pool_name, status (stopped | searching | requesting | bound | renewing | rebinding | error), address, prefix, expires_after, address_expires_after, prefix_expires_after, dhcp_server, server_duid, duid, primary_dns, secondary_dns, domains, missing, routes, t1_after, t2_after, error, invalid, disabled, comment, prefix_hint, accept_prefix_without_address, add_default_route, default_route_distance, use_peer_dns, rapid_commit, custom_duid, allowed_servers}]",
        always, list),
    cmd!(query "ipv6.dhcp-client.options", "Received Options", [], None,
        "{id: *hex} → {id, interface, dhcp_server, options: [{code, name, value, hex}]}",
        has_clients, options),
    cmd!(query "ipv6.dhcp-client.history", "DHCPv6 Client History", [], None,
        "{id?: *hex, after_seq?: u32} → {events: [{seq, time, client, interface, event (searching | advertised | bound | renewed | lost | status | refused | ignored | error | stopped), message}], last_seq}",
        always, history),
    cmd!(query "ipv6.pool.list", "Pools", ["IPv6", "Pool"], None,
        "{} → [{name, flags (D dynamic, I inactive), prefix, interface, client, expires_after, preferred_lifetime, valid_lifetime, used: [{interface, address, id}], status}]",
        always, pools),
    cmd!(query "ipv6.settings.get", "IPv6 Settings", ["IPv6", "Settings"], None,
        "{} → {accept_router_advertisements, accept_router_advertisements_on, interfaces: [{interface, accept (off | if-not-forwarding | on), accepts, why}]}",
        always, settings_get),
    cmd!(
        "ipv6.settings.set",
        "Set IPv6 Settings",
        [],
        None,
        "{accept_router_advertisements?: auto | yes | no | yes-if-forwarding-disabled (default auto: only where a DHCPv6 client runs), accept_router_advertisements_on?: string (interface list: all | none | <list>, default all)} → {accept_router_advertisements, accept_router_advertisements_on}",
        always,
        settings_set
    ),
];

fn has_clients(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ipv6.dhcp_clients.is_empty() {
        Err("there are no DHCPv6 clients".into())
    } else {
        Ok(())
    }
}

fn opt_allowed(p: &Value) -> Result<Option<Vec<AllowedServer6>>> {
    let key = "allowed_servers";
    let Some(items) = opt_list(p, key)? else {
        return Ok(None);
    };
    if items.len() > MAX_ALLOWED {
        return Err(EngineError::bad(
            key,
            format!("at most {MAX_ALLOWED} servers"),
        ));
    }
    let mut out: Vec<AllowedServer6> = Vec::new();
    for it in items {
        let a: AllowedServer6 = it
            .parse()
            .map_err(|e: corerouter_model::ParseError| EngineError::bad(key, e.to_string()))?;
        if !out.contains(&a) {
            out.push(a);
        }
    }
    Ok(Some(out))
}

fn opt_hint(p: &Value) -> Result<Option<Option<Ipv6Net>>> {
    let Some(t) = opt_str(p, "prefix_hint")? else {
        return Ok(None);
    };
    let t = t.trim();
    if t.is_empty() {
        return Ok(Some(None));
    }
    let net: Ipv6Net = t.parse().map_err(|_| {
        EngineError::bad(
            "prefix_hint",
            format!(
                "'{}': write ::/56 (a length) or 2001:db8:1::/48 (a prefix)",
                clip(t)
            ),
        )
    })?;
    // RouterOS: ::/0 means no hint.
    Ok(Some((net.prefix_len() > 0).then_some(net)))
}

fn clip(s: &str) -> String {
    s.chars().take(48).collect()
}

fn edit(c: &mut Dhcp6Client, p: &Value) -> Result<()> {
    if let Some(i) = opt_parse::<IfName>(p, "interface")? {
        c.interface = i;
    }
    if let Some(r) = opt_parse::<Request6>(p, "request")? {
        c.request = r;
    }
    if let Some(v) = opt_bool(p, "disabled")? {
        c.disabled = v;
    }
    if let Some(v) = opt_text(p, "comment", 256)? {
        c.comment = v;
    }
    if let Some(v) = opt_text(p, "pool_name", 63)? {
        c.pool_name = v.trim().to_owned();
    }
    if let Some(h) = opt_hint(p)? {
        c.prefix_hint = h;
    }
    if let Some(v) = opt_bool(p, "accept_prefix_without_address")? {
        c.accept_prefix_without_address = v;
    }
    if let Some(v) = opt_bool(p, "add_default_route")? {
        c.add_default_route = v;
    }
    if let Some(d) = opt_u32(p, "default_route_distance")? {
        c.default_route_distance = u8::try_from(d)
            .ok()
            .filter(|d| *d >= 1)
            .ok_or_else(|| EngineError::bad("default_route_distance", "must be 1..=255"))?;
    }
    if let Some(v) = opt_bool(p, "use_peer_dns")? {
        c.use_peer_dns = v;
    }
    if let Some(v) = opt_bool(p, "rapid_commit")? {
        c.rapid_commit = v;
    }
    if let Some(v) = opt_text(p, "custom_duid", 2 * ipv6::MAX_DUID + 2)? {
        c.custom_duid = v.trim().to_lowercase();
    }
    if let Some(v) = opt_allowed(p)? {
        c.allowed_servers = v;
    }
    Ok(())
}

fn check(cfg: &Config, c: &Dhcp6Client) -> Result<()> {
    if let Some(other) = cfg
        .ipv6
        .dhcp_clients
        .iter()
        .find(|o| o.id != c.id && o.interface == c.interface)
    {
        return Err(EngineError::bad(
            "interface",
            format!(
                "'{}' already has DHCPv6 client {} (one per interface)",
                c.interface, other.id
            ),
        ));
    }
    if c.request.prefix()
        && let Some(other) = cfg
            .ipv6
            .dhcp_clients
            .iter()
            .find(|o| o.id != c.id && o.request.prefix() && o.pool_name == c.pool_name)
    {
        return Err(EngineError::bad(
            "pool_name",
            format!(
                "pool '{}' is already filled by client {}",
                c.pool_name, other.id
            ),
        ));
    }
    match corerouter_proto_dhcp::client6_issues(cfg, c)
        .into_iter()
        .next()
    {
        Some((field, why)) => Err(EngineError::bad(field, why)),
        None => Ok(()),
    }
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let interface: IfName = req_parse(p, "interface")?;
    let request: Request6 = req_parse(p, "request")?;
    super::interface::refuse_unmanaged(s, p, &["interface"])?;
    let cfg = s.store_mut().candidate_mut();
    if cfg.ipv6.dhcp_clients.len() >= ipv6::MAX_CLIENTS {
        return Err(EngineError::bad(
            "interface",
            format!("at most {} DHCPv6 clients", ipv6::MAX_CLIENTS),
        ));
    }
    let id = cfg.ipv6.next_dhcp_client_id();
    let mut c = Dhcp6Client::new(id, interface, request);
    edit(&mut c, p)?;
    check(cfg, &c)?;
    cfg.ipv6.dhcp_clients.push(c);
    Ok(json!({ "id": id }))
}

fn position(cfg: &Config, id: ItemId) -> Result<usize> {
    cfg.ipv6
        .dhcp_clients
        .iter()
        .position(|c| c.id == id)
        .ok_or_else(|| {
            EngineError::bad(
                "id",
                format!("no DHCPv6 client {id} (see ipv6.dhcp-client.list)"),
            )
        })
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    super::interface::refuse_unmanaged(s, p, &["interface"])?;
    let cfg = s.store_mut().candidate_mut();
    let pos = position(cfg, id)?;
    let mut c = cfg
        .ipv6
        .dhcp_clients
        .get(pos)
        .cloned()
        .ok_or_else(|| EngineError::bad("id", format!("no DHCPv6 client {id}")))?;
    edit(&mut c, p)?;
    check(cfg, &c)?;
    if let Some(slot) = cfg.ipv6.dhcp_clients.get_mut(pos) {
        *slot = c;
    }
    Ok(json!({ "id": id }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let cfg = s.store_mut().candidate_mut();
    let pos = position(cfg, id)?;
    let c = cfg.ipv6.dhcp_clients.remove(pos);
    // Addresses still taken from its pool would wait forever: say so.
    if c.request.prefix()
        && let Some(a) = cfg
            .ip
            .addresses
            .iter()
            .find(|a| a.from_pool.as_deref() == Some(c.pool_name.as_str()))
    {
        return Err(EngineError::bad(
            "id",
            format!(
                "address {} ({} on {}) takes its prefix from pool '{}'; remove it or move it to \
                 another pool first",
                a.id, a.address, a.interface, c.pool_name
            ),
        ));
    }
    Ok(json!({ "id": id }))
}

fn kick(s: &mut Session, p: &Value, release: bool) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    position(s.store().candidate(), id)?;
    let state = s
        .dhcp6_kick(id, release)
        .map_err(|why| EngineError::bad("id", why))?;
    Ok(json!({ "id": id, "status": state.status() }))
}

fn renew(s: &mut Session, p: &Value) -> Result<Value> {
    kick(s, p, false)
}

fn release(s: &mut Session, p: &Value) -> Result<Value> {
    kick(s, p, true)
}

fn left(now: Option<u64>, at: Option<u64>) -> Option<u64> {
    at.zip(now).map(|(e, n)| e.saturating_sub(n) / 1_000)
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let filter: Option<IfName> = opt_parse(p, "interface")?;
    let cfg = s.store().candidate();
    let now = s.dhcp.now_ms;
    let mut rows = Vec::new();
    for c in &cfg.ipv6.dhcp_clients {
        if filter.as_ref().is_some_and(|f| *f != c.interface) {
            continue;
        }
        let runner = s.dhcp6.runner(c.id).filter(|_| !c.disabled);
        let lease = runner.and_then(|r| r.lease());
        let invalid = corerouter_proto_dhcp::client6_issues(cfg, c)
            .first()
            .map(|(_, w)| w.clone());
        let error = runner.and_then(|r| r.error.clone());
        let status = match (runner, &error) {
            (_, Some(_)) => "error",
            (Some(r), None) => r.state().status(),
            (None, None) => "stopped",
        };
        let mut flags = String::new();
        if c.disabled {
            flags.push('X');
        }
        if invalid.is_some() {
            flags.push('I');
        }
        let a_left = left(
            now,
            lease.and_then(|l| l.address).and_then(|h| h.expires_ms),
        );
        let p_left = left(now, lease.and_then(|l| l.prefix).and_then(|h| h.expires_ms));
        let expires = left(now, lease.and_then(|l| l.expires_ms()));
        let t = |at: Option<u64>| {
            at.filter(|t| *t != u64::MAX)
                .and_then(|t| left(now, Some(t)))
                .map(duration_text)
        };
        let dns = lease.map(|l| l.dns.clone()).unwrap_or_default();
        let ip = |i: usize| dns.get(i).map(ToString::to_string);
        rows.push(json!({
            "id": c.id,
            "flags": flags,
            "interface": c.interface,
            "request": c.request,
            "pool_name": c.pool_name,
            "status": status,
            "address": lease.and_then(|l| l.address).map(|h| format!("{}/128", h.value)),
            "prefix": lease.and_then(|l| l.prefix).map(|h| h.value.to_string()),
            "expires_after": expires.map(duration_text),
            "address_expires_after": a_left.map(duration_text),
            "prefix_expires_after": p_left.map(duration_text),
            "dhcp_server": lease.map(|l| l.server_addr.to_string()),
            "server_duid": lease.map(|l| v6::duid_text(&l.server_duid)),
            "duid": runner.map(|r| v6::hex(&r.duid)),
            "primary_dns": ip(0),
            "secondary_dns": ip(1),
            "domains": lease.map(|l| l.domains.clone()).unwrap_or_default(),
            "missing": lease.map(|l| l.missing.clone()).unwrap_or_default(),
            "routes": runner.map(|r| r.routes.iter().map(|rt| format!("{} via {}", rt.dst_address, rt.gateway)).collect::<Vec<_>>()).unwrap_or_default(),
            "t1_after": t(lease.map(|l| l.t1_ms)),
            "t2_after": t(lease.map(|l| l.t2_ms)),
            "error": error.or(invalid.clone()),
            "invalid": invalid.is_some(),
            "disabled": c.disabled,
            "comment": c.comment,
            "prefix_hint": c.prefix_hint.map(|h| h.to_string()).unwrap_or_default(),
            "accept_prefix_without_address": c.accept_prefix_without_address,
            "add_default_route": c.add_default_route,
            "default_route_distance": c.default_route_distance,
            "use_peer_dns": c.use_peer_dns,
            "rapid_commit": c.rapid_commit,
            "custom_duid": c.custom_duid,
            "allowed_servers": c.allowed_servers.iter().map(ToString::to_string).collect::<Vec<_>>(),
        }));
    }
    Ok(Value::Array(rows))
}

fn options(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let cfg = s.store().candidate();
    let pos = position(cfg, id)?;
    let iface = cfg.ipv6.dhcp_clients.get(pos).map(|c| c.interface.clone());
    let runner = s.dhcp6.runner(id);
    let Some(lease) = runner.and_then(|r| r.lease()) else {
        let status = runner.map_or("stopped", |r| r.state().status());
        return Err(EngineError::bad(
            "id",
            format!("client {id} holds no lease (status {status})"),
        ));
    };
    let opts: Vec<Value> = lease
        .options
        .iter()
        .map(|(code, data)| {
            let (name, value) = v6::describe(*code, data);
            json!({ "code": code, "name": name, "value": value, "hex": v6::hex(data) })
        })
        .collect();
    Ok(json!({
        "id": id,
        "interface": iface,
        "dhcp_server": lease.server_addr.to_string(),
        "options": opts,
    }))
}

fn history(s: &mut Session, p: &Value) -> Result<Value> {
    let id: Option<ItemId> = opt_parse(p, "id")?;
    let after = opt_u32(p, "after_seq")?.unwrap_or(0);
    Ok(s.dhcp6_history(id, u64::from(after)))
}

fn pools(s: &mut Session, _p: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    let now = s.dhcp.now_ms;
    let rows: Vec<Value> = s
        .pools(cfg)
        .into_iter()
        .map(|pool| {
            let used: Vec<Value> = cfg
                .ip
                .addresses
                .iter()
                .filter(|a| a.from_pool.as_deref() == Some(pool.name.as_str()))
                .map(|a| {
                    let at = s.pool_address(cfg, &pool.name, a.address);
                    json!({
                        "id": a.id,
                        "interface": a.interface,
                        "address": at.as_ref().map(ToString::to_string).ok(),
                        "error": at.err(),
                    })
                })
                .collect();
            let secs = |v: Option<u32>| {
                v.map(|v| {
                    if v == u32::MAX {
                        "infinite".to_owned()
                    } else {
                        duration_text(u64::from(v))
                    }
                })
            };
            json!({
                "name": pool.name,
                "flags": if pool.prefix.is_some() { "D" } else { "DI" },
                "prefix": pool.prefix.map(|p| p.to_string()),
                "interface": pool.interface,
                "client": pool.client,
                "expires_after": left(now, pool.expires_ms).map(duration_text),
                "preferred_lifetime": secs(pool.preferred),
                "valid_lifetime": secs(pool.valid),
                "used": used,
                "status": if pool.prefix.is_some() { "bound" } else { "waiting for a prefix" },
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

fn settings_get(s: &mut Session, _p: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    let set = &cfg.ipv6.settings;
    let interfaces: Vec<Value> = cfg
        .interfaces
        .keys()
        .map(|name| {
            let (mode, why) = ra_mode(cfg, name);
            json!({
                "interface": name,
                "accept": mode,
                "accepts": mode.accepts(),
                "why": why,
            })
        })
        .collect();
    Ok(json!({
        "accept_router_advertisements": set.accept_router_advertisements.as_str(),
        "accept_router_advertisements_on": set.accept_router_advertisements_on.as_str(),
        "interfaces": interfaces,
    }))
}

fn settings_set(s: &mut Session, p: &Value) -> Result<Value> {
    let mode: Option<AcceptRa> = opt_parse(p, "accept_router_advertisements")?;
    let list: Option<Name> = opt_parse(p, "accept_router_advertisements_on")?;
    let cfg = s.store_mut().candidate_mut();
    if let Some(l) = &list
        && !matches!(l.as_str(), "all" | "none")
        && cfg.interface_lists.get(l.as_str()).is_none()
    {
        return Err(EngineError::bad(
            "accept_router_advertisements_on",
            format!(
                "no interface list '{}' (all, none, or see interface.list.list)",
                l.as_str()
            ),
        ));
    }
    let set = &mut cfg.ipv6.settings;
    if let Some(m) = mode {
        set.accept_router_advertisements = m;
    }
    if let Some(l) = list {
        set.accept_router_advertisements_on = l;
    }
    Ok(json!({
        "accept_router_advertisements": set.accept_router_advertisements.as_str(),
        "accept_router_advertisements_on": set.accept_router_advertisements_on.as_str(),
    }))
}

/// An address with `from_pool` as `ip.address.list` shows it.
pub(super) fn pool_view(
    s: &Session,
    cfg: &Config,
    pool: &str,
    address: IpNet,
) -> (String, Option<String>) {
    match s.pool_address(cfg, pool, address) {
        Ok(net) => (net.to_string(), None),
        Err(why) => (address.to_string(), Some(why)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SET_KEYS: &str = "disabled?: bool, comment?: string, pool_name?: string (where the delegated prefix goes; required with prefix), prefix_hint?: string (::/56 asks for a /56; a whole prefix asks for it; ::/0 = none), accept_prefix_without_address?: bool (default true), add_default_route?: bool (default false: ::/0 via the server's link-local), default_route_distance?: u32 (1..=255, default 1), use_peer_dns?: bool (default true), rapid_commit?: bool (default true), custom_duid?: string (0x…; empty = DUID-LL of the interface MAC), allowed_servers?: [string (IPv6 address, DUID 0x… or MAC; empty = any server)] | string";

    #[test]
    fn add_and_set_document_the_same_keys() {
        for id in ["ipv6.dhcp-client.add", "ipv6.dhcp-client.set"] {
            let c = COMMANDS.iter().find(|c| c.id == id).unwrap();
            assert!(c.params.contains(SET_KEYS), "{id}");
        }
    }
}
