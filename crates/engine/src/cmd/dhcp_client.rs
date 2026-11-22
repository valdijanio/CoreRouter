//! /ip dhcp-client (G4.7): the client's config is ordinary config (add, set,
//! remove, journaled, saved); its lease is operational state read by `list`,
//! `options` and `history`, and acted on by `renew` / `release`.

use corerouter_model::dhcp_client::{
    CheckGateway, MAX_ALLOWED, MAX_EXTRA, MAX_FALLBACK_TIMEOUT, MIN_FALLBACK_TIMEOUT,
};
use corerouter_model::{
    AddDefaultRoute, AllowedServer, Config, DhcpClient, ExtraOption, IfName, ItemId, RouteEntry,
    RoutingTable,
};
use corerouter_proto_dhcp::v4;
use ipnet::Ipv4Net;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32, req_parse};
use super::{CommandSpec, always};
use crate::dhcp_client::{duration_text, table_for};
use crate::route_table::{self, Line};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.dhcp-client.add",
        "Add DHCP Client",
        ["IP", "DHCP Client"],
        None,
        "{interface: string, disabled?: bool, comment?: string, add_default_route?: yes | no | special-classless (default yes: option 121 if sent, else a default route via option 3; special-classless: both), default_route_distance?: u32 (1..=255, default 254: a backup behind any static, OSPF or BGP route), default_route_table?: string (main | VRF; empty = the interface's table), use_peer_dns?: bool (default true), use_peer_ntp?: bool (default true), host_name?: string (option 12; empty = system identity), client_id?: string (option 61: text or 0x…; empty = 0x01+MAC), vendor_class?: string (option 60: text or 0x…), extra_options?: [string (code:value, value as 0x0a0b | 'text' | s'text' | '10.0.0.1' | '10' | $(HOSTNAME) | $(CLIENT_MAC))] | string, allowed_servers?: [string (IPv4 or MAC; empty = any server)] | string, check_gateway?: none | arp | ping (default none; every 10 s, the lease's routes are withheld after 2 unanswered checks), fallback_address?: string (IPv4/prefix put on the interface while no server answers; empty = none), fallback_timeout?: u32 (5..=3600 s without a lease before the fallback address goes up, default 30)} → {id}",
        always,
        add
    ),
    cmd!(
        "ip.dhcp-client.set",
        "Set DHCP Client",
        [],
        None,
        "{id: *hex, interface?: string, disabled?: bool, comment?: string, add_default_route?: yes | no | special-classless (default yes: option 121 if sent, else a default route via option 3; special-classless: both), default_route_distance?: u32 (1..=255, default 254: a backup behind any static, OSPF or BGP route), default_route_table?: string (main | VRF; empty = the interface's table), use_peer_dns?: bool (default true), use_peer_ntp?: bool (default true), host_name?: string (option 12; empty = system identity), client_id?: string (option 61: text or 0x…; empty = 0x01+MAC), vendor_class?: string (option 60: text or 0x…), extra_options?: [string (code:value, value as 0x0a0b | 'text' | s'text' | '10.0.0.1' | '10' | $(HOSTNAME) | $(CLIENT_MAC))] | string, allowed_servers?: [string (IPv4 or MAC; empty = any server)] | string, check_gateway?: none | arp | ping (default none; every 10 s, the lease's routes are withheld after 2 unanswered checks), fallback_address?: string (IPv4/prefix put on the interface while no server answers; empty = none), fallback_timeout?: u32 (5..=3600 s without a lease before the fallback address goes up, default 30)} → {id}",
        has_clients,
        set
    ),
    cmd!(
        "ip.dhcp-client.remove",
        "Remove DHCP Client",
        [],
        None,
        "{id: *hex} → {id}",
        has_clients,
        remove
    ),
    cmd!(
        "ip.dhcp-client.renew",
        "Renew",
        [],
        None,
        "{id: *hex} → {id, status}",
        has_clients,
        renew
    ),
    cmd!(
        "ip.dhcp-client.release",
        "Release",
        [],
        None,
        "{id: *hex} → {id, status}",
        has_clients,
        release
    ),
    cmd!(query "ip.dhcp-client.list", "DHCP Client", ["IP", "DHCP Client"], None,
        "{interface?: string} → [{id, flags (X disabled, I invalid), interface, use_peer_dns, add_default_route, status (stopped | searching | requesting | bound | renewing | rebinding | error), address, gateway, dhcp_server, expires_after, primary_dns, secondary_dns, primary_ntp, secondary_ntp, domain, lease_time, expires_after_secs, routes, route_states (each route of the lease in the routing table: [{route, state (active | standby | inactive), ecmp, reason, notice (null | info | warning: ECMP mixing origins or on the default route)}]), notes, error, invalid, disabled, comment, default_route_distance, default_route_table, routes_table, use_peer_ntp, host_name, client_id, vendor_class, extra_options, allowed_servers, check_gateway, gateway_status (unchecked | up | down), fallback_address, fallback_timeout, fallback_active, remembered (the lease kept for INIT-REBOOT, if any)}]",
        always, list),
    cmd!(query "ip.dhcp-client.options", "Received Options", [], None,
        "{id: *hex} → {id, interface, dhcp_server, options: [{code, name, value, hex}]}",
        has_clients, options),
    cmd!(query "ip.dhcp-client.history", "DHCP Client History", [], None,
        "{id?: *hex, after_seq?: u32} → {events: [{seq, time, client, interface, event (searching | rebooting | offered | bound | renewed | lost | nak | refused | declined | ignored | error | stopped | fallback | gateway), message}], last_seq}",
        always, history),
];

fn has_clients(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.dhcp_clients.is_empty() {
        Err("there are no DHCP clients".into())
    } else {
        Ok(())
    }
}

/// `allowed_servers`: a list or `"a,b"`.
fn opt_allowed(p: &Value) -> Result<Option<Vec<AllowedServer>>> {
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
    let mut out: Vec<AllowedServer> = Vec::new();
    for it in items {
        let a: AllowedServer = it
            .parse()
            .map_err(|e: corerouter_model::ParseError| EngineError::bad(key, e.to_string()))?;
        if !out.contains(&a) {
            out.push(a);
        }
    }
    Ok(Some(out))
}

/// A list of strings, or one comma-separated string (outside quotes).
pub(super) fn opt_list(p: &Value, key: &str) -> Result<Option<Vec<String>>> {
    match p.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(Some(Vec::new())),
        Some(Value::String(s)) => {
            if s.len() > 4096 {
                return Err(EngineError::bad(key, "at most 4096 characters"));
            }
            Ok(Some(split_outside_quotes(s)))
        }
        Some(Value::Array(a)) => {
            if a.len() > 64 {
                return Err(EngineError::bad(key, "at most 64 items"));
            }
            a.iter()
                .map(|v| match v {
                    Value::String(s) => Ok(s.clone()),
                    // `extra_options` may also come as {code, value}.
                    Value::Object(o) => {
                        let code = o.get("code").and_then(Value::as_u64);
                        let value = o.get("value").and_then(Value::as_str);
                        match (code, value) {
                            (Some(c), Some(v)) => Ok(format!("{c}:{v}")),
                            _ => Err(EngineError::bad(key, "items are strings or {code, value}")),
                        }
                    }
                    _ => Err(EngineError::bad(key, "must be a list of strings")),
                })
                .collect::<Result<Vec<_>>>()
                .map(Some)
        }
        Some(_) => Err(EngineError::bad(key, "must be a list or \"a,b\"")),
    }
}

fn split_outside_quotes(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for ch in s.chars() {
        match ch {
            '\'' => {
                quoted = !quoted;
                cur.push(ch);
            }
            ',' if !quoted => out.push(std::mem::take(&mut cur).trim().to_owned()),
            _ => cur.push(ch),
        }
    }
    out.push(cur.trim().to_owned());
    out.retain(|x| !x.is_empty());
    out
}

/// `extra_options`: `code:value` items.
fn opt_extra(p: &Value) -> Result<Option<Vec<ExtraOption>>> {
    let key = "extra_options";
    let Some(items) = opt_list(p, key)? else {
        return Ok(None);
    };
    if items.len() > MAX_EXTRA {
        return Err(EngineError::bad(
            key,
            format!("at most {MAX_EXTRA} options"),
        ));
    }
    items
        .iter()
        .map(|it| {
            let (code, value) = it.split_once(':').ok_or_else(|| {
                EngineError::bad(key, format!("'{}': write code:value", clip(it)))
            })?;
            let code: u8 = code.trim().parse().map_err(|_| {
                EngineError::bad(key, format!("'{}': the code is 1..=254", clip(code)))
            })?;
            Ok(ExtraOption {
                code,
                value: value.trim().to_owned(),
            })
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn clip(s: &str) -> String {
    s.chars().take(32).collect()
}

fn opt_distance(p: &Value) -> Result<Option<u8>> {
    opt_u32(p, "default_route_distance")?
        .map(|d| {
            u8::try_from(d)
                .ok()
                .filter(|d| *d >= 1)
                .ok_or_else(|| EngineError::bad("default_route_distance", "must be 1..=255"))
        })
        .transpose()
}

/// Apply the optional keys of `p` to `c`.
fn edit(c: &mut DhcpClient, p: &Value) -> Result<()> {
    if let Some(i) = opt_parse::<IfName>(p, "interface")? {
        c.interface = i;
    }
    if let Some(v) = opt_bool(p, "disabled")? {
        c.disabled = v;
    }
    if let Some(v) = opt_text(p, "comment", 256)? {
        c.comment = v;
    }
    if let Some(v) = opt_parse::<AddDefaultRoute>(p, "add_default_route")? {
        c.add_default_route = v;
    }
    if let Some(v) = opt_distance(p)? {
        c.default_route_distance = v;
    }
    if let Some(t) = opt_str(p, "default_route_table")? {
        c.default_route_table = if t.trim().is_empty() {
            None
        } else {
            Some(
                t.parse::<RoutingTable>()
                    .map_err(|e| EngineError::bad("default_route_table", e.to_string()))?,
            )
        };
    }
    if let Some(v) = opt_bool(p, "use_peer_dns")? {
        c.use_peer_dns = v;
    }
    if let Some(v) = opt_bool(p, "use_peer_ntp")? {
        c.use_peer_ntp = v;
    }
    if let Some(v) = opt_text(p, "host_name", 63)? {
        c.host_name = v;
    }
    if let Some(v) = opt_text(p, "client_id", 255)? {
        c.client_id = v;
    }
    if let Some(v) = opt_text(p, "vendor_class", 255)? {
        c.vendor_class = v;
    }
    if let Some(v) = opt_extra(p)? {
        c.extra_options = v;
    }
    if let Some(v) = opt_allowed(p)? {
        c.allowed_servers = v;
    }
    if let Some(v) = opt_parse::<CheckGateway>(p, "check_gateway")? {
        if !CheckGateway::DHCP.contains(&v) {
            return Err(crate::EngineError::bad(
                "check_gateway",
                "a DHCP client checks its gateway with arp or ping (bfd is for static routes)",
            ));
        }
        c.check_gateway = v;
    }
    if let Some(t) = opt_str(p, "fallback_address")? {
        c.fallback_address = if t.trim().is_empty() {
            None
        } else {
            Some(fallback(t)?)
        };
    }
    if let Some(v) = opt_u32(p, "fallback_timeout")? {
        if !(MIN_FALLBACK_TIMEOUT..=MAX_FALLBACK_TIMEOUT).contains(&v) {
            return Err(EngineError::bad(
                "fallback_timeout",
                format!("must be {MIN_FALLBACK_TIMEOUT}..={MAX_FALLBACK_TIMEOUT} seconds"),
            ));
        }
        c.fallback_timeout = v;
    }
    Ok(())
}

/// A fallback address: a host address with its prefix (`192.168.100.2/24`).
fn fallback(t: &str) -> Result<Ipv4Net> {
    let key = "fallback_address";
    let net: Ipv4Net = t
        .trim()
        .parse()
        .map_err(|_| EngineError::bad(key, format!("'{}': write address/prefix", clip(t))))?;
    let ip = net.addr();
    let edge = net.prefix_len() < 31 && (ip == net.network() || ip == net.broadcast());
    if ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_loopback()
        || net.prefix_len() == 0
        || edge
    {
        return Err(EngineError::bad(
            key,
            format!("{net} is not a usable host address"),
        ));
    }
    Ok(net)
}

/// Refuse `c` with the first problem the validator sees in it.
fn check(cfg: &Config, c: &DhcpClient) -> Result<()> {
    if let Some(other) = cfg
        .ip
        .dhcp_clients
        .iter()
        .find(|o| o.id != c.id && o.interface == c.interface)
    {
        return Err(EngineError::bad(
            "interface",
            format!(
                "'{}' already has DHCP client {} (one per interface)",
                c.interface, other.id
            ),
        ));
    }
    match corerouter_proto_dhcp::client_issues(cfg, c)
        .into_iter()
        .next()
    {
        Some((field, why)) => Err(EngineError::bad(field, why)),
        None => Ok(()),
    }
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let interface: IfName = req_parse(p, "interface")?;
    super::interface::refuse_unmanaged(s, p, &["interface"])?;
    let cfg = s.store_mut().candidate_mut();
    if cfg.ip.dhcp_clients.len() >= corerouter_model::dhcp_client::MAX_CLIENTS {
        return Err(EngineError::bad(
            "interface",
            format!(
                "at most {} DHCP clients",
                corerouter_model::dhcp_client::MAX_CLIENTS
            ),
        ));
    }
    let id = cfg.ip.next_dhcp_client_id();
    let mut c = DhcpClient::new(id, interface);
    edit(&mut c, p)?;
    check(cfg, &c)?;
    cfg.ip.dhcp_clients.push(c);
    Ok(json!({ "id": id }))
}

fn position(cfg: &Config, id: ItemId) -> Result<usize> {
    cfg.ip
        .dhcp_clients
        .iter()
        .position(|c| c.id == id)
        .ok_or_else(|| {
            EngineError::bad(
                "id",
                format!("no DHCP client {id} (see ip.dhcp-client.list)"),
            )
        })
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    super::interface::refuse_unmanaged(s, p, &["interface"])?;
    let cfg = s.store_mut().candidate_mut();
    let pos = position(cfg, id)?;
    let mut c = cfg
        .ip
        .dhcp_clients
        .get(pos)
        .cloned()
        .ok_or_else(|| EngineError::bad("id", format!("no DHCP client {id}")))?;
    edit(&mut c, p)?;
    check(cfg, &c)?;
    if let Some(slot) = cfg.ip.dhcp_clients.get_mut(pos) {
        *slot = c;
    }
    Ok(json!({ "id": id }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let cfg = s.store_mut().candidate_mut();
    let pos = position(cfg, id)?;
    cfg.ip.dhcp_clients.remove(pos);
    Ok(json!({ "id": id }))
}

fn kick(s: &mut Session, p: &Value, release: bool) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    position(s.store().candidate(), id)?;
    let state = s
        .dhcp_kick(id, release)
        .map_err(|why| EngineError::bad("id", why))?;
    Ok(json!({ "id": id, "status": state.status() }))
}

fn renew(s: &mut Session, p: &Value) -> Result<Value> {
    kick(s, p, false)
}

fn release(s: &mut Session, p: &Value) -> Result<Value> {
    kick(s, p, true)
}

fn ips(v: &[std::net::Ipv4Addr], i: usize) -> Value {
    v.get(i).map_or(Value::Null, |ip| json!(ip.to_string()))
}

/// What each route of a lease does in the routing table (G1.27h): one
/// `route_states` entry per route, and a note for each one that is not
/// alone in forwarding (standby, inactive, ECMP with another route).
pub(super) fn route_states(lines: &[Line], routes: &[RouteEntry]) -> (Vec<Value>, Vec<String>) {
    let mut notes = Vec::new();
    let states = routes
        .iter()
        .map(|rt| {
            let f = route_table::fate(
                lines,
                rt.id,
                &rt.routing_table,
                rt.dst_address,
                &rt.gateway.to_string(),
            );
            notes.extend(f.note.clone());
            json!({"route": f.route, "state": f.state.as_str(), "ecmp": f.ecmp, "reason": f.note, "notice": f.notice.map(|l| l.as_str())})
        })
        .collect();
    (states, notes)
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let filter: Option<IfName> = opt_parse(p, "interface")?;
    let lines = s.route_lines();
    let cfg = s.store().candidate();
    let now = s.dhcp.now_ms;
    let mut rows = Vec::new();
    for c in &cfg.ip.dhcp_clients {
        if filter.as_ref().is_some_and(|f| *f != c.interface) {
            continue;
        }
        // A disabled client is stopped at once, even before the service
        // drops its runner (the data plane already lost its lease).
        let runner = s.dhcp.runner(c.id).filter(|_| !c.disabled);
        let lease = runner.and_then(|r| r.lease());
        let invalid = corerouter_proto_dhcp::client_issues(cfg, c)
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
        let expires = lease
            .and_then(|l| l.expires_ms)
            .zip(now)
            .map(|(e, n)| e.saturating_sub(n) / 1_000);
        let routes: Vec<String> = runner
            .map(|r| {
                r.routes
                    .iter()
                    .map(|rt| format!("{} via {}", rt.dst_address, rt.gateway))
                    .collect()
            })
            .unwrap_or_default();
        let (states, route_notes) = route_states(&lines, runner.map_or(&[], |r| r.routes.as_slice()));
        let mut notes = runner.map(|r| r.notes.clone()).unwrap_or_default();
        notes.extend(route_notes);
        let empty = Vec::new();
        let (dns, ntp) = lease.map_or((&empty, &empty), |l| (&l.dns, &l.ntp));
        rows.push(json!({
            "id": c.id,
            "flags": flags,
            "interface": c.interface,
            "use_peer_dns": c.use_peer_dns,
            "add_default_route": c.add_default_route,
            "status": status,
            "address": lease.map(|l| l.address.to_string()),
            "gateway": lease.and_then(|l| l.gateway()).map(|g| g.to_string()),
            "dhcp_server": lease.map(|l| l.server.to_string()),
            "expires_after": expires.map(duration_text),
            "primary_dns": ips(dns, 0),
            "secondary_dns": ips(dns, 1),
            "primary_ntp": ips(ntp, 0),
            "secondary_ntp": ips(ntp, 1),
            "domain": lease.and_then(|l| l.domain.clone()),
            "lease_time": lease.map(|l| if l.lease_secs == u32::MAX {
                "infinite".to_owned()
            } else {
                duration_text(u64::from(l.lease_secs))
            }),
            "expires_after_secs": expires,
            "routes": routes,
            "route_states": states,
            "notes": notes,
            "error": error.or(invalid.clone()),
            "invalid": invalid.is_some(),
            "disabled": c.disabled,
            "comment": c.comment,
            "default_route_distance": c.default_route_distance,
            "default_route_table": c.default_route_table.as_ref().map(ToString::to_string).unwrap_or_default(),
            "routes_table": table_for(cfg, c).to_string(),
            "use_peer_ntp": c.use_peer_ntp,
            "host_name": c.host_name,
            "client_id": c.client_id,
            "vendor_class": c.vendor_class,
            "extra_options": c.extra_options.iter().map(|o| format!("{}:{}", o.code, o.value)).collect::<Vec<_>>(),
            "allowed_servers": c.allowed_servers.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "check_gateway": c.check_gateway,
            "gateway_status": runner.map_or("unchecked", |r| r.gateway_status()),
            "fallback_address": c.fallback_address.map(|a| a.to_string()).unwrap_or_default(),
            "fallback_timeout": c.fallback_timeout,
            "fallback_active": runner.is_some_and(|r| r.fallback.is_some()),
            "remembered": s.dhcp.remembered(c.id).map(|m| m.address.to_string()),
        }));
    }
    Ok(Value::Array(rows))
}

fn options(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let cfg = s.store().candidate();
    let pos = position(cfg, id)?;
    let iface = cfg.ip.dhcp_clients.get(pos).map(|c| c.interface.clone());
    let runner = s.dhcp.runner(id);
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
            let (name, value) = v4::describe(*code, data);
            json!({ "code": code, "name": name, "value": value, "hex": v4::hex(data) })
        })
        .collect();
    Ok(json!({
        "id": id,
        "interface": iface,
        "dhcp_server": lease.server.to_string(),
        "options": opts,
    }))
}

fn history(s: &mut Session, p: &Value) -> Result<Value> {
    let id: Option<ItemId> = opt_parse(p, "id")?;
    let after = opt_u32(p, "after_seq")?.unwrap_or(0);
    Ok(s.dhcp_history(id, u64::from(after)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `add` and `set` must document the same optional keys.
    const SET_KEYS: &str = "disabled?: bool, comment?: string, add_default_route?: yes | no | special-classless (default yes: option 121 if sent, else a default route via option 3; special-classless: both), default_route_distance?: u32 (1..=255, default 254: a backup behind any static, OSPF or BGP route), default_route_table?: string (main | VRF; empty = the interface's table), use_peer_dns?: bool (default true), use_peer_ntp?: bool (default true), host_name?: string (option 12; empty = system identity), client_id?: string (option 61: text or 0x…; empty = 0x01+MAC), vendor_class?: string (option 60: text or 0x…), extra_options?: [string (code:value, value as 0x0a0b | 'text' | s'text' | '10.0.0.1' | '10' | $(HOSTNAME) | $(CLIENT_MAC))] | string, allowed_servers?: [string (IPv4 or MAC; empty = any server)] | string, check_gateway?: none | arp | ping (default none; every 10 s, the lease's routes are withheld after 2 unanswered checks), fallback_address?: string (IPv4/prefix put on the interface while no server answers; empty = none), fallback_timeout?: u32 (5..=3600 s without a lease before the fallback address goes up, default 30)";

    #[test]
    fn add_and_set_document_the_same_keys() {
        let add = COMMANDS
            .iter()
            .find(|c| c.id == "ip.dhcp-client.add")
            .unwrap();
        let set = COMMANDS
            .iter()
            .find(|c| c.id == "ip.dhcp-client.set")
            .unwrap();
        assert!(add.params.contains(SET_KEYS));
        assert!(set.params.contains(SET_KEYS));
    }

    #[test]
    fn lists_split_outside_quotes() {
        assert_eq!(
            split_outside_quotes("77:'a,b', 81:0x00 ,"),
            vec!["77:'a,b'", "81:0x00"]
        );
    }
}
