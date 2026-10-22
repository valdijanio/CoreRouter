//! /ipv6 pool, /ipv6 dhcp-server (+ binding) and /ipv6 dhcp-relay
//! (G4.2c). Checked like the DHCPv4 ones: an error about the item refuses
//! the command, warnings come back.

use std::net::Ipv6Addr;

use corerouter_model::dhcp6_server::{Dhcp6Binding, Dhcp6Relay, Dhcp6Server, Ipv6Pool, parse_duid};
use corerouter_model::{IfName, ItemId};
use corerouter_proto_dhcp::server::checks::{Check, Level};
use corerouter_proto_dhcp::server::leases::State;
use corerouter_proto_dhcp::server6::{self, IaKind};
use ipnet::Ipv6Net;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32, req_parse};
use super::dhcp_client::opt_list;
use super::dhcp_server::{find, opt_ref, opt_secs, secs_text};
use super::{CommandSpec, always};
use crate::dhcp_client::duration_text;
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ipv6.pool.add",
        "Add IPv6 Pool",
        ["IPv6", "DHCPv6 Server"],
        None,
        "{name: string, prefix: ipv6/prefix (2001:db8:100::/40), prefix_length: u32 (what is handed out: 48..=64 for delegated prefixes, 128 for addresses), comment?: string} → {id, warnings}",
        always,
        pool_add
    ),
    cmd!(
        "ipv6.pool.set",
        "Set IPv6 Pool",
        [],
        None,
        "{id: *hex | name, name?: string, prefix?: ipv6/prefix, prefix_length?: u32, comment?: string} → {id, warnings}",
        has_pools,
        pool_set
    ),
    cmd!(
        "ipv6.pool.remove",
        "Remove IPv6 Pool",
        [],
        None,
        "{id: *hex | name} → {id, name}",
        has_pools,
        pool_remove
    ),
    cmd!(query "ipv6.pool.print", "IPv6 Pools", [], None,
        "{} → [{id, name, prefix, prefix_length, size (addresses or prefixes, capped at 2^64), size_text (2^N when large), used, comment?, checks}]",
        always, pool_print),
    cmd!(
        "ipv6.dhcp-server.add",
        "Add DHCPv6 Server",
        ["IPv6", "DHCPv6 Server"],
        None,
        "{name?: string (default dhcp6-N), interface: string, address_pool?: string (prefix_length 128: IA_NA addresses), prefix_pool?: string (IA_PD: prefixes for CPEs), lease_time?: duration (valid lifetime, default 1d; preferred = ⅔), preference?: u32 (0..=255, default 255), rapid_commit?: bool (default yes), route_distance?: u32 (route to each delegated prefix, default 1), relay?: ipv6 (serve only requests relayed from this link-address), dns_server?: [ipv6] | string, domain?: string, dns_zone?: string (AAAA + PTR for addresses), disabled?: bool, comment?: string} → {id, name, warnings}",
        always,
        server_add
    ),
    cmd!(
        "ipv6.dhcp-server.set",
        "Set DHCPv6 Server",
        [],
        None,
        "{id: *hex | name, name?: string, interface?: string, address_pool?: string, prefix_pool?: string, lease_time?: duration, preference?: u32, rapid_commit?: bool, route_distance?: u32, relay?: ipv6, dns_server?: [ipv6] | string, domain?: string, dns_zone?: string, disabled?: bool, comment?: string} → {id, name, warnings}",
        has_servers,
        server_set
    ),
    cmd!(
        "ipv6.dhcp-server.remove",
        "Remove DHCPv6 Server",
        [],
        None,
        "{id: *hex | name} → {id, name}",
        has_servers,
        server_remove
    ),
    cmd!(query "ipv6.dhcp-server.print", "DHCPv6 Server", ["IPv6", "DHCPv6 Server"], None,
        "{} → [{id, name, interface, address_pool?, prefix_pool?, lease_time, preference, rapid_commit, route_distance, relay?, dns_server, domain?, dns_zone?, disabled, comment?, status (running | disabled | invalid | starting | error), error?, bindings, checks}]",
        always, server_print),
    cmd!(
        "ipv6.dhcp-server.binding.add",
        "Add DHCPv6 Binding",
        [],
        None,
        "{duid: string (0x00030001…), iaid?: u32 (any when absent), address?: ipv6, prefix?: ipv6/prefix, server?: string (all), disabled?: bool, comment?: string} → {id, warnings}",
        always,
        binding_add
    ),
    cmd!(
        "ipv6.dhcp-server.binding.remove",
        "Remove DHCPv6 Binding",
        [],
        None,
        "{id: *hex (a static binding) | address or prefix (a dynamic one: released)} → {static}",
        always,
        binding_remove
    ),
    cmd!(query "ipv6.dhcp-server.binding.print", "DHCPv6 Bindings", [], None,
        "{server?: string} → [{id? (static), type (address | prefix), address (address or prefix), duid, iaid?, server, status (bound | offered | released | expired | declined | waiting), expires_after?, expires_after_secs?, via?, interface?, host_name?, dns?, dynamic, comment?}]",
        always, binding_print),
    cmd!(
        "ipv6.dhcp-relay.add",
        "Add DHCPv6 Relay",
        ["IPv6", "DHCPv6 Relay"],
        None,
        "{name?: string, interface: string (the clients' side), dhcp_server?: [ipv6] | string (empty: ff05::1:3, all servers), link_address?: ipv6 (default: a global address of the interface), disabled?: bool, comment?: string} → {id, name, warnings}",
        always,
        relay_add
    ),
    cmd!(
        "ipv6.dhcp-relay.remove",
        "Remove DHCPv6 Relay",
        [],
        None,
        "{id: *hex | name} → {id, name}",
        has_relays,
        relay_remove
    ),
    cmd!(query "ipv6.dhcp-relay.print", "DHCPv6 Relay", ["IPv6", "DHCPv6 Relay"], None,
        "{} → [{id, name, interface, dhcp_server, link_address?, disabled, comment?, requests, replies, dropped, error?, checks}]",
        always, relay_print),
];

fn has_pools(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ipv6.dhcp_server.pools.is_empty() {
        Err("there are no IPv6 pools (ipv6.pool.add)".into())
    } else {
        Ok(())
    }
}

fn has_servers(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ipv6.dhcp_server.servers.is_empty() {
        Err("there are no DHCPv6 servers (ipv6.dhcp-server.add)".into())
    } else {
        Ok(())
    }
}

fn has_relays(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ipv6.dhcp_server.relays.is_empty() {
        Err("there are no DHCPv6 relays".into())
    } else {
        Ok(())
    }
}

fn about(kind: &str, id: ItemId) -> impl Fn(&Check) -> bool {
    let tag = format!("{kind}[{id}]");
    move |c: &Check| c.item == id && c.path.contains(&tag)
}

fn verdict(s: &Session, kind: &str, id: ItemId) -> Result<Vec<String>> {
    let all = server6::checks(s.store().candidate());
    let mine = about(kind, id);
    if let Some(e) = all.iter().find(|c| mine(c) && c.level == Level::Error) {
        let field = e.path.rsplit('.').next().unwrap_or("id");
        return Err(EngineError::bad(field, e.text.clone()));
    }
    Ok(all.into_iter().filter(|c| mine(c) && c.level == Level::Warn).map(|c| c.text).collect())
}

fn check_rows(all: &[Check], kind: &str, id: ItemId) -> Vec<Value> {
    let mine = about(kind, id);
    all.iter()
        .filter(|c| mine(c))
        .map(|c| json!({"label": c.label, "level": c.level, "text": c.text}))
        .collect()
}

fn opt_v6(p: &Value, key: &str) -> Result<Option<Option<Ipv6Addr>>> {
    match opt_str(p, key)? {
        None => Ok(None),
        Some(t) if t.trim().is_empty() || t.trim() == "::" => Ok(Some(None)),
        Some(t) => t
            .trim()
            .parse::<Ipv6Addr>()
            .map(|a| Some(Some(a)))
            .map_err(|_| EngineError::bad(key, "an IPv6 address")),
    }
}

fn opt_v6s(p: &Value, key: &str) -> Result<Option<Vec<Ipv6Addr>>> {
    let Some(items) = opt_list(p, key)? else {
        return Ok(None);
    };
    if items.len() > corerouter_model::dhcp6_server::MAX_LIST {
        return Err(EngineError::bad(key, "at most 8 addresses"));
    }
    items
        .iter()
        .map(|t| t.trim().parse::<Ipv6Addr>().map_err(|_| EngineError::bad(key, "IPv6 addresses")))
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn u8_of(p: &Value, key: &str) -> Result<Option<u8>> {
    opt_u32(p, key)?
        .map(|n| u8::try_from(n).map_err(|_| EngineError::bad(key, "0..=255")))
        .transpose()
}

// ---- pools ---------------------------------------------------------------

fn pool_apply(pl: &mut Ipv6Pool, p: &Value) -> Result<()> {
    if let Some(n) = opt_text(p, "name", 63)? {
        pl.name = n.trim().to_owned();
    }
    if p.get("prefix").is_some() {
        let n: Ipv6Net = req_parse(p, "prefix")?;
        pl.prefix = n.trunc();
    }
    if let Some(l) = u8_of(p, "prefix_length")? {
        pl.prefix_length = l;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        pl.comment = c;
    }
    Ok(())
}

fn pool_add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = opt_str(p, "name")?.map(str::trim).filter(|n| !n.is_empty()).ok_or_else(|| EngineError::bad("name", "is required"))?.to_owned();
    let prefix: Ipv6Net = req_parse(p, "prefix")?;
    let len = u8_of(p, "prefix_length")?.ok_or_else(|| EngineError::bad("prefix_length", "is required"))?;
    let d = &mut s.store_mut().candidate_mut().ipv6.dhcp_server;
    if d.pool(&name).is_some() {
        return Err(EngineError::bad("name", format!("pool '{name}' exists")));
    }
    let mut pl = Ipv6Pool { id: d.next_id(), name, prefix: prefix.trunc(), prefix_length: len, comment: String::new() };
    pool_apply(&mut pl, p)?;
    let id = pl.id;
    d.pools.push(pl);
    let warnings = verdict(s, "pools", id)?;
    Ok(json!({"id": id, "warnings": warnings}))
}

fn pool_index(s: &Session, p: &Value) -> Result<usize> {
    find(&s.store().candidate().ipv6.dhcp_server.pools, p, |x| x.id, |x| Some(x.name.as_str()), "IPv6 pool")
}

fn pool_set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = pool_index(s, p)?;
    let d = &mut s.store_mut().candidate_mut().ipv6.dhcp_server;
    let Some(mut pl) = d.pools.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such pool"));
    };
    let old = pl.name.clone();
    pool_apply(&mut pl, p)?;
    if pl.name != old && d.servers.iter().any(|x| x.address_pool.as_deref() == Some(&old) || x.prefix_pool.as_deref() == Some(&old)) {
        return Err(EngineError::bad("name", "a server uses it by name"));
    }
    let id = pl.id;
    if let Some(slot) = d.pools.get_mut(i) {
        *slot = pl;
    }
    let warnings = verdict(s, "pools", id)?;
    Ok(json!({"id": id, "warnings": warnings}))
}

fn pool_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = pool_index(s, p)?;
    let d = &mut s.store_mut().candidate_mut().ipv6.dhcp_server;
    let pl = d.pools.remove(i);
    if let Some(x) = d.servers.iter().find(|x| x.address_pool.as_deref() == Some(&pl.name) || x.prefix_pool.as_deref() == Some(&pl.name)) {
        return Err(EngineError::bad("id", format!("in use by server {}", x.name)));
    }
    Ok(json!({"id": pl.id, "name": pl.name}))
}

fn pool_print(s: &mut Session, _: &Value) -> Result<Value> {
    let cand = s.store().candidate();
    let all = server6::checks(cand);
    let core = s.dhcp6_server();
    let rows: Vec<Value> = cand
        .ipv6
        .dhcp_server
        .pools
        .iter()
        .map(|pl| {
            let bits = u32::from(pl.prefix_length.saturating_sub(pl.prefix.prefix_len())).min(64);
            let size: u64 = if bits >= 64 { u64::MAX } else { 1u64 << bits };
            let used = core.map_or(0, |c| {
                c.leases()
                    .iter()
                    .filter(|l| l.state == State::Bound && pl.prefix.contains(&l.net) && l.net.prefix_len() == pl.prefix_length)
                    .count()
            });
            let mut v = json!({
                "id": pl.id, "name": pl.name, "prefix": pl.prefix, "prefix_length": pl.prefix_length,
                "size": size, "size_text": if bits > 20 { format!("2^{bits}") } else { size.to_string() },
                "used": used, "checks": check_rows(&all, "pools", pl.id),
            });
            if !pl.comment.is_empty()
                && let Some(o) = v.as_object_mut()
            {
                o.insert("comment".into(), json!(pl.comment));
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}

// ---- servers -------------------------------------------------------------

fn server_apply(x: &mut Dhcp6Server, p: &Value) -> Result<()> {
    if let Some(n) = opt_text(p, "name", 63)? {
        x.name = n.trim().to_owned();
    }
    if let Some(i) = opt_parse::<IfName>(p, "interface")? {
        x.interface = i;
    }
    if let Some(v) = opt_ref(p, "address_pool", &["none"])? {
        x.address_pool = v;
    }
    if let Some(v) = opt_ref(p, "prefix_pool", &["none"])? {
        x.prefix_pool = v;
    }
    if let Some(t) = opt_secs(p, "lease_time")? {
        x.lease_time = t;
    }
    if let Some(n) = u8_of(p, "preference")? {
        x.preference = n;
    }
    if let Some(b) = opt_bool(p, "rapid_commit")? {
        x.rapid_commit = b;
    }
    if let Some(n) = u8_of(p, "route_distance")? {
        if n == 0 {
            return Err(EngineError::bad("route_distance", "1..=255"));
        }
        x.route_distance = n;
    }
    if let Some(a) = opt_v6(p, "relay")? {
        x.relay = a;
    }
    if let Some(v) = opt_v6s(p, "dns_server")? {
        x.dns_server = v;
    }
    if let Some(d) = opt_text(p, "domain", 255)? {
        x.domain = d.trim().trim_end_matches('.').to_owned();
    }
    if let Some(z) = opt_ref(p, "dns_zone", &["none"])? {
        x.dns_zone = z.map(|z| corerouter_model::dns_zone::normalize_host(&z));
    }
    if let Some(b) = opt_bool(p, "disabled")? {
        x.disabled = b;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        x.comment = c;
    }
    Ok(())
}

fn server_add(s: &mut Session, p: &Value) -> Result<Value> {
    let iface: IfName = req_parse(p, "interface")?;
    let d = &mut s.store_mut().candidate_mut().ipv6.dhcp_server;
    let id = d.next_id();
    let name = (1..)
        .map(|n| format!("dhcp6-{n}"))
        .find(|n| d.server(n).is_none())
        .unwrap_or_else(|| "dhcp6".into());
    let mut x = Dhcp6Server::new(id, name, iface);
    server_apply(&mut x, p)?;
    if d.server(&x.name).is_some() {
        return Err(EngineError::bad("name", format!("server '{}' exists", x.name)));
    }
    let name = x.name.clone();
    d.servers.push(x);
    let warnings = verdict(s, "servers", id)?;
    Ok(json!({"id": id, "name": name, "warnings": warnings}))
}

fn server_index(s: &Session, p: &Value) -> Result<usize> {
    find(&s.store().candidate().ipv6.dhcp_server.servers, p, |x| x.id, |x| Some(x.name.as_str()), "DHCPv6 server")
}

fn server_set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = server_index(s, p)?;
    let d = &mut s.store_mut().candidate_mut().ipv6.dhcp_server;
    let Some(mut x) = d.servers.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such server"));
    };
    server_apply(&mut x, p)?;
    let (id, name) = (x.id, x.name.clone());
    if let Some(slot) = d.servers.get_mut(i) {
        *slot = x;
    }
    let warnings = verdict(s, "servers", id)?;
    Ok(json!({"id": id, "name": name, "warnings": warnings}))
}

fn server_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = server_index(s, p)?;
    let x = s.store_mut().candidate_mut().ipv6.dhcp_server.servers.remove(i);
    Ok(json!({"id": x.id, "name": x.name}))
}

fn server_print(s: &mut Session, _: &Value) -> Result<Value> {
    let cand = s.store().candidate();
    let all = server6::checks(cand);
    let ports = s.dhcp6_server_ports();
    let core = s.dhcp6_server();
    let rows: Vec<Value> = cand
        .ipv6
        .dhcp_server
        .servers
        .iter()
        .map(|x| {
            let invalid = all.iter().any(|c| about("servers", x.id)(c) && c.level == Level::Error);
            let port = ports.iter().find(|p| p.interface == x.interface);
            let running = core.is_some_and(|c| c.plan().servers.iter().any(|y| y.name == x.name));
            let status = if x.disabled {
                "disabled"
            } else if invalid {
                "invalid"
            } else if port.is_some_and(|p| p.error.is_some() && !p.listening) {
                "error"
            } else if running && (x.relay.is_some() || port.is_some_and(|p| p.listening)) {
                "running"
            } else {
                "starting"
            };
            let bindings = core.map_or(0, |c| c.leases().iter().filter(|l| l.server == x.name && l.state == State::Bound).count());
            let mut v = json!({
                "id": x.id, "name": x.name, "interface": x.interface,
                "lease_time": secs_text(x.lease_time), "preference": x.preference,
                "rapid_commit": x.rapid_commit, "route_distance": x.route_distance,
                "dns_server": x.dns_server, "disabled": x.disabled, "status": status,
                "bindings": bindings, "checks": check_rows(&all, "servers", x.id),
            });
            if let Some(o) = v.as_object_mut() {
                let mut put = |k: &str, val: Option<Value>| {
                    if let Some(val) = val {
                        o.insert(k.into(), val);
                    }
                };
                put("address_pool", x.address_pool.as_ref().map(|a| json!(a)));
                put("prefix_pool", x.prefix_pool.as_ref().map(|a| json!(a)));
                put("relay", x.relay.map(|a| json!(a)));
                put("domain", (!x.domain.is_empty()).then(|| json!(x.domain)));
                put("dns_zone", x.dns_zone.as_ref().map(|a| json!(a)));
                put("comment", (!x.comment.is_empty()).then(|| json!(x.comment)));
                put("error", port.and_then(|p| p.error.clone()).map(|e| json!(e)));
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}

// ---- bindings ------------------------------------------------------------

fn binding_add(s: &mut Session, p: &Value) -> Result<Value> {
    let duid = opt_str(p, "duid")?.ok_or_else(|| EngineError::bad("duid", "is required"))?.trim().to_owned();
    if parse_duid(&duid).is_none() {
        return Err(EngineError::bad("duid", "a DUID: 0x00030001…, 3..=130 bytes"));
    }
    let d = &mut s.store_mut().candidate_mut().ipv6.dhcp_server;
    if d.bindings.len() >= corerouter_model::dhcp6_server::MAX_BINDINGS {
        return Err(EngineError::bad("duid", "too many bindings"));
    }
    let b = Dhcp6Binding {
        id: d.next_id(),
        server: opt_ref(p, "server", &["all"])?.flatten(),
        duid,
        iaid: opt_u32(p, "iaid")?,
        address: opt_parse::<Ipv6Addr>(p, "address")?,
        prefix: opt_parse::<Ipv6Net>(p, "prefix")?.map(|n| n.trunc()),
        disabled: opt_bool(p, "disabled")?.unwrap_or(false),
        comment: opt_text(p, "comment", 256)?.unwrap_or_default(),
    };
    let id = b.id;
    d.bindings.push(b);
    let warnings = verdict(s, "bindings", id)?;
    Ok(json!({"id": id, "warnings": warnings}))
}

fn binding_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let bindings = &s.store().candidate().ipv6.dhcp_server.bindings;
    if let Ok(i) = find(bindings, p, |x| x.id, |_| None, "binding") {
        s.store_mut().candidate_mut().ipv6.dhcp_server.bindings.remove(i);
        return Ok(json!({"static": true}));
    }
    let raw = opt_str(p, "id")?.unwrap_or("").trim().to_owned();
    let net: Ipv6Net = raw
        .parse::<Ipv6Net>()
        .or_else(|_| raw.parse::<Ipv6Addr>().map(|a| Ipv6Net::new(a, 128).unwrap_or_default()))
        .map_err(|_| EngineError::bad("id", "a static binding (*hex) or an address/prefix"))?;
    s.dhcp6_release(&net).map_err(|e| EngineError::bad("id", e))?;
    Ok(json!({"static": false}))
}

fn binding_print(s: &mut Session, p: &Value) -> Result<Value> {
    let only = opt_str(p, "server")?.map(str::to_owned);
    let now = s.dhcp_server_clock().unix;
    let cand = s.store().candidate();
    let mut rows: Vec<(u128, Value)> = Vec::new();
    if let Some(core) = s.dhcp6_server() {
        for l in core.leases().iter().filter(|l| !matches!(l.state, State::Expired)) {
            let mut v = json!({
                "type": if l.kind == IaKind::Pd { "prefix" } else { "address" },
                "address": if l.kind == IaKind::Pd { l.net.to_string() } else { l.net.addr().to_string() },
                "duid": format!("0x{}", server6::hex(&l.duid)),
                "iaid": l.iaid, "server": l.server, "status": l.state.as_str(),
                "via": l.via, "interface": l.interface, "dynamic": true,
            });
            if let Some(o) = v.as_object_mut() {
                if l.state == State::Bound || l.state == State::Offered {
                    o.insert("expires_after".into(), json!(duration_text(l.left(now))));
                    o.insert("expires_after_secs".into(), json!(l.left(now)));
                }
                if !l.host_name.is_empty() {
                    o.insert("host_name".into(), json!(l.host_name));
                }
                if let Some((z, h)) = s.dhcp6_dns(&l.net) {
                    o.insert("dns".into(), json!(format!("{h}.{z}")));
                }
            }
            rows.push((u128::from(l.net.network()), v));
        }
    }
    for b in &cand.ipv6.dhcp_server.bindings {
        for (kind, net) in [
            ("address", b.address.and_then(|a| Ipv6Net::new(a, 128).ok())),
            ("prefix", b.prefix),
        ] {
            let Some(net) = net else { continue };
            if rows.iter().any(|(k, _)| *k == u128::from(net.network())) {
                // Shown with the dynamic row, marked static.
                if let Some((_, v)) = rows.iter_mut().find(|(k, _)| *k == u128::from(net.network()))
                    && let Some(o) = v.as_object_mut()
                {
                    o.insert("id".into(), json!(b.id));
                    o.insert("dynamic".into(), json!(false));
                }
                continue;
            }
            let mut v = json!({
                "id": b.id, "type": kind,
                "address": if kind == "prefix" { net.to_string() } else { net.addr().to_string() },
                "duid": b.duid, "server": b.server.clone().unwrap_or_else(|| "all".into()),
                "status": "waiting", "dynamic": false,
            });
            if let Some(o) = v.as_object_mut() {
                if let Some(i) = b.iaid {
                    o.insert("iaid".into(), json!(i));
                }
                if !b.comment.is_empty() {
                    o.insert("comment".into(), json!(b.comment));
                }
            }
            rows.push((u128::from(net.network()), v));
        }
    }
    rows.sort_by_key(|(k, _)| *k);
    Ok(Value::Array(
        rows.into_iter()
            .map(|(_, v)| v)
            .filter(|v| only.as_deref().is_none_or(|o| v.get("server").and_then(Value::as_str) == Some(o)))
            .collect(),
    ))
}

// ---- relays --------------------------------------------------------------

fn relay_add(s: &mut Session, p: &Value) -> Result<Value> {
    let iface: IfName = req_parse(p, "interface")?;
    let d = &mut s.store_mut().candidate_mut().ipv6.dhcp_server;
    let id = d.next_id();
    let name = match opt_text(p, "name", 63)? {
        Some(n) => n.trim().to_owned(),
        None => (1..)
            .map(|n| format!("relay6-{n}"))
            .find(|n| !d.relays.iter().any(|r| r.name == *n))
            .unwrap_or_default(),
    };
    let r = Dhcp6Relay {
        id,
        name: name.clone(),
        interface: iface,
        dhcp_server: opt_v6s(p, "dhcp_server")?.unwrap_or_default(),
        link_address: opt_v6(p, "link_address")?.flatten(),
        disabled: opt_bool(p, "disabled")?.unwrap_or(false),
        comment: opt_text(p, "comment", 256)?.unwrap_or_default(),
    };
    d.relays.push(r);
    let warnings = verdict(s, "relays", id)?;
    Ok(json!({"id": id, "name": name, "warnings": warnings}))
}

fn relay_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = find(&s.store().candidate().ipv6.dhcp_server.relays, p, |x| x.id, |x| Some(x.name.as_str()), "DHCPv6 relay")?;
    let r = s.store_mut().candidate_mut().ipv6.dhcp_server.relays.remove(i);
    Ok(json!({"id": r.id, "name": r.name}))
}

fn relay_print(s: &mut Session, _: &Value) -> Result<Value> {
    let cand = s.store().candidate();
    let all = server6::checks(cand);
    let rows: Vec<Value> = cand
        .ipv6
        .dhcp_server
        .relays
        .iter()
        .map(|r| {
            let c = s.dhcp6_relay_counters(&r.name).unwrap_or_default();
            let mut v = json!({
                "id": r.id, "name": r.name, "interface": r.interface, "dhcp_server": r.dhcp_server,
                "disabled": r.disabled, "requests": c.requests, "replies": c.replies, "dropped": c.dropped,
                "checks": check_rows(&all, "relays", r.id),
            });
            if let Some(o) = v.as_object_mut() {
                if let Some(a) = r.link_address {
                    o.insert("link_address".into(), json!(a));
                }
                if !r.comment.is_empty() {
                    o.insert("comment".into(), json!(r.comment));
                }
                if let Some(e) = s.dhcp6_uplink_error() {
                    o.insert("error".into(), json!(e));
                }
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}
