//! /ip dhcp-server (G4.2a): the servers, and the helpers every
//! `dhcp_server_*.rs` area shares. The config is ordinary config (journaled,
//! saved, rolled back); the leases, counters and alerts seen are the
//! server's operational state (`crate::dhcp_server`).
//!
//! Every change is checked at once against the operator mistakes of
//! `proto_dhcp::server::checks` (a pool that hands out the gateway, two
//! pools sharing addresses…): an error about the item refuses the command,
//! naming the parameter; warnings come back in the reply (`warnings`).

use std::net::Ipv4Addr;

use corerouter_model::dhcp_server::{Authoritative, DhcpServer};
use corerouter_model::firewall::Name;
use corerouter_model::{IfName, ItemId};
use corerouter_proto_dhcp::server::checks::{self, Check, Level};
use corerouter_proto_dhcp::server::leases::State;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32};
use super::dhcp_client::opt_list;
use super::{CommandSpec, always};
use crate::dhcp_client::duration_text;
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.dhcp-server.add",
        "Add DHCP Server",
        ["IP", "DHCP Server"],
        None,
        "{name?: string (default dhcpN), interface: string, address_pool?: string (a pool; static-only or empty: only static leases, the default), lease_time?: duration (30m default; 1m..=365d; seconds or 1h30m), authoritative?: yes | no | after-2sec-delay | after-10sec-delay (default yes: NAK requests for addresses it cannot give), conflict_detection?: bool (default yes: ARP probe before offering, ~0.5 s; an address that answers is held as conflict), always_broadcast?: bool, server_address?: ipv4 (empty: the interface's address in the client's network), relay?: ipv4 (serve only requests relayed by this agent; empty: clients on the link), dhcp_option_set?: string, address_lists?: [string] | string (firewall lists each bound address joins), client_mac_limit?: u32 (leases one MAC may hold; 0 or empty: unlimited), client_rate_limit?: u32 (messages a second per client, default 10; 0: no limit), relay_info_trusted?: bool (believe option 82 in requests without a relay, giaddr 0: a layer-2 agent such as an OLT adds it; default no: a client's own option 82 is ignored), use_radius?: no | yes | accounting (RouterOS use-radius; yes: RADIUS service=dhcp authorizes each new client, User-Name = ipoe_username, and accounts its lease; default no), ipoe?: bool (each bound lease is a subscriber session: PPP › Active Connections, XDP policer, accounting, CoA; implied by use_radius; default no), ipoe_username?: mac | circuit-id | remote-id | circuit-remote (what names a subscriber for RADIUS and ppp.secret service=ipoe; default mac), ipoe_unknown?: accept | reject (a client without a ppp.secret service=ipoe when RADIUS is not asked; default accept), disabled?: bool, comment?: string} → {id, name, warnings}",
        always,
        add
    ),
    cmd!(
        "ip.dhcp-server.set",
        "Set DHCP Server",
        [],
        None,
        "{id: *hex | name, name?: string, interface?: string, address_pool?: string (a pool; static-only or empty: only static leases, the default), lease_time?: duration (30m default; 1m..=365d; seconds or 1h30m), authoritative?: yes | no | after-2sec-delay | after-10sec-delay (default yes: NAK requests for addresses it cannot give), conflict_detection?: bool (default yes: ARP probe before offering, ~0.5 s; an address that answers is held as conflict), always_broadcast?: bool, server_address?: ipv4 (empty: the interface's address in the client's network), relay?: ipv4 (serve only requests relayed by this agent; empty: clients on the link), dhcp_option_set?: string, address_lists?: [string] | string (firewall lists each bound address joins), client_mac_limit?: u32 (leases one MAC may hold; 0 or empty: unlimited), client_rate_limit?: u32 (messages a second per client, default 10; 0: no limit), relay_info_trusted?: bool (believe option 82 in requests without a relay, giaddr 0: a layer-2 agent such as an OLT adds it; default no: a client's own option 82 is ignored), use_radius?: no | yes | accounting (RouterOS use-radius; yes: RADIUS service=dhcp authorizes each new client, User-Name = ipoe_username, and accounts its lease; default no), ipoe?: bool (each bound lease is a subscriber session: PPP › Active Connections, XDP policer, accounting, CoA; implied by use_radius; default no), ipoe_username?: mac | circuit-id | remote-id | circuit-remote (what names a subscriber for RADIUS and ppp.secret service=ipoe; default mac), ipoe_unknown?: accept | reject (a client without a ppp.secret service=ipoe when RADIUS is not asked; default accept), disabled?: bool, comment?: string} → {id, name, warnings}",
        has_servers,
        set
    ),
    cmd!(
        "ip.dhcp-server.remove",
        "Remove DHCP Server",
        [],
        None,
        "{id: *hex | name} → {id, name}",
        has_servers,
        remove
    ),
    cmd!(query "ip.dhcp-server.print", "DHCP Server", ["IP", "DHCP Server"], None,
        "{} → [{id, name, interface, address_pool (static-only when none), lease_time, lease_time_secs, authoritative, conflict_detection, always_broadcast, server_address?, relay?, dhcp_option_set?, address_lists, client_mac_limit?, client_rate_limit, relay_info_trusted, use_radius, ipoe (sessions from leases), ipoe_username, ipoe_unknown, disabled, comment?, status (running | disabled | invalid | starting | error), listening?, error?, bound (leases bound now), checks: [{label, level (ok | warn | error), text}]}]",
        always, print),
];

fn has_servers(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.dhcp_server.servers.is_empty() {
        Err("there are no DHCP servers (ip.dhcp-server.add)".into())
    } else {
        Ok(())
    }
}

// ---- helpers shared by the dhcp_server_* areas ---------------------------

/// The index of the item `p["id"]` names: `*hex` or its name.
pub(super) fn find<T>(
    items: &[T],
    p: &Value,
    id_of: impl Fn(&T) -> ItemId,
    name_of: impl Fn(&T) -> Option<&str>,
    what: &str,
) -> Result<usize> {
    let raw = opt_str(p, "id")?.ok_or_else(|| EngineError::bad("id", "is required"))?;
    let raw = raw.trim();
    let by_id = raw
        .starts_with('*')
        .then(|| raw.parse::<ItemId>().ok())
        .flatten();
    items
        .iter()
        .position(|it| match by_id {
            Some(id) => id_of(it) == id,
            None => name_of(it) == Some(raw),
        })
        .ok_or_else(|| {
            let shown: String = raw.chars().take(64).collect();
            EngineError::bad("id", format!("no {what} '{shown}'"))
        })
}

/// An optional IPv4 address; `""` clears it (`Some(None)`).
pub(super) fn opt_ip(p: &Value, key: &str) -> Result<Option<Option<Ipv4Addr>>> {
    match opt_str(p, key)? {
        None => Ok(None),
        Some(t) if t.trim().is_empty() || t.trim() == "0.0.0.0" => Ok(Some(None)),
        Some(t) => t
            .trim()
            .parse::<Ipv4Addr>()
            .map(|ip| Some(Some(ip)))
            .map_err(|_| EngineError::bad(key, "an IPv4 address (192.168.88.1)")),
    }
}

/// A list of IPv4 addresses (`[..]` or `"a,b"`).
pub(super) fn opt_ips(p: &Value, key: &str) -> Result<Option<Vec<Ipv4Addr>>> {
    let Some(items) = opt_list(p, key)? else {
        return Ok(None);
    };
    if items.len() > corerouter_model::dhcp_server::MAX_LIST {
        return Err(EngineError::bad(key, "at most 16 addresses"));
    }
    items
        .iter()
        .map(|t| {
            t.trim()
                .parse::<Ipv4Addr>()
                .map_err(|_| EngineError::bad(key, format!("'{}' is not an IPv4 address", t.chars().take(32).collect::<String>())))
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

/// Names (options, lists): `[..]` or `"a,b"`.
pub(super) fn opt_strings(p: &Value, key: &str) -> Result<Option<Vec<String>>> {
    let Some(items) = opt_list(p, key)? else {
        return Ok(None);
    };
    if items.len() > corerouter_model::dhcp_server::MAX_LIST {
        return Err(EngineError::bad(key, "at most 16 items"));
    }
    Ok(Some(items.into_iter().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect()))
}

pub(super) fn opt_lists(p: &Value, key: &str) -> Result<Option<Vec<Name>>> {
    let Some(items) = opt_strings(p, key)? else {
        return Ok(None);
    };
    items
        .iter()
        .map(|t| t.parse::<Name>().map_err(|e| EngineError::bad(key, e.to_string())))
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

/// A reference to a named item; `""` / `none` clears it.
pub(super) fn opt_ref(p: &Value, key: &str, none: &[&str]) -> Result<Option<Option<String>>> {
    match opt_str(p, key)? {
        None => Ok(None),
        Some(t) if t.trim().is_empty() || none.contains(&t.trim()) => Ok(Some(None)),
        Some(t) if t.len() > 63 => Err(EngineError::bad(key, "at most 63 characters")),
        Some(t) => Ok(Some(Some(t.trim().to_owned()))),
    }
}

/// A duration: seconds or `1h30m`, `365d`, `52w` (RouterOS), as u32.
pub(super) fn opt_secs(p: &Value, key: &str) -> Result<Option<u32>> {
    let text = match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return Err(EngineError::bad(key, "seconds or like 1h30m")),
    };
    corerouter_model::dhcp_server::parse_duration(&text)
        .and_then(|s| u32::try_from(s).ok())
        .map(Some)
        .ok_or_else(|| EngineError::bad(key, "seconds or like 30m, 1d12h, 52w (at most 10 years)"))
}

/// The checks about item `id` in the candidate: the first error refuses
/// the command (on the parameter it names); the warnings come back.
pub(super) fn verdict(s: &Session, kind: &str, id: ItemId) -> Result<Vec<String>> {
    let all = checks::checks(s.store().candidate());
    let mine = about(kind, id);
    if let Some(e) = all.iter().find(|c| mine(c) && c.level == Level::Error) {
        let field = e.path.rsplit('.').next().unwrap_or("id");
        return Err(EngineError::bad(field, e.text.clone()));
    }
    // Errors elsewhere that this change caused (a pool now overlapping one
    // it did not before) are reported by the commit; here, warnings.
    Ok(all
        .into_iter()
        .filter(|c| mine(c) && c.level == Level::Warn)
        .map(|c| c.text)
        .collect())
}

/// Whether a check is about item `id` of list `kind` (`servers`, `pools`…:
/// pools and the DHCP items count their ids apart).
pub(super) fn about(kind: &str, id: ItemId) -> impl Fn(&Check) -> bool {
    let tag = format!("{kind}[{id}]");
    move |c: &Check| c.item == id && c.path.contains(&tag)
}

pub(super) fn check_rows(all: &[Check], kind: &str, id: ItemId) -> Vec<Value> {
    let mine = about(kind, id);
    all.iter()
        .filter(|c| mine(c))
        .map(|c| json!({"label": c.label, "level": c.level, "text": c.text}))
        .collect()
}

pub(super) fn secs_text(secs: u32) -> String {
    duration_text(u64::from(secs))
}

// ---- servers -------------------------------------------------------------

fn apply(d: &mut DhcpServer, p: &Value) -> Result<()> {
    if let Some(n) = opt_text(p, "name", 63)? {
        d.name = n;
    }
    if let Some(i) = opt_parse::<IfName>(p, "interface")? {
        d.interface = i;
    }
    if let Some(pool) = opt_ref(p, "address_pool", &["static-only", "none"])? {
        d.address_pool = pool;
    }
    if let Some(t) = opt_secs(p, "lease_time")? {
        d.lease_time = t;
    }
    if let Some(a) = opt_parse::<Authoritative>(p, "authoritative")? {
        d.authoritative = a;
    }
    if let Some(b) = opt_bool(p, "conflict_detection")? {
        d.conflict_detection = b;
    }
    if let Some(b) = opt_bool(p, "always_broadcast")? {
        d.always_broadcast = b;
    }
    if let Some(ip) = opt_ip(p, "server_address")? {
        d.server_address = ip;
    }
    if let Some(ip) = opt_ip(p, "relay")? {
        d.relay = ip;
    }
    if let Some(set) = opt_ref(p, "dhcp_option_set", &["none"])? {
        d.dhcp_option_set = set;
    }
    if let Some(l) = opt_lists(p, "address_lists")? {
        d.address_lists = l;
    }
    match p.get("client_mac_limit") {
        Some(Value::String(t)) if t.trim().is_empty() || t.trim() == "unlimited" => {
            d.client_mac_limit = None;
        }
        _ => {
            if let Some(n) = opt_u32(p, "client_mac_limit")? {
                d.client_mac_limit = (n > 0).then_some(n);
            }
        }
    }
    if let Some(n) = opt_u32(p, "client_rate_limit")? {
        d.client_rate_limit = n;
    }
    if let Some(b) = opt_bool(p, "relay_info_trusted")? {
        d.relay_info_trusted = b;
    }
    if let Some(v) = opt_parse(p, "use_radius")? {
        d.use_radius = v;
    }
    if let Some(b) = opt_bool(p, "ipoe")? {
        d.ipoe = b;
    }
    if let Some(v) = opt_parse(p, "ipoe_username")? {
        d.ipoe_username = v;
    }
    if let Some(v) = opt_parse(p, "ipoe_unknown")? {
        d.ipoe_unknown = v;
    }
    if let Some(b) = opt_bool(p, "disabled")? {
        d.disabled = b;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        d.comment = c;
    }
    Ok(())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let interface: IfName = super::args::req_parse(p, "interface")?;
    let d = &mut s.store_mut().candidate_mut().ip.dhcp_server;
    if d.servers.len() >= corerouter_model::dhcp_server::MAX_SERVERS {
        return Err(EngineError::bad("interface", "too many DHCP servers"));
    }
    let id = d.next_id();
    let name = (1..)
        .map(|n| format!("dhcp{n}"))
        .find(|n| d.server(n).is_none())
        .unwrap_or_else(|| "dhcp".into());
    let mut srv = DhcpServer::new(id, name, interface);
    apply(&mut srv, p)?;
    if d.server(&srv.name).is_some() {
        return Err(EngineError::bad("name", format!("server '{}' exists", srv.name)));
    }
    let name = srv.name.clone();
    d.servers.push(srv);
    let warnings = verdict(s, "servers", id)?;
    Ok(json!({"id": id, "name": name, "warnings": warnings}))
}

fn index(s: &Session, p: &Value) -> Result<usize> {
    find(
        &s.store().candidate().ip.dhcp_server.servers,
        p,
        |x| x.id,
        |x| Some(x.name.as_str()),
        "DHCP server",
    )
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let d = &mut s.store_mut().candidate_mut().ip.dhcp_server;
    let Some(mut srv) = d.servers.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such DHCP server"));
    };
    let old = srv.name.clone();
    apply(&mut srv, p)?;
    if srv.name != old {
        if d.server(&srv.name).is_some() {
            return Err(EngineError::bad("name", format!("server '{}' exists", srv.name)));
        }
        // Leases and matchers name it: follow the rename.
        for l in d.leases.iter_mut().filter(|l| l.server.as_deref() == Some(&old)) {
            l.server = Some(srv.name.clone());
        }
        for m in d.matchers.iter_mut().filter(|m| m.server.as_deref() == Some(&old)) {
            m.server = Some(srv.name.clone());
        }
    }
    let (id, name) = (srv.id, srv.name.clone());
    if let Some(slot) = d.servers.get_mut(i) {
        *slot = srv;
    }
    let warnings = verdict(s, "servers", id)?;
    Ok(json!({"id": id, "name": name, "warnings": warnings}))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let d = &mut s.store_mut().candidate_mut().ip.dhcp_server;
    let srv = d.servers.remove(i);
    let users: Vec<String> = d
        .leases
        .iter()
        .filter(|l| l.server.as_deref() == Some(&srv.name))
        .map(|l| l.address.to_string())
        .chain(
            d.matchers
                .iter()
                .filter(|m| m.server.as_deref() == Some(&srv.name))
                .map(|m| format!("matcher {}", m.name)),
        )
        .collect();
    if !users.is_empty() {
        return Err(EngineError::bad(
            "id",
            format!(
                "static leases / matchers name it: {} (remove them or set server=all)",
                users.join(", ")
            ),
        ));
    }
    Ok(json!({"id": srv.id, "name": srv.name}))
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let cand = s.store().candidate();
    let all = checks::checks(cand);
    let ports = s.dhcp_server_ports();
    let core = s.dhcp_server();
    let invalid = |id: ItemId| all.iter().any(|c| about("servers", id)(c) && c.level == Level::Error);
    let rows: Vec<Value> = cand
        .ip
        .dhcp_server
        .servers
        .iter()
        .map(|d| {
            let port = ports.iter().find(|p| p.interface == d.interface);
            let running = core.is_some_and(|c| c.plan().servers.iter().any(|x| x.name == d.name));
            let status = if d.disabled {
                "disabled"
            } else if invalid(d.id) {
                "invalid"
            } else if port.is_some_and(|p| p.error.is_some() && p.listening.is_none()) {
                "error"
            } else if running && port.is_some_and(|p| p.listening.is_some()) {
                "running"
            } else {
                "starting"
            };
            let bound = core.map_or(0, |c| {
                c.leases()
                    .iter()
                    .filter(|l| l.server == d.name && l.state == State::Bound)
                    .count()
            });
            let mut v = json!({
                "id": d.id,
                "name": d.name,
                "interface": d.interface,
                "address_pool": d.address_pool.clone().unwrap_or_else(|| "static-only".into()),
                "lease_time": secs_text(d.lease_time),
                "lease_time_secs": d.lease_time,
                "authoritative": d.authoritative.as_str(),
                "conflict_detection": d.conflict_detection,
                "always_broadcast": d.always_broadcast,
                "address_lists": d.address_lists.iter().map(Name::as_str).collect::<Vec<_>>(),
                "client_rate_limit": d.client_rate_limit,
                "relay_info_trusted": d.relay_info_trusted,
                "use_radius": d.use_radius.as_str(),
                "ipoe": d.sessions(),
                "ipoe_username": d.ipoe_username.as_str(),
                "ipoe_unknown": d.ipoe_unknown.as_str(),
                "disabled": d.disabled,
                "status": status,
                "bound": bound,
                "checks": check_rows(&all, "servers", d.id),
            });
            if let Some(o) = v.as_object_mut() {
                let mut put = |k: &str, val: Option<Value>| {
                    if let Some(val) = val {
                        o.insert(k.into(), val);
                    }
                };
                put("server_address", d.server_address.map(|a| json!(a)));
                put("relay", d.relay.map(|a| json!(a)));
                put("dhcp_option_set", d.dhcp_option_set.as_ref().map(|a| json!(a)));
                put("client_mac_limit", d.client_mac_limit.map(|a| json!(a)));
                put("comment", (!d.comment.is_empty()).then(|| json!(d.comment)));
                put("listening", port.and_then(|p| p.listening.clone()).map(|a| json!(a)));
                put("error", port.and_then(|p| p.error.clone()).map(|a| json!(a)));
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}
