//! /interface pppoe-client (G3.9ga): the router dialing a PPPoE server, as
//! the WAN of a provider. A client is an interface of type `pppoe-out`
//! (`InterfaceKind::PppoeClient`); `interface.remove` also removes it.
//! Names and defaults are RouterOS v7's (`add-default-route=no`,
//! `default-route-distance=1`, `max-mtu=1460`, `keepalive-timeout=60`); the
//! session itself runs in `crate::pppoe_client`.

use corerouter_model::pppoe_client::{
    Allow, MAX_MTU, MAX_NAME, MIN_MTU, PppoeClient, relay_peer,
};
use corerouter_model::{Config, IfName, Interface, InterfaceKind};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text, opt_u32, req_parse};
use super::interface::{new_name, refuse_unmanaged};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

/// RFC 4638 lets a link carry up to 1500 when the BNG agrees.
const MAX_PAYLOAD: u32 = 1500;
/// Longest `keepalive-timeout` (RouterOS takes up to an hour).
const MAX_KEEPALIVE: u32 = 3600;
/// Longest Host-Uniq, bytes.
const MAX_HOST_UNIQ: usize = 32;
/// `pppoe-outN` names tried for a client added without a name.
const MAX_DEFAULT_NAMES: usize = 64;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "interface.pppoe-client.add",
        "Add PPPoE Client",
        ["Interfaces", "PPP"],
        None,
        "{name?: string (the session's interface; default the first free pppoe-outN, as RouterOS), interface: string (Ethernet port, VLAN or bond it dials on), user: string, password?: string (write-only; CHAP and MS-CHAP need it in clear, so it is sealed at rest), service_name?: string (empty = any), ac_name?: string (only offers from this concentrator; empty = the first), host_uniq?: string (hex, up to 32 bytes; empty = one the router picks), add_default_route?: bool (default false, as RouterOS), default_route_distance?: int 1..255 (default 1), use_peer_dns?: bool (default false), profile?: string (/ppp profile: change-tcp-mss, use-ipv6; default default), max_mtu?: int 64..1500 (default 1460; above 1492 asks for RFC 4638), max_mru?: int 64..1500 (default 1460), keepalive_timeout?: int 0..3600 | disabled (seconds without an LCP echo answer; default 60), allow?: [mschap2|mschap1|chap|pap] | string, disabled?: bool, comment?: string} → {name, warnings}",
        always,
        add
    ),
    cmd!(
        "interface.pppoe-client.set",
        "Set PPPoE Client",
        [],
        None,
        "{name: string, interface?: string, user?: string, password?: string (write-only; CHAP and MS-CHAP need it in clear, so it is sealed at rest), service_name?: string (empty = any), ac_name?: string (only offers from this concentrator; empty = the first), host_uniq?: string (hex, up to 32 bytes; empty = one the router picks), add_default_route?: bool (default false, as RouterOS), default_route_distance?: int 1..255 (default 1), use_peer_dns?: bool (default false), profile?: string (/ppp profile: change-tcp-mss, use-ipv6; default default), max_mtu?: int 64..1500 (default 1460; above 1492 asks for RFC 4638), max_mru?: int 64..1500 (default 1460), keepalive_timeout?: int 0..3600 | disabled (seconds without an LCP echo answer; default 60), allow?: [mschap2|mschap1|chap|pap] | string, disabled?: bool, comment?: string} → {name, warnings}",
        has_clients,
        set
    ),
    cmd!(
        "interface.pppoe-client.remove",
        "Remove PPPoE Client",
        [],
        None,
        "{name: string} → {name}",
        has_clients,
        remove
    ),
    cmd!(
        "interface.pppoe-client.enable",
        "Enable PPPoE Client",
        [],
        None,
        "{name: string} → {name}",
        has_clients,
        enable
    ),
    cmd!(
        "interface.pppoe-client.disable",
        "Disable PPPoE Client",
        [],
        None,
        "{name: string} → {name}",
        has_clients,
        disable
    ),
    cmd!(
        "interface.pppoe-client.reconnect",
        "Reconnect PPPoE Client",
        [],
        None,
        "{name: string} → {name, status}",
        has_clients,
        reconnect
    ),
    cmd!(query "interface.pppoe-client.list", "PPPoE Client", ["Interfaces", "PPP"], None,
        "{show_sensitive?: bool (the passwords in clear; group full)} → [{name, interface, user, password, service_name, ac_name, host_uniq, add_default_route, default_route_distance, use_peer_dns, profile, max_mtu, max_mru, keepalive_timeout, allow, disabled, comment, status (disabled | dialing | connecting | authenticating | connected | disconnected | disconnecting | error | stopped), local_address, remote_address, uptime_secs, mtu, retry_in_secs, attempts, last_down ({reason (no-offer | service-error | ac-error | padt | lcp | auth-failed | ncp | keepalive | local), message, time, uptime_secs} or null), error}]",
        always, list),
    cmd!(query "interface.pppoe-client.monitor", "PPPoE Client Monitor", [], None,
        "{name: string} → {name, status, uptime_secs, service_name, ac_name, ac_mac, session_id, mtu, mru, encoding (mschap2 | mschap1 | chap | pap | none), local_address, remote_address, dns, attempts, retry_in_secs, last_error, rx_packets, rx_bytes, tx_packets, tx_bytes, dropped, mss_clamped, last_down}",
        has_clients, monitor),
    cmd!(query "interface.pppoe-client.history", "PPPoE Client History", [], None,
        "{name?: string, limit?: int (newest first, default 100)} → [{seq, time, name, event (dialing | connected | down | error | padt-stale), message}]",
        always, history),
    cmd!(query "interface.pppoe-client.preview", "PPPoE Client Preview", [], None,
        "{id?: string (the client being edited; leave out for a new one), name?: string, interface?: string, user?: string, password?: string, service_name?: string, ac_name?: string, host_uniq?: string, add_default_route?: bool, default_route_distance?: int 1..255, use_peer_dns?: bool, profile?: string, max_mtu?: int 64..1500, max_mru?: int 64..1500, keepalive_timeout?: int 0..3600 | disabled, allow?: [mschap2|mschap1|chap|pap] | string, disabled?: bool, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}]}",
        always, preview),
];

fn has_clients(s: &Session) -> std::result::Result<(), String> {
    if clients(s.store().candidate()).next().is_none() {
        Err("there are no PPPoE clients".into())
    } else {
        Ok(())
    }
}

fn clients(cfg: &Config) -> impl Iterator<Item = (&IfName, &Interface, &PppoeClient)> {
    cfg.interfaces.iter().filter_map(|(n, i)| match &i.kind {
        InterfaceKind::PppoeClient(c) => Some((n, i, &**c)),
        _ => None,
    })
}

fn client_of<'a>(cfg: &'a Config, name: &IfName) -> Result<&'a PppoeClient> {
    match cfg.interfaces.get(name).map(|i| &i.kind) {
        Some(InterfaceKind::PppoeClient(c)) => Ok(c),
        Some(k) => Err(EngineError::bad(
            "name",
            format!("'{name}' is a {}, not a PPPoE client", k.label()),
        )),
        None => Err(EngineError::bad(
            "name",
            format!("no PPPoE client '{name}' (see interface.pppoe-client.list)"),
        )),
    }
}

/// A short name-like field: bounded, printable.
fn opt_short(p: &Value, key: &str) -> Result<Option<String>> {
    opt_text(p, key, MAX_NAME).map(|v| v.map(|t| t.trim().to_owned()))
}

fn mtu_of(p: &Value, key: &str) -> Result<Option<u16>> {
    opt_u32(p, key)?
        .map(|v| {
            if (u32::from(MIN_MTU)..=MAX_PAYLOAD).contains(&v) {
                u16::try_from(v).map_err(|_| EngineError::bad(key, "64..=1500"))
            } else {
                Err(EngineError::bad(
                    key,
                    format!("must be 64..=1500 (1492 is the most without RFC 4638), not {v}"),
                ))
            }
        })
        .transpose()
}

fn keepalive_of(p: &Value) -> Result<Option<u32>> {
    match p.get("keepalive_timeout") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim() == "disabled" => Ok(Some(0)),
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n <= MAX_KEEPALIVE)
            .map(Some)
            .ok_or_else(|| {
                EngineError::bad("keepalive_timeout", "seconds 0..=3600, or \"disabled\"")
            }),
    }
}

fn allow_of(p: &Value) -> Result<Option<Vec<Allow>>> {
    let raw: Vec<String> = match p.get("allow") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_owned()).collect(),
        Some(Value::Array(a)) => a
            .iter()
            .take(8)
            .map(|v| {
                v.as_str()
                    .map(|t| t.trim().to_owned())
                    .ok_or_else(|| EngineError::bad("allow", "a list of mschap2, mschap1, chap, pap"))
            })
            .collect::<Result<_>>()?,
        Some(_) => return Err(EngineError::bad("allow", "a list of mschap2, mschap1, chap, pap")),
    };
    let mut out: Vec<Allow> = Vec::new();
    for r in raw.iter().filter(|r| !r.is_empty()).take(8) {
        let a = Allow::parse(r).ok_or_else(|| {
            EngineError::bad(
                "allow",
                format!(
                    "'{}' is not one of mschap2, mschap1, chap, pap",
                    r.chars().take(16).collect::<String>()
                ),
            )
        })?;
        if !out.contains(&a) {
            out.push(a);
        }
    }
    if out.is_empty() {
        return Err(EngineError::bad(
            "allow",
            "at least one of mschap2, mschap1, chap, pap",
        ));
    }
    Ok(Some(out))
}

/// Why `uplink` cannot carry a PPPoE client, if it cannot.
fn uplink_problem(cfg: &Config, uplink: &IfName) -> Option<String> {
    let Some(i) = cfg.interfaces.get(uplink) else {
        return Some(format!("no interface '{uplink}' (see interface.list)"));
    };
    match &i.kind {
        InterfaceKind::Ethernet
        | InterfaceKind::Vlan { .. }
        | InterfaceKind::Bonding { .. }
        | InterfaceKind::Bridge => {}
        k => {
            return Some(format!(
                "'{uplink}' is a {}; PPPoE runs on an Ethernet port, VLAN, bond or bridge",
                k.label()
            ));
        }
    }
    if let Some(b) = &i.bond {
        return Some(format!(
            "'{uplink}' is a slave of bond '{b}'; dial on '{b}' instead"
        ));
    }
    if let Some(b) = &i.bridge {
        return Some(format!(
            "'{uplink}' is a port of bridge '{b}'; dial on '{b}' instead"
        ));
    }
    None
}

/// Apply the optional keys of `p` on `c` (all but the password).
fn update(cfg: &Config, c: &mut PppoeClient, p: &Value) -> Result<()> {
    if let Some(i) = super::args::opt_parse::<IfName>(p, "interface")? {
        if let Some(why) = uplink_problem(cfg, &i) {
            return Err(EngineError::bad("interface", why));
        }
        c.interface = i;
    }
    if let Some(u) = opt_short(p, "user")? {
        if u.is_empty() {
            return Err(EngineError::bad("user", "must not be empty"));
        }
        c.user = u;
    }
    if let Some(v) = opt_short(p, "service_name")? {
        c.service_name = v;
    }
    if let Some(v) = opt_short(p, "ac_name")? {
        c.ac_name = v;
    }
    if let Some(v) = opt_str(p, "host_uniq")? {
        let v = v.trim();
        if !v.is_empty() {
            let ok = crate::pppoe_client::parse_hex(v).is_some_and(|b| b.len() <= MAX_HOST_UNIQ);
            if !ok {
                return Err(EngineError::bad(
                    "host_uniq",
                    "hex digits (0x optional), an even count, up to 32 bytes",
                ));
            }
        }
        c.host_uniq = v.trim_start_matches("0x").to_lowercase();
    }
    if let Some(b) = opt_bool(p, "add_default_route")? {
        c.add_default_route = b;
    }
    if let Some(d) = opt_u32(p, "default_route_distance")? {
        c.default_route_distance = u8::try_from(d)
            .ok()
            .filter(|d| *d >= 1)
            .ok_or_else(|| EngineError::bad("default_route_distance", "must be 1..=255"))?;
    }
    if let Some(b) = opt_bool(p, "use_peer_dns")? {
        c.use_peer_dns = b;
    }
    if let Some(pr) = opt_short(p, "profile")? {
        let pr = if pr.is_empty() { "default".to_owned() } else { pr };
        if cfg.ppp.profile(&pr).is_none() {
            return Err(EngineError::bad(
                "profile",
                format!("no PPP profile '{pr}' (see ppp.profile.list)"),
            ));
        }
        c.profile = pr;
    }
    if let Some(m) = mtu_of(p, "max_mtu")? {
        c.max_mtu = m;
    }
    if let Some(m) = mtu_of(p, "max_mru")? {
        c.max_mru = m;
    }
    if let Some(k) = keepalive_of(p)? {
        c.keepalive_timeout = k;
    }
    if let Some(a) = allow_of(p)? {
        c.allow = a;
    }
    Ok(())
}

fn seal(s: &mut Session, c: &mut PppoeClient, p: &Value) -> Result<()> {
    if let Some(pw) = super::ppp_secret::password_of(p)? {
        let key = crate::sealing::key(s).map_err(EngineError::Internal)?;
        c.password = key.seal(pw).map_err(EngineError::Internal)?;
    }
    Ok(())
}

/// The default routes `cfg` would have, other than client `me`'s:
/// (who, distance).
fn other_defaults(cfg: &Config, me: Option<&IfName>) -> Vec<(String, u8)> {
    let mut out: Vec<(String, u8)> = cfg
        .ip
        .routes
        .iter()
        .filter(|r| !r.disabled && r.dst_address.prefix_len() == 0 && r.dst_address.addr().is_ipv4())
        .map(|r| (format!("static route {}", r.id), r.distance))
        .collect();
    out.extend(
        cfg.ip
            .dhcp_clients
            .iter()
            .filter(|c| !c.disabled && c.add_default_route != corerouter_model::dhcp_client::AddDefaultRoute::No)
            .map(|c| {
                (
                    format!("DHCP client on {}", c.interface),
                    c.default_route_distance,
                )
            }),
    );
    out.extend(
        clients(cfg)
            .filter(|(n, i, c)| Some(*n) != me && !i.disabled && c.add_default_route)
            .map(|(n, _, c)| (format!("PPPoE client {n}"), c.default_route_distance)),
    );
    out
}

/// The warnings of client `name` with settings `c` in `cfg` (`name` absent
/// from `cfg` for a new one).
fn warnings(cfg: &Config, name: &IfName, c: &PppoeClient, disabled: bool) -> Vec<String> {
    let mut w = Vec::new();
    let others = other_defaults(cfg, Some(name));
    if c.add_default_route && !disabled {
        for (who, d) in others.iter().filter(|(_, d)| *d == c.default_route_distance) {
            w.push(format!(
                "{who} also adds a default route at distance {d}: both share the traffic \
                 (ECMP); give one of them a higher default_route_distance to keep it as a backup"
            ));
        }
    } else if others.is_empty() {
        w.push(
            "no default route: nothing adds one (no static 0.0.0.0/0, no DHCP client or PPPoE \
             client with add_default_route); set add_default_route=true for a provider uplink"
                .to_owned(),
        );
    }
    if c.max_mtu > MAX_MTU || c.max_mru > MAX_MTU {
        w.push(format!(
            "max-mtu/max-mru above {MAX_MTU} need the provider's BNG to accept RFC 4638 \
             (PPP-Max-Payload); otherwise the link stays at {MAX_MTU}"
        ));
    }
    if c.password.is_empty() {
        w.push("no password: most providers refuse the login".to_owned());
    }
    w
}

fn check_name_free(cfg: &Config, name: &IfName) -> Result<()> {
    let peer = relay_peer(name.as_str());
    if cfg.interfaces.keys().any(|n| n.as_str() == peer) {
        return Err(EngineError::bad(
            "name",
            format!("'{peer}' would be the relay end of '{name}', and it is taken"),
        ));
    }
    if let Some((other, _, _)) = clients(cfg).find(|(n, _, _)| relay_peer(n.as_str()) == name.as_str()) {
        return Err(EngineError::bad(
            "name",
            format!("'{name}' is the relay end of PPPoE client '{other}'"),
        ));
    }
    Ok(())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    refuse_unmanaged(s, p, &["name", "interface"])?;
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let cfg = s.store().candidate();
    let mut named = p.clone();
    if p.get("name").is_none_or(|v| v.as_str().is_some_and(|t| t.trim().is_empty()))
        && let Some(o) = named.as_object_mut()
    {
        o.insert("name".into(), json!(default_name(cfg)));
    }
    let name = new_name(cfg, &named)?;
    check_name_free(cfg, &name)?;
    let uplink: IfName = req_parse(p, "interface")?;
    if let Some(why) = uplink_problem(cfg, &uplink) {
        return Err(EngineError::bad("interface", why));
    }
    let user = opt_short(p, "user")?
        .filter(|u| !u.is_empty())
        .ok_or_else(|| EngineError::bad("user", "is required"))?;
    let mut c = PppoeClient::new(uplink, user);
    update(cfg, &mut c, p)?;
    seal(s, &mut c, p)?;
    let cfg = s.store().candidate();
    let warn = warnings(cfg, &name, &c, disabled);
    let mut iface = Interface::new(name.clone(), InterfaceKind::PppoeClient(Box::new(c.clone())));
    iface.mtu = c.max_mtu.max(c.max_mru);
    iface.disabled = disabled;
    iface.comment = comment;
    s.store_mut()
        .candidate_mut()
        .interfaces
        .insert(name.clone(), iface);
    Ok(json!({ "name": name, "warnings": warn }))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    refuse_unmanaged(s, p, &["name", "interface"])?;
    let name: IfName = req_parse(p, "name")?;
    let comment = opt_text(p, "comment", 256)?;
    let disabled = opt_bool(p, "disabled")?;
    let cfg = s.store().candidate();
    let mut c = client_of(cfg, &name)?.clone();
    update(cfg, &mut c, p)?;
    seal(s, &mut c, p)?;
    let cfg = s.store_mut().candidate_mut();
    let Some(iface) = cfg.interfaces.get_mut(&name) else {
        return Err(EngineError::bad("name", format!("no PPPoE client '{name}'")));
    };
    iface.mtu = c.max_mtu.max(c.max_mru);
    if let Some(d) = disabled {
        iface.disabled = d;
    }
    if let Some(t) = comment {
        iface.comment = t;
    }
    let off = iface.disabled;
    iface.kind = InterfaceKind::PppoeClient(Box::new(c.clone()));
    let warn = warnings(s.store().candidate(), &name, &c, off);
    Ok(json!({ "name": name, "warnings": warn }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    client_of(s.store().candidate(), &name)?;
    super::interface::remove(s, &json!({ "name": name }))
}

fn toggle(s: &mut Session, p: &Value, off: bool) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    client_of(s.store().candidate(), &name)?;
    if let Some(i) = s.store_mut().candidate_mut().interfaces.get_mut(&name) {
        i.disabled = off;
    }
    Ok(json!({ "name": name }))
}

fn enable(s: &mut Session, p: &Value) -> Result<Value> {
    toggle(s, p, false)
}

fn disable(s: &mut Session, p: &Value) -> Result<Value> {
    toggle(s, p, true)
}

fn reconnect(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    client_of(s.store().candidate(), &name)?;
    if !s.pppoe_reconnect(&name) {
        return Err(EngineError::bad(
            "name",
            format!("'{name}' is not running (disabled, not committed, or its interface is down)"),
        ));
    }
    Ok(json!({ "name": name, "status": "dialing" }))
}

fn row(s: &Session, name: &IfName, i: &Interface, c: &PppoeClient, password: Value) -> Value {
    let rt = s.pppoe_clients();
    let now = rt.and_then(|rt| rt.now_ms).unwrap_or_default();
    let r = rt.and_then(|rt| rt.runners.get(name));
    let status = match r {
        Some(r) => r.status(),
        None if i.disabled => "disabled",
        None => "stopped",
    };
    let up = r.and_then(|r| r.up.as_ref());
    json!({
        "name": name,
        "interface": c.interface,
        "user": c.user,
        "password": password,
        "service_name": c.service_name,
        "ac_name": c.ac_name,
        "host_uniq": c.host_uniq,
        "add_default_route": c.add_default_route,
        "default_route_distance": c.default_route_distance,
        "use_peer_dns": c.use_peer_dns,
        "profile": c.profile,
        "max_mtu": c.max_mtu,
        "max_mru": c.max_mru,
        "keepalive_timeout": if c.keepalive_timeout == 0 { json!("disabled") } else { json!(c.keepalive_timeout) },
        "allow": c.allow_text(),
        "disabled": i.disabled,
        "comment": i.comment,
        "status": status,
        "local_address": up.map(|u| u.local.to_string()),
        "remote_address": up.and_then(|u| u.remote).map(|a| a.to_string()),
        "uptime_secs": up.map(|u| now.saturating_sub(u.since_ms) / 1000),
        "mtu": up.map(|u| u.mtu),
        "retry_in_secs": r.and_then(|r| r.retry_in(now)).map(|ms| ms.div_ceil(1000)),
        "attempts": r.map_or(0, |r| r.failures),
        "last_down": r.and_then(|r| r.last_down.as_ref()).map(|d| json!({
            "reason": d.reason, "message": d.message, "time": d.time, "uptime_secs": d.uptime_secs,
        })),
        "error": r.and_then(|r| r.error.clone()),
    })
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    // Whoever reads them logs in as this router: group full only.
    let key = if opt_bool(p, "show_sensitive")?.unwrap_or(false) {
        s.permit(crate::auth::Group::Full)
            .map_err(|reason| EngineError::Denied {
                id: "interface.pppoe-client.list".into(),
                reason: format!("show_sensitive: {reason}"),
            })?;
        Some(crate::sealing::key(s).map_err(EngineError::Internal)?)
    } else {
        None
    };
    let cfg = s.store().candidate();
    let rows: Vec<Value> = clients(cfg)
        .map(|(n, i, c)| {
            let pw = match &key {
                Some(k) => Value::from(k.open(&c.password).unwrap_or_default()),
                None if c.password.is_empty() => Value::from(""),
                None => Value::from("***"),
            };
            row(s, n, i, c, pw)
        })
        .collect();
    Ok(Value::Array(rows))
}

fn monitor(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    let cfg = s.store().candidate();
    let c = client_of(cfg, &name)?;
    let disabled = cfg.interfaces.get(&name).is_some_and(|i| i.disabled);
    let mut v = s.pppoe_monitor(&name).unwrap_or_else(|| {
        json!({
            "status": if disabled { "disabled" } else { "stopped" },
            "service_name": c.service_name,
        })
    });
    if let Some(o) = v.as_object_mut() {
        o.insert("name".into(), json!(name));
    }
    Ok(v)
}

fn history(s: &mut Session, p: &Value) -> Result<Value> {
    let name = super::args::opt_parse::<IfName>(p, "name")?;
    let limit = opt_u32(p, "limit")?.unwrap_or(100).min(1000) as usize;
    let Some(rt) = s.pppoe_clients() else {
        return Ok(json!([]));
    };
    let rows: Vec<Value> = rt
        .history()
        .rev()
        .filter(|h| name.as_ref().is_none_or(|n| *n == h.name))
        .take(limit)
        .map(|h| json!(h))
        .collect();
    Ok(Value::Array(rows))
}

/// The list modal's preview (G0.24): `add`, or `set` of the client named
/// by `id`, tried on the candidate and undone, so the checks and warnings
/// are exactly the command's.
fn preview(s: &mut Session, p: &Value) -> Result<Value> {
    let mut q = p.clone();
    let editing = match q.as_object_mut().and_then(|o| o.remove("id")) {
        Some(id) => {
            if let Some(o) = q.as_object_mut() {
                o.insert("name".into(), id);
            }
            true
        }
        None => false,
    };
    // An empty field in the modal means "not given".
    if let Some(o) = q.as_object_mut() {
        o.retain(|k, v| !(v.as_str().is_some_and(|t| t.trim().is_empty()) && k != "comment"));
        for k in ["default_route_distance", "max_mtu", "max_mru", "keepalive_timeout"] {
            if let Some(n) = o.get(k).and_then(Value::as_str).and_then(|t| t.trim().parse::<u64>().ok()) {
                o.insert(k.into(), json!(n));
            }
        }
    }
    let (cmds, run): ((&str, &str), (super::Run, super::Run)) = if editing {
        (("interface.pppoe-client.set", "interface.pppoe-client.set"), (set, set))
    } else {
        (("interface.pppoe-client.add", "interface.pppoe-client.add"), (add, add))
    };
    super::ppp_common::preview(s, &q, cmds, run, |s, v| {
        let Some(name) = v.get("name").and_then(Value::as_str).and_then(|n| n.parse::<IfName>().ok()) else {
            return Vec::new();
        };
        let Ok(c) = client_of(s.store().candidate(), &name) else {
            return Vec::new();
        };
        let mtu = if c.max_mtu > MAX_MTU { format!("{} (RFC 4638, if the BNG agrees)", c.max_mtu) } else { c.max_mtu.to_string() };
        let clamp = s
            .store()
            .candidate()
            .ppp
            .profile(&c.profile)
            .is_none_or(|p| p.change_tcp_mss != corerouter_model::ppp::Tri::No);
        vec![
            json!({"label": "Interface", "value": name}),
            json!({"label": "MTU", "value": mtu}),
            json!({"label": "TCP MSS", "value": if clamp {
                format!("clamped to {} (IPv4) / {} (IPv6)", c.max_mtu.saturating_sub(40), c.max_mtu.saturating_sub(60))
            } else {
                "left alone (profile change-tcp-mss=no)".to_owned()
            }}),
            json!({"label": "Default route", "value": if c.add_default_route {
                format!("0.0.0.0/0 via {name}, distance {}", c.default_route_distance)
            } else {
                "none".to_owned()
            }}),
        ]
    })
}

/// `pppoe-out1`, `pppoe-out2`…: the first name free (RouterOS names them so).
fn default_name(cfg: &Config) -> String {
    (1..=MAX_DEFAULT_NAMES)
        .map(|i| format!("pppoe-out{i}"))
        .find(|n| n.parse::<IfName>().is_ok_and(|n| !cfg.interfaces.contains_key(&n)))
        .unwrap_or_else(|| "pppoe-out".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Session;

    fn session() -> Session {
        Session::virtual_lab()
    }

    fn run(s: &mut Session, id: &str, p: Value) -> Result<Value> {
        s.execute(id, &p)
    }

    fn add_wan(s: &mut Session) -> Value {
        run(
            s,
            "interface.pppoe-client.add",
            json!({"name": "pppoe-out1", "interface": "ether1", "user": "cliente@isp", "password": "s3nh4"}),
        )
        .unwrap()
    }

    #[test]
    fn add_keeps_routeros_defaults_and_seals_the_password() {
        let mut s = session();
        let r = add_wan(&mut s);
        assert_eq!(r["name"], "pppoe-out1");
        // RouterOS default add-default-route=no and nothing else gives one.
        let w = r["warnings"].as_array().unwrap();
        assert!(w.iter().any(|x| x.as_str().unwrap().contains("no default route")), "{w:?}");
        let cfg = s.store().candidate();
        let i = &cfg.interfaces[&"pppoe-out1".parse::<IfName>().unwrap()];
        assert_eq!(i.kind.label(), "pppoe-out");
        assert_eq!(i.mtu, 1460);
        let InterfaceKind::PppoeClient(c) = &i.kind else { panic!() };
        assert!(c.password.is_sealed(), "password must not be stored in clear");
        assert!(!c.add_default_route && c.default_route_distance == 1 && c.keepalive_timeout == 60);
        let rows = run(&mut s, "interface.pppoe-client.list", json!({})).unwrap();
        assert_eq!(rows[0]["password"], "***");
        assert_eq!(rows[0]["allow"], "mschap2,mschap1,chap,pap");
        let clear = run(&mut s, "interface.pppoe-client.list", json!({"show_sensitive": true})).unwrap();
        assert_eq!(clear[0]["password"], "s3nh4");
        // The journal never holds it either.
        let text = serde_json::to_string(&s.store().candidate()).unwrap();
        assert!(!text.contains("s3nh4"));
    }

    #[test]
    fn validation_errors_say_what_to_fix() {
        let mut s = session();
        let bad = |s: &mut Session, p: Value, key: &str| {
            let e = run(s, "interface.pppoe-client.add", p).unwrap_err().to_string();
            assert!(e.contains(key), "{e}");
        };
        bad(&mut s, json!({"name": "w", "interface": "ether9", "user": "u"}), "ether9");
        bad(&mut s, json!({"name": "w", "interface": "ether1", "user": ""}), "user");
        bad(&mut s, json!({"name": "w", "interface": "ether1", "user": "u", "max_mtu": 1600}), "max_mtu");
        bad(&mut s, json!({"name": "w", "interface": "ether1", "user": "u", "allow": "eap"}), "allow");
        bad(&mut s, json!({"name": "w", "interface": "ether1", "user": "u", "host_uniq": "xyz"}), "host_uniq");
        bad(&mut s, json!({"name": "w", "interface": "ether1", "user": "u", "profile": "nope"}), "profile");
        bad(&mut s, json!({"name": "w", "interface": "ether1", "user": "u", "default_route_distance": 0}), "default_route_distance");
        bad(&mut s, json!({"name": "w", "interface": "ether1", "user": "u", "keepalive_timeout": 9999}), "keepalive_timeout");
        bad(&mut s, json!({"name": "w", "interface": "ether1", "user": "u\u{7}"}), "user");
        add_wan(&mut s);
        bad(&mut s, json!({"name": "x", "interface": "pppoe-out1", "user": "u"}), "pppoe-out");
        bad(&mut s, json!({"name": "pppoe-out1-r", "interface": "ether1", "user": "u"}), "relay end");
    }

    #[test]
    fn default_route_at_the_same_distance_as_dhcp_is_a_warning() {
        let mut s = session();
        run(&mut s, "ip.dhcp-client.add", json!({"interface": "ether2", "default_route_distance": 1})).unwrap();
        let r = run(
            &mut s,
            "interface.pppoe-client.add",
            json!({"name": "pppoe-out1", "interface": "ether1", "user": "u", "password": "p", "add_default_route": true}),
        )
        .unwrap();
        let w = r["warnings"].to_string();
        assert!(w.contains("DHCP client on ether2") && w.contains("ECMP"), "{w}");
        let r = run(&mut s, "interface.pppoe-client.set", json!({"name": "pppoe-out1", "default_route_distance": 2})).unwrap();
        assert_eq!(r["warnings"], json!([]));
        // The modal's preview of a second client: the same warning, as a check.
        let c = run(
            &mut s,
            "interface.pppoe-client.preview",
            json!({"interface": "ether3", "user": "b", "password": "p", "add_default_route": true, "default_route_distance": "2"}),
        )
        .unwrap();
        assert!(c["checks"].to_string().contains("PPPoE client pppoe-out1"), "{c}");
        assert_eq!(c["commands"][0]["command"], "interface.pppoe-client.add");
        assert!(c["computed"].to_string().contains("pppoe-out2"), "the default name: {c}");
        // Editing: `id` names the client, the command is `set` with `name`.
        let e = run(&mut s, "interface.pppoe-client.preview", json!({"id": "pppoe-out1", "max_mtu": "1500"})).unwrap();
        assert_eq!(e["commands"][0]["command"], "interface.pppoe-client.set");
        assert_eq!(e["commands"][0]["params"]["name"], "pppoe-out1");
        assert!(e["checks"].to_string().contains("RFC 4638"), "{e}");
        // A bad value is an error check under its field, not a failure.
        let bad = run(&mut s, "interface.pppoe-client.preview", json!({"interface": "ether9", "user": "u"})).unwrap();
        assert_eq!(bad["checks"][0]["param"], "interface", "{bad}");
        assert_eq!(bad["commands"], json!([]));
    }

    #[test]
    fn transaction_rollback_takes_the_client_away() {
        let mut s = session();
        run(&mut s, "config.mode.set", json!({"mode": "transactional"})).unwrap();
        add_wan(&mut s);
        assert!(s.store().candidate().interfaces.contains_key(&"pppoe-out1".parse::<IfName>().unwrap()));
        run(&mut s, "config.discard", json!({})).unwrap();
        assert!(!s.store().candidate().interfaces.contains_key(&"pppoe-out1".parse::<IfName>().unwrap()));
    }

    #[test]
    fn remove_frees_the_uplink() {
        let mut s = session();
        add_wan(&mut s);
        let e = run(&mut s, "interface.bonding.add", json!({"name": "bond1", "slaves": "ether1", "mode": "active-backup"}));
        assert!(e.is_ok() || e.is_err());
        run(&mut s, "interface.pppoe-client.remove", json!({"name": "pppoe-out1"})).unwrap();
        assert!(run(&mut s, "interface.pppoe-client.list", json!({})).unwrap().as_array().unwrap().is_empty());
    }

    /// Lab BNG: the session comes up, installs address and default route,
    /// and a wrong password backs off at least 30 s.
    #[test]
    fn dials_the_lab_bng_and_backs_off_on_auth_failure() {
        let mut s = session();
        run(
            &mut s,
            "interface.pppoe-client.add",
            json!({"name": "pppoe-out1", "interface": "ether1", "user": "u", "password": "p",
                   "add_default_route": true, "use_peer_dns": true, "allow": "pap"}),
        )
        .unwrap();
        for t in 0..10 {
            s.dhcp_service(1000 + t * 250);
        }
        let m = run(&mut s, "interface.pppoe-client.monitor", json!({"name": "pppoe-out1"})).unwrap();
        assert_eq!(m["status"], "connected", "{m}");
        assert_eq!(m["ac_name"], crate::pppoe_client::LAB_AC_NAME);
        let local = m["local_address"].as_str().unwrap().to_owned();
        assert!(local.starts_with("100.64.0."), "{m}");
        let routes = run(&mut s, "ip.route.list", json!({})).unwrap().to_string();
        assert!(routes.contains("0.0.0.0/0") && routes.contains("pppoe-out1"), "{routes}");
        let addrs = run(&mut s, "ip.address.list", json!({})).unwrap().to_string();
        assert!(addrs.contains(&format!("{local}/32")), "{addrs}");
        assert!(s.dns_dynamic_servers().contains(&"100.64.0.53".parse().unwrap()));

        // Wrong password: down with auth-failed, redial no sooner than 30 s.
        run(&mut s, "interface.pppoe-client.set", json!({"name": "pppoe-out1", "password": "wrong"})).unwrap();
        for t in 0..10 {
            s.dhcp_service(5000 + t * 250);
        }
        let m = run(&mut s, "interface.pppoe-client.monitor", json!({"name": "pppoe-out1"})).unwrap();
        assert_eq!(m["last_down"]["reason"], "auth-failed", "{m}");
        assert!(m["last_down"]["message"].as_str().unwrap().contains("password"), "{m}");
        let wait = m["retry_in_secs"].as_u64().unwrap();
        assert!((23..=37).contains(&wait), "{m}");
        let addrs = run(&mut s, "ip.address.list", json!({})).unwrap().to_string();
        assert!(!addrs.contains("100.64.0."), "the session's address must go: {addrs}");
        let h = run(&mut s, "interface.pppoe-client.history", json!({})).unwrap().to_string();
        assert!(h.contains("connected") && h.contains("down"), "{h}");
    }

    #[test]
    fn reconnect_and_disable_end_the_session() {
        let mut s = session();
        run(
            &mut s,
            "interface.pppoe-client.add",
            json!({"name": "pppoe-out1", "interface": "ether1", "user": "u", "password": "p", "allow": "pap"}),
        )
        .unwrap();
        for t in 0..6 {
            s.dhcp_service(1000 + t * 250);
        }
        let r = run(&mut s, "interface.pppoe-client.reconnect", json!({"name": "pppoe-out1"})).unwrap();
        assert_eq!(r["status"], "dialing");
        for t in 0..6 {
            s.dhcp_service(3000 + t * 250);
        }
        let m = run(&mut s, "interface.pppoe-client.monitor", json!({"name": "pppoe-out1"})).unwrap();
        assert_eq!(m["status"], "connected", "{m}");
        run(&mut s, "interface.pppoe-client.disable", json!({"name": "pppoe-out1"})).unwrap();
        s.dhcp_service(6000);
        let m = run(&mut s, "interface.pppoe-client.monitor", json!({"name": "pppoe-out1"})).unwrap();
        assert_eq!(m["status"], "disabled", "{m}");
        let e = run(&mut s, "interface.pppoe-client.reconnect", json!({"name": "pppoe-out1"}));
        assert!(e.unwrap_err().to_string().contains("not running"));
    }
}
