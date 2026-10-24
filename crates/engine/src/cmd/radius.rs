//! `/radius` (G4.3j): the servers PPP, IPoE, hotspot and login ask, with
//! RouterOS v7's names; `/radius incoming` (CoA and Disconnect, RFC 5176)
//! and `/radius monitor`. The daemon's `radius` service follows the running
//! config and drives `proto-radius`; the network is never touched here.
//! `radius.test` sends an Access-Request through the service (a task, never
//! a wait under the session lock) and shows the reply decoded.
//!
//! Secrets are write-only: `radius.list` shows `***`, the journal masks
//! `secret` (`auth::SECRET_KEYS`).

use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use corerouter_model::radius::{
    AaaService, AuthOutcome, AuthReply, AuthRequest, Credentials, MAX_SECRET, MAX_SERVERS,
    MAX_TEXT, Protocol, Radius, RadiusServer, REPLAY_WINDOW, RequireMessageAuth, ServerMonitor,
    ServerState, TIMEOUT_MS,
};
use corerouter_model::{Config, IfName, InterfaceKind, ItemId};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32, req_parse, req_str};
use super::{CommandSpec, always};
use crate::tasks::can_run;
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("radius.add", "Add RADIUS Server", ["RADIUS"], None,
        "{address: ip, service: [ppp|login|hotspot|wireless|dhcp|ipsec|dot1x] (list or \"ppp,login\"), secret: string (write-only), authentication_port?: int 1..65535 (default 1812), accounting_port?: int 1..65535 (default 1813), timeout?: int 100..60000 (ms, default 1100), src_address?: ip (\"\" = kernel picks), vrf?: string (default main), require_message_auth?: no|yes-for-request-resp (default yes-for-request-resp), protocol?: udp|radsec, realm?: string, called_id?: string, domain?: string, accounting_backup?: bool, status_server?: bool (probe a down server, RFC 5997), disabled?: bool, comment?: string} → {id}",
        always, add),
    cmd!("radius.set", "Set RADIUS Server", [], None,
        "{id: *hex, address?: ip, service?: [ppp|login|hotspot|wireless|dhcp|ipsec|dot1x] (list or \"ppp,login\"), secret?: string (write-only), authentication_port?: int 1..65535 (default 1812), accounting_port?: int 1..65535 (default 1813), timeout?: int 100..60000 (ms, default 1100), src_address?: ip (\"\" = kernel picks), vrf?: string (default main), require_message_auth?: no|yes-for-request-resp (default yes-for-request-resp), protocol?: udp|radsec, realm?: string, called_id?: string, domain?: string, accounting_backup?: bool, status_server?: bool (probe a down server, RFC 5997), disabled?: bool, comment?: string} → {id}",
        has_servers, set),
    cmd!("radius.remove", "Remove RADIUS Server", [], None,
        "{id: *hex} → {id}", has_servers, remove),
    cmd!("radius.enable", "Enable RADIUS Server", [], None,
        "{id: *hex} → {id}", has_servers, enable),
    cmd!("radius.disable", "Disable RADIUS Server", [], None,
        "{id: *hex} → {id}", has_servers, disable),
    cmd!("radius.move", "Move RADIUS Server", [], None,
        "{id: *hex, destination?: *hex (before this entry; none = to the end)} → {id, order}",
        has_servers, move_server),
    cmd!(query "radius.list", "RADIUS", ["RADIUS"], None,
        "{} → [{id, address, service, secret: \"***\", authentication_port, accounting_port, timeout, src_address?, vrf, require_message_auth, protocol, realm?, called_id?, domain?, accounting_backup, status_server, disabled, comment?, order, flags (X disabled)}]",
        always, list),
    cmd!("radius.incoming.set", "RADIUS Incoming", [], None,
        "{accept?: bool (default no), port?: int 1..65535 (default 3799, RFC 5176; RouterOS uses 1700), vrf?: string, replay_window?: int 10..3600 (s, default 300), require_event_timestamp?: bool, require_message_auth?: bool} → {accept, port, vrf, replay_window, require_event_timestamp, require_message_auth, allowed}",
        always, incoming_set),
    cmd!(query "radius.incoming.get", "RADIUS Incoming", [], None,
        "{} → {accept, port, vrf, replay_window, require_event_timestamp, require_message_auth, allowed (sources accepted: the enabled /radius entries), listening?, requests, acks, naks, dropped, duplicates, owners, last_error?, daemon}",
        always, incoming_get),
    cmd!(query "radius.monitor", "RADIUS Monitor", [], None,
        "{id?: *hex} → [{id, address, state: up|down|probing|disabled|idle, pending, requests, accepts, rejects, acct_responses, resends, timeouts, bad_replies, unsolicited, last_request_rtt (ms), sockets}]",
        always, monitor),
    cmd!(query "radius.test", "Test RADIUS", [], None,
        "{user: string, password?: string (PAP; \"\" sends none), service?: ppp|login|hotspot|wireless|dhcp|ipsec|dot1x (default ppp), nas_port_id?: string, calling_station_id?: string} → {id, task_id}; events {outcome: accept|reject|challenge|timeout|error, server?, server_address?, rtt_ms?, attributes: [{name, value, tag?}], message?}",
        can_run, test)
    .task(),
];

fn has_servers(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().radius.servers.is_empty() {
        Err("there are no RADIUS servers".into())
    } else {
        Ok(())
    }
}

fn position(s: &Session, id: ItemId) -> Result<usize> {
    s.store()
        .candidate()
        .radius
        .servers
        .iter()
        .position(|e| e.id == id)
        .ok_or_else(|| EngineError::bad("id", format!("no RADIUS server {id}")))
}

/// `ppp,login`, `["ppp","login"]` or `""` (none).
fn services(p: &Value) -> Result<Option<Vec<AaaService>>> {
    let raw: Vec<String> = match p.get("service") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_owned()).filter(|x| !x.is_empty()).collect(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|x| x.trim().to_owned())
                    .ok_or_else(|| EngineError::bad("service", "each item must be a string"))
            })
            .collect::<Result<_>>()?,
        Some(_) => return Err(EngineError::bad("service", "must be a list")),
    };
    let mut out = Vec::new();
    for r in raw.iter().take(16) {
        let Some(v) = AaaService::parse(r) else {
            let shown: String = r.chars().take(32).collect();
            return Err(EngineError::bad(
                "service",
                format!("'{shown}': one of ppp, login, hotspot, wireless, dhcp, ipsec, dot1x"),
            ));
        };
        if !out.contains(&v) {
            out.push(v);
        }
    }
    if raw.len() > 16 {
        return Err(EngineError::bad("service", "at most 16 items"));
    }
    out.sort();
    Ok(Some(out))
}

fn port(p: &Value, key: &str) -> Result<Option<u16>> {
    opt_u32(p, key)?
        .map(|v| {
            u16::try_from(v)
                .ok()
                .filter(|v| *v != 0)
                .ok_or_else(|| EngineError::bad(key, "must be 1..=65535"))
        })
        .transpose()
}

/// "main" or the name of a VRF interface.
fn vrf(cfg: &Config, p: &Value) -> Result<Option<String>> {
    let Some(v) = opt_str(p, "vrf")? else {
        return Ok(None);
    };
    let v = v.trim();
    if v.is_empty() || v == "main" {
        return Ok(Some("main".into()));
    }
    let name: IfName = v.parse().map_err(|e| EngineError::bad("vrf", format!("{e}")))?;
    match cfg.interfaces.get(&name).map(|i| &i.kind) {
        Some(InterfaceKind::Vrf { .. }) => Ok(Some(v.to_owned())),
        _ => Err(EngineError::bad("vrf", format!("no VRF '{name}' (interface.vrf.add first)"))),
    }
}

/// Whether the router has `ip` (an enabled `/ip address`) or it is a
/// loopback address: a source the kernel accepts in `bind`.
fn local_address(cfg: &Config, ip: IpAddr) -> bool {
    ip.is_loopback()
        || cfg
            .ip
            .addresses
            .iter()
            .any(|a| !a.disabled && a.address.addr() == ip)
}

fn usable_server(ip: IpAddr) -> bool {
    !(ip.is_unspecified() || ip.is_multicast() || ip == IpAddr::from([255, 255, 255, 255]))
}

fn apply(cfg: &Config, e: &mut RadiusServer, p: &Value) -> Result<()> {
    if let Some(a) = opt_parse::<IpAddr>(p, "address")? {
        if !usable_server(a) {
            return Err(EngineError::bad("address", format!("{a} cannot be a RADIUS server")));
        }
        e.address = a.to_canonical();
    }
    if let Some(v) = services(p)? {
        e.service = v;
    }
    if let Some(v) = opt_str(p, "secret")? {
        if v.len() > MAX_SECRET {
            return Err(EngineError::bad("secret", format!("at most {MAX_SECRET} bytes")));
        }
        if v.chars().any(char::is_control) {
            return Err(EngineError::bad("secret", "control characters are not allowed"));
        }
        v.clone_into(&mut e.secret);
    }
    if let Some(v) = port(p, "authentication_port")? {
        e.authentication_port = v;
    }
    if let Some(v) = port(p, "accounting_port")? {
        e.accounting_port = v;
    }
    if let Some(v) = opt_u32(p, "timeout")? {
        if !TIMEOUT_MS.contains(&v) {
            return Err(EngineError::bad(
                "timeout",
                format!("must be {}..={} ms", TIMEOUT_MS.start(), TIMEOUT_MS.end()),
            ));
        }
        e.timeout = v;
    }
    match opt_str(p, "src_address")? {
        None => {}
        Some(v) if v.trim().is_empty() || v.trim() == "0.0.0.0" || v.trim() == "::" => {
            e.src_address = None;
        }
        Some(v) => {
            let shown: String = v.chars().take(64).collect();
            let ip: IpAddr = v
                .trim()
                .parse()
                .map_err(|_| EngineError::bad("src_address", format!("'{shown}' is not an IP address")))?;
            e.src_address = Some(ip.to_canonical());
        }
    }
    if let Some(v) = vrf(cfg, p)? {
        e.vrf = v;
    }
    if let Some(v) = opt_str(p, "require_message_auth")? {
        e.require_message_auth = match v {
            "no" => RequireMessageAuth::No,
            "yes-for-request-resp" | "yes" => RequireMessageAuth::YesForRequestResp,
            _ => {
                return Err(EngineError::bad(
                    "require_message_auth",
                    "must be no or yes-for-request-resp",
                ));
            }
        };
    }
    if let Some(v) = opt_str(p, "protocol")? {
        e.protocol = match v {
            "udp" => Protocol::Udp,
            "radsec" => Protocol::Radsec,
            _ => return Err(EngineError::bad("protocol", "must be udp or radsec")),
        };
    }
    for (key, slot) in [
        ("realm", &mut e.realm),
        ("called_id", &mut e.called_id),
        ("domain", &mut e.domain),
    ] {
        if let Some(v) = opt_text(p, key, MAX_TEXT)? {
            *slot = v.trim().to_owned();
        }
    }
    if e.realm.contains(['@', ' ']) {
        return Err(EngineError::bad("realm", "a domain, without '@' or spaces"));
    }
    for (key, slot) in [
        ("accounting_backup", &mut e.accounting_backup),
        ("status_server", &mut e.status_server),
        ("disabled", &mut e.disabled),
    ] {
        if let Some(v) = opt_bool(p, key)? {
            *slot = v;
        }
    }
    if let Some(v) = opt_text(p, "comment", 256)? {
        e.comment = v;
    }
    check(cfg, e)
}

/// The rules an entry must meet as a whole (after any change).
fn check(cfg: &Config, e: &RadiusServer) -> Result<()> {
    if e.protocol == Protocol::Radsec {
        return Err(EngineError::bad(
            "protocol",
            "RadSec (RADIUS over TLS) is not available yet (gap G4.3ba): use udp",
        ));
    }
    if e.secret.is_empty() {
        return Err(EngineError::bad(
            "secret",
            "is required: RADIUS signs every packet with it (RFC 2865 §3)",
        ));
    }
    if let Some(src) = e.src_address {
        if src.is_ipv4() != e.address.is_ipv4() {
            return Err(EngineError::bad(
                "src_address",
                format!("{src} and the server {} are of different families", e.address),
            ));
        }
        if !local_address(cfg, src) {
            return Err(EngineError::bad(
                "src_address",
                format!("{src} is not an address of this router (ip.address.add first)"),
            ));
        }
    }
    if e.authentication_port == e.accounting_port {
        return Err(EngineError::bad(
            "accounting_port",
            "must differ from authentication_port",
        ));
    }
    // The same server twice for one service would be asked twice in a row
    // on failover, with two sets of counters.
    if let Some(o) = cfg.radius.servers.iter().find(|o| {
        o.id != e.id
            && o.address == e.address
            && o.authentication_port == e.authentication_port
            && o.vrf == e.vrf
            && o.service.iter().any(|s| e.service.contains(s))
    }) {
        let both: Vec<&str> = o
            .service
            .iter()
            .filter(|s| e.service.contains(s))
            .map(|s| s.as_str())
            .collect();
        return Err(EngineError::bad(
            "address",
            format!(
                "entry {} already asks {} for {}: add the service there",
                o.id,
                e.address,
                both.join(",")
            ),
        ));
    }
    Ok(())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    if s.store().candidate().radius.servers.len() >= MAX_SERVERS {
        return Err(EngineError::bad("address", format!("at most {MAX_SERVERS} RADIUS servers")));
    }
    let address: IpAddr = req_parse(p, "address")?;
    req_str(p, "secret")?;
    if p.get("service").is_none_or(Value::is_null) {
        return Err(EngineError::bad("service", "is required (ppp, login, hotspot, dhcp…)"));
    }
    let mut e = RadiusServer::new(ItemId(0), address);
    let cfg = s.store().candidate().clone();
    apply(&cfg, &mut e, p)?;
    let r = &mut s.store_mut().candidate_mut().radius;
    e.id = r.next_id();
    let id = e.id;
    r.servers.push(e);
    Ok(json!({ "id": id }))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let i = position(s, id)?;
    let cfg = s.store().candidate().clone();
    let Some(mut e) = cfg.radius.servers.get(i).cloned() else {
        return Err(EngineError::bad("id", format!("no RADIUS server {id}")));
    };
    apply(&cfg, &mut e, p)?;
    if let Some(slot) = s.store_mut().candidate_mut().radius.servers.get_mut(i) {
        *slot = e;
    }
    Ok(json!({ "id": id }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let i = position(s, id)?;
    s.store_mut().candidate_mut().radius.servers.remove(i);
    Ok(json!({ "id": id }))
}

fn toggle(s: &mut Session, p: &Value, disabled: bool) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let i = position(s, id)?;
    let cfg = s.store().candidate().clone();
    let Some(mut e) = cfg.radius.servers.get(i).cloned() else {
        return Err(EngineError::bad("id", format!("no RADIUS server {id}")));
    };
    e.disabled = disabled;
    if !disabled {
        // An entry enabled again meets today's rules (addresses change).
        check(&cfg, &e)?;
    }
    if let Some(slot) = s.store_mut().candidate_mut().radius.servers.get_mut(i) {
        *slot = e;
    }
    Ok(json!({ "id": id }))
}

fn enable(s: &mut Session, p: &Value) -> Result<Value> {
    toggle(s, p, false)
}

fn disable(s: &mut Session, p: &Value) -> Result<Value> {
    toggle(s, p, true)
}

fn move_server(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let dest: Option<ItemId> = opt_parse(p, "destination")?;
    let i = position(s, id)?;
    if let Some(d) = dest {
        position(s, d).map_err(|_| EngineError::bad("destination", format!("no RADIUS server {d}")))?;
    }
    let servers = &mut s.store_mut().candidate_mut().radius.servers;
    let e = servers.remove(i);
    let at = dest
        .and_then(|d| servers.iter().position(|o| o.id == d))
        .unwrap_or(servers.len());
    servers.insert(at, e);
    Ok(json!({ "id": id, "order": at }))
}

fn server_json(e: &RadiusServer, order: usize) -> Value {
    let service: Vec<&str> = e.service.iter().map(|s| s.as_str()).collect();
    let mut v = json!({
        "id": e.id,
        "address": e.address,
        "service": service,
        "secret": if e.secret.is_empty() { "" } else { "***" },
        "authentication_port": e.authentication_port,
        "accounting_port": e.accounting_port,
        "timeout": e.timeout,
        "vrf": e.vrf,
        "require_message_auth": e.require_message_auth.as_str(),
        "protocol": match e.protocol { Protocol::Udp => "udp", Protocol::Radsec => "radsec" },
        "accounting_backup": e.accounting_backup,
        "status_server": e.status_server,
        "disabled": e.disabled,
        "order": order,
        "flags": if e.disabled { "X" } else { "" },
    });
    if let Some(o) = v.as_object_mut() {
        if let Some(src) = e.src_address {
            o.insert("src_address".into(), json!(src));
        }
        for (k, val) in [
            ("realm", &e.realm),
            ("called_id", &e.called_id),
            ("domain", &e.domain),
            ("comment", &e.comment),
        ] {
            if !val.is_empty() {
                o.insert(k.into(), json!(val));
            }
        }
    }
    v
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    let r = &s.store().candidate().radius;
    Ok(Value::Array(
        r.servers.iter().enumerate().map(|(i, e)| server_json(e, i)).collect(),
    ))
}

fn incoming_json(r: &Radius) -> Value {
    let i = &r.incoming;
    let mut allowed: Vec<IpAddr> = Vec::new();
    for e in r.servers.iter().filter(|e| !e.disabled) {
        if !allowed.contains(&e.address) {
            allowed.push(e.address);
        }
    }
    json!({
        "accept": i.accept,
        "port": i.port,
        "vrf": i.vrf,
        "replay_window": i.replay_window,
        "require_event_timestamp": i.require_event_timestamp,
        "require_message_auth": i.require_message_auth,
        "allowed": allowed,
    })
}

fn incoming_set(s: &mut Session, p: &Value) -> Result<Value> {
    let cfg = s.store().candidate().clone();
    let mut i = cfg.radius.incoming.clone();
    if let Some(v) = opt_bool(p, "accept")? {
        i.accept = v;
    }
    if let Some(v) = port(p, "port")? {
        i.port = v;
    }
    if let Some(v) = vrf(&cfg, p)? {
        i.vrf = v;
    }
    if let Some(v) = opt_u32(p, "replay_window")? {
        if !REPLAY_WINDOW.contains(&v) {
            return Err(EngineError::bad(
                "replay_window",
                format!("must be {}..={} s", REPLAY_WINDOW.start(), REPLAY_WINDOW.end()),
            ));
        }
        i.replay_window = v;
    }
    if let Some(v) = opt_bool(p, "require_event_timestamp")? {
        i.require_event_timestamp = v;
    }
    if let Some(v) = opt_bool(p, "require_message_auth")? {
        i.require_message_auth = v;
    }
    let r = &mut s.store_mut().candidate_mut().radius;
    r.incoming = i;
    let mut out = incoming_json(r);
    if r.incoming.accept
        && r.servers.iter().all(|e| e.disabled)
        && let Some(o) = out.as_object_mut()
    {
        o.insert(
            "warning".into(),
            json!("no enabled /radius entry: every request will be dropped (the allow-list is the /radius servers)"),
        );
    }
    Ok(out)
}

fn incoming_get(s: &mut Session, _: &Value) -> Result<Value> {
    let mut out = incoming_json(&s.store().candidate().radius);
    let status = s.aaa_backend().map(|b| b.status());
    if let Some(o) = out.as_object_mut() {
        o.insert("daemon".into(), json!(status.is_some()));
        let inc = status.map(|st| st.incoming).unwrap_or_default();
        if let Ok(Value::Object(m)) = serde_json::to_value(&inc) {
            o.extend(m);
        }
    }
    Ok(out)
}

fn monitor(s: &mut Session, p: &Value) -> Result<Value> {
    let only: Option<ItemId> = opt_parse(p, "id")?;
    if let Some(id) = only {
        position(s, id)?;
    }
    let live = s.aaa_backend().map(|b| b.status());
    let rows: Vec<Value> = s
        .store()
        .candidate()
        .radius
        .servers
        .iter()
        .filter(|e| only.is_none_or(|id| id == e.id))
        .map(|e| {
            let m = live
                .as_ref()
                .and_then(|st| st.servers.iter().find(|m| m.id == e.id).cloned())
                .unwrap_or(ServerMonitor {
                    id: e.id,
                    address: Some(e.address),
                    state: if e.disabled { ServerState::Disabled } else { ServerState::Idle },
                    pending: 0,
                    requests: 0,
                    accepts: 0,
                    rejects: 0,
                    acct_responses: 0,
                    resends: 0,
                    timeouts: 0,
                    bad_replies: 0,
                    unsolicited: 0,
                    last_request_rtt: 0,
                    sockets: 0,
                });
            serde_json::to_value(&m).unwrap_or(Value::Null)
        })
        .collect();
    Ok(Value::Array(rows))
}

/// How long `radius.test` waits for the service's answer: every server's
/// retries (8 s each) for a few servers.
const TEST_WAIT: Duration = Duration::from_secs(40);

fn test(s: &mut Session, p: &Value) -> Result<Value> {
    let user = opt_text(p, "user", 253)?.unwrap_or_default();
    if user.trim().is_empty() {
        return Err(EngineError::bad("user", "is required"));
    }
    let password = opt_text(p, "password", 128)?;
    let service = match opt_str(p, "service")? {
        None | Some("") => AaaService::Ppp,
        Some(v) => AaaService::parse(v).ok_or_else(|| {
            EngineError::bad("service", "one of ppp, login, hotspot, wireless, dhcp, ipsec, dot1x")
        })?,
    };
    let mut req = AuthRequest::pap(service, user.trim(), "");
    req.credentials = match password {
        Some(pw) if !pw.is_empty() => Credentials::Pap { password: pw },
        _ => Credentials::None,
    };
    req.nas_port_id = opt_text(p, "nas_port_id", 253)?;
    req.calling_station_id = opt_text(p, "calling_station_id", 253)?;
    let cfg = &s.store().running().radius;
    let ids: Vec<ItemId> = cfg.servers.iter().filter(|e| e.serves(service)).map(|e| e.id).collect();
    if ids.is_empty() {
        return Err(EngineError::bad(
            "service",
            format!("no enabled /radius entry has service={} (radius.add first)", service.as_str()),
        ));
    }
    let Some(backend) = s.aaa_backend() else {
        return Err(EngineError::Disabled {
            id: "radius.test".into(),
            reason: "radius.test needs the router daemon's radius service".into(),
        });
    };
    let shown: String = user.chars().take(32).collect();
    let id = s.start_task("radius-test", format!("radius test {shown}"), move |ctx| {
        // A server just added reaches the service with its next look at
        // the config (a fraction of a second): wait for it, briefly.
        let loading = ctx.now();
        while !backend.status().servers.iter().any(|m| {
            ids.contains(&m.id) && !matches!(m.state, ServerState::Idle | ServerState::Disabled)
        }) && ctx.now().saturating_sub(loading) < Duration::from_secs(3)
            && !ctx.stopped()
        {
            ctx.sleep(Duration::from_millis(50));
        }
        let slot: Arc<Mutex<Option<AuthReply>>> = Arc::new(Mutex::new(None));
        let put = slot.clone();
        backend.authenticate(
            req,
            Box::new(move |r| {
                *put.lock().unwrap_or_else(PoisonError::into_inner) = Some(r);
            }),
        );
        let started = ctx.now();
        loop {
            if let Some(r) = slot.lock().unwrap_or_else(PoisonError::into_inner).take() {
                let ev = serde_json::to_value(&r).unwrap_or(Value::Null);
                ctx.emit(ev.clone());
                ctx.summary(ev);
                return match r.outcome {
                    AuthOutcome::Error => Err(r.message.unwrap_or_else(|| "error".into())),
                    _ => Ok(()),
                };
            }
            if ctx.stopped() || ctx.now().saturating_sub(started) > TEST_WAIT {
                return Err("no answer from the radius service".into());
            }
            ctx.sleep(Duration::from_millis(20));
        }
    })?;
    Ok(json!({"id": id, "task_id": id}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::radius::{AaaBackend, AcctSource, AuthDone, SessionOwner};
    use crate::tasks::test_runner;
    use corerouter_model::radius::{AcctRequest, Attribute, RadiusStatus};
    use std::thread;

    fn lab() -> Session {
        Session::virtual_lab()
    }

    fn add(s: &mut Session, p: Value) -> Result<Value> {
        s.execute("radius.add", &p)
    }

    #[test]
    fn add_list_set_and_remove() {
        let mut s = lab();
        let r = add(&mut s, json!({"address": "10.0.0.10", "service": "ppp,login", "secret": "s3cr3t"})).unwrap();
        let rows = s.execute("radius.list", &json!({})).unwrap();
        assert_eq!(rows[0]["id"], r["id"]);
        assert_eq!(rows[0]["service"], json!(["ppp", "login"]));
        assert_eq!(rows[0]["secret"], "***", "secrets are write-only");
        assert_eq!(rows[0]["timeout"], 1100);
        assert_eq!(rows[0]["require_message_auth"], "yes-for-request-resp");
        // The journal never sees the secret.
        let j = serde_json::to_string(&s.journal()).unwrap();
        assert!(!j.contains("s3cr3t"), "{j}");
        s.execute("radius.set", &json!({"id": r["id"], "timeout": 3000, "service": ["ppp"]})).unwrap();
        assert_eq!(s.store().running().radius.servers[0].timeout, 3000);
        assert_eq!(s.store().running().radius.servers[0].secret, "s3cr3t");
        s.execute("radius.disable", &json!({"id": r["id"]})).unwrap();
        assert_eq!(s.execute("radius.list", &json!({})).unwrap()[0]["flags"], "X");
        s.execute("radius.enable", &json!({"id": r["id"]})).unwrap();
        s.execute("radius.remove", &json!({"id": r["id"]})).unwrap();
        assert!(s.store().running().radius.servers.is_empty());
    }

    #[test]
    fn bad_servers_are_refused() {
        let mut s = lab();
        add(&mut s, json!({"address": "10.0.0.10", "service": "ppp", "secret": "x"})).unwrap();
        for p in [
            json!({"address": "10.0.0.11", "service": "ppp", "secret": ""}),
            json!({"address": "10.0.0.11", "service": "ppp"}),
            json!({"address": "10.0.0.11", "secret": "x"}),
            json!({"address": "10.0.0.10", "service": "login,ppp", "secret": "x"}),
            json!({"address": "0.0.0.0", "service": "ppp", "secret": "x"}),
            json!({"address": "224.0.0.1", "service": "ppp", "secret": "x"}),
            json!({"address": "10.0.0.11", "service": "pppoe", "secret": "x"}),
            json!({"address": "10.0.0.11", "service": "ppp", "secret": "x", "src_address": "192.0.2.99"}),
            json!({"address": "10.0.0.11", "service": "ppp", "secret": "x", "src_address": "::1"}),
            json!({"address": "10.0.0.11", "service": "ppp", "secret": "x", "timeout": 5}),
            json!({"address": "10.0.0.11", "service": "ppp", "secret": "x", "authentication_port": 0}),
            json!({"address": "10.0.0.11", "service": "ppp", "secret": "x", "accounting_port": 1812}),
            json!({"address": "10.0.0.11", "service": "ppp", "secret": "x", "protocol": "radsec"}),
            json!({"address": "10.0.0.11", "service": "ppp", "secret": "x", "vrf": "nope"}),
            json!({"address": "10.0.0.11", "service": "ppp", "secret": "x", "realm": "a@b"}),
            json!({"address": "10.0.0.11", "service": "ppp", "secret": "x\u{1}"}),
            json!({"address": "10.0.0.11", "service": "ppp", "secret": "x".repeat(200)}),
        ] {
            let err = add(&mut s, p.clone()).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        // The same address for another service is fine.
        add(&mut s, json!({"address": "10.0.0.10", "service": "login", "secret": "x"})).unwrap();
    }

    #[test]
    fn src_address_must_be_the_routers() {
        let mut s = lab();
        s.execute("ip.address.add", &json!({"address": "192.0.2.1/24", "interface": "ether1"})).unwrap();
        add(&mut s, json!({"address": "192.0.2.10", "service": "ppp", "secret": "x", "src_address": "192.0.2.1"})).unwrap();
        add(&mut s, json!({"address": "127.0.0.1", "service": "dhcp", "secret": "x", "src_address": "127.0.0.1"})).unwrap();
        assert_eq!(s.store().running().radius.servers[0].src_address, Some("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn rollback_drops_the_server() {
        let mut s = lab();
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        add(&mut s, json!({"address": "10.0.0.10", "service": "ppp", "secret": "x"})).unwrap();
        s.execute("radius.incoming.set", &json!({"accept": true})).unwrap();
        s.execute("config.discard", &json!({})).unwrap();
        assert!(s.store().candidate().radius.is_default());
    }

    #[test]
    fn move_changes_the_failover_order() {
        let mut s = lab();
        for a in ["10.0.0.1", "10.0.0.2", "10.0.0.3"] {
            add(&mut s, json!({"address": a, "service": "ppp", "secret": "x"})).unwrap();
        }
        s.execute("radius.move", &json!({"id": "*3", "destination": "*1"})).unwrap();
        let rows = s.execute("radius.list", &json!({})).unwrap();
        let order: Vec<&str> = rows.as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert_eq!(order, ["*3", "*1", "*2"]);
        s.execute("radius.move", &json!({"id": "*3"})).unwrap();
        assert_eq!(s.execute("radius.list", &json!({})).unwrap()[2]["id"], "*3");
    }

    #[test]
    fn incoming_defaults_and_validation() {
        let mut s = lab();
        let g = s.execute("radius.incoming.get", &json!({})).unwrap();
        assert_eq!(g["accept"], false);
        assert_eq!(g["port"], 3799, "RFC 5176 §2.3");
        assert_eq!(g["daemon"], false);
        let r = s.execute("radius.incoming.set", &json!({"accept": true, "port": 1700})).unwrap();
        assert!(r["warning"].is_string(), "{r}");
        for p in [json!({"port": 0}), json!({"replay_window": 1}), json!({"vrf": "x"})] {
            let err = s.execute("radius.incoming.set", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        add(&mut s, json!({"address": "10.0.0.10", "service": "ppp", "secret": "x"})).unwrap();
        let g = s.execute("radius.incoming.get", &json!({})).unwrap();
        assert_eq!(g["allowed"], json!(["10.0.0.10"]));
        assert_eq!(g["port"], 1700);
    }

    #[test]
    fn monitor_without_daemon_is_idle() {
        let mut s = lab();
        add(&mut s, json!({"address": "10.0.0.10", "service": "ppp", "secret": "x"})).unwrap();
        add(&mut s, json!({"address": "10.0.0.11", "service": "ppp", "secret": "x", "disabled": true})).unwrap();
        let m = s.execute("radius.monitor", &json!({})).unwrap();
        assert_eq!(m[0]["state"], "idle");
        assert_eq!(m[1]["state"], "disabled");
        assert!(s.execute("radius.monitor", &json!({"id": "*9"})).is_err());
    }

    struct Fake;

    impl AaaBackend for Fake {
        fn authenticate(&self, req: AuthRequest, done: AuthDone) {
            thread::spawn(move || {
                let ok = matches!(&req.credentials, Credentials::Pap { password } if password == "segredo");
                let mut r = AuthReply::failed(
                    if ok { AuthOutcome::Accept } else { AuthOutcome::Reject },
                    "",
                );
                r.message = None;
                r.server = Some(ItemId(1));
                r.attributes = vec![Attribute::new("Mikrotik-Rate-Limit", "10M/20M")];
                done(r);
            });
        }
        fn account(&self, _: AcctRequest, _: Option<Arc<dyn AcctSource>>) -> std::result::Result<(), String> {
            Ok(())
        }
        fn register_owner(&self, _: Arc<dyn SessionOwner>) {}
        fn status(&self) -> RadiusStatus {
            let mut m: ServerMonitor = serde_json::from_value(json!({
                "id": "*1", "address": null, "state": "up", "pending": 0, "requests": 0,
                "accepts": 0, "rejects": 0, "acct_responses": 0, "resends": 0, "timeouts": 0,
                "bad_replies": 0, "unsolicited": 0, "last_request_rtt": 0, "sockets": 0}))
            .unwrap();
            m.state = ServerState::Up;
            RadiusStatus { servers: vec![m], ..RadiusStatus::default() }
        }
    }

    fn until_done(s: &mut Session, id: u64) -> Value {
        for _ in 0..500 {
            let p = s.execute("tool.task.poll", &json!({"id": id, "max": 256})).unwrap();
            if p["done"] == true {
                return p;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("task {id} did not finish");
    }

    #[test]
    fn test_runs_as_a_task_and_decodes_the_reply() {
        let mut s = lab();
        add(&mut s, json!({"address": "10.0.0.10", "service": "ppp", "secret": "x"})).unwrap();
        // No runner, no backend: disabled with the reason.
        let err = s.execute("radius.test", &json!({"user": "ana", "password": "segredo"})).unwrap_err();
        assert!(matches!(err, EngineError::Disabled { .. }), "{err}");
        s.set_runner(test_runner::threads());
        let err = s.execute("radius.test", &json!({"user": "ana", "password": "segredo"})).unwrap_err();
        assert!(err.to_string().contains("daemon"), "{err}");
        s.set_aaa_backend(Arc::new(Fake));
        let r = s.execute("radius.test", &json!({"user": "ana", "password": "segredo"})).unwrap();
        let done = until_done(&mut s, r["id"].as_u64().unwrap());
        assert_eq!(done["events"][0]["outcome"], "accept", "{done}");
        assert_eq!(done["events"][0]["attributes"][0]["value"], "10M/20M");
        let r = s.execute("radius.test", &json!({"user": "ana", "password": "nope"})).unwrap();
        let done = until_done(&mut s, r["id"].as_u64().unwrap());
        assert_eq!(done["summary"]["outcome"], "reject");
        // No server for the service: refused before anything is sent.
        let err = s.execute("radius.test", &json!({"user": "ana", "service": "login"})).unwrap_err();
        assert!(matches!(err, EngineError::BadParam { .. }), "{err}");
        let err = s.execute("radius.test", &json!({"user": ""})).unwrap_err();
        assert!(matches!(err, EngineError::BadParam { .. }), "{err}");
    }
}
