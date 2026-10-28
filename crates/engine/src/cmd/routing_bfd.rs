//! /routing bfd (G3.6): profiles, peers, the live sessions and the history
//! of state changes. The daemon's `bfd` service runs the sessions
//! (CoreRouter's own BFD, `corerouter_proto_bfd`) and publishes them in
//! `ext::<BfdState>`; without the daemon (a GUI on the virtual lab) the
//! sessions the config asks for are listed as `inactive`.

use std::net::IpAddr;

use corerouter_model::bfd::{
    BfdAuth, BfdConfig, BfdKeyText, BfdPeer, BfdProfile, BfdState, FAST_WARN_MS, INTERVAL_MS, MAX_KEY, MAX_PEERS,
    MAX_PROFILES, PROFILE_DEFAULT, PROFILE_FAST, builtin_profiles, wanted_all,
};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text, opt_u32, req_str};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("routing.bfd.profile.add", "Add BFD Profile", ["Routing", "BFD"], None,
        "{name: string, min_tx?: u32 (ms, 10..=60000, default 300), min_rx?: u32 (ms, 10..=60000, default 300), multiplier?: u8 (1..=255, default 3), passive?: bool, dampening?: bool (default yes), half_life?: u32 (s, 1..=3600), suppress?: u32 (1..=20000), reuse?: u32 (1..suppress), max_suppress?: u32 (s, 1..=3600), auth?: none | keyed-sha1 | meticulous-keyed-sha1, auth_key_id?: u8, auth_secret?: string (1..=20 bytes), min_ttl?: u8 (multihop, 1..=255), comment?: string} → {name, detect_ms, warning?}",
        always, profile_add),
    cmd!("routing.bfd.profile.set", "Set BFD Profile", [], None,
        "{id: string (the name; default and fast are built in), min_tx?: u32 (ms, 10..=60000), min_rx?: u32 (ms, 10..=60000), multiplier?: u8 (1..=255), passive?: bool, dampening?: bool, half_life?: u32 (s, 1..=3600), suppress?: u32 (1..=20000), reuse?: u32 (1..suppress), max_suppress?: u32 (s, 1..=3600), auth?: none | keyed-sha1 | meticulous-keyed-sha1, auth_key_id?: u8, auth_secret?: string (1..=20 bytes), min_ttl?: u8 (multihop, 1..=255), comment?: string} → {name, detect_ms, warning?}",
        always, profile_set),
    cmd!("routing.bfd.profile.remove", "Remove BFD Profile", [], None,
        "{id: string (the name; a built-in goes back to its defaults)} → {name, reset}",
        always, profile_remove),
    cmd!(query "routing.bfd.profile.list", "BFD Profiles", ["Routing", "BFD"], None,
        "{} → [{id, name, builtin, default, min_tx, min_rx, multiplier, detect_ms, passive, dampening, half_life, suppress, reuse, max_suppress, auth, auth_key_id, auth_secret (*** when set), min_ttl, comment, used_by: [string]}]",
        always, profile_list),
    cmd!("routing.bfd.peer.add", "Add BFD Peer", ["Routing", "BFD"], None,
        "{address: ip, name?: string (default: the address), local_address?: ip, interface?: string, multihop?: bool, profile?: string (default \"default\"), disabled?: bool, comment?: string} → {name}",
        always, peer_add),
    cmd!("routing.bfd.peer.set", "Set BFD Peer", [], None,
        "{id: string (the name), address?: ip, local_address?: ip | null, interface?: string | null, multihop?: bool, profile?: string, disabled?: bool, comment?: string} → {name}",
        has_peers, peer_set),
    cmd!("routing.bfd.peer.remove", "Remove BFD Peer", [], None,
        "{id: string (the name)} → {name}",
        has_peers, peer_remove),
    cmd!(query "routing.bfd.peer.list", "BFD Peers", ["Routing", "BFD"], None,
        "{} → [{id, name, address, local_address?, interface?, multihop, profile, disabled, comment, state}]",
        always, peer_list),
    cmd!(query "routing.bfd.session.list", "BFD Sessions", ["Routing", "BFD"], None,
        "{} → {running, steering, error?, threads: [{index, sessions, cpu_percent, packets_in, packets_out, forwarded}], sessions: [{peer, local?, multihop, users, profile, state: up | down | init | admin-down | inactive, remote_state, diag, dampened, penalty, local_discr, remote_discr, tx_interval_us, remote_min_rx_us, remote_desired_tx_us, multiplier, remote_multiplier, detect_time_us, packets_tx, packets_rx, dropped, state_changes, flaps_24h, last_change?, tx_jitter_p99_us?, rx_gap_p99_us?, thread}]}",
        always, session_list),
    cmd!("routing.bfd.attach", "Use BFD Everywhere", ["Routing", "BFD"], None,
        "{protocols?: [bgp | ospf] | string (default both), profile?: string (default \"default\")} → {profile, bgp: [connection], ospf: [template id]} (only those without a profile of their own or from a template)",
        always, attach),
    cmd!(query "routing.bfd.profile.preview", "Check BFD Profile", [], None,
        "{id?: string (the profile being edited), name?: string, min_tx?: u32 | string, min_rx?: u32 | string, multiplier?: u8 | string, passive?: bool | yes | no, dampening?: bool | yes | no, half_life?: u32 | string, suppress?: u32 | string, reuse?: u32 | string, max_suppress?: u32 | string, auth?: string, auth_key_id?: u8 | string, auth_secret?: string, min_ttl?: u8 | string, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}]} (form texts accepted; never an error: bad input is a check)",
        always, profile_preview),
    cmd!(query "routing.bfd.peer.preview", "Check BFD Peer", [], None,
        "{id?: string (the peer being edited), name?: string, address?: string, local_address?: string, interface?: string, multihop?: bool | yes | no, profile?: string, disabled?: bool | yes | no, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}]} (form texts accepted; never an error: bad input is a check)",
        always, peer_preview),
    cmd!(query "routing.bfd.history.list", "BFD History", ["Routing", "BFD"], None,
        "{peer?: ip, limit?: u32 (default 200)} → [{at_ms, peer, multihop, from, to, diag, users, detect_time_us, dampened}] (newest first)",
        always, history_list),
];

fn has_peers(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.bfd.peers.is_empty() {
        Err("there are no BFD peers (routing.bfd.peer.add)".into())
    } else {
        Ok(())
    }
}

fn cut(s: &str) -> String {
    crate::logging::cut(s, 64).to_string()
}

fn check_name(key: &str, name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(EngineError::bad(key, "1..=64 characters of [A-Za-z0-9_.:-]"));
    }
    Ok(())
}

fn ranged(p: &Value, key: &str, lo: u32, hi: u32, what: &str) -> Result<Option<u32>> {
    match opt_u32(p, key)? {
        Some(v) if !(lo..=hi).contains(&v) => Err(EngineError::bad(key, format!("must be {lo}..={hi} {what}"))),
        v => Ok(v),
    }
}

fn apply_profile(prof: &mut BfdProfile, p: &Value) -> Result<()> {
    let (lo, hi) = INTERVAL_MS;
    let why = "ms (RFC 7419 common intervals: 10, 20, 50, 100, 1000)";
    if let Some(v) = ranged(p, "min_tx", lo, hi, why)? {
        prof.min_tx = v;
    }
    if let Some(v) = ranged(p, "min_rx", lo, hi, why)? {
        prof.min_rx = v;
    }
    if let Some(v) = ranged(p, "multiplier", 1, 255, "(RFC 5880 §4.1: Detect Mult is never 0)")? {
        prof.multiplier = v as u8;
    }
    if let Some(v) = opt_bool(p, "passive")? {
        prof.passive = v;
    }
    let d = &mut prof.dampening;
    if let Some(v) = opt_bool(p, "dampening")? {
        d.enabled = v;
    }
    if let Some(v) = ranged(p, "half_life", 1, 3600, "seconds")? {
        d.half_life = v;
    }
    if let Some(v) = ranged(p, "suppress", 1, 20_000, "(1000 per flap)")? {
        d.suppress = v;
    }
    if let Some(v) = ranged(p, "reuse", 1, 20_000, "(1000 per flap)")? {
        d.reuse = v;
    }
    if let Some(v) = ranged(p, "max_suppress", 1, 3600, "seconds")? {
        d.max_suppress = v;
    }
    if d.reuse >= d.suppress {
        return Err(EngineError::bad(
            "reuse",
            format!("must be below suppress ({}), or the session would never be released", d.suppress),
        ));
    }
    if let Some(a) = opt_str(p, "auth")? {
        prof.auth = BfdAuth::parse(a).ok_or_else(|| {
            EngineError::bad("auth", format!("{:?}: use none, keyed-sha1 or meticulous-keyed-sha1", cut(a)))
        })?;
    }
    if let Some(v) = ranged(p, "auth_key_id", 0, 255, "")? {
        prof.auth_key_id = v as u8;
    }
    if let Some(k) = opt_str(p, "auth_secret")? {
        if k.len() > MAX_KEY {
            return Err(EngineError::bad("auth_secret", format!("at most {MAX_KEY} bytes (RFC 5880 §4.4)")));
        }
        prof.auth_secret = BfdKeyText(k.to_owned());
    }
    if prof.auth != BfdAuth::None && prof.auth_secret.is_empty() {
        return Err(EngineError::bad("auth_secret", "is required with auth (1..=20 bytes, the same on both sides)"));
    }
    if let Some(v) = ranged(p, "min_ttl", 1, 255, "")? {
        prof.min_ttl = v as u8;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        prof.comment = c;
    }
    Ok(())
}

fn profile_answer(prof: &BfdProfile) -> Value {
    let fastest = prof.min_tx.min(prof.min_rx);
    let warning = (fastest < FAST_WARN_MS).then(|| {
        format!(
            "{fastest} ms: each session sends {} packets/s each way; fine for tens of sessions per core, \
             measure before using it on hundreds (routing.bfd.session.list shows CPU per thread)",
            1000 / fastest.max(1)
        )
    });
    json!({"name": prof.name, "detect_ms": prof.detect_ms(), "warning": warning})
}

/// Add (`id` None) or change a profile in `bfd`.
fn profile_apply(bfd: &mut BfdConfig, p: &Value, id: Option<&str>) -> Result<BfdProfile> {
    let mut prof = match id {
        Some(id) => bfd
            .profile(id)
            .ok_or_else(|| EngineError::bad("id", format!("no BFD profile {:?}", cut(id))))?,
        None => {
            let name = req_str(p, "name")?;
            corerouter_model::bfd::check_profile_name(name).map_err(|e| EngineError::bad("name", e))?;
            if bfd.profile(name).is_some() {
                return Err(EngineError::bad(
                    "name",
                    format!("profile {:?} already exists (routing.bfd.profile.set)", cut(name)),
                ));
            }
            if bfd.profiles.len() >= MAX_PROFILES {
                return Err(EngineError::bad("name", format!("at most {MAX_PROFILES} profiles")));
            }
            BfdProfile::new(name, 300, 3)
        }
    };
    apply_profile(&mut prof, p)?;
    bfd.profiles.insert(prof.name.clone(), prof.clone());
    Ok(prof)
}

fn profile_add(s: &mut Session, p: &Value) -> Result<Value> {
    let prof = profile_apply(&mut s.store_mut().candidate_mut().routing.bfd, p, None)?;
    Ok(profile_answer(&prof))
}

fn profile_set(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?.to_owned();
    let prof = profile_apply(&mut s.store_mut().candidate_mut().routing.bfd, p, Some(&id))?;
    Ok(profile_answer(&prof))
}

/// Form texts as `add`/`set` take them: numbers as numbers, yes/no as
/// bools, an empty field left out (a profile has no unset values; a peer's
/// optional addresses are unset by `null` on edit).
fn normalize(p: &Value, editing: bool, numbers: &[&str], bools: &[&str], nullable: &[&str]) -> Value {
    let Some(o) = p.as_object() else {
        return p.clone();
    };
    let mut out = serde_json::Map::new();
    for (k, v) in o {
        let text = v.as_str().map(str::trim);
        let v = match text {
            Some("") if editing && nullable.contains(&k.as_str()) => Value::Null,
            Some("") => continue,
            Some(t) if numbers.contains(&k.as_str()) => t.parse::<u64>().map_or_else(|_| v.clone(), Value::from),
            Some("yes" | "true") if bools.contains(&k.as_str()) => Value::Bool(true),
            Some("no" | "false") if bools.contains(&k.as_str()) => Value::Bool(false),
            _ => v.clone(),
        };
        out.insert(k.clone(), v);
    }
    if !editing {
        out.remove("id");
    }
    Value::Object(out)
}

fn check(level: &str, check: &str, message: String, param: &str) -> Value {
    json!({"level": level, "check": check, "message": message, "param": param})
}

fn param_error(e: EngineError) -> Value {
    match e {
        EngineError::BadParam { param, reason } => check("error", "param", reason, &param),
        e => check("error", "param", e.to_string(), ""),
    }
}

const PROFILE_NUMBERS: &[&str] = &[
    "min_tx", "min_rx", "multiplier", "half_life", "suppress", "reuse", "max_suppress", "auth_key_id", "min_ttl",
];

/// The profile modal: detection time, packets per second, the CPU and
/// dampening notes, and what OK sends.
fn profile_preview(s: &mut Session, raw: &Value) -> Result<Value> {
    let id = raw.get("id").and_then(Value::as_str).map(str::to_owned);
    let editing = id.is_some();
    let p = normalize(raw, editing, PROFILE_NUMBERS, &["passive", "dampening"], &[]);
    let mut bfd = s.store().candidate().routing.bfd.clone();
    let (mut computed, mut checks, mut commands) = (Vec::new(), Vec::new(), Vec::new());
    match profile_apply(&mut bfd, &p, id.as_deref()) {
        Err(e) => checks.push(param_error(e)),
        Ok(prof) => {
            let fastest = prof.min_tx.min(prof.min_rx).max(1);
            computed.push(json!({"label": "Detection time", "value": format!("{} ms ({} × {} ms)", prof.detect_ms(), prof.multiplier, prof.min_tx.max(prof.min_rx))}));
            computed.push(json!({"label": "Packets per second", "value": format!("{} each way per session", 1000 / prof.min_tx.max(1))}));
            computed.push(json!({"label": "Until up", "value": "1 s timers (RFC 5880 §6.8.3), then these through a Poll"}));
            if fastest < FAST_WARN_MS {
                checks.push(check("warning", "cpu", profile_answer(&prof).get("warning").and_then(Value::as_str).unwrap_or_default().to_owned(), "min_tx"));
            }
            if prof.multiplier < 3 {
                checks.push(check("warning", "multiplier", format!("multiplier {}: one or two lost packets bring the session down (3 is the usual)", prof.multiplier), "multiplier"));
            }
            if prof.dampening.enabled {
                checks.push(check("info", "dampening", format!("dampening on: about 3 flaps within {} s keep the session down for its clients until it is quiet", prof.dampening.half_life), "dampening"));
            } else {
                checks.push(check("info", "dampening", "dampening off: a flapping link takes BGP and OSPF down and up with it".into(), "dampening"));
            }
            if prof.auth == BfdAuth::None {
                checks.push(check("info", "auth", "no authentication: fine on a link; across hops (multihop) prefer meticulous-keyed-sha1 (RFC 5883 §6)".into(), "auth"));
            }
            let users = users_of(&bfd, &prof.name);
            if editing && !users.is_empty() {
                checks.push(check("info", "users", format!("used by {}: new timers go through a Poll Sequence, the sessions stay up", users.join(", ")), ""));
            }
            let command = if editing { "routing.bfd.profile.set" } else { "routing.bfd.profile.add" };
            commands.push(json!({"command": command, "params": p}));
        }
    }
    Ok(json!({"computed": computed, "checks": checks, "commands": commands}))
}

/// The peer modal: the session it makes, what already uses that address.
fn peer_preview(s: &mut Session, raw: &Value) -> Result<Value> {
    let id = raw.get("id").and_then(Value::as_str).map(str::to_owned);
    let editing = id.is_some();
    let p = normalize(raw, editing, &[], &["multihop", "disabled"], &["local_address", "interface"]);
    let mut bfd = s.store().candidate().routing.bfd.clone();
    let (mut computed, mut checks, mut commands) = (Vec::new(), Vec::new(), Vec::new());
    match apply_peer(&mut bfd, &p, id.as_deref()) {
        Err(e) => checks.push(param_error(e)),
        Ok(name) => {
            if let Some(peer) = bfd.peers.get(&name) {
                let port = if peer.multihop { "4784 (multihop, RFC 5883)" } else { "3784 (single hop, RFC 5881: TTL 255)" };
                computed.push(json!({"label": "Session", "value": format!("{}, UDP {port}", peer.address)}));
                if let Some(prof) = bfd.profile(&peer.profile) {
                    computed.push(json!({"label": "Detection time", "value": format!("{} ms", prof.detect_ms())}));
                }
                let routing = &s.store().candidate().routing;
                let bgp: Vec<&str> = routing
                    .bgp_connections
                    .values()
                    .filter(|c| c.remote_address == peer.address)
                    .map(|c| c.name.as_str())
                    .collect();
                if !bgp.is_empty() {
                    checks.push(check("info", "bgp", format!("BGP {} talks to this address: its own bfd profile (routing.bgp.connection.set bfd=…) makes BGP follow the session", bgp.join(", ")), ""));
                }
                if peer.multihop && bfd.profile(&peer.profile).is_some_and(|p| p.auth == BfdAuth::None) {
                    checks.push(check("warning", "auth", "multihop without authentication: anyone on the path can bring it down (RFC 5883 §6)".into(), "profile"));
                }
            }
            let command = if editing { "routing.bfd.peer.set" } else { "routing.bfd.peer.add" };
            commands.push(json!({"command": command, "params": p}));
        }
    }
    Ok(json!({"computed": computed, "checks": checks, "commands": commands}))
}

fn users_of(bfd: &BfdConfig, profile: &str) -> Vec<String> {
    bfd.peers
        .values()
        .filter(|x| x.profile == profile)
        .map(|x| format!("peer {}", x.name))
        .collect()
}

fn profile_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?;
    let cand = s.store_mut().candidate_mut();
    // G3.6g: static routes with check_gateway=bfd use profiles too.
    let routes: Vec<String> = cand
        .ip
        .routes
        .iter()
        .filter(|r| r.check_gateway == corerouter_model::dhcp_client::CheckGateway::Bfd && r.bfd_profile == id)
        .map(|r| format!("route {}", r.id))
        .collect();
    let bfd = &mut cand.routing.bfd;
    let builtin = id == PROFILE_DEFAULT || id == PROFILE_FAST;
    if !builtin {
        let mut users = users_of(bfd, id);
        users.extend(routes);
        if !users.is_empty() {
            return Err(EngineError::bad(
                "id",
                format!("profile {:?} is used by {}; move them to another profile first", cut(id), users.join(", ")),
            ));
        }
    }
    if bfd.profiles.remove(id).is_none() && !builtin {
        return Err(EngineError::bad("id", format!("no BFD profile {:?}", cut(id))));
    }
    Ok(json!({"name": id, "reset": builtin}))
}

fn profile_list(s: &mut Session, _: &Value) -> Result<Value> {
    let bfd = &s.store().candidate().routing.bfd;
    let builtins = builtin_profiles();
    let rows = bfd
        .all_profiles()
        .into_iter()
        .map(|prof| {
            let builtin = builtins.iter().any(|b| b.name == prof.name);
            let d = prof.dampening;
            json!({
                "id": prof.name,
                "name": prof.name,
                "builtin": builtin,
                // `/export`: present in every config, exported as `set`.
                "default": builtin,
                "min_tx": prof.min_tx,
                "min_rx": prof.min_rx,
                "multiplier": prof.multiplier,
                "detect_ms": prof.detect_ms(),
                "passive": prof.passive,
                "dampening": d.enabled,
                "half_life": d.half_life,
                "suppress": d.suppress,
                "reuse": d.reuse,
                "max_suppress": d.max_suppress,
                "auth": prof.auth.name(),
                "auth_key_id": prof.auth_key_id,
                "auth_secret": if prof.auth_secret.is_empty() { "" } else { "***" },
                "min_ttl": prof.min_ttl,
                "comment": prof.comment,
                "used_by": users_of(bfd, &prof.name),
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

fn ip(p: &Value, key: &str) -> Result<Option<IpAddr>> {
    match opt_str(p, key)? {
        Some(a) => a
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| EngineError::bad(key, format!("{:?} is not an IP address", cut(a)))),
        None => Ok(None),
    }
}

fn apply_peer(bfd: &mut BfdConfig, p: &Value, id: Option<&str>) -> Result<String> {
    let mut peer = match id {
        Some(id) => bfd
            .peers
            .get(id)
            .cloned()
            .ok_or_else(|| EngineError::bad("id", format!("no BFD peer {:?}", cut(id))))?,
        None => {
            let address = ip(p, "address")?.ok_or_else(|| EngineError::bad("address", "is required"))?;
            BfdPeer {
                name: address.to_string(),
                address,
                local_address: None,
                interface: None,
                multihop: false,
                profile: PROFILE_DEFAULT.to_owned(),
                disabled: false,
                comment: String::new(),
            }
        }
    };
    if let Some(a) = ip(p, "address")? {
        peer.address = a;
    }
    if id.is_none() && p.get("name").is_none() {
        peer.name = peer.address.to_string();
    }
    if let Some(n) = opt_str(p, "name")? {
        check_name("name", n)?;
        peer.name = n.to_owned();
    }
    if p.get("local_address").is_some() {
        peer.local_address = ip(p, "local_address")?;
    }
    if let Some(l) = peer.local_address
        && l.is_ipv4() != peer.address.is_ipv4()
    {
        return Err(EngineError::bad("local_address", "must be the same family as address"));
    }
    if p.get("interface").is_some() {
        peer.interface = opt_str(p, "interface")?.map(str::to_owned);
        if let Some(i) = &peer.interface {
            check_name("interface", i)?;
        }
    }
    if let Some(m) = opt_bool(p, "multihop")? {
        peer.multihop = m;
    }
    if peer.multihop && peer.local_address.is_none() {
        return Err(EngineError::bad(
            "local_address",
            "a multihop session needs local_address (RFC 5883 §3: the session is the address pair)",
        ));
    }
    if peer.multihop && peer.interface.is_some() {
        return Err(EngineError::bad("interface", "a multihop session is not tied to an interface (RFC 5883)"));
    }
    if let Some(pr) = opt_str(p, "profile")? {
        if bfd.profile(pr).is_none() {
            return Err(EngineError::bad("profile", format!("no BFD profile {:?} (routing.bfd.profile.add)", cut(pr))));
        }
        peer.profile = pr.to_owned();
    }
    if let Some(d) = opt_bool(p, "disabled")? {
        peer.disabled = d;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        peer.comment = c;
    }
    let name = peer.name.clone();
    if id != Some(name.as_str()) && bfd.peers.contains_key(&name) {
        return Err(EngineError::bad("name", format!("peer {:?} already exists", cut(&name))));
    }
    if let Some(other) = bfd.peers.values().find(|o| {
        Some(o.name.as_str()) != id
            && o.name != name
            && o.address == peer.address
            && o.multihop == peer.multihop
            && o.local_address == peer.local_address
            && o.profile != peer.profile
    }) {
        return Err(EngineError::bad(
            "profile",
            format!(
                "peer {:?} is the same session ({}) with profile {:?}; one session has one profile",
                cut(&other.name),
                peer.address,
                other.profile
            ),
        ));
    }
    if id.is_none() && bfd.peers.len() >= MAX_PEERS {
        return Err(EngineError::bad("address", format!("at most {MAX_PEERS} BFD peers")));
    }
    if let Some(old) = id.filter(|old| *old != name) {
        bfd.peers.remove(old);
    }
    bfd.peers.insert(name.clone(), peer);
    Ok(name)
}

fn peer_add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = apply_peer(&mut s.store_mut().candidate_mut().routing.bfd, p, None)?;
    Ok(json!({"name": name}))
}

fn peer_set(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?.to_owned();
    let name = apply_peer(&mut s.store_mut().candidate_mut().routing.bfd, p, Some(&id))?;
    Ok(json!({"name": name}))
}

fn peer_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?;
    if s.store_mut().candidate_mut().routing.bfd.peers.remove(id).is_none() {
        return Err(EngineError::bad("id", format!("no BFD peer {:?}", cut(id))));
    }
    Ok(json!({"name": id}))
}

fn live_state(st: Option<&BfdState>, peer: IpAddr, multihop: bool) -> String {
    st.and_then(|st| {
        st.sessions
            .iter()
            .find(|x| x.peer == Some(peer) && x.multihop == multihop)
            .map(|x| if x.dampened { "dampened".to_owned() } else { x.state.clone() })
    })
    .unwrap_or_else(|| "inactive".to_owned())
}

fn peer_list(s: &mut Session, _: &Value) -> Result<Value> {
    let st = s.ext::<BfdState>();
    let rows = s
        .store()
        .candidate()
        .routing
        .bfd
        .peers
        .values()
        .map(|x| {
            let mut v = serde_json::to_value(x).unwrap_or_else(|_| json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("id".into(), json!(x.name));
                let state = if x.disabled { "disabled".to_owned() } else { live_state(st, x.address, x.multihop) };
                o.insert("state".into(), json!(state));
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}

fn session_list(s: &mut Session, _: &Value) -> Result<Value> {
    let st = s.ext::<BfdState>().cloned().unwrap_or_default();
    let mut sessions: Vec<Value> = st
        .sessions
        .iter()
        .map(|x| serde_json::to_value(x).unwrap_or_else(|_| json!({})))
        .collect();
    // What the running config asks for and the service does not run (yet).
    for (k, (prof, users)) in wanted_all(s.store().running()) {
        if st.sessions.iter().any(|x| x.peer == Some(k.peer) && x.multihop == k.multihop && x.local == k.local) {
            continue;
        }
        sessions.push(json!({
            "peer": k.peer, "local": k.local, "multihop": k.multihop, "users": users,
            "profile": prof.name, "state": "inactive", "remote_state": "down", "diag": "none",
            "dampened": false, "multiplier": prof.multiplier,
            "detect_time_us": prof.detect_ms() * 1000,
        }));
    }
    let mut out = json!({
        "running": st.running,
        "steering": st.steering,
        "threads": st.threads,
        "sessions": sessions,
    });
    if let (Some(e), Some(o)) = (st.error, out.as_object_mut()) {
        o.insert("error".into(), json!(e));
    }
    Ok(out)
}

/// BFD with one click: the profile on every BGP connection and OSPF
/// interface template that has none (its own or a template's).
fn attach(s: &mut Session, p: &Value) -> Result<Value> {
    let protocols: Vec<String> = match p.get("protocols") {
        None | Some(Value::Null) => vec!["bgp".into(), "ospf".into()],
        Some(Value::String(t)) => t.split(',').map(|x| x.trim().to_owned()).filter(|x| !x.is_empty()).collect(),
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
        Some(_) => return Err(EngineError::bad("protocols", "a list of bgp, ospf")),
    };
    if let Some(bad) = protocols.iter().find(|x| *x != "bgp" && *x != "ospf") {
        return Err(EngineError::bad("protocols", format!("{:?}: bgp or ospf", cut(bad))));
    }
    let profile = opt_str(p, "profile")?.unwrap_or(PROFILE_DEFAULT).to_owned();
    let routing = &mut s.store_mut().candidate_mut().routing;
    if routing.bfd.profile(&profile).is_none() {
        return Err(EngineError::bad("profile", format!("no BFD profile {:?}", cut(&profile))));
    }
    let mut bgp = Vec::new();
    if protocols.iter().any(|x| x == "bgp") {
        let resolved = corerouter_model::bgp::resolve_templates(&routing.bgp_templates);
        for c in routing.bgp_connections.values_mut() {
            let inherited = c.effective(&resolved).ok().and_then(|e| e.bfd);
            if inherited.is_none() {
                c.params.bfd = Some(profile.clone());
                bgp.push(c.name.clone());
            }
        }
    }
    let mut ospf = Vec::new();
    if protocols.iter().any(|x| x == "ospf") {
        for t in routing.ospf.templates.iter_mut().filter(|t| t.bfd.is_none()) {
            t.bfd = Some(profile.clone());
            ospf.push(t.id.to_string());
        }
    }
    Ok(json!({"profile": profile, "bgp": bgp, "ospf": ospf}))
}

fn history_list(s: &mut Session, p: &Value) -> Result<Value> {
    let peer = ip(p, "peer")?;
    let limit = opt_u32(p, "limit")?.unwrap_or(200) as usize;
    let Some(st) = s.ext::<BfdState>() else {
        return Ok(json!([]));
    };
    let rows: Vec<Value> = st
        .history
        .iter()
        .rev()
        .filter(|e| peer.is_none_or(|a| e.peer == a))
        .take(limit)
        .map(|e| serde_json::to_value(e).unwrap_or_else(|_| json!({})))
        .collect();
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use corerouter_model::bfd::{BfdEvent, BfdSessionStatus};

    use super::*;

    fn session() -> Session {
        Session::virtual_lab()
    }

    #[test]
    fn builtin_profiles_are_listed_and_reset() {
        let mut s = session();
        let l = s.execute("routing.bfd.profile.list", &json!({})).unwrap();
        assert_eq!(l[0]["name"], "default");
        assert_eq!(l[0]["detect_ms"], 900);
        assert_eq!(l[1]["name"], "fast");
        assert_eq!(l[1]["builtin"], true);
        let r = s.execute("routing.bfd.profile.set", &json!({"id": "fast", "min_tx": 20, "min_rx": 20})).unwrap();
        assert!(r["warning"].as_str().unwrap().contains("50 packets/s"));
        assert_eq!(s.store().candidate().routing.bfd.profile("fast").unwrap().min_tx, 20);
        let r = s.execute("routing.bfd.profile.remove", &json!({"id": "fast"})).unwrap();
        assert_eq!(r["reset"], true);
        assert_eq!(s.store().candidate().routing.bfd.profile("fast").unwrap().min_tx, 50);
    }

    #[test]
    fn profile_validation() {
        let mut s = session();
        for bad in [
            json!({"name": "x", "min_tx": 5}),
            json!({"name": "x", "multiplier": 0}),
            json!({"name": "x", "auth": "md5"}),
            json!({"name": "x", "auth": "keyed-sha1"}),
            json!({"name": "x", "auth": "keyed-sha1", "auth_secret": "012345678901234567890"}),
            json!({"name": "x", "reuse": 3000}),
            json!({"name": "bad name"}),
            json!({"name": "default"}),
        ] {
            let e = s.execute("routing.bfd.profile.add", &bad).unwrap_err();
            assert!(matches!(e, EngineError::BadParam { .. }), "{bad}: {e}");
        }
        assert!(s.store().candidate().routing.bfd.profiles.is_empty());
        let r = s
            .execute("routing.bfd.profile.add", &json!({"name": "wan", "min_tx": 500, "multiplier": 5, "auth": "meticulous-keyed-sha1", "auth_secret": "k3y"}))
            .unwrap();
        assert_eq!(r["detect_ms"], 2500);
        assert!(r["warning"].is_null());
        let l = s.execute("routing.bfd.profile.list", &json!({})).unwrap();
        assert_eq!(l[2]["auth_secret"], "***");
    }

    #[test]
    fn peers_and_inactive_sessions() {
        let mut s = session();
        s.execute("routing.bfd.peer.add", &json!({"address": "192.0.2.2", "profile": "fast"})).unwrap();
        let e = s.execute("routing.bfd.peer.add", &json!({"name": "mh", "address": "198.51.100.9", "multihop": true})).unwrap_err();
        assert!(e.to_string().contains("RFC 5883"), "{e}");
        s.execute("routing.bfd.peer.add", &json!({"name": "mh", "address": "198.51.100.9", "multihop": true, "local_address": "192.0.2.1"})).unwrap();
        // One session, one profile.
        let e = s
            .execute("routing.bfd.peer.add", &json!({"name": "dup", "address": "192.0.2.2", "profile": "default"}))
            .unwrap_err();
        assert!(e.to_string().contains("one session has one profile"), "{e}");
        let e = s.execute("routing.bfd.peer.add", &json!({"address": "192.0.2.3", "profile": "nope"})).unwrap_err();
        assert!(e.to_string().contains("no BFD profile"));
        let e = s
            .execute("routing.bfd.peer.add", &json!({"address": "192.0.2.4", "multihop": true, "local_address": "192.0.2.1", "interface": "ether1"}))
            .unwrap_err();
        assert!(e.to_string().contains("multihop"));
        // A profile in use cannot go.
        s.execute("routing.bfd.profile.add", &json!({"name": "wan"})).unwrap();
        s.execute("routing.bfd.peer.set", &json!({"id": "mh", "profile": "wan"})).unwrap();
        let e = s.execute("routing.bfd.profile.remove", &json!({"id": "wan"})).unwrap_err();
        assert!(e.to_string().contains("peer mh"));
        let l = s.execute("routing.bfd.peer.list", &json!({})).unwrap();
        assert_eq!(l[0]["name"], "192.0.2.2");
        assert_eq!(l[0]["state"], "inactive");
        // Immediate mode: running = candidate.
        let sl = s.execute("routing.bfd.session.list", &json!({})).unwrap();
        assert_eq!(sl["running"], false);
        assert_eq!(sl["sessions"].as_array().unwrap().len(), 2);
        assert_eq!(sl["sessions"][0]["state"], "inactive");
        s.execute("routing.bfd.peer.remove", &json!({"id": "mh"})).unwrap();
        s.execute("routing.bfd.profile.remove", &json!({"id": "wan"})).unwrap();
    }

    #[test]
    fn live_state_and_history_from_the_service() {
        let mut s = session();
        s.execute("routing.bfd.peer.add", &json!({"address": "192.0.2.2"})).unwrap();
        let peer: IpAddr = "192.0.2.2".parse().unwrap();
        if let Some(st) = s.ext_mut::<BfdState>() {
            st.running = true;
            st.sessions.push(BfdSessionStatus {
                peer: Some(peer),
                state: "up".into(),
                dampened: true,
                ..BfdSessionStatus::default()
            });
            for i in 0..3 {
                st.history.push_back(BfdEvent {
                    at_ms: i,
                    peer,
                    multihop: false,
                    from: "up".into(),
                    to: "down".into(),
                    diag: "control-detection-time-expired".into(),
                    users: vec![],
                    detect_time_us: 900_000,
                    dampened: false,
                });
            }
        }
        let l = s.execute("routing.bfd.peer.list", &json!({})).unwrap();
        assert_eq!(l[0]["state"], "dampened");
        let sl = s.execute("routing.bfd.session.list", &json!({})).unwrap();
        assert_eq!(sl["sessions"].as_array().unwrap().len(), 1);
        let h = s.execute("routing.bfd.history.list", &json!({"limit": 2})).unwrap();
        assert_eq!(h.as_array().unwrap().len(), 2);
        assert_eq!(h[0]["at_ms"], 2);
    }

    #[test]
    fn bgp_and_ospf_name_profiles_that_must_exist() {
        let mut s = session();
        s.execute("routing.bgp.instance.set", &json!({"asn": 65000, "router_id": "10.0.0.1"})).unwrap();
        s.execute(
            "routing.bgp.connection.add",
            &json!({"name": "up1", "remote_address": "192.0.2.6", "remote_as": 64500, "bfd": "fast"}),
        )
        .unwrap();
        let conf = corerouter_proto_bgp::render_all(&s.store().running().routing, &|_| None).unwrap();
        assert!(conf.contains(" neighbor 192.0.2.6 bfd profile fast\n"), "{conf}");
        let bfd = corerouter_proto_bfd::frr::render(s.store().running());
        assert!(bfd.starts_with("bfd\n profile default\n"), "{bfd}");
        // A profile nobody defined is refused at commit.
        let e = s.execute("routing.bgp.connection.set", &json!({"id": "up1", "bfd": "nope"})).unwrap_err();
        assert!(e.to_string().contains("no BFD profile"), "{e}");
        let e = s.execute("routing.bgp.connection.set", &json!({"id": "up1", "bfd": "bad name"})).unwrap_err();
        assert!(matches!(e, EngineError::BadParam { .. }), "{e}");
        // Unset: no BFD, no bfd block.
        s.execute("routing.bgp.connection.set", &json!({"id": "up1", "bfd": null})).unwrap();
        assert_eq!(corerouter_proto_bfd::frr::render(s.store().running()), "");
    }

    #[test]
    fn attach_puts_the_profile_where_none_is() {
        let mut s = session();
        s.execute("routing.bgp.instance.set", &json!({"asn": 65000, "router_id": "10.0.0.1"})).unwrap();
        s.execute("routing.bgp.connection.add", &json!({"name": "a", "remote_address": "192.0.2.6", "remote_as": 64500})).unwrap();
        s.execute("routing.bgp.connection.add", &json!({"name": "b", "remote_address": "192.0.2.7", "remote_as": 64500, "bfd": "fast"})).unwrap();
        let r = s.execute("routing.bfd.attach", &json!({"protocols": ["bgp"]})).unwrap();
        assert_eq!(r["bgp"], json!(["a"]));
        let c = &s.store().candidate().routing.bgp_connections;
        assert_eq!(c["a"].params.bfd.as_deref(), Some("default"));
        assert_eq!(c["b"].params.bfd.as_deref(), Some("fast"));
        assert!(s.execute("routing.bfd.attach", &json!({"profile": "nope"})).is_err());
        assert!(s.execute("routing.bfd.attach", &json!({"protocols": "isis"})).is_err());
        let r = s.execute("routing.bfd.attach", &json!({})).unwrap();
        assert_eq!(r["bgp"], json!([]));
    }

    #[test]
    fn previews_check_without_changing_anything() {
        let mut s = session();
        let r = s
            .execute("routing.bfd.profile.preview", &json!({"name": "edge", "min_tx": "20", "min_rx": "20", "multiplier": "2", "dampening": "no"}))
            .unwrap();
        assert_eq!(r["computed"][0]["value"], "40 ms (2 × 20 ms)");
        let levels: Vec<&str> = r["checks"].as_array().unwrap().iter().map(|c| c["check"].as_str().unwrap()).collect();
        assert!(levels.contains(&"cpu") && levels.contains(&"multiplier"), "{levels:?}");
        assert_eq!(r["commands"][0]["command"], "routing.bfd.profile.add");
        assert_eq!(r["commands"][0]["params"]["min_tx"], 20);
        assert_eq!(r["commands"][0]["params"]["dampening"], false);
        let r = s.execute("routing.bfd.profile.preview", &json!({"name": "x", "min_tx": "5"})).unwrap();
        assert_eq!(r["checks"][0]["level"], "error");
        assert_eq!(r["checks"][0]["param"], "min_tx");
        assert!(r["commands"].as_array().unwrap().is_empty());
        let r = s.execute("routing.bfd.peer.preview", &json!({"address": "198.51.100.9", "multihop": "yes", "local_address": "192.0.2.1"})).unwrap();
        assert!(r["computed"][0]["value"].as_str().unwrap().contains("4784"));
        assert!(r["checks"].as_array().unwrap().iter().any(|c| c["check"] == "auth"));
        // Nothing changed.
        assert!(s.store().candidate().routing.bfd.is_empty());
        // The commands it gives run as they are.
        let r = s.execute("routing.bfd.peer.preview", &json!({"address": "192.0.2.2", "profile": "fast"})).unwrap();
        let c = &r["commands"][0];
        s.execute(c["command"].as_str().unwrap(), &c["params"]).unwrap();
        assert_eq!(s.store().candidate().routing.bfd.peers.len(), 1);
    }

    #[test]
    fn rollback_drops_the_peer() {
        let mut s = session();
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        s.execute("routing.bfd.peer.add", &json!({"address": "192.0.2.2"})).unwrap();
        s.execute("config.discard", &json!({})).unwrap();
        assert!(s.store().candidate().routing.bfd.peers.is_empty());
    }
}
