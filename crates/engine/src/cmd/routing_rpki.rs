//! /routing rpki (G3.2c): the RTR validators (RFC 8210) in the RouterOS v7
//! model, their live sessions, `rpki-check`, and what each BGP connection
//! does with invalid routes.
//!
//! Adding the first validator turns the RPKI policy on: invalid routes are
//! rejected on every connection that does not say `accept` (as Junos and
//! IOS XR with origin validation on). RFC 8481 §5 applies policy only with
//! operator configuration; the validator is that configuration, and the
//! answer of `add` and the window say what it does.

use std::net::IpAddr;

use corerouter_model::rpki::{DEFAULT_GROUP, DEFAULT_PORT, MAX_CACHES, RpkiCache, RpkiInvalid, RpkiState};
use corerouter_model::Routing;
use corerouter_proto_bgp::rpki::{Vrp, enabled, origin_as};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text, req_str};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("routing.rpki.add", "Add RPKI Validator", ["Routing", "RPKI"], None,
        "{name: string, address: ip, port?: u16 (default 323), group?: string (default \"default\"), refresh_interval?: u32 (s, 1..=86400), retry_interval?: u32 (s, 1..=7200), expire_interval?: u32 (s, 600..=172800), preference?: u8 (0..=254, higher wins), disabled?: bool, comment?: string} → {name, notice (what the RPKI policy now does)}",
        always, add),
    cmd!("routing.rpki.set", "Set RPKI Validator", [], None,
        "{id: string (the name), name?: string, address?: ip, port?: u16, group?: string, refresh_interval?: u32 | null, retry_interval?: u32 | null, expire_interval?: u32 | null, preference?: u8 | null, disabled?: bool, comment?: string} → {name}",
        has_caches, set),
    cmd!("routing.rpki.remove", "Remove RPKI Validator", [], None,
        "{id: string (the name)} → {name, notice?}",
        has_caches, remove),
    cmd!(query "routing.rpki.list", "RPKI Validators", ["Routing", "RPKI"], None,
        "{} → [{name, group, address, port, refresh_interval?, retry_interval?, expire_interval?, preference?, disabled, comment, state (the session's: idle | connecting | loading | sync | error | disabled | unknown), version?, serial?, ipv4, ipv6, error?}]",
        always, list),
    cmd!(query "routing.rpki.session.list", "RPKI Sessions", ["Routing", "RPKI"], None,
        "{} → {updated?, frr? (bgpd's own RTR state), policy: {active, rejecting: [connection], accepting: [connection], ebgp_waiting: [connection]}, sessions: [{name, group, address, port, state, version?, session_id?, serial?, ipv4, ipv6, router_keys?, last_update?, expires?, refresh, retry, expire, error?}]}",
        always, session_list),
    cmd!(query "routing.rpki.check", "RPKI Check", ["Routing", "RPKI"], None,
        "{prefix: cidr, origin_as: u32 | asdot string | path (the last AS of an AS path)} → {prefix, origin_as?, state: valid | invalid | unknown | unverified, covering: [{prefix, max_length, asn, matches}], reason}",
        always, check),
    cmd!(query "routing.rpki.preview", "Check RPKI Validator", [], None,
        "{id?: string (the validator being edited), name?: string, address?: string, port?: u16 | string, group?: string, refresh_interval?: u32 | string | null, retry_interval?: u32 | string | null, expire_interval?: u32 | string | null, preference?: u8 | string | null, disabled?: bool | yes | no, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}]} (form texts accepted; never an error: bad input is a check)",
        always, preview),
    cmd!("routing.rpki.invalid.set", "RPKI Invalid Routes", [], None,
        "{connection?: string, template?: string (one of the two), invalid?: reject | accept | null (left out or null: inherit; the default is reject)} → {connection? | template?, invalid?, effective (connection: in force)}",
        always, invalid_set),
];

fn has_caches(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.rpki.is_empty() {
        Err("there are no RPKI validators (routing.rpki.add)".into())
    } else {
        Ok(())
    }
}

fn check_name(key: &str, name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(EngineError::bad(key, "1..=64 characters of [A-Za-z0-9_.-]"));
    }
    Ok(())
}

/// `null` unsets, a number sets, absent keeps.
fn opt_num<T: TryFrom<u64>>(p: &Value, key: &str, slot: &mut Option<T>) -> Result<()> {
    match p.get(key) {
        None => {}
        Some(Value::Null) => *slot = None,
        Some(v) => {
            *slot = Some(
                v.as_u64()
                    .and_then(|n| T::try_from(n).ok())
                    .ok_or_else(|| EngineError::bad(key, "must be a whole number in range"))?,
            );
        }
    }
    Ok(())
}

fn apply(routing: &mut Routing, p: &Value, id: Option<&str>) -> Result<String> {
    let mut c = match id {
        Some(id) => routing
            .rpki
            .get(id)
            .cloned()
            .ok_or_else(|| EngineError::bad("id", format!("no RPKI validator {:?}", crate::logging::cut(id, 64))))?,
        None => RpkiCache {
            name: String::new(),
            group: DEFAULT_GROUP.to_owned(),
            address: IpAddr::from([0, 0, 0, 0]),
            port: DEFAULT_PORT,
            refresh_interval: None,
            retry_interval: None,
            expire_interval: None,
            preference: None,
            disabled: false,
            comment: String::new(),
        },
    };
    match opt_str(p, "name")? {
        Some(n) => {
            check_name("name", n)?;
            c.name = n.to_owned();
        }
        None if id.is_none() => return Err(EngineError::bad("name", "is required")),
        None => {}
    }
    match opt_str(p, "address")? {
        Some(a) => {
            c.address = a.trim().parse().map_err(|_| {
                EngineError::bad("address", format!("{:?} is not an IP address", crate::logging::cut(a, 64)))
            })?;
        }
        None if id.is_none() => return Err(EngineError::bad("address", "is required")),
        None => {}
    }
    if let Some(g) = opt_str(p, "group")? {
        check_name("group", g)?;
        c.group = g.to_owned();
    }
    if let Some(v) = p.get("port") {
        c.port = v
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .filter(|n| *n > 0)
            .ok_or_else(|| EngineError::bad("port", "must be 1..=65535"))?;
    }
    opt_num(p, "refresh_interval", &mut c.refresh_interval)?;
    opt_num(p, "retry_interval", &mut c.retry_interval)?;
    opt_num(p, "expire_interval", &mut c.expire_interval)?;
    opt_num(p, "preference", &mut c.preference)?;
    if let Some(d) = opt_bool(p, "disabled")? {
        c.disabled = d;
    }
    if let Some(note) = opt_text(p, "comment", 256)? {
        c.comment = note;
    }
    let name = c.name.clone();
    if id != Some(name.as_str()) && routing.rpki.contains_key(&name) {
        return Err(EngineError::bad("name", format!("validator {name:?} already exists")));
    }
    if id.is_none() && routing.rpki.len() >= MAX_CACHES {
        return Err(EngineError::bad("name", format!("at most {MAX_CACHES} RPKI validators")));
    }
    if let Some(old) = id.filter(|old| *old != name) {
        routing.rpki.remove(old);
    }
    routing.rpki.insert(name.clone(), c);
    Ok(name)
}

/// Which connections reject, which accept, which wait for a policy.
fn policy(routing: &Routing) -> Value {
    let resolved = corerouter_model::bgp::resolve_templates(&routing.bgp_templates);
    let on = !enabled(routing).is_empty();
    let (mut rejecting, mut accepting, mut waiting) = (Vec::new(), Vec::new(), Vec::new());
    for c in routing.bgp_connections.values() {
        let Ok(eff) = c.effective(&resolved) else { continue };
        let ibgp = match (eff.local_role, eff.remote_as, routing.bgp.get(&c.instance)) {
            (Some(r), _, _) => r.is_ibgp(),
            (None, Some(a), Some(i)) => a == i.asn,
            _ => false,
        };
        if eff.rpki_invalid == Some(RpkiInvalid::Accept) {
            accepting.push(c.name.clone());
        } else if ibgp {
            rejecting.push(c.name.clone());
        } else {
            waiting.push(c.name.clone());
        }
    }
    json!({"active": on, "rejecting": rejecting, "accepting": accepting, "ebgp_waiting": waiting})
}

fn notice(routing: &Routing) -> String {
    if enabled(routing).is_empty() {
        return "no enabled validator: RPKI does not filter anything".into();
    }
    "RPKI is on: routes whose origin a ROA contradicts (invalid, RFC 6811) are rejected on every \
     connection that does not set rpki_invalid=accept (routing.rpki.invalid.set). eBGP connections \
     accept nothing until they have a policy (RFC 8212); the RPKI check joins that policy (G3.2b)."
        .into()
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let routing = &mut s.store_mut().candidate_mut().routing;
    let name = apply(routing, p, None)?;
    Ok(json!({ "name": name, "notice": notice(routing) }))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?.to_owned();
    let name = apply(&mut s.store_mut().candidate_mut().routing, p, Some(&id))?;
    Ok(json!({ "name": name }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?;
    let routing = &mut s.store_mut().candidate_mut().routing;
    if routing.rpki.remove(id).is_none() {
        return Err(EngineError::bad("id", format!("no RPKI validator {:?}", crate::logging::cut(id, 64))));
    }
    let n = (enabled(routing).is_empty()).then(|| notice(routing));
    Ok(json!({ "name": id, "notice": n }))
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    let status = s.rpki_status().cloned().unwrap_or_default();
    let rows: Vec<Value> = s
        .store()
        .candidate()
        .routing
        .rpki
        .values()
        .map(|c| {
            let live = status.sessions.iter().find(|x| x.name == c.name);
            let mut v = serde_json::to_value(c).unwrap_or_else(|_| json!({}));
            if let Some(o) = v.as_object_mut() {
                let state = if c.disabled {
                    "disabled".to_owned()
                } else {
                    live.map_or_else(|| "unknown".to_owned(), |l| l.state.clone())
                };
                o.insert("state".into(), json!(state));
                o.insert("version".into(), json!(live.and_then(|l| l.version)));
                o.insert("serial".into(), json!(live.and_then(|l| l.serial)));
                o.insert("ipv4".into(), json!(live.map_or(0, |l| l.ipv4)));
                o.insert("ipv6".into(), json!(live.map_or(0, |l| l.ipv6)));
                o.insert("error".into(), json!(live.and_then(|l| l.error.clone())));
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}

fn session_list(s: &mut Session, _: &Value) -> Result<Value> {
    let status = s.rpki_status().cloned().unwrap_or_default();
    let mut v = serde_json::to_value(&status).unwrap_or_else(|_| json!({}));
    if let Some(o) = v.as_object_mut() {
        o.insert("policy".into(), policy(&s.store().running().routing));
    }
    Ok(v)
}

fn parse_origin(p: &Value) -> Result<Option<u32>> {
    match p.get("origin_as") {
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| EngineError::bad("origin_as", "must be 0..=4294967295")),
        Some(Value::String(t)) if t.len() <= 4_096 => {
            // An AS path: its origin per RFC 6811 §2 (None for an AS_SET).
            let t = t.trim();
            if t.is_empty() || !t.chars().all(|c| c.is_ascii_digit() || " .{},()".contains(c)) {
                return Err(EngineError::bad("origin_as", "an AS number, asdot, or an AS path"));
            }
            Ok(origin_as(t, None))
        }
        _ => Err(EngineError::bad("origin_as", "is required (an AS number or an AS path)")),
    }
}

fn check(s: &mut Session, p: &Value) -> Result<Value> {
    let raw = req_str(p, "prefix")?;
    let net: ipnet::IpNet = raw.trim().parse().map_err(|_| {
        EngineError::bad("prefix", format!("{:?} is not a prefix (192.0.2.0/24)", crate::logging::cut(raw, 64)))
    })?;
    let net = net.trunc();
    let origin = parse_origin(p)?;
    let Some(table) = s.vrps() else {
        return Ok(json!({
            "prefix": net.to_string(), "origin_as": origin, "state": RpkiState::Unverified.name(),
            "covering": [], "reason": "no validator is in sync (routing.rpki.session.list)",
        }));
    };
    let state = table.validate(net.network(), net.prefix_len(), origin);
    let covering: Vec<Value> = table
        .covering(net.network(), net.prefix_len())
        .iter()
        .take(256)
        .map(|v: &Vrp| {
            let matches = net.prefix_len() <= v.max_len && Some(v.asn) == origin && v.asn != 0;
            json!({"prefix": format!("{}/{}", v.addr(), v.prefix_len()), "max_length": v.max_len, "asn": v.asn, "matches": matches})
        })
        .collect();
    let reason = match state {
        RpkiState::Valid => "a VRP covers it, allows this length and names this origin (RFC 6811 §2)",
        RpkiState::Invalid if origin.is_none() => "VRPs cover it but the path has no origin AS (it ends in an AS_SET)",
        RpkiState::Invalid => "VRPs cover it but none allows this origin AS at this length (RFC 6811 §2)",
        _ => "no VRP covers it (RFC 6811 NotFound)",
    };
    Ok(json!({
        "prefix": net.to_string(), "origin_as": origin, "state": state.name(),
        "covering": covering, "reason": reason,
    }))
}

const NUMBERS: [&str; 5] = ["port", "refresh_interval", "retry_interval", "expire_interval", "preference"];

/// Form texts as `add`/`set` take them: numbers as numbers, yes/no as
/// bools, an empty optional field unset (`set`) or left out (`add`).
fn normalize(p: &Value, editing: bool) -> Value {
    let Some(o) = p.as_object() else {
        return p.clone();
    };
    let mut out = serde_json::Map::new();
    for (k, v) in o {
        let text = v.as_str().map(str::trim);
        let v = match text {
            Some("") if NUMBERS.contains(&k.as_str()) && k != "port" => {
                if editing {
                    Value::Null
                } else {
                    continue;
                }
            }
            Some("") if k == "port" || k == "group" => continue,
            Some(t) if NUMBERS.contains(&k.as_str()) => t.parse::<u64>().map_or_else(|_| v.clone(), Value::from),
            Some("yes") if k == "disabled" => Value::Bool(true),
            Some("no") if k == "disabled" => Value::Bool(false),
            _ => v.clone(),
        };
        out.insert(k.clone(), v);
    }
    if !editing {
        out.remove("id");
    }
    Value::Object(out)
}

fn preview(s: &mut Session, raw: &Value) -> Result<Value> {
    let id = raw.get("id").and_then(Value::as_str).map(str::to_owned);
    let editing = id.is_some();
    let p = normalize(raw, editing);
    let mut routing = s.store().candidate().routing.clone();
    let check = |level: &str, check: &str, message: String, param: &str| {
        json!({"level": level, "check": check, "message": message, "param": param})
    };
    let mut checks = Vec::new();
    let mut computed = Vec::new();
    let mut commands = Vec::new();
    match apply(&mut routing, &p, id.as_deref()) {
        Err(EngineError::BadParam { param, reason }) => {
            checks.push(check("error", "param", reason, &param));
        }
        Err(e) => checks.push(check("error", "param", e.to_string(), "")),
        Ok(name) => {
            for i in corerouter_proto_bgp::rpki::validate(&routing) {
                let param = i.path.rsplit('.').next().unwrap_or_default().to_owned();
                checks.push(check("error", "rfc8210", i.message, &param));
            }
            if let Some(c) = routing.rpki.get(&name) {
                computed.push(json!({"label": "Session", "value": format!("RTR to {}:{} (RFC 8210, falls back to RFC 6810)", c.address, c.port)}));
                let t = |v: Option<u32>, d: &str| v.map_or_else(|| format!("the validator's ({d} s until it says)"), |v| format!("{v} s"));
                computed.push(json!({"label": "Refresh", "value": t(c.refresh_interval, "3600")}));
                computed.push(json!({"label": "Expire", "value": t(c.expire_interval, "7200")}));
                if c.refresh_interval.is_some_and(|r| r > 3_600) {
                    checks.push(check("info", "frr", "FRR polls at most every 3600 s; it gets 3600".into(), "refresh_interval"));
                }
                if c.port != DEFAULT_PORT {
                    checks.push(check("info", "port", format!("{} is not the IANA RTR port 323 (Routinator uses 3323, StayRTR 8282)", c.port), "port"));
                }
            }
            let was_on = !enabled(&s.store().candidate().routing).is_empty();
            if !was_on && !enabled(&routing).is_empty() {
                checks.push(check("warning", "policy", notice(&routing), ""));
            }
            let command = if editing { "routing.rpki.set" } else { "routing.rpki.add" };
            commands.push(json!({"command": command, "params": p}));
        }
    }
    Ok(json!({"computed": computed, "checks": checks, "commands": commands}))
}

fn invalid_set(s: &mut Session, p: &Value) -> Result<Value> {
    let conn = opt_str(p, "connection")?.map(str::to_owned);
    let tmpl = opt_str(p, "template")?.map(str::to_owned);
    let value = match p.get("invalid") {
        None | Some(Value::Null) => None,
        Some(Value::String(v)) => Some(
            RpkiInvalid::parse(v.trim()).ok_or_else(|| EngineError::bad("invalid", "reject, accept or null"))?,
        ),
        _ => return Err(EngineError::bad("invalid", "reject, accept or null")),
    };
    let routing = &mut s.store_mut().candidate_mut().routing;
    match (conn, tmpl) {
        (Some(c), None) => {
            let entry = routing
                .bgp_connections
                .get_mut(&c)
                .ok_or_else(|| EngineError::bad("connection", format!("no BGP connection {:?}", crate::logging::cut(&c, 64))))?;
            entry.params.rpki_invalid = value;
            let resolved = corerouter_model::bgp::resolve_templates(&routing.bgp_templates);
            let eff = routing
                .bgp_connections
                .get(&c)
                .and_then(|e| e.effective(&resolved).ok())
                .and_then(|e| e.rpki_invalid)
                .unwrap_or_default();
            Ok(json!({"connection": c, "invalid": value.map(RpkiInvalid::name), "effective": eff.name()}))
        }
        (None, Some(t)) => {
            let entry = routing
                .bgp_templates
                .get_mut(&t)
                .ok_or_else(|| EngineError::bad("template", format!("no BGP template {:?}", crate::logging::cut(&t, 64))))?;
            entry.params.rpki_invalid = value;
            Ok(json!({"template": t, "invalid": value.map(RpkiInvalid::name)}))
        }
        _ => Err(EngineError::bad("connection", "give a connection or a template, not both")),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use corerouter_hal::VirtualHal;
    use corerouter_proto_bgp::rpki::VrpTable;

    use super::*;

    fn session() -> Session {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        s.execute("routing.bgp.instance.set", &json!({"asn": 65000, "router_id": "10.0.0.1"}))
            .unwrap();
        s.execute("routing.bgp.connection.add", &json!({"name": "rr1", "remote_address": "192.0.2.2", "remote_as": 65000}))
            .unwrap();
        s.execute("routing.bgp.connection.add", &json!({"name": "up1", "remote_address": "192.0.2.6", "remote_as": 64500}))
            .unwrap();
        s
    }

    #[test]
    fn validators_turn_the_policy_on() {
        let mut s = session();
        let p = s.execute("routing.rpki.session.list", &json!({})).unwrap();
        assert_eq!(p["policy"]["active"], false);
        let r = s
            .execute("routing.rpki.add", &json!({"name": "rtr1", "address": "192.0.2.10", "port": 3323, "refresh_interval": 60}))
            .unwrap();
        assert!(r["notice"].as_str().unwrap().contains("rejected"));
        let p = s.execute("routing.rpki.session.list", &json!({})).unwrap();
        assert_eq!(p["policy"]["active"], true);
        assert_eq!(p["policy"]["rejecting"], json!(["rr1"]));
        assert_eq!(p["policy"]["ebgp_waiting"], json!(["up1"]));
        let l = s.execute("routing.rpki.list", &json!({})).unwrap();
        assert_eq!((l[0]["port"].as_u64(), l[0]["state"].as_str()), (Some(3323), Some("unknown")));
        // The switch per connection.
        let r = s.execute("routing.rpki.invalid.set", &json!({"connection": "rr1", "invalid": "accept"})).unwrap();
        assert_eq!(r["effective"], "accept");
        let p = s.execute("routing.rpki.session.list", &json!({})).unwrap();
        assert_eq!(p["policy"]["accepting"], json!(["rr1"]));
        // FRR render: the rpki node, and no route-map on the accepting one.
        let frr = corerouter_proto_bgp::render_all(&s.store().running().routing, &|_| None).unwrap();
        assert!(frr.contains(" rpki cache tcp 192.0.2.10 3323 preference 255"), "{frr}");
        assert!(!frr.contains("neighbor 192.0.2.2 route-map CR-RPKI-IN in"), "{frr}");
        s.execute("routing.rpki.invalid.set", &json!({"connection": "rr1", "invalid": null})).unwrap();
        let frr = corerouter_proto_bgp::render_all(&s.store().running().routing, &|_| None).unwrap();
        assert!(frr.contains("  neighbor 192.0.2.2 soft-reconfiguration inbound\n  neighbor 192.0.2.2 route-map CR-RPKI-IN in"), "{frr}");
        // eBGP: no route-map (RFC 8212 stays closed).
        assert!(!frr.contains("neighbor 192.0.2.6 route-map"), "{frr}");
        let r = s.execute("routing.rpki.remove", &json!({"id": "rtr1"})).unwrap();
        assert!(r["notice"].as_str().unwrap().contains("no enabled validator"));
    }

    #[test]
    fn validation_errors_and_rollback() {
        let mut s = session();
        for bad in [
            json!({"name": "x", "address": "nope"}),
            json!({"name": "bad name", "address": "192.0.2.1"}),
            json!({"name": "x", "address": "192.0.2.1", "port": 0}),
            json!({"address": "192.0.2.1"}),
        ] {
            assert!(s.execute("routing.rpki.add", &bad).is_err(), "{bad}");
        }
        // RFC 8210 §6: refused at commit by proto-bgp, nothing changes.
        let e = s
            .execute("routing.rpki.add", &json!({"name": "x", "address": "192.0.2.1", "expire_interval": 100}))
            .unwrap_err();
        assert!(e.to_string().contains("RFC 8210"), "{e}");
        assert!(s.store().running().routing.rpki.is_empty());
        assert!(s.execute("routing.rpki.invalid.set", &json!({"connection": "nope", "invalid": "accept"})).is_err());
        assert!(s.execute("routing.rpki.invalid.set", &json!({"connection": "rr1", "invalid": "maybe"})).is_err());
    }

    #[test]
    fn the_preview_takes_form_texts() {
        let mut s = session();
        let r = s
            .execute("routing.rpki.preview", &json!({"name": "rtr1", "address": "192.0.2.10", "port": "3323", "refresh_interval": "", "disabled": "no"}))
            .unwrap();
        assert_eq!(r["commands"][0]["command"], "routing.rpki.add");
        assert_eq!(r["commands"][0]["params"]["port"], 3323);
        assert!(r["commands"][0]["params"].get("refresh_interval").is_none());
        assert!(r["checks"].as_array().unwrap().iter().any(|c| c["check"] == "policy"));
        let r = s.execute("routing.rpki.preview", &json!({"name": "rtr1", "address": "x"})).unwrap();
        assert_eq!(r["checks"][0]["param"], "address");
        let r = s
            .execute("routing.rpki.preview", &json!({"name": "rtr1", "address": "192.0.2.10", "expire_interval": "60"}))
            .unwrap();
        assert_eq!(r["checks"][0]["param"], "expire_interval");
        assert!(s.store().candidate().routing.rpki.is_empty(), "the preview changes nothing");
    }

    #[test]
    fn check_against_the_table() {
        let mut s = session();
        let r = s.execute("routing.rpki.check", &json!({"prefix": "192.0.2.0/24", "origin_as": 64500})).unwrap();
        assert_eq!(r["state"], "unverified");
        let t = VrpTable::build(&[Vrp::new("192.0.2.0".parse().unwrap(), 24, 24, 64500).unwrap()]);
        s.set_rpki_table(Some(Arc::new(t)));
        let r = s.execute("routing.rpki.check", &json!({"prefix": "192.0.2.0/24", "origin_as": 64500})).unwrap();
        assert_eq!(r["state"], "valid");
        assert_eq!(r["covering"][0]["matches"], true);
        let r = s.execute("routing.rpki.check", &json!({"prefix": "192.0.2.0/25", "origin_as": "64511 64500"})).unwrap();
        assert_eq!(r["state"], "invalid");
        let r = s.execute("routing.rpki.check", &json!({"prefix": "192.0.2.0/24", "origin_as": "64511 {64500}"})).unwrap();
        assert_eq!(r["state"], "invalid");
        assert!(r["reason"].as_str().unwrap().contains("AS_SET"));
        assert!(s.execute("routing.rpki.check", &json!({"prefix": "x", "origin_as": 1})).is_err());
        assert!(s.execute("routing.rpki.check", &json!({"prefix": "10.0.0.0/8", "origin_as": "a;b"})).is_err());
    }
}
