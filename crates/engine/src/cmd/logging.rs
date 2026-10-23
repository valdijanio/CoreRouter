//! /system logging (G4.6): remote syslog actions and the rules that send
//! events with some topics to them; the built-in `memory` action keeps the
//! router's own log (`log.print`, G4.6d) and only takes `memory_lines`;
//! the built-in `analytics` action is the ClickHouse exporter's `logs`
//! table (G4.4f), configured with `system.analytics.*`.

use std::net::IpAddr;

use corerouter_model::ItemId;
use corerouter_model::logging::{
    Facility, LogAction, LogRule, Logging, MAX_ACTIONS, MAX_MEMORY_LINES, MAX_NAME, MAX_PREFIX,
    ANALYTICS_ACTION, MAX_RULES, MAX_TOPICS, MEMORY_ACTION, SeverityChoice, valid_topic,
};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_text, opt_u32, req_parse, req_str};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "system.logging.action.add",
        "Add Logging Action",
        ["System", "Logging"],
        None,
        "{name: string, remote: ip, remote_port?: int 1..65535, src_address?: ip, syslog_facility?: kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|authpriv|ftp|ntp|local0..local7, syslog_severity?: auto|emergency|alert|critical|error|warning|notice|info|debug, comment?: string} → {name}",
        always,
        action_add
    ),
    cmd!(
        "system.logging.action.set",
        "Edit Logging Action",
        [],
        None,
        "{name: string, remote?: ip, remote_port?: int 1..65535, src_address?: ip|\"\", syslog_facility?: kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|authpriv|ftp|ntp|local0..local7, syslog_severity?: auto|emergency|alert|critical|error|warning|notice|info|debug, comment?: string, memory_lines?: int 1..65535} → {name}",
        always,
        action_set
    ),
    cmd!(
        "system.logging.action.remove",
        "Remove Logging Action",
        [],
        None,
        "{name: string} → {name}",
        always,
        action_remove
    ),
    cmd!(query "system.logging.action.list", "Logging Actions", [], None,
        "{} → [{name, target, default, memory_lines, remote, remote_port, src_address, syslog_facility, syslog_severity, comment}]",
        always, action_list),
    cmd!(
        "system.logging.add",
        "Add Logging Rule",
        ["System", "Logging"],
        None,
        "{topics: [string], action: string, prefix?: string, disabled?: bool} → {id}",
        always,
        rule_add
    ),
    cmd!(
        "system.logging.set",
        "Edit Logging Rule",
        [],
        None,
        "{id: string, topics?: [string], action?: string, prefix?: string, disabled?: bool} → {id}",
        always,
        rule_set
    ),
    cmd!(
        "system.logging.remove",
        "Remove Logging Rule",
        [],
        None,
        "{id: string} → {id}",
        always,
        rule_remove
    ),
    cmd!(query "system.logging.list", "Logging Rules", [], None,
        "{} → [{id, topics, action, prefix, disabled, default}]",
        always, rule_list),
];

fn logging(s: &mut Session) -> &mut Logging {
    &mut s.store_mut().candidate_mut().system.logging
}

fn action_name(p: &Value, key: &str) -> Result<String> {
    let name = req_str(p, key)?.trim();
    let ok = (1..=MAX_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !ok {
        return Err(EngineError::bad(
            key,
            format!("1..={MAX_NAME} letters, digits, '-' or '_'"),
        ));
    }
    Ok(name.to_owned())
}

fn action_json(a: &LogAction) -> Value {
    json!({
        "name": a.name,
        "target": "remote",
        "default": false,
        "memory_lines": null,
        "remote": a.remote,
        "remote_port": a.remote_port,
        "src_address": a.src_address,
        "syslog_facility": a.syslog_facility.as_str(),
        "syslog_severity": a.syslog_severity.to_string(),
        "comment": a.comment,
    })
}

/// Applies the optional fields of add/set to `a`, then checks the result.
fn apply_action(a: &mut LogAction, p: &Value) -> Result<()> {
    if let Some(r) = opt_parse::<IpAddr>(p, "remote")? {
        a.remote = r;
    }
    if let Some(port) = opt_u32(p, "remote_port")? {
        a.remote_port = u16::try_from(port)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| EngineError::bad("remote_port", "must be 1..=65535"))?;
    }
    match p.get("src_address") {
        Some(Value::String(s)) if s.trim().is_empty() => a.src_address = None,
        _ => {
            if let Some(src) = opt_parse::<IpAddr>(p, "src_address")? {
                a.src_address = Some(src);
            }
        }
    }
    if let Some(f) = opt_parse::<Facility>(p, "syslog_facility")? {
        a.syslog_facility = f;
    }
    if let Some(sev) = opt_parse::<SeverityChoice>(p, "syslog_severity")? {
        a.syslog_severity = sev;
    }
    if let Some(c) = opt_text(p, "comment", 255)? {
        a.comment = c;
    }
    if a.remote.is_unspecified() || a.remote.is_multicast() {
        return Err(EngineError::bad(
            "remote",
            "must be the address of a syslog server (not 0.0.0.0, :: or multicast)",
        ));
    }
    if let Some(src) = a.src_address
        && src.is_ipv4() != a.remote.is_ipv4()
    {
        return Err(EngineError::bad(
            "src_address",
            format!("{src} and remote {} are different IP families", a.remote),
        ));
    }
    Ok(())
}

fn action_add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = action_name(p, "name")?;
    let remote: IpAddr = req_parse(p, "remote")?;
    let l = &s.store().candidate().system.logging;
    if l.has_action(&name) {
        return Err(EngineError::bad(
            "name",
            format!("action '{name}' already exists (use system.logging.action.set)"),
        ));
    }
    if l.actions.len() >= MAX_ACTIONS {
        return Err(EngineError::bad(
            "name",
            format!("at most {MAX_ACTIONS} actions"),
        ));
    }
    let mut a = LogAction {
        name: name.clone(),
        remote,
        remote_port: corerouter_model::logging::DEFAULT_PORT,
        src_address: None,
        syslog_facility: Facility::default(),
        syslog_severity: SeverityChoice::default(),
        comment: String::new(),
    };
    apply_action(&mut a, p)?;
    logging(s).actions.push(a);
    Ok(json!({ "name": name }))
}

/// `memory_lines` of the built-in `memory` action, the only thing it has.
fn memory_set(s: &mut Session, p: &Value) -> Result<Value> {
    let remote_keys = [
        "remote",
        "remote_port",
        "src_address",
        "syslog_facility",
        "syslog_severity",
        "comment",
    ];
    if let Some(k) = remote_keys.iter().find(|k| p.get(**k).is_some_and(|v| !v.is_null())) {
        return Err(EngineError::bad(
            k,
            "the memory action keeps the log in RAM: it only takes memory_lines",
        ));
    }
    if let Some(n) = opt_u32(p, "memory_lines")? {
        if !(1..=MAX_MEMORY_LINES).contains(&n) {
            return Err(EngineError::bad(
                "memory_lines",
                format!("must be 1..={MAX_MEMORY_LINES}"),
            ));
        }
        logging(s).memory_lines = n;
    }
    Ok(json!({ "name": MEMORY_ACTION }))
}

fn action_set(s: &mut Session, p: &Value) -> Result<Value> {
    let name = action_name(p, "name")?;
    if name == MEMORY_ACTION {
        return memory_set(s, p);
    }
    if name == ANALYTICS_ACTION {
        return Err(EngineError::bad(
            "name",
            "analytics is the ClickHouse exporter: configure it with system.analytics.set",
        ));
    }
    if p.get("memory_lines").is_some_and(|v| !v.is_null()) {
        return Err(EngineError::bad(
            "memory_lines",
            format!("only the memory action has memory_lines; '{name}' is remote"),
        ));
    }
    let mut a = s
        .store()
        .candidate()
        .system
        .logging
        .action(&name)
        .cloned()
        .ok_or_else(|| no_action(&name))?;
    apply_action(&mut a, p)?;
    if let Some(slot) = logging(s).actions.iter_mut().find(|x| x.name == name) {
        *slot = a;
    }
    Ok(json!({ "name": name }))
}

fn no_action(name: &str) -> EngineError {
    EngineError::bad(
        "name",
        format!("no logging action '{name}' (see system.logging.action.list)"),
    )
}

fn action_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let name = action_name(p, "name")?;
    if name == MEMORY_ACTION {
        return Err(EngineError::bad(
            "name",
            "memory is the router's own log: it cannot be removed (disable its rules instead)",
        ));
    }
    if name == ANALYTICS_ACTION {
        return Err(EngineError::bad(
            "name",
            "analytics is built in: it cannot be removed (disable its rules, or system.analytics.set logs=no)",
        ));
    }
    let l = &s.store().candidate().system.logging;
    if l.action(&name).is_none() {
        return Err(no_action(&name));
    }
    // Like RouterOS: an action in use cannot go (a rule would point nowhere).
    if let Some(r) = l.rules.iter().find(|r| r.action == name) {
        return Err(EngineError::bad(
            "name",
            format!(
                "action '{name}' is used by logging rule {} (remove or change it first)",
                r.id
            ),
        ));
    }
    logging(s).actions.retain(|a| a.name != name);
    Ok(json!({ "name": name }))
}

fn action_list(s: &mut Session, _: &Value) -> Result<Value> {
    let l = &s.store().candidate().system.logging;
    let memory = json!({
        "name": MEMORY_ACTION,
        "target": "memory",
        "default": true,
        "memory_lines": l.memory_lines,
        "remote": null,
        "remote_port": null,
        "src_address": null,
        "syslog_facility": null,
        "syslog_severity": null,
        "comment": "",
    });
    let analytics = json!({
        "name": ANALYTICS_ACTION,
        "target": "analytics",
        "default": true,
        "memory_lines": null,
        "remote": null,
        "remote_port": null,
        "src_address": null,
        "syslog_facility": null,
        "syslog_severity": null,
        "comment": "",
    });
    Ok(Value::Array(
        [memory, analytics]
            .into_iter()
            .chain(l.actions.iter().map(action_json))
            .collect(),
    ))
}

/// Topics as a JSON array or, for the CLI, `"ntp,!debug"`.
fn topics(p: &Value) -> Result<Option<Vec<String>>> {
    let raw: Vec<String> = match p.get("topics") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.split(',').map(|t| t.trim().to_owned()).collect(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|t| t.trim().to_owned())
                    .ok_or_else(|| EngineError::bad("topics", "each item must be a string"))
            })
            .collect::<Result<_>>()?,
        Some(_) => {
            return Err(EngineError::bad(
                "topics",
                "must be a list, e.g. [\"info\"] or [\"ntp\", \"!debug\"]",
            ));
        }
    };
    if raw.len() > MAX_TOPICS {
        return Err(EngineError::bad(
            "topics",
            format!("at most {MAX_TOPICS} topics"),
        ));
    }
    let mut out: Vec<String> = Vec::new();
    for t in raw.into_iter().filter(|t| !t.is_empty()) {
        valid_topic(&t).map_err(|e| EngineError::bad("topics", e))?;
        if !out.contains(&t) {
            out.push(t);
        }
    }
    if !out.iter().any(|t| !t.starts_with('!')) {
        return Err(EngineError::bad(
            "topics",
            "name at least one topic without '!' (e.g. \"info\"); a rule of only exclusions matches nothing",
        ));
    }
    Ok(Some(out))
}

/// Ids of the default rules (`Logging::default`).
const DEFAULT_RULES: u32 = 4;

fn rule_json(r: &LogRule) -> Value {
    json!({
        "id": r.id,
        "topics": r.topics,
        "action": r.action,
        "prefix": r.prefix,
        "disabled": r.disabled,
        // The four rules every new config has (*1..*4; ids are never
        // reused): `/export` sets them instead of adding copies.
        "default": r.id.0 <= DEFAULT_RULES,
    })
}

/// Applies the optional fields of add/set to `r`; the action must exist.
fn apply_rule(s: &Session, r: &mut LogRule, p: &Value) -> Result<()> {
    if let Some(t) = topics(p)? {
        r.topics = t;
    }
    if p.get("action").is_some_and(|v| !v.is_null()) {
        let name = action_name(p, "action")?;
        if !s.store().candidate().system.logging.has_action(&name) {
            return Err(EngineError::bad(
                "action",
                format!(
                    "no logging action '{name}' (create it with system.logging.action.add)"
                ),
            ));
        }
        r.action = name;
    }
    if let Some(prefix) = opt_text(p, "prefix", MAX_PREFIX)? {
        r.prefix = prefix;
    }
    if let Some(d) = opt_bool(p, "disabled")? {
        r.disabled = d;
    }
    Ok(())
}

fn rule_add(s: &mut Session, p: &Value) -> Result<Value> {
    if topics(p)?.is_none() {
        return Err(EngineError::bad("topics", "is required"));
    }
    req_str(p, "action")?;
    if s.store().candidate().system.logging.rules.len() >= MAX_RULES {
        return Err(EngineError::bad(
            "topics",
            format!("at most {MAX_RULES} logging rules"),
        ));
    }
    let mut r = LogRule {
        id: ItemId(0),
        topics: Vec::new(),
        action: String::new(),
        prefix: String::new(),
        disabled: false,
    };
    apply_rule(s, &mut r, p)?;
    let l = logging(s);
    r.id = l.next_rule_id();
    let id = r.id;
    l.rules.push(r);
    Ok(json!({ "id": id }))
}

fn existing_rule(s: &Session, p: &Value) -> Result<LogRule> {
    let id: ItemId = req_parse(p, "id")?;
    s.store()
        .candidate()
        .system
        .logging
        .rules
        .iter()
        .find(|r| r.id == id)
        .cloned()
        .ok_or_else(|| {
            EngineError::bad("id", format!("no logging rule {id} (see system.logging.list)"))
        })
}

fn rule_set(s: &mut Session, p: &Value) -> Result<Value> {
    let mut r = existing_rule(s, p)?;
    apply_rule(s, &mut r, p)?;
    let id = r.id;
    if let Some(slot) = logging(s).rules.iter_mut().find(|x| x.id == id) {
        *slot = r;
    }
    Ok(json!({ "id": id }))
}

fn rule_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id = existing_rule(s, p)?.id;
    logging(s).rules.retain(|r| r.id != id);
    Ok(json!({ "id": id }))
}

fn rule_list(s: &mut Session, _: &Value) -> Result<Value> {
    let l = &s.store().candidate().system.logging;
    Ok(Value::Array(l.rules.iter().map(rule_json).collect()))
}
