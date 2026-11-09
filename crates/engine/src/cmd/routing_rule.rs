//! /routing rule (G1.27e): policy routing in the RouterOS v7 model. The rules
//! run top to bottom, the first that decides wins. See `docs/routes.md` and
//! `corerouter_hal::policy` for where they sit among the kernel's own.

use std::net::IpAddr;

use corerouter_hal::policy::{KernelRule, KernelRuleRow, RuleOwner, mangle_marks, rule_pref};
use corerouter_model::firewall::Name;
use corerouter_model::policy_rule::{MAX_RULES, RoutingRule, RuleAction};
use corerouter_model::route;
use corerouter_model::{Config, IfName, ItemId, RoutingTable, parse_destination};
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_text, opt_u32, req_parse};
use super::{CommandSpec, always};
use crate::lockout::{route_out, take_force};
use crate::policy_rule::{action_json, notices, rule_issues, summary};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("routing.rule.add", "Add Routing Rule", ["Routing", "Rules"], None,
        "{src_address?: cidr | ip, dst_address?: cidr | ip, interface?: string (incoming; lo: the router's own packets), routing_mark?: string (set by the mangle), action?: lookup | lookup-only-in-table | drop | unreachable (default lookup), table?: string (main | VRF | routing.table name; default main), min_prefix?: u32 (routes of this length or shorter are ignored; 0 hides the default route), place_before?: *hex (default: last), disabled?: bool, comment?: string, force?: bool (cuts this session's way back all the same)} → {id, summary, notice? (many rules: what they cost per packet)}",
        always, add),
    cmd!("routing.rule.set", "Set Routing Rule", [], None,
        "{id: *hex, src_address?: cidr | ip | null, dst_address?: cidr | ip | null, interface?: string | null, routing_mark?: string | null, action?: lookup | lookup-only-in-table | drop | unreachable, table?: string, min_prefix?: u32 | null, disabled?: bool, comment?: string, force?: bool} → {id, summary}",
        has_rules, set),
    cmd!("routing.rule.remove", "Remove Routing Rule", [], None,
        "{id: *hex, force?: bool} → {id}",
        has_rules, remove),
    cmd!("routing.rule.move", "Move Routing Rule", [], None,
        "{id: *hex, place_before?: *hex (left out: last), force?: bool} → {id, position}",
        has_rules, move_rule),
    cmd!(query "routing.rule.list", "Routing Rules", ["Routing", "Rules"], None,
        "{} → [{id, position, flags (X disabled), src_address, dst_address, interface, routing_mark, action, table (null: the action has none), min_prefix, family (ipv4 | ipv6 | both), priority (kernel priority), disabled, comment, summary, notices: [{level, text, id, args}]}]",
        always, list),
    cmd!(query "routing.rule.preview", "Check Routing Rule", [], None,
        "{id?: *hex (the rule being edited), src_address?: string, dst_address?: string, interface?: string, routing_mark?: string, action?: string, table?: string, min_prefix?: u32 | string, disabled?: bool | yes | no, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}], risk} (form texts accepted; never an error: bad input is a check)",
        always, preview),
    cmd!(query "routing.rule.kernel", "Kernel Rule List", [], None,
        "{} → {available, reason, rules: [{priority, family, src, dst, iif, fwmark, action, table, owner (kernel | corerouter | foreign), rule (the id of the routing rule; null), what}], marks_without_table: [string], drift: [string]}",
        always, kernel),
];

fn has_rules(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.rules.is_empty() {
        Err("there are no routing rules".into())
    } else {
        Ok(())
    }
}

/// A key `set` may clear: absent, null or "" to clear, or a value.
enum Field<T> {
    Keep,
    Clear,
    Set(T),
}

fn field<T>(p: &Value, key: &str, parse: impl Fn(&str) -> Result<T>) -> Result<Field<T>> {
    match p.get(key) {
        None => Ok(Field::Keep),
        Some(Value::Null) => Ok(Field::Clear),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(Field::Clear),
        Some(Value::String(s)) => parse(s).map(Field::Set),
        Some(_) => Err(EngineError::bad(key, "must be a string or null")),
    }
}

fn net(key: &'static str) -> impl Fn(&str) -> Result<IpNet> {
    move |s| {
        let n = parse_destination(s).map_err(|e| EngineError::bad(key, e.to_string()))?;
        if n != n.trunc() {
            return Err(EngineError::bad(
                key,
                format!("{n} has host bits set; did you mean {}?", n.trunc()),
            ));
        }
        Ok(n)
    }
}

fn parsed<T: std::str::FromStr>(key: &'static str) -> impl Fn(&str) -> Result<T>
where
    T::Err: std::fmt::Display,
{
    move |s| {
        s.trim()
            .parse::<T>()
            .map_err(|e| EngineError::bad(key, e.to_string()))
    }
}

fn opt_action(p: &Value) -> Result<Option<RuleAction>> {
    super::args::opt_str(p, "action")?
        .map(|s| {
            RuleAction::parse(s).ok_or_else(|| {
                EngineError::bad(
                    "action",
                    "must be lookup, lookup-only-in-table, drop or unreachable",
                )
            })
        })
        .transpose()
}

fn min_prefix(p: &Value) -> Result<Option<u8>> {
    opt_u32(p, "min_prefix")?
        .map(|v| {
            u8::try_from(v)
                .ok()
                .filter(|v| *v <= 128)
                .ok_or_else(|| EngineError::bad("min_prefix", "must be 0..=128"))
        })
        .transpose()
}

/// What `add` and `set` read, applied to `r`.
fn fill(r: &mut RoutingRule, p: &Value) -> Result<()> {
    let keep = |slot: &mut Option<_>, f| match f {
        Field::Keep => {}
        Field::Clear => *slot = None,
        Field::Set(v) => *slot = Some(v),
    };
    keep(&mut r.src_address, field(p, "src_address", net("src_address"))?);
    keep(&mut r.dst_address, field(p, "dst_address", net("dst_address"))?);
    match field::<IfName>(p, "interface", parsed("interface"))? {
        Field::Keep => {}
        Field::Clear => r.interface = None,
        Field::Set(v) => r.interface = Some(v),
    }
    match field::<Name>(p, "routing_mark", parsed("routing_mark"))? {
        Field::Keep => {}
        Field::Clear => r.routing_mark = None,
        Field::Set(v) => r.routing_mark = Some(v),
    }
    if let Some(a) = opt_action(p)? {
        r.action = a;
    }
    if let Some(t) = opt_parse::<RoutingTable>(p, "table")? {
        r.table = t;
    }
    match p.get("min_prefix") {
        None => {}
        Some(Value::Null) => r.min_prefix = None,
        Some(_) => r.min_prefix = min_prefix(p)?,
    }
    if let Some(d) = opt_bool(p, "disabled")? {
        r.disabled = d;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        r.comment = c;
    }
    Ok(())
}

fn check_rule(cfg: &Config, r: &RoutingRule) -> Result<()> {
    match rule_issues(cfg, r).into_iter().next() {
        Some((field, why)) => Err(EngineError::bad(field, why)),
        None => Ok(()),
    }
}

/// The position of rule `id` under key `key`.
fn position(cfg: &Config, id: ItemId, key: &str) -> Result<usize> {
    cfg.routing
        .rules
        .iter()
        .position(|r| r.id == id)
        .ok_or_else(|| EngineError::bad(key, format!("no routing rule {id} (see routing.rule.list)")))
}

fn blank_rule() -> RoutingRule {
    RoutingRule {
        id: ItemId(0),
        src_address: None,
        dst_address: None,
        interface: None,
        routing_mark: None,
        action: RuleAction::default(),
        table: RoutingTable::Main,
        min_prefix: None,
        disabled: false,
        comment: String::new(),
    }
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let before: Option<ItemId> = opt_parse(p, "place_before")?;
    let mut rule = blank_rule();
    fill(&mut rule, p)?;
    let cfg = s.store_mut().candidate_mut();
    check_rule(cfg, &rule)?;
    if cfg.routing.rules.len() >= MAX_RULES {
        return Err(EngineError::bad(
            "action",
            format!("at most {MAX_RULES} rules: the kernel walks them one by one per packet"),
        ));
    }
    let at = match before {
        Some(b) => position(cfg, b, "place_before")?,
        None => cfg.routing.rules.len(),
    };
    cfg.routing.next_rule_id = cfg.routing.next_rule_id.saturating_add(1);
    rule.id = ItemId(cfg.routing.next_rule_id);
    let text = summary(&rule);
    let id = rule.id;
    cfg.routing.rules.insert(at, rule);
    let mut out = json!({ "id": id, "summary": text });
    if cfg.routing.rules.len() >= COST_NOTICE
        && let Some(o) = out.as_object_mut()
    {
        o.insert(
            "notice".to_owned(),
            json!(cost_notice(cfg.routing.rules.len())),
        );
    }
    Ok(out)
}

/// From here on the walk per packet costs more than the rest of forwarding
/// (`docs/policy-routing.md`: 100 rules cut one core to about 40% or less of
/// the rate without rules, **medido** on a loaded machine).
pub(crate) const COST_NOTICE: usize = 100;

pub(crate) fn cost_notice(n: usize) -> String {
    format!(
        "{n} rules: the kernel walks them one by one for every packet (about 15 to 30 ns each). Many \
         sources going to one table cost far less as one firewall address list and one mangle \
         mark-routing rule, which look up in a hash"
    )
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let id: ItemId = req_parse(p, "id")?;
    let cfg = s.store_mut().candidate_mut();
    let pos = position(cfg, id, "id")?;
    let mut rule = cfg
        .routing
        .rules
        .get(pos)
        .cloned()
        .ok_or_else(|| EngineError::bad("id", format!("no routing rule {id}")))?;
    fill(&mut rule, p)?;
    check_rule(cfg, &rule)?;
    let text = summary(&rule);
    if let Some(slot) = cfg.routing.rules.get_mut(pos) {
        *slot = rule;
    }
    Ok(json!({ "id": id, "summary": text }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let id: ItemId = req_parse(p, "id")?;
    let cfg = s.store_mut().candidate_mut();
    let pos = position(cfg, id, "id")?;
    cfg.routing.rules.remove(pos);
    Ok(json!({ "id": id }))
}

fn move_rule(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let id: ItemId = req_parse(p, "id")?;
    let dest: Option<ItemId> = opt_parse(p, "place_before")?;
    let cfg = s.store_mut().candidate_mut();
    let from = position(cfg, id, "id")?;
    if dest == Some(id) {
        return Ok(json!({ "id": id, "position": from }));
    }
    if let Some(d) = dest {
        position(cfg, d, "place_before")?;
    }
    let rule = cfg.routing.rules.remove(from);
    let to = match dest {
        Some(d) => position(cfg, d, "place_before")?,
        None => cfg.routing.rules.len(),
    };
    cfg.routing.rules.insert(to, rule);
    Ok(json!({ "id": id, "position": to }))
}

/// Some active route of `r`'s family in its table.
fn table_has_route(cfg: &Config, r: &RoutingRule) -> bool {
    let probe = |ip: IpAddr| {
        route_out(cfg, ip, &r.table).is_some()
    };
    let wide = cfg.ip.routes.iter().any(|e| {
        e.routing_table == r.table
            && !e.disabled
            && r.same_family(e.dst_address.addr())
            && matches!(
                route::reach(cfg, e),
                route::Reach::Active { .. } | route::Reach::Discard(_)
            )
    });
    wide || cfg
        .ip
        .addresses
        .iter()
        .filter(|a| !a.disabled && r.same_family(a.address.addr()))
        .any(|a| probe(a.address.addr()))
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    let has_route = |r: &RoutingRule| table_has_route(cfg, r);
    let rows: Vec<Value> = cfg
        .routing
        .rules
        .iter()
        .enumerate()
        .map(|(pos, r)| {
            json!({
                "id": r.id,
                "position": pos,
                "flags": if r.disabled { "X" } else { "" },
                "src_address": r.src_address.map(|n| n.to_string()),
                "dst_address": r.dst_address.map(|n| n.to_string()),
                "interface": r.interface,
                "routing_mark": r.routing_mark.as_ref().map(Name::as_str),
                "action": r.action.as_str(),
                "table": r.action.looks_up().then(|| r.table.to_string()),
                "min_prefix": r.min_prefix,
                "family": match r.is_v6() {
                    Some(true) => "ipv6",
                    Some(false) => "ipv4",
                    None => "both",
                },
                "priority": rule_pref(pos),
                "disabled": r.disabled,
                "comment": r.comment,
                "summary": summary(r),
                "notices": notices(cfg, pos, &has_route),
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

/// The form's texts as `add`/`set` parameters: empty leaves a field out when
/// adding and clears it when editing.
fn form_params(raw: &Value, editing: bool) -> Value {
    let mut p = serde_json::Map::new();
    for key in ["src_address", "dst_address", "interface", "routing_mark", "action", "table", "comment"] {
        match raw.get(key).and_then(Value::as_str).map(str::trim) {
            Some("") if key == "comment" && editing => {
                p.insert(key.into(), json!(""));
            }
            Some("") if editing && !matches!(key, "action" | "table") => {
                p.insert(key.into(), Value::Null);
            }
            Some("") | None => {}
            Some(v) => {
                p.insert(key.into(), json!(v));
            }
        }
    }
    match raw.get("min_prefix") {
        Some(Value::String(t)) if t.trim().is_empty() => {
            if editing {
                p.insert("min_prefix".into(), Value::Null);
            }
        }
        Some(Value::String(t)) => {
            let v = t.trim().parse::<u32>().map_or_else(|_| json!(t), |n| json!(n));
            p.insert("min_prefix".into(), v);
        }
        Some(v @ Value::Number(_)) => {
            p.insert("min_prefix".into(), v.clone());
        }
        _ => {}
    }
    let disabled = match raw.get("disabled") {
        Some(Value::Bool(b)) => Some(*b),
        Some(Value::String(t)) => Some(t == "yes" || t == "true"),
        _ => None,
    };
    if let Some(d) = disabled.filter(|d| *d || editing) {
        p.insert("disabled".into(), json!(d));
    }
    if let Some(id) = raw.get("id").filter(|_| editing) {
        p.insert("id".into(), id.clone());
    }
    Value::Object(p)
}

fn preview(s: &mut Session, raw: &Value) -> Result<Value> {
    let editing = raw.get("id").is_some_and(|i| !i.is_null());
    let p = form_params(raw, editing);
    let check = |level: &str, check: &str, message: String, param: &str| {
        json!({"level": level, "check": check, "message": message, "param": param})
    };
    let mut checks = Vec::new();
    let mut computed = Vec::new();
    let mut commands = Vec::new();
    let mut risk = None;
    let mut next = s.store().candidate().clone();
    let fail = |e: EngineError, checks: &mut Vec<Value>| match e {
        EngineError::BadParam { param, reason } => {
            checks.push(check("error", "param", reason, &param));
        }
        e => checks.push(check("error", "param", e.to_string(), "")),
    };
    let base = if editing {
        let id: Option<ItemId> = opt_parse(&p, "id").unwrap_or(None);
        id.and_then(|id| next.routing.rules.iter().position(|r| r.id == id))
            .and_then(|pos| next.routing.rules.get(pos).cloned().map(|r| (pos, r)))
    } else {
        let at = next.routing.rules.len();
        Some((at, blank_rule()))
    };
    match base {
        None => checks.push(check("error", "param", "no such rule".to_owned(), "id")),
        Some((pos, mut rule)) => match fill(&mut rule, &p).and_then(|()| check_rule(&next, &rule)) {
            Err(e) => fail(e, &mut checks),
            Ok(()) => {
                if editing {
                    if let Some(slot) = next.routing.rules.get_mut(pos) {
                        *slot = rule.clone();
                    }
                } else {
                    next.routing.rules.insert(pos, rule.clone());
                }
                let family = match rule.is_v6() {
                    Some(true) => "IPv6",
                    Some(false) => "IPv4",
                    None => "IPv4 and IPv6",
                };
                computed.push(json!({"label": "Family", "value": family}));
                computed.push(json!({"label": "Kernel priority", "value": rule_pref(pos).to_string()}));
                computed.push(json!({"label": "Summary", "value": summary(&rule)}));
                let cfg = &next;
                let has_route = |r: &RoutingRule| table_has_route(cfg, r);
                for n in notices(cfg, pos, &has_route) {
                    let text = n.get("text").and_then(Value::as_str).unwrap_or_default().to_owned();
                    checks.push(check("warning", "effect", text, ""));
                }
                if next.routing.rules.len() >= COST_NOTICE {
                    checks.push(check("warning", "cost", cost_notice(next.routing.rules.len()), ""));
                }
                let command = if editing { "routing.rule.set" } else { "routing.rule.add" };
                commands.push(json!({"command": command, "params": p}));
                risk = super::ip_address::access_risk(s, &next);
                if risk.is_none() && s.in_safe_mode() {
                    checks.push(check("info", "access", "Safe Mode is on: a change that cuts this session is undone".to_owned(), ""));
                }
            }
        },
    }
    Ok(json!({"computed": computed, "checks": checks, "commands": commands, "risk": risk}))
}

fn row(cfg: &Config, k: &KernelRuleRow) -> Value {
    let r: &KernelRule = &k.rule;
    let (action, table) = action_json(r.action, cfg);
    let (rule, what) = match k.owner {
        RuleOwner::Corerouter => crate::policy_rule::describe_pref(cfg, r.pref),
        RuleOwner::Kernel => (None, "the kernel's own".to_owned()),
        RuleOwner::Foreign => (
            None,
            format!(
                "not CoreRouter's (protocol {}): left alone; it can change what the rules decide",
                k.protocol
            ),
        ),
    };
    json!({
        "priority": r.pref,
        "family": if r.v6 { "ipv6" } else { "ipv4" },
        "src": r.src.map(|n| n.to_string()),
        "dst": r.dst.map(|n| n.to_string()),
        "iif": r.iif,
        "fwmark": r.mark.map(|m| format!("{m:#x}")),
        "l3mdev": r.l3mdev,
        "action": action,
        "table": table,
        "owner": k.owner,
        "rule": rule,
        "what": what,
    })
}

fn kernel(s: &mut Session, _: &Value) -> Result<Value> {
    let cfg = s.store().running().clone();
    let marks: Vec<String> = mangle_marks(&cfg)
        .into_iter()
        .filter(|(_, t)| t.is_none())
        .map(|(n, _)| n.as_str().to_owned())
        .collect();
    Ok(match s.hal_mut().rule_dump() {
        Ok(rows) => {
            let want = corerouter_hal::policy::expected_rules(&cfg);
            let mine: std::collections::BTreeSet<&KernelRule> = rows
                .iter()
                .filter(|r| r.owner == RuleOwner::Corerouter)
                .map(|r| &r.rule)
                .collect();
            let drift: Vec<String> = want
                .iter()
                .filter(|r| !mine.contains(r))
                .map(|r| format!("missing: {r}"))
                .chain(
                    mine.iter()
                        .filter(|r| !want.contains(**r))
                        .map(|r| format!("extra: {r}")),
                )
                .collect();
            json!({
                "available": true,
                "reason": null,
                "rules": rows.iter().map(|r| row(&cfg, r)).collect::<Vec<_>>(),
                "marks_without_table": marks,
                "drift": drift,
            })
        }
        Err(e) => json!({
            "available": false,
            "reason": e.to_string(),
            "rules": [],
            "marks_without_table": marks,
            "drift": [],
        }),
    })
}
