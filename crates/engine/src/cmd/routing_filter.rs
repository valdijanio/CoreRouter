//! /routing filter (G3.2b): BGP route policy in the RouterOS v7 language —
//! rules in chains, prefix lists, community lists — and what makes it safe
//! to change: the preview ("which routes pass"), the commit impact ("this
//! change withdraws N prefixes announced to AS X") and the RFC 8212 status
//! (an eBGP connection without a chain gets and sends nothing).
//!
//! `proto-bgp::filter` parses, evaluates and renders; the commit takes the
//! route-maps to FRR (only the difference). A connection names its chains
//! with `input_filter` / `output_filter` (`routing.bgp.connection.set`).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use corerouter_model::bgp::{BgpConnection, LocalRole, resolve_templates};
use corerouter_model::routing_filter::{
    CommunityList, FilterRule, MAX_COMMUNITIES, MAX_LISTS, MAX_PREFIX_ENTRIES, MAX_RULES, PrefixEntry,
    PrefixList, RoutingFilter,
};
use corerouter_model::types::ItemId;
use corerouter_model::{Config, Routing};
use corerouter_proto_bgp::filter::eval::{self, Policy, Preview, Row, Side};
use corerouter_proto_bgp::filter::parse::{self, Atom, CommArg, CommHow, Expr, SetOp, Stmt};
use corerouter_proto_bgp::filter::{Route, community_text, sample};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32, req_parse, req_str};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

/// Routes of the virtual lab's sample (no neighbor sends any there).
pub const SAMPLE_ROUTES: usize = 5_000;
/// Most routes a preview lists by kind.
pub const MAX_ROWS: usize = 500;
/// Default routes listed by kind.
pub const DEFAULT_ROWS: usize = 50;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("routing.filter.rule.add", "Add Filter Rule", ["Routing", "Filters"], None,
        "{chain: string, rule: string (RouterOS v7: if (dst in 10.0.0.0/8) { reject }), disabled?: bool, comment?: string, place_before?: *hex} → {id}",
        always, rule_add),
    cmd!("routing.filter.rule.set", "Set Filter Rule", [], None,
        "{id: *hex, chain?: string, rule?: string, disabled?: bool, comment?: string} → {id}",
        has_rules, rule_set),
    cmd!("routing.filter.rule.remove", "Remove Filter Rule", [], None,
        "{id: *hex} → {id}",
        has_rules, rule_remove),
    cmd!("routing.filter.rule.move", "Move Filter Rule", [], None,
        "{id: *hex, place_before?: *hex (absent: to the end)} → {id, position}",
        has_rules, rule_move),
    cmd!(query "routing.filter.rule.list", "Filter Rules", ["Routing", "Filters"], None,
        "{chain?: string, find?: string} → [{id, position, chain, rule, disabled, comment, error?, matchers: [string], actions: [string], verdict (accept | reject | mixed | none)}]",
        always, rule_list),
    cmd!(query "routing.filter.rule.check", "Check Filter Rule", [], None,
        "{id?: *hex (the rule being edited), chain?: string, rule?: string, disabled?: bool | yes | no, comment?: string, place_before?: *hex} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}], risk, preview?: {total, accepted, rejected, newly_rejected, newly_accepted, source}}",
        always, rule_check),
    cmd!("routing.filter.prefix-list.add", "Add Prefix List", ["Routing", "Filters"], None,
        "{name: string, entries: [string] | string (\"10.0.0.0/8 le 24\", comma or newline separated), comment?: string} → {name}",
        always, plist_add),
    cmd!("routing.filter.prefix-list.set", "Set Prefix List", [], None,
        "{id: string (the name), name?: string, entries?: [string] | string, comment?: string} → {name}",
        has_plists, plist_set),
    cmd!("routing.filter.prefix-list.remove", "Remove Prefix List", [], None,
        "{id: string (the name)} → {name}",
        has_plists, plist_remove),
    cmd!(query "routing.filter.prefix-list.list", "Prefix Lists", ["Routing", "Filters"], None,
        "{} → [{name, entries: [string], count, ipv4, ipv6, used_by: [chain], comment}]",
        always, plist_list),
    cmd!("routing.filter.community-list.add", "Add Community List", ["Routing", "Filters"], None,
        "{name: string, communities: [string] | string (65000:100, no-export, 65000:1:2), comment?: string} → {name}",
        always, clist_add),
    cmd!("routing.filter.community-list.set", "Set Community List", [], None,
        "{id: string (the name), name?: string, communities?: [string] | string, comment?: string} → {name}",
        has_clists, clist_set),
    cmd!("routing.filter.community-list.remove", "Remove Community List", [], None,
        "{id: string (the name)} → {name}",
        has_clists, clist_remove),
    cmd!(query "routing.filter.community-list.list", "Community Lists", ["Routing", "Filters"], None,
        "{} → [{name, communities: [string], normal, large, used_by: [chain], comment}]",
        always, clist_list),
    cmd!(query "routing.filter.prefix-list.check", "Check Prefix List", [], None,
        "{id?: string (the list being edited), name?: string, entries?: [string] | string, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}], risk}",
        always, plist_check),
    cmd!(query "routing.filter.community-list.check", "Check Community List", [], None,
        "{id?: string (the list being edited), name?: string, communities?: [string] | string, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}], risk}",
        always, clist_check),
    cmd!(query "routing.filter.status", "Filter Status", ["Routing", "Filters"], None,
        "{} → {chains: [{chain, rules, enabled, used_in: [connection], used_out: [connection], errors}], rfc8212: [{connection, remote_address, remote_as?, missing: [in | out], message}]}",
        always, status),
    cmd!(query "routing.filter.preview", "Filter Preview", ["Routing", "Filters"], None,
        "{chain?: string, connection?: string, direction?: in | out (default in), limit?: u32 (routes listed by kind, default 50, at most 500), threads?: u32} → {chain?, connection?, direction, source (sample | frr), pending (FRR's routes are being read: ask again), error? (why they could not be read), partial (routes read without their communities: FRR 10 shows them only for accepted routes), total, accepted, rejected, modified, compared (a policy is committed), newly_rejected, newly_accepted, attrs_changed, elapsed_us, threads, rows: [{prefix, as_path, communities, verdict (accept | reject), before? (accept | reject), change?}]} (the pending candidate against the running policy)",
        always, preview),
    cmd!(query "routing.filter.impact", "Filter Commit Impact", ["Routing", "Filters"], None,
        "{} → [{connection, remote_as?, direction (in | out), chain?, before_chain?, total, withdrawn, added, changed, source, message}] (what committing the pending changes does to each connection's routes; empty when nothing changes)",
        always, impact),
];

fn has_rules(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.filter.rules.is_empty() {
        Err("there are no filter rules (routing.filter.rule.add)".into())
    } else {
        Ok(())
    }
}

fn has_plists(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.filter.prefix_lists.is_empty() {
        Err("there are no prefix lists (routing.filter.prefix-list.add)".into())
    } else {
        Ok(())
    }
}

fn has_clists(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.filter.community_lists.is_empty() {
        Err("there are no community lists (routing.filter.community-list.add)".into())
    } else {
        Ok(())
    }
}

fn filter_mut(s: &mut Session) -> &mut RoutingFilter {
    &mut s.store_mut().candidate_mut().routing.filter
}

fn cut(s: &str) -> String {
    crate::logging::cut(s, 64).to_string()
}

// ---- rules ----

fn check_chain(key: &str, chain: &str) -> Result<()> {
    parse::check_chain(chain).map_err(|e| EngineError::bad(key, e))
}

fn check_rule(text: &str) -> Result<Vec<Stmt>> {
    parse::parse(text).map_err(|e| EngineError::bad("rule", e.to_string()))
}

fn position(f: &RoutingFilter, id: ItemId, key: &str) -> Result<usize> {
    f.rules
        .iter()
        .position(|r| r.id == id)
        .ok_or_else(|| EngineError::bad(key, format!("no filter rule {id}")))
}

/// The rule of `p` onto `r` (what `add` and `set` share).
fn apply_rule(r: &mut FilterRule, p: &Value) -> Result<()> {
    if let Some(c) = opt_str(p, "chain")? {
        check_chain("chain", c.trim())?;
        r.chain = c.trim().to_owned();
    }
    if let Some(text) = opt_str(p, "rule")? {
        check_rule(text)?;
        r.rule = text.trim().to_owned();
    }
    if let Some(d) = opt_bool(p, "disabled")? {
        r.disabled = d;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        r.comment = c;
    }
    Ok(())
}

fn add_rule(f: &mut RoutingFilter, p: &Value) -> Result<ItemId> {
    let before: Option<ItemId> = opt_parse(p, "place_before")?;
    let at = before.map(|b| position(f, b, "place_before")).transpose()?;
    if opt_str(p, "chain")?.is_none() {
        return Err(EngineError::bad("chain", "is required"));
    }
    if opt_str(p, "rule")?.is_none() {
        return Err(EngineError::bad("rule", "is required (accept, reject, if (…) { … })"));
    }
    if f.rules.len() >= MAX_RULES {
        return Err(EngineError::bad("rule", format!("at most {MAX_RULES} rules")));
    }
    let mut r = FilterRule { id: ItemId(0), chain: String::new(), rule: String::new(), disabled: false, comment: String::new() };
    apply_rule(&mut r, p)?;
    r.id = f.next_id();
    let id = r.id;
    match at {
        Some(i) => f.rules.insert(i, r),
        None => f.rules.push(r),
    }
    Ok(id)
}

fn rule_add(s: &mut Session, p: &Value) -> Result<Value> {
    let id = add_rule(filter_mut(s), p)?;
    Ok(json!({ "id": id }))
}

fn set_rule(f: &mut RoutingFilter, p: &Value) -> Result<ItemId> {
    let id: ItemId = req_parse(p, "id")?;
    let i = position(f, id, "id")?;
    let Some(r) = f.rules.get_mut(i) else {
        return Err(EngineError::bad("id", format!("no filter rule {id}")));
    };
    apply_rule(r, p)?;
    Ok(id)
}

fn rule_set(s: &mut Session, p: &Value) -> Result<Value> {
    let id = set_rule(filter_mut(s), p)?;
    Ok(json!({ "id": id }))
}

fn rule_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let f = filter_mut(s);
    let i = position(f, id, "id")?;
    f.rules.remove(i);
    Ok(json!({ "id": id }))
}

fn rule_move(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let before: Option<ItemId> = opt_parse(p, "place_before")?;
    let f = filter_mut(s);
    let from = position(f, id, "id")?;
    if let Some(b) = before {
        position(f, b, "place_before")?;
    }
    let r = f.rules.remove(from);
    let to = before.and_then(|b| f.rules.iter().position(|x| x.id == b)).unwrap_or(f.rules.len());
    f.rules.insert(to, r);
    Ok(json!({ "id": id, "position": to }))
}

/// What a rule tests and does, for the chips of the list.
fn summary(stmts: &[Stmt]) -> (Vec<String>, Vec<String>, &'static str) {
    fn atoms(e: &Expr, out: &mut Vec<String>) {
        match e {
            Expr::Not(x) => atoms(x, out),
            Expr::And(a, b) | Expr::Or(a, b) => {
                atoms(a, out);
                atoms(b, out);
            }
            Expr::Atom(a) => {
                let name = match a {
                    Atom::DstIn(_) | Atom::DstEq(_) | Atom::DstList(_) => "dst",
                    Atom::DstLen(..) => "dst-len",
                    Atom::Afi(_) => "afi",
                    Atom::Protocol(_) => "protocol",
                    Atom::AsPath(_) => "bgp-as-path",
                    Atom::Comm { large: false, .. } => "bgp-communities",
                    Atom::Comm { large: true, .. } => "bgp-large-communities",
                };
                if !out.iter().any(|x| x == name) {
                    out.push(name.to_owned());
                }
            }
        }
    }
    fn walk(stmts: &[Stmt], m: &mut Vec<String>, a: &mut Vec<String>, acc: &mut (bool, bool)) {
        fn push(a: &mut Vec<String>, s: String) {
            if !a.contains(&s) {
                a.push(s);
            }
        }
        for s in stmts {
            match s {
                Stmt::If { cond, then, els } => {
                    atoms(cond, m);
                    walk(then, m, a, acc);
                    walk(els, m, a, acc);
                }
                Stmt::Accept => {
                    acc.0 = true;
                    push(a, "accept".into());
                }
                Stmt::Reject => {
                    acc.1 = true;
                    push(a, "reject".into());
                }
                Stmt::Return => push(a, "return".into()),
                Stmt::Jump(c) => push(a, format!("jump {c}")),
                Stmt::Set(op) => push(
                    a,
                    match op {
                        SetOp::LocalPref(v) => format!("local-pref {v}"),
                        SetOp::Med(v) => format!("med {v}"),
                        SetOp::Prepend(n) => format!("prepend {n}"),
                        SetOp::Comm { large, how, .. } => format!(
                            "{} {}",
                            match how {
                                CommHow::Set => "set",
                                CommHow::Append => "append",
                                CommHow::Delete => "delete",
                            },
                            if *large { "large-communities" } else { "communities" }
                        ),
                    },
                ),
            }
        }
    }
    let (mut m, mut a, mut acc) = (Vec::new(), Vec::new(), (false, false));
    walk(stmts, &mut m, &mut a, &mut acc);
    let verdict = match acc {
        (true, true) => "mixed",
        (true, false) => "accept",
        (false, true) => "reject",
        (false, false) => "none",
    };
    (m, a, verdict)
}

fn rule_row(i: usize, r: &FilterRule) -> Value {
    let (matchers, actions, verdict, error) = match parse::parse(&r.rule) {
        Ok(st) => {
            let (m, a, v) = summary(&st);
            (m, a, v, None)
        }
        Err(e) => (Vec::new(), Vec::new(), "none", Some(e.to_string())),
    };
    json!({
        "id": r.id,
        "position": i,
        "chain": r.chain,
        "rule": r.rule,
        "disabled": r.disabled,
        "comment": r.comment,
        "error": error,
        "matchers": matchers,
        "actions": actions,
        "verdict": verdict,
    })
}

fn rule_list(s: &mut Session, p: &Value) -> Result<Value> {
    let chain = opt_str(p, "chain")?;
    let find = opt_text(p, "find", 128)?.map(|f| f.to_lowercase());
    let f = &s.store().candidate().routing.filter;
    let rows = f
        .rules
        .iter()
        .enumerate()
        .filter(|(_, r)| chain.is_none_or(|c| r.chain == c))
        .filter(|(_, r)| {
            find.as_ref()
                .is_none_or(|q| format!("{} {} {}", r.chain, r.rule, r.comment).to_lowercase().contains(q.as_str()))
        })
        .map(|(i, r)| rule_row(i, r))
        .collect();
    Ok(Value::Array(rows))
}

// ---- lists ----

/// A list parameter: an array, or one string split on commas and newlines.
fn items(p: &Value, key: &str, max: usize) -> Result<Option<Vec<String>>> {
    let out: Vec<String> = match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => {
            if s.len() > max * 48 {
                return Err(EngineError::bad(key, format!("at most {max} items")));
            }
            s.split([',', '\n']).map(str::trim).filter(|t| !t.is_empty()).map(str::to_owned).collect()
        }
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| v.as_str().map(|t| t.trim().to_owned()).ok_or_else(|| EngineError::bad(key, "items are strings")))
            .collect::<Result<Vec<_>>>()?,
        Some(_) => return Err(EngineError::bad(key, "a list of strings, or one comma-separated string")),
    };
    if out.len() > max {
        return Err(EngineError::bad(key, format!("at most {max} items")));
    }
    Ok(Some(out))
}

fn check_list_name(key: &str, name: &str) -> Result<()> {
    parse::check_name(name).map_err(|e| EngineError::bad(key, e))
}

fn parse_entries(list: Vec<String>) -> Result<Vec<PrefixEntry>> {
    let mut out: Vec<PrefixEntry> = Vec::with_capacity(list.len());
    for (i, t) in list.iter().enumerate() {
        let e: PrefixEntry = t.parse().map_err(|e: String| EngineError::bad("entries", format!("entry {}: {e}", i + 1)))?;
        out.push(e);
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|e| seen.insert(*e));
    Ok(out)
}

/// Who uses list `name` (`dst in NAME`, `…-list NAME`).
fn chains_using(f: &RoutingFilter, name: &str, prefix: bool) -> Vec<String> {
    fn in_expr(e: &Expr, name: &str, prefix: bool) -> bool {
        match e {
            Expr::Not(x) => in_expr(x, name, prefix),
            Expr::And(a, b) | Expr::Or(a, b) => in_expr(a, name, prefix) || in_expr(b, name, prefix),
            Expr::Atom(Atom::DstList(n)) => prefix && n == name,
            Expr::Atom(Atom::Comm { arg: CommArg::List(n), .. }) => !prefix && n == name,
            Expr::Atom(_) => false,
        }
    }
    fn in_stmts(st: &[Stmt], name: &str, prefix: bool) -> bool {
        st.iter().any(|s| match s {
            Stmt::If { cond, then, els } => in_expr(cond, name, prefix) || in_stmts(then, name, prefix) || in_stmts(els, name, prefix),
            Stmt::Set(SetOp::Comm { arg: CommArg::List(n), .. }) => !prefix && n == name,
            _ => false,
        })
    }
    let mut out: Vec<String> = Vec::new();
    for r in &f.rules {
        if let Ok(st) = parse::parse(&r.rule)
            && in_stmts(&st, name, prefix)
            && !out.contains(&r.chain)
        {
            out.push(r.chain.clone());
        }
    }
    out
}

fn plist_apply(f: &mut RoutingFilter, p: &Value, id: Option<&str>) -> Result<String> {
    let mut l = match id {
        Some(id) => f
            .prefix_lists
            .get(id)
            .cloned()
            .ok_or_else(|| EngineError::bad("id", format!("no prefix list {:?}", cut(id))))?,
        None => PrefixList { name: String::new(), entries: Vec::new(), comment: String::new() },
    };
    if let Some(n) = opt_str(p, "name")? {
        check_list_name("name", n.trim())?;
        l.name = n.trim().to_owned();
    } else if id.is_none() {
        return Err(EngineError::bad("name", "is required"));
    }
    if let Some(list) = items(p, "entries", MAX_PREFIX_ENTRIES)? {
        l.entries = parse_entries(list)?;
    } else if id.is_none() {
        return Err(EngineError::bad("entries", "is required (10.0.0.0/8 le 24, …)"));
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        l.comment = c;
    }
    let name = l.name.clone();
    if id != Some(name.as_str()) && f.prefix_lists.contains_key(&name) {
        return Err(EngineError::bad("name", format!("prefix list {name:?} already exists")));
    }
    if id.is_none() && f.prefix_lists.len() >= MAX_LISTS {
        return Err(EngineError::bad("name", format!("at most {MAX_LISTS} prefix lists")));
    }
    if let Some(old) = id.filter(|o| *o != name) {
        let users = chains_using(f, old, true);
        if !users.is_empty() {
            return Err(EngineError::bad("name", format!("prefix list {old:?} is used by chain {}: change those rules first", users.join(", "))));
        }
        f.prefix_lists.remove(old);
    }
    f.prefix_lists.insert(name.clone(), l);
    Ok(name)
}

fn plist_add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = plist_apply(filter_mut(s), p, None)?;
    Ok(json!({ "name": name }))
}

fn plist_set(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?.to_owned();
    let name = plist_apply(filter_mut(s), p, Some(&id))?;
    Ok(json!({ "name": name }))
}

fn plist_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?.to_owned();
    let f = filter_mut(s);
    if !f.prefix_lists.contains_key(&id) {
        return Err(EngineError::bad("id", format!("no prefix list {:?}", cut(&id))));
    }
    let users = chains_using(f, &id, true);
    if !users.is_empty() {
        return Err(EngineError::bad("id", format!("prefix list {id:?} is used by chain {}: change those rules first", users.join(", "))));
    }
    f.prefix_lists.remove(&id);
    Ok(json!({ "name": id }))
}

fn plist_list(s: &mut Session, _: &Value) -> Result<Value> {
    let f = &s.store().candidate().routing.filter;
    let rows = f
        .prefix_lists
        .values()
        .map(|l| {
            let v4 = l.entries.iter().filter(|e| e.prefix.max_prefix_len() == 32).count();
            json!({
                "name": l.name,
                // A long list shows its first entries; `count` says how many.
                "entries": l.entries.iter().take(1_000).map(ToString::to_string).collect::<Vec<_>>(),
                "count": l.entries.len(),
                "ipv4": v4,
                "ipv6": l.entries.len() - v4,
                "used_by": chains_using(f, &l.name, true),
                "comment": l.comment,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

fn clist_apply(f: &mut RoutingFilter, p: &Value, id: Option<&str>) -> Result<String> {
    let mut l = match id {
        Some(id) => f
            .community_lists
            .get(id)
            .cloned()
            .ok_or_else(|| EngineError::bad("id", format!("no community list {:?}", cut(id))))?,
        None => CommunityList { name: String::new(), communities: Vec::new(), comment: String::new() },
    };
    if let Some(n) = opt_str(p, "name")? {
        check_list_name("name", n.trim())?;
        l.name = n.trim().to_owned();
    } else if id.is_none() {
        return Err(EngineError::bad("name", "is required"));
    }
    if let Some(list) = items(p, "communities", MAX_COMMUNITIES)? {
        let mut out: Vec<String> = Vec::new();
        for c in list {
            // Stored as FRR writes it (well-known names, no repeats).
            let v = corerouter_proto_bgp::filter::parse_community(&c).map_err(|e| EngineError::bad("communities", e))?;
            let t = v.to_string();
            if !out.contains(&t) {
                out.push(t);
            }
        }
        l.communities = out;
    } else if id.is_none() {
        return Err(EngineError::bad("communities", "is required (65000:100, no-export, 65000:1:2)"));
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        l.comment = c;
    }
    let name = l.name.clone();
    if id != Some(name.as_str()) && f.community_lists.contains_key(&name) {
        return Err(EngineError::bad("name", format!("community list {name:?} already exists")));
    }
    if id.is_none() && f.community_lists.len() >= MAX_LISTS {
        return Err(EngineError::bad("name", format!("at most {MAX_LISTS} community lists")));
    }
    if let Some(old) = id.filter(|o| *o != name) {
        let users = chains_using(f, old, false);
        if !users.is_empty() {
            return Err(EngineError::bad("name", format!("community list {old:?} is used by chain {}: change those rules first", users.join(", "))));
        }
        f.community_lists.remove(old);
    }
    f.community_lists.insert(name.clone(), l);
    Ok(name)
}

fn clist_add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = clist_apply(filter_mut(s), p, None)?;
    Ok(json!({ "name": name }))
}

fn clist_set(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?.to_owned();
    let name = clist_apply(filter_mut(s), p, Some(&id))?;
    Ok(json!({ "name": name }))
}

fn clist_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?.to_owned();
    let f = filter_mut(s);
    if !f.community_lists.contains_key(&id) {
        return Err(EngineError::bad("id", format!("no community list {:?}", cut(&id))));
    }
    let users = chains_using(f, &id, false);
    if !users.is_empty() {
        return Err(EngineError::bad("id", format!("community list {id:?} is used by chain {}: change those rules first", users.join(", "))));
    }
    f.community_lists.remove(&id);
    Ok(json!({ "name": id }))
}

fn clist_list(s: &mut Session, _: &Value) -> Result<Value> {
    let f = &s.store().candidate().routing.filter;
    let rows = f
        .community_lists
        .values()
        .map(|l| {
            let large = l.communities.iter().filter(|c| c.matches(':').count() == 2).count();
            json!({
                "name": l.name,
                "communities": l.communities,
                "normal": l.communities.len() - large,
                "large": large,
                "used_by": chains_using(f, &l.name, false),
                "comment": l.comment,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

// ---- status, RFC 8212 ----

/// Whether a connection is eBGP (its effective role or AS).
fn is_ebgp(routing: &Routing, c: &BgpConnection, role: Option<LocalRole>, remote_as: Option<corerouter_model::Asn>) -> bool {
    match (role, remote_as) {
        (Some(r), _) => !r.is_ibgp(),
        (None, Some(a)) => routing.bgp.get(&c.instance).is_none_or(|i| i.asn != a),
        (None, None) => true,
    }
}

/// The eBGP connections that miss a chain (RFC 8212: nothing passes that
/// way), with what to do.
pub(crate) fn rfc8212(routing: &Routing) -> Vec<Value> {
    let resolved = resolve_templates(&routing.bgp_templates);
    let mut out = Vec::new();
    for c in routing.bgp_connections.values() {
        let Ok(eff) = c.effective(&resolved) else { continue };
        if c.disabled || !is_ebgp(routing, c, eff.local_role, eff.remote_as) {
            continue;
        }
        let mut missing = Vec::new();
        if eff.input_filter.is_none() {
            missing.push("in");
        }
        if eff.output_filter.is_none() {
            missing.push("out");
        }
        if missing.is_empty() {
            continue;
        }
        let what = match missing.as_slice() {
            ["in", "out"] => "accepts no route and sends none",
            ["in"] => "accepts no route",
            _ => "sends no route",
        };
        let set = missing.iter().map(|d| if *d == "in" { "input_filter" } else { "output_filter" }).collect::<Vec<_>>().join(" and ");
        out.push(json!({
            "connection": c.name,
            "remote_address": c.remote_address.to_string(),
            "remote_as": eff.remote_as.map(|a| a.0),
            "missing": missing,
            "message": format!("eBGP connection {} {what} until it has a filter chain (RFC 8212): set {set}", c.name),
        }));
    }
    out
}

fn status(s: &mut Session, _: &Value) -> Result<Value> {
    let routing = &s.store().candidate().routing;
    let f = &routing.filter;
    let resolved = resolve_templates(&routing.bgp_templates);
    let (_, problems) = Policy::build(f);
    /// Rules, enabled rules, connections using it in, out.
    type Use = (usize, usize, Vec<String>, Vec<String>);
    let mut chains: BTreeMap<&str, Use> = BTreeMap::new();
    for r in &f.rules {
        let e = chains.entry(r.chain.as_str()).or_default();
        e.0 += 1;
        if !r.disabled {
            e.1 += 1;
        }
    }
    for c in routing.bgp_connections.values() {
        let Ok(eff) = c.effective(&resolved) else { continue };
        if let Some(e) = eff.input_filter.as_deref().and_then(|ch| chains.get_mut(ch)) {
            e.2.push(c.name.clone());
        }
        if let Some(e) = eff.output_filter.as_deref().and_then(|ch| chains.get_mut(ch)) {
            e.3.push(c.name.clone());
        }
    }
    let rows: Vec<Value> = chains
        .into_iter()
        .map(|(name, (rules, enabled, used_in, used_out))| {
            let errors = problems.iter().filter(|p| p.item == format!("chain {name}")).count()
                + f.rules.iter().filter(|r| r.chain == name && problems.iter().any(|p| p.item == r.id.to_string())).count();
            json!({"chain": name, "rules": rules, "enabled": enabled, "used_in": used_in, "used_out": used_out, "errors": errors})
        })
        .collect();
    Ok(json!({ "chains": rows, "rfc8212": rfc8212(routing) }))
}

// ---- preview ----

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dir {
    In,
    Out,
}

impl Dir {
    fn name(self) -> &'static str {
        match self {
            Dir::In => "in",
            Dir::Out => "out",
        }
    }
}

/// Where a preview's routes come from.
struct Routes {
    routes: Arc<Vec<Route>>,
    source: &'static str,
    pending: bool,
    /// Routes read without their communities.
    partial: usize,
    /// Why FRR's routes could not be read.
    error: Option<String>,
}

/// The routes a connection's chain sees in `dir`: the virtual lab's
/// sample (reproducible per connection), or FRR's (G3.2b, read by the
/// daemon's FRR thread outside the lock: the first ask is `pending`).
fn routes_for(s: &mut Session, c: Option<&BgpConnection>, dir: Dir) -> Routes {
    if s.has_routing()
        && let Some(c) = c
    {
        let key = crate::bgp_routes::RouteKey {
            instance: c.instance.clone(),
            neighbor: c.remote_address.to_string(),
            received: dir == Dir::In,
        };
        match s.bgp_routes(&key) {
            Some(Ok((routes, partial))) => return Routes { routes, source: "frr", pending: false, partial, error: None },
            Some(Err(e)) => return Routes { routes: Arc::new(Vec::new()), source: "frr", pending: false, partial: 0, error: Some(e) },
            None => return Routes { routes: Arc::new(Vec::new()), source: "frr", pending: true, partial: 0, error: None },
        }
    }
    let peer = c.and_then(|c| c.params.remote_as).map_or(64_500, |a| a.0);
    let seed = corerouter_proto_bgp::filter::sample_seed(c.map_or("", |c| c.name.as_str()), dir == Dir::In);
    let peer = if dir == Dir::In { peer } else { 64_496 };
    Routes { routes: Arc::new(sample::routes(SAMPLE_ROUTES, seed, peer)), source: "sample", pending: false, partial: 0, error: None }
}

fn row_json(r: &Row) -> Value {
    let comms: Vec<String> = r
        .route
        .communities
        .iter()
        .map(|c| community_text(*c))
        .chain(r.route.large.iter().map(ToString::to_string))
        .collect();
    let mut o = json!({
        "prefix": r.route.prefix.to_string(),
        "as_path": r.route.path_text(),
        "communities": comms,
        "verdict": if r.accepted { "accept" } else { "reject" },
    });
    if let Some(obj) = o.as_object_mut() {
        if let Some(b) = r.before {
            obj.insert("before".into(), json!(if b { "accept" } else { "reject" }));
        }
        if let Some(c) = &r.changed {
            obj.insert("change".into(), json!(describe_change(&r.route, c)));
        }
    }
    o
}

/// "local-pref 200, prepend 65000 65000, +65000:1".
fn describe_change(a: &Route, b: &Route) -> String {
    let mut out = Vec::new();
    if a.local_pref != b.local_pref
        && let Some(v) = b.local_pref
    {
        out.push(format!("local-pref {v}"));
    }
    if a.med != b.med
        && let Some(v) = b.med
    {
        out.push(format!("med {v}"));
    }
    if b.as_path.len() > a.as_path.len() {
        let added: Vec<String> = b.as_path.iter().take(b.as_path.len() - a.as_path.len()).map(ToString::to_string).collect();
        out.push(format!("prepend {}", added.join(" ")));
    }
    for c in &b.communities {
        if !a.communities.contains(c) {
            out.push(format!("+{}", community_text(*c)));
        }
    }
    for c in &a.communities {
        if !b.communities.contains(c) {
            out.push(format!("-{}", community_text(*c)));
        }
    }
    for c in &b.large {
        if !a.large.contains(c) {
            out.push(format!("+{c}"));
        }
    }
    for c in &a.large {
        if !b.large.contains(c) {
            out.push(format!("-{c}"));
        }
    }
    out.join(", ")
}

/// What chain the connection runs in `dir` under `cfg`, and whether it is
/// eBGP; `None` when the connection does not resolve.
fn chain_of(cfg: &Config, name: &str, dir: Dir) -> Option<(Option<String>, bool, BgpConnection, u32)> {
    let routing = &cfg.routing;
    let c = routing.bgp_connections.get(name)?;
    let resolved = resolve_templates(&routing.bgp_templates);
    let eff = c.effective(&resolved).ok()?;
    let ebgp = is_ebgp(routing, c, eff.local_role, eff.remote_as);
    let asn = routing.bgp.get(&c.instance).map_or(0, |i| i.asn.0);
    let chain = match dir {
        Dir::In => eff.input_filter,
        Dir::Out => eff.output_filter,
    };
    let mut c = c.clone();
    c.params.remote_as = eff.remote_as;
    Some((chain, ebgp, c, asn))
}

fn opt_dir(p: &Value) -> Result<Dir> {
    match opt_str(p, "direction")? {
        None | Some("in") => Ok(Dir::In),
        Some("out") => Ok(Dir::Out),
        Some(o) => Err(EngineError::bad("direction", format!("{:?}: in or out", cut(o)))),
    }
}

fn preview(s: &mut Session, p: &Value) -> Result<Value> {
    let dir = opt_dir(p)?;
    let limit = opt_u32(p, "limit")?.map_or(DEFAULT_ROWS, |l| (l as usize).min(MAX_ROWS));
    let chain_param = opt_str(p, "chain")?.map(str::to_owned);
    let conn_name = opt_str(p, "connection")?.map(str::to_owned);
    if chain_param.is_none() && conn_name.is_none() {
        return Err(EngineError::bad("chain", "give a chain or a connection"));
    }
    let cand = s.store().candidate().clone();
    let running = s.store().running().clone();
    let (new_chain, old_chain, ebgp, conn, asn) = match &conn_name {
        Some(n) => {
            let (ch, ebgp, c, asn) = chain_of(&cand, n, dir)
                .ok_or_else(|| EngineError::bad("connection", format!("no BGP connection {:?} (or its templates do not resolve)", cut(n))))?;
            let old = chain_of(&running, n, dir).and_then(|x| x.0);
            let ch = chain_param.clone().or(ch);
            (ch.clone(), if chain_param.is_some() { ch } else { old }, ebgp, Some(c), asn)
        }
        None => {
            let asn = cand.routing.bgp.values().next().map_or(0, |i| i.asn.0);
            (chain_param.clone(), chain_param.clone(), true, None, asn)
        }
    };
    if let Some(ch) = &new_chain {
        check_chain("chain", ch)?;
    }
    let (new_policy, _) = Policy::build(&cand.routing.filter);
    let (old_policy, _) = Policy::build(&running.routing.filter);
    if let (Some(ch), None) = (&new_chain, conn_name.as_ref())
        && new_policy.chain(ch).is_none()
    {
        let names: Vec<&str> = new_policy.chain_names().collect();
        return Err(EngineError::bad("chain", format!("chain {ch:?} has no rules{}", parse::did_you_mean(ch, &names))));
    }
    let side = |pol: &'_ Policy, ch: &Option<String>| -> (Option<usize>, bool) {
        match ch {
            Some(c) => (pol.chain(c), false),
            // No chain: iBGP passes everything, eBGP nothing (RFC 8212).
            None => (None, !ebgp),
        }
    };
    let (nc, n_without) = side(&new_policy, &new_chain);
    let (oc, o_without) = side(&old_policy, &old_chain);
    let new_side = Side { policy: &new_policy, chain: nc, accept_without: n_without, asn };
    let compared = old_chain.as_ref().is_some_and(|c| old_policy.chain(c).is_some()) || conn_name.is_some();
    let old_side = Side { policy: &old_policy, chain: oc, accept_without: o_without, asn };
    let src = routes_for(s, conn.as_ref(), dir);
    let threads = opt_u32(p, "threads")?.map_or_else(|| eval::threads_for(src.routes.len()), |t| t.clamp(1, 64) as usize);
    let t0 = Instant::now();
    let pv: Preview = eval::preview(&new_side, compared.then_some(&old_side), &src.routes, limit, threads);
    let elapsed = t0.elapsed().as_micros();
    let rows: Vec<Value> = pv.changes.iter().chain(&pv.rejected_rows).chain(&pv.accepted_rows).map(row_json).collect();
    Ok(json!({
        "chain": new_chain,
        "connection": conn_name,
        "direction": dir.name(),
        "source": src.source,
        "pending": src.pending,
        "total": pv.total,
        "accepted": pv.accepted,
        "rejected": pv.rejected,
        "modified": pv.modified,
        "compared": compared,
        "newly_rejected": pv.newly_rejected,
        "newly_accepted": pv.newly_accepted,
        "attrs_changed": pv.attrs_changed,
        "elapsed_us": u64::try_from(elapsed).unwrap_or(u64::MAX),
        "threads": threads,
        "partial": src.partial,
        "error": src.error,
        "rows": rows,
    }))
}

/// What committing the candidate does to every connection's routes, by
/// direction: the policy in force against the pending one, on the same
/// routes. Only connections whose chain or filter changed are run.
pub(crate) fn impact_rows(s: &mut Session) -> Vec<Value> {
    let cand = s.store().candidate().clone();
    let running = s.store().running().clone();
    let filter_changed = cand.routing.filter != running.routing.filter;
    let (new_policy, _) = Policy::build(&cand.routing.filter);
    let (old_policy, _) = Policy::build(&running.routing.filter);
    let mut out = Vec::new();
    let names: Vec<String> = cand.routing.bgp_connections.keys().cloned().collect();
    for name in names {
        for dir in [Dir::In, Dir::Out] {
            let Some((nch, ebgp, conn, asn)) = chain_of(&cand, &name, dir) else { continue };
            let Some((och, _, _, _)) = chain_of(&running, &name, dir) else { continue };
            if !filter_changed && nch == och {
                continue;
            }
            if conn.disabled {
                continue;
            }
            let new_side = Side { policy: &new_policy, chain: nch.as_deref().and_then(|c| new_policy.chain(c)), accept_without: nch.is_none() && !ebgp, asn };
            let old_side = Side { policy: &old_policy, chain: och.as_deref().and_then(|c| old_policy.chain(c)), accept_without: och.is_none() && !ebgp, asn };
            let src = routes_for(s, Some(&conn), dir);
            let pv = eval::preview(&new_side, Some(&old_side), &src.routes, 0, eval::threads_for(src.routes.len()));
            if pv.newly_rejected == 0 && pv.newly_accepted == 0 && pv.attrs_changed == 0 && !src.pending {
                continue;
            }
            let peer = conn.params.remote_as.map_or_else(|| conn.remote_address.to_string(), |a| format!("AS {a}"));
            let message = if src.pending {
                format!("{name}: reading the routes from FRR to measure the impact")
            } else {
                let (verb_out, verb_in, prep) = match dir {
                    Dir::Out => ("withdraws", "announces", "to"),
                    Dir::In => ("rejects", "accepts", "from"),
                };
                let mut parts = Vec::new();
                if pv.newly_rejected > 0 {
                    parts.push(format!("{verb_out} {} prefixes {} {prep} {peer}", pv.newly_rejected, if dir == Dir::Out { "announced" } else { "received" }));
                }
                if pv.newly_accepted > 0 {
                    parts.push(format!("{verb_in} {} new prefixes {prep} {peer}", pv.newly_accepted));
                }
                if pv.attrs_changed > 0 {
                    parts.push(format!("changes the attributes of {}", pv.attrs_changed));
                }
                format!("this change {} (connection {name}, {} of {} routes{})", parts.join("; "), dir.name(), pv.total, if src.source == "sample" { ", virtual lab sample" } else { "" })
            };
            out.push(json!({
                "connection": name,
                "remote_as": conn.params.remote_as.map(|a| a.0),
                "direction": dir.name(),
                "chain": nch,
                "before_chain": och,
                "total": pv.total,
                "withdrawn": pv.newly_rejected,
                "added": pv.newly_accepted,
                "changed": pv.attrs_changed,
                "source": src.source,
                "pending": src.pending,
                "message": message,
            }));
        }
    }
    out
}

fn impact(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(Value::Array(impact_rows(s)))
}

// ---- the modal ----

/// The modal's preview of a list: the change on a copy, its entries
/// counted, its users named; bad input is a check, never an error.
fn list_check(s: &mut Session, raw: &Value, prefix: bool) -> Result<Value> {
    let check = |level: &str, check: &str, message: String, param: &str| {
        json!({"level": level, "check": check, "message": message, "param": param})
    };
    let id = opt_str(raw, "id").ok().flatten().filter(|i| !i.is_empty()).map(str::to_owned);
    let mut p = raw.clone();
    if let Some(o) = p.as_object_mut() {
        if id.is_none() {
            o.remove("id");
        }
        if id.is_some() && o.get("name").and_then(Value::as_str) == id.as_deref() {
            o.remove("name");
        }
    }
    let mut cfg: Config = s.store().candidate().clone();
    let f = &mut cfg.routing.filter;
    let applied = if prefix { plist_apply(f, &p, id.as_deref()) } else { clist_apply(f, &p, id.as_deref()) };
    let mut computed = Vec::new();
    let mut checks = Vec::new();
    match applied {
        Err(e) => {
            let (param, msg) = match &e {
                EngineError::BadParam { param, reason } => (param.clone(), reason.clone()),
                other => (String::new(), other.to_string()),
            };
            checks.push(check("error", "params", msg, &param));
        }
        Ok(name) => {
            if prefix && let Some(l) = cfg.routing.filter.prefix_lists.get(&name) {
                let v4 = l.entries.iter().filter(|e| e.prefix.max_prefix_len() == 32).count();
                computed.push(json!({"label": "Entries", "value": format!("{} ({v4} IPv4, {} IPv6)", l.entries.len(), l.entries.len() - v4)}));
                if l.entries.is_empty() {
                    checks.push(check("warning", "empty", "an empty list matches nothing".into(), "entries"));
                }
            }
            if !prefix && let Some(l) = cfg.routing.filter.community_lists.get(&name) {
                let large = l.communities.iter().filter(|c| c.matches(':').count() == 2).count();
                computed.push(json!({"label": "Communities", "value": format!("{} normal, {large} large", l.communities.len() - large)}));
            }
            let users = chains_using(&cfg.routing.filter, &name, prefix);
            if !users.is_empty() {
                computed.push(json!({"label": "Used By", "value": users.join(", ")}));
            }
            let what = if prefix { "prefix_lists" } else { "community_lists" };
            for issue in corerouter_proto_bgp::validate(&cfg) {
                if issue.path.starts_with(&format!("routing.filter.{what}.{name}")) {
                    checks.push(check("error", "validate", issue.message.clone(), if prefix { "entries" } else { "communities" }));
                }
            }
        }
    }
    let ok = !checks.iter().any(|c| c.get("level").and_then(Value::as_str) == Some("error"));
    let kind = if prefix { "prefix-list" } else { "community-list" };
    let command = if id.is_some() { format!("routing.filter.{kind}.set") } else { format!("routing.filter.{kind}.add") };
    Ok(json!({
        "computed": computed,
        "checks": checks,
        "commands": if ok { vec![json!({"command": command, "params": p})] } else { Vec::new() },
        "risk": null,
    }))
}

fn plist_check(s: &mut Session, p: &Value) -> Result<Value> {
    list_check(s, p, true)
}

fn clist_check(s: &mut Session, p: &Value) -> Result<Value> {
    list_check(s, p, false)
}

fn rule_check(s: &mut Session, raw: &Value) -> Result<Value> {
    let check = |level: &str, check: &str, message: String, param: &str| {
        json!({"level": level, "check": check, "message": message, "param": param})
    };
    let mut checks: Vec<Value> = Vec::new();
    let mut computed: Vec<Value> = Vec::new();
    let id = opt_str(raw, "id").ok().flatten().map(str::to_owned);
    // Form texts: yes/no for disabled, empty fields left out.
    let mut p = raw.clone();
    if let Some(o) = p.as_object_mut() {
        if let Some(d) = o.get("disabled").and_then(Value::as_str) {
            let b = d == "yes" || d == "true";
            o.insert("disabled".into(), json!(b));
        }
        o.retain(|k, v| !(v.as_str() == Some("") && k != "comment" && k != "rule"));
        if id.is_none() {
            o.remove("id");
        }
    }
    let mut cfg: Config = s.store().candidate().clone();
    let applied = match &id {
        Some(_) => set_rule(&mut cfg.routing.filter, &p),
        None => add_rule(&mut cfg.routing.filter, &p),
    };
    let rid = match applied {
        Ok(r) => r,
        Err(e) => {
            let (param, msg) = match &e {
                EngineError::BadParam { param, reason } => (param.clone(), reason.clone()),
                other => (String::new(), other.to_string()),
            };
            checks.push(check("error", "params", msg, &param));
            return Ok(json!({"computed": computed, "checks": checks, "commands": [], "risk": null}));
        }
    };
    let rule = cfg.routing.filter.rules.iter().find(|r| r.id == rid).cloned();
    if let Some(r) = &rule
        && let Ok(st) = parse::parse(&r.rule)
    {
        let (m, a, v) = summary(&st);
        if !m.is_empty() {
            computed.push(json!({"label": "Matches", "value": m.join(", ")}));
        }
        computed.push(json!({"label": "Actions", "value": a.join(", ")}));
        // A rule after one that always ends the chain never runs.
        let before = cfg.routing.filter.rules.iter().take_while(|x| x.id != r.id).filter(|x| x.chain == r.chain && !x.disabled);
        if let Some(blocker) = before.filter(|x| parse::parse(&x.rule).is_ok_and(|st| st.iter().any(|s| matches!(s, Stmt::Accept | Stmt::Reject)))).last() {
            checks.push(check(
                "warning",
                "unreachable",
                format!("rule {} before it always accepts or rejects: this rule never runs (move it up, or use place_before)", blocker.id),
                "rule",
            ));
        }
        if v == "none" {
            checks.push(check(
                "info",
                "fallthrough",
                "this rule neither accepts nor rejects: routes go on to the next rule (and are rejected at the end of the chain)".into(),
                "rule",
            ));
        }
    }
    for issue in corerouter_proto_bgp::validate(&cfg) {
        if issue.path.starts_with("routing.filter") {
            let mine = issue.path.ends_with(&rid.to_string()) || rule.as_ref().is_some_and(|r| issue.path.ends_with(&format!("chain {}", r.chain)));
            if mine {
                checks.push(check("error", "validate", issue.message.clone(), "rule"));
            }
        }
    }
    let mut preview_v = Value::Null;
    if let Some(r) = &rule {
        // The chain on the sample (or FRR's routes of a connection that
        // uses it), against the chain in force.
        let (new_policy, _) = Policy::build(&cfg.routing.filter);
        let (old_policy, _) = Policy::build(&s.store().running().routing.filter);
        let user = cfg
            .routing
            .bgp_connections
            .values()
            .find(|c| c.params.input_filter.as_deref() == Some(r.chain.as_str()))
            .cloned();
        let asn = cfg.routing.bgp.values().next().map_or(0, |i| i.asn.0);
        let ns = Side { policy: &new_policy, chain: new_policy.chain(&r.chain), accept_without: false, asn };
        let oc = old_policy.chain(&r.chain);
        let os = Side { policy: &old_policy, chain: oc, accept_without: false, asn };
        let src = routes_for(s, user.as_ref(), Dir::In);
        let pv = eval::preview(&ns, oc.is_some().then_some(&os), &src.routes, 0, eval::threads_for(src.routes.len()));
        computed.push(json!({"label": "Chain passes", "value": format!("{} of {} routes ({})", pv.accepted, pv.total, src.source)}));
        if oc.is_some() && (pv.newly_rejected > 0 || pv.newly_accepted > 0) {
            checks.push(check(
                "warning",
                "impact",
                format!("chain {}: {} routes rejected that pass today, {} accepted that are rejected today", r.chain, pv.newly_rejected, pv.newly_accepted),
                "rule",
            ));
        }
        preview_v = json!({
            "total": pv.total, "accepted": pv.accepted, "rejected": pv.rejected,
            "newly_rejected": pv.newly_rejected, "newly_accepted": pv.newly_accepted, "source": src.source,
        });
    }
    let ok = !checks.iter().any(|c| c.get("level").and_then(Value::as_str) == Some("error"));
    let command = if id.is_some() { "routing.filter.rule.set" } else { "routing.filter.rule.add" };
    Ok(json!({
        "computed": computed,
        "checks": checks,
        "commands": if ok { vec![json!({"command": command, "params": p})] } else { Vec::new() },
        "risk": null,
        "preview": preview_v,
    }))
}

#[cfg(test)]
mod tests {
    use corerouter_hal::VirtualHal;

    use super::*;

    fn session() -> Session {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        s.execute("routing.bgp.instance.set", &json!({"asn": 65000, "router_id": "10.0.0.1"})).unwrap();
        s.execute(
            "routing.bgp.connection.add",
            &json!({"name": "up1", "remote_address": "192.0.2.1", "remote_as": 64500}),
        )
        .unwrap();
        s
    }

    #[test]
    fn rules_lists_and_chains_validate_and_render() {
        let mut s = session();
        s.execute("routing.filter.prefix-list.add", &json!({"name": "bogons", "entries": "10.0.0.0/8 le 32, 192.168.0.0/16 le 32, 0.0.0.0/0"})).unwrap();
        s.execute("routing.filter.community-list.add", &json!({"name": "blackhole", "communities": ["65535:666", "64500:666"]})).unwrap();
        let r1 = s.execute("routing.filter.rule.add", &json!({"chain": "up-in", "rule": "if (dst in bogons) { reject }"})).unwrap();
        s.execute("routing.filter.rule.add", &json!({"chain": "up-in", "rule": "if (bgp-communities any-list blackhole) { reject } set bgp-local-pref 150; accept"})).unwrap();
        s.execute("routing.filter.rule.add", &json!({"chain": "up-out", "rule": "set bgp-path-prepend 2; append bgp-communities 65000:10; accept"})).unwrap();
        s.execute("routing.bgp.connection.set", &json!({"id": "up1", "input_filter": "up-in", "output_filter": "up-out"})).unwrap();
        let text = corerouter_proto_bgp::render_all(&s.store().running().routing, &|_| None).unwrap();
        for want in [
            "  neighbor 192.0.2.1 route-map CR-up-in in\n",
            "  neighbor 192.0.2.1 route-map CR-up-out out\n",
            "ip prefix-list CR-L-bogons seq 5 permit 10.0.0.0/8 le 32\n",
            " set as-path prepend 65000 65000\n",
            "bgp community-list standard CR-C-",
        ] {
            assert!(text.contains(want), "{want:?}\n{text}");
        }
        // The list shows chips; a list in use cannot go.
        let rows = s.execute("routing.filter.rule.list", &json!({"chain": "up-in"})).unwrap();
        assert_eq!(rows[0]["matchers"], json!(["dst"]));
        assert_eq!(rows[0]["verdict"], "reject");
        assert_eq!(rows[1]["actions"], json!(["reject", "local-pref 150", "accept"]));
        let e = s.execute("routing.filter.prefix-list.remove", &json!({"id": "bogons"})).unwrap_err();
        assert!(e.to_string().contains("used by chain up-in"), "{e}");
        // Move puts the second rule first.
        let r2 = rows[1]["id"].as_str().unwrap().to_owned();
        s.execute("routing.filter.rule.move", &json!({"id": r2, "place_before": r1["id"]})).unwrap();
        let rows = s.execute("routing.filter.rule.list", &json!({})).unwrap();
        assert_eq!(rows[0]["id"].as_str(), Some(r2.as_str()));
    }

    #[test]
    fn bad_rules_are_refused_with_where_and_a_suggestion() {
        let mut s = session();
        let e = s.execute("routing.filter.rule.add", &json!({"chain": "in", "rule": "if (dts in 10.0.0.0/8) { reject }"})).unwrap_err();
        assert!(e.to_string().contains("column 5") && e.to_string().contains("did you mean \"dst\""), "{e}");
        let e = s.execute("routing.filter.rule.add", &json!({"chain": "bad chain", "rule": "accept"})).unwrap_err();
        assert!(e.to_string().contains("A-Za-z0-9"), "{e}");
        // Validation at commit: an unknown list, a jump nowhere, a chain
        // that does not exist; nothing changes (rollback).
        let before = s.store().running().routing.clone();
        let e = s.execute("routing.filter.rule.add", &json!({"chain": "in", "rule": "if (dst in bogon) { reject }"})).unwrap_err();
        assert!(e.to_string().contains("prefix list \"bogon\" does not exist"), "{e}");
        let e = s.execute("routing.filter.rule.add", &json!({"chain": "in", "rule": "jump nowhere"})).unwrap_err();
        assert!(e.to_string().contains("nowhere"), "{e}");
        s.execute("routing.filter.rule.add", &json!({"chain": "upstream-in", "rule": "accept"})).unwrap();
        let e = s.execute("routing.bgp.connection.set", &json!({"id": "up1", "input_filter": "upstream-im"})).unwrap_err();
        assert!(e.to_string().contains("did you mean \"upstream-in\""), "{e}");
        let e = s.execute("routing.filter.rule.add", &json!({"chain": "a", "rule": "jump b"}));
        assert!(e.is_err());
        assert_eq!(s.store().running().routing.bgp_connections, before.bgp_connections);
    }

    #[test]
    fn preview_and_impact_on_the_sample() {
        let mut s = session();
        s.execute("routing.filter.rule.add", &json!({"chain": "out", "rule": "accept"})).unwrap();
        s.execute("routing.bgp.connection.set", &json!({"id": "up1", "output_filter": "out"})).unwrap();
        // RFC 8212: no input chain yet.
        let st = s.execute("routing.filter.status", &json!({})).unwrap();
        assert_eq!(st["rfc8212"][0]["missing"], json!(["in"]));
        assert!(st["rfc8212"][0]["message"].as_str().unwrap().contains("RFC 8212"));
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        let id = s.store().candidate().routing.filter.rules[0].id.to_string();
        s.execute("routing.filter.rule.set", &json!({"id": id, "rule": "if (dst-len > 23) { reject } accept"})).unwrap();
        let pv = s.execute("routing.filter.preview", &json!({"connection": "up1", "direction": "out", "limit": 5})).unwrap();
        assert_eq!(pv["source"], "sample");
        assert_eq!(pv["total"], SAMPLE_ROUTES);
        assert!(pv["newly_rejected"].as_u64().unwrap() > 1000, "{pv}");
        assert_eq!(pv["rows"].as_array().unwrap().len(), 10);
        assert_eq!(pv["rows"][0]["before"], "accept");
        let im = s.execute("routing.filter.impact", &json!({})).unwrap();
        let out: Vec<&Value> = im.as_array().unwrap().iter().filter(|r| r["direction"] == "out").collect();
        assert_eq!(out.len(), 1, "{im}");
        let msg = out[0]["message"].as_str().unwrap();
        assert!(msg.contains("withdraws") && msg.contains("announced to AS 64500"), "{msg}");
        // The modal's check counts what the chain would pass.
        let chk = s.execute("routing.filter.rule.check", &json!({"chain": "out", "rule": "reject"})).unwrap();
        assert!(chk["commands"][0]["command"] == "routing.filter.rule.add", "{chk}");
        let chk2 = s.execute("routing.filter.rule.check", &json!({"chain": "out", "rule": "reject"})).unwrap();
        assert!(chk2["checks"].to_string().contains("never runs"), "{chk2}");
        let chk = s.execute("routing.filter.rule.check", &json!({"chain": "out", "rule": "acept"})).unwrap();
        assert!(chk["checks"][0]["message"].as_str().unwrap().contains("did you mean"), "{chk}");
        assert_eq!(chk["commands"], json!([]));
    }

    #[test]
    fn rpki_entries_go_first_in_the_input_chain() {
        let mut s = session();
        s.execute("routing.filter.rule.add", &json!({"chain": "up-in", "rule": "accept"})).unwrap();
        s.execute("routing.bgp.connection.set", &json!({"id": "up1", "input_filter": "up-in"})).unwrap();
        let text = corerouter_proto_bgp::render_all(&s.store().running().routing, &|_| None).unwrap();
        assert!(!text.contains("rpki"), "no validator, no RPKI entries:\n{text}");
        s.execute("routing.rpki.add", &json!({"name": "v1", "address": "192.0.2.50", "port": 3323})).unwrap();
        let text = corerouter_proto_bgp::render_all(&s.store().running().routing, &|_| None).unwrap();
        assert!(text.contains("route-map CR-up-in deny 1\n match rpki invalid\nexit\nroute-map CR-up-in permit 10\n"), "{text}");
        // The chain carries it: no CR-RPKI-IN on this neighbor.
        assert!(!text.contains("192.0.2.1 route-map CR-RPKI-IN"), "{text}");
    }

    #[test]
    fn rollback_restores_rules() {
        let mut s = session();
        s.execute("routing.filter.rule.add", &json!({"chain": "in", "rule": "accept"})).unwrap();
        let hist = s.execute("config.history", &json!({})).unwrap();
        let rev = hist.as_array().unwrap().iter().filter_map(|h| h["number"].as_u64()).max().unwrap() as u32;
        s.execute("routing.filter.rule.add", &json!({"chain": "in", "rule": "reject"})).unwrap();
        assert_eq!(s.store().running().routing.filter.rules.len(), 2);
        s.execute("config.rollback", &json!({"revision": rev})).unwrap();
        assert_eq!(s.store().running().routing.filter.rules.len(), 1);
    }
}
