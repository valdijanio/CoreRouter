//! Simple mode: the zone matrix (G2.1b). Zones are the interface lists plus
//! `router` (the router itself); each cell says what happens to new
//! connections from one zone to another: allow, block, or nothing (the
//! other rules decide).
//!
//! The matrix lives in the config (`ip.firewall.zones`) and generates one
//! block of filter rules, flagged `zone`, under a section header:
//! established/related accepted and invalid dropped first (per chain used),
//! then one rule per cell — `L → router` in input, `router → L` in output,
//! `L1 → L2` in forward. Every change to the matrix rewrites the whole
//! block in place (at the top of the filter table the first time).
//!
//! Hand edits of generated rules would be lost at the next rewrite, so the
//! rule commands refuse them and refuse placing a rule inside the block;
//! `ip.firewall.zone.detach` turns the block into ordinary rules (and
//! empties the matrix) for whoever wants to take over by hand.

use corerouter_firewall::rule_issues;
use corerouter_model::firewall::{
    Action, Family, FirewallRule, Matchers, Name, Neg, Table, Zone, ZoneAction, ZonePolicy,
};
use corerouter_model::{Config, ItemId};
use serde_json::{Value, json};

use super::args::{opt_str, req_parse};
use super::{CommandSpec, always};
use crate::lockout::take_force;
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "ip.firewall.zone.list", "Zones", ["IP", "Firewall"], None,
        "{} → {zones: [router | interface list], cells: [{from, to, action: allow | block}], rules: [*hex of the generated rules]}",
        always, list),
    cmd!(
        "ip.firewall.zone.set",
        "Set Zone Cell",
        [],
        None,
        "{from: router | interface list, to: router | interface list, action: allow | block | none (none clears the cell), force?: bool} → {rules: [*hex]}",
        always,
        set
    ),
    cmd!(
        "ip.firewall.zone.clear",
        "Clear Zones",
        [],
        None,
        "{force?: bool} → {removed: [*hex]}",
        has_zones,
        clear
    ),
    cmd!(
        "ip.firewall.zone.detach",
        "Detach Zone Rules",
        [],
        None,
        "{} → {rules: [*hex] (now ordinary rules; the matrix is empty)}",
        has_zones,
        detach
    ),
];

fn has_zones(s: &Session) -> std::result::Result<(), String> {
    let fw = &s.store().candidate().ip.firewall;
    if fw.zones.is_empty() && !fw.filter.iter().any(|r| r.zone) {
        Err("the zone matrix is empty".into())
    } else {
        Ok(())
    }
}

fn zone_rule_ids(cfg: &Config) -> Vec<ItemId> {
    cfg.ip
        .firewall
        .filter
        .iter()
        .filter(|r| r.zone)
        .map(|r| r.id)
        .collect()
}

fn list(s: &mut Session, _p: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    let mut zones = vec![Zone::ROUTER.to_owned()];
    zones.extend(
        cfg.interface_lists
            .lists
            .iter()
            .map(|l| l.name.to_string())
            .filter(|n| n != Zone::ROUTER),
    );
    let cells: Vec<Value> = cfg
        .ip
        .firewall
        .zones
        .iter()
        .map(|z| json!({ "from": z.from, "to": z.to, "action": z.action.name() }))
        .collect();
    Ok(json!({ "zones": zones, "cells": cells, "rules": zone_rule_ids(cfg) }))
}

fn zone_param(cfg: &Config, p: &Value, key: &str) -> Result<Zone> {
    let z: Zone = req_parse(p, key)?;
    if let Zone::List(l) = &z
        && cfg.interface_lists.get(l.as_str()).is_none()
    {
        return Err(EngineError::bad(
            key,
            format!("no interface list '{l}' (zones are router or an interface list)"),
        ));
    }
    Ok(z)
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let cfg = s.store().candidate();
    let from = zone_param(cfg, p, "from")?;
    let to = zone_param(cfg, p, "to")?;
    if from == to {
        return Err(EngineError::bad(
            "to",
            "from and to are the same zone (traffic inside one zone is not filtered here)",
        ));
    }
    let action = match opt_str(p, "action")?.map(str::trim) {
        Some("allow") => Some(ZoneAction::Allow),
        Some("block") => Some(ZoneAction::Block),
        Some("none") => None,
        _ => return Err(EngineError::bad("action", "allow, block or none")),
    };
    let cfg = s.store_mut().candidate_mut();
    let zones = &mut cfg.ip.firewall.zones;
    zones.retain(|z| !(z.from == from && z.to == to));
    if let Some(action) = action {
        if zones.len() >= corerouter_firewall::validate::MAX_ZONE_CELLS {
            return Err(EngineError::bad("from", "too many zone cells"));
        }
        zones.push(ZonePolicy { from, to, action });
        zones.sort_by(|a, b| (&a.from, &a.to).cmp(&(&b.from, &b.to)));
    }
    let rules = regenerate(cfg)?;
    Ok(json!({ "rules": rules }))
}

fn clear(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let cfg = s.store_mut().candidate_mut();
    let removed = zone_rule_ids(cfg);
    cfg.ip.firewall.zones.clear();
    regenerate(cfg)?;
    Ok(json!({ "removed": removed }))
}

fn detach(s: &mut Session, _p: &Value) -> Result<Value> {
    let cfg = s.store_mut().candidate_mut();
    let ids = zone_rule_ids(cfg);
    for r in &mut cfg.ip.firewall.filter {
        r.zone = false;
    }
    cfg.ip.firewall.zones.clear();
    Ok(json!({ "rules": ids }))
}

fn list_name(z: &Zone) -> Option<&Name> {
    match z {
        Zone::Router => None,
        Zone::List(l) => Some(l),
    }
}

fn verb(a: ZoneAction) -> &'static str {
    match a {
        ZoneAction::Allow => "permitir",
        ZoneAction::Block => "bloquear",
    }
}

/// One generated rule (its id is given when it is placed).
fn zone_rule(
    chain: &str,
    matchers: Matchers,
    action: Action,
    comment: String,
) -> Result<FirewallRule> {
    Ok(FirewallRule {
        id: ItemId(0),
        chain: chain
            .parse()
            .map_err(|e: corerouter_model::ParseError| EngineError::Internal(e.to_string()))?,
        family: Family::Both,
        matchers,
        action,
        disabled: false,
        comment,
        section: false,
        zone: true,
    })
}

fn states(text: &str) -> Result<Matchers> {
    Ok(Matchers {
        connection_state: Some(
            text.parse()
                .map_err(|e: corerouter_model::ParseError| EngineError::Internal(e.to_string()))?,
        ),
        ..Matchers::default()
    })
}

/// The rules the matrix stands for (ids not assigned yet).
fn generate(zones: &[ZonePolicy]) -> Result<Vec<FirewallRule>> {
    if zones.is_empty() {
        return Ok(Vec::new());
    }
    let chain_of = |z: &ZonePolicy| match (&z.from, &z.to) {
        (_, Zone::Router) => "input",
        (Zone::Router, _) => "output",
        _ => "forward",
    };
    let mut header = zone_rule(
        "input",
        Matchers::default(),
        Action::Accept,
        "Zonas: gerado pela matriz (IP › Firewall › Zones); edite pela matriz".to_owned(),
    )?;
    header.section = true;
    let mut out = vec![header];
    for chain in ["input", "forward", "output"] {
        let cells: Vec<&ZonePolicy> = zones.iter().filter(|z| chain_of(z) == chain).collect();
        if cells.is_empty() {
            continue;
        }
        out.push(zone_rule(
            chain,
            states("established,related")?,
            Action::Accept,
            "zonas: aceita respostas e conexões já aceitas".into(),
        )?);
        out.push(zone_rule(
            chain,
            states("invalid")?,
            Action::Drop,
            "zonas: descarta pacotes inválidos".into(),
        )?);
        for z in cells {
            let m = Matchers {
                in_interface_list: list_name(&z.from).map(|l| Neg::is(l.clone())),
                out_interface_list: list_name(&z.to).map(|l| Neg::is(l.clone())),
                ..Matchers::default()
            };
            let action = match z.action {
                ZoneAction::Allow => Action::Accept,
                ZoneAction::Block => Action::Drop,
            };
            out.push(zone_rule(
                chain,
                m,
                action,
                format!("zona {} -> {}: {}", z.from, z.to, verb(z.action)),
            )?);
        }
    }
    Ok(out)
}

/// Rewrite the zone block of the filter table from the matrix, where it
/// was (at the top the first time). Returns the new rules' ids.
pub(super) fn regenerate(cfg: &mut Config) -> Result<Vec<ItemId>> {
    let mut new = generate(&cfg.ip.firewall.zones)?;
    let fw = &mut cfg.ip.firewall;
    let at = fw.filter.iter().position(|r| r.zone);
    fw.filter.retain(|r| !r.zone);
    let at = at.unwrap_or(0).min(fw.filter.len());
    for r in &mut new {
        r.id = fw.next_rule_id();
    }
    let ids: Vec<ItemId> = new.iter().map(|r| r.id).collect();
    for r in &new {
        if let Some((field, why)) = rule_issues(cfg, Table::Filter, r).into_iter().next() {
            return Err(EngineError::bad("from", format!("{field}: {why}")));
        }
    }
    let fw = &mut cfg.ip.firewall;
    for (k, r) in new.into_iter().enumerate() {
        fw.filter.insert(at + k, r);
    }
    Ok(ids)
}
