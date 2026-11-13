//! `/routing rule` (G1.27e): validation, the words for what a rule of the
//! kernel's list is, and the lockout check. The list itself and the walk are
//! `corerouter_hal::policy`.

use std::collections::BTreeMap;
use std::net::IpAddr;

use corerouter_firewall::nft::{MarkKind, mark_value};
use corerouter_hal::policy::{
    self, FIRST_MARK_PREF, KernelRuleAction, L3MDEV_PREF, LAST_MARK_PREF, MAIN_PREF, RulePacket,
    RuleVerdict, VRF_UNREACH_PREF, expected_rules, pos_of_pref, routing_marks, wireguard_vrfs,
};
use corerouter_model::firewall::Name;
use corerouter_model::policy_rule::{MAX_RULES, RoutingRule};
use corerouter_model::route::{self, table_id};
use corerouter_model::validate::Issue;
use corerouter_model::{Config, IfName, InterfaceKind, ItemId, RoutingTable};
use serde_json::{Value, json};

use crate::lockout::{Link, best_way, local_interface, plain, route_out};

/// Why rule `r` cannot be applied, as (field, why). `Config` holds it or not
/// yet; only `r` and what it names are read.
pub(crate) fn rule_issues(cfg: &Config, r: &RoutingRule) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if let (Some(s), Some(d)) = (r.src_address, r.dst_address)
        && s.addr().is_ipv4() != d.addr().is_ipv4()
    {
        out.push((
            "dst_address",
            format!("{s} and {d} are not of the same family"),
        ));
    }
    if r.action.looks_up() && table_id(cfg, &r.table).is_none() {
        out.push((
            "table",
            format!(
                "routing table '{}' does not exist (routing.table.add, or see routing.table.list)",
                r.table
            ),
        ));
    }
    if let Some(p) = r.min_prefix {
        let max = if r.is_v6() == Some(false) { 32 } else { 128 };
        if p > max {
            out.push(("min_prefix", format!("must be 0..={max}")));
        }
        if !r.action.looks_up() {
            out.push(("min_prefix", format!("means nothing with action={}", r.action.as_str())));
        }
    }
    if let Some(i) = &r.interface
        && let Some(why) = interface_issue(cfg, i)
    {
        out.push(("interface", why));
    }
    out
}

/// A rule's `interface` is what the kernel sees as the incoming device.
fn interface_issue(cfg: &Config, i: &IfName) -> Option<String> {
    if i.as_str() == "lo" {
        return None;
    }
    let Some(iface) = cfg.interfaces.get(i) else {
        return Some(format!("no interface '{i}' (see interface.list)"));
    };
    if let Some(b) = &iface.bridge {
        return Some(format!(
            "'{i}' is a port of bridge '{b}': its packets come in through '{b}'"
        ));
    }
    if let Some(b) = &iface.bond {
        return Some(format!(
            "'{i}' is a slave of bond '{b}': its packets come in through '{b}'"
        ));
    }
    if let Some(v) = &iface.vrf {
        return Some(format!(
            "'{i}' is a member of VRF '{v}': its packets stop at the VRF's table before any \
             rule; mark them in the mangle to choose a table"
        ));
    }
    if matches!(iface.kind, InterfaceKind::Vrf { .. }) {
        return Some(format!(
            "'{i}' is a VRF: its packets stop at its table before any rule"
        ));
    }
    None
}

/// The validator's unit: what the commands enforce, for a config that did not
/// come through them, and what only the whole list shows.
pub(crate) fn checks(cfg: &Config) -> Vec<Issue> {
    let mut out = Vec::new();
    let rules = &cfg.routing.rules;
    if rules.len() > MAX_RULES {
        out.push(Issue::new(
            "routing.rules",
            format!("at most {MAX_RULES} rules"),
        ));
    }
    for r in rules {
        for (field, why) in rule_issues(cfg, r) {
            out.push(Issue::new(format!("routing.rules[{}].{field}", r.id), why));
        }
    }
    let marks = routing_marks(cfg);
    let tabled = marks.values().filter(|t| t.is_some()).count();
    let room = (LAST_MARK_PREF - FIRST_MARK_PREF + 1) as usize;
    if tabled > room {
        out.push(Issue::new(
            "ip.firewall.mangle",
            format!("at most {room} routing marks can name a table; there are {tabled}"),
        ));
    }
    // Different names, one kernel mark: a rule would take the other's
    // packets. The firewall's validator compares its own marks only.
    let mut seen: BTreeMap<u32, &Name> = BTreeMap::new();
    let socket_vrfs: Vec<&str> = wireguard_vrfs(cfg).map(|(_, v)| v.as_str()).collect();
    for n in marks.keys() {
        // A VRF a WireGuard socket names against a mangle mark (G1.31c;
        // two mangle marks are the firewall validator's).
        if let Some(other) = seen.insert(mark_value(MarkKind::Routing, n), n)
            && (socket_vrfs.contains(&other.as_str()) || socket_vrfs.contains(&n.as_str()))
        {
            out.push(Issue::new(
                "ip.firewall.mangle",
                format!("mark names '{other}' and '{n}' map to the same kernel mark; rename one"),
            ));
        }
    }
    for r in rules {
        let Some(name) = &r.routing_mark else {
            continue;
        };
        if let Some(other) = seen.insert(mark_value(MarkKind::Routing, name), name)
            && other != name
        {
            out.push(Issue::new(
                format!("routing.rules[{}].routing_mark", r.id),
                format!("mark names '{other}' and '{name}' map to the same kernel mark; rename one"),
            ));
        }
    }
    out
}

/// What each rule of the kernel's list stands for, as (rule id, the words).
pub(crate) fn describe_pref(cfg: &Config, pref: u32) -> (Option<ItemId>, String) {
    if pref >= MAIN_PREF {
        return (None, "main table".to_owned());
    }
    if let Some(r) = pos_of_pref(pref).and_then(|pos| cfg.routing.rules.get(pos)) {
        return (
            Some(r.id),
            format!("routing rule {} ({})", r.id, summary(r)),
        );
    }
    if pref == VRF_UNREACH_PREF {
        return (None, "its VRF has no route (VRFs do not fall through to main)".to_owned());
    }
    if pref == L3MDEV_PREF {
        return (None, "the table of its VRF".to_owned());
    }
    if (FIRST_MARK_PREF..=LAST_MARK_PREF).contains(&pref) {
        let name = routing_marks(cfg)
            .into_iter()
            .filter(|(_, t)| t.is_some())
            .nth((pref - FIRST_MARK_PREF) as usize)
            .map_or_else(String::new, |(n, _)| n.as_str().to_owned());
        let tunnels: Vec<&str> = wireguard_vrfs(cfg)
            .filter(|(_, v)| v.as_str() == name)
            .map(|(i, _)| i.as_str())
            .collect();
        if !tunnels.is_empty() {
            return (
                None,
                format!(
                    "routing mark '{name}': the encrypted packets of WireGuard {} (vrf={name})",
                    tunnels.join(", ")
                ),
            );
        }
        return (None, format!("routing mark '{name}' of the mangle"));
    }
    (None, format!("kernel rule {pref}"))
}

/// `src-address=… action=lookup table=x`, as RouterOS prints it.
pub(crate) fn summary(r: &RoutingRule) -> String {
    let mut out = Vec::new();
    if let Some(s) = r.src_address {
        out.push(format!("src-address={s}"));
    }
    if let Some(d) = r.dst_address {
        out.push(format!("dst-address={d}"));
    }
    if let Some(i) = &r.interface {
        out.push(format!("interface={i}"));
    }
    if let Some(m) = &r.routing_mark {
        out.push(format!("routing-mark={m}"));
    }
    out.push(format!("action={}", r.action.as_str()));
    if r.action.looks_up() {
        out.push(format!("table={}", r.table));
    }
    if let Some(p) = r.min_prefix {
        out.push(format!("min-prefix={p}"));
    }
    out.join(" ")
}

/// Why a rule is here but does nothing, one line each (empty: nothing to say).
/// `active_tables`: kernel ids with an active route of the rule's family or
/// any. Earlier rules whose action is final are compared up to `MAX_COMPARED`.
pub(crate) fn notices(cfg: &Config, pos: usize, has_route: &dyn Fn(&RoutingRule) -> bool) -> Vec<Value> {
    const MAX_COMPARED: usize = 1024;
    let mut out = Vec::new();
    let Some(r) = cfg.routing.rules.get(pos) else {
        return out;
    };
    if r.disabled {
        return out;
    }
    let earlier = cfg.routing.rules.get(..pos).unwrap_or_default();
    let hidden = earlier
        .iter()
        .take(MAX_COMPARED)
        .find(|e| !e.disabled && e.action.is_final() && r.covered_by(e));
    if let Some(e) = hidden {
        out.push(json!({
            "level": "warning",
            "text": format!("never reached: rule {} above matches all its packets and always decides", e.id),
            "id": "hidden",
            "args": {"rule": e.id.to_string()},
        }));
    }
    if r.action.looks_up() && !has_route(r) {
        let then = if r.action.is_final() {
            "matching packets are unreachable"
        } else {
            "matching packets go on to the next rule"
        };
        out.push(json!({
            "level": "warning",
            "text": format!("table '{}' has no active route: {then}", r.table),
            "id": "empty-table",
            "args": {"table": r.table.to_string(), "action": r.action.as_str()},
        }));
    }
    out
}

/// The rule walk of a reply to `peer` from `local`. A table decides when it
/// has any route to `peer`, a discard route (G1.5a) included: the kernel stops
/// at that too.
fn reply_walk(cfg: &Config, peer: IpAddr, local: IpAddr) -> policy::RuleWalk {
    let vrf = local_interface(cfg, local)
        .and_then(|i| i.parse::<IfName>().ok())
        .map(|i| route::table_of(cfg, &i))
        .filter(|t| route::is_vrf_table(cfg, t));
    let tables = route::tables_by_id(cfg);
    let packet = RulePacket {
        src: Some(local),
        dst: peer,
        iif: None,
        mark: 0,
        vrf: vrf.and_then(|t| table_id(cfg, &t)),
    };
    // `min-prefix` is not looked at (`best_way` does not say the prefix): a
    // route of the default length counts as the whole table, which errs on
    // the side of reporting nothing.
    policy::walk(&expected_rules(cfg), &packet, |id, _suppress| {
        tables
            .get(&id)
            .is_some_and(|t| best_way(cfg, peer, t, true).is_some())
    })
}

/// The table the rules choose for a reply to `peer` from `local` (`None`: a
/// rule drops it, or the table is not one of `cfg`'s).
pub(crate) fn reply_table(cfg: &Config, peer: IpAddr, local: IpAddr) -> Option<RoutingTable> {
    match reply_walk(cfg, peer, local).verdict {
        RuleVerdict::Table(t) => route::tables_by_id(cfg).get(&t).map(|t| (*t).clone()),
        RuleVerdict::Blackhole | RuleVerdict::Unreachable => None,
    }
}

/// Which way routing sends `peer` from `local` in `cfg`: the interface, or
/// what stops it.
fn way_out(cfg: &Config, peer: IpAddr, local: IpAddr) -> Result<String, String> {
    let walked = reply_walk(cfg, peer, local);
    let by = || {
        walked
            .steps
            .last()
            .map_or_else(String::new, |s| describe_pref(cfg, s.pref).1)
    };
    match walked.verdict {
        RuleVerdict::Table(t) => route::tables_by_id(cfg)
            .get(&t)
            .and_then(|table| route_out(cfg, peer, table))
            .ok_or_else(by),
        RuleVerdict::Blackhole | RuleVerdict::Unreachable => Err(by()),
    }
}

/// G1.27e: the replies to this connection stop, or leave by another way, once
/// the rules change. Its incoming packets are the kernel's `local` table,
/// rule 0, before any rule of ours: only the way back is at stake. `None`:
/// neither config has rules, or the way stays.
pub(crate) fn reply_cut(before: &Config, after: &Config, link: &Link) -> Option<String> {
    if before.routing.rules.is_empty() && after.routing.rules.is_empty() {
        return None;
    }
    let (peer, local) = (plain(link.peer.ip()), plain(link.local.ip()));
    if local.is_loopback() {
        return None;
    }
    let was = way_out(before, peer, local).ok()?;
    match way_out(after, peer, local) {
        Ok(now) if now == was => None,
        Ok(now) => Some(format!(
            "the routing rules would send the replies to this connection out of {now} instead \
             of {was} (tcp {} -> {})",
            link.peer, link.local
        )),
        Err(by) => Some(format!(
            "{by} would stop the replies to this connection (tcp {} -> {})",
            link.peer, link.local
        )),
    }
}

/// `{action, table}` of a kernel rule for the query commands.
pub(crate) fn action_json(a: KernelRuleAction, cfg: &Config) -> (&'static str, Value) {
    match a {
        KernelRuleAction::Table(t) => {
            let name = match t {
                255 => "local".to_owned(),
                253 => "default".to_owned(),
                _ => route::tables_by_id(cfg)
                    .get(&t)
                    .map_or_else(|| t.to_string(), ToString::to_string),
            };
            ("lookup", json!(name))
        }
        KernelRuleAction::Blackhole => ("drop", Value::Null),
        KernelRuleAction::Unreachable => ("unreachable", Value::Null),
        KernelRuleAction::Other(_) => ("other", Value::Null),
    }
}
