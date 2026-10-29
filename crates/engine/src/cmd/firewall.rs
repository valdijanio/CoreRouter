//! /ip firewall — filter, nat, mangle, raw (G2.1c) and address-list (G2.1).
//!
//! RouterOS names and syntax (`chain`, `action`, `src_address=!10.0.0.0/8`,
//! `dst_port=80,443`, `connection_state=established,related`); one list for
//! IPv4 and IPv6, narrowed by `family` or by the addresses a rule uses.
//! Every rule change is checked by `corerouter_firewall::rule_issues` before
//! it touches the candidate; the whole config is validated again at commit.

use corerouter_firewall::describe::describe;
use corerouter_firewall::{rule_issues, table_issues};
use corerouter_firewall::shadow::shadowed;
use corerouter_firewall::validate::MAX_RULES;
use corerouter_hal::DynamicChange;
use corerouter_model::firewall::{
    Action, AddrMatch, AddressListEntry, Family, FirewallRule, Matchers, Name, Table, Timeout,
};
use corerouter_model::{Config, ItemId};
use serde_json::{Map, Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, req_parse};
use super::{CommandSpec, always};
use crate::firewall_dyn::{DynamicEntry, MAX_DYNAMIC};
use crate::lockout::take_force;
use crate::{EngineError, Result, Session};

/// Matcher parameters, in the order the GUI and `summary` show them.
pub const MATCHERS: [&str; 18] = [
    "src_address",
    "dst_address",
    "src_address_list",
    "dst_address_list",
    "protocol",
    "src_port",
    "dst_port",
    "in_interface",
    "out_interface",
    "in_interface_list",
    "out_interface_list",
    "connection_state",
    "connection_nat_state",
    "icmp_options",
    "connection_mark",
    "packet_mark",
    "routing_mark",
    "limit",
];

/// Action parameters and the actions each one belongs to.
const ACTION_FIELDS: [(&str, &[&str]); 11] = [
    ("reject_with", &["reject"]),
    ("jump_target", &["jump"]),
    ("log_prefix", &["log"]),
    ("to_addresses", &["src-nat", "dst-nat"]),
    ("to_ports", &["masquerade", "src-nat", "dst-nat"]),
    ("new_connection_mark", &["mark-connection"]),
    ("new_packet_mark", &["mark-packet"]),
    ("new_routing_mark", &["mark-routing"]),
    (
        "passthrough",
        &["mark-connection", "mark-packet", "mark-routing"],
    ),
    (
        "address_list",
        &["add-src-to-address-list", "add-dst-to-address-list"],
    ),
    (
        "address_list_timeout",
        &["add-src-to-address-list", "add-dst-to-address-list"],
    ),
];

macro_rules! per_table {
    ($table:expr, $add:ident, $set:ident, $remove:ident, $move_:ident, $list:ident, $has:ident) => {
        fn $add(s: &mut Session, p: &Value) -> Result<Value> {
            add(s, $table, p)
        }
        fn $set(s: &mut Session, p: &Value) -> Result<Value> {
            set(s, $table, p)
        }
        fn $remove(s: &mut Session, p: &Value) -> Result<Value> {
            remove(s, $table, p)
        }
        fn $move_(s: &mut Session, p: &Value) -> Result<Value> {
            move_rule(s, $table, p)
        }
        fn $list(s: &mut Session, p: &Value) -> Result<Value> {
            list(s, $table, p)
        }
        fn $has(s: &Session) -> std::result::Result<(), String> {
            has_rules(s, $table)
        }
    };
}

per_table!(
    Table::Filter,
    filter_add,
    filter_set,
    filter_remove,
    filter_move,
    filter_list,
    has_filter
);
per_table!(
    Table::Nat,
    nat_add,
    nat_set,
    nat_remove,
    nat_move,
    nat_list,
    has_nat
);
per_table!(
    Table::Mangle,
    mangle_add,
    mangle_set,
    mangle_remove,
    mangle_move,
    mangle_list,
    has_mangle
);
per_table!(
    Table::Raw,
    raw_add,
    raw_set,
    raw_remove,
    raw_move,
    raw_list,
    has_raw
);

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.firewall.filter.add",
        "Add Filter Rule",
        ["IP", "Firewall"],
        None,
        "{chain?: input | forward | output | <custom>, action?: accept | drop | reject | jump | return | log | passthrough | add-src-to-address-list | add-dst-to-address-list (default accept), family?: both | ipv4 | ipv6, src_address?: [!]ip | cidr | ip-ip, dst_address?: [!]ip | cidr | ip-ip, src_address_list?: [!]name, dst_address_list?: [!]name, protocol?: [!]tcp | udp | icmp | icmpv6 | 0..255, src_port?: [!]ports (22 or 80-90 or a comma-separated list), dst_port?: [!]ports, in_interface?: [!]interface, out_interface?: [!]interface, in_interface_list?: [!]list, out_interface_list?: [!]list, connection_state?: [!]list of established | related | new | invalid | untracked (comma-separated), connection_nat_state?: [!]srcnat | dstnat (comma-separated), icmp_options?: type[:code], connection_mark?: [!]name, packet_mark?: [!]name, routing_mark?: [!]name, limit?: count/time[,burst] (5/1s,10; time 1s 1m 1h 1d), reject_with?: icmp-no-route | icmp-admin-prohibited | icmp-address-unreachable | icmp-port-unreachable | tcp-reset, jump_target?: chain, log_prefix?: string, address_list?: name (add-*-to-address-list), address_list_timeout?: duration (30s, 1h, 1d; absent = until restart), disabled?: bool, comment?: string, section?: string (a section header with this title instead of a rule), place_before?: *hex, force?: bool (apply even if it would cut your management connection)} → {id}",
        always,
        filter_add
    ),
    cmd!(
        "ip.firewall.filter.set",
        "Set Filter Rule",
        [],
        None,
        "{id: *hex, chain?, action?, family?, src_address?, dst_address?, src_address_list?, dst_address_list?, protocol?, src_port?, dst_port?, in_interface?, out_interface?, in_interface_list?, out_interface_list?, connection_state?, connection_nat_state?, icmp_options?, connection_mark?, packet_mark?, routing_mark?, limit?, reject_with?, jump_target?, log_prefix?, address_list?, address_list_timeout?, disabled?: bool, comment?: string, section?: string (title of a section header), force?: bool} → {id} (same syntax as add; \"\" clears a matcher)",
        has_filter,
        filter_set
    ),
    cmd!(
        "ip.firewall.filter.remove",
        "Remove Filter Rule",
        [],
        None,
        "{id: *hex, force?: bool} → {id}",
        has_filter,
        filter_remove
    ),
    cmd!(
        "ip.firewall.filter.move",
        "Move Filter Rule",
        [],
        None,
        "{id: *hex, destination?: *hex (moved above it; absent = to the end), force?: bool} → {id, position}",
        has_filter,
        filter_move
    ),
    cmd!(query "ip.firewall.filter.list", "Filter Rules", ["IP", "Firewall"], None,
        "{chain?: string} → [{id, position, chain, family, action, flags (X disabled, I invalid, S shadowed, Z zone matrix), disabled, invalid, reason, shadowed_by (*hex of the earlier rule that takes all its packets, else null), zone (generated by ip.firewall.zone), section (title of a section header, else null), comment, summary, description (in Portuguese), packets, bytes, pps, last_used (unix seconds or null), idle_secs, stale (live counters, once the daemon has read them), <matchers and action parameters set on the rule>}]",
        always, filter_list),
    cmd!(
        "ip.firewall.nat.add",
        "Add NAT Rule",
        ["IP", "Firewall"],
        None,
        "{chain?: srcnat | dstnat | <custom>, action?: accept | masquerade | src-nat | dst-nat | jump | return | log | passthrough | add-src-to-address-list | add-dst-to-address-list (default accept), family?: both | ipv4 | ipv6, src_address?: [!]ip | cidr | ip-ip, dst_address?: [!]ip | cidr | ip-ip, src_address_list?: [!]name, dst_address_list?: [!]name, protocol?: [!]tcp | udp | icmp | icmpv6 | 0..255, src_port?: [!]ports, dst_port?: [!]ports, in_interface?: [!]interface, out_interface?: [!]interface, in_interface_list?: [!]list, out_interface_list?: [!]list, connection_state?: [!]states, connection_nat_state?: [!]srcnat | dstnat (comma-separated), icmp_options?: type[:code], connection_mark?: [!]name, packet_mark?: [!]name, routing_mark?: [!]name, limit?: count/time[,burst], to_addresses?: ip | ip-ip (src-nat, dst-nat), to_ports?: port | port-port, jump_target?: chain, log_prefix?: string, address_list?: name, address_list_timeout?: duration, disabled?: bool, comment?: string, section?: string, place_before?: *hex, force?: bool} → {id}",
        always,
        nat_add
    ),
    cmd!(
        "ip.firewall.nat.set",
        "Set NAT Rule",
        [],
        None,
        "{id: *hex, chain?, action?, family?, src_address?, dst_address?, src_address_list?, dst_address_list?, protocol?, src_port?, dst_port?, in_interface?, out_interface?, in_interface_list?, out_interface_list?, connection_state?, connection_nat_state?, icmp_options?, connection_mark?, packet_mark?, routing_mark?, limit?, to_addresses?, to_ports?, jump_target?, log_prefix?, address_list?, address_list_timeout?, disabled?: bool, comment?: string, section?: string, force?: bool} → {id} (same syntax as add; \"\" clears a matcher)",
        has_nat,
        nat_set
    ),
    cmd!(
        "ip.firewall.nat.remove",
        "Remove NAT Rule",
        [],
        None,
        "{id: *hex, force?: bool} → {id}",
        has_nat,
        nat_remove
    ),
    cmd!(
        "ip.firewall.nat.move",
        "Move NAT Rule",
        [],
        None,
        "{id: *hex, destination?: *hex (moved above it; absent = to the end), force?: bool} → {id, position}",
        has_nat,
        nat_move
    ),
    cmd!(query "ip.firewall.nat.list", "NAT Rules", ["IP", "Firewall"], None,
        "{chain?: string} → [{id, position, chain, family, action, flags, disabled, invalid, reason, shadowed_by, zone, section, comment, summary, description, …}]",
        always, nat_list),
    cmd!(
        "ip.firewall.mangle.add",
        "Add Mangle Rule",
        ["IP", "Firewall"],
        None,
        "{chain?: prerouting | input | forward | output | postrouting | <custom>, action?: accept | mark-connection | mark-packet | mark-routing | jump | return | log | passthrough | add-src-to-address-list | add-dst-to-address-list (default accept), family?: both | ipv4 | ipv6, src_address?: [!]ip | cidr | ip-ip, dst_address?: [!]ip | cidr | ip-ip, src_address_list?: [!]name, dst_address_list?: [!]name, protocol?: [!]tcp | udp | icmp | icmpv6 | 0..255, src_port?: [!]ports, dst_port?: [!]ports, in_interface?: [!]interface, out_interface?: [!]interface, in_interface_list?: [!]list, out_interface_list?: [!]list, connection_state?: [!]states, connection_nat_state?: [!]srcnat | dstnat (comma-separated), icmp_options?: type[:code], connection_mark?: [!]name, packet_mark?: [!]name, routing_mark?: [!]name, limit?: count/time[,burst], new_connection_mark?: name, new_packet_mark?: name, new_routing_mark?: name, passthrough?: bool (default true), jump_target?: chain, log_prefix?: string, address_list?: name, address_list_timeout?: duration, disabled?: bool, comment?: string, section?: string, place_before?: *hex, force?: bool} → {id}",
        always,
        mangle_add
    ),
    cmd!(
        "ip.firewall.mangle.set",
        "Set Mangle Rule",
        [],
        None,
        "{id: *hex, chain?, action?, family?, src_address?, dst_address?, src_address_list?, dst_address_list?, protocol?, src_port?, dst_port?, in_interface?, out_interface?, in_interface_list?, out_interface_list?, connection_state?, connection_nat_state?, icmp_options?, connection_mark?, packet_mark?, routing_mark?, limit?, new_connection_mark?, new_packet_mark?, new_routing_mark?, passthrough?: bool, jump_target?, log_prefix?, address_list?, address_list_timeout?, disabled?: bool, comment?: string, section?: string, force?: bool} → {id} (same syntax as add; \"\" clears a matcher)",
        has_mangle,
        mangle_set
    ),
    cmd!(
        "ip.firewall.mangle.remove",
        "Remove Mangle Rule",
        [],
        None,
        "{id: *hex, force?: bool} → {id}",
        has_mangle,
        mangle_remove
    ),
    cmd!(
        "ip.firewall.mangle.move",
        "Move Mangle Rule",
        [],
        None,
        "{id: *hex, destination?: *hex (moved above it; absent = to the end), force?: bool} → {id, position}",
        has_mangle,
        mangle_move
    ),
    cmd!(query "ip.firewall.mangle.list", "Mangle Rules", ["IP", "Firewall"], None,
        "{chain?: string} → [{id, position, chain, family, action, flags, disabled, invalid, reason, shadowed_by, zone, section, comment, summary, description, …}]",
        always, mangle_list),
    cmd!(
        "ip.firewall.raw.add",
        "Add Raw Rule",
        ["IP", "Firewall"],
        None,
        "{chain?: prerouting | output | <custom>, action?: accept | drop | notrack | jump | return | log | passthrough | add-src-to-address-list | add-dst-to-address-list (default accept), family?: both | ipv4 | ipv6, src_address?: [!]ip | cidr | ip-ip, dst_address?: [!]ip | cidr | ip-ip, src_address_list?: [!]name, dst_address_list?: [!]name, protocol?: [!]tcp | udp | icmp | icmpv6 | 0..255, src_port?: [!]ports, dst_port?: [!]ports, in_interface?: [!]interface, out_interface?: [!]interface, in_interface_list?: [!]list, out_interface_list?: [!]list, icmp_options?: type[:code], packet_mark?: [!]name, limit?: count/time[,burst], jump_target?: chain, log_prefix?: string, address_list?: name, address_list_timeout?: duration, disabled?: bool, comment?: string, section?: string, place_before?: *hex, force?: bool} → {id} (before connection tracking: no connection_* matchers)",
        always,
        raw_add
    ),
    cmd!(
        "ip.firewall.raw.set",
        "Set Raw Rule",
        [],
        None,
        "{id: *hex, chain?, action?, family?, src_address?, dst_address?, src_address_list?, dst_address_list?, protocol?, src_port?, dst_port?, in_interface?, out_interface?, in_interface_list?, out_interface_list?, icmp_options?, packet_mark?, limit?, jump_target?, log_prefix?, address_list?, address_list_timeout?, disabled?: bool, comment?: string, section?: string, force?: bool} → {id} (same syntax as add; \"\" clears a matcher)",
        has_raw,
        raw_set
    ),
    cmd!(
        "ip.firewall.raw.remove",
        "Remove Raw Rule",
        [],
        None,
        "{id: *hex, force?: bool} → {id}",
        has_raw,
        raw_remove
    ),
    cmd!(
        "ip.firewall.raw.move",
        "Move Raw Rule",
        [],
        None,
        "{id: *hex, destination?: *hex (moved above it; absent = to the end), force?: bool} → {id, position}",
        has_raw,
        raw_move
    ),
    cmd!(query "ip.firewall.raw.list", "Raw Rules", ["IP", "Firewall"], None,
        "{chain?: string} → [{id, position, chain, family, action, flags, disabled, invalid, reason, shadowed_by, zone, section, comment, summary, description, …}]",
        always, raw_list),
    cmd!(
        "ip.firewall.address-list.add",
        "Add Address List Entry",
        ["IP", "Firewall"],
        None,
        "{list: name, address: ip | cidr | ip-ip (IPv4 or IPv6), timeout?: seconds | 30s | 5m | 1h | 1d | 1h30m (dynamic entry: not saved, expires), disabled?: bool, comment?: string, force?: bool} → {id, dynamic}",
        always,
        al_add
    ),
    cmd!(
        "ip.firewall.address-list.set",
        "Set Address List Entry",
        [],
        None,
        "{id: *hex (a static entry), list?: name, address?: ip | cidr | ip-ip, disabled?: bool, comment?: string, force?: bool} → {id}",
        has_static_entries,
        al_set
    ),
    cmd!(
        "ip.firewall.address-list.remove",
        "Remove Address List Entry",
        [],
        None,
        "{id: *hex (static or dynamic), force?: bool} → {id}",
        has_entries,
        al_remove
    ),
    cmd!(query "ip.firewall.address-list.list", "Address Lists", ["IP", "Firewall"], None,
        "{list?: name} → [{id, list, address, family, dynamic, timeout (seconds left, dynamic only), flags (X disabled, D dynamic), disabled, comment}]",
        always, al_list),
];

fn has_rules(s: &Session, table: Table) -> std::result::Result<(), String> {
    if s.store().candidate().ip.firewall.rules(table).is_empty() {
        Err(format!("there are no {} rules", table.name()))
    } else {
        Ok(())
    }
}

fn has_static_entries(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.firewall.address_lists.is_empty() {
        Err("there are no static address-list entries".into())
    } else {
        Ok(())
    }
}

fn has_entries(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.firewall.address_lists.is_empty()
        && s.dynamic_addresses.entries().is_empty()
    {
        Err("there are no address-list entries".into())
    } else {
        Ok(())
    }
}

/// Position of rule `id` in `table`.
fn position(cfg: &Config, table: Table, id: ItemId, key: &str) -> Result<usize> {
    cfg.ip
        .firewall
        .rules(table)
        .iter()
        .position(|r| r.id == id)
        .ok_or_else(|| {
            EngineError::bad(
                key,
                format!(
                    "no {} rule {id} (see ip.firewall.{}.list)",
                    table.name(),
                    table.name()
                ),
            )
        })
}

/// What the zone matrix generated is rewritten by `ip.firewall.zone.set`:
/// a hand edit would be lost at the next change, so it is refused.
fn not_zone(r: &FirewallRule) -> Result<()> {
    if r.zone {
        return Err(EngineError::bad(
            "id",
            format!(
                "{} is generated by the zone matrix: change the matrix (ip.firewall.zone.set), \
                 or ip.firewall.zone.detach to turn its rules into normal rules",
                r.id
            ),
        ));
    }
    Ok(())
}

/// A rule placed above `anchor` must not land inside the zone block (only
/// above its header).
fn outside_zone_block(cfg: &Config, table: Table, anchor: ItemId, key: &str) -> Result<()> {
    let rules = cfg.ip.firewall.rules(table);
    let first_zone = rules.iter().find(|r| r.zone).map(|r| r.id);
    let inside = rules
        .iter()
        .any(|r| r.id == anchor && r.zone && Some(r.id) != first_zone);
    if inside {
        return Err(EngineError::bad(
            key,
            format!(
                "{anchor} is inside the zone matrix's rules; place it above the zone \
                 section's header or after its last rule"
            ),
        ));
    }
    Ok(())
}

/// The JSON of `p[key]` as a matcher/action value: a string; `""` clears.
fn text_param(p: &Value, key: &str) -> Result<Option<Option<String>>> {
    match p.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if s.trim().is_empty() => Ok(Some(None)),
        Some(Value::String(s)) => {
            if s.chars().count() > 1024 {
                return Err(EngineError::bad(key, "at most 1024 characters"));
            }
            Ok(Some(Some(s.trim().to_owned())))
        }
        Some(Value::Number(n)) => Ok(Some(Some(n.to_string()))),
        // Lists (ports, states) may come as a JSON array: ["22", "80"].
        Some(Value::Array(items)) if items.len() <= 64 => {
            let parts: Option<Vec<String>> = items
                .iter()
                .map(|v| match v {
                    Value::String(s) => Some(s.trim().to_owned()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
                .collect();
            let parts = parts.ok_or_else(|| EngineError::bad(key, "must be a string"))?;
            Ok(Some((!parts.is_empty()).then(|| parts.join(","))))
        }
        Some(_) => Err(EngineError::bad(key, "must be a string")),
    }
}

/// Apply the matcher parameters of `p` to `m`, each checked on its own so
/// the error names the parameter.
fn apply_matchers(m: &mut Matchers, p: &Value) -> Result<bool> {
    let mut obj = match serde_json::to_value(&*m) {
        Ok(Value::Object(o)) => o,
        _ => Map::new(),
    };
    let mut touched = false;
    for key in MATCHERS {
        let Some(v) = text_param(p, key)? else {
            continue;
        };
        touched = true;
        match v {
            None => {
                obj.remove(key);
            }
            Some(text) => {
                let one: Map<String, Value> =
                    std::iter::once((key.to_owned(), Value::String(text.clone()))).collect();
                serde_json::from_value::<Matchers>(Value::Object(one))
                    .map_err(|e| EngineError::bad(key, serde_reason(&e)))?;
                obj.insert(key.to_owned(), Value::String(text));
            }
        }
    }
    *m = serde_json::from_value(Value::Object(obj))
        .map_err(|e| EngineError::bad("matchers", serde_reason(&e)))?;
    Ok(touched)
}

/// serde's message without its "at line 1 column 3" tail.
fn serde_reason(e: &serde_json::Error) -> String {
    let text = e.to_string();
    let text = text.split(" at line ").next().unwrap_or(&text).to_owned();
    text.chars().take(300).collect()
}

/// The rule's action after `p`: `action` switches type (keeping fields that
/// still apply), action parameters change the current one.
fn apply_action(current: &Action, p: &Value) -> Result<Option<Action>> {
    let name = match opt_str(p, "action")? {
        Some(n) => {
            let n = n.trim();
            if !Action::NAMES.contains(&n) {
                return Err(EngineError::bad(
                    "action",
                    format!("expected one of {}", Action::NAMES.join(", ")),
                ));
            }
            n.to_owned()
        }
        None => current.name().to_owned(),
    };
    let mut obj = match serde_json::to_value(current) {
        Ok(Value::Object(o)) if current.name() == name => o,
        _ => Map::new(),
    };
    obj.insert("type".into(), Value::String(name.clone()));
    let mut touched = p.get("action").is_some_and(|v| !v.is_null());
    for (key, owners) in ACTION_FIELDS {
        let value = if key == "passthrough" {
            match opt_bool(p, key)? {
                None => continue,
                Some(b) => Some(Value::Bool(b)),
            }
        } else {
            match text_param(p, key)? {
                None => continue,
                Some(v) => v.map(Value::String),
            }
        };
        touched = true;
        if !owners.contains(&name.as_str()) {
            return Err(EngineError::bad(
                key,
                format!(
                    "is only for action={} (this rule's action is {name})",
                    owners.join(" or action=")
                ),
            ));
        }
        match value {
            None => {
                obj.remove(key);
            }
            Some(v) => {
                obj.insert(key.to_owned(), v);
            }
        }
    }
    if !touched {
        return Ok(None);
    }
    serde_json::from_value(Value::Object(obj))
        .map(Some)
        .map_err(|e| {
            let reason = serde_reason(&e);
            // "missing field `jump_target`" → that parameter is required.
            match reason
                .split('`')
                .nth(1)
                .filter(|_| reason.starts_with("missing field"))
            {
                Some(field) => {
                    let key = ACTION_FIELDS
                        .iter()
                        .map(|(k, _)| *k)
                        .find(|k| *k == field)
                        .unwrap_or("action");
                    EngineError::bad(key, format!("is required for action={name}"))
                }
                None => {
                    let key = ACTION_FIELDS
                        .iter()
                        .map(|(k, _)| *k)
                        .find(|k| p.get(*k).is_some())
                        .unwrap_or("action");
                    EngineError::bad(key, reason)
                }
            }
        })
}

/// An interface named by a matcher must exist when the rule is written
/// (RouterOS refuses unknown interfaces too).
fn check_interfaces(cfg: &Config, before: &Matchers, after: &Matchers) -> Result<()> {
    for (key, b, a) in [
        ("in_interface", &before.in_interface, &after.in_interface),
        ("out_interface", &before.out_interface, &after.out_interface),
    ] {
        // `lo` (loopback) is never in the config but always exists.
        if let Some(n) = a.as_ref().filter(|n| Some(*n) != b.as_ref())
            && n.value.as_str() != "lo"
            && !cfg.interfaces.contains_key(&n.value)
        {
            return Err(EngineError::bad(
                key,
                format!("interface '{}' does not exist", n.value),
            ));
        }
    }
    Ok(())
}

/// Refuse `r` with the first problem the validator sees in it.
fn check_rule(cfg: &Config, table: Table, r: &FirewallRule) -> Result<()> {
    match rule_issues(cfg, table, r).into_iter().next() {
        Some((field, why)) => Err(EngineError::bad(field, why)),
        None => Ok(()),
    }
}

/// Keys that make no sense on a section header.
fn rule_keys_in(p: &Value) -> Option<&'static str> {
    let others = ["chain", "action", "family"];
    MATCHERS
        .iter()
        .chain(ACTION_FIELDS.iter().map(|(k, _)| k))
        .chain(others.iter())
        .copied()
        .find(|k| p.get(*k).is_some_and(|v| !v.is_null()))
}

pub(super) fn add(s: &mut Session, table: Table, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let section = opt_text(p, "section", 256)?;
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let before: Option<ItemId> = opt_parse(p, "place_before")?;
    let first_chain = table.builtin_chains().first().copied().unwrap_or("input");

    let mut rule = FirewallRule {
        id: ItemId(0),
        chain: first_chain
            .parse()
            .map_err(|e: corerouter_model::ParseError| EngineError::Internal(e.to_string()))?,
        family: Family::Both,
        matchers: Matchers::default(),
        action: Action::Accept,
        disabled,
        comment,
        section: false,
        zone: false,
    };
    if let Some(anchor) = before {
        outside_zone_block(s.store().candidate(), table, anchor, "place_before")?;
    }
    if let Some(title) = section {
        if let Some(k) = rule_keys_in(p) {
            return Err(EngineError::bad(
                k,
                "a section header only takes a title (section), disabled and place_before",
            ));
        }
        rule.section = true;
        rule.comment = title;
    } else {
        if let Some(c) = opt_parse::<Name>(p, "chain")? {
            rule.chain = c;
        }
        if let Some(f) = opt_parse::<Family>(p, "family")? {
            rule.family = f;
        }
        apply_matchers(&mut rule.matchers, p)?;
        if let Some(a) = apply_action(&Action::Accept, p)? {
            rule.action = a;
        }
    }

    let cfg = s.store_mut().candidate_mut();
    if cfg.ip.firewall.rules(table).len() >= MAX_RULES {
        return Err(EngineError::bad(
            "chain",
            format!("at most {MAX_RULES} {} rules", table.name()),
        ));
    }
    check_interfaces(cfg, &Matchers::default(), &rule.matchers)?;
    let at = match before {
        Some(id) => position(cfg, table, id, "place_before")?,
        None => cfg.ip.firewall.rules(table).len(),
    };
    rule.id = cfg.ip.firewall.next_rule_id();
    check_rule(cfg, table, &rule)?;
    let id = rule.id;
    cfg.ip.firewall.rules_mut(table).insert(at, rule);
    Ok(json!({ "id": id }))
}

fn set(s: &mut Session, table: Table, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let id: ItemId = req_parse(p, "id")?;
    let section = opt_text(p, "section", 256)?;
    let disabled = opt_bool(p, "disabled")?;
    let comment = opt_text(p, "comment", 256)?;
    let chain: Option<Name> = opt_parse(p, "chain")?;
    let family: Option<Family> = opt_parse(p, "family")?;

    let cfg = s.store_mut().candidate_mut();
    let pos = position(cfg, table, id, "id")?;
    let mut rule = cfg
        .ip
        .firewall
        .rules(table)
        .get(pos)
        .cloned()
        .ok_or_else(|| EngineError::bad("id", format!("no rule {id}")))?;
    not_zone(&rule)?;
    let old = rule.clone();
    if rule.section {
        if let Some(k) = rule_keys_in(p) {
            return Err(EngineError::bad(
                k,
                format!("{id} is a section header: only section (its title), disabled and comment"),
            ));
        }
        if let Some(t) = section.or(comment) {
            rule.comment = t;
        }
    } else {
        if section.is_some() {
            return Err(EngineError::bad(
                "section",
                format!("{id} is a rule, not a section header (add one with section=…)"),
            ));
        }
        if let Some(c) = chain {
            rule.chain = c;
        }
        if let Some(f) = family {
            rule.family = f;
        }
        apply_matchers(&mut rule.matchers, p)?;
        if let Some(a) = apply_action(&rule.action, p)? {
            rule.action = a;
        }
        if let Some(c) = comment {
            rule.comment = c;
        }
    }
    if let Some(d) = disabled {
        rule.disabled = d;
    }
    check_interfaces(cfg, &old.matchers, &rule.matchers)?;
    check_rule(cfg, table, &rule)?;
    if let Some(slot) = cfg.ip.firewall.rules_mut(table).get_mut(pos) {
        *slot = rule;
    }
    Ok(json!({ "id": id }))
}

fn remove(s: &mut Session, table: Table, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let id: ItemId = req_parse(p, "id")?;
    let cfg = s.store_mut().candidate_mut();
    let pos = position(cfg, table, id, "id")?;
    if let Some(r) = cfg.ip.firewall.rules(table).get(pos) {
        not_zone(r)?;
    }
    cfg.ip.firewall.rules_mut(table).remove(pos);
    Ok(json!({ "id": id }))
}

/// RouterOS `move`: above `destination`, or to the end.
fn move_rule(s: &mut Session, table: Table, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let id: ItemId = req_parse(p, "id")?;
    let dest: Option<ItemId> = opt_parse(p, "destination")?;
    let cfg = s.store_mut().candidate_mut();
    let from = position(cfg, table, id, "id")?;
    if let Some(r) = cfg.ip.firewall.rules(table).get(from) {
        not_zone(r)?;
    }
    if let Some(d) = dest {
        outside_zone_block(cfg, table, d, "destination")?;
    }
    if dest == Some(id) {
        return Ok(json!({ "id": id, "position": from }));
    }
    if let Some(d) = dest {
        position(cfg, table, d, "destination")?;
    }
    let rules = cfg.ip.firewall.rules_mut(table);
    let Some(rule) = rules.remove(from) else {
        return Err(EngineError::bad("id", "no such rule"));
    };
    let to = match dest {
        Some(d) => rules.iter().position(|r| r.id == d).unwrap_or(rules.len()),
        None => rules.len(),
    };
    rules.insert(to, rule);
    Ok(json!({ "id": id, "position": to }))
}

/// `chain=input action=accept connection-state=established,related` — the
/// rule as RouterOS `print` would show it.
pub fn summary(r: &FirewallRule) -> String {
    if r.section {
        return format!(";;; {}", r.comment);
    }
    let mut parts = vec![
        format!("chain={}", r.chain),
        format!("action={}", r.action.name()),
    ];
    if r.family != Family::Both {
        parts.push(format!("family={}", r.family.name()));
    }
    let matchers = serde_json::to_value(&r.matchers).unwrap_or(Value::Null);
    let action = serde_json::to_value(&r.action).unwrap_or(Value::Null);
    let keys = MATCHERS
        .iter()
        .map(|k| (&matchers, *k))
        .chain(ACTION_FIELDS.iter().map(|(k, _)| (&action, *k)));
    for (obj, k) in keys {
        let Some(v) = obj.get(k) else { continue };
        let text = match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        parts.push(format!("{}={text}", k.replace('_', "-")));
    }
    parts.join(" ")
}

/// One rule as `ip.firewall.<table>.list` shows it; `shadowed_by` comes
/// from [`corerouter_firewall::shadow::shadowed`] and `issue` from
/// [`table_issues`], both over the whole table.
pub fn row(
    table: Table,
    position: usize,
    r: &FirewallRule,
    shadowed_by: Option<ItemId>,
    issue: Option<(&'static str, String)>,
) -> Value {
    let mut flags = String::new();
    if r.disabled {
        flags.push('X');
    }
    if issue.is_some() {
        flags.push('I');
    }
    if shadowed_by.is_some() {
        flags.push('S');
    }
    if r.zone {
        flags.push('Z');
    }
    let mut obj = Map::new();
    if let Ok(Value::Object(m)) = serde_json::to_value(&r.matchers) {
        obj.extend(m);
    }
    if let Ok(Value::Object(a)) = serde_json::to_value(&r.action) {
        obj.extend(a.into_iter().filter(|(k, _)| k != "type"));
    }
    obj.insert("id".into(), json!(r.id));
    obj.insert("position".into(), json!(position));
    obj.insert(
        "chain".into(),
        if r.section {
            Value::Null
        } else {
            json!(r.chain)
        },
    );
    obj.insert(
        "family".into(),
        if r.section {
            Value::Null
        } else {
            json!(r.family.name())
        },
    );
    obj.insert(
        "action".into(),
        if r.section {
            Value::Null
        } else {
            json!(r.action.name())
        },
    );
    obj.insert("flags".into(), json!(flags));
    obj.insert("disabled".into(), json!(r.disabled));
    obj.insert("invalid".into(), json!(issue.is_some()));
    obj.insert(
        "reason".into(),
        json!(issue.map(|(f, m)| format!("{f}: {m}"))),
    );
    // The title for a section header (what `add` takes back), else null.
    obj.insert(
        "section".into(),
        if r.section {
            json!(r.comment)
        } else {
            Value::Null
        },
    );
    obj.insert("comment".into(), json!(r.comment));
    obj.insert("summary".into(), json!(summary(r)));
    obj.insert("description".into(), json!(describe(table, r)));
    obj.insert("shadowed_by".into(), json!(shadowed_by));
    obj.insert("zone".into(), json!(r.zone));
    Value::Object(obj)
}

fn list(s: &mut Session, table: Table, p: &Value) -> Result<Value> {
    let chain: Option<Name> = opt_parse(p, "chain")?;
    // Someone looks at the rules: keep the live counters coming (G2.1c).
    s.firewall_counters_want();
    let now = s.now().unwrap_or(0);
    // Under the lock: the config and the counters, as pointers (G0.31b).
    let live = s
        .ext::<crate::firewall_diag::FwDiag>()
        .map(|d| std::sync::Arc::clone(&d.live));
    let cfg = s.store().candidate().clone();
    s.defer(move || {
        let shadows = shadowed(&cfg, table);
        let issues = table_issues(&cfg, table);
        Ok(Value::Array(
            cfg.ip
                .firewall
                .rules(table)
                .iter()
                .zip(issues)
                .enumerate()
                .filter(|(_, (r, _))| chain.as_ref().is_none_or(|c| *c == r.chain && !r.section))
                .map(|(i, (r, issue))| {
                    let first = issue.into_iter().next();
                    let mut v = row(table, i, r, shadows.get(&r.id).copied(), first);
                    if let (Some(l), Some(o)) =
                        (live.as_ref().and_then(|m| m.get(&(table, r.id))), v.as_object_mut())
                    {
                        let idle = l.idle_secs(now);
                        o.insert("packets".into(), json!(l.shown_packets()));
                        o.insert("bytes".into(), json!(l.shown_bytes()));
                        o.insert("pps".into(), json!((l.pps * 10.0).round() / 10.0));
                        o.insert("last_used".into(), json!(l.last_used));
                        o.insert("idle_secs".into(), json!(idle));
                        o.insert(
                            "stale".into(),
                            json!(idle >= crate::firewall_diag::STALE_DAYS * 86_400),
                        );
                    }
                    v
                })
                .collect(),
        ))
    })
}

/// RouterOS durations: `90`, `30s`, `5m`, `1h30m`, `1d`, `1w` (at most 35
/// days: nftables keeps timeouts in 32-bit milliseconds).
pub fn parse_timeout(p: &Value, key: &str) -> Result<Option<u64>> {
    let text = match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(|n| n.to_string())
            .ok_or_else(|| EngineError::bad(key, "must be a whole number of seconds"))?,
        Some(Value::String(s)) => s.trim().to_owned(),
        Some(_) => return Err(EngineError::bad(key, "must be seconds or like 1h30m")),
    };
    let t: Timeout = text
        .parse()
        .map_err(|e: corerouter_model::ParseError| EngineError::bad(key, e.to_string()))?;
    Ok(Some(u64::from(t.secs())))
}

pub(super) fn al_add(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let list: Name = req_parse(p, "list")?;
    let address: AddrMatch = req_parse(p, "address")?;
    let timeout = parse_timeout(p, "timeout")?;
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();

    let duplicate = s
        .store()
        .candidate()
        .ip
        .firewall
        .address_lists
        // O(1) in the index of what each list holds (G0.21).
        .holders(&list, &address)
        > 0
        || s.dynamic_addresses.find(&list, &address).is_some();
    if duplicate {
        return Err(EngineError::bad(
            "address",
            format!("{address} is already in list {list}"),
        ));
    }
    if let Some(secs) = timeout {
        if disabled {
            return Err(EngineError::bad(
                "disabled",
                "a dynamic entry (with timeout) cannot be disabled",
            ));
        }
        if s.dynamic_addresses.entries().len() >= MAX_DYNAMIC {
            return Err(EngineError::bad(
                "timeout",
                format!("at most {MAX_DYNAMIC} dynamic entries"),
            ));
        }
        let now = s.now();
        let entry = DynamicEntry {
            id: s.dynamic_addresses.next_id(),
            list,
            address,
            timeout_secs: secs,
            added: now,
            comment,
        };
        let id = entry.id;
        // Not a commit (operational state), so the lockout check is here.
        let before = s.dynamic_now();
        let mut after = before.clone();
        after.push(entry.data_plane(now));
        // As the commit path sees it: with the addresses and routes DHCP
        // clients installed (the operator may be on one of them).
        let running = s.effective(s.store().running());
        s.check_lockout(&running, &running, &before, &after)?;
        s.hal_mut()
            .address_list_dynamic(DynamicChange::Add(&entry.data_plane(now)))
            .map_err(|e| EngineError::Hal(e.to_string()))?;
        s.dynamic_addresses.push(entry);
        return Ok(json!({ "id": id, "dynamic": true }));
    }
    let cfg = s.store_mut().candidate_mut();
    if cfg.ip.firewall.address_lists.len()
        >= corerouter_firewall::validate::MAX_ADDRESS_LIST_ENTRIES
    {
        return Err(EngineError::bad("list", "too many address-list entries"));
    }
    let id = cfg.ip.firewall.next_address_list_id();
    cfg.ip.firewall.address_lists.push(AddressListEntry {
        id,
        list,
        address,
        disabled,
        comment,
    });
    Ok(json!({ "id": id, "dynamic": false }))
}

fn static_entry(cfg: &Config, id: ItemId) -> Result<usize> {
    cfg.ip
        .firewall
        .address_lists
        .position(id)
        .ok_or_else(|| {
            EngineError::bad(
                "id",
                format!("no static address-list entry {id} (dynamic ones can only be removed)"),
            )
        })
}

fn al_set(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let id: ItemId = req_parse(p, "id")?;
    let list: Option<Name> = opt_parse(p, "list")?;
    let address: Option<AddrMatch> = opt_parse(p, "address")?;
    let disabled = opt_bool(p, "disabled")?;
    let comment = opt_text(p, "comment", 256)?;
    let cfg = s.store().candidate();
    let pos = static_entry(cfg, id)?;
    let mut e = cfg
        .ip
        .firewall
        .address_lists
        .get(pos)
        .cloned()
        .ok_or_else(|| EngineError::bad("id", format!("no entry {id}")))?;
    if let Some(l) = list {
        e.list = l;
    }
    if let Some(a) = address {
        e.address = a;
    }
    if let Some(d) = disabled {
        e.disabled = d;
    }
    if let Some(c) = comment {
        e.comment = c;
    }
    let lists = &cfg.ip.firewall.address_lists;
    let unchanged = lists.get(pos).is_some_and(|o| o.address == e.address && o.list == e.list);
    if lists.holders(&e.list, &e.address) > u32::from(unchanged)
        || s.dynamic_addresses.find(&e.list, &e.address).is_some()
    {
        return Err(EngineError::bad(
            "address",
            format!("{} is already in list {}", e.address, e.list),
        ));
    }
    let cfg = s.store_mut().candidate_mut();
    cfg.ip.firewall.address_lists.update(pos, |slot| *slot = e);
    Ok(json!({ "id": id }))
}

fn al_remove(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let id: ItemId = req_parse(p, "id")?;
    let now = s.now();
    if let Some(e) = s.dynamic_addresses.remove(id) {
        if let Err(err) = s
            .hal_mut()
            .address_list_dynamic(DynamicChange::Remove(&e.data_plane(now)))
        {
            // Already expired in the data plane, or merged into a range.
            log::warn!("dynamic entry {id} ({} in {}): {err}", e.address, e.list);
        }
        return Ok(json!({ "id": id }));
    }
    let cfg = s.store_mut().candidate_mut();
    let pos = static_entry(cfg, id)?;
    cfg.ip.firewall.address_lists.remove(pos);
    Ok(json!({ "id": id }))
}

fn al_list(s: &mut Session, p: &Value) -> Result<Value> {
    let filter: Option<Name> = opt_parse(p, "list")?;
    s.expire_dynamic_addresses();
    let now = s.now();
    // Under the lock: two pointers; 100 000 rows are built after (G0.31b).
    let lists = s.store().candidate().ip.firewall.address_lists.list().clone();
    let dynamic = s.dynamic_addresses.shared();
    s.defer(move || {
        let keep = |l: &Name| filter.as_ref().is_none_or(|f| f == l);
        let mut rows: Vec<Value> = lists
            .iter()
            .filter(|e| keep(&e.list))
            .map(|e| {
                json!({
                    "id": e.id,
                    "list": e.list,
                    "address": e.address,
                    "family": e.address.family().name(),
                    "dynamic": false,
                    "timeout": Value::Null,
                    "flags": if e.disabled { "X" } else { "" },
                    "disabled": e.disabled,
                    "comment": e.comment,
                })
            })
            .collect();
        rows.extend(dynamic.iter().filter(|e| keep(&e.list)).map(|e| {
            json!({
                "id": e.id,
                "list": e.list,
                "address": e.address,
                "family": e.address.family().name(),
                "dynamic": true,
                "timeout": e.left(now),
                "flags": "D",
                "disabled": false,
                "comment": e.comment,
            })
        }));
        Ok(Value::Array(rows))
    })
}
