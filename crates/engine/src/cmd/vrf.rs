//! /ip vrf — a VRF is a named routing table plus the interfaces that route
//! with it. It is also an interface (type `vrf`, the Linux `vrf` device),
//! so its name follows interface-name rules and shows in `interface.list`.
//! `ip.vrf.add` is disabled, with the reason, on a kernel without VRF.

use corerouter_model::route::{FIRST_VRF_TABLE, LAST_VRF_TABLE};
use corerouter_model::{Config, IfName, Interface, InterfaceKind, RoutingTable};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_names, opt_text, req_parse};
use super::interface::{MAX_INTERFACES, new_name};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.vrf.add",
        "Add VRF",
        ["IP", "VRF"],
        None,
        "{name: string, interfaces?: [string] | string (comma-separated), comment?: string} → {name, table}",
        vrf_supported,
        add
    ),
    cmd!(
        "ip.vrf.set",
        "Set VRF",
        [],
        None,
        "{name: string, interfaces?: [string] | string (comma-separated) (replaces the members), disabled?: bool, comment?: string} → {name}",
        always,
        set
    ),
    cmd!(
        "ip.vrf.remove",
        "Remove VRF",
        [],
        None,
        "{name: string (members return to main; routes in its table must go first)} → {name}",
        always,
        remove
    ),
    cmd!(query "ip.vrf.list", "VRFs", ["IP", "VRF"], None,
        "{} → [{name, table, interfaces, disabled, comment}]",
        always, list),
];

/// The backend can create VRF devices (Linux: `CONFIG_NET_VRF`).
fn vrf_supported(s: &Session) -> std::result::Result<(), String> {
    if s.hal().features().vrf {
        Ok(())
    } else {
        Err(corerouter_hal::NO_VRF.to_owned())
    }
}

fn is_vrf(cfg: &Config, name: &IfName) -> bool {
    matches!(
        cfg.interfaces.get(name).map(|i| &i.kind),
        Some(InterfaceKind::Vrf { .. })
    )
}

/// Parse `name` as an existing VRF.
fn existing(cfg: &Config, p: &Value) -> Result<IfName> {
    let name: IfName = req_parse(p, "name")?;
    if !is_vrf(cfg, &name) {
        return Err(EngineError::bad(
            "name",
            format!("no VRF '{name}' (see ip.vrf.list)"),
        ));
    }
    Ok(name)
}

/// Lowest kernel table id no VRF uses.
fn free_table(cfg: &Config) -> Result<u32> {
    let used: Vec<u32> = cfg
        .interfaces
        .values()
        .filter_map(|i| match i.kind {
            InterfaceKind::Vrf { table } => Some(table),
            _ => None,
        })
        .collect();
    (FIRST_VRF_TABLE..=LAST_VRF_TABLE)
        .find(|t| !used.contains(t))
        .ok_or_else(|| EngineError::bad("name", "no free routing table id left"))
}

/// Check that `members` may join `vrf`, then make them exactly its members.
fn set_members(cfg: &mut Config, vrf: &IfName, members: &[IfName]) -> Result<()> {
    for m in members {
        let iface = cfg.interfaces.get(m).ok_or_else(|| {
            EngineError::bad(
                "interfaces",
                format!("no interface '{m}' (see interface.list)"),
            )
        })?;
        if matches!(iface.kind, InterfaceKind::Vrf { .. }) {
            return Err(EngineError::bad(
                "interfaces",
                format!("'{m}' is a VRF; a VRF cannot be a member of another"),
            ));
        }
        if let Some(b) = &iface.bridge {
            return Err(EngineError::bad(
                "interfaces",
                format!("'{m}' is a port of bridge '{b}'; put '{b}' in the VRF instead"),
            ));
        }
        if let Some(other) = iface.vrf.as_ref().filter(|v| *v != vrf) {
            return Err(EngineError::bad(
                "interfaces",
                format!("'{m}' is already in VRF '{other}'; take it out there first (ip.vrf.set)"),
            ));
        }
    }
    for iface in cfg.interfaces.values_mut() {
        if members.contains(&iface.name) {
            iface.vrf = Some(vrf.clone());
        } else if iface.vrf.as_ref() == Some(vrf) {
            iface.vrf = None;
        }
    }
    Ok(())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    super::interface::refuse_unmanaged(s, p, &["name", "interfaces"])?;
    let members = opt_names(p, "interfaces", MAX_INTERFACES)?.unwrap_or_default();
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let cfg = s.store_mut().candidate_mut();
    let name = new_name(cfg, p)?;
    if name.as_str() == RoutingTable::MAIN {
        return Err(EngineError::bad(
            "name",
            "'main' is the main routing table; pick another name",
        ));
    }
    let table = free_table(cfg)?;
    let mut vrf = Interface::new(name.clone(), InterfaceKind::Vrf { table });
    vrf.comment = comment;
    cfg.interfaces.insert(name.clone(), vrf);
    set_members(cfg, &name, &members)?;
    Ok(json!({ "name": name, "table": table }))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    super::interface::refuse_unmanaged(s, p, &["interfaces"])?;
    let members = opt_names(p, "interfaces", MAX_INTERFACES)?;
    let disabled = opt_bool(p, "disabled")?;
    let comment = opt_text(p, "comment", 256)?;
    let cfg = s.store_mut().candidate_mut();
    let name = existing(cfg, p)?;
    if let Some(m) = members {
        set_members(cfg, &name, &m)?;
    }
    if let Some(vrf) = cfg.interfaces.get_mut(&name) {
        if let Some(d) = disabled {
            vrf.disabled = d;
        }
        if let Some(c) = comment {
            vrf.comment = c;
        }
    }
    Ok(json!({ "name": name }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let cfg = s.store_mut().candidate_mut();
    let name = existing(cfg, p)?;
    let table = RoutingTable::Vrf(name.clone());
    let mut blockers = Vec::new();
    let routes: Vec<String> = cfg
        .ip
        .routes
        .iter()
        .filter(|r| r.routing_table == table)
        .map(|r| r.id.to_string())
        .collect();
    if !routes.is_empty() {
        blockers.push(format!(
            "remove route {} of its table first (ip.route.remove)",
            routes.join(", ")
        ));
    }
    let addrs: Vec<String> = cfg
        .ip
        .addresses
        .iter()
        .filter(|a| a.interface == name)
        .map(|a| format!("{} ({})", a.id, a.address))
        .collect();
    if !addrs.is_empty() {
        blockers.push(format!(
            "remove IP address {} first (ip.address.remove)",
            addrs.join(", ")
        ));
    }
    if !blockers.is_empty() {
        return Err(EngineError::bad(
            "name",
            format!("'{name}' is in use: {}", blockers.join("; ")),
        ));
    }
    set_members(cfg, &name, &[])?;
    cfg.interfaces.remove(&name);
    Ok(json!({ "name": name }))
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    let rows = cfg
        .interfaces
        .values()
        .filter_map(|v| match v.kind {
            InterfaceKind::Vrf { table } => Some((v, table)),
            _ => None,
        })
        .map(|(v, table)| {
            let members: Vec<&IfName> = cfg
                .interfaces
                .values()
                .filter(|i| i.vrf.as_ref() == Some(&v.name))
                .map(|i| &i.name)
                .collect();
            json!({
                "name": v.name,
                "table": table,
                "interfaces": members,
                "disabled": v.disabled,
                "comment": v.comment,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}
