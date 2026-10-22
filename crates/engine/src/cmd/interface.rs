//! /interface — ports, VLANs, bridges and loopbacks.

use corerouter_model::{Config, IfName, Interface, InterfaceKind, VlanId};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32, req_parse, req_u32};
use super::{CommandSpec, always};
use crate::validate::vlan_lowers;
use crate::{EngineError, Result, Session};

/// Hostile-input bound: a router with more logical interfaces is a mistake.
pub const MAX_INTERFACES: usize = 4096;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "interface.list", "Interfaces", ["Interfaces"], None,
        "{type?: ether|vlan|bridge|loopback} → [{name, type, mtu, disabled, running, rx_bytes, tx_bytes, rx_packets, tx_packets, comment, parent, vlan_id, bridge}]",
        always, list),
    cmd!(
        "interface.set",
        "Set Interface",
        [],
        None,
        "{name: string, mtu?: u32 (68..=9216), disabled?: bool, comment?: string} → {name}",
        always,
        set
    ),
    cmd!(
        "interface.vlan.add",
        "Add VLAN",
        ["Interfaces"],
        None,
        "{name: string, parent: string, vlan_id: u32 (1..=4094), mtu?: u32 (68..=9216, default: parent MTU), comment?: string} → {name}",
        always,
        vlan_add
    ),
    cmd!(
        "interface.bridge.add",
        "Add Bridge",
        ["Interfaces"],
        None,
        "{name: string, comment?: string} → {name}",
        always,
        bridge_add
    ),
    cmd!(
        "interface.bridge.port.add",
        "Add Bridge Port",
        ["Interfaces"],
        None,
        "{bridge: string, interface: string} → {bridge, interface}",
        always,
        port_add
    ),
    cmd!(
        "interface.bridge.port.remove",
        "Remove Bridge Port",
        [],
        None,
        "{bridge: string, interface: string} → {bridge, interface}",
        always,
        port_remove
    ),
    cmd!(query "interface.bridge.port.list", "Bridge Ports", ["Interfaces"], None,
        "{bridge?: string} → [{bridge, interface}]",
        always, port_list),
    cmd!(
        "interface.loopback.add",
        "Add Loopback",
        ["Interfaces"],
        None,
        "{name: string, comment?: string} → {name}",
        always,
        loopback_add
    ),
    cmd!(
        "interface.remove",
        "Remove Interface",
        [],
        None,
        "{name: string (not a physical port; nothing may depend on it)} → {name}",
        always,
        remove
    ),
];

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let filter = opt_str(p, "type")?;
    let live = s.hal_mut().poll();
    let rows = s
        .store()
        .candidate()
        .interfaces
        .values()
        .filter(|i| filter.is_none_or(|t| i.kind.label() == t))
        .map(|i| {
            let st = live.iter().find(|l| l.name == i.name);
            let (parent, vlan_id) = match &i.kind {
                InterfaceKind::Vlan { parent, vlan_id } => (Some(parent), Some(vlan_id.get())),
                _ => (None, None),
            };
            json!({
                "name": i.name,
                "type": i.kind.label(),
                "mtu": i.mtu,
                "disabled": i.disabled,
                "running": st.is_some_and(|l| l.running),
                "rx_bytes": st.map_or(0, |l| l.rx_bytes),
                "tx_bytes": st.map_or(0, |l| l.tx_bytes),
                "rx_packets": st.map_or(0, |l| l.rx_packets),
                "tx_packets": st.map_or(0, |l| l.tx_packets),
                "comment": i.comment,
                "parent": parent,
                "vlan_id": vlan_id,
                "bridge": i.bridge,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

fn parse_mtu(mtu: u32) -> Result<u16> {
    u16::try_from(mtu)
        .ok()
        .filter(|m| (68..=9216).contains(m))
        .ok_or_else(|| EngineError::bad("mtu", "must be 68..=9216"))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    let mtu = opt_u32(p, "mtu")?.map(parse_mtu).transpose()?;
    let disabled = opt_bool(p, "disabled")?;
    let comment = opt_text(p, "comment", 256)?;
    let iface = s
        .store_mut()
        .candidate_mut()
        .interfaces
        .get_mut(&name)
        .ok_or_else(|| EngineError::bad("name", format!("no interface '{name}'")))?;
    if let Some(mtu) = mtu {
        iface.mtu = mtu;
    }
    if let Some(d) = disabled {
        iface.disabled = d;
    }
    if let Some(c) = comment {
        iface.comment = c;
    }
    Ok(json!({ "name": name }))
}

/// Parse `key` as an interface that must exist in `cfg`.
fn existing<'a>(cfg: &'a Config, p: &Value, key: &str) -> Result<(IfName, &'a Interface)> {
    let name: IfName = req_parse(p, key)?;
    let iface = cfg.interfaces.get(&name).ok_or_else(|| {
        EngineError::bad(key, format!("no interface '{name}' (see interface.list)"))
    })?;
    Ok((name, iface))
}

/// Parse the `name` of an interface about to be created.
fn new_name(cfg: &Config, p: &Value) -> Result<IfName> {
    let name: IfName = req_parse(p, "name")?;
    if cfg.interfaces.contains_key(&name) {
        return Err(EngineError::bad(
            "name",
            format!("interface '{name}' already exists"),
        ));
    }
    if cfg.interfaces.len() >= MAX_INTERFACES {
        return Err(EngineError::bad(
            "name",
            format!("at most {MAX_INTERFACES} interfaces"),
        ));
    }
    Ok(name)
}

fn insert(s: &mut Session, mut iface: Interface, p: &Value) -> Result<Value> {
    iface.comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let name = iface.name.clone();
    s.store_mut()
        .candidate_mut()
        .interfaces
        .insert(name.clone(), iface);
    Ok(json!({ "name": name }))
}

fn vlan_add(s: &mut Session, p: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    let name = new_name(cfg, p)?;
    let (parent, parent_iface) = existing(cfg, p, "parent")?;
    if matches!(parent_iface.kind, InterfaceKind::Loopback) {
        return Err(EngineError::bad(
            "parent",
            format!("'{parent}' is a loopback; use an ethernet, bridge or VLAN interface"),
        ));
    }
    let vlan_id = u16::try_from(req_u32(p, "vlan_id")?)
        .ok()
        .and_then(|id| VlanId::new(id).ok())
        .ok_or_else(|| EngineError::bad("vlan_id", "must be 1..=4094"))?;
    if let Some(other) = cfg.interfaces.values().find(|i| {
        matches!(&i.kind, InterfaceKind::Vlan { parent: p, vlan_id: v } if *p == parent && *v == vlan_id)
    }) {
        return Err(EngineError::bad(
            "vlan_id",
            format!(
                "VLAN {} on {parent} already exists ({})",
                vlan_id.get(),
                other.name
            ),
        ));
    }
    let mtu = match opt_u32(p, "mtu")? {
        Some(m) => parse_mtu(m)?,
        None => parent_iface.mtu,
    };
    if mtu > parent_iface.mtu {
        return Err(EngineError::bad(
            "mtu",
            format!("{mtu} exceeds the MTU {} of '{parent}'", parent_iface.mtu),
        ));
    }
    let mut iface = Interface::new(name, InterfaceKind::Vlan { parent, vlan_id });
    iface.mtu = mtu;
    insert(s, iface, p)
}

fn bridge_add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = new_name(s.store().candidate(), p)?;
    insert(s, Interface::new(name, InterfaceKind::Bridge), p)
}

fn loopback_add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = new_name(s.store().candidate(), p)?;
    insert(s, Interface::new(name, InterfaceKind::Loopback), p)
}

/// Parse `bridge` (must be a bridge) and `interface` (must exist).
fn port_params(cfg: &Config, p: &Value) -> Result<(IfName, IfName)> {
    let (bridge, b) = existing(cfg, p, "bridge")?;
    if !matches!(b.kind, InterfaceKind::Bridge) {
        return Err(EngineError::bad(
            "bridge",
            format!("'{bridge}' is not a bridge (type {})", b.kind.label()),
        ));
    }
    let (port, _) = existing(cfg, p, "interface")?;
    Ok((bridge, port))
}

fn port_add(s: &mut Session, p: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    let (bridge, port) = port_params(cfg, p)?;
    let iface = cfg
        .interfaces
        .get(&port)
        .ok_or_else(|| EngineError::bad("interface", format!("no interface '{port}'")))?;
    if port == bridge {
        return Err(EngineError::bad(
            "interface",
            "a bridge cannot be a port of itself",
        ));
    }
    match iface.kind {
        InterfaceKind::Bridge | InterfaceKind::Loopback => {
            return Err(EngineError::bad(
                "interface",
                format!(
                    "'{port}' is a {} and cannot be a bridge port",
                    iface.kind.label()
                ),
            ));
        }
        _ => {}
    }
    match &iface.bridge {
        Some(b) if *b == bridge => {
            return Err(EngineError::bad(
                "interface",
                format!("'{port}' is already a port of '{bridge}'"),
            ));
        }
        Some(b) => {
            return Err(EngineError::bad(
                "interface",
                format!(
                    "'{port}' is already a port of bridge '{b}'; remove it there first with interface.bridge.port.remove"
                ),
            ));
        }
        None => {}
    }
    if vlan_lowers(cfg, &port).0.contains(&&bridge) {
        return Err(EngineError::bad(
            "interface",
            format!("'{port}' runs on top of '{bridge}'; adding it as a port would loop"),
        ));
    }
    if let Some(i) = s.store_mut().candidate_mut().interfaces.get_mut(&port) {
        i.bridge = Some(bridge.clone());
    }
    Ok(json!({ "bridge": bridge, "interface": port }))
}

fn port_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let (bridge, port) = port_params(s.store().candidate(), p)?;
    let iface = s
        .store_mut()
        .candidate_mut()
        .interfaces
        .get_mut(&port)
        .ok_or_else(|| EngineError::bad("interface", format!("no interface '{port}'")))?;
    if iface.bridge.as_ref() != Some(&bridge) {
        return Err(EngineError::bad(
            "interface",
            format!("'{port}' is not a port of bridge '{bridge}'"),
        ));
    }
    iface.bridge = None;
    Ok(json!({ "bridge": bridge, "interface": port }))
}

fn port_list(s: &mut Session, p: &Value) -> Result<Value> {
    let filter: Option<IfName> = opt_parse(p, "bridge")?;
    let rows = s
        .store()
        .candidate()
        .interfaces
        .values()
        .filter_map(|i| Some((i.bridge.as_ref()?, &i.name)))
        .filter(|(b, _)| filter.as_ref().is_none_or(|f| f == *b))
        .map(|(b, i)| json!({ "bridge": b, "interface": i }))
        .collect();
    Ok(Value::Array(rows))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    let (name, iface) = existing(cfg, p, "name")?;
    if matches!(iface.kind, InterfaceKind::Ethernet) {
        return Err(EngineError::bad(
            "name",
            format!(
                "'{name}' is a physical port and cannot be removed (disable it with interface.set)"
            ),
        ));
    }
    let blockers = dependents(cfg, &name, iface);
    if !blockers.is_empty() {
        return Err(EngineError::bad(
            "name",
            format!("'{name}' is in use: {}", blockers.join("; ")),
        ));
    }
    let cfg = s.store_mut().candidate_mut();
    cfg.interfaces.remove(&name);
    // Discovery stops on it with it, instead of blocking the removal.
    cfg.ip.neighbor_discovery.interfaces.remove(&name);
    Ok(json!({ "name": name }))
}

/// What must be removed before `name` can go, each with the command to use.
fn dependents(cfg: &Config, name: &IfName, iface: &Interface) -> Vec<String> {
    let mut out = Vec::new();
    let addrs: Vec<String> = cfg
        .ip
        .addresses
        .iter()
        .filter(|a| a.interface == *name)
        .map(|a| format!("{} ({})", a.id, a.address))
        .collect();
    if !addrs.is_empty() {
        out.push(format!(
            "remove IP address {} first (ip.address.remove)",
            addrs.join(", ")
        ));
    }
    let children: Vec<&str> = cfg
        .interfaces
        .values()
        .filter(|i| matches!(&i.kind, InterfaceKind::Vlan { parent, .. } if parent == name))
        .map(|i| i.name.as_str())
        .collect();
    if !children.is_empty() {
        out.push(format!(
            "remove VLAN {} first (interface.remove)",
            children.join(", ")
        ));
    }
    let ports: Vec<&str> = cfg
        .interfaces
        .values()
        .filter(|i| i.bridge.as_ref() == Some(name))
        .map(|i| i.name.as_str())
        .collect();
    if !ports.is_empty() {
        out.push(format!(
            "remove bridge port {} first (interface.bridge.port.remove)",
            ports.join(", ")
        ));
    }
    if let Some(b) = &iface.bridge {
        out.push(format!(
            "remove it from bridge {b} first (interface.bridge.port.remove)"
        ));
    }
    out
}
