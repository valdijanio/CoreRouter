//! /interface — ports, VLANs, bridges and loopbacks (VRFs and bonds are
//! interfaces too, managed by `ip.vrf.*` and `interface.bonding.*`).

use std::collections::BTreeMap;

use corerouter_model::os_loopback;
use corerouter_model::{Config, IfName, Interface, InterfaceKind, RoutingTable, VlanId};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32, req_parse, req_u32};
use super::{CommandSpec, always};
use crate::validate::vlan_lowers;
use crate::{EngineError, Result, Session};

/// Hostile-input bound: a router with more logical interfaces is a mistake.
pub const MAX_INTERFACES: usize = 4096;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "interface.list", "Interfaces", ["Interfaces"], None,
        "{type?: string (ether | vlan | bridge | bonding | loopback | vrf | veth | …)} → [{name, type, kind, managed, unmanaged_reason, mtu, disabled, running, rx_bytes, tx_bytes, rx_packets, tx_packets, comment, parent, vlan_id, use_service_tag, bridge, bond, vrf, table}]",
        always, list),
    cmd!(
        "interface.set",
        "Set Interface",
        [],
        None,
        "{name: string, mtu?: u32 (68..=9216; a bond passes it to its slaves), disabled?: bool, comment?: string} → {name}",
        always,
        set
    ),
    cmd!(
        "interface.vlan.add",
        "Add VLAN",
        ["Interfaces"],
        None,
        "{name: string, parent: string (terminal: also interface=, as RouterOS writes it), vlan_id: u32 (1..=4094), use_service_tag?: bool (802.1ad S-tag, TPID 0x88a8: the outer tag of QinQ; default no, 802.1Q 0x8100), mtu?: u32 (68..=9216, default: parent MTU), disabled?: bool, comment?: string} → {name}",
        always,
        vlan_add
    )
    .key_alias(&[("interface", "parent")]),
    // `/interface vlan print` and the like (G3.9hl): one type each, the
    // columns RouterOS prints first (`interface.list` keeps every type).
    cmd!(query "interface.vlan.list", "VLANs", [], None,
        "{} → [{name, mtu, vlan_id, interface (the parent: interface= in RouterOS), mac_address, use_service_tag, disabled, running, comment}]",
        always, vlan_list),
    cmd!(query "interface.bridge.list", "Bridges", [], None,
        "{} → [{name, mtu, mac_address, ports (count), disabled, running, comment}]",
        always, bridge_list),
    cmd!(query "interface.loopback.list", "Loopbacks", [], None,
        "{} → [{name, mtu, disabled, running, comment}]",
        always, loopback_list),
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
        "{bridge?: string} → [{interface, bridge}]",
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
        "{name: string (not a physical port; nothing may depend on it; a bond releases its slaves)} → {name}",
        always,
        remove
    ),
];

/// Config interfaces first (with the kernel's `kind` and counters), then
/// the platform links outside the config, all `managed: false` (G1.18).
fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let filter = opt_str(p, "type")?;
    let live = s.hal_mut().poll();
    s.watch_links(&live);
    let cfg = s.store().candidate();
    let mut rows: Vec<Value> = cfg
        .interfaces
        .values()
        .filter(|i| filter.is_none_or(|t| i.kind.label() == t))
        .map(|i| {
            let st = live.iter().find(|l| l.name == i.name);
            let (parent, vlan_id, service_tag) = match &i.kind {
                InterfaceKind::Vlan {
                    parent,
                    vlan_id,
                    service_tag,
                } => (Some(parent), Some(vlan_id.get()), Some(*service_tag)),
                InterfaceKind::PppoeClient(c) => (Some(&c.interface), None, None),
                _ => (None, None, None),
            };
            // A PPPoE client runs when its session is up, not when its veth is.
            let session_up = matches!(i.kind, InterfaceKind::PppoeClient(_)).then(|| {
                s.pppoe_clients()
                    .and_then(|rt| rt.runners.get(&i.name))
                    .is_some_and(|r| r.up.is_some())
            });
            let table = match i.kind {
                InterfaceKind::Vrf { table } => Some(table),
                _ => None,
            };
            let unmanaged = st.and_then(|l| l.unmanaged.as_deref());
            json!({
                "name": i.name,
                "type": i.kind.label(),
                "kind": st.map_or(i.kind.label(), |l| l.kind.as_str()),
                "managed": unmanaged.is_none(),
                "unmanaged_reason": unmanaged,
                "mtu": i.mtu,
                "disabled": i.disabled,
                "running": session_up.unwrap_or_else(|| st.is_some_and(|l| l.running)),
                "rx_bytes": st.map_or(0, |l| l.rx_bytes),
                "tx_bytes": st.map_or(0, |l| l.tx_bytes),
                "rx_packets": st.map_or(0, |l| l.rx_packets),
                "tx_packets": st.map_or(0, |l| l.tx_packets),
                "comment": i.comment,
                "parent": parent,
                "vlan_id": vlan_id,
                "use_service_tag": service_tag,
                "bridge": i.bridge,
                "bond": i.bond,
                "vrf": i.vrf,
                "table": table,
            })
        })
        .collect();
    rows.extend(
        live.iter()
            .filter(|l| !cfg.interfaces.contains_key(&l.name))
            .filter(|l| filter.is_none_or(|t| l.kind == t))
            .map(|l| {
                let why = l
                    .unmanaged
                    .as_deref()
                    .unwrap_or("not in the configuration (appeared after boot)");
                json!({
                    "name": l.name,
                    "type": l.kind,
                    "kind": l.kind,
                    "managed": false,
                    "unmanaged_reason": why,
                    "mtu": l.mtu,
                    "disabled": false,
                    "running": l.running,
                    "rx_bytes": l.rx_bytes,
                    "tx_bytes": l.tx_bytes,
                    "rx_packets": l.rx_packets,
                    "tx_packets": l.tx_packets,
                    "comment": "",
                    "parent": null,
                    "vlan_id": null,
                    "bridge": null,
                    "bond": null,
                    "vrf": null,
                    "table": null,
                })
            }),
    );
    Ok(Value::Array(rows))
}

type Typed = Vec<(Interface, Option<corerouter_hal::LinkState>)>;

/// The config interfaces `keep` selects, each with its kernel link (if
/// any), in config order: the rows of the per-type lists (G3.9hl). Also
/// the links left over (a VLAN's parent, for its MAC).
pub(super) fn typed(
    s: &mut Session,
    keep: impl Fn(&InterfaceKind) -> bool,
) -> (Typed, Vec<corerouter_hal::LinkState>) {
    let mut live = s.hal_mut().poll();
    s.watch_links(&live);
    let rows = s
        .store()
        .candidate()
        .interfaces
        .values()
        .filter(|i| keep(&i.kind))
        .map(|i| {
            let st = live
                .iter()
                .position(|l| l.name == i.name)
                .map(|at| live.swap_remove(at));
            (i.clone(), st)
        })
        .collect();
    (rows, live)
}

fn running(st: Option<&corerouter_hal::LinkState>) -> bool {
    st.is_some_and(|l| l.running)
}

fn vlan_list(s: &mut Session, _: &Value) -> Result<Value> {
    let (vlans, live) = typed(s, |k| matches!(k, InterfaceKind::Vlan { .. }));
    // Without its own, a VLAN carries its parent's MAC (Linux and RouterOS),
    // up a stack of VLANs (QinQ). Two maps, built once: O(1) per row.
    let mut macs: BTreeMap<&IfName, &str> = live
        .iter()
        .filter_map(|l| Some((&l.name, l.mac.as_deref()?)))
        .collect();
    macs.extend(
        vlans
            .iter()
            .filter_map(|(i, st)| Some((&i.name, st.as_ref()?.mac.as_deref()?))),
    );
    let parents: BTreeMap<&IfName, &IfName> = vlans
        .iter()
        .filter_map(|(i, _)| match &i.kind {
            InterfaceKind::Vlan { parent, .. } => Some((&i.name, parent)),
            _ => None,
        })
        .collect();
    let mac_of = |name: &IfName| {
        let mut at = name;
        // A stack is short; the bound only stops a loop the config forbids.
        for _ in 0..8 {
            if let Some(m) = macs.get(at) {
                return Some((*m).to_owned());
            }
            at = parents.get(at)?;
        }
        None
    };
    let rows = vlans
        .iter()
        .filter_map(|(i, st)| {
            let InterfaceKind::Vlan {
                parent,
                vlan_id,
                service_tag,
            } = &i.kind
            else {
                return None;
            };
            Some(json!({
                "name": i.name,
                "mtu": i.mtu,
                "vlan_id": vlan_id.get(),
                "interface": parent,
                "mac_address": mac_of(&i.name),
                "use_service_tag": service_tag,
                "disabled": i.disabled,
                "running": running(st.as_ref()),
                "comment": i.comment,
            }))
        })
        .collect();
    Ok(Value::Array(rows))
}

fn bridge_list(s: &mut Session, _: &Value) -> Result<Value> {
    let mut ports: BTreeMap<IfName, usize> = BTreeMap::new();
    for b in s
        .store()
        .candidate()
        .interfaces
        .values()
        .filter_map(|i| i.bridge.clone())
    {
        *ports.entry(b).or_default() += 1;
    }
    let rows = typed(s, |k| matches!(k, InterfaceKind::Bridge))
        .0
        .into_iter()
        .map(|(i, st)| {
            json!({
                "name": i.name,
                "mtu": i.mtu,
                "mac_address": st.as_ref().and_then(|l| l.mac.clone()),
                "ports": ports.get(&i.name).copied().unwrap_or(0),
                "disabled": i.disabled,
                "running": running(st.as_ref()),
                "comment": i.comment,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

fn loopback_list(s: &mut Session, _: &Value) -> Result<Value> {
    let rows = typed(s, |k| matches!(k, InterfaceKind::Loopback))
        .0
        .into_iter()
        .map(|(i, st)| {
            json!({
                "name": i.name,
                "mtu": i.mtu,
                "disabled": i.disabled,
                "running": running(st.as_ref()),
                "comment": i.comment,
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
    refuse_unmanaged(s, p, &["name"])?;
    let mtu = opt_u32(p, "mtu")?.map(parse_mtu).transpose()?;
    let disabled = opt_bool(p, "disabled")?;
    let comment = opt_text(p, "comment", 256)?;
    let cfg = s.store_mut().candidate_mut();
    if let Some(mtu) = mtu {
        if let Some(b) = cfg.interfaces.get(&name).and_then(|i| i.bond.as_ref()) {
            return Err(EngineError::bad(
                "mtu",
                format!("'{name}' is a slave of '{b}' and takes its MTU; set it on '{b}'"),
            ));
        }
        // A bond's slaves follow its MTU (the kernel does the same).
        for slave in cfg.interfaces.values_mut() {
            if slave.bond.as_ref() == Some(&name) {
                slave.mtu = mtu;
            }
        }
    }
    let iface = cfg
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

/// Kernel links the platform says CoreRouter must not change (G1.18).
pub(super) fn unmanaged(s: &mut Session) -> BTreeMap<IfName, String> {
    s.hal_mut().unmanaged().into_iter().collect()
}

/// Refuse when an interface named by `keys` in `p` (a name, a list, or a
/// comma-separated string) is one the platform does not let CoreRouter
/// manage. Runs before the other checks, so the reason beats "no interface".
pub(super) fn refuse_unmanaged(s: &mut Session, p: &Value, keys: &[&str]) -> Result<()> {
    let named: Vec<(&str, String)> = keys
        .iter()
        .flat_map(|k| {
            let vals: Vec<String> = match p.get(*k) {
                Some(Value::String(t)) => t.split(',').map(|x| x.trim().to_owned()).collect(),
                Some(Value::Array(a)) => a
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
                _ => Vec::new(),
            };
            vals.into_iter().map(move |v| (*k, v))
        })
        .collect();
    if named.is_empty() {
        return Ok(());
    }
    let external = unmanaged(s);
    for (key, name) in named {
        let Ok(n) = name.parse::<IfName>() else {
            continue;
        };
        // The OS loopback is CoreRouter's for its addresses once the
        // candidate has it, even before the commit that claims it (G3.4i).
        if os_loopback::is_os_loopback(s.store().candidate(), &n) {
            continue;
        }
        if let Some(why) = external.get(&n) {
            return Err(EngineError::bad(
                key,
                format!("'{n}' is not managed by CoreRouter: {why}"),
            ));
        }
    }
    Ok(())
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
pub(super) fn new_name(cfg: &Config, p: &Value) -> Result<IfName> {
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
    refuse_unmanaged(s, p, &["name", "parent"])?;
    let cfg = s.store().candidate();
    let name = new_name(cfg, p)?;
    let (parent, parent_iface) = existing(cfg, p, "parent")?;
    if matches!(
        parent_iface.kind,
        InterfaceKind::Loopback | InterfaceKind::Vrf { .. }
    ) {
        return Err(EngineError::bad(
            "parent",
            format!(
                "'{parent}' is a {}; use an ethernet, bridge or VLAN interface",
                parent_iface.kind.label()
            ),
        ));
    }
    let vlan_id = u16::try_from(req_u32(p, "vlan_id")?)
        .ok()
        .and_then(|id| VlanId::new(id).ok())
        .ok_or_else(|| EngineError::bad("vlan_id", "must be 1..=4094"))?;
    let service_tag = opt_bool(p, "use_service_tag")?.unwrap_or(false);
    if let Some(other) = cfg.interfaces.values().find(|i| {
        matches!(&i.kind, InterfaceKind::Vlan { parent: p, vlan_id: v, service_tag: t }
            if *p == parent && *v == vlan_id && *t == service_tag)
    }) {
        return Err(EngineError::bad(
            "vlan_id",
            format!(
                "{} {} on {parent} already exists ({})",
                if service_tag { "S-VLAN" } else { "VLAN" },
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
    let mut iface = Interface::new(
        name,
        InterfaceKind::Vlan {
            parent,
            vlan_id,
            service_tag,
        },
    );
    iface.mtu = mtu;
    iface.disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    insert(s, iface, p)
}

fn bridge_add(s: &mut Session, p: &Value) -> Result<Value> {
    refuse_unmanaged(s, p, &["name"])?;
    let name = new_name(s.store().candidate(), p)?;
    insert(s, Interface::new(name, InterfaceKind::Bridge), p)
}

fn loopback_add(s: &mut Session, p: &Value) -> Result<Value> {
    // `lo` is the OS loopback (G3.4i): it exists already, outside the
    // config, and becomes CoreRouter's for its addresses only.
    if p.get("name").and_then(Value::as_str) != Some(os_loopback::NAME) {
        refuse_unmanaged(s, p, &["name"])?;
    }
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
    refuse_unmanaged(s, p, &["bridge", "interface"])?;
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
        InterfaceKind::Bridge | InterfaceKind::Loopback | InterfaceKind::Vrf { .. } => {
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
    if let Some(v) = &iface.vrf {
        return Err(EngineError::bad(
            "interface",
            format!(
                "'{port}' is in VRF '{v}'; take it out first (ip.vrf.set), or put '{bridge}' in the VRF"
            ),
        ));
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
    refuse_unmanaged(s, p, &["bridge", "interface"])?;
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
        .map(|(b, i)| json!({ "interface": i, "bridge": b }))
        .collect();
    Ok(Value::Array(rows))
}

pub(super) fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    // A port entry for a link CoreRouter does not manage (a stale seed that
    // took `docker0`) may go: apply never touches that link anyway.
    let external = unmanaged(s);
    let cfg = s.store().candidate();
    let (name, iface) = existing(cfg, p, "name")?;
    if matches!(iface.kind, InterfaceKind::Ethernet) && !external.contains_key(&name) {
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
    // A bond takes its slaves with it (RouterOS does the same): they go
    // back to being plain ports.
    for slave in cfg.interfaces.values_mut() {
        if slave.bond.as_ref() == Some(&name) {
            slave.bond = None;
        }
    }
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
    let clients: Vec<String> = cfg
        .ip
        .dhcp_clients
        .iter()
        .filter(|c| c.interface == *name)
        .map(|c| c.id.to_string())
        .collect();
    if !clients.is_empty() {
        out.push(format!(
            "remove DHCP client {} first (ip.dhcp-client.remove)",
            clients.join(", ")
        ));
    }
    let dialers: Vec<&str> = cfg
        .interfaces
        .values()
        .filter(|i| matches!(&i.kind, InterfaceKind::PppoeClient(c) if c.interface == *name))
        .map(|i| i.name.as_str())
        .collect();
    if !dialers.is_empty() {
        out.push(format!(
            "remove PPPoE client {} first (interface.pppoe-client.remove)",
            dialers.join(", ")
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
    if matches!(iface.kind, InterfaceKind::Vrf { .. }) {
        out.push(format!(
            "'{name}' is a VRF: remove it with ip.vrf.remove, which releases its members"
        ));
    }
    let table = RoutingTable::Vrf(name.clone());
    let routes: Vec<String> = cfg
        .ip
        .routes
        .iter()
        .filter(|r| r.gateway.iface() == Some(name) || r.routing_table == table)
        .map(|r| format!("{} ({})", r.id, r.dst_address))
        .collect();
    if !routes.is_empty() {
        out.push(format!(
            "remove route {} first (ip.route.remove)",
            routes.join(", ")
        ));
    }
    out
}
