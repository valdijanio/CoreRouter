//! Whole-config validation run before every commit: cross-reference checks
//! owned by the engine plus each `proto-*` subsystem validator.

use std::collections::BTreeMap;

use corerouter_model::{Config, IfName, Interface, InterfaceKind, Issue, VlanId};

pub fn validate_all(cfg: &Config) -> Vec<Issue> {
    let mut out = core_checks(cfg);
    out.extend(corerouter_proto_bgp::validate(cfg));
    out.extend(corerouter_proto_ospf::validate(cfg));
    out.extend(corerouter_proto_mpls::validate(cfg));
    out.extend(corerouter_proto_cgnat::validate(cfg));
    out.extend(corerouter_proto_dns::validate(cfg));
    out.extend(corerouter_proto_dhcp::validate(cfg));
    out.extend(corerouter_proto_discovery::validate(cfg));
    out
}

fn core_checks(cfg: &Config) -> Vec<Issue> {
    let mut out = Vec::new();
    let mut vlans: BTreeMap<(&IfName, VlanId), &IfName> = BTreeMap::new();
    for (name, iface) in &cfg.interfaces {
        if iface.name != *name {
            out.push(Issue::new(
                format!("interfaces.{name}"),
                "name does not match key",
            ));
        }
        if let InterfaceKind::Vlan { parent, vlan_id } = &iface.kind {
            if vlan_lowers(cfg, name).1 {
                out.push(Issue::new(
                    format!("interfaces.{name}.kind.parent"),
                    "VLAN parent chain loops back on itself",
                ));
            }
            vlan_checks(cfg, name, iface, parent, *vlan_id, &mut out);
            if let Some(other) = vlans.insert((parent, *vlan_id), name) {
                out.push(Issue::new(
                    format!("interfaces.{name}.kind.vlan_id"),
                    format!(
                        "VLAN {} on {parent} is already used by {other}",
                        vlan_id.get()
                    ),
                ));
            }
        }
        if let Some(bridge) = &iface.bridge {
            bridge_port_checks(cfg, name, iface, bridge, &mut out);
        }
        if !(68..=9216).contains(&iface.mtu) {
            out.push(Issue::new(
                format!("interfaces.{name}.mtu"),
                "MTU must be 68..=9216",
            ));
        }
    }
    for a in &cfg.ip.addresses {
        if !cfg.interfaces.contains_key(&a.interface) {
            out.push(Issue::new(
                format!("ip.addresses[{}].interface", a.id),
                format!("interface '{}' does not exist", a.interface),
            ));
        }
    }
    out
}

fn vlan_checks(
    cfg: &Config,
    name: &IfName,
    iface: &Interface,
    parent: &IfName,
    vlan_id: VlanId,
    out: &mut Vec<Issue>,
) {
    let path = format!("interfaces.{name}.kind.parent");
    let Some(p) = cfg.interfaces.get(parent) else {
        out.push(Issue::new(
            path,
            format!("parent interface '{parent}' does not exist"),
        ));
        return;
    };
    if matches!(p.kind, InterfaceKind::Loopback) {
        out.push(Issue::new(
            path,
            format!(
                "parent '{parent}' is a loopback; VLAN {} needs ethernet, bridge or VLAN",
                vlan_id.get()
            ),
        ));
    }
    if iface.mtu > p.mtu {
        out.push(Issue::new(
            format!("interfaces.{name}.mtu"),
            format!(
                "MTU {} exceeds the MTU {} of parent '{parent}'",
                iface.mtu, p.mtu
            ),
        ));
    }
}

fn bridge_port_checks(
    cfg: &Config,
    name: &IfName,
    iface: &Interface,
    bridge: &IfName,
    out: &mut Vec<Issue>,
) {
    let mut problems = Vec::new();
    match cfg.interfaces.get(bridge).map(|b| &b.kind) {
        None => problems.push(format!("bridge '{bridge}' does not exist")),
        Some(InterfaceKind::Bridge) => {}
        Some(other) => problems.push(format!(
            "'{bridge}' is not a bridge (type {})",
            other.label()
        )),
    }
    if matches!(iface.kind, InterfaceKind::Bridge | InterfaceKind::Loopback) {
        problems.push(format!(
            "'{name}' is a {} and cannot be a bridge port",
            iface.kind.label()
        ));
    }
    if vlan_lowers(cfg, name).0.contains(&bridge) {
        problems.push(format!(
            "'{name}' runs on top of '{bridge}'; a port of it would loop"
        ));
    }
    out.extend(
        problems
            .into_iter()
            .map(|m| Issue::new(format!("interfaces.{name}.bridge"), m)),
    );
}

/// Interfaces `name` is stacked on through VLAN parents, nearest first, and
/// whether the chain loops. Bounded by the interface count, so a hostile
/// config with a cycle cannot hang the validator.
pub(crate) fn vlan_lowers<'a>(cfg: &'a Config, name: &IfName) -> (Vec<&'a IfName>, bool) {
    let mut chain = Vec::new();
    let mut cur = cfg.interfaces.get(name);
    while let Some(InterfaceKind::Vlan { parent, .. }) = cur.map(|i| &i.kind) {
        if parent == name || chain.contains(&parent) || chain.len() > cfg.interfaces.len() {
            return (chain, true);
        }
        chain.push(parent);
        cur = cfg.interfaces.get(parent);
    }
    (chain, false)
}
