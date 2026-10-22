//! Whole-config validation run before every commit: cross-reference checks
//! owned by the engine plus each `proto-*` subsystem validator.

use std::collections::BTreeMap;

use corerouter_model::route::{self, FIRST_VRF_TABLE, LAST_VRF_TABLE, Reach};
use corerouter_model::{
    Config, IfName, Interface, InterfaceKind, Issue, RouteEntry, RoutingTable, VlanId,
};

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
    let mut vrf_tables: BTreeMap<u32, &IfName> = BTreeMap::new();
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
        if let Some(vrf) = &iface.vrf {
            vrf_member_checks(cfg, name, iface, vrf, &mut out);
        }
        if let InterfaceKind::Vrf { table } = iface.kind {
            if !(FIRST_VRF_TABLE..=LAST_VRF_TABLE).contains(&table) {
                out.push(Issue::new(
                    format!("interfaces.{name}.kind.table"),
                    format!("VRF table must be {FIRST_VRF_TABLE}..={LAST_VRF_TABLE}"),
                ));
            }
            if name.as_str() == RoutingTable::MAIN {
                out.push(Issue::new(
                    format!("interfaces.{name}"),
                    "'main' is the name of the main routing table",
                ));
            }
            if let Some(other) = vrf_tables.insert(table, name) {
                out.push(Issue::new(
                    format!("interfaces.{name}.kind.table"),
                    format!("table {table} is already used by VRF {other}"),
                ));
            }
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
    for (i, r) in cfg.ip.routes.iter().enumerate() {
        let earlier = cfg.ip.routes.iter().take(i);
        out.extend(
            route_issues(cfg, r, earlier)
                .into_iter()
                .map(|(field, m)| Issue::new(format!("ip.routes[{}].{field}", r.id), m)),
        );
    }
    out
}

/// What is wrong with route `r` in `cfg`, as (field, message). `others` are
/// the routes it must not duplicate. Shared with the `ip.route.*` commands,
/// which report the first problem as a parameter error.
pub(crate) fn route_issues<'a>(
    cfg: &Config,
    r: &RouteEntry,
    others: impl Iterator<Item = &'a RouteEntry>,
) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let dst = r.dst_address;
    if dst != dst.trunc() {
        out.push((
            "dst_address",
            format!("{dst} has host bits set; did you mean {}?", dst.trunc()),
        ));
    }
    if r.distance == 0 {
        out.push((
            "distance",
            "must be 1..=255 (0 is for connected routes)".into(),
        ));
    }
    if let Reach::Invalid { field, why } = route::reach(cfg, r) {
        out.push((field, why));
    }
    for o in others.filter(|o| o.id != r.id && o.routing_table == r.routing_table) {
        if o.dst_address != r.dst_address {
            continue;
        }
        if o.gateway == r.gateway {
            out.push((
                "gateway",
                format!(
                    "route {} already goes to {dst} via {} in table {}",
                    o.id, o.gateway, r.routing_table
                ),
            ));
        } else if o.distance == r.distance && !o.disabled && !r.disabled {
            out.push((
                "distance",
                format!(
                    "route {} to {dst} in table {} has distance {} too; give a backup route \
                     another distance, or disable one of them",
                    o.id, r.routing_table, r.distance
                ),
            ));
        }
    }
    out
}

fn vrf_member_checks(
    cfg: &Config,
    name: &IfName,
    iface: &Interface,
    vrf: &IfName,
    out: &mut Vec<Issue>,
) {
    let path = format!("interfaces.{name}.vrf");
    match cfg.interfaces.get(vrf).map(|v| &v.kind) {
        None => out.push(Issue::new(
            path.clone(),
            format!("VRF '{vrf}' does not exist"),
        )),
        Some(InterfaceKind::Vrf { .. }) => {}
        Some(other) => out.push(Issue::new(
            path.clone(),
            format!("'{vrf}' is not a VRF (type {})", other.label()),
        )),
    }
    if matches!(iface.kind, InterfaceKind::Vrf { .. }) {
        out.push(Issue::new(
            path.clone(),
            "a VRF cannot be a member of a VRF",
        ));
    }
    if let Some(b) = &iface.bridge {
        out.push(Issue::new(
            path,
            format!("'{name}' is a port of bridge '{b}'; put the bridge in the VRF instead"),
        ));
    }
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
    if matches!(p.kind, InterfaceKind::Loopback | InterfaceKind::Vrf { .. }) {
        out.push(Issue::new(
            path,
            format!(
                "parent '{parent}' is a {}; VLAN {} needs ethernet, bridge or VLAN",
                p.kind.label(),
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
    if matches!(
        iface.kind,
        InterfaceKind::Bridge | InterfaceKind::Loopback | InterfaceKind::Vrf { .. }
    ) {
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
