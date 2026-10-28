//! Which interfaces each OSPF instance runs on: the interface templates
//! matched against the config's interfaces, as RouterOS v7 does — a
//! template matches an interface it names (directly or through an
//! interface list) or one with an address inside one of its networks, and
//! the first matching template of an instance wins.
//!
//! The render puts each match in the interface's own FRR context
//! (`ip ospf area`, `ipv6 ospf6 area`), with the template's values;
//! `routing.ospf.interface-template.check` shows the same list before the
//! commit ("these interfaces enter area X").

use std::collections::{BTreeMap, HashMap};

use corerouter_model::Config;
use corerouter_model::config::InterfaceKind;
use corerouter_model::ospf::{NetworkType, OspfArea, OspfInstance, OspfTemplate, Version};
use corerouter_model::types::IfName;
use ipnet::IpNet;

/// One interface in one instance, through one template.
#[derive(Debug, Clone, PartialEq)]
pub struct Binding<'a> {
    pub interface: IfName,
    pub instance: &'a OspfInstance,
    pub area: &'a OspfArea,
    pub template: &'a OspfTemplate,
    /// Why it matched: `interface`, `list <name>` or `network <prefix>`.
    pub why: String,
}

/// The instance and area of a template, when both exist and are enabled.
pub fn area_of<'a>(cfg: &'a Config, t: &OspfTemplate) -> Option<(&'a OspfInstance, &'a OspfArea)> {
    let area = cfg.routing.ospf.areas.get(&t.area)?;
    let inst = cfg.routing.ospf.instances.get(&area.instance)?;
    (!area.disabled && !inst.disabled).then_some((inst, area))
}

/// The addresses of each interface (enabled ones), one family.
pub fn addresses(cfg: &Config, v6: bool) -> BTreeMap<&IfName, Vec<IpNet>> {
    let mut out: BTreeMap<&IfName, Vec<IpNet>> = BTreeMap::new();
    for a in cfg.ip.addresses.iter() {
        if a.disabled || matches!(a.address, IpNet::V6(_)) != v6 {
            continue;
        }
        out.entry(&a.interface).or_default().push(a.address);
    }
    out
}

/// Whether template `t` matches interface `name` (with addresses `addrs`
/// of the instance's family), and why.
pub fn matches(cfg: &Config, t: &OspfTemplate, name: &IfName, addrs: &[IpNet]) -> Option<String> {
    for i in &t.interfaces {
        if i == name.as_str() {
            return Some("interface".into());
        }
        if cfg.interface_lists.interfaces_of(i).any(|m| m == name) {
            return Some(format!("list {i}"));
        }
    }
    for n in &t.networks {
        if addrs.iter().any(|a| n.contains(&a.addr())) {
            return Some(format!("network {n}"));
        }
    }
    None
}

/// Every interface of every enabled instance, in interface order. A
/// virtual link is not an interface (it is rendered in the router
/// context) and is left out.
///
/// The templates are indexed once by the names they list (interface lists
/// expanded), so an interface only tries the templates naming it and the
/// templates matching by network: 4 000 interfaces × 1 000 templates went
/// from 146 ms (each interface against every template) to the time in
/// `docs/perf.md` (G3.4, **medido**).
pub fn bindings(cfg: &Config) -> Vec<Binding<'_>> {
    let ospf = &cfg.routing.ospf;
    if ospf.templates.is_empty() {
        return Vec::new();
    }
    // Usable templates, in order, with their instance and area.
    let live: Vec<(usize, &OspfTemplate, &OspfInstance, &OspfArea)> = ospf
        .templates
        .iter()
        .enumerate()
        .filter(|(_, t)| !t.disabled && t.kind != NetworkType::VirtualLink)
        .filter_map(|(i, t)| area_of(cfg, t).map(|(inst, area)| (i, t, inst, area)))
        .collect();
    let mut by_name: HashMap<&str, Vec<(usize, String)>> = HashMap::new();
    let mut by_net: Vec<usize> = Vec::new();
    for (k, (_, t, _, _)) in live.iter().enumerate() {
        for i in &t.interfaces {
            by_name
                .entry(i.as_str())
                .or_default()
                .push((k, "interface".into()));
            for m in cfg.interface_lists.interfaces_of(i) {
                by_name
                    .entry(m.as_str())
                    .or_default()
                    .push((k, format!("list {i}")));
            }
        }
        if !t.networks.is_empty() {
            by_net.push(k);
        }
    }
    let v4 = addresses(cfg, false);
    let v6 = addresses(cfg, true);
    let mut out = Vec::new();
    let mut cands: Vec<(usize, Option<String>)> = Vec::new();
    for iface in cfg.interfaces.values() {
        if iface.disabled {
            continue;
        }
        cands.clear();
        if let Some(v) = by_name.get(iface.name.as_str()) {
            cands.extend(v.iter().map(|(k, why)| (*k, Some(why.clone()))));
        }
        cands.extend(by_net.iter().map(|k| (*k, None)));
        if cands.is_empty() {
            continue;
        }
        // Template order; a name match before a network match of the same
        // template (RouterOS reports the interface).
        cands.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.is_some().cmp(&a.1.is_some())));
        let mut taken: Vec<&str> = Vec::new();
        for (k, why) in &cands {
            let Some((_, t, inst, area)) = live.get(*k) else {
                continue;
            };
            if taken.contains(&inst.name.as_str()) {
                continue;
            }
            let why = match why {
                Some(w) => w.clone(),
                None => {
                    let addrs = match inst.version {
                        Version::V2 => v4.get(&iface.name),
                        Version::V3 => v6.get(&iface.name),
                    }
                    .map_or(&[][..], Vec::as_slice);
                    match t
                        .networks
                        .iter()
                        .find(|n| addrs.iter().any(|a| n.contains(&a.addr())))
                    {
                        Some(n) => format!("network {n}"),
                        None => continue,
                    }
                }
            };
            taken.push(inst.name.as_str());
            out.push(Binding {
                interface: iface.name.clone(),
                instance: inst,
                area,
                template: t,
                why,
            });
        }
    }
    out
}

/// The network type that fits interface `name` (RFC 2328 §1.2): a PPP
/// link, a /30 or /31 has two routers on it and gains nothing from a DR
/// election (`ptp`: adjacency up to 40 s sooner, no type-2 LSA); a
/// loopback or a bridge of subscribers keeps `broadcast`. `None`: no
/// better guess than the default.
pub fn suggest_type(cfg: &Config, name: &IfName) -> Option<(NetworkType, String)> {
    suggest_type_in(cfg, &addresses(cfg, false), name)
}

/// [`suggest_type`] with the IPv4 addresses already gathered (many
/// interfaces at once: one pass over the addresses, not one each).
pub fn suggest_type_in(
    cfg: &Config,
    v4: &BTreeMap<&IfName, Vec<IpNet>>,
    name: &IfName,
) -> Option<(NetworkType, String)> {
    let iface = cfg.interfaces.get(name)?;
    if name.as_str().starts_with("ppp") || name.as_str().starts_with("<pppoe") {
        return Some((NetworkType::Ptp, "a PPP link has two ends".into()));
    }
    if matches!(iface.kind, InterfaceKind::Loopback) {
        return None;
    }
    if let Some(a) = v4
        .get(name)
        .and_then(|v| v.iter().find(|a| a.prefix_len() >= 30))
    {
        return Some((
            NetworkType::Ptp,
            format!("{a} has room for two routers only"),
        ));
    }
    None
}

/// Why interface `name` faces subscribers (a DHCP or PPPoE server runs
/// on it): OSPF there should be `passive` — the networks are announced
/// and no hello goes to the customers, who could otherwise form an
/// adjacency and inject routes (RFC 2328 §D: OSPF trusts its neighbors).
pub fn client_facing(cfg: &Config, name: &IfName) -> Option<String> {
    if let Some(s) = cfg
        .ip
        .dhcp_server
        .servers
        .iter()
        .find(|s| &s.interface == name)
    {
        return Some(format!("DHCP server {} runs on it", s.name));
    }
    cfg.ppp
        .pppoe_servers
        .iter()
        .find(|s| &s.interface == name)
        .map(|s| format!("PPPoE server {} runs on it", s.name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample;

    #[test]
    fn first_template_wins_by_name_list_or_network() {
        let cfg = sample();
        let b = bindings(&cfg);
        let got: Vec<(String, String, String)> = b
            .iter()
            .map(|b| (b.interface.to_string(), b.area.name.clone(), b.why.clone()))
            .collect();
        assert!(
            got.contains(&("ether1".into(), "backbone".into(), "interface".into())),
            "{got:?}"
        );
        assert!(
            got.contains(&(
                "ether2".into(),
                "backbone".into(),
                "network 10.0.2.0/24".into()
            )),
            "{got:?}"
        );
        // ether1 matches the second template too: the first one wins.
        assert_eq!(got.iter().filter(|g| g.0 == "ether1").count(), 1);
    }

    #[test]
    fn a_slash_30_suggests_ptp() {
        let cfg = sample();
        let (t, why) = suggest_type(&cfg, &"ether2".parse().unwrap()).unwrap();
        assert_eq!(t, NetworkType::Ptp);
        assert!(why.contains("10.0.2.1/30"), "{why}");
        assert!(suggest_type(&cfg, &"ether1".parse().unwrap()).is_none());
    }
}
