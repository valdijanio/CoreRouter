//! Whole-config validation run before every commit: cross-reference checks
//! owned by the engine plus each `proto-*` subsystem validator.

use corerouter_model::{Config, InterfaceKind, Issue};

pub fn validate_all(cfg: &Config) -> Vec<Issue> {
    let mut out = core_checks(cfg);
    out.extend(corerouter_proto_bgp::validate(cfg));
    out.extend(corerouter_proto_ospf::validate(cfg));
    out.extend(corerouter_proto_mpls::validate(cfg));
    out.extend(corerouter_proto_cgnat::validate(cfg));
    out.extend(corerouter_proto_dns::validate(cfg));
    out.extend(corerouter_proto_dhcp::validate(cfg));
    out
}

fn core_checks(cfg: &Config) -> Vec<Issue> {
    let mut out = Vec::new();
    for (name, iface) in &cfg.interfaces {
        if iface.name != *name {
            out.push(Issue::new(
                format!("interfaces.{name}"),
                "name does not match key",
            ));
        }
        if let InterfaceKind::Vlan { parent, .. } = &iface.kind
            && !cfg.interfaces.contains_key(parent)
        {
            out.push(Issue::new(
                format!("interfaces.{name}.kind.parent"),
                format!("parent interface '{parent}' does not exist"),
            ));
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
