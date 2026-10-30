//! Ports in the config that the platform does not have (G1.3b): a NIC that
//! was unplugged, a USB adapter that fell off, a card that burned, a VM
//! that lost a virtio device. RouterOS keeps their configuration and flags
//! what hangs on them `I` (invalid); Junos accepts configuration for an
//! interface that is not there and applies it when the hardware shows up.
//! CoreRouter does the same: a backend takes the transition without the
//! absent ports ([`mask`]), so the rest (the management address on another
//! port above all) is applied, and puts their configuration back when they
//! return.
//!
//! Only physical ports ([`InterfaceKind::Ethernet`]) can be absent: every
//! other link is one CoreRouter creates. A VLAN on an absent port goes with
//! it (the kernel cannot create it without its parent, and deletes it with
//! the parent); its addresses and the routes through it then fall out of
//! the plan by themselves, since both only count interfaces of the config
//! (`drift::active_addresses`, `route::reach`).

use std::borrow::Cow;
use std::collections::BTreeSet;

use corerouter_model::{Config, IfName, InterfaceKind};

/// Physical ports of `cfg` for which `present` says no.
pub fn missing(cfg: &Config, present: impl Fn(&IfName) -> bool) -> BTreeSet<IfName> {
    cfg.interfaces
        .values()
        .filter(|i| i.kind == InterfaceKind::Ethernet && !present(&i.name))
        .map(|i| i.name.clone())
        .collect()
}

/// `cfg` without the ports in `gone` and what cannot exist without them
/// (VLANs stacked on them, at any depth), a bond's `primary` that names
/// one of them, and their port tuning. Borrowed when nothing is gone.
pub fn mask<'a>(cfg: &'a Config, gone: &BTreeSet<IfName>) -> Cow<'a, Config> {
    let drop = with_dependents(cfg, gone);
    if drop.is_empty() {
        return Cow::Borrowed(cfg);
    }
    let mut out = cfg.clone();
    out.interfaces.retain(|n, _| !drop.contains(n));
    for i in out.interfaces.values_mut() {
        if let InterfaceKind::Bonding { primary, .. } = &mut i.kind
            && primary.as_ref().is_some_and(|p| drop.contains(p))
        {
            *primary = None;
        }
    }
    if out.system.tuning.ports.keys().any(|n| drop.contains(n)) {
        out.system.tuning.ports.retain(|n, _| !drop.contains(n));
    }
    Cow::Owned(out)
}

/// `gone` (those of them in `cfg`) plus the VLANs stacked on them.
fn with_dependents(cfg: &Config, gone: &BTreeSet<IfName>) -> BTreeSet<IfName> {
    let mut out: BTreeSet<IfName> = gone
        .iter()
        .filter(|n| cfg.interfaces.contains_key(*n))
        .cloned()
        .collect();
    if out.is_empty() {
        return out;
    }
    // Each pass adds at least one name or stops: bounded by the
    // interface count, so a cyclic (hand-edited) config cannot loop.
    for _ in 0..=cfg.interfaces.len() {
        let more: Vec<IfName> = cfg
            .interfaces
            .values()
            .filter(|i| !out.contains(&i.name))
            .filter(
                |i| matches!(&i.kind, InterfaceKind::Vlan { parent, .. } if out.contains(parent)),
            )
            .map(|i| i.name.clone())
            .collect();
        if more.is_empty() {
            break;
        }
        out.extend(more);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::types::VlanId;
    use corerouter_model::{AddressEntry, Interface};

    fn n(s: &str) -> IfName {
        s.parse().unwrap()
    }

    fn cfg() -> Config {
        let mut c = Config::default();
        for p in ["ether1", "ether2", "ether3"] {
            c.interfaces
                .insert(n(p), Interface::new(n(p), InterfaceKind::Ethernet));
        }
        let vlan = |name: &str, parent: &str, id: u16| {
            Interface::new(
                n(name),
                InterfaceKind::Vlan {
                    parent: n(parent),
                    vlan_id: VlanId::new(id).unwrap(),
                    service_tag: false,
                },
            )
        };
        c.interfaces
            .insert(n("vlan10"), vlan("vlan10", "ether2", 10));
        c.interfaces
            .insert(n("vlan20"), vlan("vlan20", "vlan10", 20));
        c.interfaces
            .insert(n("vlan30"), vlan("vlan30", "ether3", 30));
        c.interfaces.insert(
            n("bond1"),
            Interface::new(
                n("bond1"),
                InterfaceKind::Bonding {
                    mode: corerouter_model::BondMode::ActiveBackup,
                    primary: Some(n("ether2")),
                    transmit_hash_policy: Default::default(),
                    lacp_rate: Default::default(),
                    mii_interval_ms: 100,
                    min_links: 0,
                },
            ),
        );
        c.ip.addresses.push(AddressEntry {
            id: Default::default(),
            address: "192.0.2.1/24".parse().unwrap(),
            interface: n("ether3"),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
        c.system
            .tuning
            .ports
            .insert(n("ether2"), [("rx_ring".to_owned(), 512)].into());
        c
    }

    #[test]
    fn missing_counts_only_physical_ports() {
        let c = cfg();
        let have = [n("ether1"), n("ether3")];
        let gone = missing(&c, |p| have.contains(p));
        assert_eq!(gone, [n("ether2")].into());
    }

    #[test]
    fn nothing_gone_borrows() {
        let c = cfg();
        assert!(matches!(mask(&c, &BTreeSet::new()), Cow::Borrowed(_)));
        // A name the config does not have changes nothing either.
        assert!(matches!(mask(&c, &[n("ether9")].into()), Cow::Borrowed(_)));
    }

    #[test]
    fn mask_drops_the_port_and_what_stacks_on_it() {
        let c = cfg();
        let m = mask(&c, &[n("ether2")].into());
        let names: Vec<&str> = m.interfaces.keys().map(IfName::as_str).collect();
        assert_eq!(names, ["bond1", "ether1", "ether3", "vlan30"]);
        let Some(InterfaceKind::Bonding { primary, .. }) =
            m.interfaces.get(&n("bond1")).map(|i| &i.kind)
        else {
            panic!("bond1 kept");
        };
        assert_eq!(*primary, None, "primary named the absent port");
        assert!(m.system.tuning.ports.is_empty());
        // The management address on another port stays.
        assert_eq!(
            crate::drift::active_addresses(&m),
            [(n("ether3"), "192.0.2.1/24".parse().unwrap())].into()
        );
    }
}
