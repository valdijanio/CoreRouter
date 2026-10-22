//! Pure diff `from` → `to` into an ordered list of kernel operations.
//!
//! No kernel, no I/O: the plan is computed and unit-tested on any platform.
//! The netlink executor (`netlink.rs`) runs it in order and, if one step
//! fails, undoes the steps already done in reverse.
//!
//! Order (teardown first, then build):
//! 1. remove addresses that go away (or whose link is recreated);
//! 2. detach bridge ports that leave (or change) their bridge;
//! 3. delete virtual links, VLAN children before their parents;
//! 4. create virtual links, parents before VLAN children;
//! 5. MTU: decreases children-first, then increases parents-first, so a VLAN
//!    never exceeds its parent on the way (nor on the way back, in rollback);
//! 6. attach bridge ports;
//! 7. add addresses;
//! 8. admin state up/down, parents first.
//!
//! Only interfaces present in `from` or `to` ever appear in the plan, so a
//! host interface outside the config is never touched. Physical ports
//! (`Ethernet`) are configured but never created or deleted.

use std::collections::BTreeSet;
use std::fmt;

use corerouter_hal::HalError;
use corerouter_model::{Config, IfName, InterfaceKind};
use ipnet::IpNet;

/// A link CoreRouter creates and deletes itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkSpec {
    /// 802.1Q VLAN on top of `parent`.
    Vlan {
        parent: IfName,
        vlan_id: u16,
    },
    Bridge,
    /// Linux `dummy`: what a RouterOS-style loopback is in the kernel.
    Dummy,
}

impl LinkSpec {
    /// `None` for physical ports, which already exist and are never created.
    pub fn of(kind: &InterfaceKind) -> Option<Self> {
        match kind {
            InterfaceKind::Ethernet => None,
            InterfaceKind::Vlan { parent, vlan_id } => Some(Self::Vlan {
                parent: parent.clone(),
                vlan_id: vlan_id.get(),
            }),
            InterfaceKind::Bridge => Some(Self::Bridge),
            InterfaceKind::Loopback => Some(Self::Dummy),
        }
    }

    /// Kernel `IFLA_INFO_KIND`.
    pub fn kernel_kind(&self) -> &'static str {
        match self {
            Self::Vlan { .. } => "vlan",
            Self::Bridge => "bridge",
            Self::Dummy => "dummy",
        }
    }
}

impl fmt::Display for LinkSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vlan { parent, vlan_id } => write!(f, "vlan {vlan_id} on '{parent}'"),
            Self::Bridge => f.write_str("bridge"),
            Self::Dummy => f.write_str("loopback (dummy)"),
        }
    }
}

/// One kernel operation. Each one is small enough to undo on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    DelAddress {
        link: IfName,
        addr: IpNet,
    },
    SetMaster {
        link: IfName,
        master: Option<IfName>,
    },
    DeleteLink {
        link: IfName,
        spec: LinkSpec,
    },
    CreateLink {
        link: IfName,
        spec: LinkSpec,
    },
    /// `u32` like the kernel: `lo` has MTU 65536, and undo must restore it.
    SetMtu {
        link: IfName,
        mtu: u32,
    },
    AddAddress {
        link: IfName,
        addr: IpNet,
    },
    SetUp {
        link: IfName,
        up: bool,
    },
}

impl Op {
    pub fn link(&self) -> &IfName {
        match self {
            Self::DelAddress { link, .. }
            | Self::SetMaster { link, .. }
            | Self::DeleteLink { link, .. }
            | Self::CreateLink { link, .. }
            | Self::SetMtu { link, .. }
            | Self::AddAddress { link, .. }
            | Self::SetUp { link, .. } => link,
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DelAddress { link, addr } => write!(f, "remove address {addr} from '{link}'"),
            Self::SetMaster { link, master: None } => {
                write!(f, "detach '{link}' from its bridge")
            }
            Self::SetMaster {
                link,
                master: Some(m),
            } => write!(f, "attach '{link}' to bridge '{m}'"),
            Self::DeleteLink { link, spec } => write!(f, "delete {spec} '{link}'"),
            Self::CreateLink { link, spec } => write!(f, "create {spec} '{link}'"),
            Self::SetMtu { link, mtu } => write!(f, "set MTU of '{link}' to {mtu}"),
            Self::AddAddress { link, addr } => write!(f, "add address {addr} to '{link}'"),
            Self::SetUp { link, up: true } => write!(f, "bring '{link}' up"),
            Self::SetUp { link, up: false } => write!(f, "bring '{link}' down"),
        }
    }
}

/// Number of VLAN hops under `name` (0 for anything that is not a VLAN).
/// Bounded by the interface count, so a cyclic config cannot loop forever.
fn depth(cfg: &Config, name: &IfName) -> usize {
    let mut d = 0;
    let mut cur = name;
    while let Some(InterfaceKind::Vlan { parent, .. }) = cfg.interfaces.get(cur).map(|i| &i.kind) {
        d += 1;
        if d > cfg.interfaces.len() {
            break;
        }
        cur = parent;
    }
    d
}

/// Enabled addresses on interfaces that exist in `cfg`, as (link, prefix).
fn active_addresses(cfg: &Config) -> BTreeSet<(IfName, IpNet)> {
    cfg.ip
        .addresses
        .iter()
        .filter(|a| !a.disabled && cfg.interfaces.contains_key(&a.interface))
        .map(|a| (a.interface.clone(), a.address))
        .collect()
}

/// Virtual links of `from` that must be deleted: gone from `to`, changed
/// spec, or stacked (VLAN) on a link that is itself deleted, since the
/// kernel removes VLANs together with their parent.
fn doomed(from: &Config, to: &Config) -> Result<BTreeSet<IfName>, HalError> {
    let mut out = BTreeSet::new();
    for (name, old) in &from.interfaces {
        let old_spec = LinkSpec::of(&old.kind);
        let new_spec = to.interfaces.get(name).map(|i| LinkSpec::of(&i.kind));
        match (&old_spec, &new_spec) {
            (None, Some(Some(s))) => {
                return Err(HalError::Rejected(format!(
                    "'{name}' is a physical port and cannot become a {s}"
                )));
            }
            (Some(s), Some(None)) => {
                return Err(HalError::Rejected(format!(
                    "'{name}' is a {s} and cannot become a physical port"
                )));
            }
            (Some(_), None) => {
                out.insert(name.clone());
            }
            (Some(a), Some(Some(b))) if a != b => {
                out.insert(name.clone());
            }
            _ => {}
        }
    }
    // Cascade to VLAN children; each pass adds at least one name or stops.
    for _ in 0..=from.interfaces.len() {
        let more: Vec<IfName> = from
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
    Ok(out)
}

/// The ordered operations that take the kernel from `from` to `to`.
pub fn plan(from: &Config, to: &Config) -> Result<Vec<Op>, HalError> {
    let doomed = doomed(from, to)?;
    // Links of `to` created by this plan: new virtual links and recreated ones.
    let fresh: BTreeSet<&IfName> = to
        .interfaces
        .values()
        .filter(|i| LinkSpec::of(&i.kind).is_some())
        .filter(|i| !from.interfaces.contains_key(&i.name) || doomed.contains(&i.name))
        .map(|i| &i.name)
        .collect();
    // State of `from` that survives into the build phase.
    let kept = |name: &IfName| from.interfaces.contains_key(name) && !doomed.contains(name);

    let mut ops = Vec::new();

    // 1. Addresses that go away.
    let old_addrs = active_addresses(from);
    let new_addrs = active_addresses(to);
    for (link, addr) in &old_addrs {
        if doomed.contains(link) || !new_addrs.contains(&(link.clone(), *addr)) {
            ops.push(Op::DelAddress {
                link: link.clone(),
                addr: *addr,
            });
        }
    }

    // 2. Ports that leave (or change) their bridge.
    for old in from.interfaces.values() {
        let Some(bridge) = &old.bridge else { continue };
        let stays = kept(&old.name)
            && kept(bridge)
            && to.interfaces.get(&old.name).and_then(|i| i.bridge.as_ref()) == Some(bridge);
        if !stays {
            ops.push(Op::SetMaster {
                link: old.name.clone(),
                master: None,
            });
        }
    }

    // 3. Delete, VLAN children first.
    let mut dels: Vec<&IfName> = doomed.iter().collect();
    dels.sort_by_key(|n| std::cmp::Reverse(depth(from, n)));
    for name in dels {
        if let Some(spec) = from
            .interfaces
            .get(name)
            .and_then(|i| LinkSpec::of(&i.kind))
        {
            ops.push(Op::DeleteLink {
                link: name.clone(),
                spec,
            });
        }
    }

    // 4. Create, parents first.
    let mut adds: Vec<&IfName> = fresh.iter().copied().collect();
    adds.sort_by_key(|n| depth(to, n));
    for name in adds {
        if let Some(spec) = to.interfaces.get(name).and_then(|i| LinkSpec::of(&i.kind)) {
            ops.push(Op::CreateLink {
                link: name.clone(),
                spec,
            });
        }
    }

    // 5. MTU. Unknown old value (new port, fresh link) counts as "increase";
    //    the executor skips a change that is already in place.
    let mut down = Vec::new();
    let mut up = Vec::new();
    for new in to.interfaces.values() {
        let old = from
            .interfaces
            .get(&new.name)
            .filter(|_| kept(&new.name))
            .map(|i| i.mtu);
        match old {
            Some(o) if o == new.mtu => {}
            Some(o) if new.mtu < o => down.push((depth(to, &new.name), new)),
            _ => up.push((depth(to, &new.name), new)),
        }
    }
    down.sort_by_key(|(d, _)| std::cmp::Reverse(*d));
    up.sort_by_key(|(d, _)| *d);
    for (_, i) in down.into_iter().chain(up) {
        ops.push(Op::SetMtu {
            link: i.name.clone(),
            mtu: u32::from(i.mtu),
        });
    }

    // 6. Ports that join (or change) their bridge.
    for new in to.interfaces.values() {
        let Some(bridge) = &new.bridge else { continue };
        let already = kept(&new.name)
            && kept(bridge)
            && from
                .interfaces
                .get(&new.name)
                .and_then(|i| i.bridge.as_ref())
                == Some(bridge);
        if !already {
            ops.push(Op::SetMaster {
                link: new.name.clone(),
                master: Some(bridge.clone()),
            });
        }
    }

    // 7. Addresses that arrive (or whose link was recreated).
    for (link, addr) in &new_addrs {
        if fresh.contains(link) || !old_addrs.contains(&(link.clone(), *addr)) {
            ops.push(Op::AddAddress {
                link: link.clone(),
                addr: *addr,
            });
        }
    }

    // 8. Admin state, parents first.
    let mut states: Vec<(usize, &IfName, bool)> = to
        .interfaces
        .values()
        .filter(|new| {
            fresh.contains(&new.name)
                || from
                    .interfaces
                    .get(&new.name)
                    .is_none_or(|old| old.disabled != new.disabled)
        })
        .map(|i| (depth(to, &i.name), &i.name, !i.disabled))
        .collect();
    states.sort_by_key(|(d, _, _)| *d);
    for (_, name, up) in states {
        ops.push(Op::SetUp {
            link: name.clone(),
            up,
        });
    }

    Ok(ops)
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::{AddressEntry, Interface, ItemId, VlanId};

    fn n(s: &str) -> IfName {
        s.parse().unwrap()
    }

    fn eth(cfg: &mut Config, name: &str) {
        cfg.interfaces
            .insert(n(name), Interface::new(n(name), InterfaceKind::Ethernet));
    }

    fn add(cfg: &mut Config, name: &str, kind: InterfaceKind) {
        cfg.interfaces
            .insert(n(name), Interface::new(n(name), kind));
    }

    fn vlan(parent: &str, id: u16) -> InterfaceKind {
        InterfaceKind::Vlan {
            parent: n(parent),
            vlan_id: VlanId::new(id).unwrap(),
        }
    }

    fn addr(cfg: &mut Config, iface: &str, a: &str) {
        let id = cfg.ip.next_address_id();
        cfg.ip.addresses.push(AddressEntry {
            id,
            address: a.parse().unwrap(),
            interface: n(iface),
            disabled: false,
            comment: String::new(),
        });
    }

    fn base() -> Config {
        let mut c = Config::default();
        eth(&mut c, "ether1");
        eth(&mut c, "ether2");
        c
    }

    fn pos(ops: &[Op], want: &Op) -> usize {
        ops.iter()
            .position(|o| o == want)
            .unwrap_or_else(|| panic!("missing {want} in {ops:#?}"))
    }

    #[test]
    fn same_config_is_empty_plan() {
        let mut c = base();
        add(&mut c, "vlan10", vlan("ether1", 10));
        addr(&mut c, "vlan10", "10.0.0.1/24");
        assert_eq!(plan(&c, &c).unwrap(), vec![]);
    }

    #[test]
    fn build_order_is_create_ports_addresses_up() {
        let from = base();
        let mut to = base();
        add(&mut to, "br0", InterfaceKind::Bridge);
        add(&mut to, "vlan10", vlan("br0", 10));
        add(&mut to, "lo0", InterfaceKind::Loopback);
        to.interfaces.get_mut(&n("ether2")).unwrap().bridge = Some(n("br0"));
        addr(&mut to, "vlan10", "10.0.0.1/24");
        addr(&mut to, "lo0", "2001:db8::1/128");
        let ops = plan(&from, &to).unwrap();

        let create_br = pos(
            &ops,
            &Op::CreateLink {
                link: n("br0"),
                spec: LinkSpec::Bridge,
            },
        );
        let create_vlan = pos(
            &ops,
            &Op::CreateLink {
                link: n("vlan10"),
                spec: LinkSpec::Vlan {
                    parent: n("br0"),
                    vlan_id: 10,
                },
            },
        );
        let attach = pos(
            &ops,
            &Op::SetMaster {
                link: n("ether2"),
                master: Some(n("br0")),
            },
        );
        let address = pos(
            &ops,
            &Op::AddAddress {
                link: n("vlan10"),
                addr: "10.0.0.1/24".parse().unwrap(),
            },
        );
        let up = pos(
            &ops,
            &Op::SetUp {
                link: n("vlan10"),
                up: true,
            },
        );
        assert!(create_br < create_vlan, "parent before VLAN");
        assert!(create_vlan < attach && attach < address && address < up);
        assert!(ops.contains(&Op::CreateLink {
            link: n("lo0"),
            spec: LinkSpec::Dummy
        }));
        // Physical ports are never created, and untouched ones get no ops.
        assert!(!ops.iter().any(|o| o.link() == &n("ether1")));
        assert!(
            !ops.iter()
                .any(|o| matches!(o, Op::CreateLink { link, .. } if link == &n("ether2")))
        );
    }

    #[test]
    fn teardown_is_the_reverse() {
        let mut from = base();
        add(&mut from, "br0", InterfaceKind::Bridge);
        add(&mut from, "vlan10", vlan("br0", 10));
        add(&mut from, "vlan11", vlan("vlan10", 11));
        from.interfaces.get_mut(&n("ether2")).unwrap().bridge = Some(n("br0"));
        addr(&mut from, "vlan11", "10.1.1.1/24");
        let to = base();
        let ops = plan(&from, &to).unwrap();
        assert_eq!(
            ops,
            vec![
                Op::DelAddress {
                    link: n("vlan11"),
                    addr: "10.1.1.1/24".parse().unwrap()
                },
                Op::SetMaster {
                    link: n("ether2"),
                    master: None
                },
                Op::DeleteLink {
                    link: n("vlan11"),
                    spec: LinkSpec::Vlan {
                        parent: n("vlan10"),
                        vlan_id: 11
                    }
                },
                Op::DeleteLink {
                    link: n("vlan10"),
                    spec: LinkSpec::Vlan {
                        parent: n("br0"),
                        vlan_id: 10
                    }
                },
                Op::DeleteLink {
                    link: n("br0"),
                    spec: LinkSpec::Bridge
                },
            ]
        );
    }

    #[test]
    fn recreating_a_parent_recreates_its_vlans_and_their_addresses() {
        let mut from = base();
        add(&mut from, "vlan10", vlan("ether1", 10));
        add(&mut from, "vlan100", vlan("vlan10", 100));
        addr(&mut from, "vlan100", "10.0.0.1/24");
        let mut to = from.clone();
        // Same name, new VLAN id: the kernel cannot change it in place.
        to.interfaces.get_mut(&n("vlan10")).unwrap().kind = vlan("ether1", 20);
        let ops = plan(&from, &to).unwrap();
        let a: IpNet = "10.0.0.1/24".parse().unwrap();
        let del_addr = pos(
            &ops,
            &Op::DelAddress {
                link: n("vlan100"),
                addr: a,
            },
        );
        let del_child = pos(
            &ops,
            &Op::DeleteLink {
                link: n("vlan100"),
                spec: LinkSpec::Vlan {
                    parent: n("vlan10"),
                    vlan_id: 100,
                },
            },
        );
        let del_parent = pos(
            &ops,
            &Op::DeleteLink {
                link: n("vlan10"),
                spec: LinkSpec::Vlan {
                    parent: n("ether1"),
                    vlan_id: 10,
                },
            },
        );
        let add_parent = pos(
            &ops,
            &Op::CreateLink {
                link: n("vlan10"),
                spec: LinkSpec::Vlan {
                    parent: n("ether1"),
                    vlan_id: 20,
                },
            },
        );
        let add_child = pos(
            &ops,
            &Op::CreateLink {
                link: n("vlan100"),
                spec: LinkSpec::Vlan {
                    parent: n("vlan10"),
                    vlan_id: 100,
                },
            },
        );
        let add_addr = pos(
            &ops,
            &Op::AddAddress {
                link: n("vlan100"),
                addr: a,
            },
        );
        assert!(del_addr < del_child && del_child < del_parent);
        assert!(del_parent < add_parent && add_parent < add_child && add_child < add_addr);
    }

    #[test]
    fn mtu_decreases_children_first_and_increases_parents_first() {
        let mut from = base();
        add(&mut from, "vlan10", vlan("ether1", 10));
        from.interfaces.get_mut(&n("ether1")).unwrap().mtu = 9000;
        from.interfaces.get_mut(&n("vlan10")).unwrap().mtu = 9000;
        let mut to = from.clone();
        to.interfaces.get_mut(&n("ether1")).unwrap().mtu = 1500;
        to.interfaces.get_mut(&n("vlan10")).unwrap().mtu = 1500;
        assert_eq!(
            plan(&from, &to).unwrap(),
            vec![
                Op::SetMtu {
                    link: n("vlan10"),
                    mtu: 1500
                },
                Op::SetMtu {
                    link: n("ether1"),
                    mtu: 1500
                },
            ]
        );
        assert_eq!(
            plan(&to, &from).unwrap(),
            vec![
                Op::SetMtu {
                    link: n("ether1"),
                    mtu: 9000
                },
                Op::SetMtu {
                    link: n("vlan10"),
                    mtu: 9000
                },
            ]
        );
    }

    #[test]
    fn address_changes_are_minimal() {
        let mut from = base();
        addr(&mut from, "ether1", "10.0.0.1/24");
        addr(&mut from, "ether1", "10.0.1.1/24");
        let mut to = base();
        addr(&mut to, "ether1", "10.0.1.1/24");
        addr(&mut to, "ether1", "2001:db8::1/64");
        // Disabled entries and entries on unknown interfaces are ignored.
        addr(&mut to, "ether2", "10.9.9.9/24");
        to.ip.addresses.last_mut().unwrap().disabled = true;
        to.ip.addresses.push(AddressEntry {
            id: ItemId(99),
            address: "10.8.8.8/24".parse().unwrap(),
            interface: n("host0"),
            disabled: false,
            comment: String::new(),
        });
        assert_eq!(
            plan(&from, &to).unwrap(),
            vec![
                Op::DelAddress {
                    link: n("ether1"),
                    addr: "10.0.0.1/24".parse().unwrap()
                },
                Op::AddAddress {
                    link: n("ether1"),
                    addr: "2001:db8::1/64".parse().unwrap()
                },
            ]
        );
    }

    #[test]
    fn admin_state_follows_disabled() {
        let from = base();
        let mut to = base();
        to.interfaces.get_mut(&n("ether2")).unwrap().disabled = true;
        assert_eq!(
            plan(&from, &to).unwrap(),
            vec![Op::SetUp {
                link: n("ether2"),
                up: false
            }]
        );
    }

    #[test]
    fn newly_managed_port_gets_mtu_and_state() {
        // Session::new applies Config::default() → discovered ports.
        let to = base();
        let ops = plan(&Config::default(), &to).unwrap();
        assert!(ops.contains(&Op::SetMtu {
            link: n("ether1"),
            mtu: 1500
        }));
        assert!(ops.contains(&Op::SetUp {
            link: n("ether1"),
            up: true
        }));
        assert!(!ops.iter().any(|o| matches!(o, Op::CreateLink { .. })));
    }

    #[test]
    fn moving_a_port_between_bridges_detaches_then_attaches() {
        let mut from = base();
        add(&mut from, "br0", InterfaceKind::Bridge);
        add(&mut from, "br1", InterfaceKind::Bridge);
        from.interfaces.get_mut(&n("ether1")).unwrap().bridge = Some(n("br0"));
        let mut to = from.clone();
        to.interfaces.get_mut(&n("ether1")).unwrap().bridge = Some(n("br1"));
        assert_eq!(
            plan(&from, &to).unwrap(),
            vec![
                Op::SetMaster {
                    link: n("ether1"),
                    master: None
                },
                Op::SetMaster {
                    link: n("ether1"),
                    master: Some(n("br1"))
                },
            ]
        );
    }

    #[test]
    fn physical_port_cannot_change_kind() {
        let from = base();
        let mut to = base();
        add(&mut to, "ether1", InterfaceKind::Bridge);
        let err = plan(&from, &to).unwrap_err();
        assert!(err.to_string().contains("physical port"), "{err}");
        let err = plan(&to, &from).unwrap_err();
        assert!(err.to_string().contains("physical port"), "{err}");
    }

    #[test]
    fn cyclic_vlans_do_not_hang() {
        // Validation rejects this, but the planner must still terminate.
        let mut from = base();
        add(&mut from, "a", vlan("b", 1));
        add(&mut from, "b", vlan("a", 2));
        let ops = plan(&from, &base()).unwrap();
        assert_eq!(
            ops.iter()
                .filter(|o| matches!(o, Op::DeleteLink { .. }))
                .count(),
            2
        );
    }
}
