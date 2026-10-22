//! Pure diff `from` → `to` into an ordered list of kernel operations.
//!
//! No kernel, no I/O: the plan is computed and unit-tested on any platform.
//! The netlink executor (`netlink.rs`) runs it in order and, if one step
//! fails, undoes the steps already done in reverse.
//!
//! Order (teardown first, then build):
//! 0. remove static routes that go away (or whose link is rebuilt, below);
//! 1. remove addresses that go away, or whose link is disabled, recreated or
//!    changes master (Linux drops IPv6 addresses of a link that goes down or
//!    joins a VRF);
//! 2. detach bridge ports / VRF members that leave (or change) their master;
//! 3. delete virtual links, VLAN children before their parents;
//! 4. create virtual links, parents before VLAN children;
//! 5. MTU: decreases children-first, then increases parents-first, so a VLAN
//!    never exceeds its parent on the way (nor on the way back, in rollback);
//! 6. attach bridge ports / VRF members;
//! 7. add addresses;
//! 8. admin state up/down, parents first;
//! 9. add static routes that arrive (or whose link was rebuilt).
//!
//! The kernel deletes routes by itself when their link goes down, is
//! recreated, is enslaved to (or released from) a VRF, or loses its last
//! IPv4 address. Those links are "rebuilt": their routes are removed
//! explicitly in step 0 and added again in step 9, so the undo of a failed
//! apply can put every route back, and the kernel never holds a route the
//! running config does not know about. Which routes belong in the kernel is
//! decided by `corerouter_model::route::reach` — the same function behind
//! the A flag of `ip.route.list`.
//!
//! Only interfaces present in `from` or `to` ever appear in the plan, so a
//! host interface outside the config is never touched. Physical ports
//! (`Ethernet`) are configured but never created or deleted.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

use corerouter_hal::HalError;
use corerouter_model::route::{self, Reach};
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
    /// Linux `vrf` (l3mdev) bound to kernel routing table `table`.
    Vrf {
        table: u32,
    },
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
            InterfaceKind::Vrf { table } => Some(Self::Vrf { table: *table }),
        }
    }

    /// Kernel `IFLA_INFO_KIND`.
    pub fn kernel_kind(&self) -> &'static str {
        match self {
            Self::Vlan { .. } => "vlan",
            Self::Bridge => "bridge",
            Self::Dummy => "dummy",
            Self::Vrf { .. } => "vrf",
        }
    }
}

impl fmt::Display for LinkSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vlan { parent, vlan_id } => write!(f, "vlan {vlan_id} on '{parent}'"),
            Self::Bridge => f.write_str("bridge"),
            Self::Dummy => f.write_str("loopback (dummy)"),
            Self::Vrf { table } => write!(f, "vrf (table {table})"),
        }
    }
}

/// A unicast route as the kernel holds it (protocol `static`). `metric` is
/// the RouterOS distance, so the kernel prefers the lowest one, too.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelRoute {
    pub table: u32,
    pub dst: IpNet,
    pub metric: u32,
    pub link: IfName,
    pub gateway: Option<IpAddr>,
}

impl fmt::Display for KernelRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "route {}", self.dst)?;
        if let Some(g) = self.gateway {
            write!(f, " via {g}")?;
        }
        write!(f, " dev '{}' metric {}", self.link, self.metric)?;
        if self.table != route::MAIN_TABLE_ID {
            write!(f, " table {}", self.table)?;
        }
        Ok(())
    }
}

/// One kernel operation. Each one is small enough to undo on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    DelRoute(KernelRoute),
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
    AddRoute(KernelRoute),
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
            Self::DelRoute(r) | Self::AddRoute(r) => &r.link,
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DelAddress { link, addr } => write!(f, "remove address {addr} from '{link}'"),
            Self::SetMaster { link, master: None } => {
                write!(f, "detach '{link}' from its bridge/VRF")
            }
            Self::SetMaster {
                link,
                master: Some(m),
            } => write!(f, "attach '{link}' to '{m}'"),
            Self::DeleteLink { link, spec } => write!(f, "delete {spec} '{link}'"),
            Self::CreateLink { link, spec } => write!(f, "create {spec} '{link}'"),
            Self::SetMtu { link, mtu } => write!(f, "set MTU of '{link}' to {mtu}"),
            Self::AddAddress { link, addr } => write!(f, "add address {addr} to '{link}'"),
            Self::SetUp { link, up: true } => write!(f, "bring '{link}' up"),
            Self::SetUp { link, up: false } => write!(f, "bring '{link}' down"),
            Self::AddRoute(r) => write!(f, "add {r}"),
            Self::DelRoute(r) => write!(f, "remove {r}"),
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

/// Enabled addresses on enabled interfaces of `cfg`, as (link, prefix).
/// A disabled interface keeps none in the kernel: Linux drops the IPv6
/// addresses of a link that goes down (`keep_addr_on_down` is 0 by default),
/// so they are removed explicitly before it goes down — which an undo can
/// reverse — and added again before it comes back up.
fn active_addresses(cfg: &Config) -> BTreeSet<(IfName, IpNet)> {
    cfg.ip
        .addresses
        .iter()
        .filter(|a| {
            !a.disabled
                && cfg
                    .interfaces
                    .get(&a.interface)
                    .is_some_and(|i| !i.disabled)
        })
        .map(|a| (a.interface.clone(), a.address))
        .collect()
}

/// Kernel master of `name` (`IFLA_MASTER`): its bridge or its VRF.
fn master<'a>(cfg: &'a Config, name: &IfName) -> Option<&'a IfName> {
    let i = cfg.interfaces.get(name)?;
    i.bridge.as_ref().or(i.vrf.as_ref())
}

/// Static routes of `cfg` that belong in the kernel: the usable ones.
pub fn kernel_routes(cfg: &Config) -> BTreeSet<KernelRoute> {
    cfg.ip
        .routes
        .iter()
        .filter_map(|r| {
            let Reach::Active { link, gateway } = route::reach(cfg, r) else {
                return None;
            };
            Some(KernelRoute {
                table: route::table_id(cfg, &r.routing_table)?,
                dst: r.dst_address.trunc(),
                metric: u32::from(r.distance),
                link,
                gateway,
            })
        })
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

    // Kept links whose master (bridge or VRF) changes, or whose master is
    // itself deleted or recreated. Enslaving to a VRF cycles the link, which
    // drops its IPv6 addresses, so their addresses are re-added too.
    let remastered: BTreeSet<IfName> = from
        .interfaces
        .keys()
        .filter(|n| kept(n) && to.interfaces.contains_key(*n))
        .filter(|n| {
            let (a, b) = (master(from, n), master(to, n));
            a != b || a.is_some_and(|m| !kept(m))
        })
        .cloned()
        .collect();

    let old_addrs = active_addresses(from);
    let new_addrs = active_addresses(to);
    let rebuilt = rebuilt_links(from, &doomed, &fresh, &remastered, &old_addrs, &new_addrs);

    let mut ops = Vec::new();

    // 0. Routes that go away, or whose link is rebuilt.
    let old_routes = kernel_routes(from);
    let new_routes = kernel_routes(to);
    for r in &old_routes {
        if rebuilt.contains(&r.link) || !new_routes.contains(r) {
            ops.push(Op::DelRoute(r.clone()));
        }
    }

    // 1. Addresses that go away.
    for (link, addr) in &old_addrs {
        if doomed.contains(link)
            || remastered.contains(link)
            || !new_addrs.contains(&(link.clone(), *addr))
        {
            ops.push(Op::DelAddress {
                link: link.clone(),
                addr: *addr,
            });
        }
    }

    // 2. Ports and members that leave (or change) their bridge or VRF.
    for old in from.interfaces.values() {
        let stays = kept(&old.name)
            && to.interfaces.contains_key(&old.name)
            && !remastered.contains(&old.name);
        if master(from, &old.name).is_some() && !stays {
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

    // 6. Ports and members that join (or change) their bridge or VRF.
    for new in to.interfaces.values() {
        let Some(m) = master(to, &new.name) else {
            continue;
        };
        if !kept(&new.name) || remastered.contains(&new.name) {
            ops.push(Op::SetMaster {
                link: new.name.clone(),
                master: Some(m.clone()),
            });
        }
    }

    // 7. Addresses that arrive (or whose link was recreated or remastered).
    for (link, addr) in &new_addrs {
        if fresh.contains(link)
            || remastered.contains(link)
            || !old_addrs.contains(&(link.clone(), *addr))
        {
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

    // 9. Routes that arrive, or whose link was rebuilt.
    for r in &new_routes {
        if rebuilt.contains(&r.link) || !old_routes.contains(r) {
            ops.push(Op::AddRoute(r.clone()));
        }
    }

    Ok(ops)
}

/// Links whose static routes the kernel drops on its own during this plan.
/// (A link going down is not listed: its routes stop being usable, so they
/// leave `kernel_routes` anyway.)
fn rebuilt_links(
    from: &Config,
    doomed: &BTreeSet<IfName>,
    fresh: &BTreeSet<&IfName>,
    remastered: &BTreeSet<IfName>,
    old_addrs: &BTreeSet<(IfName, IpNet)>,
    new_addrs: &BTreeSet<(IfName, IpNet)>,
) -> BTreeSet<IfName> {
    let has_v4 = |set: &BTreeSet<(IfName, IpNet)>, link: &IfName| {
        set.iter()
            .any(|(l, a)| l == link && matches!(a, IpNet::V4(_)))
    };
    let mut out: BTreeSet<IfName> = doomed.iter().chain(remastered).cloned().collect();
    out.extend(fresh.iter().map(|n| (*n).clone()));
    // Linux disables IPv4 on a link that loses its last IPv4 address,
    // flushing every IPv4 route through it.
    out.extend(
        from.interfaces
            .keys()
            .filter(|l| has_v4(old_addrs, l) && !has_v4(new_addrs, l))
            .cloned(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::{AddressEntry, Interface, ItemId, RouteEntry, RoutingTable, VlanId};

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
            from_pool: None,
        });
    }

    fn route(cfg: &mut Config, dst: &str, gw: &str, distance: u8) {
        let id = cfg.ip.next_route_id();
        cfg.ip.routes.push(RouteEntry {
            id,
            dst_address: dst.parse().unwrap(),
            gateway: gw.parse().unwrap(),
            distance,
            routing_table: RoutingTable::Main,
            disabled: false,
            comment: String::new(),
        });
    }

    fn kr(dst: &str, gw: Option<&str>, link: &str, metric: u32, table: u32) -> KernelRoute {
        KernelRoute {
            table,
            dst: dst.parse().unwrap(),
            metric,
            link: n(link),
            gateway: gw.map(|g| g.parse().unwrap()),
        }
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
            from_pool: None,
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

    /// ether1 10.0.0.2/24 + 2001:db8::2/64, default routes via the upstream.
    fn routed() -> Config {
        let mut c = base();
        addr(&mut c, "ether1", "10.0.0.2/24");
        addr(&mut c, "ether1", "2001:db8::2/64");
        route(&mut c, "0.0.0.0/0", "10.0.0.1", 1);
        route(&mut c, "::/0", "2001:db8::1", 1);
        c
    }

    #[test]
    fn routes_come_after_their_address_and_go_before_it() {
        let to = routed();
        let ops = plan(&base(), &to).unwrap();
        let v4 = Op::AddRoute(kr("0.0.0.0/0", Some("10.0.0.1"), "ether1", 1, 254));
        let v6 = Op::AddRoute(kr("::/0", Some("2001:db8::1"), "ether1", 1, 254));
        let address = Op::AddAddress {
            link: n("ether1"),
            addr: "10.0.0.2/24".parse().unwrap(),
        };
        assert!(pos(&ops, &address) < pos(&ops, &v4));
        assert!(pos(&ops, &address) < pos(&ops, &v6));
        assert_eq!(plan(&to, &to).unwrap(), vec![], "nothing to do twice");

        let back = plan(&to, &base()).unwrap();
        let del = Op::DelRoute(kr("0.0.0.0/0", Some("10.0.0.1"), "ether1", 1, 254));
        let del_addr = Op::DelAddress {
            link: n("ether1"),
            addr: "10.0.0.2/24".parse().unwrap(),
        };
        assert!(pos(&back, &del) < pos(&back, &del_addr));
    }

    #[test]
    fn changing_a_route_replaces_only_that_route() {
        let from = routed();
        let mut to = from.clone();
        to.ip.routes.first_mut().unwrap().distance = 5;
        assert_eq!(
            plan(&from, &to).unwrap(),
            vec![
                Op::DelRoute(kr("0.0.0.0/0", Some("10.0.0.1"), "ether1", 1, 254)),
                Op::AddRoute(kr("0.0.0.0/0", Some("10.0.0.1"), "ether1", 5, 254)),
            ]
        );
        // A disabled route leaves the kernel; an interface route needs no address.
        let mut to = from.clone();
        to.ip.routes.first_mut().unwrap().disabled = true;
        route(&mut to, "198.51.100.0/24", "ether2", 3);
        assert_eq!(
            plan(&from, &to).unwrap(),
            vec![
                Op::DelRoute(kr("0.0.0.0/0", Some("10.0.0.1"), "ether1", 1, 254)),
                Op::AddRoute(kr("198.51.100.0/24", None, "ether2", 3, 254)),
            ]
        );
    }

    #[test]
    fn link_down_and_up_removes_and_restores_its_routes() {
        let from = routed();
        let mut down = from.clone();
        down.interfaces.get_mut(&n("ether1")).unwrap().disabled = true;
        let ops = plan(&from, &down).unwrap();
        let del = Op::DelRoute(kr("0.0.0.0/0", Some("10.0.0.1"), "ether1", 1, 254));
        let off = Op::SetUp {
            link: n("ether1"),
            up: false,
        };
        // Removed explicitly before the kernel would flush them, so an undo
        // can bring them back.
        let del6 = Op::DelAddress {
            link: n("ether1"),
            addr: "2001:db8::2/64".parse().unwrap(),
        };
        assert!(pos(&ops, &del) < pos(&ops, &del6) && pos(&ops, &del6) < pos(&ops, &off));
        let ops = plan(&down, &from).unwrap();
        let on = Op::SetUp {
            link: n("ether1"),
            up: true,
        };
        let add = Op::AddRoute(kr("0.0.0.0/0", Some("10.0.0.1"), "ether1", 1, 254));
        let add6 = Op::AddAddress {
            link: n("ether1"),
            addr: "2001:db8::2/64".parse().unwrap(),
        };
        assert!(pos(&ops, &add6) < pos(&ops, &on) && pos(&ops, &on) < pos(&ops, &add));
    }

    #[test]
    fn losing_the_last_ipv4_address_reinstalls_the_links_routes() {
        let mut from = base();
        addr(&mut from, "ether2", "192.0.2.1/24");
        route(&mut from, "198.51.100.0/24", "ether2", 1);
        let mut to = from.clone();
        to.ip.addresses.clear();
        let r = kr("198.51.100.0/24", None, "ether2", 1, 254);
        assert_eq!(
            plan(&from, &to).unwrap(),
            vec![
                Op::DelRoute(r.clone()),
                Op::DelAddress {
                    link: n("ether2"),
                    addr: "192.0.2.1/24".parse().unwrap()
                },
                Op::AddRoute(r),
            ]
        );
    }

    #[test]
    fn joining_a_vrf_moves_addresses_and_routes_to_its_table() {
        let mut from = base();
        addr(&mut from, "ether2", "10.9.0.2/24");
        addr(&mut from, "ether2", "2001:db8:9::2/64");
        let mut to = from.clone();
        add(&mut to, "blue", InterfaceKind::Vrf { table: 1000 });
        to.interfaces.get_mut(&n("ether2")).unwrap().vrf = Some(n("blue"));
        route(&mut to, "10.50.0.0/16", "10.9.0.1", 1);
        to.ip.routes.first_mut().unwrap().routing_table = RoutingTable::Vrf(n("blue"));
        let ops = plan(&from, &to).unwrap();

        let create = pos(
            &ops,
            &Op::CreateLink {
                link: n("blue"),
                spec: LinkSpec::Vrf { table: 1000 },
            },
        );
        let del6 = pos(
            &ops,
            &Op::DelAddress {
                link: n("ether2"),
                addr: "2001:db8:9::2/64".parse().unwrap(),
            },
        );
        let enslave = pos(
            &ops,
            &Op::SetMaster {
                link: n("ether2"),
                master: Some(n("blue")),
            },
        );
        let add6 = pos(
            &ops,
            &Op::AddAddress {
                link: n("ether2"),
                addr: "2001:db8:9::2/64".parse().unwrap(),
            },
        );
        let up = pos(
            &ops,
            &Op::SetUp {
                link: n("blue"),
                up: true,
            },
        );
        let rt = pos(
            &ops,
            &Op::AddRoute(kr("10.50.0.0/16", Some("10.9.0.1"), "ether2", 1, 1000)),
        );
        assert!(del6 < create && create < enslave && enslave < add6 && add6 < up && up < rt);

        // Leaving it: routes out first, VRF gone last.
        let back = plan(&to, &from).unwrap();
        let del_rt = pos(
            &back,
            &Op::DelRoute(kr("10.50.0.0/16", Some("10.9.0.1"), "ether2", 1, 1000)),
        );
        let release = pos(
            &back,
            &Op::SetMaster {
                link: n("ether2"),
                master: None,
            },
        );
        let delete = pos(
            &back,
            &Op::DeleteLink {
                link: n("blue"),
                spec: LinkSpec::Vrf { table: 1000 },
            },
        );
        assert!(del_rt < release && release < delete);
    }
}
