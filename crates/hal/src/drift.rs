//! Drift: the data plane no longer holds what the applied config put there
//! (G1.3). Someone ran `ip addr del`, a script flushed a route, a VLAN was
//! deleted by hand, a link went down.
//!
//! [`expected`] says what a config puts in the data plane, in the same terms
//! a backend reads it back ([`Snapshot`]); [`diff`] lists the differences.
//! Only what CoreRouter owns is compared: the links of the config, the
//! addresses on them and the static routes through them. Another program's
//! link, an address the kernel made itself (SLAAC, IPv6 link-local) or a
//! route of another protocol is never drift.
//!
//! The rules (which addresses and routes are "active") are the ones the
//! Linux plan applies with (`hal-linux` `plan`), so a config applied without
//! errors has no drift.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use corerouter_model::os_loopback::{is_os_address, is_os_loopback};
use corerouter_model::route::{self, Reach};
use corerouter_model::routes::Dst;
use corerouter_model::{Config, IfName, InterfaceKind, RouteEntry};
use ipnet::IpNet;
use serde::Serialize;

/// A unicast route as the kernel holds it (protocol `static`). `metric` is
/// the RouterOS distance, so the kernel prefers the lowest one, too.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

/// One link as the drift check sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSnap {
    /// Administratively up.
    pub up: bool,
    /// `u32` like the kernel.
    pub mtu: u32,
    /// Bridge or VRF it is enslaved to.
    pub master: Option<IfName>,
}

/// What the data plane holds, restricted to what CoreRouter manages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub links: BTreeMap<IfName, LinkSnap>,
    pub addresses: BTreeSet<(IfName, IpNet)>,
    pub routes: BTreeSet<KernelRoute>,
}

/// Enabled addresses on enabled interfaces of `cfg`, as (link, prefix).
/// A disabled interface keeps none in the kernel: Linux drops the IPv6
/// addresses of a link that goes down (`keep_addr_on_down` is 0 by default),
/// so they are removed explicitly before it goes down — which an undo can
/// reverse — and added again before it comes back up. The OS's 127.0.0.0/8
/// and ::1 on its `lo` are never CoreRouter's (G3.4i, `os_loopback`).
pub fn active_addresses(cfg: &Config) -> BTreeSet<(IfName, IpNet)> {
    cfg.ip
        .addresses
        .iter()
        .filter(|a| {
            !a.disabled
                && cfg
                    .interfaces
                    .get(&a.interface)
                    .is_some_and(|i| !i.disabled)
                && !(is_os_loopback(cfg, &a.interface) && is_os_address(&a.address))
        })
        .map(|a| (a.interface.clone(), a.address))
        .collect()
}

/// Kernel master of `name` (`IFLA_MASTER`): its bridge, bond (G1.8) or VRF.
pub fn master<'a>(cfg: &'a Config, name: &IfName) -> Option<&'a IfName> {
    let i = cfg.interfaces.get(name)?;
    i.bridge.as_ref().or(i.bond.as_ref()).or(i.vrf.as_ref())
}

/// Static routes of `cfg` that belong in the kernel: the usable ones.
/// Which ones those are is `corerouter_model::route::reach` — the same
/// function behind the A flag of `ip.route.list`.
pub fn kernel_routes(cfg: &Config) -> BTreeSet<KernelRoute> {
    kernel_routes_of(cfg, cfg.ip.routes.iter())
}

/// [`kernel_routes`] of some of the routes of `cfg`.
pub fn kernel_routes_of<'a>(
    cfg: &Config,
    routes: impl Iterator<Item = &'a RouteEntry>,
) -> BTreeSet<KernelRoute> {
    routes
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

/// [`kernel_routes`] of the routes of `cfg` to the destinations `dsts`,
/// found through the index of `ip.routes` (G0.31e).
pub fn kernel_routes_to<'a>(
    cfg: &Config,
    dsts: impl IntoIterator<Item = &'a Dst>,
) -> BTreeSet<KernelRoute> {
    kernel_routes_of(
        cfg,
        dsts.into_iter().flat_map(|d| cfg.ip.routes.routes_to(d)),
    )
}

/// The kernel routes a commit from `from` to `to` removes and adds, as
/// (gone, new), resolving only the destinations it touched (G0.31e: one
/// route among 60 000 resolved ~128, not 120 000). A route resolves
/// through the interfaces and addresses only (`route::reach`): with those
/// the same, a route in a block both configs share resolves the same on
/// both sides. `None` when they changed: compare [`kernel_routes`] whole.
pub fn route_changes(
    from: &Config,
    to: &Config,
) -> Option<(BTreeSet<KernelRoute>, BTreeSet<KernelRoute>)> {
    let addresses_same =
        corerouter_model::cow_list::CowList::ptr_eq(&from.ip.addresses, &to.ip.addresses)
            || from.ip.addresses == to.ip.addresses;
    if corerouter_model::sections::interfaces_changed(from, to) || !addresses_same {
        return None;
    }
    let dsts = to.ip.routes.changed_dsts(&from.ip.routes);
    let (old, new) = (kernel_routes_to(from, &dsts), kernel_routes_to(to, &dsts));
    Some((
        old.difference(&new).cloned().collect(),
        new.difference(&old).cloned().collect(),
    ))
}

/// What applying `cfg` leaves in the data plane.
pub fn expected(cfg: &Config) -> Snapshot {
    Snapshot {
        links: expected_links(cfg),
        addresses: active_addresses(cfg),
        routes: kernel_routes(cfg),
    }
}

/// The links part of [`expected`].
pub fn expected_links(cfg: &Config) -> BTreeMap<IfName, LinkSnap> {
    cfg.interfaces
        .values()
        .map(|i| {
            let snap = LinkSnap {
                up: !i.disabled,
                mtu: u32::from(i.mtu),
                master: master(cfg, &i.name).cloned(),
            };
            (i.name.clone(), snap)
        })
        .collect()
}

/// What drifted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DriftKind {
    /// A link of the config is gone (or is no longer CoreRouter's).
    LinkMissing,
    /// Up where the config says disabled, or down where it says enabled.
    AdminState,
    Mtu,
    /// Bridge or VRF membership.
    Master,
    AddressMissing,
    /// An address on a managed link that the config does not have.
    AddressExtra,
    RouteMissing,
    /// A static route through a managed link that the config does not have.
    RouteExtra,
}

/// One difference between the config and the data plane.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Drift {
    pub kind: DriftKind,
    pub interface: IfName,
    /// What it is about: `ether1`, `10.0.0.1/24`, `route 0.0.0.0/0 via …`.
    pub item: String,
    /// What the config says; empty when it says nothing (an extra item).
    pub expected: String,
    /// What the data plane has; empty when it has nothing (a missing item).
    pub actual: String,
}

fn up_text(up: bool) -> String {
    if up { "up" } else { "down" }.into()
}

fn master_text(m: Option<&IfName>) -> String {
    m.map_or_else(|| "none".into(), ToString::to_string)
}

/// Differences between `want` (from [`expected`]) and `have` (read from
/// the data plane). Addresses and routes of `have` count only on links of
/// `want`; IPv6 link-local addresses the config does not list are the
/// kernel's own. A missing link is reported once, without its addresses
/// and routes. Sorted, so the same drift is listed the same way each time.
pub fn diff(want: &Snapshot, have: &Snapshot) -> Vec<Drift> {
    let mut out = Vec::new();
    for (name, w) in &want.links {
        let Some(h) = have.links.get(name) else {
            out.push(Drift {
                kind: DriftKind::LinkMissing,
                interface: name.clone(),
                item: name.to_string(),
                expected: "present".into(),
                actual: String::new(),
            });
            continue;
        };
        let mut push = |kind, expected: String, actual: String| {
            out.push(Drift {
                kind,
                interface: name.clone(),
                item: name.to_string(),
                expected,
                actual,
            });
        };
        if w.up != h.up {
            push(DriftKind::AdminState, up_text(w.up), up_text(h.up));
        }
        if w.mtu != h.mtu {
            push(DriftKind::Mtu, w.mtu.to_string(), h.mtu.to_string());
        }
        if w.master != h.master {
            push(
                DriftKind::Master,
                master_text(w.master.as_ref()),
                master_text(h.master.as_ref()),
            );
        }
    }
    let present = |l: &IfName| have.links.contains_key(l);
    let managed = |l: &IfName| want.links.contains_key(l);
    for (link, addr) in want.addresses.difference(&have.addresses) {
        if present(link) {
            out.push(Drift {
                kind: DriftKind::AddressMissing,
                interface: link.clone(),
                item: addr.to_string(),
                expected: "present".into(),
                actual: String::new(),
            });
        }
    }
    for (link, addr) in have.addresses.difference(&want.addresses) {
        let link_local = matches!(addr, IpNet::V6(v6) if v6.addr().is_unicast_link_local());
        if managed(link) && !link_local {
            out.push(Drift {
                kind: DriftKind::AddressExtra,
                interface: link.clone(),
                item: addr.to_string(),
                expected: String::new(),
                actual: "present".into(),
            });
        }
    }
    for r in want.routes.difference(&have.routes) {
        if present(&r.link) {
            out.push(Drift {
                kind: DriftKind::RouteMissing,
                interface: r.link.clone(),
                item: r.to_string(),
                expected: "present".into(),
                actual: String::new(),
            });
        }
    }
    for r in have.routes.difference(&want.routes) {
        if managed(&r.link) {
            out.push(Drift {
                kind: DriftKind::RouteExtra,
                interface: r.link.clone(),
                item: r.to_string(),
                expected: String::new(),
                actual: "present".into(),
            });
        }
    }
    out.sort();
    out
}

/// Whether `name` is a link a backend can create again (a virtual one),
/// as opposed to a port that has to come back by itself.
pub fn recreatable(cfg: &Config, name: &IfName) -> bool {
    cfg.interfaces
        .get(name)
        .is_some_and(|i| i.kind != InterfaceKind::Ethernet)
}

/// `have` with what [`diff`] lists put back as `cfg` says, except links
/// that cannot be recreated ([`recreatable`]): a backend that keeps its
/// state as a [`Snapshot`] (the virtual lab) reconciles with it.
pub fn repaired(cfg: &Config, have: &Snapshot) -> Snapshot {
    let want = expected(cfg);
    let mut out = have.clone();
    for (name, w) in &want.links {
        if out.links.contains_key(name) || recreatable(cfg, name) {
            out.links.insert(name.clone(), w.clone());
        }
    }
    let on = |links: &BTreeMap<IfName, LinkSnap>, l: &IfName| links.contains_key(l);
    out.addresses.retain(|(l, a)| {
        let link_local = matches!(a, IpNet::V6(v6) if v6.addr().is_unicast_link_local());
        !on(&want.links, l) || link_local || want.addresses.contains(&(l.clone(), *a))
    });
    let links = out.links.clone();
    out.addresses.extend(
        want.addresses
            .iter()
            .filter(|(l, _)| on(&links, l))
            .cloned(),
    );
    out.routes
        .retain(|r| !on(&want.links, &r.link) || want.routes.contains(r));
    out.routes
        .extend(want.routes.iter().filter(|r| on(&links, &r.link)).cloned());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::{AddressEntry, Interface, RouteEntry, RoutingTable};

    fn n(s: &str) -> IfName {
        s.parse().unwrap()
    }

    fn cfg() -> Config {
        let mut c = Config::default();
        for p in ["ether1", "ether2"] {
            c.interfaces
                .insert(n(p), Interface::new(n(p), InterfaceKind::Ethernet));
        }
        let id = c.ip.next_address_id();
        c.ip.addresses.push(AddressEntry {
            id,
            address: "10.0.0.1/24".parse().unwrap(),
            interface: n("ether1"),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
        let id = c.ip.next_route_id();
        c.ip.routes.push(RouteEntry {
            id,
            dst_address: "0.0.0.0/0".parse().unwrap(),
            gateway: "10.0.0.254".parse().unwrap(),
            distance: 1,
            routing_table: RoutingTable::Main,
            disabled: false,
            comment: String::new(),
            check_gateway: Default::default(),
            bfd_profile: String::new(),
        });
        c
    }

    #[test]
    fn a_config_applied_as_is_has_no_drift() {
        let want = expected(&cfg());
        assert_eq!(want.routes.len(), 1, "{want:?}");
        assert!(diff(&want, &want).is_empty());
    }

    #[test]
    fn each_kind_of_difference_is_listed_once() {
        let want = expected(&cfg());
        let mut have = want.clone();
        have.addresses.clear();
        have.addresses
            .insert((n("ether2"), "192.0.2.9/24".parse().unwrap()));
        // The kernel's own link-local is not drift.
        have.addresses
            .insert((n("ether2"), "fe80::1/64".parse().unwrap()));
        have.routes.clear();
        if let Some(l) = have.links.get_mut(&n("ether2")) {
            l.up = false;
            l.mtu = 9000;
        }
        let kinds: Vec<DriftKind> = diff(&want, &have).iter().map(|d| d.kind).collect();
        assert_eq!(
            kinds,
            [
                DriftKind::AdminState,
                DriftKind::Mtu,
                DriftKind::AddressMissing,
                DriftKind::AddressExtra,
                DriftKind::RouteMissing,
            ]
        );
    }

    #[test]
    fn a_missing_link_hides_its_addresses_and_routes() {
        let want = expected(&cfg());
        let mut have = want.clone();
        have.links.remove(&n("ether1"));
        have.addresses.clear();
        have.routes.clear();
        let d = diff(&want, &have);
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].kind, DriftKind::LinkMissing);
        assert!(!recreatable(&cfg(), &n("ether1")));
    }

    #[test]
    fn foreign_links_are_not_drift() {
        let want = expected(&cfg());
        let mut have = want.clone();
        have.addresses
            .insert((n("docker0"), "172.17.0.1/16".parse().unwrap()));
        assert!(diff(&want, &have).is_empty());
    }

    #[test]
    fn repaired_leaves_only_what_cannot_come_back() {
        let c = cfg();
        let want = expected(&c);
        let mut have = want.clone();
        have.addresses.clear();
        have.addresses
            .insert((n("ether2"), "192.0.2.9/24".parse().unwrap()));
        have.addresses
            .insert((n("docker0"), "172.17.0.1/16".parse().unwrap()));
        have.routes.clear();
        have.links.remove(&n("ether2"));
        let fixed = repaired(&c, &have);
        let left = diff(&want, &fixed);
        assert_eq!(left.len(), 1, "{left:?}");
        assert_eq!(left[0].kind, DriftKind::LinkMissing);
        assert!(
            fixed
                .addresses
                .contains(&(n("docker0"), "172.17.0.1/16".parse().unwrap()))
        );
    }
}
