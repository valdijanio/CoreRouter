//! Which sections of the config a commit changed (G0.22).
//!
//! The candidate and the running config share every section the commit did
//! not write (G0.16, G0.21): [`changed`] finds the rest by pointer first and
//! by value only for the small sections, so it costs O(small sections), not
//! O(config). The engine then runs only the validators that read a changed
//! section, and the data plane skips the plans of unchanged ones.
//!
//! The interfaces are two sections: [`Sections::INTERFACES`] (everything
//! but the comments) and [`Sections::IFACE_COMMENTS`]. A comment never
//! reaches the kernel nor a validator, so `interface.set comment=…` with
//! 10 000 routes does not look at the routes.
//!
//! [`restrict`] is the other side of the contract: the config with every
//! section outside a set blanked. A validator that declares it reads only
//! `deps` must give the same answer on `restrict(cfg, deps)` as on `cfg`;
//! the engine's tests check that on a corpus of configs, so a dependency
//! left out of the table fails a test instead of letting a bad config in.
//!
//! A field added to `Config`, `Ip`, `Firewall` or `Ppp` without a section
//! of its own falls in [`Sections::OTHER`], [`Sections::IP_REST`],
//! [`Sections::FIREWALL_REST`] or [`Sections::PPP_REST`] by itself (they are
//! compared as "everything not named"): a change there is never missed.

use std::collections::BTreeMap;

use crate::config::{Config, Interface, Ip};
use crate::cow::CowArc;
use crate::cow_list::CowList;
use crate::firewall::Firewall;
use crate::ppp::Ppp;
use crate::types::IfName;

/// A set of sections of the config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Sections(u32);

impl Sections {
    pub const NONE: Self = Self(0);
    pub const SYSTEM: Self = Self(1);
    /// The interfaces, comments aside.
    pub const INTERFACES: Self = Self(1 << 1);
    pub const IFACE_COMMENTS: Self = Self(1 << 2);
    pub const INTERFACE_LISTS: Self = Self(1 << 3);
    pub const ADDRESSES: Self = Self(1 << 4);
    pub const ROUTES: Self = Self(1 << 5);
    pub const FILTER: Self = Self(1 << 6);
    pub const NAT: Self = Self(1 << 7);
    pub const MANGLE: Self = Self(1 << 8);
    pub const ADDRESS_LISTS: Self = Self(1 << 9);
    /// The firewall's small fields (zones, id counters, new fields).
    pub const FIREWALL_REST: Self = Self(1 << 10);
    pub const DNS_STATIC: Self = Self(1 << 11);
    pub const DNS_ZONES: Self = Self(1 << 12);
    pub const DHCP_SERVER: Self = Self(1 << 13);
    /// Every other field of `ip` (pools, CGNAT, DNS settings, …).
    pub const IP_REST: Self = Self(1 << 14);
    pub const IPV6: Self = Self(1 << 15);
    pub const ROUTING: Self = Self(1 << 16);
    pub const RADIUS: Self = Self(1 << 17);
    pub const PPP_SECRETS: Self = Self(1 << 18);
    /// Every other field of `ppp` (profiles, servers, AAA, …).
    pub const PPP_REST: Self = Self(1 << 19);
    pub const QUEUE: Self = Self(1 << 20);
    /// A top-level field none of the above names: whoever reads it is not
    /// in any table yet, so a change here validates everything.
    pub const OTHER: Self = Self(1 << 21);
    pub const ALL: Self = Self((1 << 22) - 1);

    /// The firewall tables and lists, all of it.
    pub const FIREWALL: Self = Self(Self::FILTER.0 | Self::NAT.0 | Self::MANGLE.0 | Self::ADDRESS_LISTS.0 | Self::FIREWALL_REST.0);
    /// All of `ip`.
    pub const IP: Self = Self(
        Self::ADDRESSES.0
            | Self::ROUTES.0
            | Self::FIREWALL.0
            | Self::DNS_STATIC.0
            | Self::DNS_ZONES.0
            | Self::DHCP_SERVER.0
            | Self::IP_REST.0,
    );
    /// All of `ppp`.
    pub const PPP: Self = Self(Self::PPP_SECRETS.0 | Self::PPP_REST.0);

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// Each section of the set on its own.
    pub fn each(self) -> impl Iterator<Item = Self> {
        (0..22).map(|b| Self(1 << b)).filter(move |s| self.contains(*s))
    }
}

impl std::ops::BitOr for Sections {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

/// `a` and `b` differ in something else than the interfaces' comments.
pub fn interfaces_differ(a: &BTreeMap<IfName, Interface>, b: &BTreeMap<IfName, Interface>) -> bool {
    a.len() != b.len()
        || a.iter().zip(b).any(|((ka, x), (kb, y))| {
            ka != kb || {
                let mut x = x.clone();
                x.comment.clone_from(&y.comment);
                x != *y
            }
        })
}

/// The interfaces of `a` and `b` differ in more than comments (by
/// pointer first: O(1) when a commit did not touch them).
pub fn interfaces_changed(a: &Config, b: &Config) -> bool {
    !CowArc::ptr_eq(&a.interfaces, &b.interfaces) && interfaces_differ(&a.interfaces, &b.interfaces)
}

/// The links, addresses and static routes the kernel gets are the same in
/// `a` and `b` (comments aside): the data plane's link plan has nothing to
/// do.
pub fn links_and_routes_same(a: &Config, b: &Config) -> bool {
    !interfaces_changed(a, b)
        && (CowList::ptr_eq(&a.ip.addresses, &b.ip.addresses) || a.ip.addresses == b.ip.addresses)
        && (CowList::ptr_eq(&a.ip.routes, &b.ip.routes) || a.ip.routes == b.ip.routes)
}

fn cow_changed<T: PartialEq>(a: &CowArc<T>, b: &CowArc<T>) -> bool {
    !CowArc::ptr_eq(a, b) && **a != **b
}

fn list_changed<T: PartialEq>(a: &CowList<T>, b: &CowList<T>) -> bool {
    !CowList::ptr_eq(a, b) && a != b
}

/// `ip` with its named sections emptied: what is left is [`Sections::IP_REST`].
fn ip_rest(ip: &Ip) -> Ip {
    let mut l = ip.clone();
    l.addresses = CowList::default();
    l.routes = CowList::default();
    l.firewall = CowArc::default();
    l.dns_static = CowArc::default();
    l.dns_zones = CowArc::default();
    l.dhcp_server = CowArc::default();
    l
}

fn firewall_rest(f: &Firewall) -> Firewall {
    let mut l = f.clone();
    l.filter = CowList::default();
    l.nat = CowList::default();
    l.mangle = CowList::default();
    l.address_lists = Default::default();
    l
}

fn ppp_rest(p: &Ppp) -> Ppp {
    let mut l = p.clone();
    l.secrets = Default::default();
    l
}

/// `cfg` with its named top-level sections at their defaults: what is left
/// is [`Sections::OTHER`].
fn other(cfg: &Config) -> Config {
    let mut l = cfg.clone();
    l.system = Default::default();
    l.interfaces = CowArc::default();
    l.interface_lists = Default::default();
    l.ip = CowArc::default();
    l.ipv6 = Default::default();
    l.routing = Default::default();
    l.radius = Default::default();
    l.ppp = Default::default();
    l.queue = Default::default();
    l
}

/// The sections that differ between `a` and `b`.
pub fn changed(a: &Config, b: &Config) -> Sections {
    let mut out = Sections::NONE;
    let mut mark = |yes: bool, s: Sections| {
        if yes {
            out.insert(s);
        }
    };
    mark(a.system != b.system, Sections::SYSTEM);
    if !CowArc::ptr_eq(&a.interfaces, &b.interfaces) && *a.interfaces != *b.interfaces {
        let structural = interfaces_differ(&a.interfaces, &b.interfaces);
        mark(structural, Sections::INTERFACES);
        let comments = a.interfaces.len() != b.interfaces.len()
            || a.interfaces.values().zip(b.interfaces.values()).any(|(x, y)| x.comment != y.comment);
        mark(comments, Sections::IFACE_COMMENTS);
    }
    mark(a.interface_lists != b.interface_lists, Sections::INTERFACE_LISTS);
    if !CowArc::ptr_eq(&a.ip, &b.ip) {
        let (x, y) = (&*a.ip, &*b.ip);
        mark(list_changed(&x.addresses, &y.addresses), Sections::ADDRESSES);
        mark(list_changed(&x.routes, &y.routes), Sections::ROUTES);
        if !CowArc::ptr_eq(&x.firewall, &y.firewall) {
            let (f, g) = (&*x.firewall, &*y.firewall);
            mark(list_changed(&f.filter, &g.filter), Sections::FILTER);
            mark(list_changed(&f.nat, &g.nat), Sections::NAT);
            mark(list_changed(&f.mangle, &g.mangle), Sections::MANGLE);
            mark(f.address_lists != g.address_lists, Sections::ADDRESS_LISTS);
            mark(firewall_rest(f) != firewall_rest(g), Sections::FIREWALL_REST);
        }
        mark(cow_changed(&x.dns_static, &y.dns_static), Sections::DNS_STATIC);
        mark(cow_changed(&x.dns_zones, &y.dns_zones), Sections::DNS_ZONES);
        mark(cow_changed(&x.dhcp_server, &y.dhcp_server), Sections::DHCP_SERVER);
        mark(ip_rest(x) != ip_rest(y), Sections::IP_REST);
    }
    mark(a.ipv6 != b.ipv6, Sections::IPV6);
    mark(a.routing != b.routing, Sections::ROUTING);
    mark(a.radius != b.radius, Sections::RADIUS);
    mark(a.ppp.secrets != b.ppp.secrets, Sections::PPP_SECRETS);
    mark(ppp_rest(&a.ppp) != ppp_rest(&b.ppp), Sections::PPP_REST);
    mark(a.queue != b.queue, Sections::QUEUE);
    mark(other(a) != other(b), Sections::OTHER);
    out
}

/// `cfg` with every section outside `keep` blanked (and the interfaces'
/// comments emptied unless `keep` has [`Sections::IFACE_COMMENTS`]). The
/// unnamed fields ([`Sections::OTHER`]) are always kept.
pub fn restrict(cfg: &Config, keep: Sections) -> Config {
    let has = |s: Sections| keep.contains(s);
    let mut c = cfg.clone();
    if !has(Sections::SYSTEM) {
        c.system = Default::default();
    }
    if !has(Sections::INTERFACES) {
        c.interfaces = CowArc::default();
    } else if !has(Sections::IFACE_COMMENTS) {
        for i in c.interfaces.values_mut() {
            i.comment.clear();
        }
    }
    if !has(Sections::INTERFACE_LISTS) {
        c.interface_lists = Default::default();
    }
    {
        let ip = &mut *c.ip;
        if !has(Sections::IP_REST) {
            let mut blank = Ip::default();
            std::mem::swap(&mut blank.addresses, &mut ip.addresses);
            std::mem::swap(&mut blank.routes, &mut ip.routes);
            std::mem::swap(&mut blank.firewall, &mut ip.firewall);
            std::mem::swap(&mut blank.dns_static, &mut ip.dns_static);
            std::mem::swap(&mut blank.dns_zones, &mut ip.dns_zones);
            std::mem::swap(&mut blank.dhcp_server, &mut ip.dhcp_server);
            *ip = blank;
        }
        if !has(Sections::ADDRESSES) {
            ip.addresses = CowList::default();
        }
        if !has(Sections::ROUTES) {
            ip.routes = CowList::default();
        }
        if !has(Sections::DNS_STATIC) {
            ip.dns_static = CowArc::default();
        }
        if !has(Sections::DNS_ZONES) {
            ip.dns_zones = CowArc::default();
        }
        if !has(Sections::DHCP_SERVER) {
            ip.dhcp_server = CowArc::default();
        }
        let fw = &mut *ip.firewall;
        if !has(Sections::FIREWALL_REST) {
            let mut blank = Firewall::default();
            std::mem::swap(&mut blank.filter, &mut fw.filter);
            std::mem::swap(&mut blank.nat, &mut fw.nat);
            std::mem::swap(&mut blank.mangle, &mut fw.mangle);
            std::mem::swap(&mut blank.address_lists, &mut fw.address_lists);
            *fw = blank;
        }
        if !has(Sections::FILTER) {
            fw.filter = CowList::default();
        }
        if !has(Sections::NAT) {
            fw.nat = CowList::default();
        }
        if !has(Sections::MANGLE) {
            fw.mangle = CowList::default();
        }
        if !has(Sections::ADDRESS_LISTS) {
            fw.address_lists = Default::default();
        }
    }
    if !has(Sections::IPV6) {
        c.ipv6 = Default::default();
    }
    if !has(Sections::ROUTING) {
        c.routing = Default::default();
    }
    if !has(Sections::RADIUS) {
        c.radius = Default::default();
    }
    if !has(Sections::PPP_REST) {
        let mut blank = Ppp::default();
        std::mem::swap(&mut blank.secrets, &mut c.ppp.secrets);
        c.ppp = blank;
    }
    if !has(Sections::PPP_SECRETS) {
        c.ppp.secrets = Default::default();
    }
    if !has(Sections::QUEUE) {
        c.queue = Default::default();
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AddressEntry, InterfaceKind};
    use crate::types::ItemId;

    fn lab() -> Config {
        let mut c = Config::default();
        for n in ["ether1", "ether2"] {
            let name: IfName = n.parse().unwrap();
            c.interfaces.insert(
                name.clone(),
                Interface {
                    name,
                    kind: InterfaceKind::Ethernet,
                    mtu: 1500,
                    disabled: false,
                    mac: None,
                    comment: String::new(),
                    bridge: None,
                    vrf: None,
                    bond: None,
                    ethernet: Default::default(),
                },
            );
        }
        c.ip.addresses.push(AddressEntry {
            id: ItemId(1),
            address: "192.0.2.1/24".parse().unwrap(),
            interface: "ether1".parse().unwrap(),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
        c
    }

    #[test]
    fn a_copy_changes_nothing_and_each_write_marks_its_section() {
        let a = lab();
        let mut b = a.clone();
        assert_eq!(changed(&a, &b), Sections::NONE);
        if let Some(i) = b.interfaces.get_mut(&"ether2".parse::<IfName>().unwrap()) {
            i.comment = "uplink".into();
        }
        assert_eq!(changed(&a, &b), Sections::IFACE_COMMENTS);
        if let Some(i) = b.interfaces.get_mut(&"ether2".parse::<IfName>().unwrap()) {
            i.mtu = 9000;
        }
        assert_eq!(changed(&a, &b), Sections::IFACE_COMMENTS | Sections::INTERFACES);
        let mut c = a.clone();
        c.ip.next_route_id = 9;
        assert_eq!(changed(&a, &c), Sections::IP_REST);
        let mut d = a.clone();
        d.ip.firewall.next_rule_id = 9;
        d.ppp.next_id = 3;
        assert_eq!(changed(&a, &d), Sections::FIREWALL_REST | Sections::PPP_REST);
        let mut e = a.clone();
        e.ip.addresses.get_mut(0).unwrap().comment = "x".into();
        assert_eq!(changed(&a, &e), Sections::ADDRESSES);
    }

    #[test]
    fn restrict_keeps_only_what_it_is_asked_and_all_is_identity() {
        let a = lab();
        assert_eq!(restrict(&a, Sections::ALL), a);
        let r = restrict(&a, Sections::INTERFACES);
        assert!(r.ip.addresses.is_empty());
        assert_eq!(r.interfaces.len(), 2);
        assert_eq!(changed(&a, &restrict(&a, Sections::ALL)), Sections::NONE);
        // Every section blanked alone shows up as that section.
        let mut b = a.clone();
        b.system.identity = "x".into();
        for s in Sections::ALL.each() {
            let kept = Sections(Sections::ALL.0 & !s.0);
            let diff = changed(&b, &restrict(&b, kept));
            // Without the interfaces there are no comments either.
            let allowed = if s == Sections::INTERFACES { s | Sections::IFACE_COMMENTS } else { s };
            assert!(Sections(diff.0 & !allowed.0).is_empty(), "{s:?}: {diff:?}");
        }
    }
}
