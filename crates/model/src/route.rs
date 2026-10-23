//! Route resolution: which interface and next hop a static route uses now,
//! and the connected routes derived from IP addresses.
//!
//! Pure functions over a [`Config`], shared by the engine (route flags and
//! validation) and the Linux backend (what goes into the kernel), so the
//! two can never disagree about whether a route is usable.
//!
//! A gateway is resolved inside the route's own routing table: `main` holds
//! the interfaces outside any VRF, a VRF table holds its member interfaces.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::config::{Config, InterfaceKind, RouteEntry};
use crate::types::{IfName, RoutingTable};

/// Kernel id of the main table (`RT_TABLE_MAIN`).
pub const MAIN_TABLE_ID: u32 = 254;
/// VRF tables get kernel ids from here up (below are the reserved ones and
/// whatever an operator set up by hand).
pub const FIRST_VRF_TABLE: u32 = 1000;
pub const LAST_VRF_TABLE: u32 = 1_000_000;

/// Why a route is not usable: a stable `id` (the GUI translates it with
/// `args`, G0.15) and the English text, which is what `Display` prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Why {
    pub id: &'static str,
    pub args: Vec<(&'static str, String)>,
    pub text: String,
}

impl Why {
    pub fn new(id: &'static str, text: String) -> Self {
        Self {
            id,
            args: Vec::new(),
            text,
        }
    }

    /// With argument `key` (a `{key}` of the translated template).
    #[must_use]
    pub fn arg(mut self, key: &'static str, value: impl std::fmt::Display) -> Self {
        self.args.push((key, value.to_string()));
        self
    }
}

impl std::fmt::Display for Why {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// What a static route does right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reach {
    /// Usable: traffic leaves through `link`, to `gateway` when there is one.
    Active {
        link: IfName,
        gateway: Option<IpAddr>,
    },
    /// Well formed but not usable now: the route, its interface or the
    /// address that reaches its gateway is disabled.
    Inactive(Why),
    /// Wrong whatever the state: nothing in its table can reach the gateway,
    /// mixed address families, unknown table or interface. `field` is the
    /// `RouteEntry` field to fix.
    Invalid { field: &'static str, why: Why },
}

fn invalid(field: &'static str, why: Why) -> Reach {
    Reach::Invalid { field, why }
}

/// Kernel table id of `table`; `None` when the VRF does not exist.
pub fn table_id(cfg: &Config, table: &RoutingTable) -> Option<u32> {
    match table {
        RoutingTable::Main => Some(MAIN_TABLE_ID),
        RoutingTable::Vrf(name) => match cfg.interfaces.get(name).map(|i| &i.kind) {
            Some(InterfaceKind::Vrf { table }) => Some(*table),
            _ => None,
        },
    }
}

/// Routing table the addresses of `name` live in.
pub fn table_of(cfg: &Config, name: &IfName) -> RoutingTable {
    match cfg.interfaces.get(name) {
        Some(i) if matches!(i.kind, InterfaceKind::Vrf { .. }) => RoutingTable::Vrf(name.clone()),
        Some(i) => i.vrf.clone().map_or(RoutingTable::Main, RoutingTable::Vrf),
        None => RoutingTable::Main,
    }
}

/// Enabled, and so is its VRF.
pub fn is_up(cfg: &Config, name: &IfName) -> bool {
    let Some(i) = cfg.interfaces.get(name) else {
        return false;
    };
    !i.disabled
        && i.vrf
            .as_ref()
            .is_none_or(|v| cfg.interfaces.get(v).is_some_and(|v| !v.disabled))
}

/// `fe80::/10`: only meaningful together with an interface.
pub fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V6(v6) => v6.segments().first().is_some_and(|s| s & 0xffc0 == 0xfe80),
        IpAddr::V4(_) => false,
    }
}

fn family(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() { "IPv4" } else { "IPv6" }
}

/// Resolve `r` against `cfg`.
pub fn reach(cfg: &Config, r: &RouteEntry) -> Reach {
    let gw = r.gateway.address();
    if let Some(g) = gw
        && g.is_ipv4() != r.dst_address.addr().is_ipv4()
    {
        return invalid(
            "gateway",
            Why::new(
                "family-mismatch",
                format!(
                    "gateway {g} is {} but dst-address {} is {}",
                    family(g),
                    r.dst_address,
                    family(r.dst_address.addr())
                ),
            )
            .arg("gateway", g)
            .arg("dst", r.dst_address),
        );
    }
    if table_id(cfg, &r.routing_table).is_none() {
        return invalid(
            "routing_table",
            Why::new(
                "no-table",
                format!(
                    "routing table '{}' does not exist (create it with ip.vrf.add)",
                    r.routing_table
                ),
            )
            .arg("table", &r.routing_table),
        );
    }
    if let Some(i) = r.gateway.iface() {
        let Some(iface) = cfg.interfaces.get(i) else {
            return invalid(
                "gateway",
                Why::new("no-interface", format!("interface '{i}' does not exist"))
                    .arg("interface", i),
            );
        };
        if let Some(b) = &iface.bridge {
            return invalid(
                "gateway",
                Why::new(
                    "bridge-port",
                    format!("'{i}' is a port of bridge '{b}'; route through '{b}' instead"),
                )
                .arg("interface", i)
                .arg("master", b),
            );
        }
        if let Some(b) = &iface.bond {
            return invalid(
                "gateway",
                Why::new(
                    "bond-slave",
                    format!("'{i}' is a slave of bond '{b}'; route through '{b}' instead"),
                )
                .arg("interface", i)
                .arg("master", b),
            );
        }
        let t = table_of(cfg, i);
        if t != r.routing_table {
            return invalid(
                "gateway",
                Why::new(
                    "other-table",
                    format!("'{i}' is in routing table '{t}', not '{}'", r.routing_table),
                )
                .arg("interface", i)
                .arg("table", &t)
                .arg("route_table", &r.routing_table),
            );
        }
    }
    if r.disabled {
        return Reach::Inactive(Why::new("disabled", "route is disabled".into()));
    }
    match (gw, r.gateway.iface()) {
        (None, Some(i)) => up_or(cfg, i, None),
        (Some(g), Some(i)) if is_link_local(g) => up_or(cfg, i, Some(g)),
        (Some(g), Some(i)) => {
            if let Some(why) = own_address(cfg, g, &r.routing_table) {
                return invalid("gateway", why);
            }
            let nets: Vec<_> = cfg
                .ip
                .addresses
                .iter()
                .filter(|a| a.interface == *i && a.address.contains(&g))
                .collect();
            if nets.is_empty() {
                return invalid(
                    "gateway",
                    Why::new(
                        "not-on-interface",
                        format!("{g} is not in a network of '{i}' (see ip.address.list)"),
                    )
                    .arg("gateway", g)
                    .arg("interface", i),
                );
            }
            if !nets.iter().any(|a| !a.disabled) {
                return Reach::Inactive(
                    Why::new(
                        "address-disabled",
                        format!("the address of '{i}' that reaches {g} is disabled"),
                    )
                    .arg("interface", i)
                    .arg("gateway", g),
                );
            }
            up_or(cfg, i, Some(g))
        }
        (Some(g), None) => resolve_ip(cfg, g, &r.routing_table),
        // `Gateway` cannot be built empty; a hand-edited file still is not.
        (None, None) => invalid("gateway", Why::new("empty", "gateway is empty".into())),
    }
}

fn up_or(cfg: &Config, link: &IfName, gateway: Option<IpAddr>) -> Reach {
    if is_up(cfg, link) {
        Reach::Active {
            link: link.clone(),
            gateway,
        }
    } else {
        Reach::Inactive(
            Why::new(
                "interface-disabled",
                format!("interface '{link}' (or its VRF) is disabled"),
            )
            .arg("interface", link),
        )
    }
}

fn own_address(cfg: &Config, g: IpAddr, table: &RoutingTable) -> Option<Why> {
    cfg.ip
        .addresses
        .iter()
        .find(|a| a.address.addr() == g && table_of(cfg, &a.interface) == *table)
        .map(|a| {
            Why::new(
                "own-address",
                format!("{g} is an address of this router (on '{}')", a.interface),
            )
            .arg("gateway", g)
            .arg("interface", &a.interface)
        })
}

/// A bare IP gateway: the connected network that holds it, longest prefix
/// first, then interface name, so the choice is deterministic.
fn resolve_ip(cfg: &Config, g: IpAddr, table: &RoutingTable) -> Reach {
    if is_link_local(g) {
        return invalid(
            "gateway",
            Why::new(
                "needs-interface",
                format!("link-local gateway {g} needs an interface: {g}%<interface>"),
            )
            .arg("gateway", g),
        );
    }
    if let Some(why) = own_address(cfg, g, table) {
        return invalid("gateway", why);
    }
    let mut nets: Vec<_> = cfg
        .ip
        .addresses
        .iter()
        .filter(|a| cfg.interfaces.contains_key(&a.interface))
        .filter(|a| a.address.contains(&g) && table_of(cfg, &a.interface) == *table)
        .collect();
    if nets.is_empty() {
        return invalid(
            "gateway",
            Why::new(
                "unreachable",
                format!(
                    "{g} is not in any connected network of routing table '{table}' (see ip.address.list)"
                ),
            )
            .arg("gateway", g)
            .arg("table", table),
        );
    }
    nets.sort_by(|a, b| {
        b.address
            .prefix_len()
            .cmp(&a.address.prefix_len())
            .then_with(|| a.interface.cmp(&b.interface))
    });
    match nets
        .iter()
        .find(|a| !a.disabled && is_up(cfg, &a.interface))
    {
        Some(a) => Reach::Active {
            link: a.interface.clone(),
            gateway: Some(g),
        },
        None => Reach::Inactive(
            Why::new(
                "network-disabled",
                format!("the network of {g} is on a disabled address or interface"),
            )
            .arg("gateway", g),
        ),
    }
}

/// A connected route: the network of an IP address, in the table of its
/// interface. Distance 0, so it beats any static route to the same prefix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Connected {
    pub table: RoutingTable,
    pub dst: IpNet,
    pub interface: IfName,
    pub active: bool,
}

/// Connected routes of `cfg`, one per (table, network, interface), sorted.
pub fn connected(cfg: &Config) -> Vec<Connected> {
    // Keyed, so many addresses stay O(A log A) (a linear search per
    // address was O(A²)).
    let mut out: BTreeMap<(RoutingTable, IpNet, IfName), bool> = BTreeMap::new();
    for a in &cfg.ip.addresses {
        if !cfg.interfaces.contains_key(&a.interface) {
            continue;
        }
        let active = !a.disabled && is_up(cfg, &a.interface);
        let key = (
            table_of(cfg, &a.interface),
            a.address.trunc(),
            a.interface.clone(),
        );
        *out.entry(key).or_default() |= active;
    }
    // The key order is the sort order of `Connected` (table, dst, interface).
    out.into_iter()
        .map(|((table, dst, interface), active)| Connected {
            table,
            dst,
            interface,
            active,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AddressEntry, Interface};
    use crate::types::{Gateway, ItemId};

    fn n(s: &str) -> IfName {
        s.parse().unwrap()
    }

    fn lab() -> Config {
        let mut c = Config::default();
        for name in ["ether1", "ether2", "ether3"] {
            c.interfaces
                .insert(n(name), Interface::new(n(name), InterfaceKind::Ethernet));
        }
        addr(&mut c, "ether1", "10.0.0.2/24");
        addr(&mut c, "ether2", "10.0.0.130/25");
        addr(&mut c, "ether1", "2001:db8::2/64");
        c
    }

    fn addr(c: &mut Config, iface: &str, a: &str) {
        let id = c.ip.next_address_id();
        c.ip.addresses.push(AddressEntry {
            id,
            address: a.parse().unwrap(),
            interface: n(iface),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
    }

    fn route(dst: &str, gw: &str) -> RouteEntry {
        RouteEntry {
            id: ItemId(1),
            dst_address: dst.parse().unwrap(),
            gateway: gw.parse::<Gateway>().unwrap(),
            distance: 1,
            routing_table: RoutingTable::Main,
            disabled: false,
            comment: String::new(),
        }
    }

    fn active(link: &str, gw: Option<&str>) -> Reach {
        Reach::Active {
            link: n(link),
            gateway: gw.map(|g| g.parse().unwrap()),
        }
    }

    fn invalid(r: Reach, needle: &str) {
        match r {
            Reach::Invalid { why, .. } => assert!(why.text.contains(needle), "{why}"),
            other => panic!("expected Invalid({needle}), got {other:?}"),
        }
    }

    #[test]
    fn ip_gateway_resolves_through_the_longest_connected_prefix() {
        let c = lab();
        assert_eq!(
            reach(&c, &route("0.0.0.0/0", "10.0.0.1")),
            active("ether1", Some("10.0.0.1"))
        );
        // 10.0.0.129 is in both 10.0.0.0/24 (ether1) and 10.0.0.128/25 (ether2).
        assert_eq!(
            reach(&c, &route("0.0.0.0/0", "10.0.0.129")),
            active("ether2", Some("10.0.0.129"))
        );
        assert_eq!(
            reach(&c, &route("::/0", "2001:db8::1")),
            active("ether1", Some("2001:db8::1"))
        );
        assert_eq!(
            reach(&c, &route("10.9.0.0/16", "ether3")),
            active("ether3", None)
        );
        assert_eq!(
            reach(&c, &route("::/0", "fe80::1%ether3")),
            active("ether3", Some("fe80::1"))
        );
    }

    #[test]
    fn bad_gateways_are_invalid() {
        let c = lab();
        invalid(
            reach(&c, &route("0.0.0.0/0", "192.0.2.1")),
            "not in any connected",
        );
        invalid(reach(&c, &route("0.0.0.0/0", "2001:db8::1")), "IPv6");
        invalid(
            reach(&c, &route("0.0.0.0/0", "10.0.0.2")),
            "address of this router",
        );
        invalid(reach(&c, &route("0.0.0.0/0", "ether9")), "does not exist");
        invalid(reach(&c, &route("::/0", "fe80::1")), "needs an interface");
        invalid(
            reach(&c, &route("0.0.0.0/0", "10.0.0.1%ether3")),
            "not in a network of 'ether3'",
        );
        let mut r = route("0.0.0.0/0", "10.0.0.1");
        r.routing_table = RoutingTable::Vrf(n("blue"));
        invalid(reach(&c, &r), "does not exist");
    }

    #[test]
    fn disabled_things_make_a_route_inactive_not_invalid() {
        let mut c = lab();
        let mut r = route("0.0.0.0/0", "10.0.0.1");
        r.disabled = true;
        assert!(matches!(reach(&c, &r), Reach::Inactive(_)));
        c.interfaces.get_mut(&n("ether1")).unwrap().disabled = true;
        assert!(matches!(
            reach(&c, &route("0.0.0.0/0", "10.0.0.1")),
            Reach::Inactive(_)
        ));
        assert!(matches!(
            reach(&c, &route("0.0.0.0/0", "ether1")),
            Reach::Inactive(_)
        ));
        c.interfaces.get_mut(&n("ether1")).unwrap().disabled = false;
        c.ip.addresses.first_mut().unwrap().disabled = true;
        assert!(matches!(
            reach(&c, &route("0.0.0.0/0", "10.0.0.1")),
            Reach::Inactive(_)
        ));
    }

    #[test]
    fn vrf_tables_keep_their_interfaces() {
        let mut c = lab();
        c.interfaces.insert(
            n("blue"),
            Interface::new(n("blue"), InterfaceKind::Vrf { table: 1000 }),
        );
        c.interfaces.get_mut(&n("ether3")).unwrap().vrf = Some(n("blue"));
        addr(&mut c, "ether3", "10.0.0.2/24"); // same network as main's ether1
        let blue = RoutingTable::Vrf(n("blue"));
        assert_eq!(table_id(&c, &blue), Some(1000));
        assert_eq!(table_of(&c, &n("ether3")), blue);

        let mut r = route("0.0.0.0/0", "10.0.0.1");
        r.routing_table = blue.clone();
        assert_eq!(reach(&c, &r), active("ether3", Some("10.0.0.1")));
        // main still resolves through its own ether1.
        assert_eq!(
            reach(&c, &route("0.0.0.0/0", "10.0.0.1")),
            active("ether1", Some("10.0.0.1"))
        );
        invalid(
            reach(&c, &route("0.0.0.0/0", "ether3")),
            "routing table 'blue'",
        );
        // A disabled VRF takes its members down with it.
        c.interfaces.get_mut(&n("blue")).unwrap().disabled = true;
        assert!(matches!(reach(&c, &r), Reach::Inactive(_)));

        let conn = connected(&c);
        assert!(
            conn.iter()
                .any(|x| x.table == blue && x.interface == n("ether3") && !x.active)
        );
        assert!(conn.iter().any(|x| x.table == RoutingTable::Main
            && x.dst.to_string() == "10.0.0.0/24"
            && x.active));
    }
}
