//! Whole-config validation run before every commit: cross-reference checks
//! owned by the engine plus each `proto-*` subsystem validator.
//!
//! G0.22: the validation is a table of [`Unit`]s, each with the sections of
//! the config it reads. A commit runs only the units that read a section
//! the commit changed ([`validate_changed`]); the running config passed all
//! of them, and a unit whose sections are the same gives the same answer.
//! The table is checked by tests, not trusted: on a corpus of configs each
//! unit must answer the same on the config restricted to its sections
//! (`corerouter_model::sections::restrict`), and random changes validated
//! both ways must agree (`tests/incremental_validate.rs`).

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use ipnet::IpNet;

use corerouter_model::os_loopback;
use corerouter_model::route::{self, FIRST_VRF_TABLE, LAST_VRF_TABLE, Reach};
use corerouter_model::sections::Sections;
use corerouter_model::{
    BondMode, Config, IfName, Interface, InterfaceKind, Issue, ItemId, RouteEntry, RoutingTable, VlanId,
};

/// One validator and the sections of the config it reads.
pub struct Unit {
    pub name: &'static str,
    pub reads: Sections,
    pub run: fn(&Config) -> Vec<Issue>,
}

/// The big sections: a unit that does not name one of them is not run
/// by a commit that writes only it (a secret, a route, an address-list
/// entry), and those are the commits that come by the thousand.
const BIG: Sections = Sections::ADDRESSES
    .union(Sections::ROUTES)
    .union(Sections::FILTER)
    .union(Sections::NAT)
    .union(Sections::MANGLE)
    .union(Sections::ADDRESS_LISTS)
    .union(Sections::DNS_STATIC)
    .union(Sections::DNS_ZONES)
    .union(Sections::DHCP_SERVER)
    .union(Sections::PPP_SECRETS)
    .union(Sections::QUEUE);

/// Every section but the big ones and the interfaces' comments (which no
/// validator reads), plus `extra`: what a `proto-*` validator declares,
/// from a review of what its code (and the model helpers it calls) reads.
const fn small_and(extra: Sections) -> Sections {
    Sections::ALL.without(BIG).without(Sections::IFACE_COMMENTS).union(extra)
}

/// Every validator, in the order their issues are reported.
pub const UNITS: &[Unit] = &[
    Unit {
        name: "interfaces",
        // A bond slave carries no address nor DHCP client of its own.
        reads: Sections::INTERFACES
            .union(Sections::ADDRESSES)
            .union(Sections::IP_REST)
            .union(Sections::IPV6),
        run: interface_checks,
    },
    Unit {
        name: "addresses",
        reads: Sections::ADDRESSES.union(Sections::INTERFACES),
        run: address_checks,
    },
    Unit {
        name: ROUTES_UNIT,
        reads: Sections::ROUTES.union(Sections::ADDRESSES).union(Sections::INTERFACES),
        run: route_checks,
    },
    Unit {
        name: "ntp",
        reads: Sections::SYSTEM,
        run: |cfg| {
            let mut out = Vec::new();
            ntp_checks(cfg, &mut out);
            out
        },
    },
    Unit {
        name: "firewall",
        reads: small_and(Sections::FIREWALL),
        run: corerouter_firewall::validate,
    },
    Unit {
        name: "bgp",
        reads: small_and(Sections::NONE),
        run: corerouter_proto_bgp::validate,
    },
    Unit {
        name: "ospf",
        reads: small_and(Sections::NONE),
        run: corerouter_proto_ospf::validate,
    },
    Unit {
        name: "bfd",
        reads: small_and(Sections::NONE),
        run: corerouter_proto_bfd::frr::validate,
    },
    Unit {
        name: "mpls",
        reads: small_and(Sections::NONE),
        run: corerouter_proto_mpls::validate,
    },
    Unit {
        name: "cgnat",
        reads: small_and(Sections::ADDRESSES),
        run: corerouter_proto_cgnat::validate,
    },
    Unit {
        name: "dns",
        reads: small_and(Sections::ADDRESSES.union(Sections::DNS_STATIC).union(Sections::DNS_ZONES)),
        run: corerouter_proto_dns::validate,
    },
    Unit {
        name: "dhcp",
        reads: small_and(
            Sections::ADDRESSES
                .union(Sections::ROUTES)
                .union(Sections::ADDRESS_LISTS)
                .union(Sections::DNS_ZONES)
                .union(Sections::DHCP_SERVER)
                .union(Sections::PPP_SECRETS),
        ),
        run: corerouter_proto_dhcp::validate,
    },
    Unit {
        name: "discovery",
        reads: small_and(Sections::NONE),
        run: corerouter_proto_discovery::validate,
    },
];

pub fn validate_all(cfg: &Config) -> Vec<Issue> {
    validate_changed(cfg, Sections::ALL)
}

/// The issues of the units that read a section in `changed` (a section
/// no table names, [`Sections::OTHER`], runs them all). With the running
/// config valid, `changed` = what the candidate changed gives the same
/// issues as [`validate_all`].
pub fn validate_changed(cfg: &Config, changed: Sections) -> Vec<Issue> {
    let all = changed.contains(Sections::OTHER);
    UNITS
        .iter()
        .filter(|u| all || u.reads.intersects(changed))
        .flat_map(|u| (u.run)(cfg))
        .collect()
}

/// [`validate_changed`] for a commit from `running` (valid: the commit
/// path keeps it so, `ValidRunning`) to `cfg`. With the interfaces and
/// addresses the same, the route checks look only at the destinations the
/// commit touched (G0.31e: 16 ms with 60 000 routes); the rest as
/// [`validate_changed`]. Same issues, in the same order.
pub fn validate_commit(running: &Config, cfg: &Config, changed: Sections) -> Vec<Issue> {
    let routes_only = !changed.contains(Sections::OTHER)
        && !changed.intersects(Sections::ADDRESSES.union(Sections::INTERFACES));
    UNITS
        .iter()
        .filter(|u| changed.contains(Sections::OTHER) || u.reads.intersects(changed))
        .flat_map(|u| {
            if routes_only && u.name == ROUTES_UNIT {
                route_checks_since(running, cfg)
            } else {
                (u.run)(cfg)
            }
        })
        .collect()
}

/// Name of the unit that [`validate_commit`] runs incrementally.
const ROUTES_UNIT: &str = "routes";

fn interface_checks(cfg: &Config) -> Vec<Issue> {
    let mut out = Vec::new();
    let mut vlans: BTreeMap<(&IfName, VlanId, bool), &IfName> = BTreeMap::new();
    let mut vrf_tables: BTreeMap<u32, &IfName> = BTreeMap::new();
    for (name, iface) in &cfg.interfaces {
        if iface.name != *name {
            out.push(Issue::new(
                format!("interfaces.{name}"),
                "name does not match key",
            ));
        }
        if let InterfaceKind::Vlan {
            parent,
            vlan_id,
            service_tag,
        } = &iface.kind
        {
            if vlan_lowers(cfg, name).1 {
                out.push(Issue::new(
                    format!("interfaces.{name}.kind.parent"),
                    "VLAN parent chain loops back on itself",
                ));
            }
            vlan_checks(cfg, name, iface, parent, *vlan_id, &mut out);
            // A C-VLAN and an S-VLAN may share an id on one port (TPIDs differ).
            if let Some(other) = vlans.insert((parent, *vlan_id, *service_tag), name) {
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
        if let Some(bond) = &iface.bond {
            bond_slave_checks(cfg, name, iface, bond, &mut out);
        }
        if let InterfaceKind::Bonding { mode, primary, .. } = &iface.kind {
            bond_checks(cfg, name, *mode, primary.as_ref(), &mut out);
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
        os_loopback_checks(name, iface, &mut out);
        if !(68..=9216).contains(&iface.mtu) {
            out.push(Issue::new(
                format!("interfaces.{name}.mtu"),
                "MTU must be 68..=9216",
            ));
        }
    }
    out
}

/// `lo` is the OS loopback (G3.4i, `os_loopback`): only a loopback takes
/// the name, and the kernel's `lo` joins no VRF, bridge or bond.
fn os_loopback_checks(name: &IfName, iface: &Interface, out: &mut Vec<Issue>) {
    if name.as_str() != os_loopback::NAME {
        return;
    }
    if iface.kind != InterfaceKind::Loopback {
        out.push(Issue::new(
            format!("interfaces.{name}"),
            format!(
                "'{name}' is the OS loopback: only a loopback interface takes the name (this one is {})",
                iface.kind.label()
            ),
        ));
    }
    if iface.vrf.is_some() || iface.bridge.is_some() || iface.bond.is_some() {
        out.push(Issue::new(
            format!("interfaces.{name}"),
            format!("'{name}' is the OS loopback and joins no VRF, bridge or bond; use another loopback"),
        ));
    }
}

fn address_checks(cfg: &Config) -> Vec<Issue> {
    let mut out = Vec::new();
    if cfg.ip.addresses.len() > MAX_ADDRESSES {
        out.push(Issue::new(
            "ip.addresses",
            format!("at most {MAX_ADDRESSES} addresses"),
        ));
    }
    // (Addresses from different pools differ once the prefixes are in.)
    let mut v6: BTreeMap<(&IfName, Ipv6Addr, Option<&str>), IpNet> = BTreeMap::new();
    for a in &cfg.ip.addresses {
        if !cfg.interfaces.contains_key(&a.interface) {
            out.push(Issue::new(
                format!("ip.addresses[{}].interface", a.id),
                format!("interface '{}' does not exist", a.interface),
            ));
        }
        if os_loopback::is_os_loopback(cfg, &a.interface) && os_loopback::is_os_address(&a.address) {
            out.push(Issue::new(
                format!("ip.addresses[{}].address", a.id),
                format!(
                    "{} is the OS's own on '{}' (127.0.0.0/8 and ::1 are always there and are never CoreRouter's)",
                    a.address, a.interface
                ),
            ));
        }
        if let IpNet::V6(net) = a.address
            && let Some(other) = v6.insert(
                (&a.interface, net.addr(), a.from_pool.as_deref()),
                a.address,
            )
            && other != a.address
        {
            out.push(Issue::new(
                format!("ip.addresses[{}].address", a.id),
                v6_twice(net.addr(), &a.interface, other),
            ));
        }
    }
    out
}

fn route_checks(cfg: &Config) -> Vec<Issue> {
    let mut out = Vec::new();
    // Duplicates can only be among routes to the same destination in the
    // same table: compare inside those groups (O(R log R); comparing every
    // pair was O(R²) on each commit, with up to MAX_ROUTES routes).
    let mut groups: BTreeMap<(&RoutingTable, IpNet), Vec<&RouteEntry>> = BTreeMap::new();
    for r in &cfg.ip.routes {
        let group = groups
            .entry((&r.routing_table, r.dst_address))
            .or_default();
        out.extend(
            route_issues(
                cfg,
                r,
                group.iter().filter(|o| o.gateway == r.gateway).map(|o| o.id),
            )
                .into_iter()
                .map(|(field, m)| Issue::new(format!("ip.routes[{}].{field}", r.id), m)),
        );
        group.push(r);
    }
    out
}

/// [`route_checks`] when only routes changed since `running` (valid, same
/// interfaces and addresses): a route resolves through those alone, so an
/// untouched route gives what it gave there (nothing), and a duplicate
/// pairs two routes to one destination, one of them touched. So only the
/// routes at the destinations the commit touched are looked at, through
/// the index, in list order with the earlier routes of their group, as
/// [`route_checks`] does.
fn route_checks_since(running: &Config, cfg: &Config) -> Vec<Issue> {
    let routes = &cfg.ip.routes;
    let mut at: Vec<(usize, &RouteEntry)> = routes
        .changed_dsts(&running.ip.routes)
        .iter()
        .flat_map(|d| routes.to_dst(&d.0, d.1))
        .filter_map(|id| {
            let pos = routes.position(*id)?;
            Some((pos, routes.get(pos)?))
        })
        .collect();
    at.sort_by_key(|(pos, _)| *pos);
    at.dedup_by_key(|(pos, _)| *pos);
    let mut out = Vec::new();
    let mut groups: BTreeMap<(&RoutingTable, IpNet), Vec<&RouteEntry>> = BTreeMap::new();
    for (_, r) in at {
        let group = groups.entry((&r.routing_table, r.dst_address)).or_default();
        out.extend(
            route_issues(
                cfg,
                r,
                group.iter().filter(|o| o.gateway == r.gateway).map(|o| o.id),
            )
            .into_iter()
            .map(|(field, m)| Issue::new(format!("ip.routes[{}].{field}", r.id), m)),
        );
        group.push(r);
    }
    out
}

/// What `system.ntp.client.set` enforces, for a config that did not come
/// through it (a saved or hand-edited file).
fn ntp_checks(cfg: &Config, out: &mut Vec<Issue>) {
    use corerouter_model::ntp::{MAX_SERVERS, POLL_RANGE, valid_server};
    let c = &cfg.system.ntp_client;
    for (field, v) in [("min_poll", c.min_poll), ("max_poll", c.max_poll)] {
        if !POLL_RANGE.contains(&v) {
            out.push(Issue::new(
                format!("system.ntp_client.{field}"),
                format!("must be {}..={}", POLL_RANGE.start(), POLL_RANGE.end()),
            ));
        }
    }
    if c.min_poll > c.max_poll {
        out.push(Issue::new(
            "system.ntp_client.min_poll",
            "min_poll must not be above max_poll",
        ));
    }
    if c.servers.len() > MAX_SERVERS {
        out.push(Issue::new(
            "system.ntp_client.servers",
            format!("at most {MAX_SERVERS} servers"),
        ));
    }
    for s in c.servers.iter().take(MAX_SERVERS.saturating_add(1)) {
        if let Err(e) = valid_server(s) {
            out.push(Issue::new("system.ntp_client.servers", e));
        }
    }
}

/// Bound on `ip.addresses` (hostile input; every other list has one).
/// Far above what a router holds (**estimado**).
pub const MAX_ADDRESSES: usize = 65_536;

/// Linux keys an IPv6 address by address and interface only: a second
/// prefix length for the same address is refused by the kernel (EEXIST).
pub(crate) fn v6_twice(addr: Ipv6Addr, iface: &IfName, other: IpNet) -> String {
    format!(
        "{addr} is already on {iface} as {other}; an IPv6 address can be on an interface \
         with one prefix length only (remove the other first)"
    )
}

/// What is wrong with route `r` in `cfg`, as (field, message). `same_hop`
/// are the ids of the routes with its table, destination and gateway (`r`
/// itself may be among them). Shared with the `ip.route.*` commands, which
/// report the first problem as a parameter error.
pub(crate) fn route_issues(
    cfg: &Config,
    r: &RouteEntry,
    same_hop: impl Iterator<Item = ItemId>,
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
        out.push((field, why.text));
    }
    check_gateway_issues(cfg, r, &mut out);
    discard_issues(cfg, r, &mut out);
    // Equal distance is ECMP (RouterOS v7, G1.27): only the very same
    // next hop twice is refused.
    for o in same_hop.filter(|o| *o != r.id) {
        out.push((
            "gateway",
            format!(
                "route {o} already goes to {dst} via {} in table {}",
                r.gateway, r.routing_table
            ),
        ));
    }
    out
}

/// G1.5a: the kernel holds one route per prefix, metric and table, and a
/// route without next hop has no path to merge with another: it cannot
/// share its distance with a route of the other kind (or another type of
/// discard) to the same destination. Enabled routes only.
fn discard_issues(cfg: &Config, r: &RouteEntry, out: &mut Vec<(&'static str, String)>) {
    if r.disabled {
        return;
    }
    let dst = (r.routing_table.clone(), r.dst_address.trunc());
    let clash = cfg.ip.routes.routes_to(&dst).find(|o| {
        o.id != r.id
            && !o.disabled
            && o.distance == r.distance
            && o.dst_address.trunc() == r.dst_address.trunc()
            && (o.gateway.discards().is_some() || r.gateway.discards().is_some())
            && o.gateway.discards() != r.gateway.discards()
    });
    if let Some(o) = clash {
        out.push((
            "distance",
            format!(
                "route {} already goes to {} via {} at distance {} in table {}: a {} route \
                 cannot share a distance with it; give one of them another distance",
                o.id,
                r.dst_address,
                o.gateway,
                r.distance,
                r.routing_table,
                r.gateway.discards().or(o.gateway.discards()).map_or("", |d| d.as_str()),
            ),
        ));
    }
}

/// G1.27f / G3.6g: what `check_gateway` can check.
fn check_gateway_issues(cfg: &Config, r: &RouteEntry, out: &mut Vec<(&'static str, String)>) {
    use corerouter_model::dhcp_client::CheckGateway;
    let gw = r.gateway.address();
    match (r.check_gateway, gw) {
        (CheckGateway::None, _) => {}
        (m, _) if r.gateway.discards().is_some() => out.push((
            "check_gateway",
            format!(
                "check-gateway={m} needs a gateway: a {} route has none to check",
                r.gateway
            ),
        )),
        (m, None) => out.push((
            "check_gateway",
            format!(
                "check-gateway={m} needs a gateway address: an interface gateway ({}) has no \
                 host to check",
                r.gateway
            ),
        )),
        (CheckGateway::Arp, Some(std::net::IpAddr::V6(_))) => out.push((
            "check_gateway",
            "arp checks IPv4 gateways; use ping or bfd for an IPv6 gateway".into(),
        )),
        (CheckGateway::Bfd, Some(_)) => {
            let name = if r.bfd_profile.is_empty() {
                corerouter_model::bfd::PROFILE_DEFAULT
            } else {
                r.bfd_profile.as_str()
            };
            if cfg.routing.bfd.profile(name).is_none() {
                out.push((
                    "bfd_profile",
                    format!(
                        "no BFD profile '{}' (see routing.bfd.profile.list)",
                        name.chars().take(48).collect::<String>()
                    ),
                ));
            }
        }
        _ => {}
    }
    if !r.bfd_profile.is_empty() && r.check_gateway != CheckGateway::Bfd {
        out.push(("bfd_profile", "only with check_gateway=bfd".into()));
    }
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

/// A slave carries no L3 and nothing else may own it: the bond does.
fn bond_slave_checks(
    cfg: &Config,
    name: &IfName,
    iface: &Interface,
    bond: &IfName,
    out: &mut Vec<Issue>,
) {
    let mut problems = Vec::new();
    match cfg.interfaces.get(bond) {
        None => problems.push(format!("bond '{bond}' does not exist")),
        Some(b) if !matches!(b.kind, InterfaceKind::Bonding { .. }) => {
            problems.push(format!("'{bond}' is not a bond (type {})", b.kind.label()))
        }
        Some(b) if b.mtu != iface.mtu => problems.push(format!(
            "MTU {} differs from the MTU {} of bond '{bond}' (the kernel gives slaves the bond's)",
            iface.mtu, b.mtu
        )),
        Some(_) => {}
    }
    if !matches!(iface.kind, InterfaceKind::Ethernet) {
        problems.push(format!(
            "'{name}' is a {}; only ethernet ports can be bond slaves",
            iface.kind.label()
        ));
    }
    if let Some(b) = &iface.bridge {
        problems.push(format!(
            "'{name}' is also a port of bridge '{b}'; add '{bond}' to the bridge instead"
        ));
    }
    if let Some(v) = &iface.vrf {
        problems.push(format!(
            "'{name}' is also in VRF '{v}'; put '{bond}' in the VRF instead"
        ));
    }
    if cfg.ip.addresses.iter().any(|a| a.interface == *name) {
        problems.push(format!(
            "'{name}' has an IP address; addresses go on '{bond}'"
        ));
    }
    if cfg.ip.dhcp_clients.iter().any(|c| c.interface == *name) {
        problems.push(format!("'{name}' has a DHCP client; run it on '{bond}'"));
    }
    if cfg.ipv6.dhcp_clients.iter().any(|c| c.interface == *name) {
        problems.push(format!("'{name}' has a DHCPv6 client; run it on '{bond}'"));
    }
    if let Some(v) = cfg
        .interfaces
        .values()
        .find(|i| matches!(&i.kind, InterfaceKind::Vlan { parent, .. } if parent == name))
    {
        problems.push(format!(
            "VLAN '{}' runs on '{name}'; put it on '{bond}' instead",
            v.name
        ));
    }
    out.extend(
        problems
            .into_iter()
            .map(|m| Issue::new(format!("interfaces.{name}.bond"), m)),
    );
}

fn bond_checks(
    cfg: &Config,
    name: &IfName,
    mode: BondMode,
    primary: Option<&IfName>,
    out: &mut Vec<Issue>,
) {
    let Some(p) = primary else {
        return;
    };
    let path = format!("interfaces.{name}.kind.primary");
    if !mode.has_primary() {
        out.push(Issue::new(
            path,
            format!("mode {mode} has no primary slave (active-backup, balance-tlb, balance-alb)"),
        ));
    } else if cfg.interfaces.get(p).and_then(|i| i.bond.as_ref()) != Some(name) {
        out.push(Issue::new(
            path,
            format!("'{p}' is not a slave of '{name}'"),
        ));
    }
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
