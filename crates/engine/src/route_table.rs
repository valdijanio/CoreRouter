//! The routing table as the operator reads it (G1.27): every route the
//! router knows — static, connected, from a DHCP lease, from a Router
//! Advertisement — with its state, where it came from, how its gateway
//! resolves and, when it is not the one in use, why. Behind
//! `ip.route.list` and `ip.route.lookup`; the GUI only shows it.
//!
//! Selection follows RFC 1812 §5.2.4.3: among the usable routes to one
//! prefix of one table the lowest distance (administrative preference,
//! §5.2.4.4) wins; several at that distance share the traffic (ECMP,
//! §5.2.4.5, RouterOS v7's `+` flag). Forwarding then takes the longest
//! matching prefix (§5.2.4.3 "Longest Match", RFC 4632 §5.1).

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::net::IpAddr;

use corerouter_hal::Learned;
use corerouter_model::route::{self, Reach, Why};
use corerouter_model::{Config, IfName, InterfaceKind, ItemId, RoutingTable};
use ipnet::IpNet;

use crate::Session;
use crate::dhcp_client::is_dynamic;
use crate::dhcp_resilience::RouteCheck;
use crate::dhcp6_client::ra_id;

/// Every reason a route can be standby or inactive (`reason_id`), with the
/// English wording and its `{argument}` places (`reason_args`): the GUI
/// translates by id (G0.15), and a test checks each translation has the
/// same places. The ids from `corerouter_model::route::reach` are here too.
pub const REASONS: &[(&str, &str)] = &[
    ("address-disabled", "the address of '{interface}' that reaches {gateway} is disabled"),
    ("bond-slave", "'{interface}' is a slave of bond '{master}'; route through '{master}' instead"),
    ("bridge-port", "'{interface}' is a port of bridge '{master}'; route through '{master}' instead"),
    ("check-gateway", "check-gateway={method} failed {secs} s ago: {gateway} does not answer"),
    ("check-gateway-down", "check-gateway={method}: {gateway} does not answer"),
    ("connected-disabled", "interface '{interface}' or its address is disabled"),
    ("connected-wins", "the connected network on {interface} wins"),
    ("disabled", "route is disabled"),
    ("ecmp-default", "the default route is split per connection between {paths} paths at distance {distance} ({vias}): each leaves with a different address; make one a backup: {fix}"),
    ("ecmp-mixed", "{origins} routes share the traffic per connection at distance {distance} ({vias}): each leaves with a different address; make one a backup: {fix}"),
    ("ecmp-same", "{paths} {origin} paths share the traffic at distance {distance} ({vias})"),
    ("empty", "gateway is empty"),
    ("family-mismatch", "gateway {gateway} and dst-address {dst} are of different families"),
    ("interface-disabled", "interface '{interface}' (or its VRF) is disabled"),
    ("interface-down", "interface '{interface}' has no link"),
    ("loses-distance", "loses to distance {distance} (route {route} via {via})"),
    ("needs-interface", "link-local gateway {gateway} needs an interface: {gateway}%<interface>"),
    ("network-disabled", "the network of {gateway} is on a disabled address or interface"),
    ("no-interface", "interface '{interface}' does not exist"),
    ("no-table", "routing table '{table}' does not exist (create it with ip.vrf.add)"),
    ("not-on-interface", "{gateway} is not in a network of '{interface}'"),
    ("other-table", "'{interface}' is in routing table '{table}', not '{route_table}'"),
    ("own-address", "{gateway} is an address of this router (on '{interface}')"),
    ("tie", "route {route} via {via} has the same distance and wins"),
    ("unreachable", "{gateway} is not in any connected network of routing table '{table}'"),
];

/// Where a route comes from (RouterOS' `c s d` … source flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    Connected,
    Static,
    Dhcp,
    Ra,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Static => "static",
            Self::Dhcp => "dhcp",
            Self::Ra => "ra",
        }
    }
}

/// What a route does now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    /// Forwards traffic (alone or as one path of an ECMP group).
    Active,
    /// Usable, but a route with a lower distance wins: it takes over when
    /// that one goes.
    Standby,
    /// Not usable now (disabled, no link, gateway unreachable…).
    Inactive,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Inactive => "inactive",
        }
    }
}

/// How the route leaves the router when it is usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Via {
    pub link: IfName,
    pub gateway: Option<IpAddr>,
}

/// One route.
#[derive(Debug, Clone)]
pub struct Line {
    /// Stable identity for the GUI and the watch: the id of a static or
    /// DHCP route, a made-up key for connected and RA routes.
    pub key: String,
    pub id: Option<ItemId>,
    pub dst: IpNet,
    pub table: RoutingTable,
    pub distance: u8,
    pub origin: Origin,
    /// The gateway as configured (`10.0.0.1`, `ether1`, `fe80::1%ether2`).
    pub gateway: String,
    pub gateway_address: Option<IpAddr>,
    pub gateway_interface: Option<IfName>,
    pub via: Option<Via>,
    pub disabled: bool,
    /// Why it is inactive or standby (`None` when active).
    pub why: Option<Why>,
    pub check: Option<RouteCheck>,
    pub comment: String,
    pub state: State,
    /// Paths of its ECMP group (1: no ECMP).
    pub ecmp: usize,
    /// G1.27j: what to know about its ECMP group (active members only).
    /// Boxed: most routes have none, and a million lines are sorted.
    pub notice: Option<Box<Notice>>,
}

/// How much an ECMP group needs the operator's eye (G1.27j).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// Paths of one origin on a prefix that is not the default route (two
    /// static gateways, RA routers on a LAN): usually meant.
    Info,
    /// Paths of different origins (static + DHCP, two DHCP uplinks), or the
    /// default route: traffic to the internet leaves per connection by
    /// uplinks with different public addresses (a site sees one user come
    /// from two addresses; a dead uplink takes half the flows down).
    Warning,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
        }
    }
}

/// The ECMP notice of a route: one per group, on each active member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub level: Level,
    /// Its text: an id of [`REASONS`] (`ecmp-…`) with the arguments.
    pub why: Why,
    /// The command that makes one path a backup (warnings only).
    pub fix: Option<String>,
    /// The first member of its group (counted once by [`Summary`]).
    pub lead: bool,
}

impl Line {
    fn usable(&self) -> bool {
        self.via.is_some()
    }

    /// RouterOS flags for the terminal: X disabled, A active, then the
    /// source (D dynamic + C connect / S static; an RA route is just D).
    pub fn flags(&self) -> String {
        let mut f = String::new();
        if self.disabled {
            f.push('X');
        }
        if self.state == State::Active {
            f.push('A');
        }
        f.push_str(match self.origin {
            Origin::Connected => "DC",
            Origin::Ra => "D",
            Origin::Dhcp => "DS",
            Origin::Static => "S",
        });
        if self.ecmp > 1 && self.state == State::Active {
            f.push('+');
        }
        f
    }

    /// `10.0.0.1%ether1`, or the interface alone.
    pub fn immediate_gw(&self) -> Option<String> {
        self.via.as_ref().map(|v| match v.gateway {
            Some(g) => format!("{g}%{}", v.link),
            None => v.link.to_string(),
        })
    }
}

/// Main table first, then VRFs by name; inside a table by destination,
/// then distance (the winner first), then origin and id.
fn order(a: &Line, b: &Line) -> Ordering {
    (
        !a.table.is_main(),
        &a.table,
        a.dst,
        a.distance,
        a.origin,
        a.id,
        &a.key,
    )
        .cmp(&(
            !b.table.is_main(),
            &b.table,
            b.dst,
            b.distance,
            b.origin,
            b.id,
            &b.key,
        ))
}

/// Inputs that are not the config: what the platform and the clients know.
#[derive(Default)]
pub struct Live {
    pub learned: Vec<Learned>,
    /// Lease routes withheld by check-gateway, with why.
    pub withheld: Vec<(corerouter_model::RouteEntry, String)>,
    pub checks: HashMap<ItemId, RouteCheck>,
    /// Links known to have no carrier now.
    pub down: Vec<IfName>,
    /// The DHCP clock (ms), to say how long ago a check failed.
    pub now_ms: Option<u64>,
}

fn link_down(why_link: &IfName) -> Why {
    Why::new(
        "interface-down",
        format!("interface '{why_link}' has no link"),
    )
    .arg("interface", why_link)
}

/// Every route of `cfg` with its state (sorted like `ip.route.list`).
pub fn build(cfg: &Config, live: &Live) -> Vec<Line> {
    let down = |l: &IfName| live.down.contains(l);
    let mut lines: Vec<Line> = Vec::with_capacity(cfg.ip.routes.len() + cfg.ip.addresses.len());
    for r in cfg.ip.routes.iter() {
        let origin = if is_dynamic(r.id) {
            Origin::Dhcp
        } else {
            Origin::Static
        };
        let (via, why) = match route::reach(cfg, r) {
            Reach::Active { link, .. } if down(&link) => (None, Some(link_down(&link))),
            Reach::Active { link, gateway } => (Some(Via { link, gateway }), None),
            Reach::Inactive(why) | Reach::Invalid { why, .. } => (None, Some(why)),
        };
        lines.push(Line {
            key: r.id.to_string(),
            id: Some(r.id),
            dst: r.dst_address,
            table: r.routing_table.clone(),
            distance: r.distance,
            origin,
            gateway: r.gateway.to_string(),
            gateway_address: r.gateway.address(),
            gateway_interface: r.gateway.iface().cloned(),
            via,
            disabled: r.disabled,
            why,
            check: live.checks.get(&r.id).cloned(),
            comment: r.comment.clone(),
            state: State::Inactive,
            ecmp: 1,
            notice: None,
        });
    }
    // Lease routes whose gateway fails check-gateway (G4.7c), and static
    // ones (G1.27f).
    for (r, text) in &live.withheld {
        let check = live.checks.get(&r.id).cloned();
        let origin = if is_dynamic(r.id) {
            Origin::Dhcp
        } else {
            Origin::Static
        };
        // A static route's line is cached: its time is in `changed_secs`.
        let ago = check
            .as_ref()
            .filter(|_| origin == Origin::Dhcp)
            .and_then(|c| Some(live.now_ms?.saturating_sub(c.down_since_ms?) / 1000));
        let method = check.as_ref().map_or("arp", |c| c.method);
        let gw = r.gateway.to_string();
        let why = match ago {
            Some(s) => Why::new(
                "check-gateway",
                format!("check-gateway={method} failed {s} s ago: {gw} does not answer"),
            )
            .arg("method", method)
            .arg("gateway", &gw)
            .arg("secs", s),
            None => Why::new("check-gateway-down", text.clone())
                .arg("method", method)
                .arg("gateway", &gw),
        };
        lines.push(Line {
            key: r.id.to_string(),
            id: Some(r.id),
            dst: r.dst_address,
            table: r.routing_table.clone(),
            distance: r.distance,
            origin,
            gateway: gw,
            gateway_address: r.gateway.address(),
            gateway_interface: r.gateway.iface().cloned(),
            via: None,
            disabled: r.disabled,
            why: Some(why),
            check,
            comment: r.comment.clone(),
            state: State::Inactive,
            ecmp: 1,
            notice: None,
        });
    }
    for c in route::connected(cfg) {
        let (via, why) = if !c.active {
            (
                None,
                Some(
                    Why::new(
                        "connected-disabled",
                        format!("interface '{}' or its address is disabled", c.interface),
                    )
                    .arg("interface", &c.interface),
                ),
            )
        } else if down(&c.interface) {
            (None, Some(link_down(&c.interface)))
        } else {
            (
                Some(Via {
                    link: c.interface.clone(),
                    gateway: None,
                }),
                None,
            )
        };
        lines.push(Line {
            key: format!("connected {} {} {}", c.table, c.dst, c.interface),
            id: None,
            dst: c.dst,
            table: c.table,
            distance: 0,
            origin: Origin::Connected,
            gateway: c.interface.to_string(),
            gateway_address: None,
            gateway_interface: Some(c.interface),
            via,
            disabled: false,
            why,
            check: None,
            comment: String::new(),
            state: State::Inactive,
            ecmp: 1,
            notice: None,
        });
    }
    // What the kernel learned from Router Advertisements: its metric (1024
    // for a default router) is above every static distance, so they sort
    // last and lose to a static route, as in the kernel.
    for (n, l) in live.learned.iter().enumerate() {
        let Learned::Route {
            interface,
            dst,
            gateway,
            table,
            expires_secs,
            ..
        } = l
        else {
            continue;
        };
        let table = cfg
            .interfaces
            .iter()
            .find_map(|(name, i)| match i.kind {
                InterfaceKind::Vrf { table: t } if t == *table => {
                    Some(RoutingTable::Vrf(name.clone()))
                }
                _ => None,
            })
            .unwrap_or(RoutingTable::Main);
        let gateway_text = match gateway {
            Some(g) => format!("{g}%{interface}"),
            None => interface.to_string(),
        };
        lines.push(Line {
            key: format!("ra {table} {dst} {gateway_text}"),
            id: Some(ra_id(n)),
            dst: IpNet::V6(*dst),
            table,
            distance: u8::MAX,
            origin: Origin::Ra,
            gateway: gateway_text,
            gateway_address: gateway.map(IpAddr::V6),
            gateway_interface: Some(interface.clone()),
            via: Some(Via {
                link: interface.clone(),
                gateway: gateway.map(IpAddr::V6),
            }),
            disabled: false,
            why: None,
            check: None,
            comment: match expires_secs {
                Some(e) => format!("router advertisement, expires in {e}s"),
                None => "router advertisement".into(),
            },
            state: State::Inactive,
            ecmp: 1,
            notice: None,
        });
    }
    lines.sort_by(order);
    select(&mut lines);
    lines
}

/// Whether two routes at the same distance share traffic. Static and DHCP
/// routes do (RouterOS v7; the kernel holds them as one multipath route);
/// RA routes from several routers do (the kernel merges them); connected
/// routes do not: the first one wins, as in the kernel.
fn shares(a: Origin, b: Origin) -> bool {
    let installed = |o| matches!(o, Origin::Static | Origin::Dhcp);
    (installed(a) && installed(b)) || (a == Origin::Ra && b == Origin::Ra)
}

/// Decide the state of every line. `lines` is sorted by `order`, so each
/// (table, dst) is one run and its usable winner comes first: one pass.
fn select(lines: &mut [Line]) {
    let mut start = 0;
    while start < lines.len() {
        let (table, dst) = match lines.get(start) {
            Some(l) => (l.table.clone(), l.dst),
            None => break,
        };
        let end = lines
            .iter()
            .skip(start)
            .position(|l| l.table != table || l.dst != dst)
            .map_or(lines.len(), |n| start + n);
        if let Some(group) = lines.get_mut(start..end) {
            select_group(group);
        }
        start = end;
    }
}

fn select_group(group: &mut [Line]) {
    let winner = group
        .iter()
        .find(|l| l.usable())
        .map(|w| (w.distance, w.origin, w.key.clone(), w.immediate_gw(), w.id));
    let Some((distance, origin, wkey, wvia, wid)) = winner else {
        for l in group.iter_mut() {
            l.state = State::Inactive;
        }
        return;
    };
    let ecmp = group
        .iter()
        .filter(|l| {
            l.usable() && l.distance == distance && (l.key == wkey || shares(l.origin, origin))
        })
        .count();
    for l in group.iter_mut() {
        l.notice = None;
        if !l.usable() {
            l.state = State::Inactive;
            continue;
        }
        let shared = l.distance == distance && (l.key == wkey || shares(l.origin, origin));
        if shared {
            l.state = State::Active;
            l.ecmp = ecmp;
            l.why = None;
            continue;
        }
        l.state = State::Standby;
        let via = wvia.clone().unwrap_or_default();
        let name = wid.map_or_else(|| "connected".to_owned(), |i| i.to_string());
        l.why = Some(if origin == Origin::Connected {
            Why::new(
                "connected-wins",
                format!("the connected network on {via} wins"),
            )
            .arg("interface", &via)
        } else if l.distance == distance {
            Why::new(
                "tie",
                format!("route {name} via {via} has the same distance and wins"),
            )
            .arg("route", &name)
            .arg("via", &via)
        } else {
            Why::new(
                "loses-distance",
                format!("loses to distance {distance} (route {name} via {via})"),
            )
            .arg("distance", distance)
            .arg("route", &name)
            .arg("via", &via)
        });
    }
    if ecmp > 1 {
        let notice = ecmp_notice(group, distance);
        let mut lead = true;
        for l in group.iter_mut().filter(|l| l.state == State::Active) {
            l.notice = Some(Box::new(Notice {
                lead,
                ..notice.clone()
            }));
            lead = false;
        }
    }
}

/// The client of a lease route: (command area, client id).
fn lease_client(id: ItemId) -> Option<(&'static str, ItemId)> {
    let client = ItemId((id.0 >> 8) & 0x3_FFFF);
    if crate::dhcp6_client::is_dynamic6(id) {
        Some(("ipv6.dhcp-client", client))
    } else if id.0 & 0xFC00_0000 == crate::dhcp_client::DYN_BASE {
        Some(("ip.dhcp-client", client))
    } else {
        None
    }
}

/// Paths an ECMP notice names (the rest are counted).
const NOTICE_PATHS: usize = 4;

/// What the active paths of one ECMP group at `distance` mean (G1.27j).
/// One pass over the group: the whole table stays O(n).
fn ecmp_notice(group: &[Line], distance: u8) -> Notice {
    let active: Vec<&Line> = group.iter().filter(|l| l.state == State::Active).collect();
    let mut origins: Vec<Origin> = active.iter().map(|l| l.origin).collect();
    origins.sort_unstable();
    origins.dedup();
    // Two leases are two uplinks even when both say "dhcp".
    let mut clients: Vec<(&str, ItemId)> = active.iter().filter_map(|l| l.id.and_then(lease_client)).collect();
    clients.sort_unstable();
    clients.dedup();
    let default = active.first().is_some_and(|l| l.dst.prefix_len() == 0);
    let mixed = origins.len() > 1 || clients.len() > 1;
    // At most NOTICE_PATHS named: each member keeps a copy of the text, so
    // a group of k paths stays O(k), not O(k²).
    let mut vias = active
        .iter()
        .take(NOTICE_PATHS)
        .map(|l| {
            let name = l.id.map_or_else(|| l.origin.as_str().to_owned(), |i| i.to_string());
            format!("{name} via {}", l.immediate_gw().unwrap_or_default())
        })
        .collect::<Vec<_>>()
        .join(", ");
    if active.len() > NOTICE_PATHS {
        vias.push_str(&format!(" and {} more", active.len() - NOTICE_PATHS));
    }
    let paths = active.len();
    if !mixed && !default {
        let origin = origins.first().map_or("", |o| o.as_str());
        return Notice {
            level: Level::Info,
            why: Why::new(
                "ecmp-same",
                format!("{paths} {origin} paths share the traffic at distance {distance} ({vias})"),
            )
            .arg("paths", paths)
            .arg("origin", origin)
            .arg("distance", distance)
            .arg("vias", &vias),
            fix: None,
            lead: false,
        };
    }
    // The backup: a lease route first (its client's distance, 254 like a
    // new client's), else the last static path one step further.
    let backup = u8::try_from(u16::from(distance) + 1).unwrap_or(u8::MAX);
    let fix = active
        .iter()
        .find_map(|l| l.id.and_then(lease_client))
        .map(|(area, client)| {
            let d = corerouter_model::dhcp_client::DEFAULT_ROUTE_DISTANCE.max(backup);
            format!("{area}.set {{\"id\":\"{client}\",\"default_route_distance\":{d}}}")
        })
        .or_else(|| {
            active
                .iter()
                .rev()
                .find(|l| l.origin == Origin::Static)
                .and_then(|l| l.id)
                .map(|id| format!("ip.route.set {{\"id\":\"{id}\",\"distance\":{backup}}}"))
        });
    let fix_text = fix.clone().unwrap_or_else(|| "raise the distance of one of them".into());
    let why = if mixed {
        let names: Vec<&str> = origins.iter().map(|o| o.as_str()).collect();
        let names = if names.len() > 1 { names.join(" + ") } else { format!("{} {}", clients.len(), names.join("")) };
        Why::new(
            "ecmp-mixed",
            format!(
                "{names} routes share the traffic per connection at distance {distance} ({vias}): \
                 each leaves with a different address; make one a backup: {fix_text}"
            ),
        )
        .arg("origins", &names)
    } else {
        Why::new(
            "ecmp-default",
            format!(
                "the default route is split per connection between {paths} paths at distance \
                 {distance} ({vias}): each leaves with a different address; make one a backup: \
                 {fix_text}"
            ),
        )
        .arg("paths", paths)
    };
    Notice {
        level: Level::Warning,
        why: why.arg("distance", distance).arg("vias", &vias).arg("fix", &fix_text),
        fix,
        lead: false,
    }
}

/// The lines of one (table, prefix): `lines` is sorted by [`order`], so a
/// binary search finds the run (O(log n), a full table of 1 M routes too).
fn group_of<'a>(lines: &'a [Line], table: &RoutingTable, dst: IpNet) -> &'a [Line] {
    let want = (!table.is_main(), table, dst);
    let start = lines.partition_point(|l| (!l.table.is_main(), &l.table, l.dst) < want);
    let rest = lines.get(start..).unwrap_or(&[]);
    let len = rest
        .iter()
        .take_while(|l| l.table == *table && l.dst == dst)
        .count();
    rest.get(..len).unwrap_or(&[])
}

/// What a route a client installed (DHCP, DHCPv6) does in the table
/// (G1.27h): the client's list says it, so an operator sees why traffic
/// leaves elsewhere without reading the whole table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fate {
    /// `0.0.0.0/0 via 10.15.0.1%eth0`.
    pub route: String,
    pub state: State,
    /// Paths of its ECMP group when active (1: alone).
    pub ecmp: usize,
    /// Why it is not the route in use, or with whom it shares the traffic.
    pub note: Option<String>,
    /// The level of its ECMP notice (G1.27j).
    pub notice: Option<Level>,
}

/// The [`Fate`] of the route `id` of `table`/`dst` (gateway text `gw`).
pub(crate) fn fate(
    lines: &[Line],
    id: ItemId,
    table: &RoutingTable,
    dst: IpNet,
    gw: &str,
) -> Fate {
    let route = format!("{dst} via {gw}");
    let group = group_of(lines, table, dst);
    let Some(me) = group.iter().find(|l| l.id == Some(id)) else {
        return Fate {
            note: Some(format!("route {route} is not in the routing table")),
            route,
            state: State::Inactive,
            ecmp: 1,
            notice: None,
        };
    };
    let note = match me.state {
        State::Active if me.ecmp > 1 => {
            let others: Vec<String> = group
                .iter()
                .filter(|l| l.state == State::Active && l.id != Some(id))
                .map(|l| {
                    let name = l.id.map_or_else(|| "connected".to_owned(), |i| i.to_string());
                    format!("{name} via {}", l.immediate_gw().unwrap_or_default())
                })
                .collect();
            let fix = me.notice.as_ref().and_then(|n| n.fix.as_deref());
            Some(match me.notice.as_ref().map(|n| n.level) {
                // G1.27j: an uplink of its own next to another route.
                Some(Level::Warning) => format!(
                    "warning: route {route} shares the traffic (ECMP) with {} at distance {}: \
                     each connection leaves by one of them, with a different address; make one \
                     a backup: {}",
                    others.join(", "),
                    me.distance,
                    fix.unwrap_or("raise the distance of one of them")
                ),
                _ => format!(
                    "route {route} shares the traffic (ECMP) with {} at distance {}; \
                     raise the distance to keep it as a backup",
                    others.join(", "),
                    me.distance
                ),
            })
        }
        State::Active => None,
        State::Standby | State::Inactive => Some(format!(
            "route {route} is {}: {}",
            me.state.as_str(),
            me.why.as_ref().map_or("", |w| w.text.as_str())
        )),
    };
    Fate {
        route,
        state: me.state,
        ecmp: me.ecmp,
        note,
        notice: me.notice.as_ref().map(|n| n.level),
    }
}

impl Session {
    /// What [`build`] needs besides the config.
    pub(crate) fn route_live(&mut self, cfg: &Config) -> Live {
        let learned = self.hal_mut().ipv6_learned().unwrap_or_default();
        let withheld = self.dhcp_withheld(cfg);
        let checks = self.dhcp_route_checks().into_iter().collect();
        let down = self.links.down_links();
        Live {
            learned,
            withheld,
            checks,
            down,
            now_ms: self.dhcp.now_ms,
        }
    }

    /// Every route of the candidate config (what `ip.route.list` shows;
    /// the running one outside a transaction), with state. From the
    /// [`RouteCache`] when nothing it was built from changed (G1.27c).
    pub(crate) fn route_lines(&mut self) -> Arc<Vec<Line>> {
        self.cached_routes().0
    }

    /// The lines, their counts and the cache generation.
    pub(crate) fn cached_routes(&mut self) -> (Arc<Vec<Line>>, Arc<Summary>, u64) {
        let base = self.store().candidate().clone();
        let live = self.route_live(&base);
        let mut checks: Vec<(ItemId, RouteCheck)> =
            live.checks.iter().map(|(k, v)| (*k, v.clone())).collect();
        checks.sort_by_key(|(k, _)| *k);
        let key = CacheKey {
            generation: self.store().generation(),
            dynamic: self.dynamic_fingerprint(),
            checked: self.static_checks_generation(),
            learned: live.learned.clone(),
            down: live.down.clone(),
            checks,
        };
        // A withheld lease route says how long ago its check failed: never
        // kept (only on a router with a failing DHCP gateway).
        let keep = live.withheld.is_empty();
        if keep
            && let Some(c) = self.ext::<RouteCache>()
            && c.key.as_ref() == Some(&key)
        {
            return (Arc::clone(&c.lines), Arc::clone(&c.summary), c.generation);
        }
        let cfg = self.effective(&base).into_owned();
        let mut live = live;
        self.static_live(&base, &mut live);
        let lines = Arc::new(build(&cfg, &live));
        let summary = Arc::new(Summary::of(&lines));
        let Some(c) = self.ext_mut::<RouteCache>() else {
            return (lines, summary, 0);
        };
        c.key = keep.then_some(key);
        c.lines = Arc::clone(&lines);
        c.summary = Arc::clone(&summary);
        c.generation = c.generation.wrapping_add(1);
        (lines, summary, c.generation)
    }

    /// What the DHCP and DHCPv6 clients and the DHCPv6 server add to the
    /// config now, as a hash: the cache is rebuilt when it changes.
    fn dynamic_fingerprint(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for (id, r) in &self.dhcp.runners {
            id.hash(&mut h);
            format!("{:?}{:?}{:?}", r.addresses, r.routes, r.fallback).hash(&mut h);
            (r.gw.health.down, r.gw.target).hash(&mut h);
        }
        for (id, r) in &self.dhcp6.runners {
            id.hash(&mut h);
            format!("{:?}{:?}{:?}", r.addresses, r.routes, r.pool.as_ref().map(|p| p.value)).hash(&mut h);
        }
        self.dhcp6_server_routes_text().hash(&mut h);
        h.finish()
    }

    /// The effective `base` (with the DHCP routes) and its routes.
    pub(crate) fn route_lines_of(&mut self, base: &Config) -> (Config, Vec<Line>) {
        let cfg = self.effective(base).into_owned();
        let mut live = self.route_live(&cfg);
        self.static_live(base, &mut live);
        let lines = build(&cfg, &live);
        (cfg, lines)
    }

    /// The static routes' checks (G1.27f): taken from `base` (the routes
    /// a down gateway withholds are not in the effective config), only
    /// when the lines are built — the cache key is their generation.
    fn static_live(&self, base: &Config, live: &mut Live) {
        let (checks, withheld) = self.static_route_checks(base);
        live.checks.extend(checks);
        live.withheld.extend(withheld);
    }
}

/// Routes whose state changes are followed at most (hostile-input bound;
/// a full table belongs to BGP, which keeps its own, **estimado**).
const MAX_WATCHED: usize = 200_000;
/// Above this many routes the tick looks every [`SLOW_EVERY`] s, not every
/// second (one look at 10 000 routes costs ~10 ms, **estimado** from the
/// `ip.route.list` bench).
const FAST_LIMIT: usize = 4_096;
const SLOW_EVERY: u64 = 10;

/// When each route last changed state (the Changed column). Operational
/// state: never saved, gone after a restart.
#[derive(Debug, Default)]
pub struct RouteWatch {
    /// First look with a clock.
    pub since: Option<u64>,
    last_look: Option<u64>,
    /// Shared with the lists that read it outside the lock (G0.31b):
    /// a look copies it only when a state changed.
    states: Arc<HashMap<String, Seen>>,
    /// The table the last look saw ([`RouteWatch::observe_shared`]).
    looked: Option<Arc<Vec<Line>>>,
    /// Each route's state changes (G1.27b): failover, link down and back.
    /// At most [`MAX_CHANGES`] per route, the last [`KEEP_SECS`].
    changes: HashMap<String, VecDeque<Change>>,
}

/// Changes kept per route, and for how long (the detail panel shows the
/// last 24 h; a flapping link fills the ring, not the memory).
pub const MAX_CHANGES: usize = 64;
pub const KEEP_SECS: u64 = 86_400;
/// Transitions logged per look (topic `route`): a table that flips all at
/// once (a link with 10 000 routes behind it) does not flood the log.
const MAX_LOGGED: usize = 16;

/// One state change of a route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// Unix second.
    pub at: u64,
    pub from: State,
    pub to: State,
    /// Why it is in `to` (none when it became active).
    pub reason: Option<Why>,
}

/// A change the look saw, for the log.
#[derive(Debug, Clone)]
pub struct Transition {
    pub key: String,
    pub dst: IpNet,
    pub table: RoutingTable,
    pub change: Change,
}

/// What the watch knows of one route.
#[derive(Debug, Clone, Copy)]
struct Seen {
    state: State,
    /// Unix second it took `state`; `None`: already so when watching began.
    at: Option<u64>,
}

/// [`RouteWatch::changed`]: a copy of the states that costs a pointer.
#[derive(Debug, Clone, Default)]
pub struct Changed(Arc<HashMap<String, Seen>>);

impl Changed {
    /// Unix second `key` took its current state, if known.
    pub fn changed_at(&self, key: &str) -> Option<u64> {
        self.0.get(key).and_then(|s| s.at)
    }
}

impl RouteWatch {
    /// Note the states of `lines` at `now`; routes gone are forgotten.
    /// In place: a key already known is not copied again. Returns the
    /// state changes it saw.
    pub fn observe(&mut self, lines: &[Line], now: u64) -> Vec<Transition> {
        let first = self.since.is_none();
        self.since.get_or_insert(now);
        self.last_look = Some(now);
        let mut out = Vec::new();
        // Read first, write after: a look that changes nothing leaves the
        // map shared with the lists built from it (G0.31b).
        let mut writes: Vec<(&Line, Seen)> = Vec::new();
        for l in lines.iter().take(MAX_WATCHED) {
            match self.states.get(&l.key) {
                Some(seen) if seen.state != l.state => {
                    let change = Change {
                        at: now,
                        from: seen.state,
                        to: l.state,
                        reason: l.why.clone(),
                    };
                    let ring = self.changes.entry(l.key.clone()).or_default();
                    if ring.len() >= MAX_CHANGES {
                        ring.pop_front();
                    }
                    ring.push_back(change.clone());
                    out.push(Transition {
                        key: l.key.clone(),
                        dst: l.dst,
                        table: l.table.clone(),
                        change,
                    });
                    writes.push((
                        l,
                        Seen {
                            state: l.state,
                            at: Some(now),
                        },
                    ));
                }
                Some(_) => {}
                None => writes.push((
                    l,
                    Seen {
                        state: l.state,
                        at: (!first).then_some(now),
                    },
                )),
            }
        }
        if !writes.is_empty() {
            let states = Arc::make_mut(&mut self.states);
            for (l, seen) in writes {
                states.insert(l.key.clone(), seen);
            }
        }
        if self.states.len() > lines.len().min(MAX_WATCHED) {
            let live: std::collections::HashSet<&str> = lines
                .iter()
                .take(MAX_WATCHED)
                .map(|l| l.key.as_str())
                .collect();
            Arc::make_mut(&mut self.states).retain(|k, _| live.contains(k.as_str()));
            let states = &self.states;
            self.changes.retain(|k, _| states.contains_key(k));
        }
        let old = now.saturating_sub(KEEP_SECS);
        for ring in self.changes.values_mut() {
            while ring.front().is_some_and(|c| c.at < old) {
                ring.pop_front();
            }
        }
        self.changes.retain(|_, r| !r.is_empty());
        out
    }

    /// [`Self::observe`], skipped when `lines` is the table the last look
    /// saw (the [`RouteCache`] hands out the same `Arc` while nothing it
    /// was built from changed): no state can have changed, and a list of
    /// 60 000 routes does not walk them all under the lock again.
    pub fn observe_shared(&mut self, lines: &Arc<Vec<Line>>, now: u64) -> Vec<Transition> {
        if self.looked.as_ref().is_some_and(|l| Arc::ptr_eq(l, lines)) {
            self.last_look = Some(now);
            return Vec::new();
        }
        self.looked = Some(Arc::clone(lines));
        self.observe(lines, now)
    }

    /// When each route took its state, shared: read without the session.
    pub fn changed(&self) -> Changed {
        Changed(Arc::clone(&self.states))
    }

    /// The changes of `key` in the last 24 h, newest first.
    pub fn changes_of(&self, key: &str, now: u64) -> Vec<&Change> {
        let old = now.saturating_sub(KEEP_SECS);
        self.changes
            .get(key)
            .map(|r| r.iter().rev().filter(|c| c.at >= old).collect())
            .unwrap_or_default()
    }

    /// Unix second `key` took its current state, if known.
    pub fn changed_at(&self, key: &str) -> Option<u64> {
        self.states.get(key).and_then(|s| s.at)
    }

    fn due(&self, routes: usize, now: u64) -> bool {
        routes <= FAST_LIMIT
            || self
                .last_look
                .is_none_or(|t| now.saturating_sub(t) >= SLOW_EVERY)
    }
}

/// What the lines were built from: the candidate's generation, the dynamic
/// entries (DHCP, DHCPv6) and the live state. Equal key, same lines.
#[derive(Debug, Clone, PartialEq)]
struct CacheKey {
    generation: u64,
    dynamic: u64,
    /// The static routes' checks (G1.27f, [`crate::gateway_check`]).
    checked: u64,
    learned: Vec<Learned>,
    down: Vec<IfName>,
    checks: Vec<(ItemId, RouteCheck)>,
}

/// The counts of the whole table, kept with the lines (the window's footer
/// asks for them every refresh: no pass over a million routes each time).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    pub total: usize,
    pub active: usize,
    pub standby: usize,
    pub inactive: usize,
    pub ipv4: usize,
    pub ipv6: usize,
    pub origins: BTreeMap<&'static str, usize>,
    pub tables: BTreeMap<String, usize>,
    /// ECMP groups by level (G1.27j), and the first warning's prefix with
    /// its paths and the fix (the health check says it without a pass).
    pub ecmp_warning: usize,
    pub ecmp_info: usize,
    pub ecmp_first: Option<(String, Option<String>)>,
}

impl Summary {
    pub fn of(lines: &[Line]) -> Self {
        let mut s = Self::default();
        let mut run: Option<(&RoutingTable, usize)> = None;
        for l in lines {
            s.total += 1;
            match l.state {
                State::Active => s.active += 1,
                State::Standby => s.standby += 1,
                State::Inactive => s.inactive += 1,
            }
            if l.dst.addr().is_ipv4() {
                s.ipv4 += 1;
            } else {
                s.ipv6 += 1;
            }
            *s.origins.entry(l.origin.as_str()).or_default() += 1;
            if let Some(n) = l.notice.as_ref().filter(|n| n.lead) {
                match n.level {
                    Level::Info => s.ecmp_info += 1,
                    Level::Warning => {
                        s.ecmp_warning += 1;
                        if s.ecmp_first.is_none() {
                            let vias = n.why.args.iter().find(|(k, _)| *k == "vias").map_or("", |(_, v)| v.as_str());
                            s.ecmp_first = Some((format!("{} ({vias})", l.dst), n.fix.clone()));
                        }
                    }
                }
            }
            // Lines come sorted by table: count each run, name it once.
            match &mut run {
                Some((t, n)) if *t == &l.table => *n += 1,
                _ => {
                    if let Some((t, n)) = run.take() {
                        *s.tables.entry(t.to_string()).or_default() += n;
                    }
                    run = Some((&l.table, 1));
                }
            }
        }
        if let Some((t, n)) = run {
            *s.tables.entry(t.to_string()).or_default() += n;
        }
        s
    }
}

/// The lines of the candidate config and their counts (G1.27c): built once
/// and kept until the config, a DHCP lease, a link or what the kernel
/// learned changes. A million routes cost a few hundred ms to build; a read
/// that finds them here costs only its own pass.
#[derive(Debug, Default)]
pub struct RouteCache {
    key: Option<CacheKey>,
    pub lines: Arc<Vec<Line>>,
    pub summary: Arc<Summary>,
    /// Bumped by every rebuild: the GUI can tell a new table from a reread.
    pub generation: u64,
}

impl Session {
    /// Note route state changes (from `tick`, once a second).
    pub(crate) fn watch_routes(&mut self) {
        let Some(now) = self.now() else { return };
        let routes = self.store().candidate().ip.routes.len();
        if !self.ext::<RouteWatch>().is_none_or(|w| w.due(routes, now)) {
            return;
        }
        let lines = self.route_lines();
        let seen = self
            .ext_mut::<RouteWatch>()
            .map(|w| w.observe_shared(&lines, now))
            .unwrap_or_default();
        self.log_route_changes(&seen);
    }

    /// Topic `route`, like RouterOS' route log: a failover, a link down.
    fn log_route_changes(&mut self, seen: &[Transition]) {
        for t in seen.iter().take(MAX_LOGGED) {
            let c = &t.change;
            let table = if t.table.is_main() {
                String::new()
            } else {
                format!(" (table {})", t.table)
            };
            let why = c
                .reason
                .as_ref()
                .map(|r| format!(": {}", r.text))
                .unwrap_or_default();
            let message = format!(
                "route {} {}{table}: {} -> {}{why}",
                t.key,
                t.dst,
                c.from.as_str(),
                c.to.as_str()
            );
            self.log_event(
                &["route", "info"],
                crate::logging::DAEMON,
                message,
                serde_json::json!({"key": t.key, "from": c.from.as_str(), "to": c.to.as_str()}),
            );
        }
        if seen.len() > MAX_LOGGED {
            self.log_event(
                &["route", "info"],
                crate::logging::DAEMON,
                format!("{} more routes changed state", seen.len() - MAX_LOGGED),
                serde_json::Value::Null,
            );
        }
    }

    /// `route_lines`, noted by the watch too (`ip.route.list` and the
    /// lookup see the change at once, not at the next tick).
    pub(crate) fn watched_route_lines(&mut self) -> (Arc<Vec<Line>>, Option<u64>) {
        let lines = self.route_lines();
        let now = self.now();
        if let Some(now) = now {
            let seen = self
                .ext_mut::<RouteWatch>()
                .map(|w| w.observe_shared(&lines, now))
                .unwrap_or_default();
            self.log_route_changes(&seen);
        }
        (lines, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(id: u32, dst: &str, distance: u8, origin: Origin, gw: &str, up: bool) -> Line {
        let gateway: IpAddr = gw.parse().unwrap();
        Line {
            key: ItemId(id).to_string(),
            id: Some(ItemId(id)),
            dst: dst.parse().unwrap(),
            table: RoutingTable::Main,
            distance,
            origin,
            gateway: gw.to_owned(),
            gateway_address: Some(gateway),
            gateway_interface: None,
            via: up.then(|| Via {
                link: "ether1".parse().unwrap(),
                gateway: Some(gateway),
            }),
            disabled: false,
            why: (!up).then(|| Why::new("unreachable", "unreachable".into())),
            check: None,
            comment: String::new(),
            state: State::Inactive,
            ecmp: 1,
            notice: None,
        }
    }

    fn table(mut lines: Vec<Line>) -> Vec<Line> {
        lines.sort_by(order);
        select(&mut lines);
        lines
    }

    #[test]
    fn group_of_finds_one_prefix_among_many() {
        let mut v: Vec<Line> = (0..1000u32)
            .map(|n| {
                let dst = format!("10.{}.{}.0/24", n / 256, n % 256);
                line(n + 1, &dst, 1, Origin::Static, "10.0.0.1", true)
            })
            .collect();
        v.push(line(5000, "10.0.7.0/24", 1, Origin::Dhcp, "10.0.0.2", true));
        let v = table(v);
        let g = group_of(&v, &RoutingTable::Main, "10.0.7.0/24".parse().unwrap());
        assert_eq!(g.len(), 2);
        assert!(group_of(&v, &RoutingTable::Main, "192.0.2.0/24".parse().unwrap()).is_empty());
    }

    #[test]
    fn fate_says_ecmp_standby_and_inactive() {
        let dst: IpNet = "0.0.0.0/0".parse().unwrap();
        let main = RoutingTable::Main;
        // Same distance: ECMP, named with the other path.
        let v = table(vec![
            line(1, "0.0.0.0/0", 1, Origin::Static, "192.168.122.1", true),
            line(0xDC00_0101, "0.0.0.0/0", 1, Origin::Dhcp, "10.15.0.1", true),
        ]);
        let f = fate(&v, ItemId(0xDC00_0101), &main, dst, "10.15.0.1%eth0");
        assert_eq!((f.state, f.ecmp), (State::Active, 2));
        let note = f.note.unwrap();
        assert!(note.contains("ECMP") && note.contains("*1 via 192.168.122.1"), "{note}");
        // Higher distance: standby, with the winner.
        let v = table(vec![
            line(1, "0.0.0.0/0", 1, Origin::Static, "192.168.122.1", true),
            line(0xDC00_0101, "0.0.0.0/0", 2, Origin::Dhcp, "10.15.0.1", true),
        ]);
        let f = fate(&v, ItemId(0xDC00_0101), &main, dst, "10.15.0.1");
        assert_eq!(f.state, State::Standby);
        assert!(f.note.unwrap().contains("loses to distance 1 (route *1"));
        // Unreachable gateway: inactive, with the reason.
        let v = table(vec![line(0xDC00_0101, "0.0.0.0/0", 1, Origin::Dhcp, "10.15.0.1", false)]);
        let f = fate(&v, ItemId(0xDC00_0101), &main, dst, "10.15.0.1");
        assert_eq!(f.state, State::Inactive);
        assert!(f.note.unwrap().contains("is inactive: unreachable"));
        // Alone and active: nothing to say. Missing: said.
        let v = table(vec![line(0xDC00_0101, "0.0.0.0/0", 1, Origin::Dhcp, "10.15.0.1", true)]);
        assert_eq!(fate(&v, ItemId(0xDC00_0101), &main, dst, "x").note, None);
        assert!(fate(&[], ItemId(7), &main, dst, "x").note.unwrap().contains("not in the routing table"));
    }

    fn notice(v: &[Line], id: u32) -> Option<&Notice> {
        v.iter().find(|l| l.id == Some(ItemId(id)))?.notice.as_deref()
    }

    /// G1.27j: a static and a DHCP default at the same distance warn, with
    /// the command that makes the lease a backup; counted once.
    #[test]
    fn ecmp_of_static_and_dhcp_warns_with_the_fix() {
        let v = table(vec![
            line(1, "0.0.0.0/0", 1, Origin::Static, "192.168.122.1", true),
            line(0xDC00_0101, "0.0.0.0/0", 1, Origin::Dhcp, "10.15.0.1", true),
        ]);
        for id in [1, 0xDC00_0101] {
            let n = notice(&v, id).unwrap();
            assert_eq!(n.level, Level::Warning);
            assert_eq!(n.why.id, "ecmp-mixed");
            assert_eq!(
                n.fix.as_deref(),
                Some(r#"ip.dhcp-client.set {"id":"*1","default_route_distance":254}"#)
            );
            assert!(n.why.text.contains("static + dhcp"), "{}", n.why.text);
        }
        let s = Summary::of(&v);
        assert_eq!((s.ecmp_warning, s.ecmp_info), (1, 0));
        assert!(s.ecmp_first.unwrap().0.starts_with("0.0.0.0/0 (*1 via 192.168.122.1%ether1, "));
        let f = fate(&v, ItemId(0xDC00_0101), &RoutingTable::Main, "0.0.0.0/0".parse().unwrap(), "x");
        assert_eq!(f.notice, Some(Level::Warning));
        assert!(f.note.unwrap().starts_with("warning:"));
    }

    /// Two static gateways to one network: info. To the default route:
    /// a warning whose fix moves the last one a step back.
    #[test]
    fn ecmp_of_one_origin_is_info_except_the_default_route() {
        let v = table(vec![
            line(1, "10.9.0.0/16", 1, Origin::Static, "192.168.122.1", true),
            line(2, "10.9.0.0/16", 1, Origin::Static, "192.168.122.2", true),
        ]);
        let n = notice(&v, 1).unwrap();
        assert_eq!((n.level, n.why.id, n.fix.as_ref()), (Level::Info, "ecmp-same", None));
        assert_eq!(Summary::of(&v).ecmp_info, 1);
        let v = table(vec![
            line(1, "0.0.0.0/0", 3, Origin::Static, "192.168.122.1", true),
            line(2, "0.0.0.0/0", 3, Origin::Static, "192.168.122.2", true),
        ]);
        let n = notice(&v, 1).unwrap();
        assert_eq!((n.level, n.why.id), (Level::Warning, "ecmp-default"));
        assert_eq!(n.fix.as_deref(), Some(r#"ip.route.set {"id":"*2","distance":4}"#));
        // Two DHCP uplinks are two origins even on another prefix.
        let v = table(vec![
            line(0xDC00_0101, "10.9.0.0/16", 5, Origin::Dhcp, "10.15.0.1", true),
            line(0xDC00_0201, "10.9.0.0/16", 5, Origin::Dhcp, "10.16.0.1", true),
        ]);
        assert_eq!(notice(&v, 0xDC00_0101).unwrap().why.id, "ecmp-mixed");
    }

    /// A group of many paths names four of them: each member's copy of the
    /// text stays short.
    #[test]
    fn a_wide_group_names_four_paths() {
        let v = table(
            (1..=64u32)
                .map(|n| line(n, "10.9.0.0/16", 1, Origin::Static, &format!("192.168.122.{n}"), true))
                .collect(),
        );
        let n = notice(&v, 1).unwrap();
        assert!(n.why.text.contains("and 60 more"), "{}", n.why.text);
        assert!(n.why.text.len() < 300, "{}", n.why.text);
    }

    /// Breaking the tie takes the notice away (the lease becomes standby).
    #[test]
    fn breaking_the_tie_clears_the_notice() {
        let mut v = table(vec![
            line(1, "0.0.0.0/0", 1, Origin::Static, "192.168.122.1", true),
            line(0xDC00_0101, "0.0.0.0/0", 1, Origin::Dhcp, "10.15.0.1", true),
        ]);
        assert!(notice(&v, 1).is_some());
        for l in v.iter_mut() {
            if l.origin == Origin::Dhcp {
                l.distance = 254;
            }
        }
        let v = table(v);
        assert!(v.iter().all(|l| l.notice.is_none()));
        let s = Summary::of(&v);
        assert_eq!((s.ecmp_warning, s.ecmp_info, s.ecmp_first), (0, 0, None));
    }

    /// One pass per group: 50 000 ECMP pairs (100 000 routes) build in linear
    /// time (no comparison of every route with every other).
    #[test]
    fn notices_are_linear_in_the_table() {
        let mut v = Vec::new();
        for n in 0..50_000u32 {
            let dst = format!("10.{}.{}.0/24", n / 256 % 256, n % 256);
            v.push(line(2 * n + 1, &dst, 1, Origin::Static, "192.168.122.1", true));
            v.push(line(2 * n + 2, &dst, 1, Origin::Static, "192.168.122.2", true));
        }
        let v = table(v);
        assert_eq!(Summary::of(&v).ecmp_info, 50_000);
    }
}
