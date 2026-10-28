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
            Some(format!(
                "route {route} shares the traffic (ECMP) with {} at distance {}; \
                 raise the distance to keep it as a backup",
                others.join(", "),
                me.distance
            ))
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
    states: HashMap<String, Seen>,
    /// Bumped by every look: an entry not seen by the last one is gone.
    generation: u64,
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
    generation: u64,
}

impl RouteWatch {
    /// Note the states of `lines` at `now`; routes gone are forgotten.
    /// In place: a key already known is not copied again. Returns the
    /// state changes it saw.
    pub fn observe(&mut self, lines: &[Line], now: u64) -> Vec<Transition> {
        let first = self.since.is_none();
        self.since.get_or_insert(now);
        self.last_look = Some(now);
        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;
        let mut out = Vec::new();
        for l in lines.iter().take(MAX_WATCHED) {
            match self.states.get_mut(&l.key) {
                Some(seen) => {
                    if seen.state != l.state {
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
                        seen.state = l.state;
                        seen.at = Some(now);
                    }
                    seen.generation = generation;
                }
                None => {
                    self.states.insert(
                        l.key.clone(),
                        Seen {
                            state: l.state,
                            at: (!first).then_some(now),
                            generation,
                        },
                    );
                }
            }
        }
        if self.states.len() > lines.len().min(MAX_WATCHED) {
            self.states.retain(|_, s| s.generation == generation);
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
            .map(|w| w.observe(&lines, now))
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
                .map(|w| w.observe(&lines, now))
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
}
