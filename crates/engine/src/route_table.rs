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
use std::collections::HashMap;
use std::net::IpAddr;

use corerouter_hal::Learned;
use corerouter_model::route::{self, Reach, Why};
use corerouter_model::{Config, IfName, InterfaceKind, ItemId, RoutingTable};
use ipnet::IpNet;

use crate::Session;
use crate::dhcp_client::is_dynamic;
use crate::dhcp_resilience::RouteCheck;
use crate::dhcp6_client::ra_id;

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
    // Lease routes whose gateway fails check-gateway (G4.7c).
    for (r, text) in &live.withheld {
        let check = live.checks.get(&r.id).cloned();
        let ago = check
            .as_ref()
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
            origin: Origin::Dhcp,
            gateway: gw,
            gateway_address: r.gateway.address(),
            gateway_interface: r.gateway.iface().cloned(),
            via: None,
            disabled: false,
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
    /// the running one outside a transaction), with state.
    pub(crate) fn route_lines(&mut self) -> Vec<Line> {
        let base = self.store().candidate().clone();
        self.route_lines_of(&base).1
    }

    /// The effective `base` (with the DHCP routes) and its routes.
    pub(crate) fn route_lines_of(&mut self, base: &Config) -> (Config, Vec<Line>) {
        let cfg = self.effective(base).into_owned();
        let live = self.route_live(&cfg);
        let lines = build(&cfg, &live);
        (cfg, lines)
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
    /// Key → (state, Unix second it took it; `None`: already so when
    /// watching began).
    states: HashMap<String, (State, Option<u64>)>,
}

impl RouteWatch {
    /// Note the states of `lines` at `now`; routes gone are forgotten.
    pub fn observe(&mut self, lines: &[Line], now: u64) {
        let first = self.since.is_none();
        self.since.get_or_insert(now);
        self.last_look = Some(now);
        let mut seen: HashMap<String, (State, Option<u64>)> = HashMap::with_capacity(lines.len());
        for l in lines.iter().take(MAX_WATCHED) {
            let entry = match self.states.get(&l.key) {
                Some((s, at)) if *s == l.state => (*s, *at),
                Some(_) => (l.state, Some(now)),
                None if first => (l.state, None),
                None => (l.state, Some(now)),
            };
            seen.insert(l.key.clone(), entry);
        }
        self.states = seen;
    }

    /// Unix second `key` took its current state, if known.
    pub fn changed_at(&self, key: &str) -> Option<u64> {
        self.states.get(key).and_then(|(_, at)| *at)
    }

    fn due(&self, routes: usize, now: u64) -> bool {
        routes <= FAST_LIMIT
            || self
                .last_look
                .is_none_or(|t| now.saturating_sub(t) >= SLOW_EVERY)
    }
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
        if let Some(w) = self.ext_mut::<RouteWatch>() {
            w.observe(&lines, now);
        }
    }

    /// `route_lines`, noted by the watch too (`ip.route.list` and the
    /// lookup see the change at once, not at the next tick).
    pub(crate) fn watched_route_lines(&mut self) -> (Vec<Line>, Option<u64>) {
        let lines = self.route_lines();
        let now = self.now();
        if let (Some(now), Some(w)) = (now, self.ext_mut::<RouteWatch>()) {
            w.observe(&lines, now);
        }
        (lines, now)
    }
}
