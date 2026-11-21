//! Management guard (G3.4z): is a learned route taking an operator's
//! session away?
//!
//! A route more specific than a connected network wins over it (longest
//! match, RFC 1812 §5.2.4.3): an OSPF `/32` of a lab generator inside the
//! management `/24` sends the replies to the operator out of the lab port
//! and the session dies (phase C, 2026-11-13). Nothing in the config
//! changed, so the lockout check of the commits (G2.1b) never saw it.
//!
//! Three parts:
//!
//! - **The open sessions.** Every request of a logged-in connection passes
//!   through [`Session::as_caller`](crate::Session), which calls [`seen`]:
//!   one map insert by connection id. [`gone`] marks it closed when the
//!   connection closes, and it is still watched for [`RECENT_SECS`]: a
//!   learned route usually kills the session it covers, and the operator
//!   who comes back by another way (the console, another network) must see
//!   what did it; `corerouter-cli run` also opens one connection per
//!   command. Loopback sessions are left out (the `local` table answers
//!   them before any route).
//! - **The check.** The daemon's `mgmt-guard` service asks the kernel,
//!   once a second and outside the session lock, which FIB entry a reply
//!   to each distinct (peer, local address) takes ([`Session::mgmt_guard_probes`],
//!   `RTM_GETROUTE` with `RTM_F_FIB_MATCH`) and hands the answers back
//!   ([`Session::mgmt_guard_feed`]). A peer inside a connected network
//!   whose answer is a route of a routing daemon longer than that network
//!   is *covered*: a warning in the health check (`management.route`), in
//!   the summary every client shows (the GUI's top bar) and in the log.
//!   The cost per tick is one lookup per distinct pair, not per route: the
//!   kernel's trie does the longest match (`docs/changes/G3.4z.md`).
//! - **The guard itself** (`routing.management-guard.*`, the config's
//!   `routing.management_guard`): the routing daemon refuses those routes
//!   (`hal-frr`). Its window counts what it refuses from the daemon's RIB,
//!   read on demand by the same thread that polls FRR ([`Session::mgmt_guard_rib_wanted`]).
//!
//! G3.4za: everything is per routing table. A session is in the table of
//! the port its local address is on (a VRF's, or main); the kernel is asked
//! with that VRF as the output device (`ip route get … vrf <name>`: the
//! `l3mdev` rule then picks the VRF's table, as for the socket's own
//! replies), its connected networks are that table's, and a guard network
//! protects it only when it is in the same table.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

use corerouter_hal::route_get::{FibEntry, is_learned_protocol, protocol_name};
use corerouter_model::mgmt_guard::{RibRoute, is_learned};
use corerouter_model::route::is_up;
use corerouter_model::{Config, IfName, RoutingTable, route};
use ipnet::IpNet;
use serde::Serialize;
use serde_json::{Value, json};

use crate::auth::Principal;
use crate::lockout::{Link, plain};
use crate::safe_mode::Caller;
use crate::Session;

/// Most sessions tracked (the control channel takes fewer at once).
pub const MAX_SESSIONS: usize = 1024;
/// A closed session is still watched this long.
pub const RECENT_SECS: u64 = 600;
/// Most closed sessions kept (the newest).
pub const MAX_CLOSED: usize = 256;
/// Distinct (peer, local) pairs looked up per tick.
pub const MAX_PROBES: usize = 1024;
/// Answers older than this are not trusted (the service stopped).
pub const STALE_SECS: u64 = 10;
/// A RIB read is used this long before it is read again.
pub const RIB_FRESH_SECS: u64 = 10;
/// Networks whose RIB is kept or waits to be read.
pub const MAX_RIB: usize = 64;
const MAX_RIB_WANTED: usize = 16;

/// One open management session.
#[derive(Debug, Clone)]
struct Open {
    link: Link,
    via: Option<&'static str>,
    user: String,
    /// When the connection closed (`Some(None)`: closed, no clock).
    closed: Option<Option<u64>>,
}

/// What a RIB read gave.
#[derive(Debug, Clone)]
struct RibSlot {
    at: Option<u64>,
    result: Result<Vec<RibRoute>, String>,
}

/// A [`Session`] extension.
#[derive(Debug, Default)]
pub struct Guard {
    open: HashMap<u64, Open>,
    /// The last answer per (peer, local), and when it came.
    fib: HashMap<(IpAddr, IpAddr), FibEntry>,
    fed_at: Option<u64>,
    fed: bool,
    findings: Vec<Finding>,
    rib: HashMap<(RoutingTable, IpNet), RibSlot>,
    wanted: Vec<(RoutingTable, IpNet)>,
}

/// One lookup the `mgmt-guard` service makes: the replies from `local` to
/// `peer`, in `vrf` (`None`: main).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub peer: IpAddr,
    pub local: IpAddr,
    pub vrf: Option<IfName>,
}

impl Probe {
    pub fn pair(&self) -> (IpAddr, IpAddr) {
        (self.peer, self.local)
    }
}

/// One session the guard names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Who {
    #[serde(skip)]
    pub id: u64,
    /// `GUI`, `MCP`, `terminal`… (what the client said), or `tcp`.
    pub via: String,
    pub user: String,
    pub peer: IpAddr,
    /// Still connected (a closed one is watched for [`RECENT_SECS`]).
    pub open: bool,
}

/// A learned route that covers the peer of open sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub peer: IpAddr,
    pub local: IpAddr,
    pub sessions: Vec<Who>,
    /// The route the replies take.
    pub route: IpNet,
    /// G3.4za: the table the session is in (main or a VRF).
    pub vrf: RoutingTable,
    pub protocol: &'static str,
    pub interface: Option<IfName>,
    pub gateway: Option<IpAddr>,
    /// The connected network the peer is on, and its port.
    pub connected: IpNet,
    pub connected_interface: IfName,
    /// An active guard network holds `connected` (the route should not be
    /// in the kernel: the daemon did not apply it, or another program
    /// installed the route).
    pub guarded: bool,
}

/// What the window and the preview get of a guarded network's RIB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RibView {
    Ready(Vec<RibRoute>),
    Pending,
    Unavailable(String),
}

/// A connection made a request (`Session::as_caller`).
pub(crate) fn seen(s: &mut Session, caller: &Caller) {
    let Some(link) = caller.link else {
        return;
    };
    if matches!(caller.principal, Principal::Anonymous) || plain(link.peer.ip()).is_loopback() {
        return;
    }
    let Some(g) = s.ext_mut::<Guard>() else {
        return;
    };
    if let Some(o) = g.open.get_mut(&caller.id) {
        if caller.via.is_some() {
            o.via = caller.via;
        }
        return;
    }
    if g.open.values().filter(|o| o.closed.is_none()).count() >= MAX_SESSIONS {
        return;
    }
    g.open.insert(
        caller.id,
        Open {
            link,
            via: caller.via,
            user: caller.principal.label().chars().take(64).collect(),
            closed: None,
        },
    );
}

/// The connection `id` closed: watched for [`RECENT_SECS`] more, as the
/// newest closed session of its peer, user and client.
pub(crate) fn gone(s: &mut Session, id: u64) {
    let now = s.now();
    let Some(g) = s.ext_mut::<Guard>() else {
        return;
    };
    let Some(o) = g.open.get_mut(&id) else {
        return;
    };
    o.closed = Some(now);
    let key = (o.link.peer.ip(), o.link.local.ip(), o.via, o.user.clone());
    g.open.retain(|k, o| *k == id || o.closed.is_none() || (o.link.peer.ip(), o.link.local.ip(), o.via, o.user.clone()) != key);
    for f in &mut g.findings {
        for w in f.sessions.iter_mut().filter(|w| w.id == id) {
            w.open = false;
        }
    }
    prune(g, now);
}

/// Drop the closed sessions older than [`RECENT_SECS`], and the oldest
/// beyond [`MAX_CLOSED`].
fn prune(g: &mut Guard, now: Option<u64>) {
    if let Some(now) = now {
        g.open.retain(|_, o| match o.closed {
            Some(Some(at)) => now.saturating_sub(at) <= RECENT_SECS,
            _ => true,
        });
    }
    let mut closed: Vec<u64> = g.open.iter().filter(|(_, o)| o.closed.is_some()).map(|(k, _)| *k).collect();
    if closed.len() > MAX_CLOSED {
        closed.sort_unstable();
        for k in closed.iter().take(closed.len() - MAX_CLOSED) {
            g.open.remove(k);
        }
    }
    let alive: HashSet<u64> = g.open.keys().copied().collect();
    g.findings.retain_mut(|f| {
        f.sessions.retain(|w| alive.contains(&w.id));
        !f.sessions.is_empty()
    });
}

/// The connected networks that are up, by table and network (the longest
/// that holds an address is the one the kernel uses), and the table of each
/// local address. One pass over the addresses.
#[derive(Debug, Default)]
struct Tables {
    connected: HashMap<(RoutingTable, IpNet), IfName>,
    local: HashMap<IpAddr, RoutingTable>,
}

impl Tables {
    fn of(cfg: &Config) -> Self {
        let mut t = Tables::default();
        for a in &cfg.ip.addresses {
            if a.disabled || a.from_pool.is_some() || !is_up(cfg, &a.interface) {
                continue;
            }
            // A `/routing table` (G1.27e) is not where a port's connected
            // routes are: only a VRF is.
            let table = match route::table_of(cfg, &a.interface) {
                t @ RoutingTable::Vrf(_) if route::is_vrf_table(cfg, &t) => t,
                _ => RoutingTable::Main,
            };
            t.local.entry(a.address.addr()).or_insert_with(|| table.clone());
            t.connected.entry((table, a.address.trunc())).or_insert_with(|| a.interface.clone());
        }
        t
    }

    /// The table a session whose local address is `local` is in (main when
    /// the address is not one of the config's: the daemon's own listen
    /// address, a pool's).
    fn table(&self, local: IpAddr) -> RoutingTable {
        self.local.get(&local).cloned().unwrap_or_default()
    }

    /// The longest connected network of `table` holding `ip`: one hash
    /// lookup per prefix length (33 or 129), whatever the number of
    /// addresses.
    fn connected_of(&self, table: &RoutingTable, ip: IpAddr) -> Option<(IpNet, IfName)> {
        let max = if ip.is_ipv4() { 32 } else { 128 };
        (0..=max).rev().find_map(|len| {
            let n = IpNet::new(ip, len).ok()?.trunc();
            self.connected.get(&(table.clone(), n)).map(|i| (n, i.clone()))
        })
    }
}

/// Who a session is, for people.
fn who(id: u64, o: &Open) -> Who {
    Who {
        id,
        via: o.via.unwrap_or("tcp").to_owned(),
        user: o.user.clone(),
        peer: plain(o.link.peer.ip()),
        open: o.closed.is_none(),
    }
}

/// The findings of `fib` against the running config (pure, for the tests).
fn judge(cfg: &Config, open: &HashMap<u64, Open>, fib: &HashMap<(IpAddr, IpAddr), FibEntry>) -> Vec<Finding> {
    let tables = Tables::of(cfg);
    let mut by_pair: BTreeMap<(IpAddr, IpAddr), Vec<Who>> = BTreeMap::new();
    for (id, o) in open {
        by_pair
            .entry((plain(o.link.peer.ip()), plain(o.link.local.ip())))
            .or_default()
            .push(who(*id, o));
    }
    let guard = &cfg.routing.management_guard;
    let mut out = Vec::new();
    for (pair, mut sessions) in by_pair {
        let Some(e) = fib.get(&pair) else {
            continue;
        };
        let Some(route) = e.prefix else {
            continue;
        };
        if !is_learned_protocol(e.protocol) {
            continue;
        }
        let vrf = tables.table(pair.1);
        let Some((connected, connected_interface)) = tables.connected_of(&vrf, pair.0) else {
            continue;
        };
        if route.prefix_len() <= connected.prefix_len() {
            continue;
        }
        sessions.sort_by_key(|w| w.id);
        let guarded = guard.active_in(&vrf).any(|n| n.contains(&connected));
        out.push(Finding {
            peer: pair.0,
            local: pair.1,
            sessions,
            route,
            protocol: protocol_name(e.protocol),
            interface: e.interface.clone(),
            gateway: e.gateway,
            guarded,
            vrf,
            connected,
            connected_interface,
        });
    }
    out
}

/// The command that protects `net` of `table`.
pub fn protect_command(table: &RoutingTable, net: &IpNet) -> String {
    match table {
        RoutingTable::Main => format!("routing.management-guard.add {{\"network\":\"{net}\"}}"),
        RoutingTable::Vrf(v) => format!("routing.management-guard.add {{\"network\":\"{net}\",\"vrf\":\"{v}\"}}"),
    }
}

/// One finding as a sentence (Portuguese, for the health check and the log).
pub fn describe(f: &Finding) -> String {
    let via = match (&f.gateway, &f.interface) {
        (Some(g), Some(i)) => format!("via {g} {i}"),
        (None, Some(i)) => format!("por {i}"),
        (Some(g), None) => format!("via {g}"),
        (None, None) => String::new(),
    };
    let who: Vec<String> = f
        .sessions
        .iter()
        .take(4)
        .map(|w| format!("{} {} de {}{}", w.via, w.user, w.peer, if w.open { "" } else { ", já fechada" }))
        .collect();
    let more = f.sessions.len().saturating_sub(4);
    let more = if more > 0 { format!(" e mais {more}") } else { String::new() };
    let out = f.interface.as_ref().map_or_else(String::new, |i| format!(": as respostas saem por {i}"));
    let vrf = match &f.vrf {
        RoutingTable::Main => String::new(),
        RoutingTable::Vrf(v) => format!(" (VRF {v})"),
    };
    format!(
        "a rota {} ({}{}) é mais específica que a rede conectada {} de {}{vrf} e cobre o par de {} sessão(ões) de gerência ({}{more}){out}",
        f.route,
        f.protocol,
        if via.is_empty() { String::new() } else { format!(", {via}") },
        f.connected,
        f.connected_interface,
        f.sessions.len(),
        who.join("; "),
    )
}

impl Session {
    /// The distinct (peer, local address) pairs of the open management
    /// sessions, with the VRF each is in, for the `mgmt-guard` service to
    /// look up.
    pub fn mgmt_guard_probes(&mut self) -> Vec<Probe> {
        let now = self.now();
        let tables = Tables::of(self.store().running());
        let Some(g) = self.ext_mut::<Guard>() else {
            return Vec::new();
        };
        prune(g, now);
        let mut seen = HashSet::new();
        g.open
            .values()
            .map(|o| (plain(o.link.peer.ip()), plain(o.link.local.ip())))
            .filter(|p| seen.insert(*p))
            .take(MAX_PROBES)
            .map(|(peer, local)| Probe {
                peer,
                local,
                vrf: match tables.table(local) {
                    RoutingTable::Main => None,
                    RoutingTable::Vrf(v) => Some(v),
                },
            })
            .collect()
    }

    /// What the kernel answered for each pair of [`Session::mgmt_guard_probes`]
    /// (a failed lookup is left out).
    pub fn mgmt_guard_feed(&mut self, answers: Vec<((IpAddr, IpAddr), Result<FibEntry, String>)>) {
        let now = self.now();
        let fib: HashMap<_, _> = answers
            .into_iter()
            .filter_map(|(k, r)| r.ok().map(|e| (k, e)))
            .collect();
        let findings = match self.ext::<Guard>() {
            Some(g) => judge(self.store().running(), &g.open, &fib),
            None => Vec::new(),
        };
        let new: Vec<Finding> = {
            let old = self.ext::<Guard>().map(|g| g.findings.clone()).unwrap_or_default();
            findings
                .iter()
                .filter(|f| !old.iter().any(|o| o.peer == f.peer && o.route == f.route))
                .cloned()
                .collect()
        };
        if let Some(g) = self.ext_mut::<Guard>() {
            g.fib = fib;
            g.fed_at = now;
            g.fed = true;
            g.findings = findings;
        }
        // At once, not after the health check's two readings: by then the
        // operator may be gone.
        for f in new {
            let text = format!("Gerência: {}", describe(&f));
            let data = json!({"peer": f.peer, "route": f.route, "protocol": f.protocol, "connected": f.connected});
            self.log_event(&["system", "warning"], "mgmt-guard", text, data);
        }
    }

    /// The findings now (none when the service went quiet), with
    /// `guarded` as the running config says now.
    pub fn mgmt_guard_findings(&self) -> Vec<Finding> {
        let Some(g) = self.ext::<Guard>() else {
            return Vec::new();
        };
        let fresh = match (self.now(), g.fed_at) {
            (Some(now), Some(at)) => now.saturating_sub(at) <= STALE_SECS,
            _ => true,
        };
        if !fresh {
            return Vec::new();
        }
        let guard = &self.store().running().routing.management_guard;
        g.findings
            .iter()
            .map(|f| Finding { guarded: guard.active_in(&f.vrf).any(|n| n.contains(&f.connected)), ..f.clone() })
            .collect()
    }

    /// Whether the service reported at least once (the lab has none).
    pub fn mgmt_guard_watching(&self) -> bool {
        self.ext::<Guard>().is_some_and(|g| g.fed)
    }

    /// The management sessions (not loopback): the open ones and those
    /// closed in the last [`RECENT_SECS`] (`open: false`).
    pub fn mgmt_guard_sessions(&self) -> Vec<Who> {
        let mut v: Vec<Who> = self
            .ext::<Guard>()
            .map(|g| g.open.iter().map(|(id, o)| who(*id, o)).collect())
            .unwrap_or_default();
        v.sort_by_key(|w| w.id);
        v
    }

    /// The connected network each open session's peer is on, in the
    /// session's table, with the sessions: what
    /// `routing.management-guard.suggest` offers.
    pub fn mgmt_guard_networks(&self) -> Vec<MgmtNetwork> {
        let tables = Tables::of(self.store().running());
        let locals: HashMap<u64, IpAddr> = self
            .ext::<Guard>()
            .map(|g| g.open.iter().map(|(id, o)| (*id, plain(o.link.local.ip()))).collect())
            .unwrap_or_default();
        let mut by: BTreeMap<(RoutingTable, IpNet), (IfName, Vec<Who>)> = BTreeMap::new();
        for w in self.mgmt_guard_sessions() {
            let table = locals.get(&w.id).map(|l| tables.table(*l)).unwrap_or_default();
            if let Some((n, i)) = tables.connected_of(&table, w.peer) {
                by.entry((table, n)).or_insert_with(|| (i, Vec::new())).1.push(w);
            }
        }
        by.into_iter()
            .map(|((vrf, network), (interface, sessions))| MgmtNetwork { vrf, network, interface, sessions })
            .collect()
    }

    /// The RIB of `table` inside `net`, as last read; asks for a read when
    /// there is none or it is old. Without a routing daemon: unavailable.
    pub fn mgmt_guard_rib(&mut self, table: &RoutingTable, net: IpNet) -> RibView {
        if self.routing_status().is_none_or(|st| st.backend.is_empty()) {
            return RibView::Unavailable("no routing daemon attached (FRR is not running here)".into());
        }
        let now = self.now();
        let Some(g) = self.ext_mut::<Guard>() else {
            return RibView::Pending;
        };
        let key = (table.clone(), net);
        let slot = g.rib.get(&key).cloned();
        let old = slot.as_ref().is_none_or(|s| match (now, s.at) {
            (Some(n), Some(a)) => n.saturating_sub(a) >= RIB_FRESH_SECS,
            _ => false,
        });
        if old && !g.wanted.contains(&key) && g.wanted.len() < MAX_RIB_WANTED {
            g.wanted.push(key);
        }
        match slot {
            Some(RibSlot { result: Ok(r), .. }) => RibView::Ready(r),
            Some(RibSlot { result: Err(e), .. }) => RibView::Unavailable(e),
            None => RibView::Pending,
        }
    }

    /// The networks whose RIB a command asked for (the FRR thread reads
    /// them outside the lock).
    pub fn mgmt_guard_rib_wanted(&mut self) -> Vec<(RoutingTable, IpNet)> {
        self.ext_mut::<Guard>().map(|g| std::mem::take(&mut g.wanted)).unwrap_or_default()
    }

    pub fn mgmt_guard_set_rib(&mut self, table: RoutingTable, net: IpNet, result: Result<Vec<RibRoute>, String>) {
        let at = self.now();
        if let Some(g) = self.ext_mut::<Guard>() {
            let key = (table, net);
            if g.rib.len() >= MAX_RIB && !g.rib.contains_key(&key) {
                let oldest = g.rib.iter().min_by_key(|(_, s)| s.at).map(|(n, _)| n.clone());
                if let Some(o) = oldest {
                    g.rib.remove(&o);
                }
            }
            g.rib.insert(key, RibSlot { at, result });
        }
    }
}

/// A connected network management sessions come from
/// ([`Session::mgmt_guard_networks`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MgmtNetwork {
    pub vrf: RoutingTable,
    pub network: IpNet,
    pub interface: IfName,
    pub sessions: Vec<Who>,
}

/// The learned routes of `rib` the guard of `net` refuses (inside and
/// longer), and how many of them are in the kernel now.
pub fn refused(net: &IpNet, rib: &[RibRoute]) -> (Vec<RibRoute>, usize) {
    let hit: Vec<RibRoute> = rib
        .iter()
        .filter(|r| net.contains(&r.prefix) && r.prefix.prefix_len() > net.prefix_len() && is_learned(&r.protocol))
        .cloned()
        .collect();
    let installed = hit.iter().filter(|r| r.installed).count();
    (hit, installed)
}

/// "3 (ospf 2, bgp 1)".
pub fn by_protocol(routes: &[RibRoute]) -> String {
    let mut by: BTreeMap<&str, usize> = BTreeMap::new();
    for r in routes {
        *by.entry(r.protocol.as_str()).or_default() += 1;
    }
    if by.is_empty() {
        return "0".into();
    }
    let parts: Vec<String> = by.iter().map(|(p, n)| format!("{p} {n}")).collect();
    format!("{} ({})", routes.len(), parts.join(", "))
}

/// G2.1b for the guard (G3.4z): does going from `before` to `after` take
/// away the guard that keeps a learned route (in the last RIB read) off the
/// caller's peer? Only what was read is known: no read, no refusal.
pub(crate) fn unguard_cut(s: &Session, before: &Config, after: &Config, link: &Link) -> Option<String> {
    let peer = plain(link.peer.ip());
    // The session's table, as the running config (before) puts it.
    let table = Tables::of(before).table(plain(link.local.ip()));
    let kept: Vec<&IpNet> = after.routing.management_guard.active_in(&table).collect();
    let g = s.ext::<Guard>()?;
    for n in before.routing.management_guard.active_in(&table) {
        if !n.contains(&peer) || kept.iter().any(|k| k.contains(&peer)) {
            continue;
        }
        let Some(RibSlot { result: Ok(rib), .. }) = g.rib.get(&(table.clone(), *n)) else {
            continue;
        };
        if let Some(r) = rib
            .iter()
            .find(|r| r.prefix.contains(&peer) && r.prefix.prefix_len() > n.prefix_len() && is_learned(&r.protocol))
        {
            return Some(format!(
                "taking {n} out of the management guard lets {} ({}) take the replies to this session ({peer})",
                r.prefix, r.protocol
            ));
        }
    }
    None
}

/// For the summary every client shows (`state.inspect`): `null` when no
/// session is covered.
pub(crate) fn summary(s: &Session) -> Value {
    let f = s.mgmt_guard_findings();
    if f.is_empty() {
        return Value::Null;
    }
    let rows: Vec<Value> = f
        .iter()
        .take(8)
        .map(|f| {
            json!({
                "peer": f.peer,
                "route": f.route,
                "vrf": f.vrf,
                "protocol": f.protocol,
                "interface": f.interface,
                "gateway": f.gateway,
                "connected": f.connected,
                "connected_interface": f.connected_interface,
                "sessions": f.sessions,
                "guarded": f.guarded,
                "text": describe(f),
                "fix": (!f.guarded).then(|| protect_command(&f.vrf, &f.connected)),
            })
        })
        .collect();
    Value::Array(rows)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::SocketAddr;

    use corerouter_hal::route_get::RouteKind;
    use serde_json::json;

    use super::*;

    pub(crate) fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.bootstrap_admin(false);
        s.execute("ip.address.add", &json!({"address": "192.168.0.1/24", "interface": "ether1"})).unwrap();
        s.execute("ip.address.add", &json!({"address": "10.0.1.1/30", "interface": "ether2"})).unwrap();
        s
    }

    pub(crate) fn operator(id: u64, peer: &str, via: &'static str) -> Caller {
        let link = Link {
            peer: format!("{peer}:50000").parse::<SocketAddr>().unwrap(),
            local: "192.168.0.1:8729".parse().unwrap(),
        };
        let mut c = Caller::new(id, format!("tcp {peer}:50000"))
            .with_principal(Principal::User("admin".into()))
            .with_link(link);
        c.via = Some(via);
        c
    }

    pub(crate) fn learned(route: &str, protocol: u8) -> FibEntry {
        FibEntry {
            kind: RouteKind::Unicast,
            prefix: Some(route.parse().unwrap()),
            protocol,
            interface: Some("ether2".parse().unwrap()),
            gateway: Some("10.0.1.2".parse().unwrap()),
        }
    }

    pub(crate) fn feed(s: &mut Session, answer: impl Fn(IpAddr) -> FibEntry) {
        let probes = s.mgmt_guard_probes();
        let answers = probes.into_iter().map(|p| (p.pair(), Ok(answer(p.peer)))).collect();
        s.mgmt_guard_feed(answers);
    }

    #[test]
    fn an_ospf_host_route_over_the_connected_network_is_found() {
        let mut s = lab();
        s.execute_as(&operator(7, "192.168.0.2", "GUI"), "system.identity.get", &json!({})).unwrap();
        s.execute_as(&operator(8, "192.168.0.2", "MCP"), "system.identity.get", &json!({})).unwrap();
        assert_eq!(s.mgmt_guard_probes().len(), 1, "two sessions from one peer: one lookup");
        feed(&mut s, |_| learned("192.168.0.2/32", 188));
        let f = s.mgmt_guard_findings();
        assert_eq!(f.len(), 1);
        let f = &f[0];
        assert_eq!((f.protocol, f.connected.to_string().as_str(), f.connected_interface.as_str()), ("ospf", "192.168.0.0/24", "ether1"));
        assert_eq!(f.sessions.iter().map(|w| w.via.as_str()).collect::<Vec<_>>(), ["GUI", "MCP"]);
        assert!(!f.guarded);
        let text = describe(f);
        assert!(text.contains("192.168.0.2/32 (ospf, via 10.0.1.2 ether2)") && text.contains("ether1"), "{text}");
        let sum = summary(&s);
        assert_eq!(sum[0]["fix"], "routing.management-guard.add {\"network\":\"192.168.0.0/24\"}", "{sum}");
        // Said in the log at once.
        let log = s.execute("log.print", &json!({})).unwrap().to_string();
        assert!(log.contains("Gerência: a rota 192.168.0.2/32"), "{log}");
        // The route usually kills the session: still named, as closed, for
        // the operator who comes back by another way.
        s.hang_up(7);
        s.hang_up(8);
        let f = s.mgmt_guard_findings();
        assert!(f[0].sessions.iter().all(|w| !w.open));
        assert!(describe(&f[0]).contains("GUI admin de 192.168.0.2, já fechada"), "{}", describe(&f[0]));
        assert!(!summary(&s).is_null());
    }

    #[test]
    fn a_closed_session_is_watched_for_ten_minutes() {
        let mut s = lab();
        s.tick(1_000);
        // `corerouter-cli run`: one connection per command.
        s.execute_as(&operator(7, "192.168.0.2", "CLI"), "system.identity.get", &json!({})).unwrap();
        s.hang_up(7);
        s.execute_as(&operator(8, "192.168.0.2", "CLI"), "system.identity.get", &json!({})).unwrap();
        s.hang_up(8);
        assert_eq!(s.mgmt_guard_sessions().len(), 1, "the newest closed one per peer, user and client");
        s.tick(1_000 + RECENT_SECS);
        feed(&mut s, |_| learned("192.168.0.2/32", 188));
        assert_eq!(s.mgmt_guard_findings().len(), 1);
        s.tick(1_001 + RECENT_SECS);
        assert!(s.mgmt_guard_probes().is_empty(), "forgotten after RECENT_SECS");
        assert!(s.mgmt_guard_findings().is_empty());
    }

    #[test]
    fn what_is_not_a_learned_cut_is_left_alone() {
        let cases: &[(&str, u8, &str)] = &[
            ("192.168.0.0/24", 2, "the connected route itself"),
            ("192.168.0.2/32", 4, "a static route of CoreRouter (the operator's own)"),
            ("192.168.0.0/24", 188, "OSPF at the same length loses to the connected route"),
            ("192.168.0.0/16", 186, "a shorter BGP route"),
        ];
        for (route, proto, why) in cases {
            let mut s = lab();
            s.execute_as(&operator(7, "192.168.0.2", "GUI"), "system.identity.get", &json!({})).unwrap();
            feed(&mut s, |_| learned(route, *proto));
            assert!(s.mgmt_guard_findings().is_empty(), "{why}");
        }
        // A peer behind a gateway (a NOC reached by OSPF on purpose).
        let mut s = lab();
        s.execute_as(&operator(7, "203.0.113.9", "GUI"), "system.identity.get", &json!({})).unwrap();
        feed(&mut s, |_| learned("203.0.113.0/24", 188));
        assert!(s.mgmt_guard_findings().is_empty());
    }

    #[test]
    fn loopback_anonymous_and_in_process_callers_are_not_sessions() {
        let mut s = lab();
        s.execute("system.identity.get", &json!({})).unwrap();
        let mut anon = operator(5, "192.168.0.9", "GUI");
        anon.principal = Principal::Anonymous;
        let _ = s.execute_as(&anon, "system.identity.get", &json!({}));
        let mut lo = operator(6, "127.0.0.1", "CLI");
        lo.link = Some(Link { peer: "127.0.0.1:4000".parse().unwrap(), local: "127.0.0.1:7979".parse().unwrap() });
        s.execute_as(&lo, "system.identity.get", &json!({})).unwrap();
        assert!(s.mgmt_guard_probes().is_empty());
    }

    #[test]
    fn a_guarded_network_still_in_the_kernel_says_so() {
        let mut s = lab();
        s.execute("routing.management-guard.add", &json!({"network": "192.168.0.0/24"})).unwrap();
        s.execute_as(&operator(7, "192.168.0.2", "GUI"), "system.identity.get", &json!({})).unwrap();
        feed(&mut s, |_| learned("192.168.0.2/32", 188));
        assert!(s.mgmt_guard_findings()[0].guarded);
        assert!(summary(&s)[0]["fix"].is_null());
    }

    /// G3.4za: ether3 in VRF `mgmt` with 10.99.0.1/24, and the same
    /// 192.168.0.0/24 as ether1's (overlapping: another network) on ether4,
    /// also in the VRF.
    pub(crate) fn vrf_lab() -> Session {
        let mut s = lab();
        s.execute("ip.vrf.add", &json!({"name": "mgmt", "interfaces": "ether3,ether4"})).unwrap();
        s.execute("ip.address.add", &json!({"address": "10.99.0.1/24", "interface": "ether3"})).unwrap();
        s
    }

    pub(crate) fn vrf_operator(id: u64, peer: &str) -> Caller {
        let mut c = operator(id, peer, "GUI");
        c.link = Some(Link { peer: format!("{peer}:50000").parse().unwrap(), local: "10.99.0.1:8729".parse().unwrap() });
        c
    }

    #[test]
    fn a_session_in_a_vrf_is_looked_up_and_judged_in_its_table() {
        let mut s = vrf_lab();
        s.execute_as(&vrf_operator(7, "10.99.0.2"), "system.identity.get", &json!({})).unwrap();
        s.execute_as(&operator(8, "192.168.0.2", "GUI"), "system.identity.get", &json!({})).unwrap();
        let mut probes = s.mgmt_guard_probes();
        probes.sort_by_key(|p| p.peer);
        assert_eq!(probes[0].vrf.as_ref().map(|v| v.as_str()), Some("mgmt"), "{probes:?}");
        assert_eq!(probes[1].vrf, None, "main: no output device");
        feed(&mut s, |peer| learned(&format!("{peer}/32"), 186));
        let f = s.mgmt_guard_findings();
        let v = f.iter().find(|f| f.peer.to_string() == "10.99.0.2").unwrap();
        assert_eq!((v.vrf.to_string().as_str(), v.connected.to_string().as_str(), v.connected_interface.as_str(), v.protocol), ("mgmt", "10.99.0.0/24", "ether3", "bgp"));
        assert!(describe(v).contains("de ether3 (VRF mgmt)"), "{}", describe(v));
        assert_eq!(summary(&s).as_array().unwrap().iter().find(|r| r["vrf"] == "mgmt").unwrap()["fix"], "routing.management-guard.add {\"network\":\"10.99.0.0/24\",\"vrf\":\"mgmt\"}");
        // A main guard of the same prefix does not protect the VRF one.
        s.execute("routing.management-guard.add", &json!({"network": "10.99.0.0/24", "vrf": "main"})).unwrap();
        assert!(!s.mgmt_guard_findings().iter().find(|f| f.vrf.to_string() == "mgmt").unwrap().guarded);
        s.execute("routing.management-guard.add", &json!({"network": "10.99.0.0/24", "vrf": "mgmt"})).unwrap();
        assert!(s.mgmt_guard_findings().iter().find(|f| f.vrf.to_string() == "mgmt").unwrap().guarded);
        // The networks of the sessions, each in its table.
        let nets: Vec<String> = s.mgmt_guard_networks().iter().map(|m| format!("{} {}", m.vrf, m.network)).collect();
        assert_eq!(nets, ["main 192.168.0.0/24", "mgmt 10.99.0.0/24"]);
    }

    #[test]
    fn the_same_prefix_in_a_vrf_is_another_network() {
        let mut s = vrf_lab();
        s.execute("ip.address.add", &json!({"address": "192.168.0.1/24", "interface": "ether4"})).unwrap();
        // A main session: its connected network is ether1's.
        s.execute_as(&operator(8, "192.168.0.2", "GUI"), "system.identity.get", &json!({})).unwrap();
        feed(&mut s, |_| learned("192.168.0.2/32", 188));
        let f = s.mgmt_guard_findings();
        assert_eq!(f.len(), 1);
        // The first configured address wins the local lookup (ether1, main).
        assert_eq!((f[0].vrf.to_string().as_str(), f[0].connected_interface.as_str()), ("main", "ether1"));
        // A VRF guard of the same prefix does not count for main.
        s.execute("routing.management-guard.add", &json!({"network": "192.168.0.0/24", "vrf": "mgmt"})).unwrap();
        assert!(!s.mgmt_guard_findings()[0].guarded);
    }

    #[test]
    fn the_refused_routes_are_the_learned_longer_ones() {
        let net: IpNet = "192.168.0.0/24".parse().unwrap();
        let r = |p: &str, proto: &str, installed: bool| RibRoute {
            prefix: p.parse().unwrap(),
            protocol: proto.into(),
            installed,
            inactive: !installed,
            via: String::new(),
        };
        let rib = [
            r("192.168.0.0/24", "connected", true),
            r("192.168.0.0/24", "ospf", false),
            r("192.168.0.2/32", "ospf", true),
            r("192.168.0.7/32", "bgp", false),
            r("192.168.0.9/32", "kernel", true),
        ];
        let (hit, installed) = refused(&net, &rib);
        assert_eq!(by_protocol(&hit), "2 (bgp 1, ospf 1)");
        assert_eq!(installed, 1);
    }
}

