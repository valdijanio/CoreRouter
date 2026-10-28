//! The simulation: routers, links, faults and the clock.
//!
//! [`Simulation::advance`] repeats: find the earliest pending event `t0`,
//! apply the faults due at `t0`, let every router run its events in
//! `[t0, t0 + lookahead)` — the routers are independent inside the window,
//! so they run on several threads on native targets — then deliver what
//! they sent, in router order, at the barrier. The lookahead is the
//! shortest link latency: nothing sent inside a window can arrive before it
//! ends.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;

use serde::Serialize;

use crate::bgp::{BgpPeerView, BgpRouteView};
use crate::fib::FibRoute;
use crate::node::{Ev, Node, Out, Port};
use crate::ospf::{Lsa, OspfNeighborView};
use crate::queue::Queue;
use crate::timeline::{self, Convergence, Record, RecordKind};
use crate::{Fault, Link, LinkId, LinkState, MAX_LINKS, MAX_NODES, NodeConfig, NodeId, Time, mix};

/// Most timeline records kept (the oldest go first).
const MAX_RECORDS: usize = 50_000;
/// Most routers a routed message crosses (a forwarding loop drops it).
const MAX_HOPS: usize = 64;
/// Fewer routers with work in a window than this run on the calling
/// thread: handing them to the pool costs more than the window. With 16,
/// 100 routers ran 18 % slower on 8 threads than on 1; with 48 they tie
/// and 500 keep their gain (**medido**, `examples/measure.rs`).
const PAR_MIN_ACTIVE: usize = 48;

/// Counters of the run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Stats {
    pub windows: u64,
    pub parallel_windows: u64,
    pub events: u64,
    pub messages: u64,
    pub dropped: u64,
    pub records_dropped: u64,
    /// Wall-clock nanoseconds in the windows and at the barriers (native
    /// only: the split that says whether more threads can help).
    pub window_ns: u64,
    pub barrier_ns: u64,
}

pub struct Simulation {
    seed: u64,
    now: Time,
    nodes: Vec<Node>,
    links: Vec<Link>,
    faults: Queue<Fault>,
    records: VecDeque<Record>,
    owners: HashMap<Ipv4Addr, NodeId>,
    threads: usize,
    msg_seq: u64,
    stats: Stats,
    /// The last fault: when, what, best BGP prefixes summed just before.
    last_fault: Option<(Time, Fault, u64)>,
    #[cfg(not(target_arch = "wasm32"))]
    pool: Option<crate::pool::Pool>,
}

/// A router, as the window lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NodeView {
    pub id: NodeId,
    pub name: String,
    pub router_id: Ipv4Addr,
    pub up: bool,
    pub asn: Option<u32>,
    pub ospf_neighbors: usize,
    pub bgp_established: usize,
    pub bgp_peers: usize,
    pub bgp_prefixes: usize,
    pub routes: usize,
    pub lsdb: usize,
    pub pending_events: usize,
}

/// A link, as the window draws it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkView {
    pub id: LinkId,
    pub a: NodeId,
    pub a_iface: String,
    pub b: NodeId,
    pub b_iface: String,
    pub state: LinkState,
    pub latency: Time,
    pub loss_pct: u8,
    pub cost_a: u32,
    pub cost_b: u32,
    pub ospf: bool,
    pub bfd: bool,
    /// Both ends see a Full OSPF adjacency.
    pub ospf_full: bool,
}

impl Simulation {
    pub fn new(seed: u64) -> Self {
        Simulation {
            seed,
            now: 0,
            nodes: Vec::new(),
            links: Vec::new(),
            faults: Queue::default(),
            records: VecDeque::new(),
            owners: HashMap::new(),
            threads: 1,
            msg_seq: 0,
            stats: Stats::default(),
            last_fault: None,
            #[cfg(not(target_arch = "wasm32"))]
            pool: None,
        }
    }

    /// Threads a window may use (1 on wasm whatever is asked).
    pub fn set_threads(&mut self, n: usize) {
        self.threads = n.clamp(1, 64);
    }

    pub fn threads(&self) -> usize {
        self.threads
    }

    pub fn now(&self) -> Time {
        self.now
    }

    pub fn seed(&self) -> u64 {
        self.seed
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Add a router; it boots now.
    pub fn add_node(&mut self, cfg: NodeConfig) -> Result<NodeId, String> {
        if self.nodes.len() >= MAX_NODES {
            return Err(format!("at most {MAX_NODES} routers"));
        }
        if self.nodes.iter().any(|n| n.cfg.name == cfg.name) {
            return Err(format!("a router named {:?} exists", cut(&cfg.name)));
        }
        let id = NodeId(u32::try_from(self.nodes.len()).map_err(|_| "too many routers")?);
        let mut n = Node::new(id, cfg, self.seed);
        n.boot(self.now);
        n.ospf_flush_floods(self.now);
        self.nodes.push(n);
        self.reindex();
        Ok(id)
    }

    /// Replace a router's configuration. A changed BGP restarts its
    /// sessions (the peers get a NOTIFICATION); addresses and OSPF are
    /// applied in place.
    pub fn set_config(&mut self, id: NodeId, cfg: NodeConfig) -> Result<(), String> {
        let now = self.now;
        if self
            .nodes
            .iter()
            .any(|o| o.id != id && o.cfg.name == cfg.name)
        {
            return Err(format!("a router named {:?} exists", cut(&cfg.name)));
        }
        let n = self.nodes.get_mut(id.ix()).ok_or("no such router")?;
        let old = std::mem::replace(&mut n.cfg, cfg);
        if n.up {
            n.reconfigure(now, &old);
            n.ospf_flush_floods(now);
        }
        self.reindex();
        Ok(())
    }

    pub fn config(&self, id: NodeId) -> Option<&NodeConfig> {
        self.nodes.get(id.ix()).map(|n| &n.cfg)
    }

    pub fn node_by_name(&self, name: &str) -> Option<NodeId> {
        self.nodes.iter().find(|n| n.cfg.name == name).map(|n| n.id)
    }

    /// Connect two routers; both ends start OSPF on it now.
    pub fn add_link(&mut self, link: Link) -> Result<LinkId, String> {
        if self.links.len() >= MAX_LINKS {
            return Err(format!("at most {MAX_LINKS} links"));
        }
        if link.a.node == link.b.node {
            return Err("a link joins two different routers".into());
        }
        for e in [&link.a, &link.b] {
            let n = self
                .nodes
                .get(e.node.ix())
                .ok_or_else(|| format!("no router {}", e.node.0))?;
            if n.ports.iter().any(|p| p.iface == e.iface) {
                return Err(format!(
                    "{} already uses {}",
                    cut(&n.cfg.name),
                    cut(&e.iface)
                ));
            }
        }
        let id = LinkId(u32::try_from(self.links.len()).map_err(|_| "too many links")?);
        let now = self.now;
        for (end, cost) in [(&link.a, link.cost_a), (&link.b, link.cost_b)] {
            if let Some(n) = self.nodes.get_mut(end.node.ix()) {
                n.ports
                    .push(Port::new(id, end.iface.clone(), cost, link.ospf, link.bfd));
                n.ports.sort_by_key(|p| p.link);
                n.bind_addresses();
                if n.up {
                    n.ospf_port_up(now, id);
                    n.ospf_originate(now, false);
                    n.refresh(now, true);
                    n.ospf_flush_floods(now);
                }
            }
        }
        self.links.push(link);
        Ok(id)
    }

    pub fn link(&self, id: LinkId) -> Option<&Link> {
        self.links.get(id.ix())
    }

    /// Change a link's OSPF costs, BFD or the protocols on it, in place.
    pub fn set_link(
        &mut self,
        id: LinkId,
        cost_a: Option<u32>,
        cost_b: Option<u32>,
        bfd: Option<bool>,
    ) -> Result<(), String> {
        let now = self.now;
        let l = self.links.get_mut(id.ix()).ok_or("no such link")?;
        if let Some(c) = cost_a {
            l.cost_a = c.clamp(1, 65535);
        }
        if let Some(c) = cost_b {
            l.cost_b = c.clamp(1, 65535);
        }
        if let Some(b) = bfd {
            l.bfd = b;
        }
        let ends = [(l.a.node, l.cost_a), (l.b.node, l.cost_b)];
        let bfd = l.bfd;
        for (node, cost) in ends {
            if let Some(n) = self.nodes.get_mut(node.ix())
                && let Some(p) = n.port_mut(id)
            {
                p.link_cost = cost;
                p.link_bfd = bfd;
                n.bind_addresses();
                if n.up {
                    n.ospf_originate(now, false);
                    n.ospf_flush_floods(now);
                }
            }
        }
        Ok(())
    }

    /// Inject `fault` at `at` (now if in the past).
    pub fn schedule(&mut self, at: Time, fault: Fault) -> Result<(), String> {
        match fault {
            Fault::LinkCut { link }
            | Fault::LinkDown { link }
            | Fault::LinkRestore { link }
            | Fault::Latency { link, .. }
            | Fault::Loss { link, .. } => {
                self.links.get(link.ix()).ok_or("no such link")?;
            }
            Fault::NodeDown { node } | Fault::NodeUp { node } => {
                self.nodes.get(node.ix()).ok_or("no such router")?;
            }
        }
        if self.faults.len() >= 10_000 {
            return Err("too many pending faults".into());
        }
        self.faults.push(at.max(self.now), fault);
        Ok(())
    }

    fn lookahead(&self) -> Time {
        self.links
            .iter()
            .map(|l| l.latency)
            .min()
            .unwrap_or(Time::MAX)
            .max(1)
    }

    /// When the next event (or fault) is due.
    pub fn next_event(&self) -> Option<Time> {
        let n = self
            .nodes
            .iter()
            .filter(|n| n.up)
            .filter_map(|n| n.q.next_at())
            .min();
        match (n, self.faults.next_at()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Run until `until` or after about `budget` events, whichever comes
    /// first; whether `until` was reached.
    pub fn advance(&mut self, until: Time, budget: u64) -> bool {
        let start_events = self.stats.events;
        loop {
            let Some(t0) = self.next_event().filter(|t| *t < until) else {
                self.now = self.now.max(until);
                return true;
            };
            self.now = self.now.max(t0);
            while let Some((_, f)) = self.faults.pop_before(t0 + 1) {
                self.apply(f);
            }
            let mut end = t0.saturating_add(self.lookahead()).min(until);
            if let Some(f) = self.faults.next_at().filter(|f| *f > t0) {
                end = end.min(f);
            }
            #[cfg(not(target_arch = "wasm32"))]
            let t = std::time::Instant::now();
            self.run_window(end);
            #[cfg(not(target_arch = "wasm32"))]
            let t = {
                let n = std::time::Instant::now();
                self.stats.window_ns += u64::try_from((n - t).as_nanos()).unwrap_or(u64::MAX);
                n
            };
            self.deliver();
            #[cfg(not(target_arch = "wasm32"))]
            {
                self.stats.barrier_ns += u64::try_from(t.elapsed().as_nanos()).unwrap_or(u64::MAX);
            }
            self.now = end;
            if self.stats.events - start_events >= budget {
                return self.now >= until;
            }
        }
    }

    /// One window: run to the next event's window, wherever it is.
    pub fn step(&mut self) -> Time {
        if let Some(t0) = self.next_event() {
            let end = t0.saturating_add(self.lookahead());
            self.advance(end, u64::MAX);
        }
        self.now
    }

    fn run_window(&mut self, end: Time) {
        self.stats.windows += 1;
        let before: u64 = self.nodes.iter().map(|n| n.events).sum();
        #[cfg(not(target_arch = "wasm32"))]
        self.run_parallel(end);
        for n in &mut self.nodes {
            n.run(end);
        }
        let after: u64 = self.nodes.iter().map(|n| n.events).sum();
        self.stats.events += after - before;
    }

    /// The routers with work in the window, on the pool's threads.
    #[cfg(not(target_arch = "wasm32"))]
    fn run_parallel(&mut self, end: Time) {
        if self.threads < 2 {
            return;
        }
        let active: Vec<usize> = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.q.next_at().is_some_and(|t| t < end))
            .map(|(i, _)| i)
            .collect();
        if active.len() < PAR_MIN_ACTIVE {
            return;
        }
        if self.pool.as_ref().is_none_or(|p| p.size() != self.threads) {
            self.pool = crate::pool::Pool::new(self.threads);
        }
        let Some(pool) = &self.pool else { return };
        self.stats.parallel_windows += 1;
        // Round robin: neighbors in the topology (close indices) tend to
        // be busy together, so they go to different threads.
        let mut batches: Vec<Vec<(usize, Node)>> = (0..pool.size()).map(|_| Vec::new()).collect();
        for (k, i) in active.into_iter().enumerate() {
            if let (Some(n), Some(b)) = (
                self.nodes.get_mut(i),
                batches.get_mut(k % pool.size().max(1)),
            ) {
                b.push((i, std::mem::take(n)));
            }
        }
        for (i, n) in pool.run(batches, end) {
            if let Some(slot) = self.nodes.get_mut(i) {
                *slot = n;
            }
        }
    }

    /// The barrier: deliver what the routers sent, in router order, and
    /// collect their timeline records.
    fn deliver(&mut self) {
        let mut logs = Vec::new();
        for i in 0..self.nodes.len() {
            let Some(n) = self.nodes.get_mut(i) else {
                continue;
            };
            let out = std::mem::take(&mut n.out);
            logs.append(&mut n.log);
            let src = n.id;
            for o in out {
                self.stats.messages += 1;
                let delivered = match o {
                    Out::Link { at, link, msg } => self
                        .over_link(src, link)
                        .map(|(dst, lat)| (dst, at + lat, Ev::Link { link, msg })),
                    Out::Bgp { at, from, to, msg } => self
                        .routed(src, from, to)
                        .map(|(dst, lat)| (dst, at + lat, Ev::Bgp { from, to, msg })),
                };
                match delivered
                    .and_then(|(dst, at, ev)| Some((self.nodes.get_mut(dst.ix())?, at, ev)))
                {
                    Some((d, at, ev)) if d.up => d.q.push(at, ev),
                    _ => self.stats.dropped += 1,
                }
            }
        }
        logs.sort_by_key(|r| r.at);
        for r in logs {
            self.record(r);
        }
    }

    fn record(&mut self, r: Record) {
        if self.records.len() >= MAX_RECORDS {
            self.records.pop_front();
            self.stats.records_dropped += 1;
        }
        self.records.push_back(r);
    }

    /// Whether a packet survives `link`'s loss (by hash: deterministic).
    fn survives(&mut self, loss_pct: u8) -> bool {
        self.msg_seq += 1;
        loss_pct == 0 || mix(self.seed ^ mix(self.msg_seq)) % 100 >= u64::from(loss_pct)
    }

    fn over_link(&mut self, src: NodeId, link: LinkId) -> Option<(NodeId, Time)> {
        let l = self.links.get(link.ix())?;
        let (state, loss, latency) = (l.state, l.loss_pct, l.latency);
        let (_, other, _) = l.ends(src)?;
        let other = other.node;
        if state != LinkState::Up || !self.survives(loss) {
            return None;
        }
        Some((other, latency))
    }

    /// Hop by hop over the forwarding tables, as the packets would go.
    fn routed(&mut self, src: NodeId, from: Ipv4Addr, to: Ipv4Addr) -> Option<(NodeId, Time)> {
        let dst = *self.owners.get(&to)?;
        let mut cur = src;
        let mut lat: Time = 0;
        // ECMP: one flow, one path (a hash of the addresses).
        let flow = mix(u64::from(u32::from(from)) << 32 | u64::from(u32::from(to)));
        for _ in 0..MAX_HOPS {
            if cur == dst {
                return Some((dst, lat.max(1)));
            }
            let n = self.nodes.get(cur.ix())?;
            if !n.up {
                return None;
            }
            let r = n.fib.lookup(to)?;
            let pick = usize::try_from(flow % (r.links.len().max(1) as u64)).unwrap_or(0);
            let link = *r.links.get(pick)?;
            let l = self.links.get(link.ix())?;
            let (state, loss, latency) = (l.state, l.loss_pct, l.latency);
            let (_, other, _) = l.ends(cur)?;
            let next = other.node;
            if state != LinkState::Up || !self.survives(loss) {
                return None;
            }
            lat += latency;
            cur = next;
        }
        None
    }

    fn apply(&mut self, f: Fault) {
        let now = self.now;
        let before = self.bgp_prefixes();
        self.last_fault = Some((now, f, before));
        self.record(Record {
            at: now,
            node: None,
            kind: RecordKind::Fault { fault: f },
        });
        match f {
            Fault::LinkCut { link } | Fault::LinkDown { link } => {
                let down = matches!(f, Fault::LinkDown { .. });
                let Some(l) = self.links.get_mut(link.ix()) else {
                    return;
                };
                l.state = if down {
                    LinkState::Down
                } else {
                    LinkState::Cut
                };
                let ends = [l.a.node, l.b.node];
                for node in ends {
                    let Some(n) = self.nodes.get_mut(node.ix()) else {
                        continue;
                    };
                    if !n.up {
                        continue;
                    }
                    if down {
                        n.q.push(now, Ev::Carrier { link, up: false });
                    } else {
                        bfd_detect(n, now, link);
                    }
                }
            }
            Fault::LinkRestore { link } => {
                let Some(l) = self.links.get_mut(link.ix()) else {
                    return;
                };
                let was = l.state;
                l.state = LinkState::Up;
                let ends = [l.a.node, l.b.node];
                for node in ends {
                    let Some(n) = self.nodes.get_mut(node.ix()) else {
                        continue;
                    };
                    if !n.up {
                        continue;
                    }
                    match was {
                        LinkState::Down => n.q.push(now, Ev::Carrier { link, up: true }),
                        // RFC 5880 §6.2: Down → Init → Up takes a couple
                        // of packets.
                        LinkState::Cut => n.q.push(
                            now + 2 * n.cfg.timers.bfd_interval,
                            Ev::Bfd { link, up: true },
                        ),
                        LinkState::Up => {}
                    }
                }
            }
            Fault::NodeDown { node } => {
                let Some(n) = self.nodes.get_mut(node.ix()) else {
                    return;
                };
                n.halt();
                // A hung router: its neighbors keep carrier and notice by
                // BFD, hellos or the hold timer.
                for (other, link) in self.neighbors_of(node) {
                    if let Some(n) = self.nodes.get_mut(other.ix())
                        && n.up
                    {
                        bfd_detect(n, now, link);
                    }
                }
            }
            Fault::NodeUp { node } => {
                if let Some(n) = self.nodes.get_mut(node.ix())
                    && !n.up
                {
                    n.boot(now);
                    n.ospf_flush_floods(now);
                    // Its neighbors' BFD sessions come back up (RFC 5880
                    // §6.2: a couple of packets).
                    for (other, link) in self.neighbors_of(node) {
                        if let Some(n) = self.nodes.get_mut(other.ix())
                            && n.up
                        {
                            let at = now + 2 * n.cfg.timers.bfd_interval;
                            n.q.push(at, Ev::Bfd { link, up: true });
                        }
                    }
                }
            }
            Fault::Latency { link, latency } => {
                if let Some(l) = self.links.get_mut(link.ix()) {
                    l.latency = latency.clamp(1, 10 * crate::SEC);
                }
            }
            Fault::Loss { link, loss_pct } => {
                if let Some(l) = self.links.get_mut(link.ix()) {
                    l.loss_pct = loss_pct.min(100);
                }
            }
        }
    }

    /// The routers at the other end of `node`'s links, with the link.
    fn neighbors_of(&self, node: NodeId) -> Vec<(NodeId, LinkId)> {
        self.links
            .iter()
            .enumerate()
            .filter_map(|(i, l)| {
                let (_, other, _) = l.ends(node)?;
                Some((other.node, LinkId(u32::try_from(i).ok()?)))
            })
            .collect()
    }

    fn reindex(&mut self) {
        self.owners.clear();
        for n in &self.nodes {
            for a in &n.cfg.addresses {
                self.owners.entry(a.net.addr()).or_insert(n.id);
            }
        }
    }

    /// Best BGP prefixes summed over the routers that are up.
    pub fn bgp_prefixes(&self) -> u64 {
        self.nodes
            .iter()
            .filter(|n| n.up)
            .filter_map(|n| n.bgp.as_ref())
            .map(|b| b.best_count() as u64)
            .sum()
    }

    pub fn records(&self) -> impl DoubleEndedIterator<Item = &Record> + ExactSizeIterator {
        self.records.iter()
    }

    /// How the network reacted to the last fault.
    pub fn convergence(&self) -> Option<Convergence> {
        let (at, f, before) = self.last_fault?;
        let recent: Vec<Record> = self
            .records
            .iter()
            .rev()
            .take_while(|r| r.at >= at)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        Some(timeline::convergence(
            &recent,
            at,
            f,
            before,
            self.bgp_prefixes(),
            self.now,
        ))
    }

    /// When the last protocol change happened.
    pub fn last_change(&self) -> Option<Time> {
        self.records
            .iter()
            .rev()
            .find(|r| r.node.is_some())
            .map(|r| r.at)
    }

    pub fn nodes(&self) -> Vec<NodeView> {
        self.nodes
            .iter()
            .map(|n| NodeView {
                id: n.id,
                name: n.cfg.name.clone(),
                router_id: n.cfg.router_id,
                up: n.up,
                asn: n.cfg.bgp.as_ref().map(|b| b.asn),
                ospf_neighbors: n
                    .ports
                    .iter()
                    .filter(|p| p.adj == crate::node::AdjState::Full)
                    .count(),
                bgp_established: n.bgp.as_ref().map_or(0, |b| b.established()),
                bgp_peers: n.cfg.bgp.as_ref().map_or(0, |b| b.neighbors.len()),
                bgp_prefixes: n.bgp.as_ref().map_or(0, |b| b.best_count()),
                routes: n.fib.len(),
                lsdb: n.ospf.lsdb.len(),
                pending_events: n.q.len(),
            })
            .collect()
    }

    pub fn links(&self) -> Vec<LinkView> {
        self.links
            .iter()
            .enumerate()
            .map(|(i, l)| {
                let id = LinkId(u32::try_from(i).unwrap_or(u32::MAX));
                let full = |node: NodeId| {
                    self.nodes
                        .get(node.ix())
                        .and_then(|n| n.port(id))
                        .is_some_and(|p| p.adj == crate::node::AdjState::Full)
                };
                LinkView {
                    id,
                    a: l.a.node,
                    a_iface: l.a.iface.clone(),
                    b: l.b.node,
                    b_iface: l.b.iface.clone(),
                    state: l.state,
                    latency: l.latency,
                    loss_pct: l.loss_pct,
                    cost_a: l.cost_a,
                    cost_b: l.cost_b,
                    ospf: l.ospf,
                    bfd: l.bfd,
                    ospf_full: full(l.a.node) && full(l.b.node),
                }
            })
            .collect()
    }

    pub fn routes(&self, id: NodeId) -> Vec<FibRoute> {
        self.nodes
            .get(id.ix())
            .map(|n| n.fib.routes().cloned().collect())
            .unwrap_or_default()
    }

    pub fn ospf_neighbors(&self, id: NodeId) -> Vec<OspfNeighborView> {
        self.nodes
            .get(id.ix())
            .map(|n| n.ospf_neighbors())
            .unwrap_or_default()
    }

    pub fn lsdb(&self, id: NodeId) -> Vec<Lsa> {
        self.nodes
            .get(id.ix())
            .map(|n| n.ospf.lsdb.values().map(|l| (**l).clone()).collect())
            .unwrap_or_default()
    }

    pub fn bgp_peers(&self, id: NodeId) -> Vec<BgpPeerView> {
        self.nodes
            .get(id.ix())
            .and_then(|n| n.bgp.as_ref().map(|b| b.peer_views(self.now)))
            .unwrap_or_default()
    }

    pub fn bgp_routes(&self, id: NodeId, limit: usize) -> Vec<BgpRouteView> {
        self.nodes
            .get(id.ix())
            .and_then(|n| n.bgp.as_ref().map(|b| b.route_views(limit)))
            .unwrap_or_default()
    }

    /// The path a packet from router `from` to `to` takes now (router ids,
    /// in order), or where it stops.
    pub fn trace(&self, from: NodeId, to: Ipv4Addr) -> (Vec<NodeId>, bool) {
        let mut path = vec![from];
        let mut cur = from;
        let flow = mix(u64::from(u32::from(to)));
        for _ in 0..MAX_HOPS {
            let Some(n) = self.nodes.get(cur.ix()) else {
                break;
            };
            if n.owns(to) {
                return (path, true);
            }
            let Some(r) = n.fib.lookup(to).filter(|_| n.up) else {
                break;
            };
            let pick = usize::try_from(flow % (r.links.len().max(1) as u64)).unwrap_or(0);
            let Some(l) = r.links.get(pick).and_then(|l| self.links.get(l.ix())) else {
                break;
            };
            if l.state != LinkState::Up {
                break;
            }
            let Some((_, other, _)) = l.ends(cur) else {
                break;
            };
            cur = other.node;
            path.push(cur);
        }
        (path, false)
    }

    /// A digest of every forwarding table and the timeline: equal digests,
    /// equal runs (the determinism tests compare them).
    pub fn fingerprint(&self) -> u64 {
        let mut h = mix(self.now);
        let mut feed = |x: u64| h = mix(h ^ x);
        for n in &self.nodes {
            for r in n.fib.routes() {
                feed(u64::from(u32::from(r.prefix.addr())) << 8 | u64::from(r.prefix.prefix_len()));
                feed(u64::from(r.metric));
                for l in &r.links {
                    feed(u64::from(l.0));
                }
            }
        }
        for r in &self.records {
            feed(r.at);
            feed(r.node.map_or(u64::MAX, |n| u64::from(n.0)));
        }
        h
    }

    /// Bytes of protocol state per router, roughly (for the numbers in
    /// `docs/netsim.md`; the engine's `Session` per node is counted apart).
    pub fn approx_bytes(&self) -> usize {
        self.nodes
            .iter()
            .map(|n| {
                std::mem::size_of::<Node>()
                    + n.ports.len() * std::mem::size_of::<Port>()
                    + n.ospf.lsdb.len() * 48
                    + n.ospf.routes.len() * 64
                    + n.fib.len() * 96
                    + n.igp.len() * 96
                    + n.q.len() * 64
            })
            .sum()
    }
}

/// BFD on `link` (if on) notices a silent failure one detection time after
/// the last packet it got, which arrived somewhere in the last interval.
fn bfd_detect(n: &mut Node, now: Time, link: LinkId) {
    let Some(p) = n.port(link) else { return };
    if !p.bfd {
        return;
    }
    let t = n.cfg.timers;
    let phase = n.pick(0xbfd0_0000 ^ u64::from(link.0) ^ now, t.bfd_interval);
    let at = now + t.bfd_detect().saturating_sub(phase);
    n.q.push(at, Ev::Bfd { link, up: false });
}

fn cut(s: &str) -> String {
    s.chars().take(64).collect()
}

impl Node {
    /// Apply a new configuration over the running protocols.
    pub(crate) fn reconfigure(&mut self, now: Time, old: &NodeConfig) {
        if self.cfg.addresses != old.addresses
            || self.cfg.ospf != old.ospf
            || self.cfg.ospf_ifaces != old.ospf_ifaces
            || self.cfg.router_id != old.router_id
        {
            self.bind_addresses();
            // Interfaces that left OSPF (or turned passive) drop their
            // adjacency; those that joined start their hellos.
            let ports: Vec<(LinkId, bool, bool)> = self
                .ports
                .iter()
                .map(|p| {
                    (
                        p.link,
                        p.ospf && !p.passive,
                        p.adj == crate::node::AdjState::Down,
                    )
                })
                .collect();
            for (link, runs, down) in ports {
                if !runs && !down {
                    self.ospf_adj_down(now, link, "OSPF reconfigured");
                } else if runs && down && self.cfg.ospf {
                    self.ospf_port_up(now, link);
                }
            }
            if !self.cfg.ospf || self.cfg.router_id != old.router_id {
                let links: Vec<LinkId> = self.ports.iter().map(|p| p.link).collect();
                for l in links {
                    self.ospf_adj_down(now, l, "OSPF reconfigured");
                }
            }
            if self.cfg.ospf && (!old.ospf || self.cfg.router_id != old.router_id) {
                self.ospf = crate::ospf::Ospf::default();
                self.ospf_start(now);
            } else {
                self.ospf_originate(now, false);
            }
            self.refresh(now, true);
        }
        if self.cfg.bgp != old.bgp || self.cfg.router_id != old.router_id {
            if let Some(b) = &self.bgp {
                let n = b.peer_views(now).len();
                for i in 0..n {
                    self.bgp_admin_reset(now, i);
                }
            }
            self.bgp = self
                .cfg
                .bgp
                .as_ref()
                .map(|b| crate::bgp::Bgp::new(b, self.cfg.router_id));
            self.bgp_start(now);
            self.refresh(now, false);
        }
    }
}
