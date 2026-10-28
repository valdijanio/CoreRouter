//! Ready topologies: the 4-router "square" the window opens with, and the
//! ring, mesh, star and grid the tests and benchmarks use. A [`Scenario`]
//! is the plan (routers, links, BGP sessions); [`Scenario::plan`] turns it
//! into addresses and neighbors, which the engine types into each virtual
//! router's `Session` as commands and [`Scenario::build`] feeds straight to a
//! [`Simulation`].

use std::net::Ipv4Addr;
use std::sync::Arc;

use corerouter_model::ItemId;
use corerouter_model::routing_filter::{FilterRule, RoutingFilter};
use corerouter_proto_bgp::filter::eval::Policy;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::{
    BgpConfig, Endpoint, IfAddr, Link, MS, Neighbor, NodeConfig, NodeId, Simulation, Time,
};

/// The `/routing filter` chain the presets put on eBGP sessions (RFC 8212
/// would refuse everything without one).
pub const ACCEPT_CHAIN: &str = "sim-accept";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeSpec {
    pub name: String,
    pub asn: u32,
    pub loopback: Ipv4Addr,
    /// Prefixes the router originates in BGP.
    #[serde(default)]
    pub networks: Vec<Ipv4Net>,
    /// Where the window draws it (0..1 each).
    #[serde(default)]
    pub pos: [f32; 2],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkSpec {
    pub a: usize,
    pub b: usize,
    pub cost: u32,
    pub latency: Time,
    pub ospf: bool,
    pub bfd: bool,
}

/// A BGP session: eBGP between the link addresses when the ASes differ
/// (the two routers need a link), iBGP between the loopbacks otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSpec {
    pub a: usize,
    pub b: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Scenario {
    pub name: String,
    pub nodes: Vec<NodeSpec>,
    pub links: Vec<LinkSpec>,
    pub sessions: Vec<SessionSpec>,
}

/// One router of a [`Plan`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PlannedNode {
    pub name: String,
    pub asn: u32,
    pub router_id: Ipv4Addr,
    /// `lo` holds the loopback; `ether<n>` the links, in link order.
    pub addresses: Vec<IfAddr>,
    pub networks: Vec<Ipv4Net>,
    pub neighbors: Vec<Neighbor>,
    pub pos: [f32; 2],
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Plan {
    pub nodes: Vec<PlannedNode>,
    pub links: Vec<Link>,
}

/// The /30 of link `k` (inside 10.0.0.0/9).
fn link_net(k: usize) -> Option<(Ipv4Net, Ipv4Net)> {
    let k = u32::try_from(k).ok().filter(|k| *k < 1 << 21)?;
    let base = u32::from(Ipv4Addr::new(10, 0, 0, 0)) + (k << 2);
    Some((
        Ipv4Net::new(Ipv4Addr::from(base + 1), 30).ok()?,
        Ipv4Net::new(Ipv4Addr::from(base + 2), 30).ok()?,
    ))
}

/// Loopback of router `i` (10.255.0.0/16).
pub fn loopback(i: usize) -> Ipv4Addr {
    let i = u32::try_from(i).unwrap_or(0) & 0xffff;
    Ipv4Addr::from(u32::from(Ipv4Addr::new(10, 255, 0, 0)) + i + 1)
}

/// The /24 router `i` originates (172.16.0.0/12).
pub fn customer(i: usize) -> Ipv4Net {
    let i = u32::try_from(i).unwrap_or(0) & 0xfff;
    let a = Ipv4Addr::from(u32::from(Ipv4Addr::new(172, 16, 0, 0)) + (i << 8));
    Ipv4Net::new(a, 24).unwrap_or_default()
}

/// The filter the presets give every router: one chain that accepts.
pub fn accept_filter() -> RoutingFilter {
    RoutingFilter {
        rules: vec![FilterRule {
            id: ItemId(1),
            chain: ACCEPT_CHAIN.into(),
            rule: "accept".into(),
            disabled: false,
            comment: "simulator: eBGP needs a policy (RFC 8212)".into(),
        }],
        next_id: 2,
        ..RoutingFilter::default()
    }
}

/// How the generated topologies run BGP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BgpMode {
    /// OSPF only.
    None,
    /// Every router its own AS, eBGP on every link (an Internet in small).
    Ebgp,
    /// One AS, iBGP full mesh over the loopbacks (small topologies).
    Ibgp,
}

impl Scenario {
    /// Addresses (a /30 per link, a /32 loopback per router) and neighbors.
    pub fn plan(&self) -> Result<Plan, String> {
        let mut nodes: Vec<PlannedNode> = self
            .nodes
            .iter()
            .map(|n| PlannedNode {
                name: n.name.clone(),
                asn: n.asn,
                router_id: n.loopback,
                addresses: vec![IfAddr {
                    iface: "lo".into(),
                    net: Ipv4Net::new(n.loopback, 32).unwrap_or_default(),
                }],
                networks: n.networks.clone(),
                neighbors: Vec::new(),
                pos: n.pos,
            })
            .collect();
        let mut ports = vec![0usize; nodes.len()];
        let mut links = Vec::new();
        // (a, b) → (a's address, b's address)
        let mut link_addrs = std::collections::BTreeMap::new();
        for (k, l) in self.links.iter().enumerate() {
            if l.a == l.b {
                return Err(format!("link {k} joins router {} to itself", l.a));
            }
            let (na, nb) = link_net(k).ok_or("too many links")?;
            let mut iface = |i: usize| -> Result<String, String> {
                let p = ports
                    .get_mut(i)
                    .ok_or_else(|| format!("link {k}: no router {i}"))?;
                *p += 1;
                Ok(format!("ether{p}"))
            };
            let (ia, ib) = (iface(l.a)?, iface(l.b)?);
            for (i, iface, net) in [(l.a, &ia, na), (l.b, &ib, nb)] {
                if let Some(n) = nodes.get_mut(i) {
                    n.addresses.push(IfAddr {
                        iface: iface.clone(),
                        net,
                    });
                }
            }
            link_addrs
                .entry((l.a, l.b))
                .or_insert((na.addr(), nb.addr()));
            link_addrs
                .entry((l.b, l.a))
                .or_insert((nb.addr(), na.addr()));
            let mut link = Link::new(
                Endpoint {
                    node: NodeId(u32::try_from(l.a).map_err(|_| "router index")?),
                    iface: ia,
                },
                Endpoint {
                    node: NodeId(u32::try_from(l.b).map_err(|_| "router index")?),
                    iface: ib,
                },
            );
            link.cost_a = l.cost.max(1);
            link.cost_b = l.cost.max(1);
            link.latency = l.latency.max(1);
            link.ospf = l.ospf;
            link.bfd = l.bfd;
            links.push(link);
        }
        for s in &self.sessions {
            let (Some(a), Some(b)) = (self.nodes.get(s.a), self.nodes.get(s.b)) else {
                return Err(format!("session {}–{}: no such router", s.a, s.b));
            };
            let ebgp = a.asn != b.asn;
            let (addr_a, addr_b) = if ebgp {
                *link_addrs.get(&(s.a, s.b)).ok_or_else(|| {
                    format!("eBGP {}–{} needs a link between them", a.name, b.name)
                })?
            } else {
                (a.loopback, b.loopback)
            };
            for (me, other, remote, local, asn) in [
                (s.a, b, addr_b, addr_a, b.asn),
                (s.b, a, addr_a, addr_b, a.asn),
            ] {
                let mut n = Neighbor::new(other.name.to_lowercase(), remote, Some(asn));
                if ebgp {
                    n.input = Some(ACCEPT_CHAIN.into());
                    n.output = Some(ACCEPT_CHAIN.into());
                    n.bfd = true;
                } else {
                    n.local = Some(local);
                    // The eBGP links stay out of OSPF: the border router
                    // puts itself as next hop toward iBGP.
                    n.next_hop_self = true;
                }
                if let Some(p) = nodes.get_mut(me) {
                    p.neighbors.push(n);
                }
            }
        }
        Ok(Plan { nodes, links })
    }

    /// A simulation of the plan, every router with [`accept_filter`].
    pub fn build(&self, seed: u64) -> Result<Simulation, String> {
        let plan = self.plan()?;
        let policy = Arc::new(Policy::build(&accept_filter()).0);
        let mut sim = Simulation::new(seed);
        for n in &plan.nodes {
            let mut cfg = NodeConfig::new(n.name.clone(), n.router_id);
            cfg.addresses.clone_from(&n.addresses);
            cfg.bgp = (!n.neighbors.is_empty() || !n.networks.is_empty()).then(|| BgpConfig {
                asn: n.asn,
                networks: n.networks.clone(),
                neighbors: n.neighbors.clone(),
                policy: policy.clone(),
            });
            sim.add_node(cfg)?;
        }
        for l in plan.links {
            sim.add_link(l)?;
        }
        Ok(sim)
    }
}

fn spec(i: usize, asn: u32, pos: [f32; 2]) -> NodeSpec {
    NodeSpec {
        name: format!("R{}", i + 1),
        asn,
        loopback: loopback(i),
        networks: vec![customer(i)],
        pos,
    }
}

fn link(a: usize, b: usize) -> LinkSpec {
    LinkSpec {
        a,
        b,
        cost: 10,
        latency: MS,
        ospf: true,
        bfd: true,
    }
}

fn circle(i: usize, n: usize) -> [f32; 2] {
    let t = std::f32::consts::TAU * i as f32 / n.max(1) as f32 - std::f32::consts::FRAC_PI_2;
    [0.5 + 0.42 * t.cos(), 0.5 + 0.42 * t.sin()]
}

/// The 4 routers the window opens with: R1–R3 are one ISP (AS 65000:
/// OSPF on a triangle with BFD, iBGP full mesh between loopbacks, R2
/// originates a customer /16), R4 is its upstream (AS 65100) with eBGP to R1
/// and R3, originating two documentation prefixes.
pub fn square() -> Scenario {
    let pos = [[0.2, 0.25], [0.8, 0.25], [0.8, 0.75], [0.2, 0.75]];
    let mut nodes: Vec<NodeSpec> = pos
        .iter()
        .enumerate()
        .map(|(i, p)| spec(i, 65000, *p))
        .collect();
    let nets = |s: &[&str]| {
        s.iter()
            .filter_map(|p| p.parse().ok())
            .collect::<Vec<Ipv4Net>>()
    };
    if let Some(n) = nodes.get_mut(0) {
        n.networks = Vec::new();
    }
    if let Some(n) = nodes.get_mut(1) {
        n.networks = nets(&["100.64.0.0/16"]);
    }
    if let Some(n) = nodes.get_mut(2) {
        n.networks = Vec::new();
    }
    if let Some(n) = nodes.get_mut(3) {
        n.asn = 65100;
        n.networks = nets(&["198.51.100.0/24", "203.0.113.0/24"]);
    }
    let mut links = vec![link(0, 1), link(1, 2), link(0, 2), link(3, 0), link(3, 2)];
    for l in links.iter_mut().skip(3) {
        l.ospf = false;
        l.latency = 5 * MS;
    }
    Scenario {
        name: "square".into(),
        nodes,
        links,
        sessions: vec![
            SessionSpec { a: 0, b: 1 },
            SessionSpec { a: 1, b: 2 },
            SessionSpec { a: 0, b: 2 },
            SessionSpec { a: 3, b: 0 },
            SessionSpec { a: 3, b: 2 },
        ],
    }
}

fn sessions_for(nodes: &[NodeSpec], links: &[LinkSpec], mode: BgpMode) -> Vec<SessionSpec> {
    match mode {
        BgpMode::None => Vec::new(),
        BgpMode::Ebgp => links
            .iter()
            .map(|l| SessionSpec { a: l.a, b: l.b })
            .collect(),
        BgpMode::Ibgp => {
            let mut s = Vec::new();
            for a in 0..nodes.len() {
                for b in a + 1..nodes.len() {
                    s.push(SessionSpec { a, b });
                }
            }
            s
        }
    }
}

fn generated(
    name: &str,
    n: usize,
    links: Vec<LinkSpec>,
    pos: impl Fn(usize) -> [f32; 2],
    mode: BgpMode,
) -> Scenario {
    let nodes: Vec<NodeSpec> = (0..n)
        .map(|i| {
            let asn = match mode {
                BgpMode::Ebgp => 64512 + u32::try_from(i).unwrap_or(0),
                _ => 65000,
            };
            let mut s = spec(i, asn, pos(i));
            if mode == BgpMode::None {
                s.networks.clear();
            }
            s
        })
        .collect();
    let sessions = sessions_for(&nodes, &links, mode);
    Scenario {
        name: name.into(),
        nodes,
        links,
        sessions,
    }
}

pub fn ring(n: usize, mode: BgpMode) -> Scenario {
    let links = (0..n)
        .filter(|_| n >= 2)
        .map(|i| link(i, (i + 1) % n))
        .filter(|l| l.a != l.b);
    let mut links: Vec<LinkSpec> = links.collect();
    if n == 2 {
        links.truncate(1);
    }
    generated("ring", n, links, |i| circle(i, n), mode)
}

/// Every router linked to every other.
pub fn mesh(n: usize, mode: BgpMode) -> Scenario {
    let mut links = Vec::new();
    for a in 0..n {
        for b in a + 1..n {
            links.push(link(a, b));
        }
    }
    generated("mesh", n, links, |i| circle(i, n), mode)
}

/// R1 in the middle, linked to every other router.
pub fn star(n: usize, mode: BgpMode) -> Scenario {
    let links = (1..n).map(|i| link(0, i)).collect();
    generated(
        "star",
        n,
        links,
        |i| {
            if i == 0 {
                [0.5, 0.5]
            } else {
                circle(i - 1, n - 1)
            }
        },
        mode,
    )
}

/// A grid of about √n × √n routers (degree up to 4).
pub fn grid(n: usize, mode: BgpMode) -> Scenario {
    let w = (n as f64).sqrt().ceil().max(1.0) as usize;
    let mut links = Vec::new();
    for i in 0..n {
        if (i + 1) % w != 0 && i + 1 < n {
            links.push(link(i, i + 1));
        }
        if i + w < n {
            links.push(link(i, i + w));
        }
    }
    let h = n.div_ceil(w).max(1);
    generated(
        "grid",
        n,
        links,
        |i| {
            let (x, y) = (i % w, i / w);
            [
                0.08 + 0.84 * x as f32 / (w.max(2) - 1) as f32,
                0.08 + 0.84 * y as f32 / (h.max(2) - 1) as f32,
            ]
        },
        mode,
    )
}

/// A preset by name (the window's and the commands' list).
pub fn by_name(name: &str, n: usize, mode: BgpMode) -> Option<Scenario> {
    Some(match name {
        "square" => square(),
        "ring" => ring(n, mode),
        "mesh" => mesh(n, mode),
        "star" => star(n, mode),
        "grid" => grid(n, mode),
        _ => return None,
    })
}

pub const NAMES: &[&str] = &["square", "ring", "mesh", "star", "grid"];
