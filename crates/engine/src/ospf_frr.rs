//! TI-LFA over the daemon's state (G3.4d): the OSPF topology of a read
//! LSDB as `netsim::tilfa` takes it, who announces each prefix, the
//! neighbor a route leaves by, and the coverage (protected routes and why
//! the others are not). The daemon (FRR's `ospfd`) computes the backups it
//! installs; this explains them, fills them in for the virtual lab, and
//! simulates a cut without touching the network.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use corerouter_model::ospf_sr::TiLfa;
use corerouter_model::ospf_state::{Lsdb, OspfNeighbor, OspfRoute};
use corerouter_netsim::tilfa::{self, CoverInput, Coverage, Protection, Repair, Topology};
use ipnet::Ipv4Net;

/// The LSDB as a graph: routers, transit networks as pseudo-routers (the
/// network LSA's id), the owner of every stub and network prefix.
pub struct Graph {
    pub topo: Topology,
    pub root: Option<Ipv4Addr>,
    owner: HashMap<Ipv4Net, Ipv4Addr>,
}

impl Graph {
    pub fn of(db: &Lsdb) -> Graph {
        let mut arcs: Vec<(Ipv4Addr, Ipv4Addr, u32)> = Vec::new();
        let mut owner: HashMap<Ipv4Net, Ipv4Addr> = HashMap::new();
        for l in db.lsas.iter().filter(|l| l.area != u32::MAX) {
            let start = usize::try_from(l.link_start).unwrap_or(usize::MAX);
            let count = usize::from(l.link_count);
            match l.kind {
                1 => {
                    let adv = Ipv4Addr::from(l.adv);
                    for k in db.links.get(start..start.saturating_add(count)).into_iter().flatten() {
                        match k.kind {
                            1 => arcs.push((adv, Ipv4Addr::from(k.id), u32::from(k.metric))),
                            2 => arcs.push((adv, Ipv4Addr::from(k.id), u32::from(k.metric))),
                            3 => {
                                let plen = u8::try_from(k.data.count_ones()).unwrap_or(32);
                                if let Ok(n) = Ipv4Net::new(Ipv4Addr::from(k.id), plen) {
                                    owner.entry(n.trunc()).or_insert(adv);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                2 => {
                    // RFC 2328 §16.1: a network reaches its routers at cost 0.
                    let net = Ipv4Addr::from(l.id);
                    for r in db.attached.get(start..start.saturating_add(count)).into_iter().flatten() {
                        arcs.push((net, Ipv4Addr::from(*r), 0));
                    }
                    if let Ok(n) = Ipv4Net::new(net, l.plen.min(32)) {
                        owner.entry(n.trunc()).or_insert(net);
                    }
                }
                _ => {}
            }
        }
        Graph {
            topo: Topology::new(&arcs),
            root: db.router_id.map(Ipv4Addr::from),
            owner,
        }
    }

    /// The router (or transit network) that announces `prefix`.
    pub fn dest_of(&self, prefix: &str) -> Option<Ipv4Addr> {
        let n: Ipv4Net = prefix.parse().ok()?;
        self.owner.get(&n.trunc()).copied().or_else(|| {
            // A /32 that is a router id: its loopback.
            (n.prefix_len() == 32 && self.topo.routers().contains(&n.addr())).then(|| n.addr())
        })
    }
}

pub fn protection(t: TiLfa) -> Protection {
    match t {
        TiLfa::Node => Protection::Node,
        TiLfa::Link | TiLfa::Off => Protection::Link,
    }
}

/// The router id of the neighbor a route's first next hop goes to.
pub fn neighbor_of(r: &OspfRoute, nbrs: &[OspfNeighbor]) -> Option<Ipv4Addr> {
    let (via, _) = r.nexthops.first()?;
    let via = via.as_deref()?;
    nbrs.iter().find(|n| n.address == via).and_then(|n| n.router_id.parse().ok())
}

/// The coverage of `routes`.
pub fn coverage(g: &Graph, routes: &[OspfRoute], nbrs: &[OspfNeighbor], p: Protection) -> Coverage {
    let Some(root) = g.root else {
        return Coverage::default();
    };
    let inputs: Vec<CoverInput<'_>> = routes
        .iter()
        .map(|r| CoverInput {
            prefix: &r.prefix,
            dest: g.dest_of(&r.prefix),
            neighbor: neighbor_of(r, nbrs),
            has_backup: r.fast_reroute.as_ref().is_some_and(|f| !f.backup.is_empty()),
        })
        .collect();
    tilfa::coverage(&g.topo, root, p, &inputs)
}

/// The repair of `r` if its next hop `neighbor` failed, computed as the
/// daemon does (`None`: not computable here).
pub fn repair_of(g: &Graph, r: &OspfRoute, neighbor: Ipv4Addr, p: Protection) -> Option<Repair> {
    let root = g.root?;
    let dest = g.dest_of(&r.prefix)?;
    tilfa::repair(&g.topo, root, dest, neighbor, p)
}
