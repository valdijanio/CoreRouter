//! The network as the LSDB describes it (G3.4b): routers (router LSAs) and
//! transit networks (network LSAs) as nodes, their links as edges with the
//! cost each end announces (RFC 2328 §A.4.2, §A.4.3), per area.
//!
//! [`path`] answers "why this path?": the shortest path from this router
//! to a prefix or a router, with the cost added hop by hop (RFC 2328
//! §16.1: Dijkstra over the area's graph; a network's cost back to its
//! routers is 0). FRR computes the routes; this only explains them, on
//! the same LSDB the daemon has.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashMap};
use std::net::Ipv4Addr;

use corerouter_model::ospf_state::{Lsdb, ip};
use ipnet::Ipv4Net;

/// A node: a router (by router id) or a transit network (by its DR's
/// interface address, the network LSA's id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Node {
    Router(u32),
    Network(u32),
}

#[derive(Debug, Clone, Default)]
pub struct Graph {
    pub area: u32,
    pub nodes: Vec<Node>,
    index: HashMap<Node, usize>,
    /// Directed: from, to, cost (the cost the `from` end announces).
    pub arcs: Vec<(usize, usize, u32)>,
    /// Stub networks and network prefixes by owner: what each node reaches.
    pub prefixes: Vec<(Ipv4Net, usize, u32)>,
    /// Router bits (ABR 1, ASBR 2) and network masks, by node.
    pub flags: Vec<u8>,
}

impl Graph {
    fn node(&mut self, n: Node) -> usize {
        if let Some(i) = self.index.get(&n) {
            return *i;
        }
        let i = self.nodes.len();
        self.nodes.push(n);
        self.flags.push(0);
        self.index.insert(n, i);
        i
    }

    pub fn find(&self, n: Node) -> Option<usize> {
        self.index.get(&n).copied()
    }

    /// Undirected edges with both ends' costs (`None`: that end does not
    /// announce the link back — RFC 2328 §16.1 then ignores it).
    pub fn edges(&self) -> Vec<(usize, usize, u32, Option<u32>)> {
        let mut by: BTreeMap<(usize, usize), (Option<u32>, Option<u32>)> = BTreeMap::new();
        for &(a, b, c) in &self.arcs {
            let (k, fwd) = if a < b {
                ((a, b), true)
            } else {
                ((b, a), false)
            };
            let e = by.entry(k).or_default();
            let slot = if fwd { &mut e.0 } else { &mut e.1 };
            *slot = Some(slot.map_or(c, |o: u32| o.min(c)));
        }
        by.into_iter()
            .filter_map(|((a, b), (f, r))| match (f, r) {
                (Some(f), r) => Some((a, b, f, r)),
                (None, Some(r)) => Some((b, a, r, None)),
                (None, None) => None,
            })
            .collect()
    }
}

/// The graph of every area in `db`, by area id.
pub fn graphs(db: &Lsdb) -> BTreeMap<u32, Graph> {
    let mut out: BTreeMap<u32, Graph> = BTreeMap::new();
    for lsa in &db.lsas {
        if lsa.area == u32::MAX {
            continue;
        }
        let g = out.entry(lsa.area).or_insert_with(|| Graph {
            area: lsa.area,
            ..Graph::default()
        });
        match lsa.kind {
            1 => {
                let me = g.node(Node::Router(lsa.adv));
                if let Some(f) = g.flags.get_mut(me) {
                    *f |= lsa.flags & 3;
                }
                let start = usize::try_from(lsa.link_start).unwrap_or(usize::MAX);
                let links = db
                    .links
                    .get(start..start.saturating_add(usize::from(lsa.link_count)))
                    .unwrap_or(&[]);
                for l in links {
                    let cost = u32::from(l.metric);
                    match l.kind {
                        1 | 4 => {
                            let to = g.node(Node::Router(l.id));
                            g.arcs.push((me, to, cost));
                        }
                        2 => {
                            let to = g.node(Node::Network(l.id));
                            g.arcs.push((me, to, cost));
                        }
                        3 => {
                            let len = u8::try_from(l.data.count_ones()).unwrap_or(32);
                            if let Ok(p) = Ipv4Net::new(ip(l.id), len) {
                                g.prefixes.push((p.trunc(), me, cost));
                            }
                        }
                        _ => {}
                    }
                }
            }
            2 => {
                let net = g.node(Node::Network(lsa.id));
                if let Some(f) = g.flags.get_mut(net) {
                    *f = lsa.plen;
                }
                let start = usize::try_from(lsa.link_start).unwrap_or(usize::MAX);
                let att = db
                    .attached
                    .get(start..start.saturating_add(usize::from(lsa.link_count)))
                    .unwrap_or(&[]);
                for r in att {
                    let to = g.node(Node::Router(*r));
                    g.arcs.push((net, to, 0));
                }
                if let Ok(p) = Ipv4Net::new(ip(lsa.id), lsa.plen) {
                    g.prefixes.push((p.trunc(), net, 0));
                }
            }
            _ => {}
        }
    }
    out
}

/// One hop of a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    pub node: Node,
    /// The cost of the link into this node (0 for the first).
    pub cost: u32,
    /// Cost so far.
    pub total: u32,
}

/// The shortest path in `g` from router `from` to `to` (a router id, or
/// the most specific prefix holding an address), with the cost per hop.
/// `None`: unreachable or unknown.
pub fn path(g: &Graph, from: u32, to: Ipv4Addr) -> Option<Vec<Hop>> {
    let src = g.find(Node::Router(from))?;
    // The destination: a router with that id, else the node owning the
    // longest prefix that holds it.
    let target = g
        .find(Node::Router(u32::from(to)))
        .map(|n| (n, 0))
        .or_else(|| {
            g.prefixes
                .iter()
                .filter(|(p, _, _)| p.contains(&to))
                .max_by_key(|(p, _, c)| (p.prefix_len(), Reverse(*c)))
                .map(|(_, n, c)| (*n, *c))
        })?;
    let n = g.nodes.len();
    let mut out: Vec<Vec<(usize, u32)>> = vec![Vec::new(); n];
    for &(a, b, c) in &g.arcs {
        if let Some(v) = out.get_mut(a) {
            v.push((b, c));
        }
    }
    // RFC 2328 §16.1 (2b): a link is used only when the far end
    // announces it back (the two-way check).
    let back: std::collections::HashSet<(usize, usize)> =
        g.arcs.iter().map(|&(a, b, _)| (a, b)).collect();
    let mut dist = vec![u32::MAX; n];
    let mut prev = vec![usize::MAX; n];
    let mut heap = BinaryHeap::new();
    *dist.get_mut(src)? = 0;
    heap.push(Reverse((0u32, src)));
    while let Some(Reverse((d, u))) = heap.pop() {
        if d > dist.get(u).copied().unwrap_or(u32::MAX) {
            continue;
        }
        for &(v, c) in out.get(u).map_or(&[][..], Vec::as_slice) {
            if !back.contains(&(v, u)) {
                continue;
            }
            let nd = d.saturating_add(c);
            if nd < dist.get(v).copied().unwrap_or(u32::MAX) {
                if let Some(x) = dist.get_mut(v) {
                    *x = nd;
                }
                if let Some(x) = prev.get_mut(v) {
                    *x = u;
                }
                heap.push(Reverse((nd, v)));
            }
        }
    }
    let (t, extra) = target;
    if dist.get(t).copied().unwrap_or(u32::MAX) == u32::MAX {
        return None;
    }
    let mut chain = vec![t];
    let mut at = t;
    while at != src {
        at = *prev.get(at)?;
        chain.push(at);
        if chain.len() > n {
            return None;
        }
    }
    chain.reverse();
    let mut hops = Vec::with_capacity(chain.len() + 1);
    for (i, &node) in chain.iter().enumerate() {
        let total = dist.get(node).copied().unwrap_or(0);
        let cost = if i == 0 {
            0
        } else {
            total - dist.get(*chain.get(i - 1)?).copied().unwrap_or(0)
        };
        hops.push(Hop {
            node: *g.nodes.get(node)?,
            cost,
            total,
        });
    }
    if extra > 0
        && let Some(last) = hops.last().cloned()
    {
        // The stub network's own cost (§16.1 step 2: added at the end).
        hops.push(Hop {
            node: last.node,
            cost: extra,
            total: last.total + extra,
        });
    }
    Some(hops)
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::ospf_state::{Link, Lsa};

    fn rid(a: u8) -> u32 {
        u32::from(Ipv4Addr::new(10, 0, 0, a))
    }

    /// r1 —10— r2 —10— r3, and r1 —50— r3 directly; r3 has a stub /24.
    pub(crate) fn triangle() -> Lsdb {
        let mut db = Lsdb {
            version: 2,
            router_id: Some(rid(1)),
            ..Lsdb::default()
        };
        let router = |db: &mut Lsdb, me: u8, links: &[(u8, u8, u16)]| {
            let start = db.links.len();
            for &(kind, to, cost) in links {
                let (id, data) = if kind == 3 {
                    (
                        u32::from(Ipv4Addr::new(192, 168, to, 0)),
                        u32::from(Ipv4Addr::new(255, 255, 255, 0)),
                    )
                } else {
                    (rid(to), 0)
                };
                db.links.push(Link {
                    kind,
                    id,
                    data,
                    metric: cost,
                });
            }
            db.lsas.push(Lsa {
                kind: 1,
                area: 0,
                id: rid(me),
                adv: rid(me),
                link_start: start as u32,
                link_count: links.len() as u16,
                ..Lsa::default()
            });
        };
        router(&mut db, 1, &[(1, 2, 10), (1, 3, 50)]);
        router(&mut db, 2, &[(1, 1, 10), (1, 3, 10)]);
        router(&mut db, 3, &[(1, 2, 10), (1, 1, 50), (3, 3, 1)]);
        db
    }

    #[test]
    fn the_cheaper_two_hops_win_and_the_costs_add_up() {
        let gs = graphs(&triangle());
        let g = &gs[&0];
        let hops = path(g, rid(1), Ipv4Addr::new(192, 168, 3, 7)).unwrap();
        let nodes: Vec<_> = hops.iter().map(|h| h.node).collect();
        assert_eq!(
            nodes,
            vec![
                Node::Router(rid(1)),
                Node::Router(rid(2)),
                Node::Router(rid(3)),
                Node::Router(rid(3))
            ]
        );
        let totals: Vec<_> = hops.iter().map(|h| h.total).collect();
        assert_eq!(totals, vec![0, 10, 20, 21]);
        assert_eq!(g.edges().len(), 3);
        assert!(path(g, rid(1), Ipv4Addr::new(8, 8, 8, 8)).is_none());
    }

    #[test]
    fn a_one_way_link_is_not_used() {
        let mut db = triangle();
        // r2 stops announcing r3: §16.1's two-way check drops r2–r3.
        db.links[3].id = rid(9);
        let gs = graphs(&db);
        let hops = path(&gs[&0], rid(1), Ipv4Addr::new(10, 0, 0, 3)).unwrap();
        assert_eq!(hops.last().unwrap().total, 50);
    }
}
