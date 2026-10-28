//! TI-LFA, simplified (G3.4d; RFC 9855, the algorithm of FRR 10.7.1's
//! `ospfd/ospf_ti_lfa.c`): for a protected link or node next to `root`,
//! the repair path a router pushes onto a packet until the IGP converges.
//!
//! As `ospfd` does it, per destination router `d`:
//! 1. P-space: the routers `root` still reaches over a shortest path that
//!    avoids the protected resource (the SPF tree with the resource cut);
//! 2. Q-space: the routers that reach `d` over a shortest path avoiding it
//!    (the reverse SPF from `d`, cut);
//! 3. the post-convergence path: the SPF from `root` without the resource;
//! 4. walking that path from `d` towards `root`: the first router in both
//!    spaces is the PQ node (one segment); otherwise the Q node (the last
//!    of the Q-space) and, before it, the P node (the first of the
//!    P-space): a segment to P and an adjacency P→Q;
//! 5. a router next to `root` is reached by `root`'s adjacency SID, any
//!    other by its prefix SID; the destination's own prefix SID goes last.
//!
//! Kept simple: one parent per vertex (the lowest router id on a tie, where
//! FRR keeps its first), and when P and Q are not adjacent (node protection,
//! asymmetric costs) one adjacency per hop from P to Q instead of FRR's
//! recursive inner stack. The fidelity test against FRR is
//! `scripts/frr-sr-live.sh` (`live_ti_lfa`).

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::net::Ipv4Addr;
use std::rc::Rc;

use serde::Serialize;

/// Most routers the computation takes (a large single area, **estimado**).
pub const MAX_ROUTERS: usize = 20_000;

/// A point-to-point topology: routers and directed costs (`a` announces
/// the link to `b` with `cost`).
#[derive(Debug, Clone, Default)]
pub struct Topology {
    ids: Vec<Ipv4Addr>,
    index: BTreeMap<Ipv4Addr, usize>,
    /// Out arcs by router: (to, cost).
    out: Vec<Vec<(usize, u32)>>,
    /// In arcs by router: (from, cost), for the reverse SPF.
    rev: Vec<Vec<(usize, u32)>>,
}

impl Topology {
    /// From the arcs `(from, to, cost)`; a link counts only when both ends
    /// announce it (the two-way check of RFC 2328 §16.1 (2)(b)).
    pub fn new(arcs: &[(Ipv4Addr, Ipv4Addr, u32)]) -> Topology {
        let mut t = Topology::default();
        let set: BTreeSet<(Ipv4Addr, Ipv4Addr)> = arcs.iter().map(|(a, b, _)| (*a, *b)).collect();
        for (a, b, c) in arcs {
            if !set.contains(&(*b, *a)) || a == b {
                continue;
            }
            let (Some(x), Some(y)) = (t.add(*a), t.add(*b)) else {
                continue;
            };
            if let Some(v) = t.out.get_mut(x)
                && !v.iter().any(|(to, _)| *to == y)
            {
                v.push((y, *c));
            }
        }
        for v in &mut t.out {
            v.sort_unstable();
        }
        t.rev = vec![Vec::new(); t.ids.len()];
        for (a, outs) in t.out.iter().enumerate() {
            for (b, c) in outs {
                if let Some(v) = t.rev.get_mut(*b) {
                    v.push((a, *c));
                }
            }
        }
        t
    }

    fn add(&mut self, id: Ipv4Addr) -> Option<usize> {
        if let Some(i) = self.index.get(&id) {
            return Some(*i);
        }
        if self.ids.len() >= MAX_ROUTERS {
            return None;
        }
        self.ids.push(id);
        self.out.push(Vec::new());
        let i = self.ids.len() - 1;
        self.index.insert(id, i);
        Some(i)
    }

    pub fn routers(&self) -> &[Ipv4Addr] {
        &self.ids
    }

    /// The neighbors of `id`, with the cost `id` announces.
    pub fn neighbors(&self, id: Ipv4Addr) -> Vec<(Ipv4Addr, u32)> {
        let Some(i) = self.index.get(&id) else {
            return Vec::new();
        };
        self.out
            .get(*i)
            .into_iter()
            .flatten()
            .filter_map(|(to, c)| Some((*self.ids.get(*to)?, *c)))
            .collect()
    }
}

/// What is protected: the link `root`–`neighbor` or the router `neighbor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protection {
    Link,
    Node,
}

/// One segment of a repair path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Segment {
    /// The adjacency SID `from` announces for its link to `to`.
    Adjacency { from: Ipv4Addr, to: Ipv4Addr },
    /// A router's prefix (node) SID.
    Node { router: Ipv4Addr },
}

/// The repair of destination router `dest` when `neighbor` (the link to it,
/// or the router) fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Repair {
    pub dest: Ipv4Addr,
    pub neighbor: Ipv4Addr,
    pub protection: Protection,
    /// The neighbor the repaired packet leaves to.
    pub nexthop: Option<Ipv4Addr>,
    /// Segments, top first, without the destination's own (it follows).
    pub segments: Vec<Segment>,
    /// The post-convergence path, `root` to `dest`.
    pub path: Vec<Ipv4Addr>,
    pub cost: Option<u32>,
    /// Why there is no repair, when there is none.
    pub reason: Option<&'static str>,
}

/// Single-parent SPF: distances and parents from `src`, `forward` along
/// the arcs or against them (the reverse SPF of the Q-space), skipping the
/// arc `cut` (both ways) and the router `gone`.
fn spf(
    t: &Topology,
    src: usize,
    forward: bool,
    cut: Option<(usize, usize)>,
    gone: Option<usize>,
) -> (Vec<u32>, Vec<Option<usize>>) {
    let n = t.ids.len();
    let mut dist = vec![u32::MAX; n];
    let mut parent: Vec<Option<usize>> = vec![None; n];
    let arcs = |u: usize| -> &[(usize, u32)] {
        let side = if forward { &t.out } else { &t.rev };
        side.get(u).map_or(&[][..], Vec::as_slice)
    };
    let blocked = |a: usize, b: usize| {
        cut.is_some_and(|(x, y)| (a, b) == (x, y) || (a, b) == (y, x))
            || gone == Some(b)
            || gone == Some(a)
    };
    if let Some(d) = dist.get_mut(src) {
        *d = 0;
    }
    let mut heap = BinaryHeap::new();
    heap.push(Reverse((0u32, src)));
    while let Some(Reverse((d, u))) = heap.pop() {
        if dist.get(u) != Some(&d) {
            continue;
        }
        for &(v, c) in arcs(u) {
            if blocked(u, v) {
                continue;
            }
            let dv = d.saturating_add(c);
            let old = dist.get(v).copied().unwrap_or(u32::MAX);
            let tie_better = dv == old
                && parent
                    .get(v)
                    .copied()
                    .flatten()
                    .is_some_and(|p| t.ids.get(u) < t.ids.get(p));
            if dv < old || tie_better {
                if let (Some(dd), Some(pp)) = (dist.get_mut(v), parent.get_mut(v)) {
                    *dd = dv;
                    *pp = Some(u);
                }
                if dv < old {
                    heap.push(Reverse((dv, v)));
                }
            }
        }
    }
    (dist, parent)
}

/// The repair of every destination router from `root`, for each neighbor
/// on its primary path, with `protection`.
pub fn repairs(t: &Topology, root: Ipv4Addr, protection: Protection) -> Vec<Repair> {
    let Some(&r) = t.index.get(&root) else {
        return Vec::new();
    };
    let (dist, parent) = spf(t, r, true, None, None);
    let mut out = Vec::new();
    // The first hop of each destination's primary path.
    let first_hop = |mut v: usize| -> Option<usize> {
        let mut guard = 0;
        while let Some(p) = parent.get(v).copied().flatten() {
            if p == r {
                return Some(v);
            }
            v = p;
            guard += 1;
            if guard > t.ids.len() {
                return None;
            }
        }
        None
    };
    let mut c = Spfs::new(t, r, protection);
    for (d, dd) in dist.iter().enumerate() {
        if d == r || *dd == u32::MAX {
            continue;
        }
        let Some(nh) = first_hop(d) else { continue };
        out.push(repair_one(&mut c, d, nh));
    }
    out
}

type Tree = Rc<(Vec<u32>, Vec<Option<usize>>)>;

/// The SPFs the repairs from one root share: the plain tree from the root,
/// the tree without each neighbor's resource (the P-space and the
/// post-convergence path), and each destination's plain reverse tree. Only
/// the reverse tree without the resource is per destination and neighbor.
struct Spfs<'a> {
    t: &'a Topology,
    r: usize,
    p: Protection,
    orig: Option<Tree>,
    cut: BTreeMap<usize, Tree>,
    q_orig: BTreeMap<usize, Tree>,
}

impl<'a> Spfs<'a> {
    fn new(t: &'a Topology, r: usize, p: Protection) -> Self {
        Spfs {
            t,
            r,
            p,
            orig: None,
            cut: BTreeMap::new(),
            q_orig: BTreeMap::new(),
        }
    }

    fn resource(&self, n: usize) -> (Option<(usize, usize)>, Option<usize>) {
        match self.p {
            Protection::Link => (Some((self.r, n)), None),
            Protection::Node => (None, Some(n)),
        }
    }

    fn orig(&mut self) -> Tree {
        let (t, r) = (self.t, self.r);
        Rc::clone(
            self.orig
                .get_or_insert_with(|| Rc::new(spf(t, r, true, None, None))),
        )
    }

    fn cut(&mut self, n: usize) -> Tree {
        let (cut, gone) = self.resource(n);
        let (t, r) = (self.t, self.r);
        Rc::clone(
            self.cut
                .entry(n)
                .or_insert_with(|| Rc::new(spf(t, r, true, cut, gone))),
        )
    }

    fn q_orig(&mut self, d: usize) -> Tree {
        let t = self.t;
        Rc::clone(
            self.q_orig
                .entry(d)
                .or_insert_with(|| Rc::new(spf(t, d, false, None, None))),
        )
    }
}

/// The repair of destination `dest` when `neighbor` fails (`root` is this
/// router); `None` when a router is unknown.
pub fn repair(
    t: &Topology,
    root: Ipv4Addr,
    dest: Ipv4Addr,
    neighbor: Ipv4Addr,
    protection: Protection,
) -> Option<Repair> {
    let r = *t.index.get(&root)?;
    let d = *t.index.get(&dest)?;
    let n = *t.index.get(&neighbor)?;
    Some(repair_one(&mut Spfs::new(t, r, protection), d, n))
}

fn repair_one(c: &mut Spfs<'_>, d: usize, n: usize) -> Repair {
    let (t, r, protection) = (c.t, c.r, c.p);
    let id = |i: usize| t.ids.get(i).copied().unwrap_or(Ipv4Addr::UNSPECIFIED);
    let mut rep = Repair {
        dest: id(d),
        neighbor: id(n),
        protection,
        nexthop: None,
        segments: Vec::new(),
        path: Vec::new(),
        cost: None,
        reason: None,
    };
    let (cut, gone) = c.resource(n);
    if protection == Protection::Node && d == n {
        // ospf_ti_lfa_generate_q_spaces: no Q-space for the protected node.
        rep.reason = Some(
            "the destination is the next hop: node protection cannot cover it (link protection does)",
        );
        return rep;
    }
    // P-space: shortest paths from root that avoid the resource.
    let orig = c.orig();
    let pc = c.cut(n);
    let (d_orig, (pc_dist, pc_parent)) = (&orig.0, (&pc.0, &pc.1));
    let in_p = |v: usize| {
        d_orig
            .get(v)
            .is_some_and(|a| *a != u32::MAX && pc_dist.get(v) == Some(a))
    };
    // Q-space: shortest paths to d that avoid the resource.
    let qo = c.q_orig(d);
    let q_orig = &qo.0;
    let (q_cut, _) = spf(t, d, false, cut, gone);
    let in_q = |v: usize| {
        q_orig
            .get(v)
            .is_some_and(|a| *a != u32::MAX && q_cut.get(v) == Some(a))
    };
    let Some(&cost) = pc_dist.get(d).filter(|c| **c != u32::MAX) else {
        rep.reason = Some(match protection {
            Protection::Link => "no other path: the link is the only way to the destination",
            Protection::Node => "no other path: every way to the destination crosses the next hop",
        });
        return rep;
    };
    rep.cost = Some(cost);
    // dest → … → root.
    let mut back = vec![d];
    let mut v = d;
    while let Some(p) = pc_parent.get(v).copied().flatten() {
        back.push(p);
        v = p;
        if back.len() > t.ids.len() {
            break;
        }
    }
    rep.path = back.iter().rev().map(|i| id(*i)).collect();
    // The neighbor the packet leaves to.
    let next = back.iter().rev().nth(1).copied();
    rep.nexthop = next.map(id);
    let adjacent_to_root = |v: usize| Some(v) == next;
    let seg_to = |v: usize| {
        if adjacent_to_root(v) {
            Segment::Adjacency {
                from: id(r),
                to: id(v),
            }
        } else {
            Segment::Node { router: id(v) }
        }
    };
    // From d towards root: the PQ node, or the Q node.
    let mut q_at = None;
    for (k, v) in back.iter().enumerate() {
        if *v == r {
            break;
        }
        if in_p(*v) && in_q(*v) {
            rep.segments = vec![seg_to(*v)];
            return rep;
        }
        let toward_root = back.get(k + 1).copied();
        if toward_root.is_none_or(|u| !in_q(u) || u == r) {
            q_at = Some(k);
            break;
        }
    }
    let Some(qk) = q_at else {
        rep.reason = Some("no Q node on the post-convergence path");
        return rep;
    };
    let q = back.get(qk).copied().unwrap_or(d);
    // From Q towards root: the first router in P.
    let Some((pk, p)) = back
        .iter()
        .enumerate()
        .skip(qk + 1)
        .find(|(_, v)| **v == r || in_p(**v))
        .map(|(k, v)| (k, *v))
    else {
        rep.reason = Some("no P node on the post-convergence path");
        return rep;
    };
    if p != r {
        rep.segments.push(seg_to(p));
    }
    // P to Q: one adjacency per hop (FRR: adjacent P and Q, one).
    let hops: Vec<usize> = back
        .get(qk..=pk)
        .map(|s| s.iter().rev().copied().collect())
        .unwrap_or_default();
    for w in hops.windows(2) {
        if let [a, b] = w {
            rep.segments.push(Segment::Adjacency {
                from: id(*a),
                to: id(*b),
            });
        }
    }
    if q == d && rep.segments.is_empty() {
        rep.reason = Some("no repair segment");
    }
    rep
}

/// One route for the coverage: who announces the prefix (`dest`), the
/// neighbor its primary path leaves by, and whether the daemon installed a
/// backup for it.
#[derive(Debug, Clone, Copy)]
pub struct CoverInput<'a> {
    pub prefix: &'a str,
    pub dest: Option<Ipv4Addr>,
    pub neighbor: Option<Ipv4Addr>,
    pub has_backup: bool,
}

/// A route left without a backup, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Unprotected {
    pub prefix: String,
    pub reason: String,
}

/// `show … fast-reroute prefix-summary`, ours.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Coverage {
    pub total: usize,
    pub protected: usize,
    pub unprotected: Vec<Unprotected>,
}

impl Coverage {
    /// Percent protected (100 with no route).
    pub fn percent(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            self.protected as f64 * 100.0 / self.total as f64
        }
    }
}

/// The coverage of `routes` from `root`: a route is protected when the
/// daemon installed a backup; for the others the reason comes from the
/// same computation as the daemon's (one per destination and neighbor,
/// memoized: a few SPFs per router, not per prefix).
pub fn coverage(
    t: &Topology,
    root: Ipv4Addr,
    protection: Protection,
    routes: &[CoverInput<'_>],
) -> Coverage {
    let mut c = Coverage {
        total: routes.len(),
        ..Coverage::default()
    };
    let mut memo: BTreeMap<(Ipv4Addr, Ipv4Addr), &'static str> = BTreeMap::new();
    let mut spfs = t.index.get(&root).map(|r| Spfs::new(t, *r, protection));
    for r in routes {
        if r.has_backup {
            c.protected += 1;
            continue;
        }
        let reason: &'static str = match (r.dest, r.neighbor) {
            (_, None) => "directly connected: no next hop to protect",
            (None, _) => {
                "not announced by a router of the area (external or summary): no repair is computed for it"
            }
            (Some(d), Some(n)) => {
                if let Some(known) = memo.get(&(d, n)) {
                    known
                } else {
                    let ix = (t.index.get(&d), t.index.get(&n));
                    let why = match (spfs.as_mut(), ix) {
                        (Some(c), (Some(d), Some(n))) => repair_one(c, *d, *n)
                            .reason
                            .unwrap_or("a repair exists but none was installed: a router on it has no SID, SR is off there, or the daemon found none (FRR 10.7.1 leaves out some with P and Q apart)"),
                        _ => "a router of the path is not in the database",
                    };
                    memo.insert((d, n), why);
                    why
                }
            }
        };
        c.unprotected.push(Unprotected {
            prefix: r.prefix.to_owned(),
            reason: reason.to_owned(),
        });
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 255, 0, n)
    }

    /// The square of `scripts/frr-sr-live.sh`: R1–R2 10, R2–R3 10,
    /// R3–R4 20, R4–R1 10.
    fn square() -> Topology {
        let mut arcs = Vec::new();
        for (a, b, c) in [(1, 2, 10), (2, 3, 10), (3, 4, 20), (4, 1, 10)] {
            arcs.push((ip(a), ip(b), c));
            arcs.push((ip(b), ip(a), c));
        }
        Topology::new(&arcs)
    }

    #[test]
    fn link_protection_on_the_square_matches_frr() {
        let t = square();
        // R4 → R2 goes by R1; the R4–R1 link fails: FRR installed
        // "via R3, labels 15001/16002" (lab VM): R4's adjacency to R3, then
        // R2's prefix SID.
        let rep = repair(&t, ip(4), ip(2), ip(1), Protection::Link).unwrap();
        assert_eq!(rep.nexthop, Some(ip(3)));
        assert_eq!(
            rep.segments,
            vec![Segment::Adjacency {
                from: ip(4),
                to: ip(3)
            }]
        );
        assert_eq!(rep.path, vec![ip(4), ip(3), ip(2)]);
        assert_eq!(rep.cost, Some(30));
        // R1 → R3 by R2; the R1–R2 link fails: around by R4.
        let rep = repair(&t, ip(1), ip(3), ip(2), Protection::Link).unwrap();
        assert_eq!(rep.nexthop, Some(ip(4)));
        assert_eq!(rep.path, vec![ip(1), ip(4), ip(3)]);
        assert!(rep.reason.is_none(), "{rep:?}");
        // Every destination from R1 has one.
        let all = repairs(&t, ip(1), Protection::Link);
        assert_eq!(all.len(), 3);
        assert!(all.iter().all(|r| r.reason.is_none()), "{all:?}");
    }

    #[test]
    fn a_bridge_and_node_protection_say_why() {
        // R5 hangs off R1 alone.
        let mut arcs: Vec<(Ipv4Addr, Ipv4Addr, u32)> = Vec::new();
        for (a, b, c) in [(1, 2, 10), (2, 3, 10), (3, 4, 20), (4, 1, 10), (1, 5, 10)] {
            arcs.push((ip(a), ip(b), c));
            arcs.push((ip(b), ip(a), c));
        }
        let t = Topology::new(&arcs);
        let rep = repair(&t, ip(1), ip(5), ip(5), Protection::Link).unwrap();
        assert!(rep.reason.unwrap().contains("only way"));
        let rep = repair(&t, ip(1), ip(2), ip(2), Protection::Node).unwrap();
        assert!(rep.reason.unwrap().contains("node protection cannot cover"));
        // Node protection of R2 for R3: around by R4.
        let rep = repair(&t, ip(1), ip(3), ip(2), Protection::Node).unwrap();
        assert_eq!(rep.nexthop, Some(ip(4)));
        assert!(!rep.path.contains(&ip(2)));
    }

    #[test]
    fn a_one_way_link_is_not_a_link() {
        let t = Topology::new(&[(ip(1), ip(2), 10)]);
        assert!(t.neighbors(ip(1)).is_empty());
        assert!(repairs(&t, ip(1), Protection::Link).is_empty());
    }

    #[test]
    fn a_long_repair_has_p_and_q() {
        // R1–R2 is cheap, the way around is R1–R6–R7–R8–R3 with R6–R7 dear
        // enough that R7 is not in R1's P-space.
        let mut arcs: Vec<(Ipv4Addr, Ipv4Addr, u32)> = Vec::new();
        for (a, b, c) in [
            (1, 2, 1),
            (2, 3, 1),
            (1, 6, 1),
            (6, 7, 10),
            (7, 8, 1),
            (8, 3, 1),
        ] {
            arcs.push((ip(a), ip(b), c));
            arcs.push((ip(b), ip(a), c));
        }
        let t = Topology::new(&arcs);
        let rep = repair(&t, ip(1), ip(3), ip(2), Protection::Link).unwrap();
        assert_eq!(rep.nexthop, Some(ip(6)));
        assert_eq!(rep.path, vec![ip(1), ip(6), ip(7), ip(8), ip(3)]);
        assert!(!rep.segments.is_empty(), "{rep:?}");
        assert!(
            rep.segments.iter().any(
                |s| matches!(s, Segment::Adjacency { from, to } if *from == ip(6) && *to == ip(7))
            ),
            "{rep:?}"
        );
    }

    #[test]
    fn coverage_counts_and_explains() {
        let mut arcs: Vec<(Ipv4Addr, Ipv4Addr, u32)> = Vec::new();
        for (a, b, c) in [(1, 2, 10), (2, 3, 10), (3, 4, 20), (4, 1, 10), (1, 5, 10)] {
            arcs.push((ip(a), ip(b), c));
            arcs.push((ip(b), ip(a), c));
        }
        let t = Topology::new(&arcs);
        let routes = [
            CoverInput {
                prefix: "10.255.0.3/32",
                dest: Some(ip(3)),
                neighbor: Some(ip(2)),
                has_backup: true,
            },
            CoverInput {
                prefix: "10.255.0.5/32",
                dest: Some(ip(5)),
                neighbor: Some(ip(5)),
                has_backup: false,
            },
            CoverInput {
                prefix: "10.0.12.0/30",
                dest: Some(ip(2)),
                neighbor: None,
                has_backup: false,
            },
            CoverInput {
                prefix: "10.255.0.4/32",
                dest: Some(ip(4)),
                neighbor: Some(ip(4)),
                has_backup: false,
            },
        ];
        let c = coverage(&t, ip(1), Protection::Link, &routes);
        assert_eq!((c.total, c.protected), (4, 1));
        assert!((c.percent() - 25.0).abs() < 1e-9);
        assert!(c.unprotected[0].reason.contains("only way"), "{c:?}");
        assert!(c.unprotected[1].reason.contains("directly connected"));
        assert!(
            c.unprotected[2].reason.contains("none was installed"),
            "{c:?}"
        );
    }
}
