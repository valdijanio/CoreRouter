//! Simplified OSPFv2 (RFC 2328), one area, point-to-point links only.
//!
//! Kept: hellos and the dead interval (§9.5, §10.5), the 2-Way check, a
//! router-LSA per router with its point-to-point links and stub networks
//! (§12.4.1.1–12.4.1.2; loopbacks as /32 stubs of cost 0, as FRR does),
//! flooding with sequence numbers (§13; a router that finds a copy of its own
//! LSA newer than its counter jumps past it, §13.4), SPF with the 2-Way
//! check of §16.1 step (2)(b) and equal-cost next hops, FRR's SPF hold
//! (`timers throttle spf 0 50 5000`, without the exponential backoff).
//!
//! Left out: DR/BDR (no broadcast networks), the database description and
//! request/ack exchange (the whole database is flooded at Full), MinLSArrival
//! and MinLSInterval, aging, areas, external LSAs, authentication, MTU.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use std::net::Ipv4Addr;
use std::sync::Arc;

use ipnet::Ipv4Net;
use serde::Serialize;

use crate::node::{AdjState, Ev, LinkMsg, Node, Out};
use crate::timeline::RecordKind;
use crate::{LinkId, Time};

/// Most equal-cost next hops kept per route (FRR's default multipath is
/// 16 on Linux builds… and 64 in some; 16 bounds the memory).
const MAX_ECMP: usize = 16;

/// A router-LSA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Lsa {
    pub rid: Ipv4Addr,
    pub seq: u32,
    /// Point-to-point links: (neighbor router id, cost), sorted.
    pub links: Vec<(Ipv4Addr, u32)>,
    /// Stub networks: (prefix, cost), sorted.
    pub stubs: Vec<(Ipv4Net, u32)>,
}

#[derive(Debug, Default)]
pub(crate) struct Ospf {
    pub(crate) lsdb: BTreeMap<Ipv4Addr, Arc<Lsa>>,
    pub(crate) seq: u32,
    spf_pending: bool,
    last_spf: Option<Time>,
    /// Steps of the SPF hold in force (FRR `spf_hold_multiplier`).
    hold_mult: u32,
    last_orig: Option<Time>,
    pub(crate) orig_pending: bool,
    /// prefix → (cost, next-hop links).
    pub(crate) routes: BTreeMap<Ipv4Net, (u32, Vec<LinkId>)>,
    pub(crate) spf_runs: u64,
}

/// An adjacency, as the window shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OspfNeighborView {
    pub link: LinkId,
    pub iface: String,
    pub neighbor: Option<Ipv4Addr>,
    pub state: &'static str,
    pub cost: u32,
}

impl Node {
    fn ospf_runs_on(&self, link: LinkId) -> bool {
        self.cfg.ospf
            && self
                .port(link)
                .is_some_and(|p| p.ospf && !p.passive && p.carrier && p.bfd_up)
    }

    fn hello_of(&self, link: LinkId) -> Time {
        self.port(link)
            .and_then(|p| p.hello)
            .unwrap_or(self.cfg.timers.ospf_hello)
            .max(1)
    }

    fn dead_of(&self, link: LinkId) -> Time {
        self.port(link)
            .and_then(|p| p.dead)
            .unwrap_or(self.cfg.timers.ospf_dead)
            .max(1)
    }

    pub(crate) fn ospf_start(&mut self, now: Time) {
        if !self.cfg.ospf {
            return;
        }
        let links: Vec<LinkId> = self.ports.iter().map(|p| p.link).collect();
        for link in links {
            self.ospf_port_up(now, link);
        }
        self.ospf_originate(now, false);
    }

    /// A port came up: start its hellos at a phase of its own.
    pub(crate) fn ospf_port_up(&mut self, now: Time, link: LinkId) {
        if !self.ospf_runs_on(link) {
            return;
        }
        let phase = self.pick(u64::from(link.0), self.hello_of(link));
        let Some(p) = self.port_mut(link) else { return };
        p.hello_gen = p.hello_gen.wrapping_add(1);
        let generation = p.hello_gen;
        self.q.push(now + phase, Ev::HelloTimer(link, generation));
        self.ospf_originate(now, false);
    }

    /// The deferred origination of MinLSInterval.
    pub(crate) fn ospf_deferred_originate(&mut self, now: Time) {
        self.ospf.orig_pending = false;
        self.ospf_originate(now, false);
    }

    pub(crate) fn ospf_hello_timer(&mut self, now: Time, link: LinkId, generation: u32) {
        if !self.ospf_runs_on(link) || self.port(link).is_none_or(|p| p.hello_gen != generation) {
            return;
        }
        self.ospf_send_hello(now, link);
        self.q
            .push(now + self.hello_of(link), Ev::HelloTimer(link, generation));
    }

    fn ospf_send_hello(&mut self, now: Time, link: LinkId) {
        let Some(p) = self.port(link) else { return };
        let seen = p.adj != AdjState::Down;
        let rid = self.rid();
        self.out.push(Out::Link {
            at: now,
            link,
            msg: LinkMsg::Hello { rid, seen },
        });
    }

    pub(crate) fn ospf_hello(&mut self, now: Time, link: LinkId, rid: Ipv4Addr, seen: bool) {
        if !self.ospf_runs_on(link) {
            return;
        }
        let dead = self.dead_of(link);
        let Some(p) = self.port_mut(link) else { return };
        if p.nbr.is_some_and(|n| n != rid) {
            // Another router answers on this link now.
            self.ospf_adj_down(now, link, "neighbor changed");
        }
        let Some(p) = self.port_mut(link) else { return };
        p.last_hello = now;
        let state = p.adj;
        self.q.push(now + dead, Ev::DeadCheck(link));
        match (state, seen) {
            (AdjState::Down, _) => {
                if let Some(p) = self.port_mut(link) {
                    p.adj = AdjState::Init;
                    p.nbr = Some(rid);
                }
                if seen {
                    self.ospf_full(now, link, rid);
                } else {
                    // Tell it we heard it, so it goes 2-Way without
                    // waiting a whole hello interval.
                    self.ospf_send_hello(now, link);
                }
            }
            (AdjState::Init, true) => self.ospf_full(now, link, rid),
            (AdjState::Full, false) => {
                // It restarted and forgot us (1-Way, §10.2).
                self.ospf_adj_down(now, link, "1-way");
                if let Some(p) = self.port_mut(link) {
                    p.adj = AdjState::Init;
                    p.nbr = Some(rid);
                }
                self.ospf_send_hello(now, link);
            }
            _ => {}
        }
    }

    fn ospf_full(&mut self, now: Time, link: LinkId, rid: Ipv4Addr) {
        if let Some(p) = self.port_mut(link) {
            p.adj = AdjState::Full;
            p.nbr = Some(rid);
        }
        self.note(
            now,
            RecordKind::AdjUp {
                link,
                neighbor: rid,
            },
        );
        // The hello first: the neighbor goes Full before the database
        // arrives (both leave now, both take the link's latency).
        self.ospf_send_hello(now, link);
        let lsas: Vec<Arc<Lsa>> = self.ospf.lsdb.values().cloned().collect();
        if !lsas.is_empty() {
            self.out.push(Out::Link {
                at: now,
                link,
                msg: LinkMsg::Lsas(lsas),
            });
        }
        self.ospf_originate(now, false);
    }

    pub(crate) fn ospf_dead_check(&mut self, now: Time, link: LinkId) {
        let dead = self.dead_of(link);
        let Some(p) = self.port(link) else { return };
        if p.adj != AdjState::Down && now >= p.last_hello.saturating_add(dead) {
            self.ospf_adj_down(now, link, "dead timer");
        }
    }

    pub(crate) fn ospf_adj_down(&mut self, now: Time, link: LinkId, reason: &'static str) {
        let Some(p) = self.port_mut(link) else { return };
        if p.adj == AdjState::Down {
            return;
        }
        let was_full = p.adj == AdjState::Full;
        let neighbor = p.nbr.take();
        p.adj = AdjState::Down;
        if was_full {
            self.note(
                now,
                RecordKind::AdjDown {
                    link,
                    neighbor,
                    reason,
                },
            );
            self.ospf_originate(now, false);
        }
    }

    /// Build our router-LSA; flood it if it changed (or `force`).
    pub(crate) fn ospf_originate(&mut self, now: Time, force: bool) {
        if !self.cfg.ospf {
            return;
        }
        let mut links = Vec::new();
        let mut stubs = Vec::new();
        for p in &self.ports {
            if !(p.ospf && p.carrier) {
                continue;
            }
            if let (AdjState::Full, Some(n), true) = (p.adj, p.nbr, p.bfd_up) {
                links.push((n, p.cost));
            }
            if let Some(net) = p.net {
                stubs.push((net.trunc(), p.cost));
            }
        }
        for net in self.ospf_loopbacks() {
            stubs.push((net.trunc(), 0));
        }
        links.sort_unstable();
        stubs.sort_unstable();
        stubs.dedup_by_key(|s| s.0);
        let rid = self.rid();
        if !force
            && let Some(old) = self.ospf.lsdb.get(&rid)
            && old.links == links
            && old.stubs == stubs
        {
            return;
        }
        // RFC 2328 §12.4 MinLSInterval (FRR `timers throttle lsa all`, 5 s):
        // a new instance waits for the interval since the last one.
        let min = self.cfg.timers.min_ls_interval;
        if let Some(last) = self.ospf.last_orig
            && now < last.saturating_add(min)
            && !force
        {
            if !self.ospf.orig_pending {
                self.ospf.orig_pending = true;
                self.q.push(last.saturating_add(min), Ev::Originate);
            }
            return;
        }
        self.ospf.last_orig = Some(now);
        self.ospf.seq = self.ospf.seq.wrapping_add(1);
        let lsa = Arc::new(Lsa {
            rid,
            seq: self.ospf.seq,
            links,
            stubs,
        });
        self.ospf.lsdb.insert(rid, lsa.clone());
        self.ospf_flood(now, vec![lsa], None);
        self.ospf_schedule_spf(now);
    }

    fn ospf_flood(&mut self, now: Time, lsas: Vec<Arc<Lsa>>, except: Option<LinkId>) {
        if lsas.is_empty() {
            return;
        }
        let targets: Vec<LinkId> = self
            .ports
            .iter()
            .filter(|p| p.adj == AdjState::Full && Some(p.link) != except)
            .map(|p| p.link)
            .collect();
        // Queued per port and sent as one update when the router is done
        // with this instant (FRR packs the LSAs of a flood into one LS
        // Update per interface).
        let _ = now;
        for link in targets {
            match self.flood.iter_mut().find(|(l, _)| *l == link) {
                Some((_, q)) => {
                    for lsa in &lsas {
                        match q.iter_mut().find(|x| x.rid == lsa.rid) {
                            Some(x) if x.seq < lsa.seq => *x = lsa.clone(),
                            Some(_) => {}
                            None => q.push(lsa.clone()),
                        }
                    }
                }
                None => self.flood.push((link, lsas.clone())),
            }
        }
    }

    /// Send the queued floods (end of an instant).
    pub(crate) fn ospf_flush_floods(&mut self, now: Time) {
        for (link, lsas) in std::mem::take(&mut self.flood) {
            self.out.push(Out::Link {
                at: now,
                link,
                msg: LinkMsg::Lsas(lsas),
            });
        }
    }

    pub(crate) fn ospf_lsas(&mut self, now: Time, link: LinkId, lsas: Vec<Arc<Lsa>>) {
        if !self.ospf_runs_on(link) || self.port(link).is_none_or(|p| p.adj != AdjState::Full) {
            return;
        }
        let rid = self.rid();
        let mut newer = Vec::new();
        let mut mine_stale = false;
        for lsa in lsas {
            if lsa.rid == rid {
                // §13.4: our own LSA from before a restart.
                if lsa.seq >= self.ospf.seq {
                    self.ospf.seq = lsa.seq;
                    mine_stale = true;
                }
                continue;
            }
            let fresh = self
                .ospf
                .lsdb
                .get(&lsa.rid)
                .is_none_or(|old| lsa.seq > old.seq);
            if fresh {
                self.ospf.lsdb.insert(lsa.rid, lsa.clone());
                newer.push(lsa);
            }
        }
        if !newer.is_empty() {
            self.ospf_flood(now, newer, Some(link));
            self.ospf_schedule_spf(now);
        }
        if mine_stale {
            self.ospf_originate(now, true);
        }
    }

    /// FRR's SPF throttle (`ospf_spf_calculate_schedule`): the first run
    /// waits the initial delay (0); a run asked for within the hold time
    /// waits for it, and each such run makes the hold one step longer
    /// (×1, ×2, ×3… up to the maximum), until a quiet hold resets it.
    fn ospf_schedule_spf(&mut self, now: Time) {
        if self.ospf.spf_pending {
            return;
        }
        self.ospf.spf_pending = true;
        let t = self.cfg.timers;
        let at = match self.ospf.last_spf {
            None => {
                self.ospf.hold_mult = 1;
                now
            }
            Some(last) => {
                let elapsed = now.saturating_sub(last);
                let cur = t.spf_hold.saturating_mul(Time::from(self.ospf.hold_mult));
                if elapsed < cur {
                    if cur < t.spf_max_hold {
                        self.ospf.hold_mult = self.ospf.hold_mult.saturating_add(1);
                    }
                } else {
                    self.ospf.hold_mult = 1;
                }
                let hold = t
                    .spf_hold
                    .saturating_mul(Time::from(self.ospf.hold_mult))
                    .min(t.spf_max_hold);
                if hold > elapsed { last + hold } else { now }
            }
        };
        self.q.push(at, Ev::Spf);
    }

    /// Dijkstra over the database (RFC 2328 §16.1), on indices: routers
    /// sorted by id, distances in a vector, next-hop sets in an arena (a
    /// router inherits its parent's set by index; only a tie makes a new
    /// one). The first version cloned a `Vec` per relaxation and rebuilt a
    /// map of every route: 760 µs per run with 500 routers (**medido**).
    pub(crate) fn ospf_spf(&mut self, now: Time) {
        self.ospf.spf_pending = false;
        self.ospf.last_spf = Some(now);
        self.ospf.spf_runs += 1;
        let me = self.rid();
        let lsdb = &self.ospf.lsdb;
        let ids: Vec<Ipv4Addr> = lsdb.keys().copied().collect();
        let lsas: Vec<&Lsa> = lsdb.values().map(|l| &**l).collect();
        let ix = |a: &Ipv4Addr| ids.binary_search(a).ok();
        // Two-way: `v` lists `u` too.
        let lists = |v: usize, u: Ipv4Addr| {
            lsas.get(v)
                .is_some_and(|l| l.links.iter().any(|(n, _)| *n == u))
        };
        let n = ids.len();
        // Set 0 is the empty set.
        let mut sets: Vec<Vec<LinkId>> = vec![Vec::new()];
        let mut dist = vec![u32::MAX; n];
        let mut hop = vec![0u32; n];
        let mut done = vec![false; n];
        let mut heap = BinaryHeap::new();
        if let Some(m) = ix(&me) {
            if let Some(d) = dist.get_mut(m) {
                *d = 0;
            }
            heap.push(Reverse((0u32, m)));
        }
        let union = |sets: &mut Vec<Vec<LinkId>>, a: u32, b: u32| -> u32 {
            let mut v: Vec<LinkId> = sets.get(a as usize).cloned().unwrap_or_default();
            v.extend(sets.get(b as usize).into_iter().flatten().copied());
            v.sort_unstable();
            v.dedup();
            v.truncate(MAX_ECMP);
            sets.push(v);
            u32::try_from(sets.len() - 1).unwrap_or(0)
        };
        let mut edges: Vec<(usize, u32, Option<LinkId>)> = Vec::new();
        while let Some(Reverse((d, u))) = heap.pop() {
            if done.get(u).is_none_or(|x| *x) || dist.get(u) != Some(&d) {
                continue;
            }
            if let Some(x) = done.get_mut(u) {
                *x = true;
            }
            let Some(&rid_u) = ids.get(u) else { continue };
            edges.clear();
            if rid_u == me {
                // Our own links come from the ports: each is a next hop.
                for p in &self.ports {
                    if let (AdjState::Full, Some(nb), true) =
                        (p.adj, p.nbr, p.ospf && p.carrier && p.bfd_up)
                        && let Some(v) = ix(&nb)
                    {
                        edges.push((v, p.cost, Some(p.link)));
                    }
                }
            } else if let Some(l) = lsas.get(u) {
                edges.extend(
                    l.links
                        .iter()
                        .filter_map(|(nb, c)| Some((ix(nb)?, *c, None))),
                );
            }
            let hu = hop.get(u).copied().unwrap_or(0);
            for &(v, c, link) in &edges {
                if done.get(v).is_none_or(|x| *x) || !lists(v, rid_u) {
                    continue;
                }
                let dv = d.saturating_add(c);
                let old = dist.get(v).copied().unwrap_or(u32::MAX);
                if dv > old {
                    continue;
                }
                let via = match link {
                    Some(l) => {
                        sets.push(vec![l]);
                        u32::try_from(sets.len() - 1).unwrap_or(0)
                    }
                    None => hu,
                };
                let hv = hop.get(v).copied().unwrap_or(0);
                let set = if dv < old {
                    via
                } else {
                    union(&mut sets, hv, via)
                };
                if let (Some(dd), Some(hh)) = (dist.get_mut(v), hop.get_mut(v)) {
                    *dd = dv;
                    *hh = set;
                }
                if dv < old {
                    heap.push(Reverse((dv, v)));
                }
            }
        }
        // Every stub of every reached router, then the cheapest per prefix.
        let mut stubs: Vec<(Ipv4Net, u32, u32)> = Vec::new();
        for (v, ((dv, set), finished)) in dist.iter().zip(&hop).zip(&done).enumerate() {
            if !finished || *set == 0 {
                continue;
            }
            let Some(lsa) = lsas.get(v).filter(|l| l.rid != me) else {
                continue;
            };
            stubs.extend(
                lsa.stubs
                    .iter()
                    .map(|(net, c)| (*net, dv.saturating_add(*c), *set)),
            );
        }
        stubs.sort_unstable_by_key(|(net, cost, _)| (*net, *cost));
        let mut routes: Vec<(Ipv4Net, u32, u32)> = Vec::with_capacity(stubs.len());
        for (net, cost, set) in stubs {
            match routes.last_mut() {
                Some((n, c, s)) if *n == net => {
                    if *c == cost && *s != set {
                        *s = union(&mut sets, *s, set);
                    }
                }
                _ => routes.push((net, cost, set)),
            }
        }
        // What changed, by walking the old map and the new list together.
        let set_of = |s: u32| sets.get(s as usize).map_or(&[][..], Vec::as_slice);
        let mut changed: Vec<Ipv4Net> = Vec::new();
        let (mut added, mut removed) = (0usize, 0usize);
        {
            let mut old = self.ospf.routes.iter().peekable();
            let mut new = routes.iter().peekable();
            loop {
                match (old.peek(), new.peek()) {
                    (None, None) => break,
                    (Some((on, _)), None) => {
                        changed.push(**on);
                        removed += 1;
                        old.next();
                    }
                    (None, Some((nn, _, _))) => {
                        changed.push(*nn);
                        added += 1;
                        new.next();
                    }
                    (Some((on, (oc, ol))), Some((nn, nc, ns))) => {
                        if *on < nn {
                            changed.push(**on);
                            removed += 1;
                            old.next();
                        } else if nn < *on {
                            changed.push(*nn);
                            added += 1;
                            new.next();
                        } else {
                            if oc != nc || ol.as_slice() != set_of(*ns) {
                                changed.push(*nn);
                            }
                            old.next();
                            new.next();
                        }
                    }
                }
            }
        }
        if changed.is_empty() {
            return;
        }
        for net in &changed {
            match routes.binary_search_by_key(net, |(n, _, _)| *n) {
                Ok(k) => {
                    if let Some((_, cost, set)) = routes.get(k) {
                        self.ospf
                            .routes
                            .insert(*net, (*cost, set_of(*set).to_vec()));
                    }
                }
                Err(_) => {
                    self.ospf.routes.remove(net);
                }
            }
        }
        let total = self.ospf.routes.len();
        self.note(
            now,
            RecordKind::IgpChanged {
                routes: u32::try_from(total).unwrap_or(u32::MAX),
                added: u32::try_from(added).unwrap_or(u32::MAX),
                removed: u32::try_from(removed).unwrap_or(u32::MAX),
            },
        );
        self.refresh_ospf(now, &changed);
    }

    pub(crate) fn ospf_neighbors(&self) -> Vec<OspfNeighborView> {
        self.ports
            .iter()
            .filter(|p| p.ospf)
            .map(|p| OspfNeighborView {
                link: p.link,
                iface: p.iface.clone(),
                neighbor: p.nbr,
                state: match (p.carrier, p.adj) {
                    (false, _) => "interface-down",
                    (true, AdjState::Down) => "down",
                    (true, AdjState::Init) => "init",
                    (true, AdjState::Full) => "full",
                },
                cost: p.cost,
            })
            .collect()
    }
}
