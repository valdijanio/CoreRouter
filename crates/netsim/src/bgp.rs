//! Simplified BGP-4 (RFC 4271), IPv4 unicast.
//!
//! Kept: the OPEN / KEEPALIVE handshake with the peer-AS check (§6.2), the
//! hold and keepalive timers (§4.4, §10; the smaller hold of the two OPENs
//! wins), UPDATE with announcements and withdrawals, AS-path loop detection
//! (§9.1.2), eBGP prepend and next-hop-self, iBGP split horizon (no route
//! reflection), next-hop resolution over the IGP, the decision process in
//! FRR's order (checked against `proto_bgp::decision` in the tests), the
//! `/routing filter` chains of each connection run by `proto-bgp`'s own
//! evaluator, RFC 8212 (eBGP without a chain neither accepts nor sends),
//! fast external failover on carrier loss and BFD on single-hop neighbors.
//!
//! Left out: TCP itself (an OPEN reaching the peer is the connection), the
//! collision rules of §6.8 (both OPENs are simply answered), MRAI (FRR's is
//! 0), route refresh, graceful restart, communities from the wire beyond
//! what the filter sets, multipath, IPv6.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::sync::Arc;

use corerouter_proto_bgp::filter::eval::Policy;
use corerouter_proto_bgp::filter::{Protocol, Route};
use ipnet::{IpNet, Ipv4Net};
use serde::Serialize;

use crate::fib::{Fib, FibRoute, Proto};
use crate::node::{Ev, Node, Out};
use crate::timeline::RecordKind;
use crate::{BgpConfig, LinkId, Neighbor, Time};

/// FRR `bgp default local-preference`.
const DEFAULT_LOCAL_PREF: u32 = 100;

/// Path attributes, shared by every RIB that holds the same route.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Attrs {
    /// AS_PATH (one AS_SEQUENCE), the neighbor first.
    pub(crate) as_path: Vec<u32>,
    pub(crate) next_hop: Ipv4Addr,
    pub(crate) local_pref: Option<u32>,
    pub(crate) med: Option<u32>,
    /// 0 IGP, 1 EGP, 2 incomplete.
    pub(crate) origin: u8,
    pub(crate) communities: Vec<u32>,
}

#[derive(Debug, Clone)]
pub(crate) enum BgpMsg {
    /// `attempt`: the sender's connection number (a TCP connection of its
    /// own): an OPEN of an attempt already answered is a duplicate.
    Open {
        asn: u32,
        rid: Ipv4Addr,
        hold: Time,
        attempt: u32,
    },
    Keepalive,
    Update {
        announce: Vec<(Ipv4Net, Arc<Attrs>)>,
        withdraw: Vec<Ipv4Net>,
    },
    Notification {
        reason: &'static str,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    OpenSent,
    OpenConfirm,
    Established,
}

/// A connection's filter chain, looked up once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chain {
    Unset,
    /// Named but not in `/routing filter`: nothing passes (FRR denies a
    /// route-map that does not exist).
    Missing,
    At(usize),
}

impl Chain {
    fn of(policy: &Policy, name: Option<&str>) -> Chain {
        match name {
            None => Chain::Unset,
            Some(n) => policy.chain(n).map_or(Chain::Missing, Chain::At),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Peer {
    cfg: Neighbor,
    input: Chain,
    output: Chain,
    state: State,
    epoch: u32,
    sent_open: bool,
    /// Our connection attempts, and the peer's last one we answered.
    attempt: u32,
    their_attempt: Option<u32>,
    ebgp: bool,
    peer_as: u32,
    peer_rid: Ipv4Addr,
    /// Our address on the session.
    local: Option<Ipv4Addr>,
    hold: Time,
    last_rx: Time,
    up_since: Option<Time>,
    /// Accepted routes (after the input chain).
    adj_in: BTreeMap<Ipv4Net, Arc<Attrs>>,
    /// What the neighbor has from us.
    adj_out: BTreeMap<Ipv4Net, Arc<Attrs>>,
    /// Send the whole table at the next flush (session just came up).
    resync: bool,
    flaps: u32,
    last_error: Option<String>,
}

#[derive(Debug, Clone)]
struct Path {
    /// `None`: originated here.
    peer: Option<usize>,
    attrs: Arc<Attrs>,
    valid: bool,
    igp: u32,
}

#[derive(Debug, Clone, Default)]
struct Entry {
    paths: Vec<Path>,
    best: Option<usize>,
    /// The best path as last decided (where it came from, its attributes):
    /// a removed best path still counts as "before".
    decided: Option<(Option<usize>, Arc<Attrs>)>,
}

pub(crate) struct Bgp {
    asn: u32,
    policy: Arc<Policy>,
    peers: Vec<Peer>,
    rib: BTreeMap<Ipv4Net, Entry>,
    dirty: BTreeSet<Ipv4Net>,
    /// The IGP changed: the next hops are checked again.
    pub(crate) revalidate: bool,
    /// How each next hop resolved when last looked at.
    next_hops: BTreeMap<Ipv4Addr, Option<(u32, Vec<LinkId>)>>,
    flush_pending: bool,
    best_count: usize,
}

/// A neighbor, as the window shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BgpPeerView {
    pub name: String,
    pub remote_address: Ipv4Addr,
    pub remote_as: Option<u32>,
    pub local_address: Option<Ipv4Addr>,
    pub state: &'static str,
    pub established_since: Option<Time>,
    pub prefixes_received: usize,
    pub prefixes_sent: usize,
    pub flaps: u32,
    pub last_error: Option<String>,
}

/// One path of the BGP table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BgpRouteView {
    pub prefix: Ipv4Net,
    pub from: String,
    pub as_path: Vec<u32>,
    pub next_hop: Ipv4Addr,
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
    pub best: bool,
    pub valid: bool,
}

impl Bgp {
    pub(crate) fn new(cfg: &BgpConfig, _rid: Ipv4Addr) -> Self {
        let peers = cfg
            .neighbors
            .iter()
            .map(|n| Peer {
                input: Chain::of(&cfg.policy, n.input.as_deref()),
                output: Chain::of(&cfg.policy, n.output.as_deref()),
                cfg: n.clone(),
                state: State::Idle,
                epoch: 0,
                sent_open: false,
                attempt: 0,
                their_attempt: None,
                ebgp: n.remote_as.is_some_and(|a| a != cfg.asn),
                peer_as: n.remote_as.unwrap_or(0),
                peer_rid: Ipv4Addr::UNSPECIFIED,
                local: None,
                hold: n.hold,
                last_rx: 0,
                up_since: None,
                adj_in: BTreeMap::new(),
                adj_out: BTreeMap::new(),
                resync: false,
                flaps: 0,
                last_error: None,
            })
            .collect();
        let mut rib = BTreeMap::new();
        let mut dirty = BTreeSet::new();
        let local = Arc::new(Attrs {
            as_path: Vec::new(),
            next_hop: Ipv4Addr::UNSPECIFIED,
            local_pref: None,
            med: None,
            origin: 0,
            communities: Vec::new(),
        });
        for net in &cfg.networks {
            let net = net.trunc();
            rib.insert(
                net,
                Entry {
                    paths: vec![Path {
                        peer: None,
                        attrs: local.clone(),
                        valid: true,
                        igp: 0,
                    }],
                    best: None,
                    decided: None,
                },
            );
            dirty.insert(net);
        }
        Bgp {
            asn: cfg.asn,
            policy: cfg.policy.clone(),
            peers,
            rib,
            dirty,
            revalidate: false,
            next_hops: BTreeMap::new(),
            flush_pending: false,
            best_count: 0,
        }
    }

    /// The best paths learned from neighbors, resolved over the IGP.
    pub(crate) fn installed<'a>(&'a self, igp: &'a Fib) -> impl Iterator<Item = FibRoute> + 'a {
        self.rib
            .keys()
            .filter_map(move |prefix| self.installed_one(prefix, igp))
    }

    /// The route BGP installs for `prefix`, if any.
    pub(crate) fn installed_one(&self, prefix: &Ipv4Net, igp: &Fib) -> Option<FibRoute> {
        let e = self.rib.get(prefix)?;
        let p = e.paths.get(e.best?)?;
        let peer = self.peers.get(p.peer?)?;
        let via = igp.lookup(p.attrs.next_hop)?;
        if via.links.is_empty() {
            return None;
        }
        Some(FibRoute {
            prefix: *prefix,
            proto: if peer.ebgp { Proto::Ebgp } else { Proto::Ibgp },
            metric: p.igp,
            links: via.links.clone(),
            via: Some(p.attrs.next_hop),
        })
    }

    /// After an IGP change: the prefixes whose paths use a next hop that
    /// now resolves differently (validity or IGP cost), from the cache of
    /// next hops the decision saw.
    fn moved_next_hops(&mut self, igp: &Fib) -> Vec<Ipv4Net> {
        let mut moved = BTreeSet::new();
        for (nh, seen) in &mut self.next_hops {
            let now = resolve_links(igp, *nh);
            if now != *seen {
                *seen = now;
                moved.insert(*nh);
            }
        }
        if moved.is_empty() {
            return Vec::new();
        }
        self.rib
            .iter()
            .filter(|(_, e)| {
                e.paths
                    .iter()
                    .any(|p| p.peer.is_some() && moved.contains(&p.attrs.next_hop))
            })
            .map(|(n, _)| *n)
            .collect()
    }

    pub(crate) fn best_count(&self) -> usize {
        self.best_count
    }

    pub(crate) fn peer_views(&self, now: Time) -> Vec<BgpPeerView> {
        let _ = now;
        self.peers
            .iter()
            .map(|p| BgpPeerView {
                name: p.cfg.name.clone(),
                remote_address: p.cfg.remote,
                remote_as: p.cfg.remote_as,
                local_address: p.local,
                state: if p.cfg.disabled {
                    "disabled"
                } else {
                    match p.state {
                        State::Idle => "idle",
                        State::OpenSent => "open-sent",
                        State::OpenConfirm => "open-confirm",
                        State::Established => "established",
                    }
                },
                established_since: p.up_since,
                prefixes_received: p.adj_in.len(),
                prefixes_sent: p.adj_out.len(),
                flaps: p.flaps,
                last_error: p.last_error.clone(),
            })
            .collect()
    }

    pub(crate) fn route_views(&self, limit: usize) -> Vec<BgpRouteView> {
        let mut out = Vec::new();
        for (prefix, e) in &self.rib {
            for (i, p) in e.paths.iter().enumerate() {
                if out.len() >= limit {
                    return out;
                }
                out.push(BgpRouteView {
                    prefix: *prefix,
                    from: p
                        .peer
                        .and_then(|k| self.peers.get(k))
                        .map_or_else(|| "local".to_owned(), |k| k.cfg.name.clone()),
                    as_path: p.attrs.as_path.clone(),
                    next_hop: p.attrs.next_hop,
                    local_pref: p.attrs.local_pref,
                    med: p.attrs.med,
                    best: e.best == Some(i),
                    valid: p.valid,
                });
            }
        }
        out
    }

    pub(crate) fn established(&self) -> usize {
        self.peers
            .iter()
            .filter(|p| p.state == State::Established)
            .count()
    }

    fn is_ebgp_path(&self, p: &Path) -> bool {
        p.peer
            .and_then(|k| self.peers.get(k))
            .is_some_and(|k| k.ebgp)
    }

    fn peer_rid(&self, p: &Path) -> Ipv4Addr {
        p.peer
            .and_then(|k| self.peers.get(k))
            .map_or(Ipv4Addr::UNSPECIFIED, |k| k.peer_rid)
    }

    fn peer_addr(&self, p: &Path) -> Option<Ipv4Addr> {
        p.peer.and_then(|k| self.peers.get(k)).map(|k| k.cfg.remote)
    }

    /// RFC 4271 §9.1.2.2 in FRR's order (`bgp_path_info_cmp`, the same
    /// order as `proto_bgp::decision::compare`). `Greater`: `a` is better.
    /// `a_best`/`b_best`: the path chosen before (FRR keeps the older of two
    /// eBGP paths that tie down to the IGP cost).
    fn compare(&self, a: &Path, b: &Path, a_best: bool, b_best: bool) -> Ordering {
        let by = |o: Ordering| (o != Ordering::Equal).then_some(o);
        let lp = |p: &Path| p.attrs.local_pref.unwrap_or(DEFAULT_LOCAL_PREF);
        let (ea, eb) = (self.is_ebgp_path(a), self.is_ebgp_path(b));
        let left = |p: &Path| p.attrs.as_path.first().copied();
        let internal = a.attrs.as_path.is_empty() && b.attrs.as_path.is_empty();
        let med_applies = internal || (left(a).is_some() && left(a) == left(b));
        by(a.valid.cmp(&b.valid))
            .or_else(|| by(lp(a).cmp(&lp(b))))
            .or_else(|| by(a.peer.is_none().cmp(&b.peer.is_none())))
            .or_else(|| by(b.attrs.as_path.len().cmp(&a.attrs.as_path.len())))
            .or_else(|| by(b.attrs.origin.cmp(&a.attrs.origin)))
            .or_else(|| {
                med_applies
                    .then(|| by(b.attrs.med.unwrap_or(0).cmp(&a.attrs.med.unwrap_or(0))))
                    .flatten()
            })
            .or_else(|| {
                let ia = a.peer.is_some() && !ea;
                let ib = b.peer.is_some() && !eb;
                (ea && ib || eb && ia).then_some(if ea {
                    Ordering::Greater
                } else {
                    Ordering::Less
                })
            })
            .or_else(|| by(b.igp.cmp(&a.igp)))
            .or_else(|| (ea && eb && a_best != b_best).then(|| a_best.cmp(&b_best)))
            .or_else(|| by(u32::from(self.peer_rid(b)).cmp(&u32::from(self.peer_rid(a)))))
            .or_else(|| match (self.peer_addr(a), self.peer_addr(b)) {
                (Some(_), None) => Some(Ordering::Greater),
                (None, Some(_)) => Some(Ordering::Less),
                (Some(x), Some(y)) => by(y.cmp(&x)),
                (None, None) => None,
            })
            .unwrap_or(Ordering::Equal)
    }

    /// Re-run the decision for `net`; whether the best path changed.
    fn decide(&mut self, net: &Ipv4Net, igp: &Fib) -> Change {
        let Some(mut e) = self.rib.remove(net) else {
            return Change::None;
        };
        let before = e.decided.take();
        for p in &mut e.paths {
            if p.peer.is_none() {
                p.valid = true;
                p.igp = 0;
                continue;
            }
            let r = resolve(igp, p.attrs.next_hop);
            self.next_hops
                .entry(p.attrs.next_hop)
                .or_insert_with(|| resolve_links(igp, p.attrs.next_hop));
            match r {
                Some(m) => {
                    p.valid = true;
                    p.igp = m;
                }
                None => {
                    p.valid = false;
                    p.igp = u32::MAX;
                }
            }
        }
        let mut best: Option<usize> = None;
        for (i, p) in e.paths.iter().enumerate() {
            if !p.valid {
                continue;
            }
            best = match best.and_then(|b| e.paths.get(b).map(|bp| (b, bp))) {
                None => Some(i),
                Some((b, bp)) => {
                    let o = self.compare(p, bp, e.best == Some(i), e.best == Some(b));
                    if o == Ordering::Greater {
                        Some(i)
                    } else {
                        Some(b)
                    }
                }
            };
        }
        e.best = best;
        let after = best
            .and_then(|i| e.paths.get(i))
            .map(|p| (p.peer, p.attrs.clone()));
        e.decided.clone_from(&after);
        let change = match (&before, &after) {
            (None, None) => Change::None,
            (None, Some(_)) => Change::Added,
            (Some(_), None) => Change::Removed,
            (Some((pa, aa)), Some((pb, ab))) => {
                if pa == pb && (Arc::ptr_eq(aa, ab) || aa == ab) {
                    Change::None
                } else {
                    Change::Changed
                }
            }
        };
        if !e.paths.is_empty() {
            self.rib.insert(*net, e);
        }
        change
    }

    /// What we send `to` for `net` (`None`: nothing, or a withdrawal).
    fn export(&self, to: usize, net: &Ipv4Net) -> Option<Arc<Attrs>> {
        let peer = self.peers.get(to)?;
        let e = self.rib.get(net)?;
        let p = e.paths.get(e.best?)?;
        if p.peer == Some(to) || !p.valid {
            return None;
        }
        // iBGP split horizon (RFC 4271 §9.2; no route reflection).
        if !peer.ebgp && p.peer.is_some() && !self.is_ebgp_path(p) {
            return None;
        }
        let local = peer.local?;
        let mut attrs = (*p.attrs).clone();
        match peer.output {
            Chain::Unset if peer.ebgp => return None, // RFC 8212
            Chain::Unset => {}
            Chain::Missing => return None,
            Chain::At(c) => {
                let route = to_route(net, &attrs);
                let out = self.policy.eval(c, &route, self.asn);
                if !out.accepted {
                    return None;
                }
                from_route(&mut attrs, &out.route);
            }
        }
        if peer.ebgp {
            attrs.as_path.insert(0, self.asn);
            attrs.next_hop = local;
            attrs.local_pref = None;
            if p.peer.is_some() {
                // MULTI_EXIT_DISC is not passed on to other ASes (§5.1.4).
                attrs.med = None;
            }
        } else {
            if p.peer.is_none() || peer.cfg.next_hop_self {
                attrs.next_hop = local;
            }
            attrs.local_pref = Some(attrs.local_pref.unwrap_or(DEFAULT_LOCAL_PREF));
        }
        Some(Arc::new(attrs))
    }

    /// The input side of a received route: `None` if refused.
    fn import(&self, from: usize, net: &Ipv4Net, attrs: &Arc<Attrs>) -> Option<Arc<Attrs>> {
        let peer = self.peers.get(from)?;
        if attrs.as_path.contains(&self.asn) {
            return None; // §9.1.2: AS loop
        }
        match peer.input {
            Chain::Unset if peer.ebgp => None, // RFC 8212
            Chain::Unset => Some(attrs.clone()),
            Chain::Missing => None,
            Chain::At(c) => {
                let route = to_route(net, attrs);
                let out = self.policy.eval(c, &route, self.asn);
                if !out.accepted {
                    return None;
                }
                if !out.modified() {
                    return Some(attrs.clone());
                }
                let mut a = (**attrs).clone();
                from_route(&mut a, &out.route);
                Some(Arc::new(a))
            }
        }
    }

    fn set_path(&mut self, net: Ipv4Net, peer: usize, attrs: Option<Arc<Attrs>>) {
        let e = self.rib.entry(net).or_default();
        let at = e.paths.iter().position(|p| p.peer == Some(peer));
        match (at, attrs) {
            (Some(i), Some(a)) => {
                if let Some(p) = e.paths.get_mut(i) {
                    p.attrs = a;
                }
            }
            (None, Some(a)) => e.paths.push(Path {
                peer: Some(peer),
                attrs: a,
                valid: false,
                igp: u32::MAX,
            }),
            (Some(i), None) => {
                e.paths.remove(i);
                // Indices past `i` moved down by one.
                e.best = match e.best {
                    Some(b) if b == i => None,
                    Some(b) if b > i => Some(b - 1),
                    b => b,
                };
            }
            (None, None) => {}
        }
        self.dirty.insert(net);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    None,
    Added,
    Removed,
    Changed,
}

/// How `nh` resolves (cost and links), for the next-hop cache.
fn resolve_links(igp: &Fib, nh: Ipv4Addr) -> Option<(u32, Vec<LinkId>)> {
    igp.lookup(nh)
        .filter(|r| !r.links.is_empty())
        .map(|r| (r.metric, r.links.clone()))
}

/// The IGP cost to `nh`, if it resolves over a link.
fn resolve(igp: &Fib, nh: Ipv4Addr) -> Option<u32> {
    igp.lookup(nh)
        .filter(|r| !r.links.is_empty())
        .map(|r| r.metric)
}

fn to_route(net: &Ipv4Net, a: &Attrs) -> Route {
    let mut r = Route::bgp(IpNet::V4(*net), a.as_path.clone());
    r.protocol = Protocol::Bgp;
    r.communities = a.communities.clone();
    r.med = a.med;
    r.local_pref = a.local_pref;
    r
}

fn from_route(a: &mut Attrs, r: &Route) {
    a.as_path.clone_from(&r.as_path);
    a.communities.clone_from(&r.communities);
    a.med = r.med;
    a.local_pref = r.local_pref;
}

impl Node {
    pub(crate) fn bgp_start(&mut self, now: Time) {
        let Some(b) = &self.bgp else { return };
        let retry = self.cfg.timers.bgp_connect_retry;
        let n = b.peers.len();
        for i in 0..n {
            let phase = self.pick(0x6267_7000 + i as u64, retry);
            self.q
                .push(now + phase, Ev::BgpConnect { peer: i, epoch: 0 });
        }
        self.bgp_schedule(now);
    }

    pub(crate) fn bgp_schedule(&mut self, now: Time) {
        let at = now + self.cfg.timers.bgp_process;
        let Some(b) = &mut self.bgp else { return };
        if !b.flush_pending {
            b.flush_pending = true;
            self.q.push(at, Ev::BgpFlush);
        }
    }

    /// The address our side of a session uses.
    fn bgp_local(&self, n: &Neighbor) -> Option<Ipv4Addr> {
        if let Some(a) = n.local {
            return self.owns(a).then_some(a);
        }
        if let Some(p) = self
            .ports
            .iter()
            .find(|p| p.net.is_some_and(|net| net.contains(&n.remote)))
        {
            return p.net.map(|n| n.addr());
        }
        self.loopbacks().next().map(|n| n.addr())
    }

    fn bgp_reachable(&self, a: Ipv4Addr) -> bool {
        self.fib.lookup(a).is_some_and(|r| !r.links.is_empty())
    }

    fn bgp_send(&mut self, now: Time, i: usize, msg: BgpMsg) {
        let Some(p) = self.bgp.as_ref().and_then(|b| b.peers.get(i)) else {
            return;
        };
        let (Some(from), to) = (p.local, p.cfg.remote) else {
            return;
        };
        self.out.push(Out::Bgp {
            at: now,
            from,
            to,
            msg,
        });
    }

    pub(crate) fn bgp_connect(&mut self, now: Time, i: usize, epoch: u32) {
        let retry = self.cfg.timers.bgp_connect_retry;
        let Some(p) = self.bgp.as_ref().and_then(|b| b.peers.get(i)) else {
            return;
        };
        if p.epoch != epoch || p.state == State::Established || p.cfg.disabled {
            return;
        }
        let local = self.bgp_local(&p.cfg);
        let remote = p.cfg.remote;
        let reachable = self.bgp_reachable(remote);
        let asn = self.bgp.as_ref().map_or(0, |b| b.asn);
        let rid = self.rid();
        let Some(p) = self.bgp.as_mut().and_then(|b| b.peers.get_mut(i)) else {
            return;
        };
        // No answer since the last try: start over.
        p.state = State::Idle;
        p.sent_open = false;
        if let (true, Some(local)) = (reachable, local) {
            p.local = Some(local);
            p.state = State::OpenSent;
            p.sent_open = true;
            p.attempt = p.attempt.wrapping_add(1);
            let (hold, attempt) = (p.cfg.hold, p.attempt);
            self.bgp_send(
                now,
                i,
                BgpMsg::Open {
                    asn,
                    rid,
                    hold,
                    attempt,
                },
            );
        }
        self.q.push(now + retry, Ev::BgpConnect { peer: i, epoch });
    }

    pub(crate) fn bgp_receive(&mut self, now: Time, from: Ipv4Addr, to: Ipv4Addr, msg: BgpMsg) {
        let Some(b) = &self.bgp else { return };
        let Some(i) = b
            .peers
            .iter()
            .position(|p| p.cfg.remote == from && !p.cfg.disabled)
        else {
            return; // no such connection: the TCP SYN is refused
        };
        match msg {
            BgpMsg::Open {
                asn,
                rid,
                hold,
                attempt,
            } => self.bgp_open(now, i, to, (asn, rid, hold), attempt),
            BgpMsg::Keepalive => {
                let Some(p) = self.bgp.as_mut().and_then(|b| b.peers.get_mut(i)) else {
                    return;
                };
                match p.state {
                    State::OpenConfirm => self.bgp_established(now, i),
                    State::Established => p.last_rx = now,
                    _ => {}
                }
            }
            BgpMsg::Update { announce, withdraw } => self.bgp_update(now, i, announce, withdraw),
            BgpMsg::Notification { reason } => {
                let state = self
                    .bgp
                    .as_ref()
                    .and_then(|b| b.peers.get(i))
                    .map(|p| p.state);
                if state.is_some_and(|s| s != State::Idle) {
                    self.bgp_down(now, i, format!("notification from the peer: {reason}"));
                }
                self.bgp_error(now, i, format!("peer refused the session: {reason}"));
            }
        }
    }

    fn bgp_error(&mut self, now: Time, i: usize, reason: String) {
        let Some(p) = self.bgp.as_mut().and_then(|b| b.peers.get_mut(i)) else {
            return;
        };
        if p.last_error.as_deref() == Some(reason.as_str()) {
            return;
        }
        p.last_error = Some(reason.clone());
        let peer = p.cfg.name.clone();
        self.note(now, RecordKind::BgpError { peer, reason });
    }

    fn bgp_open(
        &mut self,
        now: Time,
        i: usize,
        to: Ipv4Addr,
        (asn, rid, hold): (u32, Ipv4Addr, Time),
        attempt: u32,
    ) {
        let Some(b) = &self.bgp else { return };
        let my_as = b.asn;
        let Some(p) = b.peers.get(i) else { return };
        if p.their_attempt == Some(attempt)
            && matches!(p.state, State::OpenConfirm | State::Established)
        {
            // A repeat of the attempt we are on: our KEEPALIVE may have
            // been lost, send it again (a KEEPALIVE asks for no answer).
            self.bgp_send(now, i, BgpMsg::Keepalive);
            return;
        }
        if p.cfg.remote_as.is_some_and(|r| r != asn) {
            let want = p.cfg.remote_as.unwrap_or(0);
            self.bgp_error(now, i, format!("peer AS {asn}, expected {want}"));
            if let Some(p) = self.bgp.as_mut().and_then(|b| b.peers.get_mut(i)) {
                p.local = Some(to);
            }
            self.bgp_send(
                now,
                i,
                BgpMsg::Notification {
                    reason: "bad peer AS",
                },
            );
            return;
        }
        if p.state == State::Established {
            self.bgp_down(now, i, "the peer restarted the session".into());
        }
        let rid_me = self.rid();
        let Some(p) = self.bgp.as_mut().and_then(|b| b.peers.get_mut(i)) else {
            return;
        };
        p.peer_as = asn;
        p.peer_rid = rid;
        p.ebgp = asn != my_as;
        p.hold = p.cfg.hold.min(hold);
        p.local = Some(to);
        p.their_attempt = Some(attempt);
        // Our OPEN goes (again) with this answer: the one sent before may
        // have been lost, and the peer drops a repeat of an attempt it saw.
        if !p.sent_open {
            p.attempt = p.attempt.wrapping_add(1);
        }
        p.sent_open = true;
        p.state = State::OpenConfirm;
        let (my_hold, my_attempt) = (p.cfg.hold, p.attempt);
        self.bgp_send(
            now,
            i,
            BgpMsg::Open {
                asn: my_as,
                rid: rid_me,
                hold: my_hold,
                attempt: my_attempt,
            },
        );
        self.bgp_send(now, i, BgpMsg::Keepalive);
    }

    fn bgp_established(&mut self, now: Time, i: usize) {
        let Some(p) = self.bgp.as_mut().and_then(|b| b.peers.get_mut(i)) else {
            return;
        };
        p.state = State::Established;
        p.last_rx = now;
        p.up_since = Some(now);
        p.last_error = None;
        p.resync = true;
        let (epoch, hold) = (p.epoch, p.hold);
        // Keepalive: a third of the negotiated hold (§10), or the configured.
        let ka = p.cfg.keepalive.min(hold / 3).max(1);
        let peer = p.cfg.name.clone();
        self.note(now, RecordKind::BgpUp { peer });
        if hold > 0 {
            self.q.push(now + ka, Ev::BgpKeepalive { peer: i, epoch });
            self.q.push(now + hold, Ev::BgpHold { peer: i, epoch });
        }
        self.bgp_schedule(now);
    }

    pub(crate) fn bgp_keepalive(&mut self, now: Time, i: usize, epoch: u32) {
        let Some(p) = self.bgp.as_ref().and_then(|b| b.peers.get(i)) else {
            return;
        };
        if p.epoch != epoch || p.state != State::Established {
            return;
        }
        let ka = p.cfg.keepalive.min(p.hold / 3).max(1);
        self.bgp_send(now, i, BgpMsg::Keepalive);
        self.q.push(now + ka, Ev::BgpKeepalive { peer: i, epoch });
    }

    pub(crate) fn bgp_hold(&mut self, now: Time, i: usize, epoch: u32) {
        let Some(p) = self.bgp.as_ref().and_then(|b| b.peers.get(i)) else {
            return;
        };
        if p.epoch != epoch || p.state != State::Established {
            return;
        }
        let due = p.last_rx.saturating_add(p.hold);
        if now >= due {
            self.bgp_send(
                now,
                i,
                BgpMsg::Notification {
                    reason: "hold timer expired",
                },
            );
            self.bgp_down(now, i, "hold timer expired".into());
        } else {
            self.q.push(due, Ev::BgpHold { peer: i, epoch });
        }
    }

    /// Carrier loss or BFD on a link: single-hop sessions over it drop
    /// (FRR `bgp fast-external-failover` for eBGP; BFD where enabled).
    pub(crate) fn bgp_link_down(&mut self, now: Time, link: LinkId, reason: &'static str) {
        let Some(net) = self.port(link).and_then(|p| p.net) else {
            return;
        };
        let carrier = reason == "interface down";
        let Some(b) = &self.bgp else { return };
        let hit: Vec<usize> = b
            .peers
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                p.state != State::Idle
                    && net.contains(&p.cfg.remote)
                    && (if carrier { p.ebgp } else { p.cfg.bfd })
            })
            .map(|(i, _)| i)
            .collect();
        for i in hit {
            self.bgp_down(now, i, reason.into());
        }
    }

    /// The configuration changed: tell the neighbor and start over.
    pub(crate) fn bgp_admin_reset(&mut self, now: Time, i: usize) {
        let state = self
            .bgp
            .as_ref()
            .and_then(|b| b.peers.get(i))
            .map(|p| p.state);
        if state.is_some_and(|s| s != State::Idle) {
            self.bgp_send(
                now,
                i,
                BgpMsg::Notification {
                    reason: "administrative reset",
                },
            );
            self.bgp_down(now, i, "configuration changed".into());
        }
    }

    pub(crate) fn bgp_down(&mut self, now: Time, i: usize, reason: String) {
        let retry = self.cfg.timers.bgp_connect_retry;
        let Some(b) = self.bgp.as_mut() else { return };
        let Some(p) = b.peers.get_mut(i) else { return };
        let was_up = p.state == State::Established;
        p.state = State::Idle;
        p.sent_open = false;
        p.their_attempt = None;
        p.epoch = p.epoch.wrapping_add(1);
        p.up_since = None;
        let epoch = p.epoch;
        let gone: Vec<Ipv4Net> = std::mem::take(&mut p.adj_in).into_keys().collect();
        p.adj_out.clear();
        if was_up {
            p.flaps += 1;
        }
        let peer = p.cfg.name.clone();
        for net in gone {
            b.set_path(net, i, None);
        }
        if was_up {
            self.note(now, RecordKind::BgpDown { peer, reason });
        }
        self.q.push(now + retry, Ev::BgpConnect { peer: i, epoch });
        self.bgp_schedule(now);
    }

    fn bgp_update(
        &mut self,
        now: Time,
        i: usize,
        announce: Vec<(Ipv4Net, Arc<Attrs>)>,
        withdraw: Vec<Ipv4Net>,
    ) {
        let Some(b) = self.bgp.as_mut() else { return };
        let Some(p) = b.peers.get_mut(i) else { return };
        if p.state != State::Established {
            return;
        }
        p.last_rx = now;
        for net in withdraw {
            if let Some(p) = b.peers.get_mut(i)
                && p.adj_in.remove(&net).is_some()
            {
                b.set_path(net, i, None);
            }
        }
        for (net, attrs) in announce {
            let accepted = b.import(i, &net, &attrs);
            let Some(p) = b.peers.get_mut(i) else {
                continue;
            };
            match accepted {
                Some(a) => {
                    p.adj_in.insert(net, a.clone());
                    b.set_path(net, i, Some(a));
                }
                None => {
                    if p.adj_in.remove(&net).is_some() {
                        b.set_path(net, i, None);
                    }
                }
            }
        }
        self.bgp_schedule(now);
    }

    /// Run the decision on what changed, then tell the neighbors.
    pub(crate) fn bgp_flush(&mut self, now: Time) {
        let igp = &self.igp;
        let Some(b) = self.bgp.as_mut() else { return };
        b.flush_pending = false;
        let mut dirty = std::mem::take(&mut b.dirty);
        // Prefixes whose next hop moved: decided again, and installed
        // again even if the best stays (its links changed).
        let moved = if std::mem::take(&mut b.revalidate) {
            b.moved_next_hops(igp)
        } else {
            Vec::new()
        };
        dirty.extend(moved.iter().copied());
        let nets: Vec<Ipv4Net> = dirty.into_iter().collect();
        let (mut added, mut removed, mut changed) = (0u32, 0u32, 0u32);
        let mut touched = Vec::new();
        for net in &nets {
            match b.decide(net, igp) {
                Change::None => continue,
                Change::Added => added += 1,
                Change::Removed => removed += 1,
                Change::Changed => changed += 1,
            }
            touched.push(*net);
        }
        b.best_count = (b.best_count + added as usize).saturating_sub(removed as usize);
        // Export what changed (all of it to a session that just came up).
        let mut sends = Vec::new();
        for j in 0..b.peers.len() {
            let Some(p) = b.peers.get(j) else { continue };
            if p.state != State::Established {
                continue;
            }
            let full = p.resync;
            let candidates: Vec<Ipv4Net> = if full {
                b.rib.keys().copied().collect()
            } else {
                touched.clone()
            };
            let mut announce = Vec::new();
            let mut withdraw = Vec::new();
            for net in candidates {
                let want = b.export(j, &net);
                let Some(p) = b.peers.get_mut(j) else {
                    continue;
                };
                let have = p.adj_out.get(&net);
                if have == want.as_ref() {
                    continue;
                }
                match want {
                    Some(a) => {
                        p.adj_out.insert(net, a.clone());
                        announce.push((net, a));
                    }
                    None => {
                        p.adj_out.remove(&net);
                        withdraw.push(net);
                    }
                }
            }
            if let Some(p) = b.peers.get_mut(j) {
                p.resync = false;
            }
            if !announce.is_empty() || !withdraw.is_empty() {
                sends.push((j, BgpMsg::Update { announce, withdraw }));
            }
        }
        let prefixes = u32::try_from(b.best_count).unwrap_or(u32::MAX);
        for (j, msg) in sends {
            self.bgp_send(now, j, msg);
        }
        if added + removed + changed > 0 {
            self.note(
                now,
                RecordKind::BgpBest {
                    prefixes,
                    added,
                    removed,
                    changed,
                },
            );
        }
        touched.extend(moved);
        if !touched.is_empty() {
            touched.sort_unstable();
            touched.dedup();
            self.refresh_bgp(&touched);
        }
    }
}

/// The comparison of [`Bgp::compare`] on plain values, for the test that
/// checks it against `proto_bgp::decision`.
#[cfg(test)]
pub(crate) mod check {
    use super::*;

    #[derive(Debug, Clone)]
    pub(crate) struct Side {
        pub(crate) local: bool,
        pub(crate) ebgp: bool,
        pub(crate) attrs: Attrs,
        pub(crate) igp: u32,
        pub(crate) rid: Ipv4Addr,
        pub(crate) addr: Ipv4Addr,
        pub(crate) best: bool,
    }

    pub(crate) fn compare(a: &Side, b: &Side) -> Ordering {
        let mut cfg = BgpConfig {
            asn: 65000,
            networks: Vec::new(),
            neighbors: Vec::new(),
            policy: Arc::default(),
        };
        let mut sides = Vec::new();
        for s in [a, b] {
            if !s.local {
                cfg.neighbors.push(Neighbor::new(
                    format!("n{}", cfg.neighbors.len()),
                    s.addr,
                    Some(if s.ebgp { 65001 } else { 65000 }),
                ));
            }
        }
        let mut bgp = Bgp::new(&cfg, Ipv4Addr::UNSPECIFIED);
        let mut k = 0;
        for s in [a, b] {
            let peer = if s.local {
                None
            } else {
                if let Some(p) = bgp.peers.get_mut(k) {
                    p.peer_rid = s.rid;
                }
                k += 1;
                Some(k - 1)
            };
            sides.push(Path {
                peer,
                attrs: Arc::new(s.attrs.clone()),
                valid: true,
                igp: s.igp,
            });
        }
        match (sides.first(), sides.get(1)) {
            (Some(x), Some(y)) => bgp.compare(x, y, a.best, b.best),
            _ => Ordering::Equal,
        }
    }
}
