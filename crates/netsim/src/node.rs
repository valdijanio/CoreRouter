//! One virtual router: its ports, its event queue and the protocol
//! machines (`ospf`, `bgp`) that run on them. A node only touches its own
//! state while a window runs; what it sends goes to `out` and the
//! simulation delivers it at the barrier.

use std::net::Ipv4Addr;
use std::sync::Arc;

use ipnet::Ipv4Net;

use crate::bgp::{Bgp, BgpMsg};
use crate::fib::{Fib, FibRoute, Proto};
use crate::ospf::{Lsa, Ospf};
use crate::queue::Queue;
use crate::timeline::{Record, RecordKind};
use crate::{LinkId, NodeConfig, NodeId, Time, mix};

/// What arrives on a link (OSPF talks to the router on the other end).
#[derive(Debug, Clone)]
pub(crate) enum LinkMsg {
    /// RFC 2328 §10.5: `seen`: the sender lists us as a neighbor (2-Way).
    Hello { rid: Ipv4Addr, seen: bool },
    /// Link state updates (the database exchange of §10.8 included).
    Lsas(Vec<Arc<Lsa>>),
}

#[derive(Debug, Clone)]
pub(crate) enum Ev {
    Link {
        link: LinkId,
        msg: LinkMsg,
    },
    Bgp {
        from: Ipv4Addr,
        to: Ipv4Addr,
        msg: BgpMsg,
    },
    /// The port's hello generation: a restarted port starts a new chain.
    HelloTimer(LinkId, u32),
    DeadCheck(LinkId),
    Spf,
    Originate,
    BgpConnect {
        peer: usize,
        epoch: u32,
    },
    BgpKeepalive {
        peer: usize,
        epoch: u32,
    },
    BgpHold {
        peer: usize,
        epoch: u32,
    },
    BgpFlush,
    Carrier {
        link: LinkId,
        up: bool,
    },
    Bfd {
        link: LinkId,
        up: bool,
    },
}

/// Something a node sends, delivered at the barrier.
#[derive(Debug, Clone)]
pub(crate) enum Out {
    Link {
        at: Time,
        link: LinkId,
        msg: LinkMsg,
    },
    /// Routed hop by hop over the forwarding tables.
    Bgp {
        at: Time,
        from: Ipv4Addr,
        to: Ipv4Addr,
        msg: BgpMsg,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdjState {
    Down,
    Init,
    Full,
}

/// One end of a link on this router.
#[derive(Debug, Clone)]
pub(crate) struct Port {
    pub(crate) link: LinkId,
    pub(crate) iface: String,
    pub(crate) cost: u32,
    pub(crate) ospf: bool,
    pub(crate) bfd: bool,
    pub(crate) carrier: bool,
    pub(crate) bfd_up: bool,
    /// Our address on the link's subnet.
    pub(crate) net: Option<Ipv4Net>,
    pub(crate) adj: AdjState,
    pub(crate) nbr: Option<Ipv4Addr>,
    pub(crate) last_hello: Time,
    pub(crate) hello_gen: u32,
    /// What the link says (the editor's cost, OSPF and BFD on it); `cost`,
    /// `ospf` and `bfd` are these with the router's OSPF config applied.
    pub(crate) link_cost: u32,
    pub(crate) link_ospf: bool,
    pub(crate) link_bfd: bool,
    pub(crate) passive: bool,
    pub(crate) hello: Option<Time>,
    pub(crate) dead: Option<Time>,
}

impl Port {
    pub(crate) fn new(link: LinkId, iface: String, cost: u32, ospf: bool, bfd: bool) -> Self {
        Port {
            link,
            iface,
            cost,
            ospf,
            bfd,
            carrier: true,
            bfd_up: true,
            net: None,
            adj: AdjState::Down,
            nbr: None,
            last_hello: 0,
            hello_gen: 0,
            link_cost: cost,
            link_ospf: ospf,
            link_bfd: bfd,
            passive: false,
            hello: None,
            dead: None,
        }
    }
}

pub(crate) struct Node {
    pub(crate) id: NodeId,
    pub(crate) cfg: NodeConfig,
    pub(crate) up: bool,
    pub(crate) seed: u64,
    pub(crate) q: Queue<Ev>,
    /// Sorted by link.
    pub(crate) ports: Vec<Port>,
    pub(crate) ospf: Ospf,
    pub(crate) bgp: Option<Bgp>,
    /// Connected + OSPF: what BGP next hops resolve over.
    pub(crate) igp: Fib,
    pub(crate) connected: Fib,
    /// Everything installed.
    pub(crate) fib: Fib,
    pub(crate) out: Vec<Out>,
    /// LSAs to flood, per port, until the end of the current instant.
    pub(crate) flood: Vec<(LinkId, Vec<Arc<Lsa>>)>,
    pub(crate) log: Vec<Record>,
    pub(crate) events: u64,
}

/// An empty router (what `mem::take` leaves while a worker runs the real
/// one); allocates nothing.
impl Default for Node {
    fn default() -> Self {
        Node::new(
            NodeId(u32::MAX),
            NodeConfig::new(String::new(), Ipv4Addr::UNSPECIFIED),
            0,
        )
    }
}

impl Node {
    pub(crate) fn new(id: NodeId, cfg: NodeConfig, seed: u64) -> Self {
        Node {
            id,
            cfg,
            up: true,
            seed: mix(seed ^ u64::from(id.0).wrapping_mul(0x1000_0000_01b3)),
            q: Queue::default(),
            ports: Vec::new(),
            ospf: Ospf::default(),
            bgp: None,
            igp: Fib::default(),
            connected: Fib::default(),
            fib: Fib::default(),
            out: Vec::new(),
            flood: Vec::new(),
            log: Vec::new(),
            events: 0,
        }
    }

    pub(crate) fn port(&self, link: LinkId) -> Option<&Port> {
        let i = self.ports.binary_search_by_key(&link, |p| p.link).ok()?;
        self.ports.get(i)
    }

    pub(crate) fn port_mut(&mut self, link: LinkId) -> Option<&mut Port> {
        let i = self.ports.binary_search_by_key(&link, |p| p.link).ok()?;
        self.ports.get_mut(i)
    }

    /// A number in `0..n` from this router's seed and `salt`.
    pub(crate) fn pick(&self, salt: u64, n: Time) -> Time {
        if n == 0 {
            return 0;
        }
        mix(self.seed ^ mix(salt)) % n
    }

    pub(crate) fn note(&mut self, at: Time, kind: RecordKind) {
        self.log.push(Record {
            at,
            node: Some(self.id),
            kind,
        });
    }

    pub(crate) fn rid(&self) -> Ipv4Addr {
        self.cfg.router_id
    }

    /// Assign each port its address from the config (by interface name).
    /// Bind each port to its address and to the OSPF config of its
    /// interface (cost, timers, passive, BFD; RouterOS interface templates).
    pub(crate) fn bind_addresses(&mut self) {
        for p in &mut self.ports {
            p.net = self
                .cfg
                .addresses
                .iter()
                .find(|a| a.iface == p.iface)
                .map(|a| a.net);
            match &self.cfg.ospf_ifaces {
                None => {
                    p.cost = p.link_cost;
                    p.ospf = p.link_ospf;
                    p.bfd = p.link_bfd;
                    p.passive = false;
                    p.hello = None;
                    p.dead = None;
                }
                Some(list) => {
                    let o = list.iter().find(|o| o.iface == p.iface);
                    // A single-hop BGP neighbor with BFD on this link
                    // turns BFD on for the port (G3.6b).
                    let bgp_bfd = p.net.is_some_and(|net| {
                        self.cfg
                            .bgp
                            .iter()
                            .flat_map(|b| &b.neighbors)
                            .any(|n| n.bfd && !n.disabled && net.contains(&n.remote))
                    });
                    p.ospf = p.link_ospf && o.is_some();
                    p.cost = o
                        .and_then(|o| o.cost)
                        .unwrap_or(p.link_cost)
                        .clamp(1, 65535);
                    p.bfd = p.link_bfd || bgp_bfd || o.is_some_and(|o| o.bfd);
                    p.passive = o.is_some_and(|o| o.passive);
                    p.hello = o.and_then(|o| o.hello);
                    p.dead = o.and_then(|o| o.dead);
                }
            }
        }
    }

    /// The loopbacks OSPF advertises: all (no OSPF config) or those an
    /// interface template matches.
    pub(crate) fn ospf_loopbacks(&self) -> Vec<Ipv4Net> {
        self.cfg
            .addresses
            .iter()
            .filter(|a| !self.ports.iter().any(|p| p.iface == a.iface))
            .filter(|a| match &self.cfg.ospf_ifaces {
                None => true,
                Some(list) => list.iter().any(|o| o.iface == a.iface),
            })
            .map(|a| a.net)
            .collect()
    }

    /// Addresses on interfaces no link uses: loopbacks.
    pub(crate) fn loopbacks(&self) -> impl Iterator<Item = Ipv4Net> + '_ {
        self.cfg
            .addresses
            .iter()
            .filter(|a| !self.ports.iter().any(|p| p.iface == a.iface))
            .map(|a| a.net)
    }

    /// Start the protocols (power on, or a reconfiguration from scratch).
    pub(crate) fn boot(&mut self, now: Time) {
        self.up = true;
        self.q.clear();
        self.flood.clear();
        self.ospf = Ospf::default();
        for p in &mut self.ports {
            p.adj = AdjState::Down;
            p.nbr = None;
            p.bfd_up = true;
        }
        self.bind_addresses();
        self.bgp = self
            .cfg
            .bgp
            .as_ref()
            .map(|b| Bgp::new(b, self.cfg.router_id));
        self.ospf_start(now);
        self.bgp_start(now);
        self.refresh(now, true);
    }

    /// Power off: everything is forgotten, nothing is sent.
    pub(crate) fn halt(&mut self) {
        self.up = false;
        self.q.clear();
        self.flood.clear();
        self.ospf = Ospf::default();
        self.bgp = None;
        self.igp = Fib::default();
        self.fib = Fib::default();
        self.connected = Fib::default();
        for p in &mut self.ports {
            p.adj = AdjState::Down;
            p.nbr = None;
        }
    }

    /// Process every event before `end`.
    pub(crate) fn run(&mut self, end: Time) {
        while let Some((at, ev)) = self.q.pop_before(end) {
            self.events += 1;
            if self.up {
                self.handle(at, ev);
            }
            if !self.flood.is_empty() && self.q.next_at() != Some(at) {
                self.ospf_flush_floods(at);
            }
        }
    }

    fn handle(&mut self, now: Time, ev: Ev) {
        match ev {
            Ev::Link { link, msg } => match msg {
                LinkMsg::Hello { rid, seen } => self.ospf_hello(now, link, rid, seen),
                LinkMsg::Lsas(lsas) => self.ospf_lsas(now, link, lsas),
            },
            Ev::Bgp { from, to, msg } => self.bgp_receive(now, from, to, msg),
            Ev::HelloTimer(link, generation) => self.ospf_hello_timer(now, link, generation),
            Ev::DeadCheck(link) => self.ospf_dead_check(now, link),
            Ev::Spf => self.ospf_spf(now),
            Ev::Originate => self.ospf_deferred_originate(now),
            Ev::BgpConnect { peer, epoch } => self.bgp_connect(now, peer, epoch),
            Ev::BgpKeepalive { peer, epoch } => self.bgp_keepalive(now, peer, epoch),
            Ev::BgpHold { peer, epoch } => self.bgp_hold(now, peer, epoch),
            Ev::BgpFlush => self.bgp_flush(now),
            Ev::Carrier { link, up } => self.carrier(now, link, up),
            Ev::Bfd { link, up } => self.bfd(now, link, up),
        }
    }

    fn carrier(&mut self, now: Time, link: LinkId, up: bool) {
        let Some(p) = self.port_mut(link) else { return };
        if p.carrier == up {
            return;
        }
        p.carrier = up;
        if up {
            self.ospf_port_up(now, link);
        } else {
            self.ospf_adj_down(now, link, "interface down");
            self.bgp_link_down(now, link, "interface down");
        }
        self.refresh(now, true);
    }

    fn bfd(&mut self, now: Time, link: LinkId, up: bool) {
        let Some(p) = self.port_mut(link) else { return };
        if !p.bfd || p.bfd_up == up {
            return;
        }
        p.bfd_up = up;
        if up {
            self.note(now, RecordKind::BfdUp { link });
            self.ospf_port_up(now, link);
        } else {
            self.note(now, RecordKind::BfdDown { link });
            self.ospf_adj_down(now, link, "BFD down");
            self.bgp_link_down(now, link, "BFD down");
        }
    }

    /// Rebuild the forwarding tables after the IGP (`igp_changed`) or the
    /// BGP best paths changed. A changed IGP re-checks every BGP next hop.
    pub(crate) fn refresh(&mut self, now: Time, igp_changed: bool) {
        if igp_changed {
            let mut connected = Fib::default();
            for p in &self.ports {
                if let (Some(net), true) = (p.net, p.carrier) {
                    connected.offer(FibRoute {
                        prefix: net.trunc(),
                        proto: Proto::Connected,
                        metric: 0,
                        links: vec![p.link],
                        via: None,
                    });
                }
            }
            for net in self.loopbacks().collect::<Vec<_>>() {
                connected.offer(FibRoute {
                    prefix: net.trunc(),
                    proto: Proto::Connected,
                    metric: 0,
                    links: Vec::new(),
                    via: None,
                });
            }
            let mut igp = connected.clone();
            for (prefix, (metric, links)) in &self.ospf.routes {
                igp.offer(FibRoute {
                    prefix: *prefix,
                    proto: Proto::Ospf,
                    metric: *metric,
                    links: links.clone(),
                    via: None,
                });
            }
            self.connected = connected;
            self.igp = igp;
            if let Some(b) = &mut self.bgp {
                b.revalidate = true;
            }
            self.bgp_schedule(now);
        }
        let mut fib = self.igp.clone();
        if let Some(b) = &self.bgp {
            for r in b.installed(&self.igp) {
                fib.offer(r);
            }
        }
        self.fib = fib;
    }

    /// SPF changed the OSPF routes of `changed` only: patch the IGP and
    /// forwarding tables there (a full rebuild per SPF cost O(routes) each
    /// time, **medido** in `docs/netsim.md`), and let BGP re-check its next
    /// hops.
    pub(crate) fn refresh_ospf(&mut self, now: Time, changed: &[Ipv4Net]) {
        for p in changed {
            let ospf = self.ospf.routes.get(p).map(|(metric, links)| FibRoute {
                prefix: *p,
                proto: Proto::Ospf,
                metric: *metric,
                links: links.clone(),
                via: None,
            });
            let igp = match (self.connected.get(p).cloned(), ospf) {
                (Some(c), _) => Some(c),
                (None, o) => o,
            };
            self.igp.set(*p, igp);
        }
        if let Some(b) = &mut self.bgp {
            b.revalidate = true;
        }
        self.refresh_bgp(changed);
        self.bgp_schedule(now);
    }

    /// Install what BGP decided for `touched`, the IGP being unchanged.
    pub(crate) fn refresh_bgp(&mut self, touched: &[Ipv4Net]) {
        for p in touched {
            let igp = self.igp.get(p).cloned();
            let bgp = self
                .bgp
                .as_ref()
                .and_then(|b| b.installed_one(p, &self.igp));
            let best = match (igp, bgp) {
                (Some(i), Some(g)) => Some(
                    if (g.proto.distance(), g.metric) < (i.proto.distance(), i.metric) {
                        g
                    } else {
                        i
                    },
                ),
                (i, g) => i.or(g),
            };
            self.fib.set(*p, best);
        }
    }

    /// Whether `a` is one of this router's addresses.
    pub(crate) fn owns(&self, a: Ipv4Addr) -> bool {
        self.cfg.addresses.iter().any(|x| x.net.addr() == a)
    }
}
