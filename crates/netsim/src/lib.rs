//! G3.7: the lab's network simulator. N virtual routers run simplified
//! OSPF, BGP and BFD over a topology of point-to-point links, on a virtual
//! clock, so an operator can cut a link, take a router down or change a
//! cost and watch the network converge, in the GUI, the browser (wasm) and
//! CI. Design and limits: `docs/netsim.md`.
//!
//! **Never a replacement for FRR in production.** The machines here keep
//! only what decides the outcome (who is adjacent, which LSAs exist, which
//! path is best, when a failure is detected) and leave out the wire format,
//! retransmission and most timers' corner cases.
//!
//! - **Discrete events, virtual clock.** Each router has its own queue of
//!   timestamped events (timers, received messages). Time is `u64`
//!   microseconds and only moves when [`Simulation::advance`] says so: the
//!   caller runs it at ×1, ×60, paused or one step at a time.
//! - **Deterministic.** Ties break by insertion order, every random choice
//!   (hello phase, loss) comes from a hash of the seed and the router, and
//!   no map is iterated in hash order: the same seed and the same commands
//!   give the same timeline on any machine and any number of threads.
//! - **Parallel by windows.** No message reaches another router sooner than
//!   the shortest link latency (the lookahead). The routers run their events
//!   inside a window of that length independently — in parallel on native
//!   targets — and a barrier at the end delivers what they sent, in router
//!   order (conservative parallel discrete-event simulation).

mod bgp;
mod fib;
mod node;
mod ospf;
#[cfg(not(target_arch = "wasm32"))]
mod pool;
pub mod preset;
mod queue;
mod sim;
#[cfg(test)]
mod tests;
mod timeline;

use std::net::Ipv4Addr;
use std::sync::Arc;

use corerouter_proto_bgp::filter::eval::Policy;
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

pub use bgp::{BgpPeerView, BgpRouteView};
pub use fib::{FibRoute, Proto};
pub use ospf::{Lsa, OspfNeighborView};
pub use sim::{LinkView, NodeView, Simulation, Stats};
pub use timeline::{Convergence, Record, RecordKind};

/// Virtual time, microseconds since the simulation started.
pub type Time = u64;
pub const MS: Time = 1_000;
pub const SEC: Time = 1_000_000;

/// Most routers and links one simulation holds (memory and the lock the
/// engine holds while it runs are bounded by these).
pub const MAX_NODES: usize = 2_000;
pub const MAX_LINKS: usize = 8_000;

/// A router, by its index in the simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub u32);

/// A link, by its index in the simulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LinkId(pub u32);

impl NodeId {
    pub(crate) fn ix(self) -> usize {
        self.0 as usize
    }
}

impl LinkId {
    pub(crate) fn ix(self) -> usize {
        self.0 as usize
    }
}

/// One end of a link: a router and its interface name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub node: NodeId,
    pub iface: String,
}

/// What a link does with the packets put on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinkState {
    Up,
    /// Silently drops everything (a failure past a switch or inside a
    /// carrier's network): both ports stay up, so only hellos, BFD or the
    /// BGP hold timer notice.
    Cut,
    /// Carrier lost: both ports go down at once and the routers react
    /// without waiting for a timer.
    Down,
}

/// A point-to-point link between two routers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub a: Endpoint,
    pub b: Endpoint,
    /// One-way delay.
    pub latency: Time,
    /// Percent (0..=100) of packets lost, chosen by hash (deterministic).
    pub loss_pct: u8,
    /// OSPF cost of each end's interface (RFC 2328 §12.4.1: the cost of
    /// the outgoing interface; the two ends may differ).
    pub cost_a: u32,
    pub cost_b: u32,
    /// OSPF runs on the link.
    pub ospf: bool,
    /// BFD (RFC 5880) watches the link for OSPF and single-hop BGP.
    pub bfd: bool,
    pub state: LinkState,
}

impl Link {
    pub fn new(a: Endpoint, b: Endpoint) -> Self {
        Link {
            a,
            b,
            latency: MS,
            loss_pct: 0,
            cost_a: 10,
            cost_b: 10,
            ospf: true,
            bfd: false,
            state: LinkState::Up,
        }
    }

    /// The end on `node`'s side, and the other one.
    pub(crate) fn ends(&self, node: NodeId) -> Option<(&Endpoint, &Endpoint, u32)> {
        if self.a.node == node {
            Some((&self.a, &self.b, self.cost_a))
        } else if self.b.node == node {
            Some((&self.b, &self.a, self.cost_b))
        } else {
            None
        }
    }
}

/// An interface address of a router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IfAddr {
    pub iface: String,
    pub net: Ipv4Net,
}

/// Protocol timers. The defaults are FRR's (`ospfd`, `bfdd`, `bgpd`
/// traditional profile), which the production routers run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Timers {
    /// RFC 2328 §C.3 HelloInterval (FRR: 10 s).
    pub ospf_hello: Time,
    /// RouterDeadInterval (FRR: 40 s).
    pub ospf_dead: Time,
    /// FRR `timers throttle spf 0 50 5000`: the hold between two SPF runs.
    pub spf_hold: Time,
    /// … and the longest the hold grows to under churn.
    pub spf_max_hold: Time,
    /// RFC 2328 §12.4 MinLSInterval: one LSA instance per router this often.
    pub min_ls_interval: Time,
    /// RFC 5880 §6.8.1 desired TX interval (FRR `bfdd`: 300 ms) …
    pub bfd_interval: Time,
    /// … and the detect multiplier (3): a failure is seen after
    /// interval × multiplier.
    pub bfd_multiplier: u32,
    /// How often an idle BGP neighbor tries to connect again. FRR's
    /// ConnectRetry is 120 s, but TCP retransmits the SYN at 1, 2, 4 s…;
    /// 5 s stands for both.
    pub bgp_connect_retry: Time,
    /// Time a router takes to process an UPDATE batch before it re-runs the
    /// decision and sends its own (FRR's work queue; MRAI is 0 in FRR).
    pub bgp_process: Time,
}

impl Default for Timers {
    fn default() -> Self {
        Timers {
            ospf_hello: 10 * SEC,
            ospf_dead: 40 * SEC,
            spf_hold: 50 * MS,
            spf_max_hold: 5 * SEC,
            min_ls_interval: 5 * SEC,
            bfd_interval: 300 * MS,
            bfd_multiplier: 3,
            bgp_connect_retry: 5 * SEC,
            bgp_process: 10 * MS,
        }
    }
}

impl Timers {
    pub fn bfd_detect(&self) -> Time {
        self.bfd_interval
            .saturating_mul(Time::from(self.bfd_multiplier))
    }
}

/// One BGP neighbor of a router (a `/routing bgp connection`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Neighbor {
    pub name: String,
    pub remote: Ipv4Addr,
    /// `None`: any AS (RouterOS `remote.as` unset).
    pub remote_as: Option<u32>,
    /// RouterOS `local.address`; `None`: the address of the interface
    /// toward the neighbor, or the first loopback.
    pub local: Option<Ipv4Addr>,
    pub hold: Time,
    pub keepalive: Time,
    /// `/routing filter` chains (by name; looked up in the router's policy).
    pub input: Option<String>,
    pub output: Option<String>,
    pub bfd: bool,
    /// RouterOS `nexthop-choice=force-self`: our address as next hop
    /// toward iBGP too (FRR `next-hop-self`).
    pub next_hop_self: bool,
    pub disabled: bool,
}

impl Neighbor {
    pub fn new(name: impl Into<String>, remote: Ipv4Addr, remote_as: Option<u32>) -> Self {
        Neighbor {
            name: name.into(),
            remote,
            remote_as,
            local: None,
            hold: 180 * SEC,
            keepalive: 60 * SEC,
            input: None,
            output: None,
            bfd: false,
            next_hop_self: false,
            disabled: false,
        }
    }
}

/// A router's BGP: its AS, the prefixes it originates, its neighbors and
/// its `/routing filter` (compiled by `proto-bgp`, the evaluator the
/// preview of G3.2b runs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpConfig {
    pub asn: u32,
    /// Originated unconditionally (FRR `network` without import-check).
    pub networks: Vec<Ipv4Net>,
    pub neighbors: Vec<Neighbor>,
    #[serde(skip)]
    pub policy: Arc<Policy>,
}

impl PartialEq for BgpConfig {
    fn eq(&self, o: &Self) -> bool {
        self.asn == o.asn
            && self.networks == o.networks
            && self.neighbors == o.neighbors
            && Arc::ptr_eq(&self.policy, &o.policy)
    }
}

/// What the simulator reads from a router's configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    pub router_id: Ipv4Addr,
    /// IPv4 interface addresses; loopbacks are those on an interface no
    /// link uses.
    pub addresses: Vec<IfAddr>,
    pub ospf: bool,
    pub bgp: Option<BgpConfig>,
    pub timers: Timers,
}

impl NodeConfig {
    pub fn new(name: impl Into<String>, router_id: Ipv4Addr) -> Self {
        NodeConfig {
            name: name.into(),
            router_id,
            addresses: Vec::new(),
            ospf: true,
            bgp: None,
            timers: Timers::default(),
        }
    }
}

/// A failure (or its repair) the operator injects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Fault {
    LinkCut {
        link: LinkId,
    },
    LinkDown {
        link: LinkId,
    },
    LinkRestore {
        link: LinkId,
    },
    NodeDown {
        node: NodeId,
    },
    NodeUp {
        node: NodeId,
    },
    /// One-way delay of a link, microseconds.
    Latency {
        link: LinkId,
        latency: Time,
    },
    Loss {
        link: LinkId,
        loss_pct: u8,
    },
}

/// SplitMix64: the simulator's only source of "randomness", seeded per
/// router so threads never share it.
pub(crate) fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}
