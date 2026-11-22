//! The CGNAT fast path's link (G2.5b): what the daemon's `xdp-nat` service
//! uses to keep the XDP flow map in step with conntrack — the event feed
//! (new, updated, destroyed connections), the table, the map, and the
//! timeout renewal of connections whose packets XDP carried (conntrack
//! never sees those).

use corerouter_hal::HalError;
use corerouter_hal::conntrack::{Conn, Event, EventSource};
use corerouter_hal::xdp_nat::{FlowUse, NatFlow, NatLink};

use crate::xdp::{SharedNat, lock_nat};

/// The kernel's default timeouts, read once: what a renewal sets.
#[derive(Debug, Clone, Copy)]
struct Timeouts {
    tcp_established: u32,
    udp_stream: u32,
}

impl Timeouts {
    fn read() -> Self {
        let get = |name: &str, default: u32| {
            std::fs::read_to_string(format!("/proc/sys/net/netfilter/{name}"))
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(default)
        };
        Self {
            tcp_established: get("nf_conntrack_tcp_timeout_established", 432_000),
            udp_stream: get("nf_conntrack_udp_timeout_stream", 120),
        }
    }

    fn of(&self, c: &Conn) -> u32 {
        if c.protocol == 6 {
            self.tcp_established
        } else {
            self.udp_stream
        }
    }
}

pub(crate) struct LinuxNatLink {
    slot: SharedNat,
    events: crate::ctnl::Events,
    timeouts: Timeouts,
}

impl LinuxNatLink {
    pub(crate) fn open(slot: SharedNat) -> Result<Self, HalError> {
        Ok(Self {
            slot,
            events: crate::ctnl::Events::open_groups(true)?,
            timeouts: Timeouts::read(),
        })
    }
}

impl NatLink for LinuxNatLink {
    fn generation(&self) -> Option<u64> {
        let slot = lock_nat(&self.slot);
        slot.map.as_ref().map(|_| slot.generation)
    }

    fn events(&mut self, wait_ms: u32, max: usize, out: &mut Vec<Event>) -> Result<(), HalError> {
        self.events.recv(wait_ms, max, out)
    }

    fn lost(&self) -> u64 {
        self.events.lost()
    }

    fn table(&mut self) -> Result<Vec<Conn>, HalError> {
        crate::ctnl::dump()
    }

    fn install(&mut self, flows: &[NatFlow]) -> Result<(), HalError> {
        lock_nat(&self.slot).install(flows)
    }

    fn remove(&mut self, flows: &[NatFlow]) -> Result<(), HalError> {
        lock_nat(&self.slot).remove(flows)
    }

    fn used(&self, flow: &NatFlow) -> Option<FlowUse> {
        lock_nat(&self.slot).used(flow)
    }

    fn refresh(&mut self, conns: &[Conn]) -> Result<usize, HalError> {
        let t = self.timeouts;
        crate::ctnl::renew(conns, &|c| t.of(c))
    }
}
