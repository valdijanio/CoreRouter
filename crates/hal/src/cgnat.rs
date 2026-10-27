//! CGNAT port blocks in the data plane (G2.3c): what the engine's block
//! allocator tells the kernel, and how a subscriber without a block asks
//! for one.
//!
//! In blocks mode (RFC 6888 §5) a pool's map `d_<id>` holds only the
//! subscribers that have a block. The first packet of a subscriber without
//! one is held in a netfilter queue ([`QUEUE_NUM`]) until the daemon
//! allocates a block and puts it in the map ([`CgnatQueue`]); then it goes
//! on and the NAT finds the element. The lab has no queue: it names the
//! subscribers it pretends are online ([`Hal::cgnat_waiting`]).
//!
//! [`Hal::cgnat_waiting`]: crate::Hal::cgnat_waiting

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use corerouter_model::ItemId;
use corerouter_model::cgnat::Slot;

use crate::HalError;

/// The netfilter queue of first packets (RFC 7422, as a number to
/// remember). Each blocks-mode pool's rule sends there.
pub const QUEUE_NUM: u16 = corerouter_firewall::cgnat::QUEUE_NUM;

/// One subscriber's block in pool `pool`: set (`Some`) or removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockChange {
    pub pool: ItemId,
    pub subscriber: Ipv4Addr,
    pub slot: Option<Slot>,
}

/// A subscriber waiting for a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Waiting {
    pub pool: ItemId,
    pub subscriber: Ipv4Addr,
}

/// A packet held in the queue: its id (for the verdict) and its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pending {
    pub id: u32,
    pub subscriber: Ipv4Addr,
}

/// The queue of first packets, served by a thread of the daemon outside
/// the session lock.
pub trait CgnatQueue: Send {
    /// The next held packet, waiting at most `wait`.
    fn recv(&mut self, wait: Duration) -> Result<Option<Pending>, HalError>;

    /// Let packet `id` go on (`accept`) or drop it (no block left: RFC 6888
    /// REQ-11).
    fn verdict(&mut self, id: u32, accept: bool) -> Result<(), HalError>;

    /// Drop packet `id` because its subscriber has no ports left (RFC 6888
    /// REQ-11a) and, within the limits of [`Exhaustion`], tell it so with an
    /// ICMP host unreachable (REQ-11b). Whether the ICMP went out.
    fn refuse(&mut self, id: u32) -> Result<bool, HalError> {
        self.verdict(id, false).map(|()| false)
    }
}


// ---------------------------------------------------------------------------
// G2.7: the answer when a subscriber's ports run out (RFC 6888 REQ-11).
// ---------------------------------------------------------------------------

/// The first of the queues where new connections of nearly full
/// subscribers wait after the NAT chose their tuple (G2.7).
pub const EXHAUSTED_QUEUE: u16 = corerouter_firewall::cgnat::EXHAUSTED_QUEUE;
/// How many queues from [`EXHAUSTED_QUEUE`] (the kernel spreads them by
/// flow hash; the daemon serves each with a thread).
pub const EXHAUSTED_QUEUES: u16 = corerouter_firewall::cgnat::EXHAUSTED_QUEUES;
/// ICMP messages per second for the whole router at most, whatever the
/// subscribers: the kernel's own `icmp_msgs_per_sec` default.
pub const GLOBAL_ICMP_RATE: u32 = 1000;
/// Subscribers whose limiter and counters are kept at once (a storm of
/// spoofed sources cannot grow the memory beyond it).
pub const MAX_TRACKED: usize = 65_536;

/// A token bucket per subscriber plus one for the router (RFC 1812
/// §4.3.2.8: a router SHOULD limit the ICMP errors it sends). Pure: the
/// caller gives the time, in milliseconds of any monotonic clock.
#[derive(Debug, Clone)]
pub struct Limiter {
    /// Per second and subscriber (also the burst).
    rate: u32,
    /// Subscriber → (tokens in thousandths, last refill).
    buckets: HashMap<Ipv4Addr, (u32, u64)>,
    global: (u32, u64),
}

impl Limiter {
    pub fn new(rate: u32) -> Self {
        Self {
            rate,
            buckets: HashMap::new(),
            global: (GLOBAL_ICMP_RATE.saturating_mul(1000), 0),
        }
    }

    pub fn rate(&self) -> u32 {
        self.rate
    }

    pub fn set_rate(&mut self, rate: u32) {
        if rate != self.rate {
            self.rate = rate;
            self.buckets.clear();
        }
    }

    /// Subscribers with a bucket now.
    pub fn tracked(&self) -> usize {
        self.buckets.len()
    }

    fn refill(bucket: &mut (u32, u64), rate: u32, now_ms: u64) {
        let full = rate.saturating_mul(1000);
        let elapsed = now_ms.saturating_sub(bucket.1);
        // `rate` tokens per 1000 ms, in thousandths: `rate` per ms.
        let add = u32::try_from(elapsed.saturating_mul(u64::from(rate))).unwrap_or(u32::MAX);
        bucket.0 = bucket.0.saturating_add(add).min(full);
        bucket.1 = bucket.1.max(now_ms);
    }

    /// Whether one ICMP to `subscriber` may go now (and spend its token).
    pub fn allow(&mut self, subscriber: Ipv4Addr, now_ms: u64) -> bool {
        if self.rate == 0 {
            return false;
        }
        let full = self.rate.saturating_mul(1000);
        if !self.buckets.contains_key(&subscriber) && self.buckets.len() >= MAX_TRACKED {
            // Full buckets carry no state: forget them first. Still full
            // (a storm of distinct sources): refuse rather than grow.
            let rate = self.rate;
            self.buckets.retain(|_, b| {
                Self::refill(b, rate, now_ms);
                b.0 < full
            });
            if self.buckets.len() >= MAX_TRACKED {
                return false;
            }
        }
        let rate = self.rate;
        let b = self.buckets.entry(subscriber).or_insert((full, now_ms));
        Self::refill(b, rate, now_ms);
        Self::refill(&mut self.global, GLOBAL_ICMP_RATE, now_ms);
        if b.0 < 1000 || self.global.0 < 1000 {
            return false;
        }
        b.0 -= 1000;
        self.global.0 -= 1000;
        true
    }
}

/// What happened to one subscriber's new connections without a port.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Hit {
    /// Connections dropped for lack of a port (RFC 6888 REQ-11a).
    pub refused: u64,
    /// ICMP host unreachable sent about them (REQ-11b).
    pub icmp: u64,
}

/// Counters of the exhaustion queues since the last [`Exhaustion::take`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExhaustionStats {
    /// New connections of nearly full subscribers looked at.
    pub seen: u64,
    /// Of those, refused (no free tuple).
    pub refused: u64,
    /// ICMP sent.
    pub icmp: u64,
    /// ICMP held back by the limiter.
    pub limited: u64,
    /// Subscribers not counted because [`MAX_TRACKED`] were.
    pub untracked: u64,
}

#[derive(Debug)]
struct Inner {
    limiter: Limiter,
    on: bool,
    hits: HashMap<Ipv4Addr, Hit>,
    stats: ExhaustionStats,
}

/// Shared by the queue threads (which record) and the engine's tick (which
/// takes): one short lock per refused connection, never during I/O.
#[derive(Debug)]
pub struct Exhaustion(Mutex<Inner>);

impl Default for Exhaustion {
    fn default() -> Self {
        Self::new(true, u32::from(corerouter_model::cgnat::DEFAULT_ICMP_RATE))
    }
}

impl Exhaustion {
    pub fn new(on: bool, rate: u32) -> Self {
        Self(Mutex::new(Inner {
            limiter: Limiter::new(rate),
            on,
            hits: HashMap::new(),
            stats: ExhaustionStats::default(),
        }))
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The operator's settings (`ip.firewall.cgnat.set`).
    pub fn configure(&self, on: bool, rate: u32) {
        let mut i = self.inner();
        i.on = on;
        i.limiter.set_rate(rate);
    }

    /// A new connection was looked at and went on.
    pub fn passed(&self) {
        let mut i = self.inner();
        i.stats.seen = i.stats.seen.saturating_add(1);
    }

    /// `subscriber`'s new connection found no port: count it; whether an
    /// ICMP may be sent about it now.
    pub fn refused(&self, subscriber: Ipv4Addr, now_ms: u64) -> bool {
        let mut i = self.inner();
        i.stats.seen = i.stats.seen.saturating_add(1);
        i.stats.refused = i.stats.refused.saturating_add(1);
        let send = i.on && i.limiter.allow(subscriber, now_ms);
        if i.on && !send {
            i.stats.limited = i.stats.limited.saturating_add(1);
        }
        let tracked = i.hits.len();
        match i.hits.get_mut(&subscriber) {
            Some(h) => h.refused = h.refused.saturating_add(1),
            None if tracked < MAX_TRACKED => {
                i.hits.insert(subscriber, Hit { refused: 1, icmp: 0 });
            }
            None => i.stats.untracked = i.stats.untracked.saturating_add(1),
        }
        send
    }

    /// The ICMP about `subscriber` went out.
    pub fn sent(&self, subscriber: Ipv4Addr) {
        let mut i = self.inner();
        i.stats.icmp = i.stats.icmp.saturating_add(1);
        if let Some(h) = i.hits.get_mut(&subscriber) {
            h.icmp = h.icmp.saturating_add(1);
        }
    }

    /// What happened since the last call (the engine's tick).
    pub fn take(&self) -> (Vec<(Ipv4Addr, Hit)>, ExhaustionStats) {
        let mut i = self.inner();
        let hits = i.hits.drain().collect();
        (hits, std::mem::take(&mut i.stats))
    }
}

/// One of the exhaustion queues, served by a thread of the daemon outside
/// the session lock: each packet is a new connection of a nearly full
/// subscriber whose tuple the NAT already chose. If that tuple is taken
/// (the kernel would drop it at confirmation and only count
/// `insert_failed`), the packet is dropped here and the subscriber gets the
/// ICMP; otherwise it goes on untouched.
pub trait ExhaustionQueue: Send {
    /// Serve the packets that arrive within `wait`; how many.
    fn serve(&mut self, wait: Duration) -> Result<usize, HalError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const A: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);
    const B: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);

    #[test]
    fn the_limiter_allows_the_burst_then_the_rate() {
        let mut l = Limiter::new(2);
        assert!(l.allow(A, 0));
        assert!(l.allow(A, 0));
        assert!(!l.allow(A, 0), "burst of 2 spent");
        assert!(!l.allow(A, 400), "0.8 token");
        assert!(l.allow(A, 500), "one token after 500 ms at 2/s");
        assert!(l.allow(B, 500), "another subscriber has its own bucket");
        let mut off = Limiter::new(0);
        assert!(!off.allow(A, 0));
    }

    #[test]
    fn the_router_never_sends_more_than_the_global_rate() {
        let mut l = Limiter::new(5);
        let sent = (0..5000u32)
            .filter(|i| l.allow(Ipv4Addr::from(0x6440_0000 + i), 0))
            .count();
        assert_eq!(sent, GLOBAL_ICMP_RATE as usize);
    }

    #[test]
    fn exhaustion_counts_and_limits_per_subscriber() {
        let e = Exhaustion::new(true, 1);
        assert!(e.refused(A, 0));
        e.sent(A);
        assert!(!e.refused(A, 10));
        e.passed();
        let (hits, stats) = e.take();
        assert_eq!(hits, vec![(A, Hit { refused: 2, icmp: 1 })]);
        assert_eq!(
            stats,
            ExhaustionStats { seen: 3, refused: 2, icmp: 1, limited: 1, untracked: 0 }
        );
        assert_eq!(e.take().1, ExhaustionStats::default(), "taken once");
        e.configure(false, 1);
        assert!(!e.refused(A, 5000), "turned off: counted, no ICMP");
    }

    proptest! {
        /// Whatever the arrivals, a subscriber never gets more than
        /// `rate` per second plus the burst (RFC 6888 REQ-11b without
        /// becoming an amplifier).
        #[test]
        fn never_more_than_rate_plus_burst(
            rate in 1u32..20,
            times in proptest::collection::vec(0u64..10_000, 1..500),
        ) {
            let mut times = times;
            times.sort_unstable();
            let mut l = Limiter::new(rate);
            let sent = times.iter().filter(|t| l.allow(A, **t)).count() as u64;
            let span = times.last().copied().unwrap_or(0);
            prop_assert!(sent <= u64::from(rate) + span * u64::from(rate) / 1000 + 1);
        }

        #[test]
        fn memory_stays_bounded(n in 0usize..3000) {
            let mut l = Limiter::new(1);
            for i in 0..n {
                l.allow(Ipv4Addr::from(u32::try_from(i).unwrap_or(0)), 0);
            }
            prop_assert!(l.tracked() <= MAX_TRACKED);
        }
    }
}
