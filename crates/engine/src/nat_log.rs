//! CGNAT events for the flow exporter (G4.4j): port blocks allocated and
//! released, and the limits of RFC 8158 (pool out of blocks, a subscriber
//! refused, a subscriber above its alert percentage), as records the
//! daemon's `traffic-flow` exporter takes in batches.
//!
//! Before, the exporter re-read them from the router's log, whose recent
//! window holds 1024 lines: a burst of block allocations (every subscriber
//! coming back after a reboot) lost all but the last 1024 between two
//! ticks, and each read cloned and scanned the whole window. Here they wait
//! in a queue of their own:
//!
//! - **bounded** ([`QUEUE`] records, about 100 bytes each: 26 MB at most,
//!   **estimado**), the overflow dropped and counted;
//! - **only while someone takes them**: the exporter turns it on when it
//!   starts and off when it stops ([`Session::nat_log_want`]); without it
//!   (traffic flow off, the lab without a daemon) nothing is kept;
//! - pushing is O(1) under the session lock the CGNAT already holds to
//!   allocate; the exporter takes everything in one `drain` per tick.
//!
//! Limit events are rate-limited here (RFC 8158 §4.6.5 and §5.2: "SHOULD be
//! rate-limited"): one per pool or subscriber per [`LIMIT_SECS`].

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;

use corerouter_proto_flow::record::{quota, threshold};
use corerouter_proto_flow::{NatEventType, NatLimit, PortBlock, Record};

use crate::Session;

/// Records waiting for the exporter.
pub const QUEUE: usize = 262_144;
/// One limit event per pool or subscriber in this many seconds.
pub const LIMIT_SECS: u64 = 60;
/// Rate-limit entries kept; older ones are pruned past this.
const MAX_LIMITED: usize = 65_536;

#[derive(Debug, Default)]
pub struct NatLog {
    q: VecDeque<Record>,
    /// Pushed since the start, and dropped for a full queue.
    pub pushed: u64,
    pub dropped: u64,
    /// Limit events not sent because one went out less than
    /// [`LIMIT_SECS`] before.
    pub suppressed: u64,
    blocks: bool,
    limits: bool,
    /// (event code, pool id or subscriber) → last sent.
    limited: HashMap<(u8, u32), u64>,
}

impl NatLog {
    fn push(&mut self, r: Record) {
        self.pushed = self.pushed.saturating_add(1);
        if self.q.len() >= QUEUE {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        self.q.push_back(r);
    }

    /// Whether a limit event about `key` may go out at `now` (and note it).
    fn allow(&mut self, code: u8, key: u32, now: u64) -> bool {
        if self.limited.len() >= MAX_LIMITED {
            self.limited.retain(|_, t| now.saturating_sub(*t) < LIMIT_SECS);
        }
        match self.limited.get(&(code, key)) {
            Some(t) if now.saturating_sub(*t) < LIMIT_SECS => {
                self.suppressed = self.suppressed.saturating_add(1);
                false
            }
            _ => {
                self.limited.insert((code, key), now);
                true
            }
        }
    }

    pub fn len(&self) -> usize {
        self.q.len()
    }

    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }
}

/// A limit event of a subscriber or a pool, for [`Session::nat_limit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// The pool has no block (or address) left: `natEvent` 3.
    PoolExhausted { pool: u32 },
    /// `subscriber` was refused: it has every port it may have (`ports`):
    /// `natEvent` 13, `natQuotaExceededEvent` 3.
    PerUser { subscriber: Ipv4Addr, pool: u32, ports: u32 },
    /// `subscriber` uses more than `percent` of its ports: `natEvent` 18,
    /// `natThresholdEvent` 4.
    Threshold { subscriber: Ipv4Addr, pool: u32, percent: u32 },
}

impl Session {
    /// The exporter takes CGNAT block (`blocks`) and limit (`limits`)
    /// events from now on (both off: it stopped, the queue is emptied).
    pub fn nat_log_want(&mut self, blocks: bool, limits: bool) {
        if let Some(l) = self.ext_mut::<NatLog>() {
            l.blocks = blocks;
            l.limits = limits;
            if !blocks && !limits {
                l.q.clear();
            }
        }
    }

    /// Move up to `max` waiting records into `out`.
    pub fn nat_log_take(&mut self, max: usize, out: &mut Vec<Record>) {
        if let Some(l) = self.ext_mut::<NatLog>() {
            let n = l.q.len().min(max);
            out.extend(l.q.drain(..n));
        }
    }

    pub fn nat_log(&self) -> Option<&NatLog> {
        self.ext::<NatLog>()
    }

    /// A block given to or taken from a subscriber (`now` in seconds).
    pub(crate) fn nat_log_block(&mut self, mut b: PortBlock, now: u64) {
        let Some(l) = self.ext_mut::<NatLog>() else { return };
        if !l.blocks {
            return;
        }
        b.time_ms = now.saturating_mul(1000);
        l.push(Record::PortBlock(b));
    }

    /// A limit hit (`now` in seconds), at most one per pool or subscriber
    /// per [`LIMIT_SECS`].
    pub(crate) fn nat_limit(&mut self, limit: Limit, now: u64) {
        let Some(l) = self.ext_mut::<NatLog>() else { return };
        if !l.limits {
            return;
        }
        let rec = match limit {
            Limit::PoolExhausted { pool } => NatLimit {
                time_ms: 0,
                event: NatEventType::AddressesExhausted,
                kind: 0,
                src: Ipv4Addr::UNSPECIFIED,
                pool,
                limit: 0,
            },
            Limit::PerUser { subscriber, pool, ports } => NatLimit {
                time_ms: 0,
                event: NatEventType::QuotaExceeded,
                kind: quota::MAX_ENTRIES_PER_USER,
                src: subscriber,
                pool,
                limit: ports,
            },
            Limit::Threshold { subscriber, pool, percent } => NatLimit {
                time_ms: 0,
                event: NatEventType::ThresholdReached,
                kind: threshold::ADDRESS_PORT_PER_USER_HIGH,
                src: subscriber,
                pool,
                limit: percent,
            },
        };
        let key = if rec.src.is_unspecified() { rec.pool } else { u32::from(rec.src) };
        if !l.allow(rec.event.code(), key, now) {
            return;
        }
        l.push(Record::NatLimit(NatLimit {
            time_ms: now.saturating_mul(1000),
            ..rec
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_hal::VirtualHal;

    fn block(sub: u8) -> PortBlock {
        PortBlock {
            time_ms: 0,
            event: NatEventType::PortBlockAllocation,
            src: Ipv4Addr::new(100, 64, 0, sub),
            post_src: Ipv4Addr::new(203, 0, 113, 1),
            port_start: 1024,
            port_end: 2047,
            step: 1,
            ports: 1024,
            user: String::new(),
            vlan: 0,
            pool: 1,
        }
    }

    #[test]
    fn nothing_is_kept_unless_the_exporter_wants_it() {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        let now = s.hal_now().unwrap_or(0);
        s.nat_log_block(block(1), now);
        s.nat_limit(Limit::PoolExhausted { pool: 1 }, now);
        assert!(s.nat_log().is_none_or(NatLog::is_empty));
        s.nat_log_want(true, false);
        s.nat_log_block(block(1), now);
        s.nat_limit(Limit::PoolExhausted { pool: 1 }, now);
        let mut out = Vec::new();
        s.nat_log_take(10, &mut out);
        assert_eq!(out.len(), 1, "blocks only");
        let Record::PortBlock(b) = &out[0] else { panic!() };
        assert_eq!(b.time_ms, now * 1000);
        // The exporter stopped: nothing more is kept, what waited is gone.
        s.nat_log_block(block(2), now);
        s.nat_log_want(false, false);
        s.nat_log_block(block(3), now);
        assert!(s.nat_log().is_some_and(NatLog::is_empty));
    }

    /// RFC 8158 §5.2: exhaustion events are rate-limited by the NAT device.
    #[test]
    fn limits_are_rate_limited_per_pool_and_subscriber() {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        s.nat_log_want(false, true);
        let now = s.hal_now().unwrap_or(0);
        let sub = Ipv4Addr::new(100, 64, 0, 9);
        for i in 0..100 {
            s.nat_limit(Limit::PoolExhausted { pool: 1 }, now + i % 5);
            s.nat_limit(Limit::PerUser { subscriber: sub, pool: 1, ports: 1024 }, now);
        }
        s.nat_limit(Limit::PoolExhausted { pool: 2 }, now);
        s.nat_limit(Limit::Threshold { subscriber: sub, pool: 1, percent: 80 }, now);
        let mut out = Vec::new();
        s.nat_log_take(100, &mut out);
        let codes: Vec<u8> = out
            .iter()
            .map(|r| match r {
                Record::NatLimit(l) => l.event.code(),
                _ => 0,
            })
            .collect();
        assert_eq!(codes, [3, 13, 3, 18]);
        assert_eq!(s.nat_log().map(|l| l.suppressed), Some(198));
        let Record::NatLimit(q) = &out[1] else { panic!() };
        assert_eq!((q.kind, q.limit, q.src), (quota::MAX_ENTRIES_PER_USER, 1024, sub));
    }

    #[test]
    fn a_full_queue_drops_and_counts() {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        s.nat_log_want(true, true);
        let now = s.hal_now().unwrap_or(0);
        for _ in 0..QUEUE + 5 {
            s.nat_log_block(block(1), now);
        }
        let l = s.nat_log().unwrap();
        assert_eq!((l.len(), l.dropped, l.pushed), (QUEUE, 5, QUEUE as u64 + 5));
    }
}
