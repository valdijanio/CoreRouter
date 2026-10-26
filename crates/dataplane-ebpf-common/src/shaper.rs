// SPDX-License-Identifier: GPL-2.0-or-later
//! The downstream shaper (G4.9b): Earliest Departure Time. Instead of a
//! queue per subscriber with a lock around it (HTB), each packet gets the
//! time it may leave (`skb->tstamp`), and the `fq` qdisc of the egress port
//! holds it until then (Linux EDT, netdev 0x12; Cilium's bandwidth
//! manager; Carousel, SIGCOMM 2017).
//!
//! Per target the state is a departure clock `t_next` in one word, moved by
//! compare-and-swap ([`crate::words`]): every CPU may send to the same
//! subscriber and the rate stays exact (G4.3cc). A packet leaves at
//! `max(t_next, now − slack)` and moves the clock by its size at the rate in
//! force; `slack` is the bucket (`bucket-size × rate`): an idle target may
//! send that much at once. The RouterOS burst (burst-limit while the
//! average over `burst-time` is under `burst-threshold`) picks the rate and
//! bucket exactly as the policer does ([`crate::policer`]).
//!
//! What waits too long is dropped *before* it is queued, from the delay it
//! would see (known exactly at enqueue, which an AQM at dequeue has to
//! measure):
//!
//! - `fifo` (`pfifo`/`bfifo`): tail drop past the queue's limit, converted
//!   to time at the rate (`limit_ns`);
//! - `codel` (`fq-codel`, `cake`): RFC 8289's control law on that delay
//!   (target, interval, drops spaced by `interval / sqrt(count)`), with ECN
//!   marking instead of dropping when the packet is ECN-capable (RFC 3168)
//!   and the type allows it; `limit_ns` still caps the queue.
//!
//! What EDT does not do: interleave the flows *inside* one target (they
//! leave in arrival order; CoDel keeps that queue short, ~target). The
//! measured comparison with HTB + fq_codel per target is in
//! `docs/queues.md`.

use crate::policer::{self, NANOS, Rate, TICK_SHIFT, cost_ns, cost_ticks, depth_ticks, ticks};
use crate::words::{CAS_TRIES, Words, isqrt};

/// Queue kinds of the shaper.
pub const KIND_FIFO: u64 = 0;
pub const KIND_CODEL: u64 = 1;

/// The queue of one direction: what to do with the packets that wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Queue {
    pub kind: u64,
    /// Mark instead of dropping (CoDel only). The caller clears it for a
    /// packet that is not ECN-capable: a `Mark` it then dropped would
    /// already have moved the clock.
    pub ecn: bool,
    /// Longest wait, ns: past it the packet is dropped (0 = no limit
    /// besides [`MAX_WAIT_NS`]).
    pub limit_ns: u64,
    /// CoDel target and interval, ns.
    pub target_ns: u64,
    pub interval_ns: u64,
}

pub const QUEUE_WORDS: usize = 4;

/// Longest wait any queue allows: `fq`'s default horizon is 10 s; past a
/// second a packet is useless to TCP anyway.
pub const MAX_WAIT_NS: u64 = NANOS;

impl Queue {
    /// RouterOS fq-codel defaults (target 5 ms, interval 100 ms, ECN on,
    /// limit 10 240 packets) at `rate` bytes per second.
    pub fn codel(rate: u64) -> Queue {
        Queue {
            kind: KIND_CODEL,
            ecn: true,
            limit_ns: fifo_limit_ns(10_240 * 1514, rate),
            target_ns: 5_000_000,
            interval_ns: 100_000_000,
        }
    }

    pub fn to_words(&self) -> [u64; QUEUE_WORDS] {
        [
            self.kind | u64::from(self.ecn) << 8,
            self.limit_ns,
            self.target_ns,
            self.interval_ns,
        ]
    }

    pub fn from_words([k, limit_ns, target_ns, interval_ns]: [u64; QUEUE_WORDS]) -> Queue {
        Queue {
            kind: k & 0xff,
            ecn: k >> 8 & 1 != 0,
            limit_ns,
            target_ns,
            interval_ns,
        }
    }
}

/// A queue of `bytes` at `rate` bytes per second, as a wait in ns (at
/// least two full frames, at most [`MAX_WAIT_NS`]).
pub fn fifo_limit_ns(bytes: u64, rate: u64) -> u64 {
    let rate = rate.clamp(1, policer::MAX_RATE);
    let ns = (u128::from(bytes.max(2 * 1514)) * u128::from(NANOS) / u128::from(rate))
        .min(u128::from(MAX_WAIT_NS));
    u64::try_from(ns).unwrap_or(MAX_WAIT_NS)
}

/// Where the CoDel words are in a state value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// First of three words: first-above time, next drop, count|dropping.
    pub codel: usize,
    /// The state has the burst window of [`crate::policer`] (words 1..19).
    pub window: bool,
}

/// A target's state: `[t_next, window start, 0, 16 slots, codel ×3]`.
pub const STATE_WORDS: usize = policer::STATE_WORDS + 3;
pub type State = [u64; STATE_WORDS];
pub const FULL: Layout = Layout {
    codel: policer::STATE_WORDS,
    window: true,
};

/// A PCQ sub-stream's state: `[t_next, codel ×3]`, no burst window.
pub const SUB_WORDS: usize = 4;
pub type SubState = [u64; SUB_WORDS];
pub const SUB: Layout = Layout {
    codel: 1,
    window: false,
};

const T_NEXT: usize = 0;
const DROPPING: u64 = 1 << 63;

/// What to do with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Send at this monotonic time (0: now, nothing to hold).
    Send(u64),
    /// Send at this time with the ECN CE mark (or drop it if it is not
    /// ECN-capable).
    Mark(u64),
    Drop,
    /// Four other CPUs moved the clock in the same instant: dropped (as
    /// `Drop`), counted apart so contention shows.
    Busy,
}

impl Verdict {
    pub fn time(&self) -> Option<u64> {
        match *self {
            Self::Send(t) | Self::Mark(t) => Some(t),
            Self::Drop | Self::Busy => None,
        }
    }
}

/// RFC 8289 §5 on the delay a packet entering now will see: `true` =
/// drop (or mark) it. Several CPUs may decide for one target at once (RSS,
/// RPS): each drop is claimed with a compare-and-swap (of the next drop
/// time, or of the switch into dropping), so one scheduled drop is one
/// drop, not one per CPU (four CPUs dropped four times the rate and left
/// the queue empty: 43% of the rate delivered, **medido**).
#[inline(always)]
fn codel<W: Words + ?Sized>(
    st: &mut W,
    at: usize,
    q: &Queue,
    now: u64,
    sojourn: u64,
    mtu_ns: u64,
) -> bool {
    let (first, next, count) = (at, at + 1, at + 2);
    let interval = q.interval_ns.max(1);
    // Under target, or less than one packet queued (the RFC's "backlog <=
    // MTU" for slow links): fine.
    let ok_to_drop = if sojourn < q.target_ns || sojourn <= mtu_ns {
        if st.get(first) != 0 {
            st.set(first, 0);
        }
        false
    } else {
        let f = st.get(first);
        if f == 0 {
            st.cas(first, 0, now.saturating_add(interval));
            false
        } else {
            now >= f
        }
    };
    let c = st.get(count);
    let n = c & 0xffff_ffff;
    if c & DROPPING != 0 {
        if !ok_to_drop {
            st.cas(count, c, n);
            return false;
        }
        let nx = st.get(next);
        if now < nx {
            return false;
        }
        let n = (n + 1).min(0xffff_ffff);
        // The CPU that moves the schedule drops; the others pass.
        if !st.cas(
            next,
            nx,
            nx.saturating_add(interval.checked_div(isqrt(n)).unwrap_or(interval)),
        ) {
            return false;
        }
        st.add(count, 1);
        return true;
    }
    if !ok_to_drop {
        return false;
    }
    // Back into dropping soon after leaving it: resume near the old rate
    // (RFC 8289 §5.4).
    let last = st.get(next);
    let n = if n > 2 && now.saturating_sub(last) < 16 * interval {
        n - 2
    } else {
        1
    };
    if !st.cas(count, c, DROPPING | n) {
        return false;
    }
    st.set(
        next,
        now.saturating_add(interval.checked_div(isqrt(n)).unwrap_or(interval)),
    );
    true
}

/// The departure of a packet of `bytes` at `now` (monotonic ns) to a target
/// with rate `r` and queue `q`, not before `not_before` (a PCQ sub-stream's
/// own time; 0 = none). A sent or marked packet moves the clock; a dropped
/// one changes only CoDel's state.
#[inline(always)]
pub fn depart<W: Words + ?Sized>(
    st: &mut W,
    layout: Layout,
    r: &Rate,
    q: &Queue,
    now: u64,
    bytes: u64,
    not_before: u64,
) -> Verdict {
    if r.rate == 0 {
        return Verdict::Send(if not_before > now { not_before } else { 0 });
    }
    let bursts = layout.window && r.bursts();
    if bursts {
        policer::advance(st, r.slot_ns, now);
    }
    let (rate, depth) = if layout.window {
        policer::in_force(st, r)
    } else {
        (r.rate, r.depth)
    };
    let rate = rate.clamp(1, policer::MAX_RATE);
    // The clock is in ticks (1/64 ns); times in and out are ns.
    let cost = cost_ticks(bytes, rate);
    let now_t = ticks(now);
    let floor = now_t.saturating_sub(depth_ticks(depth, rate));
    let limit = if q.limit_ns == 0 || q.limit_ns > MAX_WAIT_NS {
        MAX_WAIT_NS
    } else {
        q.limit_ns
    };
    let not_before = ticks(not_before);
    let lower = if not_before > floor {
        not_before
    } else {
        floor
    };
    let old = st.get(T_NEXT);
    let start = if old > lower { old } else { lower };
    let wait = start.saturating_sub(now_t) >> TICK_SHIFT;
    if wait > limit {
        return Verdict::Drop;
    }
    let mut mark = false;
    if q.kind == KIND_CODEL && codel(st, layout.codel, q, now, wait, cost_ns(1514, rate)) {
        if !q.ecn {
            return Verdict::Drop;
        }
        mark = true;
    }
    let mut old = old;
    let mut i = 0;
    while i < CAS_TRIES {
        let start = if old > lower { old } else { lower };
        if st.cas(T_NEXT, old, start.saturating_add(cost)) {
            if bursts {
                policer::record(st, r.slot_ns, now, bytes);
            }
            let t = if start > now_t {
                start >> TICK_SHIFT
            } else {
                0
            };
            return if mark {
                Verdict::Mark(t)
            } else {
                Verdict::Send(t)
            };
        }
        old = st.get(T_NEXT);
        i += 1;
    }
    // Lost every race (four other CPUs moved this clock in the same
    // instant): drop rather than spin or send outside the clock, so the
    // rate stays exact.
    Verdict::Busy
}

/// How long a packet entering now would wait (the "Queue" column), ns.
pub fn backlog_ns<W: Words + ?Sized>(st: &W, now: u64) -> u64 {
    (st.get(T_NEXT) >> TICK_SHIFT).saturating_sub(now)
}

/// A fresh state at `now`: an empty queue and an empty window.
pub fn fresh(r: &Rate, now: u64) -> State {
    let p = policer::fresh(r, now);
    let mut st = [0u64; STATE_WORDS];
    for (d, s) in st.iter_mut().zip(p) {
        *d = s;
    }
    st
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Offer `bytes`-sized packets every `step` ns for `secs`; the bytes
    /// that left in each second (by departure time) and the drops.
    fn run(r: &Rate, q: &Queue, secs: u64, step: u64, bytes: u64) -> (Vec<u64>, u64, u64) {
        let mut st = fresh(r, 0);
        let mut out = std::vec![0u64; secs as usize + 2];
        let (mut drops, mut max_wait) = (0, 0);
        let mut t = 1;
        while t < secs * NANOS {
            match depart(&mut st, FULL, r, q, t, bytes, 0) {
                Verdict::Drop | Verdict::Busy => drops += 1,
                v => {
                    let at = v.time().filter(|x| *x > 0).unwrap_or(t);
                    max_wait = max_wait.max(at - t);
                    if let Some(s) = out.get_mut((at / NANOS) as usize) {
                        *s += bytes;
                    }
                }
            }
            t += step;
        }
        out.truncate(secs as usize);
        (out, drops, max_wait)
    }

    #[test]
    fn holds_the_rate_and_queues_instead_of_dropping() {
        // 10 Mbit/s, offered 20 Mbit/s: half leaves on time, half waits
        // until the FIFO limit (50 packets ≈ 60 ms) and is dropped.
        let r = Rate::mikrotik(10_000_000, 0, 0, 0);
        let q = Queue {
            kind: KIND_FIFO,
            limit_ns: fifo_limit_ns(50 * 1500, r.rate),
            ..Queue::default()
        };
        let (s, drops, wait) = run(&r, &q, 5, 600_000, 1500);
        for b in &s[1..] {
            assert!(b.abs_diff(1_250_000) <= 3_000, "{s:?}");
        }
        assert!(drops > 0);
        assert!(wait <= q.limit_ns, "{wait}");
        // At the rate exactly: nothing waits past the bucket.
        let (s, drops, _) = run(&r, &q, 3, 1_200_000, 1500);
        assert_eq!(drops, 0);
        assert!(s[1].abs_diff(1_250_000) <= 3_000, "{s:?}");
    }

    #[test]
    fn codel_drops_early_and_the_rate_holds() {
        let r = Rate::mikrotik(10_000_000, 0, 0, 0);
        let codel = Queue {
            ecn: false,
            ..Queue::codel(r.rate)
        };
        // 10% over the rate for 10 s (a mildly unresponsive sender): the
        // departures hold the rate; CoDel starts dropping once the wait
        // stays over 5 ms for 100 ms, long before the queue's limit.
        let (s, drops, wait) = run(&r, &codel, 10, 1_090_000, 1500);
        for b in &s[1..] {
            assert!(b.abs_diff(1_250_000) <= 4_500, "{s:?}");
        }
        assert!(drops > 0);
        assert!(wait < codel.limit_ns, "{wait}");
        // The same load on a FIFO of the same limit: the wait grows to
        // its 1 s cap (bufferbloat) before the first drop.
        let fifo = Queue {
            kind: KIND_FIFO,
            limit_ns: codel.limit_ns,
            ..Queue::default()
        };
        let (_, _, fifo_wait) = run(&r, &fifo, 10, 1_090_000, 1500);
        assert!(fifo_wait > 5 * wait, "fifo {fifo_wait} codel {wait}");
    }

    /// Small packets at a slow rate (128 B at 200 kbit/s: one packet is a
    /// CoDel target long) 1.5× over: CoDel must still deliver the rate.
    #[test]
    fn codel_at_a_slow_rate_holds_it() {
        let r = Rate::mikrotik(200_000, 0, 0, 0);
        let q = Queue {
            ecn: false,
            ..Queue::codel(r.rate)
        };
        let (s, drops, wait) = run(&r, &q, 20, 3_413_333, 128);
        let tail: u64 = s[5..].iter().sum::<u64>() / 15;
        assert!(
            tail.abs_diff(25_000) <= 500,
            "{tail} {s:?} drops {drops} wait {wait}"
        );
    }

    #[test]
    fn ecn_marks_instead() {
        let r = Rate::mikrotik(1_000_000, 0, 0, 0);
        let q = Queue::codel(r.rate);
        let mut st = fresh(&r, 0);
        let (mut marks, mut drops) = (0, 0);
        let mut t = 1;
        while t < 5 * NANOS {
            match depart(&mut st, FULL, &r, &q, t, 1500, 0) {
                Verdict::Mark(_) => marks += 1,
                Verdict::Drop | Verdict::Busy => drops += 1,
                Verdict::Send(_) => {}
            }
            t += 6_000_000;
        }
        assert!(marks > 0);
        // Marking does not slow the queue down: past the limit it drops.
        assert!(drops > 0);
    }

    /// RouterOS burst through the shaper: the same switch as the policer.
    #[test]
    fn routeros_burst_example() {
        let r = Rate::mikrotik(1_000_000, 2_000_000, 1_500_000, 8 * NANOS);
        let q = Queue {
            kind: KIND_FIFO,
            limit_ns: 50_000_000,
            ..Queue::default()
        };
        let (s, _, _) = run(&r, &q, 40, 50_000, 1500);
        for (i, b) in s.iter().enumerate().take(9) {
            let want = match i {
                // The first bucket (0.1 s of 2M) counts in the window too: the
                // switch comes at ~5.9 s instead of 6.
                1..=4 => 250_000,
                7..=8 => 125_000,
                _ => continue,
            };
            assert!(b.abs_diff(want) <= 6_000, "second {i}: {b} {s:?}");
        }
    }

    #[test]
    fn not_before_and_sub_streams() {
        let r = Rate::mikrotik(8_000_000, 0, 0, 0);
        let q = Queue::default();
        let mut sub: SubState = [0; SUB_WORDS];
        let v = depart(&mut sub, SUB, &r, &q, 1000, 1000, 0);
        assert_eq!(v, Verdict::Send(0));
        let v = depart(&mut sub, SUB, &r, &q, 1000, 1000, 5_000_000);
        assert_eq!(v, Verdict::Send(5_000_000));
        // No rate: only `not_before` holds it.
        assert_eq!(
            depart(&mut sub, SUB, &Rate::default(), &q, 10, 1, 99),
            Verdict::Send(99)
        );
        assert_eq!(
            Queue::from_words(Queue::codel(1).to_words()),
            Queue::codel(1)
        );
    }
}
