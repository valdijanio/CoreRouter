// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-subscriber policer of the PPPoE data plane (G4.3c), with RouterOS
//! burst semantics (`rate-limit=rx/tx rx-burst/tx-burst
//! threshold/threshold time/time`, `/ppp profile` and the
//! `Mikrotik-Rate-Limit` RADIUS attribute).
//!
//! - A token bucket in bytes refills at `rate` (bytes per second) up to
//!   `depth` bytes; a packet passes if the bucket holds its size.
//! - **Burst:** the average rate over the last `burst-time` is kept in 16
//!   slots of `burst-time / 16` (RouterOS samples the average the same
//!   way). While that average is under `burst-threshold`, the bucket refills
//!   at `burst-rate` instead (up to `burst_depth`); once it reaches the
//!   threshold, back to `rate`. So a subscriber idle for a while gets
//!   `burst-rate` for about `burst-time × threshold / burst-rate`, then
//!   `rate` (RouterOS: 1M rate, 2M burst, 1.5M threshold, 8 s → 6 s of 2M).
//!
//! Integer arithmetic the verifier takes, division only by a checked
//! non-zero value. The bucket is a GCRA clock in one word, moved by
//! compare-and-swap ([`crate::words`]): exact with every CPU on the same
//! subscriber (G4.3cc). The burst window's slots are added to atomically;
//! only the instant a slot is cleared can lose a few bytes of the average.
//!
//! The bucket is `bucket-size × rate` (RouterOS v7, default 0.1 = 100 ms),
//! the "burst ≈ RTT × rate" that keeps a policer from starving TCP.

use crate::words::{CAS_TRIES, Words};

pub const NANOS: u64 = 1_000_000_000;
/// Window slots of the burst average.
pub const SLOTS: usize = 16;
/// Highest rate (bytes per second, 800 Gbit/s): `elapsed × rate` stays
/// under `u64::MAX` for any elapsed time under the fill time.
pub const MAX_RATE: u64 = 100_000_000_000;
/// Deepest bucket (bytes): `depth × NANOS` fits in a `u64`.
pub const MAX_DEPTH: u64 = u64::MAX / NANOS;
/// Smallest bucket the defaults give: two full-size frames.
pub const MIN_DEPTH: u64 = 3_200;

/// `[tat_ns, window_start_ns, 0, 16 slot sums]` (bytes per slot of
/// `burst-time / 16`).
pub const STATE_WORDS: usize = 3 + SLOTS;
pub type State = [u64; STATE_WORDS];

/// One direction's limit, as the session map stores it
/// ([`Rate::to_words`]). All in bytes and nanoseconds: the daemon converts
/// RouterOS bits per second once ([`Rate::mikrotik`]).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rate {
    /// Bytes per second; 0 = no limit.
    pub rate: u64,
    /// Bucket depth at `rate`, bytes.
    pub depth: u64,
    /// Bytes per second while bursting; at or under `rate` = no burst.
    pub burst_rate: u64,
    /// Bucket depth while bursting, bytes.
    pub burst_depth: u64,
    /// Bytes over the whole burst-time window under which bursting is
    /// allowed (`burst-threshold × burst-time`).
    pub burst_window_bytes: u64,
    /// `burst-time / 16`, nanoseconds.
    pub slot_ns: u64,
}

pub const RATE_WORDS: usize = 6;

/// RouterOS `bucket-size` default: 0.1 of the rate (100 ms), the "burst
/// ≈ RTT × rate" a policer needs not to starve TCP (Google 2016).
pub const DEFAULT_BUCKET_MILLI: u64 = 100;

/// Bucket depth for `rate` bytes per second: `bucket_milli` thousandths of
/// a second of traffic, at least [`MIN_DEPTH`].
pub fn depth_for(rate: u64, bucket_milli: u64) -> u64 {
    (rate / 1000)
        .saturating_mul(bucket_milli)
        .clamp(MIN_DEPTH, MAX_DEPTH)
}

/// Bucket depth for `rate` with the default bucket (100 ms).
pub fn default_depth(rate: u64) -> u64 {
    depth_for(rate, DEFAULT_BUCKET_MILLI)
}

impl Rate {
    /// From RouterOS values: `rate`, `burst-rate`, `burst-threshold` in
    /// bits per second, `burst-time` in nanoseconds. As in RouterOS, a
    /// burst rate without threshold uses `rate` as the threshold, and a
    /// zero burst time means 1 s.
    pub fn mikrotik(rate_bps: u64, burst_bps: u64, threshold_bps: u64, burst_time_ns: u64) -> Rate {
        Self::routeros(
            rate_bps,
            burst_bps,
            threshold_bps,
            burst_time_ns,
            DEFAULT_BUCKET_MILLI,
        )
    }

    /// [`Rate::mikrotik`] with RouterOS v7's `bucket-size` (thousandths of
    /// the rate; the burst bucket is the same share of the burst rate).
    pub fn routeros(
        rate_bps: u64,
        burst_bps: u64,
        threshold_bps: u64,
        burst_time_ns: u64,
        bucket_milli: u64,
    ) -> Rate {
        let rate = (rate_bps / 8).min(MAX_RATE);
        let burst_rate = (burst_bps / 8).min(MAX_RATE);
        if rate == 0 {
            return Rate::default();
        }
        let mut r = Rate {
            rate,
            depth: depth_for(rate, bucket_milli),
            ..Rate::default()
        };
        if burst_rate > rate {
            let time = if burst_time_ns == 0 {
                NANOS
            } else {
                burst_time_ns
            };
            let threshold = if threshold_bps == 0 {
                rate_bps
            } else {
                threshold_bps
            };
            let window = u128::from(threshold) * u128::from(time) / (8 * u128::from(NANOS));
            r.burst_rate = burst_rate;
            r.burst_depth = depth_for(burst_rate, bucket_milli);
            r.burst_window_bytes = u64::try_from(window).unwrap_or(u64::MAX);
            r.slot_ns = (time / SLOTS as u64).max(1);
        }
        r
    }

    pub fn to_words(&self) -> [u64; RATE_WORDS] {
        [
            self.rate,
            self.depth,
            self.burst_rate,
            self.burst_depth,
            self.burst_window_bytes,
            self.slot_ns,
        ]
    }

    pub fn from_words(
        [
            rate,
            depth,
            burst_rate,
            burst_depth,
            burst_window_bytes,
            slot_ns,
        ]: [u64; RATE_WORDS],
    ) -> Rate {
        Rate {
            rate,
            depth,
            burst_rate,
            burst_depth,
            burst_window_bytes,
            slot_ns,
        }
    }

    /// Whether the burst applies at all.
    #[inline(always)]
    pub fn bursts(&self) -> bool {
        self.burst_rate > self.rate && self.slot_ns > 0
    }
}

const TAT: usize = 0;
const START: usize = 1;
const SLOT0: usize = 3;

/// Largest packet the clock charges (bytes): `bytes × NANOS` stays in a
/// `u64`; a GSO/BIG TCP super-packet is far below.
pub const MAX_BYTES: u64 = 1 << 24;

/// Index of the window slot holding time `t`.
#[inline(always)]
fn slot_of(t: u64, slot_ns: u64) -> usize {
    SLOT0 + (t.checked_div(slot_ns).unwrap_or(0) as usize & (SLOTS - 1))
}

/// Bytes counted over the window (the last `burst-time`).
#[inline(always)]
pub fn window_sum<W: Words + ?Sized>(st: &W) -> u64 {
    let mut sum: u64 = 0;
    let mut i = 0;
    while i < SLOTS {
        sum = sum.saturating_add(st.get(SLOT0 + i));
        i += 1;
    }
    sum
}

/// Move the burst window up to `now`: slots older than `burst-time` leave
/// it. One CPU wins the compare-and-swap of the window start and clears
/// the slots it passed; the others go on (a byte added to a slot in that
/// instant may be lost: the average is approximate, the clock is not).
#[inline(always)]
pub(crate) fn advance<W: Words + ?Sized>(st: &mut W, slot_ns: u64, now: u64) {
    if slot_ns == 0 {
        return;
    }
    let start = st.get(START);
    if now < start.saturating_add(slot_ns) {
        return;
    }
    let new_start = now - now.checked_rem(slot_ns).unwrap_or(0);
    let k = (new_start - start).checked_div(slot_ns).unwrap_or(0);
    if !st.cas(START, start, new_start) {
        return;
    }
    // Clear the `k` slots after the old start's (all of them past 16),
    // without a branch per slot (the verifier walks each one).
    let first = start.checked_div(slot_ns).unwrap_or(0) + 1;
    let mut s: u64 = 0;
    while s < SLOTS as u64 {
        let after = s.wrapping_sub(first) & (SLOTS as u64 - 1);
        let clear = u64::from(after < k).wrapping_neg();
        let i = SLOT0 + s as usize;
        // Subtracting what the slot holds (an atomic add of 0 for the
        // others) keeps bytes other CPUs add meanwhile.
        st.add(i, (st.get(i) & clear).wrapping_neg());
        s += 1;
    }
}

/// Count `bytes` sent at `now` toward the burst average.
#[inline(always)]
pub(crate) fn record<W: Words + ?Sized>(st: &mut W, slot_ns: u64, now: u64, bytes: u64) {
    st.add(slot_of(now, slot_ns), bytes);
}

/// The rate and bucket in force: the burst pair while the window average
/// is under the threshold.
#[inline(always)]
pub(crate) fn in_force<W: Words + ?Sized>(st: &W, r: &Rate) -> (u64, u64) {
    if r.bursts() && window_sum(st) < r.burst_window_bytes {
        (r.burst_rate, r.burst_depth)
    } else {
        (r.rate, r.depth)
    }
}

/// Nanoseconds `bytes` take at `rate` bytes per second, rounded up.
#[inline(always)]
pub fn cost_ns(bytes: u64, rate: u64) -> u64 {
    let rate = rate.clamp(1, MAX_RATE);
    let b = bytes.min(MAX_BYTES) * NANOS;
    b.checked_div(rate).unwrap_or(b) + u64::from(b.checked_rem(rate).unwrap_or(0) > 0)
}

/// The clocks (GCRA and EDT) count in 1/64 ns: a 64-byte packet at 10
/// Gbit/s lasts 51.2 ns, and rounding it to whole nanoseconds made the
/// rate 1.6% slow; in ticks the error is under 0.03%. The monotonic clock
/// in ticks wraps after ~9 years of uptime.
pub const TICK_SHIFT: u32 = 6;

/// `ns` in ticks (saturating).
#[inline(always)]
pub fn ticks(ns: u64) -> u64 {
    if ns > u64::MAX >> TICK_SHIFT {
        u64::MAX
    } else {
        ns << TICK_SHIFT
    }
}

/// Ticks `bytes` take at `rate` bytes per second, rounded up (a clock
/// rounded down lets a little more than the rate through).
#[inline(always)]
pub fn cost_ticks(bytes: u64, rate: u64) -> u64 {
    let rate = rate.clamp(1, MAX_RATE);
    let b = (bytes.min(MAX_BYTES) * NANOS) << TICK_SHIFT;
    b.checked_div(rate).unwrap_or(b) + u64::from(b.checked_rem(rate).unwrap_or(0) > 0)
}

/// The bucket `depth` at `rate` as ticks of lag the clock may have.
#[inline(always)]
pub fn depth_ticks(depth: u64, rate: u64) -> u64 {
    let rate = rate.clamp(1, MAX_RATE);
    let d = (depth.clamp(1, MAX_DEPTH >> TICK_SHIFT) * NANOS) << TICK_SHIFT;
    d.checked_div(rate).unwrap_or(d)
}

/// Whether a packet of `bytes` passes at `now_ns` (monotonic). A passed
/// packet moves the clock and counts toward the burst average; a dropped
/// one changes nothing.
///
/// GCRA (ITU-T I.371, the virtual-scheduling form of a token bucket): the
/// state is one theoretical arrival time `tat`; a packet passes while
/// `max(tat, now) + cost − now ≤ depth / rate`, and moves `tat` there. The
/// same bucket as before (`depth` bytes, refilled at `rate`) in one word,
/// so one compare-and-swap makes it exact with every CPU on the same
/// subscriber (G4.3cc).
#[inline(always)]
pub fn admit<W: Words + ?Sized>(st: &mut W, r: &Rate, now_ns: u64, bytes: u64) -> bool {
    if r.rate == 0 {
        return true;
    }
    let bursts = r.bursts();
    if bursts {
        advance(st, r.slot_ns, now_ns);
    }
    let (rate, depth) = in_force(st, r);
    let rate = rate.clamp(1, MAX_RATE);
    let cost = cost_ticks(bytes, rate);
    let tau = depth_ticks(depth, rate);
    let now = ticks(now_ns);
    let mut i = 0;
    while i < CAS_TRIES {
        let old = st.get(TAT);
        let start = if old > now { old } else { now };
        if start - now + cost > tau {
            return false;
        }
        if st.cas(TAT, old, start.saturating_add(cost)) {
            if bursts {
                record(st, r.slot_ns, now_ns, bytes);
            }
            return true;
        }
        i += 1;
    }
    // Four other CPUs moved this clock in the same instant: drop this one
    // rather than spin (the rate stays exact; never a lockup).
    false
}

/// A fresh state at `now_ns`: a full bucket and an empty window (an idle
/// subscriber may burst at once).
pub fn fresh(r: &Rate, now_ns: u64) -> State {
    let mut st = [0; STATE_WORDS];
    let start = match now_ns.checked_rem(r.slot_ns) {
        Some(rem) => now_ns - rem,
        None => now_ns,
    };
    st.set(START, start);
    st
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    /// Feed 1500-byte packets as fast as the bucket takes them, every
    /// `step` ns for `secs`; the bytes passed in each second.
    fn per_second(r: &Rate, secs: u64, step: u64) -> std::vec::Vec<u64> {
        let mut st = fresh(r, 0);
        let mut out = std::vec![0u64; secs as usize];
        let mut t = 0;
        while t < secs * NANOS {
            if admit(&mut st, r, t, 1500) {
                out[(t / NANOS) as usize] += 1500;
            }
            t += step;
        }
        out
    }

    #[test]
    fn plain_rate_holds() {
        // 10 Mbit/s = 1.25 MB/s; 10 µs steps offer 150 MB/s.
        let r = Rate::mikrotik(10_000_000, 0, 0, 0);
        let s = per_second(&r, 5, 10_000);
        // First second carries the full bucket (50 ms) on top.
        assert!(s[0] <= 1_250_000 + r.depth + 1500, "{s:?}");
        for b in &s[1..] {
            assert!((1_248_000..=1_252_000).contains(b), "{s:?}");
        }
    }

    /// RouterOS's own example: 1M rate, 2M burst, 1.5M threshold, 8 s →
    /// 2M for 6 s, then 1M. As in RouterOS, once the 2M seconds leave the
    /// window the average drops under the threshold and the burst comes
    /// back: in the long run the average sits at the threshold.
    #[test]
    fn routeros_burst_example() {
        let r = Rate::mikrotik(1_000_000, 2_000_000, 1_500_000, 8 * NANOS);
        let s = per_second(&r, 120, 50_000);
        for (i, b) in s.iter().enumerate().take(9) {
            let want = match i {
                // The first bucket (0.1 s of 2M) counts in the window too: the
                // switch comes at ~5.9 s instead of 6.
                1..=4 => 250_000,
                7..=8 => 125_000,
                // The edges: the first bucket, the switch.
                _ => continue,
            };
            assert!(b.abs_diff(want) <= 5_000, "second {i}: {b} {s:?}");
        }
        let tail: u64 = s[40..].iter().sum::<u64>() / 80;
        assert!(tail.abs_diff(187_500) <= 9_000, "{tail} {s:?}");
        // Never above the burst rate nor under the plain rate.
        for b in &s[1..] {
            assert!((120_000..=255_000).contains(b), "{s:?}");
        }
    }

    #[test]
    fn no_limit_and_odd_inputs() {
        let r = Rate::default();
        let mut st = fresh(&r, 0);
        assert!(admit(&mut st, &r, 0, u64::MAX));
        let r = Rate::mikrotik(8_000, 16_000, 0, 0);
        assert_eq!(r.slot_ns, NANOS / 16);
        assert_eq!(r.burst_window_bytes, 1_000);
        let mut st = fresh(&r, 1_000);
        // Clock going back, giant packets, huge jumps: no panic.
        assert!(!admit(&mut st, &r, 0, u64::MAX));
        assert!(admit(&mut st, &r, u64::MAX, 1));
        assert_eq!(Rate::from_words(r.to_words()), r);
    }
}
