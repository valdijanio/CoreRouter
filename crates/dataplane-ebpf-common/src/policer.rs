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
//! Integer arithmetic the verifier takes: tokens are nano-bytes (one byte
//! = [`NANOS`]), every nanosecond adds `rate` of them, division only by a
//! checked non-zero value. The state is plain words in a map shared by
//! every CPU: two CPUs updating one subscriber at once can lose or add a
//! token (the rate is approximate under that race), never memory safety.

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

/// `[tokens, stamp_ns, slot_start_ns, window_sum, current_slot, 8 words
/// of 16 × u32 slot sums]`. A slot saturates at 4 GiB (10 Gbit/s with a
/// burst time up to 54 s).
pub const STATE_WORDS: usize = 5 + SLOTS / 2;
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

/// Bucket depth for `rate` bytes per second: 50 ms of traffic, at least
/// [`MIN_DEPTH`].
pub fn default_depth(rate: u64) -> u64 {
    (rate / 20).clamp(MIN_DEPTH, MAX_DEPTH)
}

impl Rate {
    /// From RouterOS values: `rate`, `burst-rate`, `burst-threshold` in
    /// bits per second, `burst-time` in nanoseconds. As in RouterOS, a
    /// burst rate without threshold uses `rate` as the threshold, and a
    /// zero burst time means 1 s.
    pub fn mikrotik(rate_bps: u64, burst_bps: u64, threshold_bps: u64, burst_time_ns: u64) -> Rate {
        let rate = (rate_bps / 8).min(MAX_RATE);
        let burst_rate = (burst_bps / 8).min(MAX_RATE);
        if rate == 0 {
            return Rate::default();
        }
        let mut r = Rate {
            rate,
            depth: default_depth(rate),
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
            r.burst_depth = default_depth(burst_rate);
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

#[inline(always)]
fn put(st: &mut State, i: usize, v: u64) {
    if let Some(w) = st.get_mut(i) {
        *w = v;
    }
}

#[inline(always)]
fn get(st: &State, i: usize) -> u64 {
    st.get(i).copied().unwrap_or(0)
}

#[inline(always)]
fn slot(st: &State, i: u64) -> u64 {
    let w = st
        .get(5 + (i as usize & (SLOTS - 1)) / 2)
        .copied()
        .unwrap_or(0);
    (w >> ((i & 1) * 32)) & 0xffff_ffff
}

#[inline(always)]
fn set_slot(st: &mut State, i: u64, v: u64) {
    let sh = (i & 1) * 32;
    if let Some(w) = st.get_mut(5 + (i as usize & (SLOTS - 1)) / 2) {
        *w = (*w & !(0xffff_ffff << sh)) | (v.min(0xffff_ffff) << sh);
    }
}

/// Move the burst window up to `now`: slots older than `burst-time` leave
/// the sum.
#[inline(always)]
fn advance(st: &mut State, r: &Rate, now: u64) {
    let (start, sum, cur) = (get(st, 2), get(st, 3), get(st, 4));
    let elapsed = now.saturating_sub(start);
    let Some(k) = elapsed.checked_div(r.slot_ns) else {
        return;
    };
    if k == 0 {
        return;
    }
    if k >= SLOTS as u64 {
        for w in st.iter_mut().skip(3) {
            *w = 0;
        }
        put(st, 2, now);
        return;
    }
    let (mut sum, mut cur) = (sum, cur);
    for i in 0..SLOTS as u64 {
        if i >= k {
            break;
        }
        cur = (cur + 1) & (SLOTS as u64 - 1);
        sum = sum.saturating_sub(slot(st, cur));
        set_slot(st, cur, 0);
    }
    put(st, 2, start + k * r.slot_ns);
    put(st, 3, sum);
    put(st, 4, cur);
}

/// Whether a packet of `bytes` passes at `now_ns` (monotonic). A passed
/// packet pays its tokens and counts toward the burst average; a dropped
/// one changes only the refill.
#[inline(always)]
pub fn admit(st: &mut State, r: &Rate, now_ns: u64, bytes: u64) -> bool {
    if r.rate == 0 {
        return true;
    }
    let bursts = r.bursts();
    if bursts {
        advance(st, r, now_ns);
    }
    let (tokens, stamp, sum, cur) = (get(st, 0), get(st, 1), get(st, 3), get(st, 4));
    let (rate, depth) = if bursts && sum < r.burst_window_bytes {
        (r.burst_rate, r.burst_depth)
    } else {
        (r.rate, r.depth)
    };
    let rate = rate.min(MAX_RATE);
    let cap = depth.clamp(1, MAX_DEPTH) * NANOS;
    let elapsed = now_ns.saturating_sub(stamp);
    let missing = cap.saturating_sub(tokens);
    let fill = missing.checked_div(rate).unwrap_or(u64::MAX);
    let tokens = if elapsed >= fill {
        cap
    } else {
        // elapsed < missing / rate, so elapsed × rate < missing ≤ cap.
        tokens.saturating_add(elapsed.wrapping_mul(rate)).min(cap)
    };
    put(st, 1, if now_ns > stamp { now_ns } else { stamp });
    let cost = bytes.min(MAX_DEPTH).saturating_mul(NANOS);
    if tokens < cost {
        put(st, 0, tokens);
        return false;
    }
    put(st, 0, tokens - cost);
    if bursts {
        set_slot(st, cur, slot(st, cur).saturating_add(bytes));
        put(st, 3, sum.saturating_add(bytes));
    }
    true
}

/// A fresh state at `now_ns`: a full bucket and an empty window (an idle
/// subscriber may burst at once).
pub fn fresh(r: &Rate, now_ns: u64) -> State {
    let mut st = [0; STATE_WORDS];
    put(&mut st, 0, r.depth.clamp(1, MAX_DEPTH) * NANOS);
    put(&mut st, 1, now_ns);
    put(&mut st, 2, now_ns);
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
                1..=5 => 250_000,
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
