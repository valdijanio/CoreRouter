//! Per-source token bucket, in integer arithmetic the verifier takes (no
//! floats, no 128-bit multiply, division only by a checked non-zero rate).
//!
//! Tokens are counted in nano-packets: one packet costs [`NANOS`], and
//! every nanosecond adds `rate` of them (a rate of `r` packets per second
//! is `r` nano-packets per nanosecond). The bucket holds at most
//! `burst × NANOS`.

pub const NANOS: u64 = 1_000_000_000;
/// Highest rate the filter takes (packets per second): keeps
/// `elapsed × rate` below `u64::MAX` for any elapsed time under the fill
/// time.
pub const MAX_RATE: u64 = 1_000_000_000;
/// Highest burst (packets): `burst × NANOS` fits in a `u64`.
pub const MAX_BURST: u64 = 1_000_000_000;

/// A bucket as the map stores it: `[tokens, stamp_ns]`.
pub type Bucket = [u64; 2];

/// A full bucket that just paid for its first packet, at `now_ns`.
pub fn fresh(now_ns: u64, burst: u64) -> Bucket {
    [cap(burst).saturating_sub(NANOS), now_ns]
}

fn cap(burst: u64) -> u64 {
    burst.clamp(1, MAX_BURST) * NANOS
}

/// Refill `b` up to `now_ns` at `rate` packets per second (capped at
/// `burst`), then take one packet's worth. `false`: not enough tokens, the
/// packet is over the limit (the refill is kept). A clock that went back
/// (another CPU's stamp) refills nothing.
pub fn take(b: &mut Bucket, now_ns: u64, rate: u64, burst: u64) -> bool {
    let [tokens, stamp] = *b;
    let cap = cap(burst);
    let rate = rate.min(MAX_RATE);
    let elapsed = now_ns.saturating_sub(stamp);
    let missing = cap.saturating_sub(tokens);
    // Time to fill the bucket from here; a zero rate never refills.
    let fill = missing.checked_div(rate).unwrap_or(u64::MAX);
    let tokens = if elapsed >= fill {
        cap
    } else {
        // elapsed < missing / rate, so elapsed × rate < missing ≤ cap.
        tokens.saturating_add(elapsed.wrapping_mul(rate)).min(cap)
    };
    let stamp = if now_ns > stamp { now_ns } else { stamp };
    if tokens >= NANOS {
        *b = [tokens - NANOS, stamp];
        true
    } else {
        *b = [tokens, stamp];
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_rate() {
        let (rate, burst) = (10, 5);
        let mut b = fresh(0, burst);
        // The fresh bucket paid for one; four more go through at once.
        for _ in 0..4 {
            assert!(take(&mut b, 0, rate, burst));
        }
        assert!(!take(&mut b, 0, rate, burst));
        // 100 ms at 10 pps = one packet.
        assert!(take(&mut b, 100_000_000, rate, burst));
        assert!(!take(&mut b, 100_000_000, rate, burst));
        // A long pause refills only up to the burst.
        let t = 3_600 * NANOS;
        for _ in 0..5 {
            assert!(take(&mut b, t, rate, burst));
        }
        assert!(!take(&mut b, t, rate, burst));
    }

    #[test]
    fn zero_rate_never_refills_and_clock_going_back_is_harmless() {
        let mut b = fresh(1_000, 1);
        assert!(!take(&mut b, u64::MAX, 0, 1));
        let mut b = [0, 5_000];
        assert!(!take(&mut b, 1_000, 1_000, 1));
        assert_eq!(b, [0, 5_000]);
    }
}
