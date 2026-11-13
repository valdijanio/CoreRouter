//! Latency histograms (G4.1h): the time to answer a client and the round
//! trip to each upstream server, in fixed buckets so a query costs one
//! search of 15 edges and memory never grows (Unbound's
//! `histogram.*` and PowerDNS' `answers0-1`… do the same).
//!
//! The edges are in microseconds, finer where a cache answers (under a
//! millisecond) and coarse where a server is failing; they include the six
//! ranges an operator reads ([`RANGES`]: <1, 1–10, 10–100, 100–500,
//! 500–1600 and >1600 ms, the last edge being `query_server_timeout`'s
//! neighbourhood), so both views come from one count.

/// Upper edge of each bucket but the last (which is open), µs.
pub const EDGES_US: [u64; 15] = [
    100, 250, 500, 1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000, 200_000, 500_000,
    1_000_000, 1_600_000, 5_000_000,
];
/// Buckets: one per edge and the open one past the last.
pub const BUCKETS: usize = EDGES_US.len() + 1;
/// The ranges shown, by name, and the first bucket of each (the last one
/// runs to the end).
pub const RANGES: [(&str, usize); 6] = [
    ("<1", 0),
    ("1-10", 4),
    ("10-100", 7),
    ("100-500", 10),
    ("500-1600", 12),
    (">1600", 14),
];

/// Counts per bucket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Hist(pub [u64; BUCKETS]);

/// The bucket of `us` microseconds.
pub fn bucket(us: u64) -> usize {
    EDGES_US.partition_point(|e| *e <= us)
}

impl Hist {
    pub fn add_us(&mut self, us: u64) {
        if let Some(b) = self.0.get_mut(bucket(us)) {
            *b = b.saturating_add(1);
        }
    }

    pub fn add_ms(&mut self, ms: u64) {
        self.add_us(ms.saturating_mul(1000));
    }

    pub fn total(&self) -> u64 {
        self.0.iter().fold(0u64, |a, b| a.saturating_add(*b))
    }

    /// Adds `other` bucket by bucket (stripes merged at read).
    pub fn merge(&mut self, other: &Hist) {
        for (a, b) in self.0.iter_mut().zip(other.0) {
            *a = a.saturating_add(b);
        }
    }

    /// What was counted after `older` (a reading kept earlier); a bucket
    /// that went down (a reset in between) counts as zero.
    pub fn since(&self, older: &Hist) -> Hist {
        let mut out = Hist::default();
        for ((o, a), b) in out.0.iter_mut().zip(self.0).zip(older.0) {
            *o = a.saturating_sub(b);
        }
        out
    }

    /// The `q` quantile (0..=1), µs: the bucket holding that rank, with
    /// the rank spread evenly inside it (a bucket's width is the error).
    /// The open bucket answers with its lower edge ("over 5 s"). `None`
    /// when nothing was counted.
    pub fn quantile_us(&self, q: f64) -> Option<u64> {
        let total = self.total();
        if total == 0 {
            return None;
        }
        let q = q.clamp(0.0, 1.0);
        // Nearest rank, at least the first.
        let rank = ((q * total as f64).ceil() as u64).clamp(1, total);
        let mut before = 0u64;
        for (i, n) in self.0.iter().enumerate() {
            if *n == 0 {
                continue;
            }
            if before.saturating_add(*n) >= rank {
                let lower = i
                    .checked_sub(1)
                    .and_then(|p| EDGES_US.get(p))
                    .copied()
                    .unwrap_or(0);
                let Some(upper) = EDGES_US.get(i).copied() else {
                    return Some(lower);
                };
                let inside = (rank - before) as f64 / *n as f64;
                return Some(lower + ((upper - lower) as f64 * inside).round() as u64);
            }
            before = before.saturating_add(*n);
        }
        None
    }

    /// Counts in each of [`RANGES`].
    pub fn ranges(&self) -> [u64; RANGES.len()] {
        let mut out = [0u64; RANGES.len()];
        for (i, n) in self.0.iter().enumerate() {
            let r = RANGES
                .iter()
                .rposition(|(_, first)| *first <= i)
                .unwrap_or(0);
            if let Some(o) = out.get_mut(r) {
                *o = o.saturating_add(*n);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_follow_the_edges() {
        assert_eq!(bucket(0), 0);
        assert_eq!(bucket(99), 0);
        assert_eq!(bucket(100), 1, "an edge opens the next bucket");
        assert_eq!(bucket(999), 3);
        assert_eq!(bucket(1_000), 4);
        assert_eq!(bucket(4_999_999), 14);
        assert_eq!(bucket(u64::MAX), BUCKETS - 1, "open bucket");
    }

    #[test]
    fn ranges_cover_every_bucket_once() {
        let mut h = Hist::default();
        for us in [
            50, 900, 1_000, 9_999, 10_000, 150_000, 499_999, 500_000, 1_599_999, 1_600_000,
            60_000_000,
        ] {
            h.add_us(us);
        }
        assert_eq!(h.ranges(), [2, 2, 1, 2, 2, 2]);
        assert_eq!(h.ranges().iter().sum::<u64>(), h.total());
    }

    #[test]
    fn quantiles() {
        let mut h = Hist::default();
        assert_eq!(h.quantile_us(0.5), None);
        // 90 answers from the cache (60–90 µs), 10 from a server (30 ms).
        for _ in 0..90 {
            h.add_us(70);
        }
        for _ in 0..10 {
            h.add_ms(30);
        }
        let p50 = h.quantile_us(0.5).unwrap();
        assert!(p50 <= 100, "{p50}");
        let p99 = h.quantile_us(0.99).unwrap();
        assert!((20_000..=50_000).contains(&p99), "{p99}");
        assert_eq!(
            h.quantile_us(1.0),
            Some(50_000),
            "upper edge of the last bucket used"
        );
        let mut slow = Hist::default();
        slow.add_ms(9_000);
        assert_eq!(
            slow.quantile_us(0.5),
            Some(5_000_000),
            "open bucket: its lower edge"
        );
    }

    #[test]
    fn since_and_merge() {
        let mut a = Hist::default();
        a.add_us(10);
        let old = a;
        a.add_us(10);
        a.add_ms(3);
        let d = a.since(&old);
        assert_eq!(d.total(), 2);
        assert_eq!(
            old.since(&a).total(),
            0,
            "a reset in between: never negative"
        );
        let mut m = Hist::default();
        m.merge(&a);
        m.merge(&d);
        assert_eq!(m.total(), 5);
    }
}
