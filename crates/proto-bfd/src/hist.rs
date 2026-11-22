//! A small log-scale histogram for per-session timings (transmit lateness,
//! gaps between received packets): 64 buckets of ~12 % from 1 µs, fixed
//! size, O(1) record, percentiles accurate to one bucket. Halving all
//! counts ([`Hist::age`]) keeps it a recent window.

const BUCKETS: usize = 64;
/// Bucket i holds values up to `FIRST · RATIO^i` µs.
const RATIO: f64 = 1.25;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hist {
    counts: [u32; BUCKETS],
    total: u64,
    max: u64,
}

impl Default for Hist {
    fn default() -> Self {
        Self {
            counts: [0; BUCKETS],
            total: 0,
            max: 0,
        }
    }
}

fn bucket(v: u64) -> usize {
    if v <= 1 {
        return 0;
    }
    let i = ((v as f64).ln() / RATIO.ln()).ceil() as usize;
    i.min(BUCKETS - 1)
}

fn upper(i: usize) -> u64 {
    RATIO.powi(i as i32).round() as u64
}

impl Hist {
    pub fn record(&mut self, v: u64) {
        if let Some(c) = self.counts.get_mut(bucket(v)) {
            *c = c.saturating_add(1);
        }
        self.total += 1;
        self.max = self.max.max(v);
    }

    pub fn count(&self) -> u64 {
        self.total
    }

    pub fn max(&self) -> u64 {
        self.max
    }

    /// The upper bound of the bucket holding the `q` quantile (0..=1);
    /// never above the largest value recorded.
    pub fn quantile(&self, q: f64) -> Option<u64> {
        if self.total == 0 {
            return None;
        }
        let want = ((self.total as f64) * q).ceil().max(1.0) as u64;
        let mut seen = 0u64;
        for (i, &c) in self.counts.iter().enumerate() {
            seen += u64::from(c);
            if seen >= want {
                return Some(upper(i).min(self.max));
            }
        }
        Some(self.max)
    }

    /// Halves every count (an older half weighs less).
    pub fn age(&mut self) {
        for c in &mut self.counts {
            *c /= 2;
        }
        self.total = self.counts.iter().map(|&c| u64::from(c)).sum();
        if self.total == 0 {
            self.max = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p99_within_a_bucket() {
        let mut h = Hist::default();
        for v in 1..=1000u64 {
            h.record(v * 10);
        }
        let p = h.quantile(0.99).unwrap();
        assert!((9_900..=12_400).contains(&p), "{p}");
        assert_eq!(h.quantile(1.0), Some(10_000));
        assert_eq!(h.max(), 10_000);
        h.age();
        assert!(h.count() < 1000);
        assert_eq!(Hist::default().quantile(0.5), None);
    }
}
