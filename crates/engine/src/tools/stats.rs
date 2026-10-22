//! Round-trip statistics of one ping target (or one MTR hop).
//!
//! - min / avg / max / standard deviation (population, Welford's method)
//!   over every reply since the start;
//! - jitter: the RFC 3550 §6.4.1 estimator applied to consecutive RTTs,
//!   `J += (|D| − J) / 16` with `D` the difference between two consecutive
//!   replies' RTTs (a timeout in between does not reset it);
//! - p50 / p95 / p99 by nearest rank over the last [`RECENT`] replies;
//! - a histogram over fixed bounds ([`BOUNDS_MS`]).
//!
//! Loss counts only finished probes: one still waiting for its reply is
//! neither received nor lost.

use std::collections::VecDeque;

use serde_json::{Value, json};

/// Replies kept for the percentiles.
pub const RECENT: usize = 4096;
/// Upper bounds (ms) of the histogram buckets; one more bucket counts the
/// rest.
pub const BOUNDS_MS: [f64; 10] = [1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0];

/// How one probe ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Timeout,
    TtlExceeded,
    Unreachable,
    TooBig,
    Error,
}

impl Outcome {
    pub fn status(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Timeout => "timeout",
            Outcome::TtlExceeded => "ttl-exceeded",
            Outcome::Unreachable => "unreachable",
            Outcome::TooBig => "too-big",
            Outcome::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub sent: u64,
    pub received: u64,
    timeouts: u64,
    ttl_exceeded: u64,
    unreachable: u64,
    too_big: u64,
    errors: u64,
    pub duplicates: u64,
    min: Option<f64>,
    max: Option<f64>,
    mean: f64,
    m2: f64,
    jitter: f64,
    last: Option<f64>,
    recent: VecDeque<f64>,
    histogram: [u64; BOUNDS_MS.len() + 1],
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

impl Stats {
    /// A probe ended with `outcome`; `rtt_ms` for replies.
    pub fn record(&mut self, outcome: Outcome, rtt_ms: Option<f64>) {
        match outcome {
            Outcome::Ok => {}
            Outcome::Timeout => self.timeouts += 1,
            Outcome::TtlExceeded => self.ttl_exceeded += 1,
            Outcome::Unreachable => self.unreachable += 1,
            Outcome::TooBig => self.too_big += 1,
            Outcome::Error => self.errors += 1,
        }
        if outcome == Outcome::Ok
            && let Some(rtt) = rtt_ms.filter(|r| r.is_finite() && *r >= 0.0)
        {
            self.add_rtt(rtt);
        }
    }

    fn add_rtt(&mut self, rtt: f64) {
        self.received += 1;
        let n = self.received as f64;
        let delta = rtt - self.mean;
        self.mean += delta / n;
        self.m2 += delta * (rtt - self.mean);
        self.min = Some(self.min.map_or(rtt, |m| m.min(rtt)));
        self.max = Some(self.max.map_or(rtt, |m| m.max(rtt)));
        if let Some(prev) = self.last {
            self.jitter += ((rtt - prev).abs() - self.jitter) / 16.0;
        }
        self.last = Some(rtt);
        self.recent.push_back(rtt);
        if self.recent.len() > RECENT {
            self.recent.pop_front();
        }
        let bucket = BOUNDS_MS
            .iter()
            .position(|b| rtt < *b)
            .unwrap_or(BOUNDS_MS.len());
        if let Some(c) = self.histogram.get_mut(bucket) {
            *c += 1;
        }
    }

    /// Probes that ended (answered, failed or timed out).
    pub fn finished(&self) -> u64 {
        self.received
            + self.timeouts
            + self.ttl_exceeded
            + self.unreachable
            + self.too_big
            + self.errors
    }

    pub fn loss_pct(&self) -> f64 {
        let done = self.finished();
        if done == 0 {
            return 0.0;
        }
        (done - self.received) as f64 * 100.0 / done as f64
    }

    pub fn min(&self) -> Option<f64> {
        self.min
    }
    pub fn max(&self) -> Option<f64> {
        self.max
    }
    pub fn avg(&self) -> Option<f64> {
        (self.received > 0).then_some(self.mean)
    }
    pub fn last(&self) -> Option<f64> {
        self.last
    }

    pub fn stddev(&self) -> Option<f64> {
        (self.received > 0).then(|| (self.m2 / self.received as f64).sqrt())
    }

    pub fn jitter(&self) -> Option<f64> {
        (self.received > 1).then_some(self.jitter)
    }

    /// Nearest-rank percentile `q` (0..=1) of the recent replies.
    pub fn percentile(&self, q: f64) -> Option<f64> {
        if self.recent.is_empty() {
            return None;
        }
        let mut v: Vec<f64> = self.recent.iter().copied().collect();
        v.sort_by(f64::total_cmp);
        let rank = (q.clamp(0.0, 1.0) * v.len() as f64).ceil() as usize;
        v.get(rank.saturating_sub(1)).copied()
    }

    pub fn histogram(&self) -> &[u64] {
        &self.histogram
    }

    /// The statistics as JSON (times in ms, 3 decimals).
    pub fn to_json(&self) -> Value {
        let ms = |x: Option<f64>| x.map(round3);
        let mut v = vec![0.5, 0.95, 0.99]
            .into_iter()
            .map(|q| ms(self.percentile(q)));
        json!({
            "sent": self.sent,
            "received": self.received,
            "finished": self.finished(),
            "loss_pct": round3(self.loss_pct()),
            "timeouts": self.timeouts,
            "ttl_exceeded": self.ttl_exceeded,
            "unreachable": self.unreachable,
            "too_big": self.too_big,
            "errors": self.errors,
            "duplicates": self.duplicates,
            "min_ms": ms(self.min),
            "avg_ms": ms(self.avg()),
            "max_ms": ms(self.max),
            "stddev_ms": ms(self.stddev()),
            "jitter_ms": ms(self.jitter()),
            "last_ms": ms(self.last),
            "p50_ms": v.next().flatten(),
            "p95_ms": v.next().flatten(),
            "p99_ms": v.next().flatten(),
            "histogram": {"bounds_ms": BOUNDS_MS, "counts": self.histogram},
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(rtts: &[f64]) -> Stats {
        let mut s = Stats::default();
        for r in rtts {
            s.sent += 1;
            s.record(Outcome::Ok, Some(*r));
        }
        s
    }

    fn close(a: Option<f64>, b: f64) -> bool {
        a.is_some_and(|a| (a - b).abs() < 1e-9)
    }

    #[test]
    fn min_avg_max_stddev() {
        let s = with(&[10.0, 20.0, 30.0, 40.0]);
        assert!(close(s.min(), 10.0));
        assert!(close(s.max(), 40.0));
        assert!(close(s.avg(), 25.0));
        // population stddev of 10,20,30,40 = sqrt(125)
        assert!(close(s.stddev(), 125f64.sqrt()));
        assert_eq!(s.loss_pct(), 0.0);
    }

    #[test]
    fn jitter_follows_rfc3550() {
        // D = 10, 10, 10: J = 10/16, then + (10 - J)/16 twice.
        let s = with(&[10.0, 20.0, 10.0, 20.0]);
        let mut j = 0.0;
        for _ in 0..3 {
            j += (10.0 - j) / 16.0;
        }
        assert!(close(s.jitter(), j));
        // Constant RTT: no jitter.
        assert!(close(with(&[5.0; 50]).jitter(), 0.0));
        assert_eq!(with(&[5.0]).jitter(), None);
    }

    #[test]
    fn percentiles_by_nearest_rank() {
        let rtts: Vec<f64> = (1..=100).map(f64::from).collect();
        let s = with(&rtts);
        assert!(close(s.percentile(0.5), 50.0));
        assert!(close(s.percentile(0.95), 95.0));
        assert!(close(s.percentile(0.99), 99.0));
        assert!(close(s.percentile(1.0), 100.0));
        assert_eq!(Stats::default().percentile(0.5), None);
    }

    #[test]
    fn loss_counts_finished_probes_only() {
        let mut s = with(&[1.0, 1.0, 1.0]);
        s.sent += 2;
        s.record(Outcome::Timeout, None);
        assert!(close(Some(s.loss_pct()), 25.0), "one in flight is not lost");
        s.record(Outcome::Unreachable, None);
        assert!(close(Some(s.loss_pct()), 40.0));
        assert_eq!(s.to_json()["unreachable"], 1);
    }

    #[test]
    fn histogram_buckets() {
        let s = with(&[0.2, 1.5, 7.0, 2000.0, 999.9]);
        assert_eq!(s.histogram()[0], 1);
        assert_eq!(s.histogram()[1], 1);
        assert_eq!(s.histogram()[3], 1);
        assert_eq!(s.histogram()[9], 1);
        assert_eq!(s.histogram()[10], 1);
        assert_eq!(s.histogram().iter().sum::<u64>(), 5);
    }

    #[test]
    fn percentiles_use_the_recent_window() {
        let mut s = with(&vec![1000.0; RECENT]);
        for _ in 0..RECENT {
            s.sent += 1;
            s.record(Outcome::Ok, Some(1.0));
        }
        assert!(close(s.percentile(0.99), 1.0));
        assert!(close(s.max(), 1000.0), "max is over everything");
    }

    #[test]
    fn hostile_rtts_are_ignored() {
        let mut s = Stats::default();
        s.record(Outcome::Ok, Some(f64::NAN));
        s.record(Outcome::Ok, Some(-1.0));
        s.record(Outcome::Ok, Some(f64::INFINITY));
        assert_eq!(s.received, 0);
        assert!(s.to_json()["min_ms"].is_null());
    }
}
