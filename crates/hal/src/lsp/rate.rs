//! Rate limits of the responder (G3.5b, G3.9d, G3.9da), without a clock:
//! the caller passes the time (`Instant::now` is the daemon's, never
//! called here, so the module builds for WASM).
//!
//! - [`Bucket`]: `rate` per second, a second's worth saved (RFC 8029 §5,
//!   RFC 1812 §4.3.2.8).
//! - [`IcmpLimit`]: the ICMP errors, one bucket per source the errors go
//!   to (as Linux's per-peer `icmp_ratelimit`), then the global one: a host
//!   flooding TTL 1 spends its own share, another one's traceroute still
//!   answers. At most [`MAX_SOURCES`] buckets: idle ones (a second, so full
//!   again) go at most once a second; while full of busy ones, a new source
//!   gets no error (a spoofed flood, when the global bucket would be empty
//!   anyway).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Sources with a bucket of their own at most (~100 bytes each).
pub const MAX_SOURCES: usize = 4096;
/// A source this long without an error has a full bucket again.
pub const IDLE: Duration = Duration::from_secs(1);

/// A token bucket: `rate` per second, at most `rate` saved.
#[derive(Debug, Clone)]
pub struct Bucket {
    rate: f64,
    tokens: f64,
    at: Instant,
}

impl Bucket {
    /// Full at `now`.
    pub fn new(rate: u32, now: Instant) -> Self {
        Self {
            rate: f64::from(rate.max(1)),
            tokens: f64::from(rate.max(1)),
            at: now,
        }
    }

    pub fn set_rate(&mut self, rate: u32) {
        self.rate = f64::from(rate.max(1));
        self.tokens = self.tokens.min(self.rate);
    }

    pub fn take(&mut self, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.at).as_secs_f64();
        self.at = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.rate);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// One [`Bucket`] per source.
#[derive(Debug, Clone)]
pub struct PerSource {
    rate: u32,
    buckets: HashMap<IpAddr, Bucket>,
    purged: Option<Instant>,
}

impl PerSource {
    pub fn new(rate: u32) -> Self {
        Self {
            rate,
            buckets: HashMap::new(),
            purged: None,
        }
    }

    pub fn set_rate(&mut self, rate: u32) {
        self.rate = rate;
        for b in self.buckets.values_mut() {
            b.set_rate(rate);
        }
    }

    /// Sources with a bucket now.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    pub fn take(&mut self, src: IpAddr, now: Instant) -> bool {
        if let Some(b) = self.buckets.get_mut(&src) {
            return b.take(now);
        }
        if self.buckets.len() >= MAX_SOURCES
            && self
                .purged
                .is_none_or(|t| now.saturating_duration_since(t) >= IDLE)
        {
            self.purged = Some(now);
            self.buckets
                .retain(|_, b| now.saturating_duration_since(b.at) < IDLE);
        }
        if self.buckets.len() >= MAX_SOURCES {
            return false;
        }
        let mut b = Bucket::new(self.rate, now);
        let ok = b.take(now);
        self.buckets.insert(src, b);
        ok
    }
}

/// Which limit refused an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The source's (`icmp-rate-per-source`).
    Source,
    /// The global one (`icmp-rate`).
    Global,
}

/// The two limits on ICMP errors, the source's first (a flood from one
/// host then does not drain the global one).
#[derive(Debug, Clone)]
pub struct IcmpLimit {
    pub global: Bucket,
    pub per_source: PerSource,
}

impl IcmpLimit {
    pub fn new(rate: u32, per_source: u32, now: Instant) -> Self {
        Self {
            global: Bucket::new(rate, now),
            per_source: PerSource::new(per_source),
        }
    }

    /// Whether an error to `to` may go at `now` (`None`: the source could
    /// not be read, only the global limit applies).
    pub fn take(&mut self, to: Option<IpAddr>, now: Instant) -> Result<(), Refused> {
        if let Some(src) = to
            && !self.per_source.take(src, now)
        {
            return Err(Refused::Source);
        }
        if !self.global.take(now) {
            return Err(Refused::Global);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u32) -> IpAddr {
        IpAddr::from(n.to_be_bytes())
    }

    #[test]
    fn the_bucket_allows_the_rate_and_a_one_second_burst() {
        let t0 = Instant::now();
        let mut b = Bucket::new(10, t0);
        let burst = (0..50).filter(|_| b.take(t0)).count();
        assert_eq!(burst, 10);
        // Half a second later: 5 more.
        let t1 = t0 + Duration::from_millis(500);
        assert_eq!((0..50).filter(|_| b.take(t1)).count(), 5);
        // Never more than a second's worth saved.
        let t2 = t1 + Duration::from_secs(60);
        assert_eq!((0..50).filter(|_| b.take(t2)).count(), 10);
        b.set_rate(2);
        let t3 = t2 + Duration::from_secs(5);
        assert_eq!((0..50).filter(|_| b.take(t3)).count(), 2);
    }

    /// G3.9da: a source that floods uses its own bucket; another still
    /// gets its errors, from the same global bucket.
    #[test]
    fn one_source_cannot_use_up_the_global_rate() {
        let t = Instant::now();
        let mut l = IcmpLimit::new(100, 10, t);
        let flood: Vec<_> = (0..1000).map(|_| l.take(Some(ip(1)), t)).collect();
        assert_eq!(flood.iter().filter(|r| r.is_ok()).count(), 10);
        assert!(flood[10..].iter().all(|r| *r == Err(Refused::Source)));
        assert_eq!((0..3).filter(|_| l.take(Some(ip(2)), t).is_ok()).count(), 3);
        // Many sources at once: the global bucket holds.
        let many: Vec<_> = (10..1000).map(|n| l.take(Some(ip(n)), t)).collect();
        assert_eq!(many.iter().filter(|r| r.is_ok()).count(), 100 - 13);
        assert!(many.contains(&Err(Refused::Global)));
        // An unreadable source: only the global limit.
        assert_eq!(l.take(None, t), Err(Refused::Global));
    }

    #[test]
    fn the_source_table_is_bounded_and_idle_sources_leave() {
        let t0 = Instant::now();
        let mut p = PerSource::new(5);
        for n in 0..MAX_SOURCES as u32 {
            assert!(p.take(ip(n), t0));
        }
        // Full of busy sources: a new one gets nothing.
        assert!(!p.take(ip(u32::MAX), t0));
        assert_eq!(p.len(), MAX_SOURCES);
        // A second later they are idle: they go, the new one comes in.
        let t1 = t0 + IDLE;
        assert!(p.take(ip(u32::MAX), t1));
        assert_eq!(p.len(), 1);
        // A lower rate also caps what was saved.
        p.set_rate(1);
        assert!(p.take(ip(u32::MAX), t1));
        assert!(!p.take(ip(u32::MAX), t1));
    }
}
