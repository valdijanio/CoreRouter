//! The LAN DNS forwarder's history (G4.1h): series `dns`, one value per
//! second from the counters of `ip.dns.statistics` (the difference between
//! two readings, [`crate::dns_statistics`]), kept like the router's own
//! series while a forwarder counts and graphing is on. The DNS Statistics
//! window draws it and the Graphs window lists it.

use corerouter_model::graphing::Graphing;

use super::{DNS, GRACE, GraphDb, Source, file_name, src};

/// Queries answered per second, the share the cache answered of those that
/// needed the resolver, SERVFAIL's share, the time to answer (median and
/// 99th percentile) and the queries waiting for an upstream.
pub const DNS_SOURCES: [Source; 6] = [
    src("queries", "/s", Some("queries"), 1.0),
    src("cache_hit", "%", None, 0.0),
    src("servfail", "%", None, 0.0),
    src("latency_p50", "ms", None, 0.0),
    src("latency_p99", "ms", None, 0.0),
    src("in_flight", "queries", None, 0.0),
];

impl GraphDb {
    /// One second of the forwarder's history at `now`: `values` in
    /// [`DNS_SOURCES`] order (`None`: no forwarder counts, so the series
    /// goes after [`GRACE`] seconds). Nothing is allocated once the series
    /// exists.
    pub fn sample_dns(&mut self, now: u64, cfg: &Graphing, values: Option<[f32; DNS_SOURCES.len()]>) {
        match values {
            Some(v) => {
                if !self.series.contains_key(DNS) {
                    // The sum over every series only when it is new.
                    let cap = self.cap(cfg);
                    let mut used = self.memory_bytes();
                    if !self.admit(DNS, cap, &mut used) {
                        return;
                    }
                }
                if let Some(k) = self.series.get_mut(DNS) {
                    k.unkept_since = None;
                    k.rrd.update(now, &v);
                }
            }
            None => {
                let Some(k) = self.series.get_mut(DNS) else { return };
                let since = *k.unkept_since.get_or_insert(now);
                if now.saturating_sub(since) >= GRACE {
                    self.series.remove(DNS);
                    if self.persistent
                        && let Some(f) = file_name(DNS)
                    {
                        self.removed.push(f);
                    }
                }
            }
        }
    }
}
