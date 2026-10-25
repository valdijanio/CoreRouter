//! The server's counters (`ip.dhcp-server.statistics.print`, `/metrics`):
//! messages by type, drops by reason, ACKs per second with the peak, and
//! the processing time of each reply as a histogram (p50/p99).

use serde::Serialize;

use super::request::Kind;

/// Why a message got no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Drop {
    /// Not a DHCP request (bad length, no cookie, a bad option).
    Malformed,
    /// A BOOTP request without a message type (not served).
    Bootp,
    /// No enabled server on that interface (or for that relay).
    NoServer,
    /// The client sent more than `client_rate_limit` messages a second.
    RateLimited,
    /// The MAC holds `client_mac_limit` leases already.
    MacLimit,
    /// No free address in the pool (nor in its `next_pool`s).
    PoolExhausted,
    /// A static-only server and a client without a static lease.
    StaticOnly,
    /// An address it cannot have, and the server is not authoritative (yet).
    NotAuthoritative,
    /// A REQUEST that chose another server (normal with two servers).
    OtherServer,
    /// A retransmission while its address is being probed.
    Probing,
    /// A message type a server never acts on (OFFER, ACK…, as a request).
    Unexpected,
    /// A retransmission while the client's authorization is asked (IPoE,
    /// G4.3f), or too many waiting.
    Authorizing,
    /// The client was refused (RADIUS reject, no secret) a moment ago.
    Rejected,
}

impl Drop {
    pub const ALL: [Self; 13] = [
        Self::Malformed,
        Self::Bootp,
        Self::NoServer,
        Self::RateLimited,
        Self::MacLimit,
        Self::PoolExhausted,
        Self::StaticOnly,
        Self::NotAuthoritative,
        Self::OtherServer,
        Self::Probing,
        Self::Unexpected,
        Self::Authorizing,
        Self::Rejected,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Bootp => "bootp",
            Self::NoServer => "no-server",
            Self::RateLimited => "rate-limited",
            Self::MacLimit => "mac-limit",
            Self::PoolExhausted => "pool-exhausted",
            Self::StaticOnly => "static-only",
            Self::NotAuthoritative => "not-authoritative",
            Self::OtherServer => "other-server",
            Self::Probing => "probing",
            Self::Unexpected => "unexpected",
            Self::Authorizing => "authorizing",
            Self::Rejected => "rejected",
        }
    }

    /// Whether the drop points at a problem (and not at normal life: a
    /// client picking another server, a retransmission while probing).
    pub fn is_problem(self) -> bool {
        !matches!(self, Self::OtherServer | Self::Probing | Self::Authorizing)
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|d| *d == self).unwrap_or(0)
    }
}

const KINDS: usize = 8;
/// Seconds of ACK history (the "ACK/s" sparkline).
pub const ACK_WINDOW: usize = 60;
/// Histogram bucket upper bounds, microseconds (≈ ×2 steps).
pub const BUCKETS_US: [u64; 18] = [
    25,
    50,
    100,
    200,
    400,
    800,
    1_600,
    3_200,
    6_400,
    12_800,
    25_600,
    51_200,
    102_400,
    204_800,
    409_600,
    819_200,
    1_638_400,
    u64::MAX,
];

#[derive(Debug, Clone)]
pub struct Stats {
    pub received: [u64; KINDS],
    pub sent: [u64; KINDS],
    pub dropped: [u64; Drop::ALL.len()],
    /// ARP probes sent and the conflicts they (or DECLINEs) found.
    pub probes: u64,
    pub conflicts: u64,
    /// Replies from other servers heard where an alert watches.
    pub rogue_replies: u64,
    /// Authorizations (IPoE, G4.3f): asked, accepted, rejected, and asked
    /// without an answer in time.
    pub auth_asked: u64,
    pub auth_accepted: u64,
    pub auth_rejected: u64,
    pub auth_timeouts: u64,
    /// Messages served without a rate-limit bucket (the table was full of
    /// clients still counting: a storm larger than `MAX_CLIENTS_TRACKED`).
    pub untracked: u64,
    /// ACKs per second: `acks[s % 60]` for second `s`.
    acks: [u32; ACK_WINDOW],
    acks_at: [u64; ACK_WINDOW],
    pub peak_acks: u32,
    pub peak_at: u64,
    latency: [u64; BUCKETS_US.len()],
    latency_sum_us: u64,
    /// Unix time of the last reset.
    pub since: u64,
}

fn slot(k: Kind) -> usize {
    usize::from(k.code().saturating_sub(1)).min(KINDS - 1)
}

impl Stats {
    pub fn new(now: u64) -> Self {
        Self {
            received: [0; KINDS],
            sent: [0; KINDS],
            dropped: [0; Drop::ALL.len()],
            probes: 0,
            conflicts: 0,
            rogue_replies: 0,
            auth_asked: 0,
            auth_accepted: 0,
            auth_rejected: 0,
            auth_timeouts: 0,
            untracked: 0,
            acks: [0; ACK_WINDOW],
            acks_at: [0; ACK_WINDOW],
            peak_acks: 0,
            peak_at: 0,
            latency: [0; BUCKETS_US.len()],
            latency_sum_us: 0,
            since: now,
        }
    }

    pub fn got(&mut self, k: Kind) {
        if let Some(n) = self.received.get_mut(slot(k)) {
            *n = n.saturating_add(1);
        }
    }

    pub fn sent(&mut self, k: Kind, now: u64) {
        if let Some(n) = self.sent.get_mut(slot(k)) {
            *n = n.saturating_add(1);
        }
        if k == Kind::Ack {
            let i = usize::try_from(now % ACK_WINDOW as u64).unwrap_or(0);
            if let (Some(n), Some(at)) = (self.acks.get_mut(i), self.acks_at.get_mut(i)) {
                if *at != now {
                    *at = now;
                    *n = 0;
                }
                *n = n.saturating_add(1);
                if *n > self.peak_acks {
                    self.peak_acks = *n;
                    self.peak_at = now;
                }
            }
        }
    }

    pub fn drop(&mut self, d: Drop) {
        if let Some(n) = self.dropped.get_mut(d.index()) {
            *n = n.saturating_add(1);
        }
    }

    pub fn received_of(&self, k: Kind) -> u64 {
        self.received.get(slot(k)).copied().unwrap_or(0)
    }

    pub fn sent_of(&self, k: Kind) -> u64 {
        self.sent.get(slot(k)).copied().unwrap_or(0)
    }

    pub fn dropped_of(&self, d: Drop) -> u64 {
        self.dropped.get(d.index()).copied().unwrap_or(0)
    }

    /// A reply took `us` microseconds from the request's arrival.
    pub fn latency(&mut self, us: u64) {
        let i = BUCKETS_US.iter().position(|b| us <= *b).unwrap_or(0);
        if let Some(n) = self.latency.get_mut(i) {
            *n = n.saturating_add(1);
        }
        self.latency_sum_us = self.latency_sum_us.saturating_add(us);
    }

    /// The bucket bound under which fraction `q` of the replies fall
    /// (microseconds); `None` before any.
    pub fn quantile_us(&self, q: f64) -> Option<u64> {
        let total: u64 = self.latency.iter().sum();
        if total == 0 {
            return None;
        }
        let want = (q * total as f64).ceil() as u64;
        let mut seen = 0;
        for (n, bound) in self.latency.iter().zip(BUCKETS_US) {
            seen += n;
            if seen >= want.max(1) {
                return Some(bound);
            }
        }
        None
    }

    pub fn latency_count(&self) -> u64 {
        self.latency.iter().sum()
    }

    pub fn latency_sum_us(&self) -> u64 {
        self.latency_sum_us
    }

    /// (bound µs, cumulative count) for Prometheus' histogram.
    pub fn latency_buckets(&self) -> Vec<(u64, u64)> {
        let mut acc = 0;
        BUCKETS_US
            .iter()
            .zip(self.latency)
            .map(|(b, n)| {
                acc += n;
                (*b, acc)
            })
            .collect()
    }

    /// ACKs per second over the last `ACK_WINDOW` seconds, oldest first.
    pub fn acks_per_sec(&self, now: u64) -> Vec<u32> {
        (0..ACK_WINDOW as u64)
            .rev()
            .map(|back| {
                let s = now.saturating_sub(back);
                let i = usize::try_from(s % ACK_WINDOW as u64).unwrap_or(0);
                match (self.acks.get(i), self.acks_at.get(i)) {
                    (Some(n), Some(at)) if *at == s => *n,
                    _ => 0,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acks_per_second_and_the_peak() {
        let mut s = Stats::new(100);
        for _ in 0..3 {
            s.sent(Kind::Ack, 100);
        }
        s.sent(Kind::Ack, 101);
        s.sent(Kind::Offer, 101);
        assert_eq!(s.peak_acks, 3);
        assert_eq!(s.peak_at, 100);
        let w = s.acks_per_sec(101);
        assert_eq!(w.len(), ACK_WINDOW);
        assert_eq!(&w[ACK_WINDOW - 2..], &[3, 1]);
        // A minute later the slot is reused, not added to.
        s.sent(Kind::Ack, 160);
        assert_eq!(*s.acks_per_sec(160).last().unwrap(), 1);
        assert_eq!(s.sent_of(Kind::Offer), 1);
    }

    #[test]
    fn quantiles_come_from_the_buckets() {
        let mut s = Stats::new(0);
        assert_eq!(s.quantile_us(0.99), None);
        for _ in 0..98 {
            s.latency(30);
        }
        s.latency(5_000);
        s.latency(5_000);
        assert_eq!(s.quantile_us(0.5), Some(50));
        assert_eq!(s.quantile_us(0.99), Some(6_400));
        assert_eq!(s.latency_buckets().last().unwrap().1, 100);
    }
}
