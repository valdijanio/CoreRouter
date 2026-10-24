//! `Mikrotik-Rate-Limit` (vendor 14988, type 8) and the PPP profile
//! `rate-limit`, one type for both.
//!
//! MikroTik's RADIUS manual gives the syntax
//! `rx-rate[/tx-rate] [rx-burst-rate[/tx-burst-rate] [rx-burst-threshold[/tx-burst-threshold]
//! [rx-burst-time[/tx-burst-time] [priority] [rx-rate-min[/tx-rate-min]]]]`,
//! "from the point of view of the router (so rx is client upload, and tx is
//! client download)", with these defaults: a missing tx equals rx; missing
//! burst thresholds are the rates; a missing burst time is 1 s; priority is
//! 1..8 (8 lowest); missing minimums are the rates; a minimum cannot exceed
//! its rate. Rates take a `k` (×1000), `M` (×10⁶) or `G` (×10⁹) suffix.
//!
//! [`RateLimit`] keeps which fields were written, so `parse(format(x)) == x`
//! and an operator's string is shown back as written.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

/// A value per direction. `rx` is the client's upload, `tx` its download.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pair<T> {
    pub rx: T,
    pub tx: T,
}

impl<T: Copy> Pair<T> {
    pub fn both(v: T) -> Self {
        Self { rx: v, tx: v }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RateLimit {
    /// Bits per second (the queue's max-limit).
    pub rate: Pair<u64>,
    pub burst_rate: Option<Pair<u64>>,
    pub burst_threshold: Option<Pair<u64>>,
    /// Seconds.
    pub burst_time: Option<Pair<u32>>,
    /// 1 (highest) to 8 (lowest).
    pub priority: Option<u8>,
    /// The queue's limit-at.
    pub min_rate: Option<Pair<u64>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RateLimitError {
    #[error("empty rate-limit")]
    Empty,
    #[error("more than six fields")]
    TooManyFields,
    #[error("bad rate {0:?} (number with optional k, M or G)")]
    BadRate(String),
    #[error("bad burst time {0:?} (seconds)")]
    BadTime(String),
    #[error("priority {0:?} is not 1..8")]
    BadPriority(String),
    #[error("minimum rate above the rate")]
    MinAboveRate,
    #[error("{0:?} must not have a field after it missing")]
    Gap(&'static str),
    #[error("rate-limit longer than 253 bytes")]
    TooLong,
}

/// Longest accepted string: one RADIUS attribute value.
const MAX_LEN: usize = 253;
/// 10 Tbit/s: anything above is a typo, not a plan.
const MAX_RATE: u64 = 10_000_000_000_000;

fn parse_rate(s: &str) -> Result<u64, RateLimitError> {
    let bad = || RateLimitError::BadRate(s.chars().take(32).collect());
    let (num, mul) = if let Some(n) = s.strip_suffix(['k', 'K']) {
        (n, 1_000)
    } else if let Some(n) = s.strip_suffix(['m', 'M']) {
        (n, 1_000_000)
    } else if let Some(n) = s.strip_suffix(['g', 'G']) {
        (n, 1_000_000_000)
    } else {
        (s, 1)
    };
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) || num.len() > 14 {
        return Err(bad());
    }
    let n: u64 = num.parse().map_err(|_| bad())?;
    n.checked_mul(mul)
        .filter(|&v| v <= MAX_RATE)
        .ok_or_else(bad)
}

fn parse_time(s: &str) -> Result<u32, RateLimitError> {
    let num = s.strip_suffix('s').unwrap_or(s);
    if num.is_empty() || num.len() > 9 || !num.bytes().all(|b| b.is_ascii_digit()) {
        return Err(RateLimitError::BadTime(s.chars().take(32).collect()));
    }
    num.parse()
        .map_err(|_| RateLimitError::BadTime(s.chars().take(32).collect()))
}

fn pair<T: Copy>(
    s: &str,
    one: impl Fn(&str) -> Result<T, RateLimitError>,
) -> Result<Pair<T>, RateLimitError> {
    match s.split_once('/') {
        Some((rx, tx)) => Ok(Pair {
            rx: one(rx)?,
            tx: one(tx)?,
        }),
        None => Ok(Pair::both(one(s)?)),
    }
}

impl FromStr for RateLimit {
    type Err = RateLimitError;

    fn from_str(s: &str) -> Result<Self, RateLimitError> {
        if s.len() > MAX_LEN {
            return Err(RateLimitError::TooLong);
        }
        let mut f = s.split_ascii_whitespace();
        let rate = pair(f.next().ok_or(RateLimitError::Empty)?, parse_rate)?;
        let mut r = Self {
            rate,
            ..Self::default()
        };
        r.burst_rate = f.next().map(|t| pair(t, parse_rate)).transpose()?;
        r.burst_threshold = f.next().map(|t| pair(t, parse_rate)).transpose()?;
        r.burst_time = f.next().map(|t| pair(t, parse_time)).transpose()?;
        r.priority = f
            .next()
            .map(|t| match t.parse::<u8>() {
                Ok(p @ 1..=8) => Ok(p),
                _ => Err(RateLimitError::BadPriority(t.chars().take(32).collect())),
            })
            .transpose()?;
        r.min_rate = f.next().map(|t| pair(t, parse_rate)).transpose()?;
        if f.next().is_some() {
            return Err(RateLimitError::TooManyFields);
        }
        r.validate()?;
        Ok(r)
    }
}

fn fmt_rate(v: u64) -> String {
    for (div, suffix) in [(1_000_000_000, "G"), (1_000_000, "M"), (1_000, "k")] {
        if v != 0 && v.is_multiple_of(div) {
            return format!("{}{suffix}", v / div);
        }
    }
    v.to_string()
}

fn fmt_pair<T: Copy + PartialEq>(p: Pair<T>, one: impl Fn(T) -> String) -> String {
    if p.rx == p.tx {
        one(p.rx)
    } else {
        format!("{}/{}", one(p.rx), one(p.tx))
    }
}

impl fmt::Display for RateLimit {
    /// The shortest form: `rx/tx` collapses to one value when equal, rates
    /// use the largest exact suffix.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&fmt_pair(self.rate, fmt_rate))?;
        if let Some(b) = self.burst_rate {
            write!(f, " {}", fmt_pair(b, fmt_rate))?;
        }
        if let Some(t) = self.burst_threshold {
            write!(f, " {}", fmt_pair(t, fmt_rate))?;
        }
        if let Some(t) = self.burst_time {
            write!(f, " {}", fmt_pair(t, |v: u32| v.to_string()))?;
        }
        if let Some(p) = self.priority {
            write!(f, " {p}")?;
        }
        if let Some(m) = self.min_rate {
            write!(f, " {}", fmt_pair(m, fmt_rate))?;
        }
        Ok(())
    }
}

impl RateLimit {
    /// Only the rate (`"10M/20M"`).
    pub fn new(rx: u64, tx: u64) -> Self {
        Self {
            rate: Pair { rx, tx },
            ..Self::default()
        }
    }

    /// Positional rules: a field needs all the ones before it; minimums
    /// cannot exceed the rates; priority 1..8.
    pub fn validate(&self) -> Result<(), RateLimitError> {
        let given = [
            self.burst_rate.is_some(),
            self.burst_threshold.is_some(),
            self.burst_time.is_some(),
            self.priority.is_some(),
            self.min_rate.is_some(),
        ];
        const NAMES: [&str; 5] = [
            "burst-rate",
            "burst-threshold",
            "burst-time",
            "priority",
            "rate-min",
        ];
        for (i, w) in given.windows(2).enumerate() {
            if let [false, true] = w {
                return Err(RateLimitError::Gap(
                    NAMES.get(i).copied().unwrap_or("field"),
                ));
            }
        }
        if self.priority.is_some_and(|p| !(1..=8).contains(&p)) {
            return Err(RateLimitError::BadPriority(format!("{:?}", self.priority)));
        }
        let rates = [
            Some(self.rate),
            self.burst_rate,
            self.burst_threshold,
            self.min_rate,
        ];
        if rates
            .iter()
            .flatten()
            .any(|p| p.rx > MAX_RATE || p.tx > MAX_RATE)
        {
            return Err(RateLimitError::BadRate("above 10T".into()));
        }
        if let Some(m) = self.min_rate
            && (m.rx > self.rate.rx || m.tx > self.rate.tx)
        {
            return Err(RateLimitError::MinAboveRate);
        }
        Ok(())
    }

    /// Burst threshold in force (the rate when not written).
    pub fn effective_burst_threshold(&self) -> Pair<u64> {
        self.burst_threshold.unwrap_or(self.rate)
    }

    /// Burst time in force (1 s when not written).
    pub fn effective_burst_time(&self) -> Pair<u32> {
        self.burst_time.unwrap_or(Pair::both(1))
    }

    /// Priority in force (8 when not written).
    pub fn effective_priority(&self) -> u8 {
        self.priority.unwrap_or(8)
    }

    /// Minimum (limit-at) in force: the rate when not written, as the
    /// MikroTik manual says.
    pub fn effective_min_rate(&self) -> Pair<u64> {
        self.min_rate.unwrap_or(self.rate)
    }

    /// Bursting is on when a burst rate above the rate is written.
    pub fn bursts(&self) -> bool {
        self.burst_rate
            .is_some_and(|b| b.rx > self.rate.rx || b.tx > self.rate.tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn rl(s: &str) -> RateLimit {
        s.parse().unwrap()
    }

    /// The examples of MikroTik's RADIUS manual.
    #[test]
    fn manual_examples() {
        let a = rl("128k");
        assert_eq!(a.rate, Pair::both(128_000));
        assert!(!a.bursts());
        let b = rl("64k/128M");
        assert_eq!(
            b.rate,
            Pair {
                rx: 64_000,
                tx: 128_000_000
            }
        );
        let c = rl("64k 256k");
        assert_eq!(c.burst_rate, Some(Pair::both(256_000)));
        assert_eq!(c.effective_burst_threshold(), Pair::both(64_000));
        assert_eq!(c.effective_burst_time(), Pair::both(1));
        let d = rl("64k/64k 256k/256k 128k/128k 10/10");
        assert_eq!(d.effective_burst_threshold(), Pair::both(128_000));
        assert_eq!(d.effective_burst_time(), Pair::both(10));
        assert_eq!(d.to_string(), "64k 256k 128k 10");
    }

    #[test]
    fn full_form_with_priority_and_minimum() {
        let r = rl("10M/20M 15M/30M 8M/16M 8/8 5 2M/4M");
        assert_eq!(r.priority, Some(5));
        assert_eq!(
            r.min_rate,
            Some(Pair {
                rx: 2_000_000,
                tx: 4_000_000
            })
        );
        assert_eq!(r.to_string(), "10M/20M 15M/30M 8M/16M 8 5 2M/4M");
        assert_eq!(rl("1G 0 0 0 1").effective_priority(), 1);
        assert_eq!(rl("1500k").to_string(), "1500k");
        assert_eq!(rl("1000000").to_string(), "1M");
        assert_eq!(rl("10m  20m 10m 20s").to_string(), "10M 20M 10M 20");
    }

    #[test]
    fn errors() {
        use RateLimitError as E;
        assert_eq!("".parse::<RateLimit>(), Err(E::Empty));
        assert!(matches!("10X".parse::<RateLimit>(), Err(E::BadRate(_))));
        assert!(matches!("k".parse::<RateLimit>(), Err(E::BadRate(_))));
        assert!(matches!(
            "1M 2M 1M 1 9".parse::<RateLimit>(),
            Err(E::BadPriority(_))
        ));
        assert!(matches!(
            "1M 2M 1M x".parse::<RateLimit>(),
            Err(E::BadTime(_))
        ));
        assert_eq!("1M 2M 1M 1 8 2M".parse::<RateLimit>(), Err(E::MinAboveRate));
        assert_eq!("1M 1 1 1 1 1 1".parse::<RateLimit>(), Err(E::TooManyFields));
        assert!(matches!(
            "99999999999999G".parse::<RateLimit>(),
            Err(E::BadRate(_))
        ));
        assert_eq!("1".repeat(300).parse::<RateLimit>(), Err(E::TooLong));
        let gap = RateLimit {
            priority: Some(1),
            ..RateLimit::new(1, 1)
        };
        assert_eq!(gap.validate(), Err(E::Gap("burst-time")));
    }

    fn rate() -> impl Strategy<Value = u64> {
        prop_oneof![
            0u64..2_000_000,
            (1u64..10_000).prop_map(|v| v * 1_000),
            (1u64..10_000).prop_map(|v| v * 1_000_000),
            (1u64..10_000).prop_map(|v| v * 1_000_000_000),
        ]
    }

    fn pr() -> impl Strategy<Value = Pair<u64>> {
        (rate(), rate()).prop_map(|(rx, tx)| Pair { rx, tx })
    }

    fn any_rl() -> impl Strategy<Value = RateLimit> {
        (
            pr(),
            0usize..=5,
            pr(),
            pr(),
            (0u32..100_000, 0u32..100_000),
            1u8..=8,
            (0u64..=1000, 0u64..=1000),
        )
            .prop_map(|(rate, n, br, bt, (t1, t2), p, (m1, m2))| RateLimit {
                rate,
                burst_rate: (n >= 1).then_some(br),
                burst_threshold: (n >= 2).then_some(bt),
                burst_time: (n >= 3).then_some(Pair { rx: t1, tx: t2 }),
                priority: (n >= 4).then_some(p),
                min_rate: (n >= 5).then_some(Pair {
                    rx: rate.rx * m1 / 1000,
                    tx: rate.tx * m2 / 1000,
                }),
            })
    }

    proptest! {
        #[test]
        fn format_then_parse_is_identity(r in any_rl()) {
            let s = r.to_string();
            prop_assert!(s.len() <= MAX_LEN);
            prop_assert_eq!(s.parse::<RateLimit>(), Ok(r));
        }

        #[test]
        fn parse_never_panics_and_canonical_form_is_stable(s in "[0-9kKmMgGs/ x]{0,60}") {
            if let Ok(r) = s.parse::<RateLimit>() {
                let canon = r.to_string();
                prop_assert_eq!(canon.parse::<RateLimit>(), Ok(r));
                prop_assert_eq!(canon.parse::<RateLimit>().map(|x| x.to_string()), Ok(canon));
            }
        }

        #[test]
        fn arbitrary_text_never_panics(s in "\\PC{0,300}") {
            let _ = s.parse::<RateLimit>();
        }
    }
}
