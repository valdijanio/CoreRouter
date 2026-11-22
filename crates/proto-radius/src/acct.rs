//! Accounting-Request contents (RFC 2866, RFC 2869 §5.1–§5.3, RFC 5080
//! §2.3) and the interim schedule.
//!
//! [`Record::encode`] writes the attributes of a Start, Interim-Update,
//! Stop or Accounting-On/Off; the client adds Acct-Delay-Time per
//! transmission (RFC 2866 §5.2) and the authenticator.

use crate::packet::{AttrList, EncodeError, PushAttr, attr};

/// RFC 2866 §5.1 Acct-Status-Type (7/8 from RFC 2866 too).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatusType {
    Start = 1,
    Stop = 2,
    InterimUpdate = 3,
    AccountingOn = 7,
    AccountingOff = 8,
}

/// RFC 2866 §5.6 Acct-Authentic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authentic {
    Radius = 1,
    Local = 2,
    Remote = 3,
}

/// RFC 2866 §5.10 Acct-Terminate-Cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminateCause {
    UserRequest = 1,
    LostCarrier = 2,
    LostService = 3,
    IdleTimeout = 4,
    SessionTimeout = 5,
    AdminReset = 6,
    AdminReboot = 7,
    PortError = 8,
    NasError = 9,
    NasRequest = 10,
    NasReboot = 11,
    PortUnneeded = 12,
    PortPreempted = 13,
    PortSuspended = 14,
    ServiceUnavailable = 15,
    Callback = 16,
    UserError = 17,
    HostRequest = 18,
}

/// Session counters. Octets are 64-bit and split into the 32-bit
/// Octets/Gigawords pair (RFC 2869 §5.1/§5.2); packets saturate at 2³²−1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counters {
    /// From the client (its upload).
    pub input_octets: u64,
    pub output_octets: u64,
    pub input_packets: u64,
    pub output_packets: u64,
    /// Seconds.
    pub session_time: u32,
}

/// What an Accounting-Request says, minus Acct-Delay-Time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub status: StatusType,
    /// RFC 2866 §5.5 (Text, RFC 5080 §2.3.2). Required except for
    /// Accounting-On/Off.
    pub session_id: String,
    pub authentic: Option<Authentic>,
    /// Interim and Stop (RFC 5080 §2.3.1 allows them in interims).
    pub counters: Option<Counters>,
    /// Stop only.
    pub terminate_cause: Option<TerminateCause>,
    /// Event-Timestamp (RFC 2869 §5.3), seconds since 1970.
    pub event_timestamp: Option<u32>,
    /// NAS and session attributes the caller adds (User-Name, NAS-*,
    /// Framed-IP-Address, Class, Calling-Station-Id…).
    pub extra: AttrList,
}

impl Record {
    pub fn new(status: StatusType, session_id: impl Into<String>) -> Self {
        Self {
            status,
            session_id: session_id.into(),
            authentic: None,
            counters: None,
            terminate_cause: None,
            event_timestamp: None,
            extra: AttrList::new(),
        }
    }

    pub fn encode(&self) -> Result<AttrList, EncodeError> {
        let mut l = AttrList::new();
        l.push_u32(attr::ACCT_STATUS_TYPE, self.status as u32)?;
        if !self.session_id.is_empty() {
            l.push_text(attr::ACCT_SESSION_ID, &self.session_id)?;
        }
        if let Some(a) = self.authentic {
            l.push_u32(attr::ACCT_AUTHENTIC, a as u32)?;
        }
        if let Some(c) = self.counters {
            push_counters(&mut l, &c)?;
        }
        if let (StatusType::Stop, Some(t)) = (self.status, self.terminate_cause) {
            l.push_u32(attr::ACCT_TERMINATE_CAUSE, t as u32)?;
        }
        if let Some(ts) = self.event_timestamp {
            l.push_u32(attr::EVENT_TIMESTAMP, ts)?;
        }
        for a in self.extra.iter() {
            l.push(a.typ, a.value)?;
        }
        Ok(l)
    }
}

/// RFC 2869 §5.1/§5.2: low 32 bits in Acct-*-Octets, the wraps in
/// Acct-*-Gigawords (sent only when non-zero).
pub fn push_counters(l: &mut AttrList, c: &Counters) -> Result<(), EncodeError> {
    let sat = |v: u64| u32::try_from(v).unwrap_or(u32::MAX);
    l.push_u32(attr::ACCT_SESSION_TIME, c.session_time)?;
    l.push_u32(attr::ACCT_INPUT_OCTETS, c.input_octets as u32)?;
    l.push_u32(attr::ACCT_OUTPUT_OCTETS, c.output_octets as u32)?;
    let (gi, go) = (sat(c.input_octets >> 32), sat(c.output_octets >> 32));
    if gi != 0 {
        l.push_u32(attr::ACCT_INPUT_GIGAWORDS, gi)?;
    }
    if go != 0 {
        l.push_u32(attr::ACCT_OUTPUT_GIGAWORDS, go)?;
    }
    l.push_u32(attr::ACCT_INPUT_PACKETS, sat(c.input_packets))?;
    l.push_u32(attr::ACCT_OUTPUT_PACKETS, sat(c.output_packets))?;
    Ok(())
}

/// Read the 64-bit octet counters back (server side).
pub fn octets(p: &crate::Packet<'_>) -> (u64, u64) {
    let get = |t| u64::from(p.attr_u32(t).unwrap_or(0));
    (
        get(attr::ACCT_INPUT_GIGAWORDS) << 32 | get(attr::ACCT_INPUT_OCTETS),
        get(attr::ACCT_OUTPUT_GIGAWORDS) << 32 | get(attr::ACCT_OUTPUT_OCTETS),
    )
}

/// RFC 2869 §5.16: Acct-Interim-Interval "MUST NOT be smaller than 60"
/// and "SHOULD NOT be smaller than 600".
pub const MIN_INTERIM_SECS: u32 = 60;

/// Interim-Update schedule with jitter.
///
/// After a mass reconnect (an OLT reboot, say) thousands of sessions start
/// in the same second; with a fixed interval their interims would hit the
/// server together forever. Each session gets a fixed offset derived from
/// its key, spread over `spread_pct` % of the interval, so the load is flat
/// from the first round on and stays deterministic (testable, and the same
/// after a daemon restart).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterimSchedule {
    interval_ms: u64,
    offset_ms: u64,
}

impl InterimSchedule {
    /// `interval_secs` is clamped to [`MIN_INTERIM_SECS`]; `spread_pct` to
    /// 0..=100 (RFC 5080 §2.2.1 asks for jitter against synchronization).
    pub fn new(interval_secs: u32, spread_pct: u8, session_key: u64) -> Self {
        let interval_ms = u64::from(interval_secs.max(MIN_INTERIM_SECS)) * 1000;
        let span = interval_ms * u64::from(spread_pct.min(100)) / 100;
        let offset_ms = if span == 0 {
            0
        } else {
            mix(session_key) % span
        };
        Self {
            interval_ms,
            offset_ms,
        }
    }

    pub fn interval_ms(&self) -> u64 {
        self.interval_ms
    }

    /// When the `n`-th interim (1-based) is due, for a session started at
    /// `start_ms`. The first one comes `offset` earlier than a full
    /// interval, never later, so no session waits longer than configured.
    pub fn due(&self, start_ms: u64, n: u64) -> u64 {
        start_ms
            .saturating_add(self.interval_ms.saturating_mul(n))
            .saturating_sub(self.offset_ms)
    }

    /// The first due time strictly after `now_ms`.
    pub fn next_after(&self, start_ms: u64, now_ms: u64) -> u64 {
        if now_ms < self.due(start_ms, 1) {
            return self.due(start_ms, 1);
        }
        let n = (now_ms + self.offset_ms - start_ms) / self.interval_ms + 1;
        self.due(start_ms, n)
    }
}

/// SplitMix64 finalizer: spreads sequential keys over the range.
pub(crate) fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Builder, Code};
    use proptest::prelude::*;

    #[test]
    fn stop_record_splits_gigawords() {
        let mut r = Record::new(StatusType::Stop, "PPP-1");
        r.counters = Some(Counters {
            input_octets: (5u64 << 32) + 7,
            output_octets: 9,
            input_packets: u64::MAX,
            output_packets: 3,
            session_time: 3600,
        });
        r.terminate_cause = Some(TerminateCause::AdminReset);
        let l = r.encode().unwrap();
        let mut b = Builder::new(Code::AccountingRequest, 0);
        b.extend(&l).unwrap();
        let bytes = b.into_unsigned();
        let p = crate::Packet::parse(&bytes).unwrap();
        assert_eq!(octets(&p), ((5u64 << 32) + 7, 9));
        assert_eq!(p.attr(attr::ACCT_OUTPUT_GIGAWORDS), None);
        assert_eq!(p.attr_u32(attr::ACCT_INPUT_PACKETS), Some(u32::MAX));
        assert_eq!(p.attr_u32(attr::ACCT_TERMINATE_CAUSE), Some(6));
        // Terminate-Cause only in Stop.
        r.status = StatusType::InterimUpdate;
        let l = r.encode().unwrap();
        assert!(l.iter().all(|a| a.typ != attr::ACCT_TERMINATE_CAUSE));
    }

    #[test]
    fn interims_are_spread_and_never_late() {
        let start = 1_000_000;
        let mut firsts: Vec<u64> = (0..1000)
            .map(|k| InterimSchedule::new(300, 50, k).due(start, 1))
            .collect();
        firsts.sort_unstable();
        let lo = start + 150_000;
        let hi = start + 300_000;
        assert!(firsts.iter().all(|&d| (lo..=hi).contains(&d)));
        // Spread: no 1-second bucket has more than 2% of the sessions.
        let mut buckets = std::collections::HashMap::new();
        for d in &firsts {
            *buckets.entry(d / 1000).or_insert(0) += 1;
        }
        assert!(buckets.values().all(|&n| n <= 20), "{buckets:?}");
        // Minimum interval of RFC 2869 §5.16.
        assert_eq!(InterimSchedule::new(5, 0, 1).interval_ms(), 60_000);
    }

    proptest! {
        #[test]
        fn next_after_is_strictly_later_and_on_schedule(
            secs in 60u32..100_000, pct in 0u8..=100, key: u64,
            start in 0u64..1u64 << 40, delta in 0u64..1u64 << 36,
        ) {
            let s = InterimSchedule::new(secs, pct, key);
            let now = start + delta;
            let next = s.next_after(start, now);
            prop_assert!(next > now);
            prop_assert!(next - now <= s.interval_ms());
            prop_assert_eq!((next + s.offset_ms - start) % s.interval_ms(), 0);
        }
    }
}
