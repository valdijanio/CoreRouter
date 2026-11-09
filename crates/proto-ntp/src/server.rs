//! The server half (G4.6c): which requests get an answer, what the answer
//! says, and the per-source rate limit. Pure: the daemon owns the sockets and
//! passes the time.
//!
//! - A request is mode 3 and nothing else (RFC 5905 §9.2, Figure 20). Modes 6
//!   and 7 are dropped in silence: they are the amplification vector of
//!   RFC 9327 §6. Symmetric and broadcast modes are not served.
//! - The reply is always the 48-byte header (RFC 5905 §14, Figure 31), so it
//!   is never larger than the request, and extension fields and MACs are
//!   ignored and never copied (RFC 7822 §4).
//! - Over the rate: a RATE kiss (RFC 5905 §7.4), itself limited to one per
//!   [`KISS_INTERVAL_MS`] per source; then silence.

use std::hash::BuildHasher;
use std::net::IpAddr;

use md5::{Digest, Md5};

use crate::{HEADER_LEN, LEAP_ALARM, MODE_CLIENT, Packet, Timestamp};

/// RFC 5905 §7.3 mode 5.
pub const MODE_BROADCAST: u8 = 5;
/// RFC 5905 Figure 6: MAXDIST = 1 s. A clock this uncertain is not served:
/// the clients' selection would discard it anyway.
pub const MAX_ROOT_DISTANCE_NANOS: i64 = 1_000_000_000;
/// RFC 5905 Figure 6: PHI = 15 ppm, how fast the dispersion grows.
pub const PHI_NANOS_PER_SEC: i64 = 15_000;
/// Average time between requests a source may keep up. A client at the
/// fastest legal poll (64 s) uses 1/32 of it, so 32 clients fit behind one
/// address (**estimado** for a NAT).
pub const RATE_INTERVAL_MS: u64 = 2_000;
/// How far ahead of that a source may run: `iburst` is 8 packets 2 s apart.
pub const RATE_BURST: u64 = 16;
/// One RATE kiss per this, per source: a spoofed source must not turn the
/// server into a stream of packets at the victim.
pub const KISS_INTERVAL_MS: u64 = 10_000;
/// Rate-limit slots: one per source, direct-mapped. 24 bytes each.
pub const RATE_SLOTS: usize = 1 << 14;

/// Why a datagram gets no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Under 48 bytes, or what follows the header is not whole words
    /// (RFC 7822 §3: extension fields and MACs are aligned to 4 octets).
    Malformed,
    /// Not mode 3. Modes 6 and 7 are the known abuse (RFC 9327 §6).
    NotARequest,
    /// Version outside 1..=4.
    Version,
    /// A zero Transmit Timestamp: nothing to copy to Origin.
    NoTimestamp,
}

/// The checks on a request, before anything else costs time.
pub fn parse_request(bytes: &[u8]) -> Result<Packet, Refused> {
    let packet = Packet::decode(bytes).map_err(|_| Refused::Malformed)?;
    if !bytes.len().saturating_sub(HEADER_LEN).is_multiple_of(4) {
        return Err(Refused::Malformed);
    }
    if packet.mode != MODE_CLIENT {
        return Err(Refused::NotARequest);
    }
    if !(1..=4).contains(&packet.version) {
        return Err(Refused::Version);
    }
    if packet.transmit.is_zero() {
        return Err(Refused::NoTimestamp);
    }
    Ok(packet)
}

/// The system variables a reply carries (RFC 5905 §11.2, Figure 31).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemVars {
    pub leap: u8,
    pub stratum: u8,
    pub precision: i8,
    pub root_delay_nanos: i64,
    pub root_dispersion_nanos: i64,
    pub reference_id: [u8; 4],
    /// When the clock was last set, Unix nanoseconds.
    pub reference_nanos: i128,
    /// RFC 5905 §14 "the dispersion field ... must be updated": it grows
    /// with PHI since the reference. A local clock has no such age.
    pub ages: bool,
}

impl SystemVars {
    /// The dispersion now (RFC 5905 §11.2: `rootdisp + PHI × age`).
    pub fn dispersion_at(&self, now_nanos: i128) -> i64 {
        if !self.ages {
            return self.root_dispersion_nanos;
        }
        let age_secs = (now_nanos - self.reference_nanos).max(0) / 1_000_000_000;
        let age = i64::try_from(age_secs).unwrap_or(i64::MAX);
        self.root_dispersion_nanos
            .saturating_add(age.saturating_mul(PHI_NANOS_PER_SEC))
    }

    /// RFC 5905 §11.2 root distance: past [`MAX_ROOT_DISTANCE_NANOS`] the
    /// clock has been alone for too long and is not served.
    pub fn usable_at(&self, now_nanos: i128) -> bool {
        let distance = (self.root_delay_nanos / 2).saturating_add(self.dispersion_at(now_nanos));
        distance < MAX_ROOT_DISTANCE_NANOS
    }
}

/// NTP short format (16.16 seconds), rounded up: a server never claims to be
/// better than it is.
pub fn short_format(nanos: i64) -> u32 {
    let nanos = i128::from(nanos.max(0));
    let units = ((nanos << 16) + 999_999_999) / 1_000_000_000;
    u32::try_from(units).unwrap_or(u32::MAX)
}

/// RFC 5905 §14 Figure 31 (`fast_xmit`): `rx` is when the request arrived,
/// `tx` when this goes out.
pub fn reply(request: &Packet, sys: &SystemVars, rx_nanos: i128, tx_nanos: i128) -> Packet {
    Packet {
        leap: sys.leap,
        version: request.version,
        mode: crate::MODE_SERVER,
        stratum: sys.stratum,
        poll: request.poll,
        precision: sys.precision,
        root_delay: short_format(sys.root_delay_nanos),
        root_dispersion: short_format(sys.dispersion_at(tx_nanos)),
        reference_id: sys.reference_id,
        reference: Timestamp::from_unix_nanos(sys.reference_nanos),
        origin: request.transmit,
        receive: Timestamp::from_unix_nanos(rx_nanos),
        transmit: Timestamp::from_unix_nanos(tx_nanos),
    }
}

/// RFC 5905 §7.4: stratum 0 and the code in the Reference ID, with leap 3
/// (Appendix A.5 and what ntpd sends). The client must see its own Origin to
/// believe it (RFC 8633 §5.4); it must discard the other timestamps.
pub fn kiss(request: &Packet, code: &[u8; 4], rx_nanos: i128, tx_nanos: i128) -> Packet {
    Packet {
        leap: LEAP_ALARM,
        version: request.version,
        mode: crate::MODE_SERVER,
        stratum: 0,
        poll: request.poll,
        precision: 0,
        root_delay: 0,
        root_dispersion: 0,
        reference_id: *code,
        reference: Timestamp(0),
        origin: request.transmit,
        receive: Timestamp::from_unix_nanos(rx_nanos),
        transmit: Timestamp::from_unix_nanos(tx_nanos),
    }
}

/// RFC 5905 §9.2 mode 5: what the clients on the segment hear, with no
/// Origin and no Receive.
pub fn broadcast(sys: &SystemVars, poll: i8, tx_nanos: i128) -> Packet {
    Packet {
        leap: sys.leap,
        version: 4,
        mode: MODE_BROADCAST,
        stratum: sys.stratum,
        poll,
        precision: sys.precision,
        root_delay: short_format(sys.root_delay_nanos),
        root_dispersion: short_format(sys.dispersion_at(tx_nanos)),
        reference_id: sys.reference_id,
        reference: Timestamp::from_unix_nanos(sys.reference_nanos),
        origin: Timestamp(0),
        receive: Timestamp(0),
        transmit: Timestamp::from_unix_nanos(tx_nanos),
    }
}

/// RFC 5905 §7.3: the Reference ID of a synchronized server. IPv4: the source's
/// address. IPv6: the first four octets of the MD5 of the address (there it
/// is only a loop check, not cryptography).
pub fn reference_id_of(ip: IpAddr) -> [u8; 4] {
    match ip.to_canonical() {
        IpAddr::V4(a) => a.octets(),
        IpAddr::V6(a) => {
            let digest = Md5::digest(a.octets());
            let mut id = [0u8; 4];
            for (d, s) in id.iter_mut().zip(digest.iter()) {
                *d = *s;
            }
            id
        }
    }
}

/// True for a source no reply may go to.
pub fn bad_source(ip: IpAddr, port: u16) -> bool {
    if port == 0 {
        return true;
    }
    match ip.to_canonical() {
        IpAddr::V4(a) => a.is_multicast() || a.is_broadcast() || a.is_unspecified(),
        IpAddr::V6(a) => a.is_multicast() || a.is_unspecified(),
    }
}

/// What the limiter says about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Allow,
    /// Over the rate: send a RATE kiss.
    Kiss,
    /// Over the rate, kiss already sent recently: silence.
    Silent,
}

#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    key: u64,
    /// When the source's credit is used up (generic cell rate algorithm).
    full_until_ms: u64,
    next_kiss_ms: u64,
}

/// A fixed table of sources: no allocation per packet and a bound on memory,
/// whatever arrives. Direct-mapped: a colliding source takes the slot, so a
/// flood of forged sources can only make the limiter forget (it never denies
/// someone who did nothing). One per thread, so no lock: `SO_REUSEPORT` sends
/// a client's address and port to the same thread (a client changing port per
/// request may get up to one bucket per thread).
pub struct RateLimiter<S> {
    slots: Vec<Slot>,
    hasher: S,
}

impl<S: BuildHasher> RateLimiter<S> {
    /// `hasher` must be keyed at random, or someone can pick sources that
    /// collide.
    pub fn new(slots: usize, hasher: S) -> Self {
        Self {
            slots: vec![Slot::default(); slots.max(1).next_power_of_two()],
            hasher,
        }
    }

    /// One request from `ip` at `now_ms`. An IPv6 source counts by its /64.
    pub fn check(&mut self, ip: IpAddr, now_ms: u64) -> Limit {
        let key = self.key(ip);
        let mask = self.slots.len().wrapping_sub(1);
        let index = usize::try_from(key).unwrap_or(usize::MAX) & mask;
        let Some(slot) = self.slots.get_mut(index) else {
            return Limit::Allow;
        };
        if slot.key != key {
            *slot = Slot {
                key,
                ..Slot::default()
            };
        }
        let start = slot.full_until_ms.max(now_ms);
        if start.saturating_sub(now_ms) >= RATE_INTERVAL_MS.saturating_mul(RATE_BURST) {
            if now_ms >= slot.next_kiss_ms {
                slot.next_kiss_ms = now_ms.saturating_add(KISS_INTERVAL_MS);
                return Limit::Kiss;
            }
            return Limit::Silent;
        }
        slot.full_until_ms = start.saturating_add(RATE_INTERVAL_MS);
        Limit::Allow
    }

    fn key(&self, ip: IpAddr) -> u64 {
        // Never 0, the empty slot.
        let hash = match ip.to_canonical() {
            IpAddr::V4(a) => self.hasher.hash_one(a.octets()),
            IpAddr::V6(a) => {
                let o = a.octets();
                let mut prefix = [0u8; 8];
                for (d, s) in prefix.iter_mut().zip(o.iter()) {
                    *d = *s;
                }
                self.hasher.hash_one(prefix)
            }
        };
        hash | 1 << 63
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MODE_SERVER, check_reply, sample_of};
    use proptest::prelude::*;
    use std::collections::hash_map::RandomState;

    const NANOS: i128 = 1_000_000_000;
    const T: i128 = 1_794_000_000 * NANOS;

    fn sys() -> SystemVars {
        SystemVars {
            leap: 0,
            stratum: 3,
            precision: -20,
            root_delay_nanos: 10_000_000,
            root_dispersion_nanos: 5_000_000,
            reference_id: [192, 0, 2, 1],
            reference_nanos: T - 100 * NANOS,
            ages: true,
        }
    }

    fn request() -> Packet {
        Packet::client_request(Timestamp::from_unix_nanos(T))
    }

    /// RFC 5905 Figure 31, field by field.
    #[test]
    fn reply_follows_figure_31() {
        let mut req = request();
        req.poll = 7;
        req.version = 3;
        let r = reply(&req, &sys(), T + 1000, T + 2000);
        assert_eq!(r.version, 3, "x.version <- r.version");
        assert_eq!(r.mode, MODE_SERVER);
        assert_eq!(r.poll, 7, "x.poll <- r.poll");
        assert_eq!(r.stratum, 3);
        assert_eq!(r.origin, req.transmit, "x.org <- r.xmt");
        assert_eq!(r.receive, Timestamp::from_unix_nanos(T + 1000));
        assert_eq!(r.transmit, Timestamp::from_unix_nanos(T + 2000));
        assert_eq!(r.reference_id, [192, 0, 2, 1]);
        assert_eq!(r.reference, Timestamp::from_unix_nanos(T - 100 * NANOS));
        // The client side accepts it and computes the same clock.
        assert_eq!(check_reply(req.transmit, &r), Ok(()));
        let s = sample_of(&r, T, T + 3000);
        assert_eq!(s.delay_nanos, 2000);
    }

    /// RFC 5905 §14: the dispersion in the header grows with PHI.
    #[test]
    fn dispersion_grows_at_15_ppm_and_the_clock_expires() {
        let s = sys();
        assert_eq!(s.dispersion_at(s.reference_nanos), 5_000_000);
        assert_eq!(s.dispersion_at(s.reference_nanos + 1000 * NANOS), 20_000_000);
        // A reference in the future (a step back) never subtracts.
        assert_eq!(s.dispersion_at(s.reference_nanos - NANOS), 5_000_000);
        assert!(s.usable_at(s.reference_nanos));
        // delay/2 + disp + 15 ppm × age = 1 s after about 18 hours.
        let hours = |h: i128| s.reference_nanos + h * 3600 * NANOS;
        assert!(s.usable_at(hours(18)));
        assert!(!s.usable_at(hours(19)));
        // A local clock does not age.
        let local = SystemVars { ages: false, ..s };
        assert!(local.usable_at(hours(10_000)));
        assert_eq!(local.dispersion_at(hours(10_000)), 5_000_000);
    }

    #[test]
    fn short_format_rounds_up() {
        assert_eq!(short_format(0), 0);
        assert_eq!(short_format(1), 1);
        assert_eq!(short_format(1_000_000_000), 1 << 16);
        assert_eq!(short_format(-5), 0);
        assert_eq!(short_format(i64::MAX), u32::MAX);
    }

    /// RFC 5905 §7.4; the client's own check reads it as a kiss.
    #[test]
    fn kiss_is_stratum_0_with_the_code_and_our_origin() {
        let req = request();
        let k = kiss(&req, b"RATE", T, T);
        assert_eq!(k.stratum, 0);
        assert_eq!(k.leap, LEAP_ALARM);
        assert_eq!(k.origin, req.transmit);
        assert_eq!(k.kiss_code().as_deref(), Some("RATE"));
        assert_eq!(
            check_reply(req.transmit, &k),
            Err(crate::ReplyError::Kiss("RATE".into()))
        );
    }

    #[test]
    fn broadcast_is_mode_5_without_origin() {
        let b = broadcast(&sys(), 6, T);
        assert_eq!(b.mode, MODE_BROADCAST);
        assert!(b.origin.is_zero() && b.receive.is_zero());
        assert_eq!(b.transmit, Timestamp::from_unix_nanos(T));
    }

    #[test]
    fn only_requests_pass() {
        let good = request().encode();
        assert!(parse_request(&good).is_ok());
        assert_eq!(parse_request(&good[..47]), Err(Refused::Malformed));
        assert_eq!(parse_request(&[]), Err(Refused::Malformed));
        // RFC 9327 §6 / RFC 8633 §3.4: modes 6 and 7 get nothing.
        for mode in [0u8, 1, 2, 4, 5, 6, 7] {
            let mut p = request();
            p.mode = mode;
            assert_eq!(parse_request(&p.encode()), Err(Refused::NotARequest), "{mode}");
        }
        for version in [0u8, 5, 7] {
            let mut p = request();
            p.version = version;
            assert_eq!(parse_request(&p.encode()), Err(Refused::Version), "{version}");
        }
        let mut p = request();
        p.transmit = Timestamp(0);
        assert_eq!(parse_request(&p.encode()), Err(Refused::NoTimestamp));
        // RFC 7822: what follows the header is ignored, if whole words.
        let mut long = good.to_vec();
        long.extend_from_slice(&[0xAA; 28]);
        assert!(parse_request(&long).is_ok());
        long.push(0);
        assert_eq!(parse_request(&long), Err(Refused::Malformed));
    }

    /// No amplification: the same 48 bytes, whatever the request carried.
    #[test]
    fn a_reply_is_never_larger_than_a_request() {
        assert_eq!(reply(&request(), &sys(), T, T).encode().len(), HEADER_LEN);
        assert_eq!(kiss(&request(), b"RATE", T, T).encode().len(), HEADER_LEN);
    }

    #[test]
    fn reference_id_is_the_ipv4_or_an_md5_of_the_ipv6() {
        let v4: IpAddr = "192.0.2.7".parse().unwrap();
        assert_eq!(reference_id_of(v4), [192, 0, 2, 7]);
        let mapped: IpAddr = "::ffff:192.0.2.7".parse().unwrap();
        assert_eq!(reference_id_of(mapped), [192, 0, 2, 7]);
        // MD5 of the 16 octets of 2001:db8::1, computed separately (md5sum).
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(reference_id_of(v6), [0x39, 0xab, 0x9b, 0x37]);
    }

    #[test]
    fn sources_no_reply_may_go_to() {
        for (ip, port) in [
            ("192.0.2.1", 0u16),
            ("224.0.0.1", 123),
            ("255.255.255.255", 123),
            ("0.0.0.0", 123),
            ("ff02::1", 123),
            ("::", 123),
            ("::ffff:224.0.0.1", 123),
        ] {
            assert!(bad_source(ip.parse().unwrap(), port), "{ip}:{port}");
        }
        assert!(!bad_source("192.0.2.1".parse().unwrap(), 40000));
        assert!(!bad_source("2001:db8::1".parse().unwrap(), 123));
    }

    fn limiter() -> RateLimiter<RandomState> {
        RateLimiter::new(RATE_SLOTS, RandomState::new())
    }

    #[test]
    fn a_polite_client_is_never_limited() {
        let mut l = limiter();
        let ip = "192.0.2.1".parse().unwrap();
        // iburst, then every 64 s, for a day.
        for i in 0..8 {
            assert_eq!(l.check(ip, i * 2_000), Limit::Allow);
        }
        for i in 0..1350 {
            assert_eq!(l.check(ip, 16_000 + i * 64_000), Limit::Allow);
        }
    }

    #[test]
    fn a_flood_gets_the_burst_one_kiss_then_silence() {
        let mut l = limiter();
        let ip = "192.0.2.1".parse().unwrap();
        let mut got = Vec::new();
        for _ in 0..100 {
            got.push(l.check(ip, 1_000_000));
        }
        let allowed = got.iter().filter(|v| **v == Limit::Allow).count();
        assert_eq!(allowed as u64, RATE_BURST);
        assert_eq!(got.get(RATE_BURST as usize), Some(&Limit::Kiss));
        assert_eq!(got.iter().filter(|v| **v == Limit::Kiss).count(), 1);
        assert_eq!(got.last(), Some(&Limit::Silent));
        // The next kiss waits KISS_INTERVAL_MS…
        assert_eq!(l.check(ip, 1_000_000 + KISS_INTERVAL_MS - 1), Limit::Allow);
        // …credit came back meanwhile; the source that stops is forgiven.
        assert_eq!(l.check(ip, 1_000_000 + 3_600_000), Limit::Allow);
    }

    #[test]
    fn sources_do_not_share_a_bucket_and_ipv6_counts_by_64() {
        let mut l = limiter();
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        for _ in 0..RATE_BURST {
            assert_eq!(l.check(a, 1), Limit::Allow);
        }
        assert_eq!(l.check(a, 1), Limit::Kiss);
        assert_eq!(l.check(b, 1), Limit::Allow);
        // A host walking its /64 is one source.
        let mut l = limiter();
        for i in 0..RATE_BURST {
            let ip: IpAddr = format!("2001:db8:1:2::{:x}", i + 1).parse().unwrap();
            assert_eq!(l.check(ip, 1), Limit::Allow);
        }
        assert_eq!(l.check("2001:db8:1:2::ffff".parse().unwrap(), 1), Limit::Kiss);
        assert_eq!(l.check("2001:db8:1:3::1".parse().unwrap(), 1), Limit::Allow);
    }

    /// A table this small is all collisions: nobody is wrongly limited.
    #[test]
    fn a_flood_of_sources_only_makes_the_table_forget() {
        let mut l = RateLimiter::new(4, RandomState::new());
        let victim: IpAddr = "192.0.2.1".parse().unwrap();
        for i in 0..100_000u32 {
            let ip = IpAddr::from(i.to_be_bytes());
            let _ = l.check(ip, u64::from(i));
            if i % 1000 == 0 {
                assert_eq!(l.check(victim, u64::from(i)), Limit::Allow);
            }
        }
        assert_eq!(l.slots.len(), 4, "memory stays bounded");
    }

    proptest! {
        /// Hostile bytes: never a panic; what passes has a request's shape
        /// and a reply of 48 bytes.
        #[test]
        fn any_bytes_are_safe(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            if let Ok(req) = parse_request(&bytes) {
                prop_assert_eq!(req.mode, MODE_CLIENT);
                let r = reply(&req, &sys(), T, T).encode();
                prop_assert!(r.len() <= bytes.len());
                prop_assert_eq!(Packet::decode(&r).unwrap().origin, req.transmit);
            }
        }

        #[test]
        fn any_system_vars_are_safe(
            delay in any::<i64>(), disp in any::<i64>(), reference in any::<i64>(), now in any::<i64>(), ages in any::<bool>(),
        ) {
            let s = SystemVars {
                root_delay_nanos: delay,
                root_dispersion_nanos: disp,
                reference_nanos: i128::from(reference),
                ages,
                ..sys()
            };
            let _ = s.usable_at(i128::from(now));
            let _ = reply(&request(), &s, i128::from(now), i128::from(now));
            let _ = broadcast(&s, 6, i128::from(now));
        }

        #[test]
        fn any_times_are_safe(times in proptest::collection::vec(any::<u64>(), 1..64)) {
            let mut l = RateLimiter::new(16, RandomState::new());
            for t in times {
                let _ = l.check(IpAddr::from([192, 0, 2, 1]), t);
            }
        }
    }
}
