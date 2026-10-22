//! L2 — SNTPv4 client packets (G4.6).
//!
//! The client half of the Simple Network Time Protocol: build the request,
//! decode and sanity-check the server's reply, and compute clock offset and
//! round-trip delay. Pure: no sockets and no clock (the caller passes the
//! timestamps), so it is tested with the RFC's own arithmetic.
//!
//! References (read 2026-10-22):
//! - RFC 5905 (NTPv4, obsoletes RFC 4330): §6 timestamp format and eras,
//!   §7.3 packet header, §7.4 Kiss-o'-Death, §8 on-wire offset/delay,
//!   §14 SNTP. <https://www.rfc-editor.org/rfc/rfc5905>
//! - RFC 4330 (SNTPv4): §4 message format, §5 client operations and the
//!   reply checks, §8 Kiss-o'-Death. <https://www.rfc-editor.org/rfc/rfc4330>
//!
//! Input is hostile: [`Packet::decode`] reads exactly the 48-byte header
//! (extension fields and MACs after it are ignored), and [`check_reply`]
//! rejects anything RFC 4330 §5 says a client should discard.

use thiserror::Error;

/// RFC 5905 §7.2: NTP is UDP port 123.
pub const PORT: u16 = 123;
/// RFC 4330 §4 / RFC 5905 §7.3: the header without extensions.
pub const HEADER_LEN: usize = 48;
/// Seconds from 1900-01-01 (NTP era 0) to 1970-01-01 (Unix epoch).
pub const NTP_UNIX_OFFSET: i128 = 2_208_988_800;
const NANOS: i128 = 1_000_000_000;
const ERA: i128 = 1 << 32;

/// 64-bit NTP timestamp: 32 bits of seconds since 1900 (modulo the era)
/// and 32 bits of fraction (RFC 5905 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// From Unix time in nanoseconds.
    pub fn from_unix_nanos(nanos: i128) -> Self {
        let secs = nanos.div_euclid(NANOS);
        let sub = nanos.rem_euclid(NANOS);
        let ntp_secs = (secs + NTP_UNIX_OFFSET).rem_euclid(ERA);
        let frac = (sub << 32) / NANOS;
        Self(((ntp_secs as u64) << 32) | (frac as u64 & 0xFFFF_FFFF))
    }

    /// To Unix time in nanoseconds. RFC 4330 §3: when the most significant
    /// bit of the seconds is set the time is in 1968..2036 (era 0),
    /// otherwise in 2036..2104 (era 1).
    pub fn to_unix_nanos(self) -> i128 {
        let secs = i128::from(self.0 >> 32);
        let frac = i128::from(self.0 & 0xFFFF_FFFF);
        let era = if secs & 0x8000_0000 != 0 { 0 } else { ERA };
        (secs + era - NTP_UNIX_OFFSET) * NANOS + ((frac * NANOS) >> 32)
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// RFC 5905 §7.3 `mode`.
pub const MODE_CLIENT: u8 = 3;
pub const MODE_SERVER: u8 = 4;
/// RFC 5905 §7.3 `leap`: 3 = clock unsynchronized.
pub const LEAP_ALARM: u8 = 3;
/// RFC 5905 §7.3: stratum 16 = unsynchronized; 0 = Kiss-o'-Death (§7.4).
pub const STRATUM_UNSYNC: u8 = 16;

/// The NTP header (RFC 5905 §7.3, Figure 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Packet {
    pub leap: u8,
    pub version: u8,
    pub mode: u8,
    pub stratum: u8,
    pub poll: i8,
    pub precision: i8,
    /// NTP short format (16.16 seconds).
    pub root_delay: u32,
    pub root_dispersion: u32,
    /// Reference ID; in a Kiss-o'-Death packet, the ASCII kiss code.
    pub reference_id: [u8; 4],
    pub reference: Timestamp,
    pub origin: Timestamp,
    pub receive: Timestamp,
    pub transmit: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("NTP packet too short: {0} bytes (the header is 48)")]
    TooShort(usize),
}

impl Packet {
    /// RFC 4330 §5: every field zero except LI = 0, VN = 4, Mode = 3 and
    /// the Transmit Timestamp, which the server copies to Origin (the
    /// client's check against spoofed or stale replies).
    pub fn client_request(transmit: Timestamp) -> Self {
        Self {
            version: 4,
            mode: MODE_CLIENT,
            transmit,
            ..Self::default()
        }
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut v = Vec::with_capacity(HEADER_LEN);
        v.push(((self.leap & 3) << 6) | ((self.version & 7) << 3) | (self.mode & 7));
        v.push(self.stratum);
        v.extend_from_slice(&self.poll.to_be_bytes());
        v.extend_from_slice(&self.precision.to_be_bytes());
        v.extend_from_slice(&self.root_delay.to_be_bytes());
        v.extend_from_slice(&self.root_dispersion.to_be_bytes());
        v.extend_from_slice(&self.reference_id);
        for t in [self.reference, self.origin, self.receive, self.transmit] {
            v.extend_from_slice(&t.0.to_be_bytes());
        }
        let mut b = [0u8; HEADER_LEN];
        for (d, s) in b.iter_mut().zip(v) {
            *d = s;
        }
        b
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let short = DecodeError::TooShort(bytes.len());
        if bytes.len() < HEADER_LEN {
            return Err(short);
        }
        let mut r = Reader(bytes);
        let [b0, stratum, poll, precision] = r.take::<4>().ok_or(short.clone())?;
        let root_delay = u32::from_be_bytes(r.take().ok_or(short.clone())?);
        let root_dispersion = u32::from_be_bytes(r.take().ok_or(short.clone())?);
        let reference_id = r.take().ok_or(short.clone())?;
        let mut ts = [Timestamp(0); 4];
        for t in &mut ts {
            *t = Timestamp(u64::from_be_bytes(r.take().ok_or(short.clone())?));
        }
        let [reference, origin, receive, transmit] = ts;
        Ok(Self {
            leap: b0 >> 6,
            version: (b0 >> 3) & 7,
            mode: b0 & 7,
            stratum,
            poll: i8::from_be_bytes([poll]),
            precision: i8::from_be_bytes([precision]),
            root_delay,
            root_dispersion,
            reference_id,
            reference,
            origin,
            receive,
            transmit,
        })
    }

    /// The kiss code of a Kiss-o'-Death packet (stratum 0), printable
    /// ASCII only (RFC 5905 §7.4).
    pub fn kiss_code(&self) -> Option<String> {
        (self.stratum == 0).then(|| {
            self.reference_id
                .iter()
                .filter(|b| b.is_ascii_graphic())
                .map(|b| char::from(*b))
                .collect()
        })
    }
}

/// Reads fixed-size fields front to back without indexing.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.0.split_first_chunk::<N>()?;
        self.0 = rest;
        Some(*head)
    }
}

/// Why a reply was not used.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReplyError {
    #[error("not a server reply (mode {0})")]
    NotServer(u8),
    #[error("unsupported NTP version {0}")]
    Version(u8),
    #[error("reply does not answer our request (origin timestamp differs)")]
    WrongOrigin,
    #[error("server sent a zero transmit timestamp")]
    ZeroTransmit,
    #[error("server is not synchronized")]
    Unsynchronized,
    /// RFC 5905 §7.4: DENY and RSTR mean stop asking this server; RATE
    /// means poll less often.
    #[error("kiss-o'-death {0}")]
    Kiss(String),
}

/// RFC 4330 §5 reply checks, with RFC 5905 §7.3/§7.4 meanings: mode 4,
/// version 1..=4 (§5 lets the server answer in an older version), Origin
/// equal to the Transmit we sent, Transmit non-zero, stratum 0 is a kiss,
/// LI 3 or stratum ≥ 16 is an unsynchronized server.
pub fn check_reply(sent: Timestamp, reply: &Packet) -> Result<(), ReplyError> {
    if reply.mode != MODE_SERVER {
        return Err(ReplyError::NotServer(reply.mode));
    }
    if !(1..=4).contains(&reply.version) {
        return Err(ReplyError::Version(reply.version));
    }
    if reply.origin != sent {
        return Err(ReplyError::WrongOrigin);
    }
    if let Some(code) = reply.kiss_code() {
        return Err(ReplyError::Kiss(code));
    }
    if reply.transmit.is_zero() {
        return Err(ReplyError::ZeroTransmit);
    }
    if reply.leap == LEAP_ALARM || reply.stratum >= STRATUM_UNSYNC {
        return Err(ReplyError::Unsynchronized);
    }
    Ok(())
}

/// Offset and round-trip delay of one exchange, nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// Server clock minus ours (positive: ours is behind).
    pub offset_nanos: i64,
    pub delay_nanos: i64,
}

/// RFC 5905 §8 (and RFC 4330 §5): with T1 = our transmit, T2 = server
/// receive, T3 = server transmit, T4 = our receive,
/// offset = ((T2 − T1) + (T3 − T4)) / 2 and delay = (T4 − T1) − (T3 − T2).
/// The arguments are Unix nanoseconds, so era wraps are already resolved.
pub fn sample(t1: i128, t2: i128, t3: i128, t4: i128) -> Sample {
    let clamp = |v: i128| i64::try_from(v).unwrap_or(if v < 0 { i64::MIN } else { i64::MAX });
    Sample {
        offset_nanos: clamp(((t2 - t1) + (t3 - t4)) / 2),
        // A server that answers faster than light (T3 < T2 beyond the
        // round trip) gives a negative delay; it is reported as is.
        delay_nanos: clamp((t4 - t1) - (t3 - t2)),
    }
}

/// [`sample`] from a checked reply and our own two timestamps.
pub fn sample_of(reply: &Packet, t1_nanos: i128, t4_nanos: i128) -> Sample {
    sample(
        t1_nanos,
        reply.receive.to_unix_nanos(),
        reply.transmit.to_unix_nanos(),
        t4_nanos,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const SEC: i128 = NANOS;

    #[test]
    fn request_is_lean_v4_client() {
        let t = Timestamp(0xE000_0000_8000_0000);
        let b = Packet::client_request(t).encode();
        // LI 0, VN 4, Mode 3 → 0b00_100_011.
        assert_eq!(b[0], 0x23);
        assert!(b[1..40].iter().all(|x| *x == 0));
        assert_eq!(&b[40..48], &t.0.to_be_bytes());
    }

    #[test]
    fn timestamps_cross_the_2036_era() {
        // 1970-01-01 is NTP seconds 2208988800 (RFC 5905 §6, Figure 4).
        let epoch = Timestamp::from_unix_nanos(0);
        assert_eq!(epoch.0 >> 32, 2_208_988_800);
        assert_eq!(epoch.to_unix_nanos(), 0);
        // 2036-02-07 06:28:16 UTC: era 1 starts, seconds wrap to 0.
        let wrap = (ERA - NTP_UNIX_OFFSET) * SEC;
        assert_eq!(Timestamp::from_unix_nanos(wrap).0 >> 32, 0);
        assert_eq!(Timestamp::from_unix_nanos(wrap).to_unix_nanos(), wrap);
        // Half a second is fraction 2^31.
        let half = Timestamp::from_unix_nanos(SEC / 2);
        assert_eq!(half.0 & 0xFFFF_FFFF, 0x8000_0000);
    }

    #[test]
    fn offset_and_delay_follow_rfc_5905_section_8() {
        // Our clock 1 s behind; 20 ms each way; server takes 10 ms.
        let t1 = 1_000 * SEC;
        let t2 = t1 + SEC + 20_000_000;
        let t3 = t2 + 10_000_000;
        let t4 = t1 + 50_000_000;
        let s = sample(t1, t2, t3, t4);
        assert_eq!(s.offset_nanos, 1_000_000_000);
        assert_eq!(s.delay_nanos, 40_000_000);
    }

    fn reply(sent: Timestamp) -> Packet {
        Packet {
            leap: 0,
            version: 4,
            mode: MODE_SERVER,
            stratum: 2,
            reference_id: *b"GPS\0",
            origin: sent,
            receive: Timestamp(sent.0 + 1),
            transmit: Timestamp(sent.0 + 2),
            ..Packet::default()
        }
    }

    #[test]
    fn replies_are_checked_like_rfc_4330_section_5() {
        let sent = Timestamp::from_unix_nanos(1_800_000_000 * SEC);
        let ok = reply(sent);
        assert_eq!(check_reply(sent, &ok), Ok(()));
        assert_eq!(
            check_reply(sent, &Packet { mode: 3, ..ok }),
            Err(ReplyError::NotServer(3))
        );
        assert_eq!(
            check_reply(Timestamp(sent.0 + 9), &ok),
            Err(ReplyError::WrongOrigin)
        );
        assert_eq!(
            check_reply(
                sent,
                &Packet {
                    transmit: Timestamp(0),
                    ..ok
                }
            ),
            Err(ReplyError::ZeroTransmit)
        );
        assert_eq!(
            check_reply(sent, &Packet { leap: 3, ..ok }),
            Err(ReplyError::Unsynchronized)
        );
        assert_eq!(
            check_reply(sent, &Packet { stratum: 16, ..ok }),
            Err(ReplyError::Unsynchronized)
        );
        let kod = Packet {
            stratum: 0,
            reference_id: *b"RATE",
            ..ok
        };
        assert_eq!(
            check_reply(sent, &kod),
            Err(ReplyError::Kiss("RATE".into()))
        );
        assert_eq!(
            check_reply(sent, &Packet { version: 0, ..ok }),
            Err(ReplyError::Version(0))
        );
    }

    #[test]
    fn short_packets_are_errors() {
        assert_eq!(Packet::decode(&[0; 47]), Err(DecodeError::TooShort(47)));
        // Extension fields / MAC after the header are ignored.
        let p = reply(Timestamp(7));
        let mut long = p.encode().to_vec();
        long.extend_from_slice(&[0xAA; 20]);
        assert_eq!(Packet::decode(&long), Ok(p));
    }

    proptest! {
        #[test]
        fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
            if let Ok(p) = Packet::decode(&bytes) {
                let _ = check_reply(Timestamp(1), &p);
                let _ = sample_of(&p, 0, 0);
                prop_assert_eq!(&p.encode()[..], &bytes[..HEADER_LEN]);
            }
        }

        #[test]
        fn timestamps_round_trip_within_a_nanosecond(
            secs in -60_000_000i64..4_000_000_000i64,
            sub in 0i64..1_000_000_000,
        ) {
            // 1968..2104 is what one 32-bit seconds field can tell apart.
            let n = i128::from(secs) * SEC + i128::from(sub);
            let back = Timestamp::from_unix_nanos(n).to_unix_nanos();
            prop_assert!((n - back).abs() <= 1, "{n} → {back}");
        }

        #[test]
        fn sample_never_panics(a in any::<i64>(), b in any::<i64>(), c in any::<i64>(), d in any::<i64>()) {
            let _ = sample(a.into(), b.into(), c.into(), d.into());
        }
    }
}
