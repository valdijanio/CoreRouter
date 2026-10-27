//! The BFD Control packet (RFC 5880 §4.1) and its authentication section
//! (§4.2–§4.4).
//!
//! [`Packet::decode`] runs the checks of §6.8.6 that need only the bytes
//! (version, lengths, detect multiplier, multipoint, My Discriminator);
//! what needs the session (Your Discriminator, the A bit against the
//! session's auth, the digest) is [`crate::session`]'s.

use thiserror::Error;

/// §4.1: the mandatory section.
pub const MIN_LEN: usize = 24;
/// §4.4: Keyed SHA1 / Meticulous Keyed SHA1 section (type, len, key id,
/// reserved, sequence, 20-byte hash).
pub const SHA1_AUTH_LEN: usize = 28;
/// The longest packet this codec reads (§4.2: Simple Password is at most
/// 16 bytes of password plus 3, the other types are fixed; 24 + 28 = 52
/// is the largest).
pub const MAX_LEN: usize = MIN_LEN + SHA1_AUTH_LEN;
/// §4.1: "Vers: … This document defines protocol version 1."
pub const VERSION: u8 = 1;

/// §4.1 Sta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum State {
    AdminDown = 0,
    Down = 1,
    Init = 2,
    Up = 3,
}

impl State {
    pub fn from_bits(b: u8) -> Self {
        match b & 3 {
            0 => Self::AdminDown,
            1 => Self::Down,
            2 => Self::Init,
            _ => Self::Up,
        }
    }

    /// As RouterOS and FRR print it.
    pub fn name(self) -> &'static str {
        match self {
            Self::AdminDown => "admin-down",
            Self::Down => "down",
            Self::Init => "init",
            Self::Up => "up",
        }
    }
}

/// §4.1 Diag: why the local system last left Up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Diag {
    #[default]
    None,
    ControlDetectionTimeExpired,
    EchoFunctionFailed,
    NeighborSignaledDown,
    ForwardingPlaneReset,
    PathDown,
    ConcatenatedPathDown,
    AdministrativelyDown,
    ReverseConcatenatedPathDown,
    /// 9–31 (reserved, or later RFCs): kept so the code goes back on the
    /// wire as received.
    Other(u8),
}

impl Diag {
    pub fn from_code(c: u8) -> Self {
        match c & 0x1f {
            0 => Self::None,
            1 => Self::ControlDetectionTimeExpired,
            2 => Self::EchoFunctionFailed,
            3 => Self::NeighborSignaledDown,
            4 => Self::ForwardingPlaneReset,
            5 => Self::PathDown,
            6 => Self::ConcatenatedPathDown,
            7 => Self::AdministrativelyDown,
            8 => Self::ReverseConcatenatedPathDown,
            n => Self::Other(n),
        }
    }

    pub fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::ControlDetectionTimeExpired => 1,
            Self::EchoFunctionFailed => 2,
            Self::NeighborSignaledDown => 3,
            Self::ForwardingPlaneReset => 4,
            Self::PathDown => 5,
            Self::ConcatenatedPathDown => 6,
            Self::AdministrativelyDown => 7,
            Self::ReverseConcatenatedPathDown => 8,
            Self::Other(n) => n & 0x1f,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ControlDetectionTimeExpired => "control-detection-time-expired",
            Self::EchoFunctionFailed => "echo-function-failed",
            Self::NeighborSignaledDown => "neighbor-signaled-session-down",
            Self::ForwardingPlaneReset => "forwarding-plane-reset",
            Self::PathDown => "path-down",
            Self::ConcatenatedPathDown => "concatenated-path-down",
            Self::AdministrativelyDown => "administratively-down",
            Self::ReverseConcatenatedPathDown => "reverse-concatenated-path-down",
            Self::Other(_) => "other",
        }
    }
}

/// §4.2 Auth Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthType {
    SimplePassword = 1,
    KeyedMd5 = 2,
    MeticulousKeyedMd5 = 3,
    KeyedSha1 = 4,
    MeticulousKeyedSha1 = 5,
}

impl AuthType {
    fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            1 => Self::SimplePassword,
            2 => Self::KeyedMd5,
            3 => Self::MeticulousKeyedMd5,
            4 => Self::KeyedSha1,
            5 => Self::MeticulousKeyedSha1,
            _ => return None,
        })
    }
}

/// The authentication section as it came: only the SHA1 types are
/// verified ([`crate::auth`]); the others are read so a peer configured
/// with them is told apart from garbage in the counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthSection {
    pub kind: AuthType,
    pub key_id: u8,
    pub seq: u32,
    /// The SHA1 hash (zeros for the other types).
    pub digest: [u8; 20],
}

/// A decoded BFD Control packet. Intervals are microseconds, as on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    pub diag: Diag,
    pub state: State,
    pub poll: bool,
    pub final_: bool,
    pub cpi: bool,
    pub demand: bool,
    pub detect_mult: u8,
    pub my_discr: u32,
    pub your_discr: u32,
    pub desired_min_tx: u32,
    pub required_min_rx: u32,
    pub required_min_echo_rx: u32,
    pub auth: Option<AuthSection>,
}

/// Why a packet was dropped before reaching a session (§6.8.6, the checks
/// that need only the bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("shorter than the 24-byte header")]
    Short,
    #[error("version {0}, not 1")]
    Version(u8),
    #[error("length field {0} is below the minimum or above the datagram")]
    Length(u8),
    #[error("detect multiplier is zero")]
    DetectMult,
    #[error("multipoint bit set")]
    Multipoint,
    #[error("my discriminator is zero")]
    MyDiscr,
    #[error("authentication section malformed")]
    Auth,
}

fn be32(b: &[u8], at: usize) -> u32 {
    let mut w = [0u8; 4];
    if let Some(s) = b.get(at..at + 4) {
        w.copy_from_slice(s);
    }
    u32::from_be_bytes(w)
}

impl Packet {
    /// A packet with the defaults of a Down session (§6.8.7 contents).
    pub fn new(my_discr: u32) -> Self {
        Self {
            diag: Diag::None,
            state: State::Down,
            poll: false,
            final_: false,
            cpi: false,
            demand: false,
            detect_mult: 3,
            my_discr,
            your_discr: 0,
            desired_min_tx: 1_000_000,
            required_min_rx: 1_000_000,
            required_min_echo_rx: 0,
            auth: None,
        }
    }

    /// §6.8.6, first checks: discard when the version is not 1, the
    /// length is below 24 (26 with the A bit) or above the datagram, the
    /// multiplier is zero, the M bit is set or My Discriminator is zero.
    /// Bytes after `Length` are ignored (§6.8.6 only bounds it by the
    /// encapsulation).
    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let (&b0, &b1, &mult, &len) = match (b.first(), b.get(1), b.get(2), b.get(3)) {
            (Some(a), Some(c), Some(d), Some(e)) if b.len() >= MIN_LEN => (a, c, d, e),
            _ => return Err(DecodeError::Short),
        };
        let version = b0 >> 5;
        if version != VERSION {
            return Err(DecodeError::Version(version));
        }
        let a_bit = b1 & 0x04 != 0;
        let min = if a_bit { MIN_LEN + 2 } else { MIN_LEN };
        if usize::from(len) < min || usize::from(len) > b.len() {
            return Err(DecodeError::Length(len));
        }
        if mult == 0 {
            return Err(DecodeError::DetectMult);
        }
        if b1 & 0x01 != 0 {
            return Err(DecodeError::Multipoint);
        }
        let my_discr = be32(b, 4);
        if my_discr == 0 {
            return Err(DecodeError::MyDiscr);
        }
        let auth = if a_bit {
            Some(decode_auth(
                b.get(MIN_LEN..usize::from(len)).unwrap_or(&[]),
            )?)
        } else {
            None
        };
        Ok(Self {
            diag: Diag::from_code(b0),
            state: State::from_bits(b1 >> 6),
            poll: b1 & 0x20 != 0,
            final_: b1 & 0x10 != 0,
            cpi: b1 & 0x08 != 0,
            demand: b1 & 0x02 != 0,
            detect_mult: mult,
            my_discr,
            your_discr: be32(b, 8),
            desired_min_tx: be32(b, 12),
            required_min_rx: be32(b, 16),
            required_min_echo_rx: be32(b, 20),
            auth,
        })
    }

    /// The wire form. With `auth` set, the section is written with its
    /// digest as given: [`crate::auth::sign`] fills it.
    pub fn encode(&self, out: &mut [u8; MAX_LEN]) -> usize {
        let len = if self.auth.is_some() {
            MAX_LEN
        } else {
            MIN_LEN
        };
        out[0] = (VERSION << 5) | self.diag.code();
        out[1] = ((self.state as u8) << 6)
            | (u8::from(self.poll) << 5)
            | (u8::from(self.final_) << 4)
            | (u8::from(self.cpi) << 3)
            | (u8::from(self.auth.is_some()) << 2)
            | (u8::from(self.demand) << 1);
        out[2] = self.detect_mult;
        out[3] = len as u8;
        out[4..8].copy_from_slice(&self.my_discr.to_be_bytes());
        out[8..12].copy_from_slice(&self.your_discr.to_be_bytes());
        out[12..16].copy_from_slice(&self.desired_min_tx.to_be_bytes());
        out[16..20].copy_from_slice(&self.required_min_rx.to_be_bytes());
        out[20..24].copy_from_slice(&self.required_min_echo_rx.to_be_bytes());
        if let Some(a) = &self.auth {
            out[24] = a.kind as u8;
            out[25] = SHA1_AUTH_LEN as u8;
            out[26] = a.key_id;
            out[27] = 0;
            out[28..32].copy_from_slice(&a.seq.to_be_bytes());
            out[32..52].copy_from_slice(&a.digest);
        }
        len
    }
}

/// §4.2: Auth Type and Auth Len; §4.3/§4.4 the fixed layouts. A section
/// whose Auth Len disagrees with its type or with the packet is malformed.
fn decode_auth(s: &[u8]) -> Result<AuthSection, DecodeError> {
    let (&ty, &alen) = match (s.first(), s.get(1)) {
        (Some(t), Some(l)) => (t, l),
        _ => return Err(DecodeError::Auth),
    };
    let kind = AuthType::from_code(ty).ok_or(DecodeError::Auth)?;
    if usize::from(alen) != s.len() {
        return Err(DecodeError::Auth);
    }
    match kind {
        // §4.2.2: 1–16 bytes of password after type, len and key id.
        AuthType::SimplePassword => {
            if !(4..=19).contains(&s.len()) {
                return Err(DecodeError::Auth);
            }
            Ok(AuthSection {
                kind,
                key_id: s.get(2).copied().unwrap_or(0),
                seq: 0,
                digest: [0; 20],
            })
        }
        // §4.3: 24 bytes (16-byte digest).
        AuthType::KeyedMd5 | AuthType::MeticulousKeyedMd5 => {
            if s.len() != 24 {
                return Err(DecodeError::Auth);
            }
            Ok(AuthSection {
                kind,
                key_id: s.get(2).copied().unwrap_or(0),
                seq: be32(s, 4),
                digest: [0; 20],
            })
        }
        // §4.4: "Auth Len: … 28".
        AuthType::KeyedSha1 | AuthType::MeticulousKeyedSha1 => {
            if s.len() != SHA1_AUTH_LEN {
                return Err(DecodeError::Auth);
            }
            let mut digest = [0u8; 20];
            if let Some(d) = s.get(8..28) {
                digest.copy_from_slice(d);
            }
            Ok(AuthSection {
                kind,
                key_id: s.get(2).copied().unwrap_or(0),
                seq: be32(s, 4),
                digest,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Down packet as FRR's bfdd sends it at start (captured layout,
    /// RFC 5880 §4.1): version 1, Sta Down, mult 3, len 24, 1 s / 1 s.
    const FRR_DOWN: [u8; 24] = [
        0x20, 0x40, 0x03, 0x18, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42,
        0x40, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x00, 0xc3, 0x50,
    ];

    #[test]
    fn decodes_the_mandatory_section() {
        let p = Packet::decode(&FRR_DOWN).unwrap();
        assert_eq!(p.state, State::Down);
        assert_eq!(p.diag, Diag::None);
        assert_eq!(p.detect_mult, 3);
        assert_eq!(p.my_discr, 42);
        assert_eq!(p.your_discr, 0);
        assert_eq!(p.desired_min_tx, 1_000_000);
        assert_eq!(p.required_min_rx, 1_000_000);
        assert_eq!(p.required_min_echo_rx, 50_000);
        assert!(p.auth.is_none());
        let mut out = [0u8; MAX_LEN];
        let n = p.encode(&mut out);
        assert_eq!(&out[..n], &FRR_DOWN);
    }

    #[test]
    fn rfc_5880_6_8_6_discards() {
        // Version 0.
        let mut b = FRR_DOWN;
        b[0] = 0x00;
        assert_eq!(Packet::decode(&b), Err(DecodeError::Version(0)));
        // Length below 24, and above the datagram.
        let mut b = FRR_DOWN;
        b[3] = 23;
        assert_eq!(Packet::decode(&b), Err(DecodeError::Length(23)));
        b[3] = 25;
        assert_eq!(Packet::decode(&b), Err(DecodeError::Length(25)));
        // A bit with length 24 (< 26).
        let mut b = FRR_DOWN;
        b[1] |= 0x04;
        assert_eq!(Packet::decode(&b), Err(DecodeError::Length(24)));
        // Detect Mult zero, M bit, My Discriminator zero.
        let mut b = FRR_DOWN;
        b[2] = 0;
        assert_eq!(Packet::decode(&b), Err(DecodeError::DetectMult));
        let mut b = FRR_DOWN;
        b[1] |= 0x01;
        assert_eq!(Packet::decode(&b), Err(DecodeError::Multipoint));
        let mut b = FRR_DOWN;
        b[7] = 0;
        assert_eq!(Packet::decode(&b), Err(DecodeError::MyDiscr));
        assert_eq!(Packet::decode(&FRR_DOWN[..23]), Err(DecodeError::Short));
    }

    #[test]
    fn trailing_bytes_after_length_are_ignored() {
        let mut b = FRR_DOWN.to_vec();
        b.extend_from_slice(&[0xff; 8]);
        assert!(Packet::decode(&b).is_ok());
    }

    #[test]
    fn flags_round_trip() {
        let mut p = Packet::new(7);
        p.state = State::Up;
        p.poll = true;
        p.cpi = true;
        p.demand = true;
        p.diag = Diag::NeighborSignaledDown;
        let mut out = [0u8; MAX_LEN];
        let n = p.encode(&mut out);
        assert_eq!(Packet::decode(&out[..n]).unwrap(), p);
        assert_eq!(out[1], 0xc0 | 0x20 | 0x08 | 0x02);
        assert_eq!(out[0], 0x23);
    }

    #[test]
    fn auth_len_must_match_the_type() {
        let mut p = Packet::new(9);
        p.auth = Some(AuthSection {
            kind: AuthType::KeyedSha1,
            key_id: 1,
            seq: 5,
            digest: [0xab; 20],
        });
        let mut out = [0u8; MAX_LEN];
        let n = p.encode(&mut out);
        assert_eq!(n, 52);
        assert_eq!(Packet::decode(&out[..n]).unwrap(), p);
        let mut bad = out;
        bad[25] = 24;
        assert_eq!(Packet::decode(&bad[..n]), Err(DecodeError::Auth));
        let mut bad = out;
        bad[24] = 9;
        assert_eq!(Packet::decode(&bad[..n]), Err(DecodeError::Auth));
    }
}
