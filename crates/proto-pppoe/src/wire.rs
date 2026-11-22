//! Byte-level helpers shared by every codec: a bounds-checked reader over a
//! borrowed slice and big-endian appends onto a reusable `Vec<u8>`.
//!
//! Nothing here allocates on its own: writers append to a buffer the caller
//! owns and reuses, so the per-packet path does not touch the allocator once
//! the buffer has grown to its working size.

use std::fmt;

/// Why a frame or packet was refused. The decoders never panic and never read
/// past a length field; every refusal is one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("truncated: needed {need} bytes, have {have}")]
    Truncated { need: usize, have: usize },
    #[error("length field {field} exceeds the {have} bytes present")]
    BadLength { field: usize, have: usize },
    #[error("unsupported version/type {0:#04x} (RFC 2516 §4: must be 0x11)")]
    BadVerType(u8),
    #[error("unknown PPPoE code {0:#04x}")]
    BadCode(u8),
    #[error("unexpected EtherType {0:#06x}")]
    BadEtherType(u16),
    #[error("too many VLAN tags (max 2)")]
    TooManyTags,
    #[error("option {kind} has invalid length {len}")]
    BadOption { kind: u8, len: usize },
    #[error("malformed field: {0}")]
    Malformed(&'static str),
    #[error("output would exceed {0} bytes")]
    TooLong(usize),
}

/// An Ethernet MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    pub const BROADCAST: Mac = Mac([0xff; 6]);
    pub const ZERO: Mac = Mac([0; 6]);

    /// Group (multicast or broadcast) bit: never a valid source.
    pub fn is_group(&self) -> bool {
        self.0[0] & 1 == 1
    }

    /// A valid unicast source: not a group address, not all zeros.
    pub fn is_unicast(&self) -> bool {
        !self.is_group() && *self != Mac::ZERO
    }
}

impl fmt::Debug for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02X}:{b:02X}:{c:02X}:{d:02X}:{e:02X}:{g:02X}")
    }
}

/// Bounds-checked cursor over a borrowed slice.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len()
    }

    pub fn rest(&self) -> &'a [u8] {
        self.buf
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let Some((head, tail)) = self.buf.split_at_checked(n) else {
            return Err(WireError::Truncated {
                need: n,
                have: self.buf.len(),
            });
        };
        self.buf = tail;
        Ok(head)
    }

    pub fn u8(&mut self) -> Result<u8, WireError> {
        let b = self.take(1)?;
        b.first()
            .copied()
            .ok_or(WireError::Truncated { need: 1, have: 0 })
    }

    pub fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.array::<2>()?;
        Ok(u16::from_be_bytes(b))
    }

    pub fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let b = self.take(N)?;
        b.try_into().map_err(|_| WireError::Truncated {
            need: N,
            have: b.len(),
        })
    }
}

/// Big-endian appends.
pub(crate) fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Overwrites two bytes at `pos` (a length placeholder written earlier).
pub(crate) fn patch_u16(out: &mut [u8], pos: usize, v: u16) {
    if let Some(dst) = out.get_mut(pos..pos.saturating_add(2)) {
        dst.copy_from_slice(&v.to_be_bytes());
    }
}

/// `n` as u16 or [`WireError::TooLong`].
pub(crate) fn len_u16(n: usize) -> Result<u16, WireError> {
    u16::try_from(n).map_err(|_| WireError::TooLong(usize::from(u16::MAX)))
}

/// Uppercase hex of `bytes` into `out` (MS-CHAPv2 "S=" and "C=" strings).
pub(crate) fn put_hex_upper(out: &mut Vec<u8>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for b in bytes {
        out.push(HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0'));
        out.push(HEX.get(usize::from(b & 0xf)).copied().unwrap_or(b'0'));
    }
}

/// Parses hex (either case) into `dst`, all or nothing.
pub(crate) fn parse_hex(src: &[u8], dst: &mut [u8]) -> Option<()> {
    if src.len() != dst.len() * 2 {
        return None;
    }
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    for (d, [h, l]) in dst.iter_mut().zip(src.as_chunks::<2>().0) {
        *d = (nib(*h)? << 4) | nib(*l)?;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_refuses_past_the_end() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.u16().unwrap(), 0x0102);
        assert_eq!(r.u16(), Err(WireError::Truncated { need: 2, have: 1 }));
        assert_eq!(r.u8().unwrap(), 3);
        assert!(r.u8().is_err());
    }

    #[test]
    fn hex_round_trip() {
        let mut s = Vec::new();
        put_hex_upper(&mut s, &[0x00, 0xab, 0xff]);
        assert_eq!(s, b"00ABFF");
        let mut d = [0u8; 3];
        parse_hex(b"00abFF", &mut d).unwrap();
        assert_eq!(d, [0, 0xab, 0xff]);
        assert!(parse_hex(b"0g0000", &mut d).is_none());
        assert!(parse_hex(b"00", &mut d).is_none());
    }

    #[test]
    fn mac_classes() {
        assert!(Mac([0x02, 0, 0, 0, 0, 1]).is_unicast());
        assert!(!Mac::BROADCAST.is_unicast());
        assert!(!Mac::ZERO.is_unicast());
        assert!(Mac([0x01, 0, 0x5e, 0, 0, 1]).is_group());
    }
}
