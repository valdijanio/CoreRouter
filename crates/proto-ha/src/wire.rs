//! Bounded little-endian reader and writer shared by the codecs: every read
//! checks the length first, so a hostile buffer ends in [`Error`], never in
//! a panic.

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    #[error("truncated: needed {need} more bytes")]
    Truncated { need: usize },
    #[error("bad magic or version")]
    BadMagic,
    #[error("unknown message kind {0}")]
    UnknownKind(u8),
    #[error("{what} too long ({len} > {max})")]
    TooLong {
        what: &'static str,
        len: usize,
        max: usize,
    },
    #[error("bad value of {0}")]
    BadValue(&'static str),
    #[error("{0} bytes left after the message")]
    Trailing(usize),
    #[error("duplicate field {0}")]
    Duplicate(u8),
    #[error("missing field {0}")]
    Missing(&'static str),
    #[error("authentication failed")]
    BadMac,
    #[error("replayed or out-of-order hello")]
    Replay,
}

pub type Result<T> = std::result::Result<T, Error>;

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

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.buf.len() {
            return Err(Error::Truncated {
                need: n - self.buf.len(),
            });
        }
        let (a, b) = self.buf.split_at(n);
        self.buf = b;
        Ok(a)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(u8::from_le_bytes(self.array()?))
    }

    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::BadValue("bool")),
        }
    }

    /// A `u16`-prefixed byte string of at most `max` bytes.
    pub fn bytes16(&mut self, what: &'static str, max: usize) -> Result<&'a [u8]> {
        let n = usize::from(self.u16()?);
        if n > max {
            return Err(Error::TooLong { what, len: n, max });
        }
        self.take(n)
    }

    /// A `u8`-prefixed byte string.
    pub fn bytes8(&mut self) -> Result<&'a [u8]> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }

    pub fn end(&self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(Error::Trailing(self.buf.len()))
        }
    }
}

pub fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// A `u16`-prefixed byte string; refused past `max` (and past `u16::MAX`).
pub fn put_bytes16(out: &mut Vec<u8>, what: &'static str, b: &[u8], max: usize) -> Result<()> {
    let max = max.min(usize::from(u16::MAX));
    if b.len() > max {
        return Err(Error::TooLong {
            what,
            len: b.len(),
            max,
        });
    }
    put_u16(out, u16::try_from(b.len()).unwrap_or(u16::MAX));
    out.extend_from_slice(b);
    Ok(())
}

/// A `u8`-prefixed byte string (at most 255 bytes).
pub fn put_bytes8(out: &mut Vec<u8>, what: &'static str, b: &[u8]) -> Result<()> {
    let n = u8::try_from(b.len()).map_err(|_| Error::TooLong {
        what,
        len: b.len(),
        max: 255,
    })?;
    out.push(n);
    out.extend_from_slice(b);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_bounded() {
        let mut r = Reader::new(&[1, 0, 2]);
        assert_eq!(r.u16().unwrap(), 1);
        assert_eq!(r.u16(), Err(Error::Truncated { need: 1 }));
        let mut r = Reader::new(&[5, 0, 1]);
        assert!(matches!(r.bytes16("x", 4), Err(Error::TooLong { .. })));
        let mut r = Reader::new(&[2]);
        assert_eq!(r.bool(), Err(Error::BadValue("bool")));
    }

    #[test]
    fn writes_refuse_what_the_reader_would() {
        let mut v = Vec::new();
        assert!(put_bytes16(&mut v, "x", &[0; 5], 4).is_err());
        assert!(put_bytes8(&mut v, "x", &[0; 256]).is_err());
        assert!(v.is_empty());
    }
}
