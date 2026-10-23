//! Read-only, bounds-checked access to a frame.

/// A frame the parser reads. Every load is checked against the end of the
/// frame: `None` past it. In the eBPF program each load compares
/// `data + off + N` with `data_end`, the check the verifier wants before a
/// packet access; offsets stay small and bounded (headers only).
pub trait Packet {
    /// Frame length in bytes.
    fn len(&self) -> usize;

    /// The `N` bytes at `off`, or `None` if they are not all in the frame.
    fn bytes<const N: usize>(&self, off: usize) -> Option<[u8; N]>;

    /// Whether the frame is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn u8_at(&self, off: usize) -> Option<u8> {
        let [b] = self.bytes::<1>(off)?;
        Some(b)
    }

    /// Big-endian (network order) `u16` at `off`.
    fn be16(&self, off: usize) -> Option<u16> {
        self.bytes::<2>(off).map(u16::from_be_bytes)
    }
}

impl Packet for [u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn bytes<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        let end = off.checked_add(N)?;
        self.get(off..end)?.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_stop_at_the_end() {
        let f: &[u8] = &[1, 2, 3];
        assert_eq!(f.bytes::<2>(1), Some([2, 3]));
        assert_eq!(f.bytes::<2>(2), None);
        assert_eq!(f.be16(0), Some(0x0102));
        assert_eq!(f.u8_at(3), None);
        assert_eq!(f.bytes::<1>(usize::MAX), None);
    }
}
