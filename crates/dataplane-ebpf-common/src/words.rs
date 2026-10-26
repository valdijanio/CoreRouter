// SPDX-License-Identifier: GPL-2.0-or-later
//! The words of a map value that every CPU updates (policer and shaper
//! state, G4.3cc). The program backs them with BPF atomic instructions
//! (compare-and-swap, add) on the map element; the host tests with a plain
//! array, and a test harness can interleave "CPUs" through the same trait.
//!
//! Why not `bpf_spin_lock`: no helper may be called while it is held, it
//! needs a BTF map, and a lock per subscriber serializes the CPUs exactly
//! where the data path should spread (the HTB problem, Carousel 2017). One
//! compare-and-swap on one word is enough for a GCRA clock or an EDT
//! departure time: the state that must be exact fits in a `u64`.

/// Words `0..len` of a state value.
pub trait Words {
    fn get(&self, i: usize) -> u64;
    /// Plain store (a word only one CPU decides at a time, or statistics).
    fn set(&mut self, i: usize, v: u64);
    /// Compare-and-swap: `true` when word `i` held `old` and now holds `new`.
    fn cas(&mut self, i: usize, old: u64, new: u64) -> bool;
    /// Atomic add (no fetch).
    fn add(&mut self, i: usize, v: u64);
}

impl<const N: usize> Words for [u64; N] {
    #[inline(always)]
    fn get(&self, i: usize) -> u64 {
        self.as_slice().get(i).copied().unwrap_or(0)
    }

    #[inline(always)]
    fn set(&mut self, i: usize, v: u64) {
        if let Some(w) = self.as_mut_slice().get_mut(i) {
            *w = v;
        }
    }

    #[inline(always)]
    fn cas(&mut self, i: usize, old: u64, new: u64) -> bool {
        match self.as_mut_slice().get_mut(i) {
            Some(w) if *w == old => {
                *w = new;
                true
            }
            _ => false,
        }
    }

    #[inline(always)]
    fn add(&mut self, i: usize, v: u64) {
        if let Some(w) = self.as_mut_slice().get_mut(i) {
            *w = w.wrapping_add(v);
        }
    }
}

impl<W: Words + ?Sized> Words for &mut W {
    #[inline(always)]
    fn get(&self, i: usize) -> u64 {
        (**self).get(i)
    }

    #[inline(always)]
    fn set(&mut self, i: usize, v: u64) {
        (**self).set(i, v)
    }

    #[inline(always)]
    fn cas(&mut self, i: usize, old: u64, new: u64) -> bool {
        (**self).cas(i, old, new)
    }

    #[inline(always)]
    fn add(&mut self, i: usize, v: u64) {
        (**self).add(i, v)
    }
}

/// How many times a compare-and-swap is retried before the data path
/// gives up and takes its own result (a bounded loop for the verifier;
/// losing four races in a row means four other CPUs moved the clock in
/// the same few nanoseconds, and the error is one packet).
pub const CAS_TRIES: usize = 4;

/// Integer square root (floor) of a CoDel count (RFC 8289 §5.1:
/// `interval / sqrt(count)`; counts fit in 32 bits). Newton's method from a
/// power of two above the root, unrolled: no loop and no branch per bit
/// for the verifier to walk (a bit-by-bit loop cost it a million
/// instructions).
#[inline(always)]
pub fn isqrt(n: u64) -> u64 {
    let n = n.min(u64::from(u32::MAX));
    if n < 2 {
        return n;
    }
    let bits = 64 - n.leading_zeros();
    let mut x: u64 = 1 << bits.div_ceil(2);
    // From above, each step at least halves the error; 32-bit inputs need
    // five.
    x = (x + n.checked_div(x).unwrap_or(0)) >> 1;
    x = (x + n.checked_div(x).unwrap_or(0)) >> 1;
    x = (x + n.checked_div(x).unwrap_or(0)) >> 1;
    x = (x + n.checked_div(x).unwrap_or(0)) >> 1;
    x = (x + n.checked_div(x).unwrap_or(0)) >> 1;
    x = (x + n.checked_div(x).unwrap_or(0)) >> 1;
    if x.saturating_mul(x) > n {
        x -= 1;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_words_and_sqrt() {
        let mut w = [0u64; 3];
        assert!(w.cas(1, 0, 7));
        assert!(!w.cas(1, 0, 9));
        w.add(1, 3);
        assert_eq!(w.get(1), 10);
        w.set(9, 1);
        assert_eq!(w.get(9), 0);
        for n in (0u64..70_000).chain([1 << 31, (1 << 32) - 1, 4_294_836_225, 4_294_836_224]) {
            let r = isqrt(n);
            assert!(u128::from(r) * u128::from(r) <= u128::from(n), "{n}");
            assert!(u128::from(r + 1) * u128::from(r + 1) > u128::from(n), "{n}");
        }
    }
}
