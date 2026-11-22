//! TinyLFU's frequency sketch (Einziger, Friedman, Manes, "TinyLFU: A
//! Highly Efficient Cache Admission Policy", ACM ToS 13(4), 2017): how
//! often each key was asked lately, in fixed memory, for the cache to
//! decide whether a newcomer is worth more than the entry it would push out
//! (G4.1x).
//!
//! A count-min sketch of 4-bit counters (16 per `u64`): a key owns four
//! counters inside one 64-byte block (one cache line per update), its
//! estimate is the smallest of the four, and an update raises only the
//! ones at that minimum ("conservative update", which keeps hash collisions
//! from inflating the estimate). The counters stop at 15. After `10 ×`
//! the entries the cache holds updates, every counter is halved (the
//! "reset" of the paper): old popularity fades, so a name that stopped
//! being asked gives way within minutes.
//!
//! The caller brings the hash: a keyed 64-bit hash (`RandomState`), so a
//! client cannot pick names that land on the counters of the hot ones.
//! Memory: one `u64` per expected entry (the next power of two), ~1.2 %
//! of the cache's byte budget at ~700 bytes an answer.

/// Counters per key.
const DEPTH: usize = 4;
/// `u64` words in a block (64 bytes).
const BLOCK_WORDS: usize = 8;
/// The smallest table: 64 words (8 blocks).
const MIN_WORDS: usize = 64;
/// The largest table (2²⁴ words, 128 MiB): above any `cache_size` (1 GiB
/// is ~1,5 M answers, 2²¹ words).
const MAX_WORDS: usize = 1 << 24;
/// Halves every counter: each nibble shifted right, the bit that crossed
/// into the nibble below cleared.
const HALVE_MASK: u64 = 0x7777_7777_7777_7777;

#[derive(Debug, Clone, Default)]
pub(crate) struct Frequency {
    table: Vec<u64>,
    /// Blocks − 1 (their count is a power of two).
    block_mask: usize,
    /// Updates since the last halving…
    adds: usize,
    /// …and how many trigger it.
    sample: usize,
}

impl Frequency {
    /// A sketch for a cache of about `entries` answers; 0: none (every
    /// estimate is 0, nothing is counted).
    pub(crate) fn new(entries: usize) -> Self {
        if entries == 0 {
            return Self::default();
        }
        let words = entries
            .clamp(MIN_WORDS, MAX_WORDS)
            .checked_next_power_of_two()
            .unwrap_or(MAX_WORDS)
            .min(MAX_WORDS);
        Self {
            table: vec![0; words],
            block_mask: words / BLOCK_WORDS - 1,
            adds: 0,
            sample: words.saturating_mul(10),
        }
    }

    /// Words in the table (it is sized by them).
    pub(crate) fn words(&self) -> usize {
        self.table.len()
    }

    /// Memory the table takes.
    pub(crate) fn bytes(&self) -> usize {
        self.table.len() * std::mem::size_of::<u64>()
    }

    /// The four counters of `hash`: (word, bit shift). The block comes from
    /// the low bits, the word and nibble inside it from bits 32..56, so the
    /// two never overlap while the table has fewer than 2³² blocks.
    fn counters(&self, hash: u64) -> [(usize, u32); DEPTH] {
        // Truncation is the point: only the low bits pick the block.
        #[allow(clippy::cast_possible_truncation)]
        let base = (hash as usize & self.block_mask) * BLOCK_WORDS;
        let mut out = [(0, 0); DEPTH];
        for (i, o) in out.iter_mut().enumerate() {
            let pick = ((hash >> (32 + i)) & 1) as usize;
            // 0..=15: fits.
            #[allow(clippy::cast_possible_truncation)]
            let nibble = ((hash >> (40 + 4 * i)) & 15) as u32;
            *o = (base + 2 * i + pick, nibble * 4);
        }
        out
    }

    fn read(&self, (word, shift): (usize, u32)) -> u8 {
        // A nibble: fits.
        #[allow(clippy::cast_possible_truncation)]
        self.table
            .get(word)
            .map_or(0, |w| ((w >> shift) & 15) as u8)
    }

    /// How often `hash` was counted lately (0..=15), never less than the
    /// truth since the last halving.
    pub(crate) fn estimate(&self, hash: u64) -> u8 {
        if self.table.is_empty() {
            return 0;
        }
        self.counters(hash)
            .into_iter()
            .map(|c| self.read(c))
            .min()
            .unwrap_or(0)
    }

    /// Counts one more of `hash`.
    pub(crate) fn add(&mut self, hash: u64) {
        if self.table.is_empty() {
            return;
        }
        let counters = self.counters(hash);
        let min = counters.iter().map(|c| self.read(*c)).min().unwrap_or(15);
        if min >= 15 {
            return;
        }
        for c in counters {
            if self.read(c) == min
                && let Some(w) = self.table.get_mut(c.0)
            {
                *w += 1 << c.1;
            }
        }
        self.adds += 1;
        if self.adds >= self.sample {
            self.halve();
        }
    }

    /// Every counter in half (the reset): O(table), once every `sample`
    /// updates, so O(1) per update on average (~0,1 ns each, **estimado**:
    /// one pass over the words for every ten).
    fn halve(&mut self) {
        for w in &mut self.table {
            *w = (*w >> 1) & HALVE_MASK;
        }
        self.adds /= 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hash::BuildHasher;

    fn h(i: u64) -> u64 {
        std::hash::RandomState::new().hash_one(i)
    }

    #[test]
    fn counts_saturate_and_fade() {
        let mut f = Frequency::new(1000);
        assert_eq!(f.words(), 1024);
        let (a, b) = (h(1), h(2));
        for _ in 0..20 {
            f.add(a);
        }
        f.add(b);
        assert_eq!(f.estimate(a), 15, "4-bit counters stop at 15");
        assert!(f.estimate(b) >= 1);
        assert!(f.estimate(h(3)) <= 1, "unseen: 0 unless a collision");
        f.halve();
        assert_eq!(f.estimate(a), 7);
    }

    #[test]
    fn the_reset_comes_after_ten_times_the_size() {
        let mut f = Frequency::new(64);
        let hot = h(7);
        for _ in 0..15 {
            f.add(hot);
        }
        // 640 more updates of other keys: one halving.
        for i in 0..640u64 {
            f.add(h(1000 + i));
        }
        assert!(f.estimate(hot) <= 8, "halved once: {}", f.estimate(hot));
    }

    #[test]
    fn unique_keys_stay_low() {
        // 100 000 different keys into a sketch for 100 000: an unseen key
        // is estimated at 0 or 1 nearly always (conservative update).
        let mut f = Frequency::new(100_000);
        let s = std::hash::RandomState::new();
        for i in 0..100_000u64 {
            f.add(s.hash_one(i));
        }
        let high = (1_000_000..1_010_000u64)
            .filter(|i| f.estimate(s.hash_one(i)) > 1)
            .count();
        assert!(high < 100, "{high} of 10 000 unseen keys above 1");
    }

    #[test]
    fn no_table_no_counts() {
        let mut f = Frequency::new(0);
        f.add(h(1));
        assert_eq!((f.estimate(h(1)), f.bytes()), (0, 0));
    }
}
