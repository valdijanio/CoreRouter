//! Fixed-memory counting for the forwarder's statistics (G4.1za, G4.1zb):
//! the heaviest keys of a stream, the rate of each, and how many different
//! names a domain was asked for.
//!
//! - [`TopK`]: Space-Saving (Metwally, Agrawal, El Abbadi, "Efficient
//!   computation of frequent and top-k elements in data streams", 2005) over
//!   an indexed min-heap. At most `CAP` keys; a newcomer to a full table
//!   takes the place of the smallest count and starts from it, so every
//!   count is the truth plus at most its `error`, and a key heavier than
//!   `total / CAP` is never lost. Cost per event: a hash lookup and at most
//!   log₂ `CAP` heap swaps (8 for 256): bounded by `CAP`, not by how many
//!   different keys the stream has (a flood of spoofed sources or random
//!   names costs what a single client costs).
//! - [`Rate`]: events per second over the last 10 s, from two 10 s
//!   buckets (the sliding-window estimate rate limiters use); O(1), no
//!   timer.
//! - [`Hll`]: HyperLogLog (Flajolet, Fusy, Gandouet, Meunier 2007) with 256
//!   one-byte registers: how many different names, ±6.5 % (1.04/√256),
//!   in 256 bytes whatever the count. Two merge by taking the larger
//!   register (the union), which is how the stripes are summed.
//!
//! Keys are found by a 64-bit keyed hash ([`std::hash::RandomState`]: a
//! client cannot aim names at one bucket) the caller computes once; the
//! table stores the key itself to tell the 2⁻⁶⁴ collision apart.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::net::IpAddr;

/// Passes a hash through (the keys of [`TopK`]'s index already are one).
#[derive(Debug, Default)]
pub struct PassHasher(u64);

impl Hasher for PassHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        // Never called for `u64` keys; folded anyway to stay a hash.
        for b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(*b);
        }
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = n;
    }
}

type PassMap<V> = HashMap<u64, V, BuildHasherDefault<PassHasher>>;

/// A key a [`TopK`] slot holds, written in place when the slot changes
/// hands (a name reuses its buffer: no allocation once the table is warm).
pub trait SlotKey {
    type Ref: ?Sized;
    fn of(r: &Self::Ref) -> Self;
    fn is(&self, r: &Self::Ref) -> bool;
    fn set(&mut self, r: &Self::Ref);
}

impl SlotKey for IpAddr {
    type Ref = IpAddr;
    fn of(r: &IpAddr) -> Self {
        *r
    }
    fn is(&self, r: &IpAddr) -> bool {
        self == r
    }
    fn set(&mut self, r: &IpAddr) {
        *self = *r;
    }
}

impl SlotKey for String {
    type Ref = str;
    fn of(r: &str) -> Self {
        r.to_owned()
    }
    fn is(&self, r: &str) -> bool {
        self == r
    }
    fn set(&mut self, r: &str) {
        self.clear();
        self.push_str(r);
    }
}

/// One key of a [`TopK`] and what is counted with it.
#[derive(Debug, Clone)]
pub struct Entry<K, V> {
    pub key: K,
    hash: u64,
    /// Events counted (Space-Saving: at most `error` of them belong to keys
    /// this one replaced).
    pub count: u64,
    pub error: u64,
    /// The caller's counts for this key (reset when the slot changes hands).
    pub value: V,
}

/// The `CAP` heaviest keys, Space-Saving (see the module).
#[derive(Debug)]
pub struct TopK<K, V, const CAP: usize> {
    slots: Vec<Entry<K, V>>,
    /// Slot numbers, a min-heap by their `count`.
    heap: Vec<usize>,
    /// Where each slot sits in `heap`.
    pos: Vec<usize>,
    index: PassMap<usize>,
    /// Newcomers that took another key's place.
    replaced: u64,
}

impl<K, V, const CAP: usize> Default for TopK<K, V, CAP> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            heap: Vec::new(),
            pos: Vec::new(),
            index: PassMap::default(),
            replaced: 0,
        }
    }
}

impl<K: SlotKey, V: Default, const CAP: usize> TopK<K, V, CAP> {
    /// Counts `weight` events for `key` (whose hash is `hash`) and gives its
    /// entry; `None` when another key has the same hash (2⁻⁶⁴) or `CAP` is 0.
    pub fn add(&mut self, hash: u64, key: &K::Ref, weight: u64) -> Option<&mut Entry<K, V>> {
        let slot = match self.index.get(&hash) {
            Some(&s) => {
                if !self.slots.get(s).is_some_and(|e| e.key.is(key)) {
                    return None;
                }
                s
            }
            None if self.slots.len() < CAP => {
                let s = self.slots.len();
                self.slots.push(Entry {
                    key: K::of(key),
                    hash,
                    count: 0,
                    error: 0,
                    value: V::default(),
                });
                self.heap.push(s);
                self.pos.push(s);
                self.index.insert(hash, s);
                // A count of 0 is the smallest: up to the root.
                self.sift_up(s);
                s
            }
            None => {
                // Space-Saving: the smallest count makes room.
                let &s = self.heap.first()?;
                let e = self.slots.get_mut(s)?;
                let gone = e.hash;
                e.key.set(key);
                e.hash = hash;
                e.error = e.count;
                e.value = V::default();
                self.index.remove(&gone);
                self.index.insert(hash, s);
                self.replaced += 1;
                s
            }
        };
        if let Some(e) = self.slots.get_mut(slot) {
            e.count = e.count.saturating_add(weight);
        }
        if let Some(h) = self.pos.get(slot).copied() {
            self.sift_down(h);
        }
        self.slots.get_mut(slot)
    }

    /// The entries, in no order.
    pub fn iter(&self) -> impl Iterator<Item = &Entry<K, V>> {
        self.slots.iter()
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Newcomers that took another key's place since the table was made.
    pub fn replaced(&self) -> u64 {
        self.replaced
    }

    fn count_at(&self, h: usize) -> u64 {
        self.heap
            .get(h)
            .and_then(|s| self.slots.get(*s))
            .map_or(u64::MAX, |e| e.count)
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.heap.swap(a, b);
        for h in [a, b] {
            if let Some(&slot) = self.heap.get(h)
                && let Some(p) = self.pos.get_mut(slot)
            {
                *p = h;
            }
        }
    }

    /// The count at heap position `h` grew: down to its place.
    fn sift_down(&mut self, mut h: usize) {
        loop {
            let (l, r) = (2 * h + 1, 2 * h + 2);
            let mut least = h;
            if self.count_at(l) < self.count_at(least) {
                least = l;
            }
            if self.count_at(r) < self.count_at(least) {
                least = r;
            }
            if least == h {
                return;
            }
            self.swap(h, least);
            h = least;
        }
    }

    fn sift_up(&mut self, mut h: usize) {
        while h > 0 {
            let parent = (h - 1) / 2;
            if self.count_at(parent) <= self.count_at(h) {
                return;
            }
            self.swap(h, parent);
            h = parent;
        }
    }

    /// Whether the heap and the index agree with the slots (tests).
    #[cfg(test)]
    fn consistent(&self) -> bool {
        let mut seen: Vec<usize> = self.heap.clone();
        seen.sort_unstable();
        let order = self.heap.iter().enumerate().all(|(h, _)| {
            [2 * h + 1, 2 * h + 2]
                .iter()
                .all(|c| self.count_at(h) <= self.count_at(*c))
        });
        let pos = self
            .heap
            .iter()
            .enumerate()
            .all(|(h, s)| self.pos.get(*s) == Some(&h));
        let index = self.index.len() == self.slots.len()
            && self
                .slots
                .iter()
                .enumerate()
                .all(|(s, e)| self.index.get(&e.hash) == Some(&s));
        seen == (0..self.slots.len()).collect::<Vec<_>>() && order && pos && index
    }
}

/// The window [`Rate`] averages over.
pub const RATE_WINDOW_MS: u64 = 10_000;

/// Events per second over the last [`RATE_WINDOW_MS`]: the events of the
/// current 10 s bucket plus the share of the previous one still inside the
/// window (assumed spread evenly).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rate {
    /// `now_ms / RATE_WINDOW_MS` of the current bucket.
    epoch: u64,
    cur: u64,
    prev: u64,
}

impl Rate {
    /// `n` events at `now_ms`. A time behind the current bucket (another
    /// thread's clock read a little earlier) counts in the current one.
    pub fn add(&mut self, now_ms: u64, n: u64) {
        let e = now_ms / RATE_WINDOW_MS;
        if e > self.epoch {
            self.prev = if e == self.epoch + 1 { self.cur } else { 0 };
            self.cur = 0;
            self.epoch = e;
        }
        self.cur = self.cur.saturating_add(n);
    }

    /// Events per second over the window that ends at `now_ms`.
    pub fn per_sec(&self, now_ms: u64) -> f64 {
        let e = now_ms / RATE_WINDOW_MS;
        let (cur, prev) = match e.checked_sub(self.epoch) {
            Some(0) | None => (self.cur, self.prev),
            Some(1) => (0, self.cur),
            Some(_) => (0, 0),
        };
        let into = (now_ms % RATE_WINDOW_MS) as f64 / RATE_WINDOW_MS as f64;
        (prev as f64 * (1.0 - into) + cur as f64) / (RATE_WINDOW_MS as f64 / 1000.0)
    }
}

/// Registers of an [`Hll`] (2⁸: the top 8 bits of the hash pick one).
pub const HLL_REGISTERS: usize = 256;

/// HyperLogLog: how many different hashes were added (see the module).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hll([u8; HLL_REGISTERS]);

impl Default for Hll {
    fn default() -> Self {
        Self([0; HLL_REGISTERS])
    }
}

impl Hll {
    pub fn add(&mut self, hash: u64) {
        let i = usize::try_from(hash >> 56).unwrap_or(0);
        // The rank of the first 1 in the other 56 bits (57: none).
        let rest = hash << 8;
        let rank = u8::try_from((rest.leading_zeros() + 1).min(57)).unwrap_or(57);
        if let Some(r) = self.0.get_mut(i)
            && rank > *r
        {
            *r = rank;
        }
    }

    /// The union with `other`.
    pub fn merge(&mut self, other: &Hll) {
        for (a, b) in self.0.iter_mut().zip(other.0.iter()) {
            *a = (*a).max(*b);
        }
    }

    /// The estimate of different hashes added (Flajolet et al. §4, with
    /// linear counting for small sets; a 64-bit hash needs no correction
    /// for large ones).
    pub fn estimate(&self) -> u64 {
        let m = HLL_REGISTERS as f64;
        let alpha = 0.7213 / (1.0 + 1.079 / m);
        let mut sum = 0.0;
        let mut zeros = 0u32;
        for r in &self.0 {
            sum += 1.0 / f64::from(1u32 << (*r).min(31));
            if *r == 0 {
                zeros += 1;
            }
        }
        let raw = alpha * m * m / sum;
        let e = if raw <= 2.5 * m && zeros > 0 {
            m * (m / f64::from(zeros)).ln()
        } else {
            raw
        };
        e.round() as u64
    }
}

#[cfg(test)]
mod tests {
    use std::hash::BuildHasher;

    use proptest::prelude::*;

    use super::*;

    fn hash(s: &impl std::hash::Hash) -> u64 {
        // Fixed keys: the tests are the same every run.
        BuildHasherDefault::<std::collections::hash_map::DefaultHasher>::default().hash_one(s)
    }

    #[test]
    fn space_saving_keeps_the_heavy_key_in_a_flood() {
        let mut t: TopK<String, (), 64> = TopK::default();
        for _ in 0..50 {
            t.add(hash(&"heavy"), "heavy", 1).unwrap();
        }
        for i in 0..64 * 3 {
            let k = format!("x{i}.example");
            t.add(hash(&k), &k, 1).unwrap();
        }
        assert_eq!(t.len(), 64, "bounded");
        let h = t.iter().find(|e| e.key == "heavy").unwrap();
        assert_eq!((h.count, h.error), (50, 0), "never replaced");
        assert!(t.replaced() >= 64 * 2);
        assert!(
            t.iter().all(|e| e.count > e.error),
            "count ≥ truth ≥ count − error"
        );
        assert!(t.consistent());
    }

    #[test]
    fn a_hash_collision_is_not_counted_on_the_other_key() {
        let mut t: TopK<String, u8, 4> = TopK::default();
        t.add(7, "a", 1).unwrap().value = 1;
        assert!(t.add(7, "b", 1).is_none());
        let a = t.iter().next().unwrap();
        assert_eq!((a.key.as_str(), a.count, a.value), ("a", 1, 1));
    }

    #[test]
    fn a_replaced_slot_starts_over() {
        let mut t: TopK<IpAddr, u32, 1> = TopK::default();
        let a = IpAddr::from([10, 0, 0, 1]);
        let b = IpAddr::from([10, 0, 0, 2]);
        t.add(hash(&a), &a, 3).unwrap().value = 9;
        let e = t.add(hash(&b), &b, 1).unwrap();
        assert_eq!((e.key, e.count, e.error, e.value), (b, 4, 3, 0));
        assert!(t.consistent());
    }

    proptest! {
        /// Space-Saving's guarantee (Metwally et al., Lemma 3.4): every
        /// key counted at least `total / CAP` times is in the table, and
        /// each count is within its error of the truth.
        #[test]
        fn space_saving_bounds(stream in prop::collection::vec(0u16..300, 0..2000)) {
            let mut t: TopK<String, (), 16> = TopK::default();
            let mut truth: HashMap<String, u64> = HashMap::new();
            for k in &stream {
                let k = k.to_string();
                t.add(hash(&k), &k, 1).unwrap();
                *truth.entry(k).or_default() += 1;
            }
            prop_assert!(t.consistent());
            let total = stream.len() as u64;
            for e in t.iter() {
                let real = truth.get(&e.key).copied().unwrap_or(0);
                prop_assert!(e.count >= real && e.count - e.error <= real, "{} {} {} {}", e.key, e.count, e.error, real);
            }
            for (k, n) in &truth {
                if *n > total / 16 {
                    prop_assert!(t.iter().any(|e| &e.key == k), "{k} ({n} of {total}) lost");
                }
            }
        }

        #[test]
        fn hll_merge_is_the_union(a in prop::collection::vec(any::<u64>(), 0..400), b in prop::collection::vec(any::<u64>(), 0..400)) {
            let (mut x, mut y, mut both) = (Hll::default(), Hll::default(), Hll::default());
            for h in &a { x.add(*h); both.add(*h); }
            for h in &b { y.add(*h); both.add(*h); }
            x.merge(&y);
            prop_assert_eq!(x, both);
        }
    }

    #[test]
    fn hll_estimates_within_its_error() {
        for n in [0u64, 1, 10, 100, 1_000, 10_000, 100_000] {
            let mut h = Hll::default();
            for i in 0..n {
                h.add(hash(&format!("{i}.random.example")));
                // Repeats do not count.
                h.add(hash(&format!("{i}.random.example")));
            }
            let e = h.estimate() as f64;
            let err = if n == 0 {
                e
            } else {
                (e - n as f64).abs() / n as f64
            };
            // Three standard errors (1.04/√256 = 6.5 %).
            assert!(err <= if n == 0 { 0.0 } else { 0.2 }, "{n}: {e}");
        }
    }

    #[test]
    fn rate_over_a_sliding_window() {
        let mut r = Rate::default();
        // 50 events a second for 20 s.
        for s in 100..120u64 {
            r.add(s * 1000, 50);
        }
        let now = 120 * 1000;
        assert!((r.per_sec(now) - 50.0).abs() < 0.01, "{}", r.per_sec(now));
        // Half-way into the next bucket with nothing: half the previous.
        assert!((r.per_sec(125_000) - 25.0).abs() < 0.01);
        // Quiet for longer than the window: zero.
        assert_eq!(r.per_sec(140_000), 0.0);
        // An event with a clock a little behind counts now.
        r.add(119_000, 1);
        assert_eq!(r.per_sec(120_000).round(), 50.0);
    }
}
