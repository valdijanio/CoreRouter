//! `CowList<T>`: a big config list in copy-on-write blocks (G0.21, G4.3gb).
//!
//! A [`crate::cow::CowArc`] section (G0.16) is copied whole on the first
//! write after a commit: one `ppp.secret.add` with 100 000 secrets copied
//! them all. Here the list is a spine of blocks of at most [`BLOCK`] items,
//! each block shared between copies of the config until one side writes
//! it. Cloning the list is one reference count; the first write after a
//! clone copies the spine (one pointer per block) and the block it
//! touches, so a write costs O(n / BLOCK + BLOCK), not O(n).
//!
//! It reads like a `Vec`: `len`, `get`, `iter` (double-ended, exact size),
//! `push`, `insert`, `remove`, `retain`, `get_mut`… The iteration order is
//! the order of the items, as in a `Vec`. There is no slice view (the items
//! are not contiguous): code that took `&[T]` takes `&CowList<T>` or an
//! iterator. A write through `iter_mut`/`retain_mut` makes every block its
//! own (it touches them all); [`CowList::find_mut`] copies one.
//!
//! Serialized exactly like a `Vec<T>` (the saved files do not change).
//! Equality skips the blocks two lists share. [`CowList::shared_blocks`]
//! tells a revision delta which runs of items a commit left alone.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::iter::FusedIterator;
use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Items per block. A write copies the spine (one pointer per block) and
/// one block. With 100 000 PPP secrets one write to a shared list costs
/// 27 / 16 / 13 / 18 µs with blocks of 32 / 64 / 128 / 256, and a walk the
/// same as a `Vec` (**medido**, `cargo bench -p corerouter-model --bench
/// cow_list`, 2026-10-26).
pub const BLOCK: usize = 128;

pub struct CowList<T> {
    spine: Arc<Spine<T>>,
}

struct Spine<T> {
    blocks: Vec<Arc<Vec<T>>>,
    /// `ends[k]`: the items in blocks `0..=k`.
    ends: Vec<usize>,
}

impl<T> Clone for Spine<T> {
    fn clone(&self) -> Self {
        Self {
            blocks: self.blocks.clone(),
            ends: self.ends.clone(),
        }
    }
}

impl<T> Default for Spine<T> {
    fn default() -> Self {
        Self {
            blocks: Vec::new(),
            ends: Vec::new(),
        }
    }
}

impl<T> Spine<T> {
    fn len(&self) -> usize {
        self.ends.last().copied().unwrap_or(0)
    }

    /// Block and offset of item `i`.
    fn locate(&self, i: usize) -> Option<(usize, usize)> {
        let k = self.ends.partition_point(|&e| e <= i);
        let start = k.checked_sub(1).and_then(|p| self.ends.get(p)).copied().unwrap_or(0);
        (k < self.blocks.len()).then(|| (k, i - start))
    }

    /// `ends` from block `k` on.
    fn reindex(&mut self, k: usize) {
        let mut acc = k.checked_sub(1).and_then(|p| self.ends.get(p)).copied().unwrap_or(0);
        self.ends.truncate(k);
        for b in self.blocks.iter().skip(k) {
            acc += b.len();
            self.ends.push(acc);
        }
    }

    /// Block `k` dropped if empty, or merged with a neighbour when both
    /// are small (removals never leave a spine of tiny blocks).
    fn tidy(&mut self, k: usize)
    where
        T: Clone,
    {
        let Some(len) = self.blocks.get(k).map(|b| b.len()) else {
            return;
        };
        if len == 0 {
            self.blocks.remove(k);
        } else if len < BLOCK / 4 {
            let next = self.blocks.get(k + 1).map(|b| b.len());
            let prev = k.checked_sub(1).and_then(|p| self.blocks.get(p)).map(|b| b.len());
            let into = match (prev, next) {
                (Some(p), _) if p + len <= BLOCK => k.checked_sub(1),
                (_, Some(n)) if n + len <= BLOCK => Some(k),
                _ => None,
            };
            if let Some(a) = into {
                let b = self.blocks.remove(a + 1);
                if let Some(first) = self.blocks.get_mut(a) {
                    Arc::make_mut(first).extend(Arc::unwrap_or_clone(b));
                }
            }
        }
        self.reindex(k.saturating_sub(1));
    }
}

impl<T> CowList<T> {
    pub fn new() -> Self {
        Self {
            spine: Arc::default(),
        }
    }

    pub fn len(&self) -> usize {
        self.spine.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Both share the whole list (nothing was written between them).
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        Arc::ptr_eq(&a.spine, &b.spine)
    }

    pub fn get(&self, i: usize) -> Option<&T> {
        let (k, o) = self.spine.locate(i)?;
        self.spine.blocks.get(k)?.get(o)
    }

    pub fn first(&self) -> Option<&T> {
        self.spine.blocks.first()?.first()
    }

    pub fn last(&self) -> Option<&T> {
        self.spine.blocks.last()?.last()
    }

    pub fn iter(&self) -> Iter<'_, T> {
        Iter {
            blocks: self.spine.blocks.iter(),
            front: Default::default(),
            back: Default::default(),
            left: self.len(),
        }
    }

    /// The items `start..start + len` (fewer past the end), without
    /// walking the ones before.
    pub fn range(&self, start: usize, len: usize) -> Iter<'_, T> {
        let blocks = &self.spine.blocks;
        let len = len.min(self.len().saturating_sub(start));
        let empty = Iter {
            blocks: Default::default(),
            front: Default::default(),
            back: Default::default(),
            left: 0,
        };
        let Some(last) = (start + len).checked_sub(1).filter(|_| len > 0) else {
            return empty;
        };
        let (Some((ka, oa)), Some((kb, ob))) = (self.spine.locate(start), self.spine.locate(last)) else {
            return empty;
        };
        let slice = |k: usize, from: usize, to: usize| -> std::slice::Iter<'_, T> {
            blocks
                .get(k)
                .and_then(|b| b.get(from..to))
                .unwrap_or_default()
                .iter()
        };
        if ka == kb {
            return Iter {
                blocks: Default::default(),
                front: slice(ka, oa, ob + 1),
                back: Default::default(),
                left: len,
            };
        }
        Iter {
            blocks: blocks.get(ka + 1..kb).unwrap_or_default().iter(),
            front: slice(ka, oa, blocks.get(ka).map_or(0, |b| b.len())),
            back: slice(kb, 0, ob + 1),
            left: len,
        }
    }

    /// The blocks in order, as slices.
    pub fn blocks(&self) -> impl ExactSizeIterator<Item = &[T]> + '_ {
        self.spine.blocks.iter().map(|b| b.as_slice())
    }

    /// For each block of `self`: the position in `old` of the same block
    /// when the two still share it, else `None`. A revision delta copies
    /// the shared runs and looks only at the rest.
    pub fn shared_blocks(&self, old: &Self) -> Vec<(usize, Option<usize>)> {
        let mut at = std::collections::HashMap::with_capacity(old.spine.blocks.len());
        let mut start = 0;
        for b in &old.spine.blocks {
            at.insert(Arc::as_ptr(b), start);
            start += b.len();
        }
        self.spine
            .blocks
            .iter()
            .map(|b| (b.len(), at.get(&Arc::as_ptr(b)).copied()))
            .collect()
    }

    /// The items of `self` outside the blocks it shares with `other`, in
    /// order; the blocks kept are shared, not copied. With one item
    /// changed between two copies of 60 000 routes it holds one block, so
    /// a diff serializes 128 items, not 120 000 (G0.31a).
    pub fn unshared(&self, other: &Self) -> Self {
        if Self::ptr_eq(self, other) {
            return Self::new();
        }
        let theirs: std::collections::HashSet<*const Vec<T>> =
            other.spine.blocks.iter().map(Arc::as_ptr).collect();
        let mut spine = Spine::default();
        let mut n = 0;
        for b in &self.spine.blocks {
            if b.is_empty() || theirs.contains(&Arc::as_ptr(b)) {
                continue;
            }
            n += b.len();
            spine.blocks.push(Arc::clone(b));
            spine.ends.push(n);
        }
        Self {
            spine: Arc::new(spine),
        }
    }

    /// An item in a block both lists hold, if there is one.
    pub fn any_shared(&self, other: &Self) -> Option<&T> {
        let theirs: std::collections::HashSet<*const Vec<T>> =
            other.spine.blocks.iter().map(Arc::as_ptr).collect();
        self.spine
            .blocks
            .iter()
            .find(|b| theirs.contains(&Arc::as_ptr(b)))
            .and_then(|b| b.first())
    }

    /// Position of the item whose `key` is `target`. A binary search when
    /// the list is in ascending `key` order (config lists are, by id: new
    /// items get the next id); otherwise, or when it misses, a walk.
    pub fn find_by_key<K: Ord>(&self, key: impl Fn(&T) -> K, target: &K) -> Option<usize> {
        let blocks = &self.spine.blocks;
        let k = blocks.partition_point(|b| b.last().is_some_and(|x| key(x) < *target));
        if let Some(b) = blocks.get(k)
            && let Ok(o) = b.binary_search_by(|x| key(x).cmp(target))
        {
            let start = k.checked_sub(1).and_then(|p| self.spine.ends.get(p)).copied().unwrap_or(0);
            return Some(start + o);
        }
        self.iter().position(|x| key(x) == *target)
    }
}

impl<T: Clone> CowList<T> {
    fn spine_mut(&mut self) -> &mut Spine<T> {
        Arc::make_mut(&mut self.spine)
    }

    /// Item `i`, writable: copies its block if shared.
    pub fn get_mut(&mut self, i: usize) -> Option<&mut T> {
        let (k, o) = self.spine.locate(i)?;
        let spine = self.spine_mut();
        Arc::make_mut(spine.blocks.get_mut(k)?).get_mut(o)
    }

    pub fn first_mut(&mut self) -> Option<&mut T> {
        self.get_mut(0)
    }

    pub fn last_mut(&mut self) -> Option<&mut T> {
        let n = self.len().checked_sub(1)?;
        self.get_mut(n)
    }

    /// The first item matching `pred`, writable: only its block is copied.
    pub fn find_mut(&mut self, pred: impl FnMut(&T) -> bool) -> Option<&mut T> {
        let i = self.iter().position(pred)?;
        self.get_mut(i)
    }

    pub fn push(&mut self, v: T) {
        let spine = self.spine_mut();
        match spine.blocks.last_mut() {
            Some(b) if b.len() < BLOCK => {
                Arc::make_mut(b).push(v);
                if let Some(e) = spine.ends.last_mut() {
                    *e += 1;
                }
            }
            _ => {
                let n = spine.len();
                let mut b = Vec::with_capacity(BLOCK);
                b.push(v);
                spine.blocks.push(Arc::new(b));
                spine.ends.push(n + 1);
            }
        }
    }

    /// Append items `start..start + len` of `src` (`false` past its end).
    /// Whole blocks of `src` are shared, not copied: a list rebuilt from a
    /// delta's copy runs costs the blocks that changed.
    pub fn extend_from(&mut self, src: &Self, start: usize, len: usize) -> bool {
        let Some(end) = start.checked_add(len).filter(|&e| e <= src.len()) else {
            return false;
        };
        let mut at = start;
        while at < end {
            let Some((k, o)) = src.spine.locate(at) else {
                return false;
            };
            let Some(b) = src.spine.blocks.get(k) else {
                return false;
            };
            let take = (b.len() - o).min(end - at);
            if o == 0 && take == b.len() {
                let spine = self.spine_mut();
                let n = spine.len();
                spine.blocks.push(Arc::clone(b));
                spine.ends.push(n + take);
            } else {
                for x in b.iter().skip(o).take(take) {
                    self.push(x.clone());
                }
            }
            at += take;
        }
        true
    }

    pub fn pop(&mut self) -> Option<T> {
        let n = self.len().checked_sub(1)?;
        self.remove(n)
    }

    /// Insert at `i` (`i == len` appends); `false` past the end.
    pub fn insert(&mut self, i: usize, v: T) -> bool {
        let n = self.len();
        if i > n {
            return false;
        }
        if i == n {
            self.push(v);
            return true;
        }
        let Some((k, o)) = self.spine.locate(i) else {
            return false;
        };
        let spine = self.spine_mut();
        let Some(b) = spine.blocks.get_mut(k) else {
            return false;
        };
        let b = Arc::make_mut(b);
        b.insert(o, v);
        if b.len() > BLOCK {
            let tail = b.split_off(b.len() / 2);
            spine.blocks.insert(k + 1, Arc::new(tail));
        }
        spine.reindex(k);
        true
    }

    /// Remove item `i` (`None` past the end).
    pub fn remove(&mut self, i: usize) -> Option<T> {
        let (k, o) = self.spine.locate(i)?;
        let spine = self.spine_mut();
        let b = spine.blocks.get_mut(k)?;
        let b = Arc::make_mut(b);
        if o >= b.len() {
            return None;
        }
        let v = b.remove(o);
        spine.tidy(k);
        Some(v)
    }

    /// Keep the items `keep` says yes to; a block where it says yes to all
    /// stays shared.
    pub fn retain(&mut self, mut keep: impl FnMut(&T) -> bool) {
        let mut verdicts: Vec<Option<Vec<bool>>> = Vec::with_capacity(self.spine.blocks.len());
        for b in &self.spine.blocks {
            let v: Vec<bool> = b.iter().map(&mut keep).collect();
            verdicts.push(v.contains(&false).then_some(v));
        }
        if verdicts.iter().all(Option::is_none) {
            return;
        }
        let spine = self.spine_mut();
        for (b, v) in spine.blocks.iter_mut().zip(verdicts) {
            if let Some(v) = v {
                let mut it = v.into_iter();
                Arc::make_mut(b).retain(|_| it.next().unwrap_or(true));
            }
        }
        spine.blocks.retain(|b| !b.is_empty());
        spine.reindex(0);
    }

    /// [`Self::retain`] with the items writable: every block is copied.
    pub fn retain_mut(&mut self, mut keep: impl FnMut(&mut T) -> bool) {
        let spine = self.spine_mut();
        for b in &mut spine.blocks {
            Arc::make_mut(b).retain_mut(&mut keep);
        }
        spine.blocks.retain(|b| !b.is_empty());
        spine.reindex(0);
    }

    pub fn clear(&mut self) {
        self.spine = Arc::default();
    }

    pub fn truncate(&mut self, n: usize) {
        if n < self.len() {
            let mut v = self.to_vec();
            v.truncate(n);
            *self = Self::from(v);
        }
    }

    /// Every item writable: every block is copied (if shared).
    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        let left = self.len();
        IterMut {
            blocks: self.spine_mut().blocks.iter_mut(),
            front: Default::default(),
            back: Default::default(),
            left,
        }
    }

    pub fn to_vec(&self) -> Vec<T> {
        self.iter().cloned().collect()
    }

    pub fn sort_by(&mut self, cmp: impl FnMut(&T, &T) -> std::cmp::Ordering) {
        let mut v = self.to_vec();
        v.sort_by(cmp);
        *self = Self::from(v);
    }

    pub fn sort_by_key<K: Ord>(&mut self, key: impl FnMut(&T) -> K) {
        let mut v = self.to_vec();
        v.sort_by_key(key);
        *self = Self::from(v);
    }

    /// Item `i` moved to position `to` (in the list without it).
    pub fn move_item(&mut self, i: usize, to: usize) -> bool {
        match self.remove(i) {
            Some(v) => self.insert(to.min(self.len()), v),
            None => false,
        }
    }
}

impl<T: PartialEq> CowList<T> {
    pub fn contains(&self, x: &T) -> bool {
        self.iter().any(|y| y == x)
    }
}

impl<T> Clone for CowList<T> {
    fn clone(&self) -> Self {
        Self {
            spine: Arc::clone(&self.spine),
        }
    }
}

impl<T> Default for CowList<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> From<Vec<T>> for CowList<T> {
    fn from(v: Vec<T>) -> Self {
        let mut spine = Spine::default();
        let mut it = v.into_iter().peekable();
        while it.peek().is_some() {
            let b: Vec<T> = it.by_ref().take(BLOCK).collect();
            spine.blocks.push(Arc::new(b));
        }
        spine.reindex(0);
        Self {
            spine: Arc::new(spine),
        }
    }
}

impl<T> FromIterator<T> for CowList<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self::from(iter.into_iter().collect::<Vec<T>>())
    }
}

impl<T: Clone> Extend<T> for CowList<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        for v in iter {
            self.push(v);
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for CowList<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<T: PartialEq> PartialEq for CowList<T> {
    fn eq(&self, other: &Self) -> bool {
        if Self::ptr_eq(self, other) {
            return true;
        }
        let (a, b) = (&self.spine, &other.spine);
        if a.ends != b.ends {
            return a.len() == b.len() && self.iter().eq(other.iter());
        }
        // Same block boundaries: the blocks still shared are skipped.
        a.blocks
            .iter()
            .zip(&b.blocks)
            .all(|(x, y)| Arc::ptr_eq(x, y) || **x == **y)
    }
}

impl<T: Eq> Eq for CowList<T> {}

impl<T: PartialEq> PartialEq<Vec<T>> for CowList<T> {
    fn eq(&self, other: &Vec<T>) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl<T: Hash> Hash for CowList<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_usize(self.len());
        for x in self {
            x.hash(state);
        }
    }
}

impl<T: Serialize> Serialize for CowList<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(self.iter())
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for CowList<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Vec::<T>::deserialize(d).map(Self::from)
    }
}

impl<'a, T> IntoIterator for &'a CowList<T> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;
    fn into_iter(self) -> Iter<'a, T> {
        self.iter()
    }
}

impl<'a, T: Clone> IntoIterator for &'a mut CowList<T> {
    type Item = &'a mut T;
    type IntoIter = IterMut<'a, T>;
    fn into_iter(self) -> IterMut<'a, T> {
        self.iter_mut()
    }
}

impl<T: Clone> IntoIterator for CowList<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;
    fn into_iter(self) -> Self::IntoIter {
        let spine = Arc::unwrap_or_clone(self.spine);
        let mut v = Vec::with_capacity(spine.len());
        for b in spine.blocks {
            v.extend(Arc::unwrap_or_clone(b));
        }
        v.into_iter()
    }
}

pub struct Iter<'a, T> {
    blocks: std::slice::Iter<'a, Arc<Vec<T>>>,
    front: std::slice::Iter<'a, T>,
    back: std::slice::Iter<'a, T>,
    left: usize,
}

impl<T> Clone for Iter<'_, T> {
    fn clone(&self) -> Self {
        Self {
            blocks: self.blocks.clone(),
            front: self.front.clone(),
            back: self.back.clone(),
            left: self.left,
        }
    }
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;
    fn next(&mut self) -> Option<&'a T> {
        loop {
            if let Some(x) = self.front.next() {
                self.left -= 1;
                return Some(x);
            }
            match self.blocks.next() {
                Some(b) => self.front = b.iter(),
                None => {
                    let x = self.back.next()?;
                    self.left -= 1;
                    return Some(x);
                }
            }
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl<T> DoubleEndedIterator for Iter<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(x) = self.back.next_back() {
                self.left -= 1;
                return Some(x);
            }
            match self.blocks.next_back() {
                Some(b) => self.back = b.iter(),
                None => {
                    let x = self.front.next_back()?;
                    self.left -= 1;
                    return Some(x);
                }
            }
        }
    }
}

impl<T> ExactSizeIterator for Iter<'_, T> {}
impl<T> FusedIterator for Iter<'_, T> {}

pub struct IterMut<'a, T> {
    blocks: std::slice::IterMut<'a, Arc<Vec<T>>>,
    front: std::slice::IterMut<'a, T>,
    back: std::slice::IterMut<'a, T>,
    left: usize,
}

impl<'a, T: Clone> Iterator for IterMut<'a, T> {
    type Item = &'a mut T;
    fn next(&mut self) -> Option<&'a mut T> {
        loop {
            if let Some(x) = self.front.next() {
                self.left -= 1;
                return Some(x);
            }
            match self.blocks.next() {
                Some(b) => self.front = Arc::make_mut(b).iter_mut(),
                None => {
                    let x = self.back.next()?;
                    self.left -= 1;
                    return Some(x);
                }
            }
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl<T: Clone> DoubleEndedIterator for IterMut<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(x) = self.back.next_back() {
                self.left -= 1;
                return Some(x);
            }
            match self.blocks.next_back() {
                Some(b) => self.back = Arc::make_mut(b).iter_mut(),
                None => {
                    let x = self.front.next_back()?;
                    self.left -= 1;
                    return Some(x);
                }
            }
        }
    }
}

impl<T: Clone> ExactSizeIterator for IterMut<'_, T> {}
impl<T: Clone> FusedIterator for IterMut<'_, T> {}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum Op {
        Push(u32),
        Insert(usize, u32),
        Remove(usize),
        Set(usize, u32),
        RetainOdd,
        Snapshot,
        Pop,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            4 => any::<u32>().prop_map(Op::Push),
            2 => (any::<usize>(), any::<u32>()).prop_map(|(i, v)| Op::Insert(i, v)),
            2 => any::<usize>().prop_map(Op::Remove),
            2 => (any::<usize>(), any::<u32>()).prop_map(|(i, v)| Op::Set(i, v)),
            1 => Just(Op::RetainOdd),
            1 => Just(Op::Snapshot),
            1 => Just(Op::Pop),
        ]
    }

    #[test]
    fn unshared_keeps_the_blocks_one_side_wrote() {
        let a: CowList<u32> = (0..1000).collect::<Vec<_>>().into();
        assert!(a.unshared(&a.clone()).is_empty());
        let mut b = a.clone();
        *b.get_mut(500).unwrap() = 7;
        b.push(1000);
        let (x, y) = (a.unshared(&b), b.unshared(&a));
        assert!(x.len() <= 2 * BLOCK && y.len() <= 2 * BLOCK, "{} {}", x.len(), y.len());
        assert!(x.iter().any(|&v| v == 500) && !x.iter().any(|&v| v == 7));
        assert!(y.iter().any(|&v| v == 7) && y.iter().any(|&v| v == 1000));
        assert_eq!(a.any_shared(&b), Some(&0));
        assert_eq!(a.any_shared(&CowList::new()), None);
    }

    proptest! {
        /// Every write gives what a `Vec` gives, and every snapshot taken
        /// on the way keeps exactly what it had.
        #[test]
        fn behaves_like_a_vec(start in 0usize..300, ops in proptest::collection::vec(op(), 0..300)) {
            let init: Vec<u32> = (0..u32::try_from(start).unwrap()).collect();
            let mut v = init.clone();
            let mut l = CowList::from(init);
            let mut snaps: Vec<(CowList<u32>, Vec<u32>)> = Vec::new();
            for op in ops {
                match op {
                    Op::Push(x) => { v.push(x); l.push(x); }
                    Op::Insert(i, x) => {
                        let i = i % (v.len() + 1);
                        v.insert(i, x);
                        prop_assert!(l.insert(i, x));
                    }
                    Op::Remove(i) => {
                        if v.is_empty() {
                            prop_assert_eq!(l.remove(i), None);
                        } else {
                            let i = i % v.len();
                            prop_assert_eq!(l.remove(i), Some(v.remove(i)));
                        }
                    }
                    Op::Set(i, x) => {
                        if !v.is_empty() {
                            let i = i % v.len();
                            v[i] = x;
                            *l.get_mut(i).unwrap() = x;
                        }
                    }
                    Op::RetainOdd => { v.retain(|x| x % 2 == 1); l.retain(|x| x % 2 == 1); }
                    Op::Snapshot => snaps.push((l.clone(), v.clone())),
                    Op::Pop => prop_assert_eq!(l.pop(), v.pop()),
                }
                prop_assert_eq!(l.len(), v.len());
            }
            prop_assert_eq!(&l, &v);
            prop_assert!(l.iter().rev().eq(v.iter().rev()));
            for (i, x) in v.iter().enumerate() {
                prop_assert_eq!(l.get(i), Some(x));
            }
            prop_assert_eq!(l.get(v.len()), None);
            for (s, want) in &snaps {
                prop_assert_eq!(s, want);
            }
            // Block sizes stay bounded.
            prop_assert!(l.blocks().all(|b| !b.is_empty() && b.len() <= BLOCK));
            let json = serde_json::to_string(&l).unwrap();
            prop_assert_eq!(&json, &serde_json::to_string(&v).unwrap());
            let back: CowList<u32> = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(back, l);
        }
    }

    #[test]
    fn range_walks_both_ways() {
        let a: CowList<u32> = (0..1000).collect();
        for (s, n) in [(0, 0), (0, 1000), (5, 10), (100, 300), (127, 2), (999, 5), (1000, 3), (2000, 1)] {
            let want: Vec<u32> = (0..1000u32).skip(s).take(n).collect();
            let got: Vec<u32> = a.range(s, n).copied().collect();
            assert_eq!(got, want, "{s}+{n}");
            let back: Vec<u32> = a.range(s, n).rev().copied().collect();
            assert_eq!(back, want.iter().rev().copied().collect::<Vec<_>>(), "{s}+{n}");
            assert_eq!(a.range(s, n).len(), want.len());
        }
    }

    #[test]
    fn extend_from_shares_whole_blocks() {
        let a: CowList<u32> = (0..1000).collect();
        let mut b = CowList::new();
        assert!(b.extend_from(&a, 0, 300));
        b.push(7);
        assert!(b.extend_from(&a, 300, 700));
        assert!(!b.extend_from(&a, 999, 2));
        let want: Vec<u32> = (0..300).chain([7]).chain(300..1000).collect();
        assert_eq!(b, want);
        let shared = b.shared_blocks(&a);
        assert!(shared.iter().filter(|(_, at)| at.is_some()).count() >= 5, "{shared:?}");
        assert!(b.blocks().all(|x| !x.is_empty() && x.len() <= BLOCK));
    }

    #[test]
    fn a_write_copies_one_block() {
        let mut a: CowList<u32> = (0..10_000).collect();
        let b = a.clone();
        assert!(CowList::ptr_eq(&a, &b));
        *a.get_mut(5000).unwrap() = 7;
        assert!(!CowList::ptr_eq(&a, &b));
        let shared = a.shared_blocks(&b);
        assert_eq!(shared.iter().filter(|(_, at)| at.is_none()).count(), 1);
        assert_eq!(b.get(5000), Some(&5000));
        assert_eq!(a.get(5000), Some(&7));
        a.push(1);
        let shared = a.shared_blocks(&b);
        assert_eq!(shared.iter().filter(|(_, at)| at.is_none()).count(), 2);
        assert_ne!(a, b);
    }

    #[test]
    fn find_by_key_searches_sorted_lists_and_walks_the_rest() {
        let mut a: CowList<u32> = (0..1000).map(|x| x * 2).collect();
        assert_eq!(a.find_by_key(|x| *x, &500), Some(250));
        assert_eq!(a.find_by_key(|x| *x, &501), None);
        a.insert(0, 3001);
        assert_eq!(a.find_by_key(|x| *x, &3001), Some(0));
        assert_eq!(a.find_by_key(|x| *x, &500), Some(251));
    }

    #[test]
    fn removals_do_not_leave_tiny_blocks() {
        let mut a: CowList<u32> = (0..10_000).collect();
        a.retain(|x| x % 50 == 0);
        assert_eq!(a.len(), 200);
        for i in (0..200).rev().step_by(2) {
            a.remove(i);
        }
        assert_eq!(a.len(), 100);
        assert!(a.blocks().len() <= 200);
    }
}
