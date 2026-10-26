//! `CowMap<K, V>`: a hash map shared between copies of the config, copied
//! a little at a time (G4.3gb).
//!
//! The indexes of a big list (a secret by name, by fixed address) live
//! with the list and are shared by every copy of the config. A plain
//! `HashMap` behind an `Arc` is copied whole by the first write after a
//! copy: 100 000 names for one `ppp.secret.add`. Here the entries hang
//! from a fixed two-level tree of 64 × 64 leaves by their hash, every node
//! shared until written: a write copies two nodes of 64 pointers and one
//! leaf (n / 4096 entries, ~25 for 100 000).
//!
//! The hash keys are random per map (`RandomState`): a name chosen to
//! collide cannot pile up one leaf.

use std::borrow::Borrow;
use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hash};
use std::sync::Arc;

const FAN: usize = 64;

type Leaf<K, V> = Vec<(u64, K, V)>;
type Mid<K, V> = Vec<Option<Arc<Leaf<K, V>>>>;
type Root<K, V> = Vec<Option<Arc<Mid<K, V>>>>;

pub struct CowMap<K, V> {
    root: Arc<Root<K, V>>,
    len: usize,
    hasher: RandomState,
}

impl<K, V> Clone for CowMap<K, V> {
    fn clone(&self) -> Self {
        Self {
            root: Arc::clone(&self.root),
            len: self.len,
            hasher: self.hasher.clone(),
        }
    }
}

impl<K, V> Default for CowMap<K, V> {
    fn default() -> Self {
        Self {
            root: Arc::new(vec![None; FAN]),
            len: 0,
            hasher: RandomState::new(),
        }
    }
}

/// Root and middle slots of hash `h`.
fn slots(h: u64) -> (usize, usize) {
    let a = usize::try_from(h >> 58).unwrap_or(0);
    let b = usize::try_from((h >> 52) & 63).unwrap_or(0);
    (a, b)
}

impl<K: Hash + Eq, V> CowMap<K, V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn hash<Q: Hash + ?Sized>(&self, k: &Q) -> u64 {
        self.hasher.hash_one(k)
    }

    pub fn get<Q>(&self, k: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let h = self.hash(k);
        let (a, b) = slots(h);
        let leaf = self.root.get(a)?.as_ref()?.get(b)?.as_ref()?;
        leaf.iter()
            .find(|(hh, kk, _)| *hh == h && kk.borrow() == k)
            .map(|(_, _, v)| v)
    }

    pub fn contains_key<Q>(&self, k: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.get(k).is_some()
    }

    /// Every entry, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.root
            .iter()
            .flatten()
            .flat_map(|m| m.iter().flatten())
            .flat_map(|l| l.iter().map(|(_, k, v)| (k, v)))
    }
}

impl<K: Hash + Eq + Clone, V: Clone> CowMap<K, V> {
    /// The leaf of hash `h`, writable (created if missing; the nodes on
    /// the way copied if shared).
    fn leaf_mut(&mut self, h: u64) -> Option<&mut Leaf<K, V>> {
        let (a, b) = slots(h);
        let mid = Arc::make_mut(&mut self.root).get_mut(a)?;
        let mid = Arc::make_mut(mid.get_or_insert_with(|| Arc::new(vec![None; FAN])));
        let leaf = mid.get_mut(b)?;
        Some(Arc::make_mut(leaf.get_or_insert_with(|| Arc::new(Vec::new()))))
    }

    /// Insert or replace; the old value back.
    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        let h = self.hash(&k);
        let leaf = self.leaf_mut(h)?;
        if let Some(slot) = leaf.iter_mut().find(|(hh, kk, _)| *hh == h && *kk == k) {
            return Some(std::mem::replace(&mut slot.2, v));
        }
        leaf.push((h, k, v));
        self.len += 1;
        None
    }

    pub fn remove<Q>(&mut self, k: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        if !self.contains_key(k) {
            return None;
        }
        let h = self.hash(k);
        let leaf = self.leaf_mut(h)?;
        let i = leaf.iter().position(|(hh, kk, _)| *hh == h && kk.borrow() == k)?;
        let (_, _, v) = leaf.swap_remove(i);
        self.len -= 1;
        Some(v)
    }
}

impl<K: Hash + Eq + Clone, V: Clone> FromIterator<(K, V)> for CowMap<K, V> {
    /// The first value of a key wins (as an index of a list built by a
    /// walk from the start).
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut m = Self::new();
        for (k, v) in iter {
            if !m.contains_key(&k) {
                m.insert(k, v);
            }
        }
        m
    }
}

impl<K: fmt::Debug + Hash + Eq, V: fmt::Debug> fmt::Debug for CowMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap;

    proptest! {
        #[test]
        fn behaves_like_a_hash_map(ops in proptest::collection::vec((0u16..300, any::<Option<u8>>(), any::<bool>()), 0..400)) {
            let mut m: CowMap<String, u8> = CowMap::new();
            let mut h: HashMap<String, u8> = HashMap::new();
            let mut snaps = Vec::new();
            for (k, v, snap) in ops {
                let k = format!("k{k}");
                match v {
                    Some(v) => prop_assert_eq!(m.insert(k.clone(), v), h.insert(k, v)),
                    None => prop_assert_eq!(m.remove(k.as_str()), h.remove(&k)),
                }
                if snap { snaps.push((m.clone(), h.clone())); }
                prop_assert_eq!(m.len(), h.len());
            }
            for (s, want) in snaps.iter().chain([(m.clone(), h.clone())].iter()) {
                prop_assert_eq!(s.len(), want.len());
                for (k, v) in want {
                    prop_assert_eq!(s.get(k.as_str()), Some(v));
                }
                prop_assert_eq!(s.iter().count(), want.len());
            }
        }
    }
}
