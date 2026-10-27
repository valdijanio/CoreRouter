//! `/queue simple` as a block list with indexes (G0.21 × G4.9).
//!
//! Every `queue.simple.add` looked a name up by walking the list, and the
//! default name (`queue<k>`) by walking it once per candidate `k`: O(n²),
//! 100 ms per add with 10 000 queues named `queue1`… (**medido**). The
//! index, like the one of `/ppp secret` ([`crate::ppp_secrets`]), is built
//! on the first look, shared by the copies of the config, and kept by
//! [`SimpleQueues::push`], [`SimpleQueues::insert`],
//! [`SimpleQueues::update`] and [`SimpleQueues::remove`] (a write copies
//! one leaf of it); any other write through `DerefMut` drops it. It holds:
//!
//! - name → id (the first of a name wins, as the walk did);
//! - target → how many enabled queues hold it, so a command can tell in
//!   O(1) per target that no other queue covers it (and skip resolving
//!   the whole plan for its warnings);
//! - the lowest `k` with `queue1`…`queue<k-1>` all taken, so the default
//!   name is found without a walk.
//!
//! Serialized exactly like the list.

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::OnceLock;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::cow_list::CowList;
use crate::cow_map::CowMap;
use crate::queue::{SimpleQueue, Target};
use crate::types::ItemId;

#[derive(Clone, Default)]
struct Index {
    names: CowMap<String, ItemId>,
    /// Some name is there twice (edited by hand): a write that touches
    /// one rebuilds.
    dup: bool,
    /// Enabled queues' targets → how many hold each.
    targets: CowMap<Target, u32>,
    /// `queue1`…`queue<auto-1>` are all taken.
    auto: u64,
}

/// `k` of a default name `queue<k>`.
fn auto_number(name: &str) -> Option<u64> {
    let digits = name.strip_prefix("queue")?;
    if digits.starts_with('0') {
        return None;
    }
    digits.parse().ok()
}

impl Index {
    fn hold(&mut self, q: &SimpleQueue, up: bool) {
        if q.disabled {
            return;
        }
        for t in &q.target {
            let n = self.targets.get(t).copied().unwrap_or(0);
            let n = if up { n.saturating_add(1) } else { n.saturating_sub(1) };
            if n == 0 {
                self.targets.remove(t);
            } else {
                self.targets.insert(t.clone(), n);
            }
        }
    }

    fn skip_taken(&mut self) {
        while self.names.contains_key(format!("queue{}", self.auto).as_str()) {
            self.auto = self.auto.saturating_add(1);
        }
    }
}

#[derive(Default)]
pub struct SimpleQueues {
    list: CowList<SimpleQueue>,
    index: OnceLock<Index>,
}

impl SimpleQueues {
    pub fn from_list(list: CowList<SimpleQueue>) -> Self {
        Self {
            list,
            index: OnceLock::new(),
        }
    }

    fn index(&self) -> &Index {
        self.index.get_or_init(|| {
            let mut ix = Index {
                auto: 1,
                ..Index::default()
            };
            for q in &self.list {
                if ix.names.contains_key(q.name.as_str()) {
                    ix.dup = true;
                } else {
                    ix.names.insert(q.name.clone(), q.id);
                }
                ix.hold(q, true);
            }
            ix.skip_taken();
            ix
        })
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Position of the queue with id `id` (O(log n) while the list is in
    /// id order; a walk once queues were moved).
    pub fn position(&self, id: ItemId) -> Option<usize> {
        self.list.find_by_key(|q| q.id, &id)
    }

    /// Position of the queue named `name`.
    pub fn position_of(&self, name: &str) -> Option<usize> {
        let &id = self.index().names.get(name)?;
        match self.position(id) {
            Some(i) if self.list.get(i).is_some_and(|q| q.name == name) => Some(i),
            // Two queues with one id (never from the commands): the walk.
            _ => self.list.iter().position(|q| q.name == name),
        }
    }

    /// The queue named `name`.
    pub fn by_name(&self, name: &str) -> Option<&SimpleQueue> {
        self.position_of(name).and_then(|i| self.list.get(i))
    }

    /// How many enabled queues have `t` among their targets.
    pub fn holders(&self, t: &Target) -> u32 {
        self.index().targets.get(t).copied().unwrap_or(0)
    }

    /// The lowest free `queue<k>` (RouterOS names new queues so).
    pub fn free_name(&self) -> String {
        format!("queue{}", self.index().auto)
    }

    fn index_add(&mut self, q: &SimpleQueue) {
        let Some(ix) = self.index.get_mut() else {
            return;
        };
        if ix.names.contains_key(q.name.as_str()) {
            // A name twice (the commands refuse it): the walk decides.
            self.index = OnceLock::new();
            return;
        }
        ix.names.insert(q.name.clone(), q.id);
        ix.hold(q, true);
        if auto_number(&q.name) == Some(ix.auto) {
            ix.skip_taken();
        }
    }

    fn index_drop(&mut self, q: &SimpleQueue) {
        let Some(ix) = self.index.get_mut() else {
            return;
        };
        if ix.dup {
            self.index = OnceLock::new();
            return;
        }
        if ix.names.get(q.name.as_str()) == Some(&q.id) {
            ix.names.remove(q.name.as_str());
            if let Some(k) = auto_number(&q.name) {
                ix.auto = ix.auto.min(k);
            }
        }
        ix.hold(q, false);
    }

    /// Append, keeping the index.
    pub fn push(&mut self, q: SimpleQueue) {
        self.index_add(&q);
        self.list.push(q);
    }

    /// Insert at `i` (`false`: past the end, nothing done), keeping the
    /// index.
    pub fn insert(&mut self, i: usize, q: SimpleQueue) -> bool {
        if i > self.list.len() {
            return false;
        }
        self.index_add(&q);
        self.list.insert(i, q)
    }

    /// Change the queue at `i` with `f`, keeping the index. Only its block
    /// of the list is copied.
    pub fn update<R>(&mut self, i: usize, f: impl FnOnce(&mut SimpleQueue) -> R) -> Option<R> {
        let before = self.list.get(i)?.clone();
        let x = self.list.get_mut(i)?;
        let r = f(x);
        let moved = x.name != before.name || x.id != before.id || x.target != before.target || x.disabled != before.disabled;
        if moved {
            let now = x.clone();
            self.index_drop(&before);
            self.index_add(&now);
        }
        Some(r)
    }

    /// Remove the queue at `i`, keeping the index.
    pub fn remove(&mut self, i: usize) -> Option<SimpleQueue> {
        let q = self.list.remove(i)?;
        self.index_drop(&q);
        Some(q)
    }

    /// Both share the same list (nothing was written between them).
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        CowList::ptr_eq(&a.list, &b.list)
    }

    /// The list itself (for a revision delta).
    pub fn list(&self) -> &CowList<SimpleQueue> {
        &self.list
    }
}

impl Clone for SimpleQueues {
    fn clone(&self) -> Self {
        let index = OnceLock::new();
        if let Some(ix) = self.index.get() {
            let _ = index.set(ix.clone());
        }
        Self {
            list: self.list.clone(),
            index,
        }
    }
}

impl Deref for SimpleQueues {
    type Target = CowList<SimpleQueue>;
    fn deref(&self) -> &CowList<SimpleQueue> {
        &self.list
    }
}

/// Any write but the ones above: the index is dropped.
impl DerefMut for SimpleQueues {
    fn deref_mut(&mut self) -> &mut CowList<SimpleQueue> {
        self.index = OnceLock::new();
        &mut self.list
    }
}

impl From<Vec<SimpleQueue>> for SimpleQueues {
    fn from(v: Vec<SimpleQueue>) -> Self {
        Self::from_list(CowList::from(v))
    }
}

impl From<CowList<SimpleQueue>> for SimpleQueues {
    fn from(list: CowList<SimpleQueue>) -> Self {
        Self::from_list(list)
    }
}

impl FromIterator<SimpleQueue> for SimpleQueues {
    fn from_iter<I: IntoIterator<Item = SimpleQueue>>(iter: I) -> Self {
        Self::from_list(iter.into_iter().collect())
    }
}

impl<'a> IntoIterator for &'a SimpleQueues {
    type Item = &'a SimpleQueue;
    type IntoIter = crate::cow_list::Iter<'a, SimpleQueue>;
    fn into_iter(self) -> Self::IntoIter {
        self.list.iter()
    }
}

impl fmt::Debug for SimpleQueues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.list.fmt(f)
    }
}

impl PartialEq for SimpleQueues {
    fn eq(&self, other: &Self) -> bool {
        self.list == other.list
    }
}

impl Eq for SimpleQueues {}

impl Serialize for SimpleQueues {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.list.serialize(s)
    }
}

impl<'de> Deserialize<'de> for SimpleQueues {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        CowList::<SimpleQueue>::deserialize(d).map(Self::from_list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::parse_targets;

    fn q(id: u32, name: &str, target: &str) -> SimpleQueue {
        SimpleQueue::new(ItemId(id), name.into(), parse_targets(target).unwrap())
    }

    /// What the index answers, from a walk of the list.
    fn walked(v: &SimpleQueues, names: &[&str], targets: &[&str]) -> (Vec<Option<ItemId>>, Vec<u32>, String) {
        let ids = names
            .iter()
            .map(|n| v.iter().find(|x| x.name == *n).map(|x| x.id))
            .collect();
        let held = targets
            .iter()
            .map(|t| {
                let t: Target = t.parse().unwrap();
                v.iter().filter(|x| !x.disabled).map(|x| x.target.iter().filter(|y| **y == t).count() as u32).sum()
            })
            .collect();
        let free = (1..).map(|k| format!("queue{k}")).find(|n| v.iter().all(|x| x.name != *n)).unwrap();
        (ids, held, free)
    }

    fn indexed(v: &SimpleQueues, names: &[&str], targets: &[&str]) -> (Vec<Option<ItemId>>, Vec<u32>, String) {
        let ids = names.iter().map(|n| v.by_name(n).map(|x| x.id)).collect();
        let held = targets.iter().map(|t| v.holders(&t.parse().unwrap())).collect();
        (ids, held, v.free_name())
    }

    proptest::proptest! {
        /// The index kept through any series of writes answers what a walk
        /// of the list answers.
        #[test]
        fn index_equals_a_walk(ops in proptest::collection::vec((0u8..7, 0u16..300, 0u8..12), 1..60)) {
            let names = ["queue1", "queue2", "queue3", "queue4", "a", "b", "queue10"];
            let targets = ["10.0.0.1", "10.0.0.2", "ether1", "10.0.0.0/24"];
            let mut v = SimpleQueues::default();
            for i in 0..200u32 {
                let t = targets[(i % 4) as usize];
                v.push(q(i + 1, &format!("queue{}", i + 5), t));
            }
            let _ = v.free_name();
            let mut next = 1000u32;
            for (op, at, k) in ops {
                let at = usize::from(at) % v.len().max(1);
                let name = names[usize::from(k) % names.len()];
                let t = targets[usize::from(k) % targets.len()];
                match op {
                    0 => {
                        next += 1;
                        if v.by_name(name).is_none() {
                            v.push(q(next, name, t));
                        }
                    }
                    1 => {
                        next += 1;
                        if v.by_name(name).is_none() {
                            v.insert(at, q(next, name, t));
                        }
                    }
                    2 => {
                        v.remove(at);
                    }
                    3 => {
                        v.update(at, |x| x.disabled = !x.disabled);
                    }
                    4 => {
                        if v.by_name(name).is_none() {
                            v.update(at, |x| x.name = name.into());
                        }
                    }
                    5 => {
                        v.update(at, |x| x.target = parse_targets(t).unwrap());
                    }
                    _ => {
                        // A copy shares the index; a write through
                        // `DerefMut` drops it.
                        let mut c = v.clone();
                        if let Some(x) = c.get_mut(at) {
                            x.name = "queue1".into();
                        }
                        proptest::prop_assert_eq!(indexed(&c, &names, &targets), walked(&c, &names, &targets));
                    }
                }
                proptest::prop_assert_eq!(indexed(&v, &names, &targets), walked(&v, &names, &targets));
            }
        }
    }
}
