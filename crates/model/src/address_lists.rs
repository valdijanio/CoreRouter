//! `/ip firewall address-list` (static entries) as a block list with an
//! index of what each list holds (G0.21).
//!
//! An add refuses an address already in the list: with 60 000 entries the
//! walk of the list cost more than the rest of the command. The index
//! counts the entries of each (list, address) — a count, so a config edited
//! by hand with an entry twice stays exact. It is built on the first look,
//! shared by the copies of the config, and kept by [`AddressLists::push`],
//! [`AddressLists::update`] and [`AddressLists::remove`] (a write copies one
//! leaf of it, [`CowMap`]). Any other write through `DerefMut` drops it.
//!
//! Serialized exactly like the list.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::{Deref, DerefMut};
use std::sync::OnceLock;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::cow_list::CowList;
use crate::cow_map::CowMap;
use crate::firewall::{AddrMatch, AddressListEntry, Name};
use crate::types::ItemId;

type Key = (Name, AddrMatch);

#[derive(Default)]
pub struct AddressLists {
    list: CowList<AddressListEntry>,
    held: OnceLock<CowMap<Key, u32>>,
}

fn key(e: &AddressListEntry) -> Key {
    (e.list.clone(), e.address)
}

fn count(m: &mut CowMap<Key, u32>, k: Key, up: bool) {
    let n = m.get(&k).copied().unwrap_or(0);
    let n = if up { n.saturating_add(1) } else { n.saturating_sub(1) };
    if n == 0 {
        m.remove(&k);
    } else {
        m.insert(k, n);
    }
}

impl AddressLists {
    pub fn from_list(list: CowList<AddressListEntry>) -> Self {
        Self {
            list,
            held: OnceLock::new(),
        }
    }

    fn held(&self) -> &CowMap<Key, u32> {
        self.held.get_or_init(|| {
            let mut m = CowMap::new();
            for e in &self.list {
                count(&mut m, key(e), true);
            }
            m
        })
    }

    /// How many static entries put `address` in `list`, in O(1).
    pub fn holders(&self, list: &Name, address: &AddrMatch) -> u32 {
        self.held().get(&(list.clone(), *address)).copied().unwrap_or(0)
    }

    /// Position of the entry with id `id` (O(log n): new entries get the
    /// next id, so the list is in id order).
    pub fn position(&self, id: ItemId) -> Option<usize> {
        self.list.find_by_key(|e| e.id, &id)
    }

    /// Append, keeping the index.
    pub fn push(&mut self, e: AddressListEntry) {
        if let Some(m) = self.held.get_mut() {
            count(m, key(&e), true);
        }
        self.list.push(e);
    }

    /// Change the entry at `i` with `f`, keeping the index.
    pub fn update<R>(&mut self, i: usize, f: impl FnOnce(&mut AddressListEntry) -> R) -> Option<R> {
        let before = key(self.list.get(i)?);
        let x = self.list.get_mut(i)?;
        let r = f(x);
        let after = key(x);
        if before != after
            && let Some(m) = self.held.get_mut()
        {
            count(m, before, false);
            count(m, after, true);
        }
        Some(r)
    }

    /// Remove the entry at `i`, keeping the index.
    pub fn remove(&mut self, i: usize) -> Option<AddressListEntry> {
        let e = self.list.remove(i)?;
        if let Some(m) = self.held.get_mut() {
            count(m, key(&e), false);
        }
        Some(e)
    }

    /// The list itself (for a revision delta).
    pub fn list(&self) -> &CowList<AddressListEntry> {
        &self.list
    }

    /// Both share the same list (nothing was written between them).
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        CowList::ptr_eq(&a.list, &b.list)
    }
}

impl Clone for AddressLists {
    fn clone(&self) -> Self {
        let held = OnceLock::new();
        if let Some(m) = self.held.get() {
            let _ = held.set(m.clone());
        }
        Self {
            list: self.list.clone(),
            held,
        }
    }
}

impl Deref for AddressLists {
    type Target = CowList<AddressListEntry>;
    fn deref(&self) -> &CowList<AddressListEntry> {
        &self.list
    }
}

/// Any write but [`AddressLists::push`], [`AddressLists::update`] and
/// [`AddressLists::remove`]: the index is dropped.
impl DerefMut for AddressLists {
    fn deref_mut(&mut self) -> &mut CowList<AddressListEntry> {
        self.held = OnceLock::new();
        &mut self.list
    }
}

impl From<Vec<AddressListEntry>> for AddressLists {
    fn from(v: Vec<AddressListEntry>) -> Self {
        Self::from_list(CowList::from(v))
    }
}

impl From<CowList<AddressListEntry>> for AddressLists {
    fn from(list: CowList<AddressListEntry>) -> Self {
        Self::from_list(list)
    }
}

impl FromIterator<AddressListEntry> for AddressLists {
    fn from_iter<I: IntoIterator<Item = AddressListEntry>>(iter: I) -> Self {
        Self::from_list(iter.into_iter().collect())
    }
}

impl<'a> IntoIterator for &'a AddressLists {
    type Item = &'a AddressListEntry;
    type IntoIter = crate::cow_list::Iter<'a, AddressListEntry>;
    fn into_iter(self) -> Self::IntoIter {
        self.list.iter()
    }
}

impl fmt::Debug for AddressLists {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.list.fmt(f)
    }
}

impl PartialEq for AddressLists {
    fn eq(&self, other: &Self) -> bool {
        self.list == other.list
    }
}

impl Eq for AddressLists {}

impl Hash for AddressLists {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.list.hash(state);
    }
}

impl Serialize for AddressLists {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.list.serialize(s)
    }
}

impl<'de> Deserialize<'de> for AddressLists {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        CowList::deserialize(d).map(Self::from_list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(id: u32, list: &str, address: &str) -> AddressListEntry {
        AddressListEntry {
            id: ItemId(id),
            list: list.parse().unwrap(),
            address: address.parse().unwrap(),
            disabled: false,
            comment: String::new(),
        }
    }

    fn held(l: &AddressLists, list: &str, address: &str) -> u32 {
        l.holders(&list.parse().unwrap(), &address.parse().unwrap())
    }

    #[test]
    fn the_index_follows_every_write_and_copies_keep_theirs() {
        let mut l: AddressLists = vec![e(1, "a", "10.0.0.1"), e(2, "a", "10.0.0.1")].into();
        assert_eq!(held(&l, "a", "10.0.0.1"), 2);
        l.push(e(3, "b", "10.0.0.2"));
        let copy = l.clone();
        l.remove(0);
        assert_eq!(held(&l, "a", "10.0.0.1"), 1);
        assert_eq!(held(&copy, "a", "10.0.0.1"), 2);
        l.update(1, |x| x.address = "10.0.0.3".parse().unwrap());
        assert_eq!(held(&l, "b", "10.0.0.2"), 0);
        assert_eq!(held(&l, "b", "10.0.0.3"), 1);
        assert_eq!(held(&copy, "b", "10.0.0.2"), 1);
        assert_eq!(l.position(ItemId(3)), Some(1));
        // A write the index cannot follow drops it; the next look rebuilds.
        l.clear();
        assert_eq!(held(&l, "a", "10.0.0.1"), 0);
        let j = serde_json::to_value(&copy).unwrap();
        assert!(j.is_array());
        assert_eq!(serde_json::from_value::<AddressLists>(j).unwrap(), copy);
    }
}
