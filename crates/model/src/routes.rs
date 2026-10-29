//! `/ip route` (static routes) as a block list with an index of each next
//! hop (G0.31d).
//!
//! An add refuses the very same next hop twice (same table, destination
//! and gateway): with 60 000 routes the walk of the list cost ~60 µs per
//! command and made an import of 60 000 routes quadratic. The index maps
//! each (table, destination, gateway) to the ids of the routes on it — a
//! list, so a config edited by hand with a hop twice stays exact. It is
//! built on the first look, shared by the copies of the config, and kept by
//! [`Routes::push`], [`Routes::update`] and [`Routes::remove`] (a write
//! copies one leaf of it, [`CowMap`]). Any other write through `DerefMut`
//! drops it. Same design as [`crate::address_lists`] (G0.21).
//!
//! Serialized exactly like the list.

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::OnceLock;

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::config::RouteEntry;
use crate::cow_list::CowList;
use crate::cow_map::CowMap;
use crate::types::{Gateway, ItemId, RoutingTable};

type Key = (RoutingTable, IpNet, Gateway);

#[derive(Default)]
pub struct Routes {
    list: CowList<RouteEntry>,
    hops: OnceLock<CowMap<Key, Vec<ItemId>>>,
}

fn key(r: &RouteEntry) -> Key {
    (r.routing_table.clone(), r.dst_address, r.gateway.clone())
}

fn hold(m: &mut CowMap<Key, Vec<ItemId>>, r: &RouteEntry) {
    let mut ids = m.get(&key(r)).cloned().unwrap_or_default();
    ids.push(r.id);
    m.insert(key(r), ids);
}

fn release(m: &mut CowMap<Key, Vec<ItemId>>, r: &RouteEntry) {
    let k = key(r);
    let Some(mut ids) = m.get(&k).cloned() else {
        return;
    };
    if let Some(i) = ids.iter().position(|id| *id == r.id) {
        ids.swap_remove(i);
    }
    if ids.is_empty() {
        m.remove(&k);
    } else {
        m.insert(k, ids);
    }
}

impl Routes {
    pub fn from_list(list: CowList<RouteEntry>) -> Self {
        Self {
            list,
            hops: OnceLock::new(),
        }
    }

    fn hops(&self) -> &CowMap<Key, Vec<ItemId>> {
        self.hops.get_or_init(|| {
            let mut m = CowMap::new();
            for r in &self.list {
                hold(&mut m, r);
            }
            m
        })
    }

    /// The ids of the routes with the same table, destination and gateway
    /// as `r` (`r` itself among them if it is in the list), in O(1).
    pub fn same_hop(&self, r: &RouteEntry) -> &[ItemId] {
        self.hops()
            .get(&key(r))
            .map_or(&[], |ids| ids.as_slice())
    }

    /// Position of the route with id `id` (O(log n): new routes get the
    /// next id, so the list is in id order; a walk otherwise).
    pub fn position(&self, id: ItemId) -> Option<usize> {
        self.list.find_by_key(|r| r.id, &id)
    }

    /// Append, keeping the index.
    pub fn push(&mut self, r: RouteEntry) {
        if let Some(m) = self.hops.get_mut() {
            hold(m, &r);
        }
        self.list.push(r);
    }

    /// Change the route at `i` with `f`, keeping the index.
    pub fn update<R>(&mut self, i: usize, f: impl FnOnce(&mut RouteEntry) -> R) -> Option<R> {
        let before = self.list.get(i)?.clone();
        let x = self.list.get_mut(i)?;
        let out = f(x);
        if (key(&before), before.id) != (key(x), x.id)
            && let Some(m) = self.hops.get_mut()
        {
            release(m, &before);
            hold(m, x);
        }
        Some(out)
    }

    /// Remove the route at `i`, keeping the index.
    pub fn remove(&mut self, i: usize) -> Option<RouteEntry> {
        let r = self.list.remove(i)?;
        if let Some(m) = self.hops.get_mut() {
            release(m, &r);
        }
        Some(r)
    }

    /// The list itself (for a revision delta).
    pub fn list(&self) -> &CowList<RouteEntry> {
        &self.list
    }

    /// Both share the same list (nothing was written between them).
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        CowList::ptr_eq(&a.list, &b.list)
    }
}

impl Clone for Routes {
    fn clone(&self) -> Self {
        let hops = OnceLock::new();
        if let Some(m) = self.hops.get() {
            let _ = hops.set(m.clone());
        }
        Self {
            list: self.list.clone(),
            hops,
        }
    }
}

impl Deref for Routes {
    type Target = CowList<RouteEntry>;
    fn deref(&self) -> &CowList<RouteEntry> {
        &self.list
    }
}

/// Any write but [`Routes::push`], [`Routes::update`] and
/// [`Routes::remove`]: the index is dropped.
impl DerefMut for Routes {
    fn deref_mut(&mut self) -> &mut CowList<RouteEntry> {
        self.hops = OnceLock::new();
        &mut self.list
    }
}

impl From<Vec<RouteEntry>> for Routes {
    fn from(v: Vec<RouteEntry>) -> Self {
        Self::from_list(CowList::from(v))
    }
}

impl From<CowList<RouteEntry>> for Routes {
    fn from(list: CowList<RouteEntry>) -> Self {
        Self::from_list(list)
    }
}

impl FromIterator<RouteEntry> for Routes {
    fn from_iter<I: IntoIterator<Item = RouteEntry>>(iter: I) -> Self {
        Self::from_list(iter.into_iter().collect())
    }
}

impl<'a> IntoIterator for &'a Routes {
    type Item = &'a RouteEntry;
    type IntoIter = crate::cow_list::Iter<'a, RouteEntry>;
    fn into_iter(self) -> Self::IntoIter {
        self.list.iter()
    }
}

impl fmt::Debug for Routes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.list.fmt(f)
    }
}

impl PartialEq for Routes {
    fn eq(&self, other: &Self) -> bool {
        self.list == other.list
    }
}

impl Serialize for Routes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.list.serialize(s)
    }
}

impl<'de> Deserialize<'de> for Routes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        CowList::deserialize(d).map(Self::from_list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(id: u32, dst: &str, gw: &str) -> RouteEntry {
        RouteEntry {
            id: ItemId(id),
            dst_address: dst.parse().unwrap(),
            gateway: gw.parse().unwrap(),
            distance: 1,
            routing_table: RoutingTable::default(),
            disabled: false,
            comment: String::new(),
            check_gateway: Default::default(),
            bfd_profile: String::new(),
        }
    }

    fn hop(l: &Routes, dst: &str, gw: &str) -> Vec<u32> {
        let mut ids: Vec<u32> = l.same_hop(&r(0, dst, gw)).iter().map(|i| i.0).collect();
        ids.sort_unstable();
        ids
    }

    #[test]
    fn the_index_follows_every_write_and_copies_keep_theirs() {
        let mut l: Routes = vec![
            r(1, "10.0.0.0/8", "192.0.2.1"),
            r(2, "10.0.0.0/8", "192.0.2.1"),
        ]
        .into();
        assert_eq!(hop(&l, "10.0.0.0/8", "192.0.2.1"), [1, 2]);
        l.push(r(3, "10.1.0.0/16", "192.0.2.2"));
        let copy = l.clone();
        l.remove(0);
        assert_eq!(hop(&l, "10.0.0.0/8", "192.0.2.1"), [2]);
        assert_eq!(hop(&copy, "10.0.0.0/8", "192.0.2.1"), [1, 2]);
        l.update(1, |x| x.gateway = "192.0.2.3".parse().unwrap());
        assert!(hop(&l, "10.1.0.0/16", "192.0.2.2").is_empty());
        assert_eq!(hop(&l, "10.1.0.0/16", "192.0.2.3"), [3]);
        assert_eq!(hop(&copy, "10.1.0.0/16", "192.0.2.2"), [3]);
        // Another distance is the same hop (ECMP keys on the gateway).
        l.update(1, |x| x.distance = 9);
        assert_eq!(hop(&l, "10.1.0.0/16", "192.0.2.3"), [3]);
        assert_eq!(l.position(ItemId(3)), Some(1));
        // A write the index cannot follow drops it; the next look rebuilds.
        l.clear();
        assert!(hop(&l, "10.0.0.0/8", "192.0.2.1").is_empty());
        let j = serde_json::to_value(&copy).unwrap();
        assert!(j.is_array());
        assert_eq!(serde_json::from_value::<Routes>(j).unwrap(), copy);
    }
}
