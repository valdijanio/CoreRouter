//! `/ip route` (static routes) as a block list with an index of each
//! destination (G0.31d, G0.31e).
//!
//! An add refuses the very same next hop twice (same table, destination
//! and gateway): with 60 000 routes the walk of the list cost ~60 µs per
//! command and made an import of 60 000 routes quadratic. A commit asks
//! which routes go to the destinations it changed, to plan the kernel and
//! validate only those (G0.31e). The index maps each (table, destination)
//! to the ids of the routes to it — a list, so ECMP paths and a config
//! edited by hand with a hop twice stay exact. It is built on the first
//! look, shared by the copies of the config, and kept by [`Routes::push`],
//! [`Routes::update`] and [`Routes::remove`] (a write copies one leaf of it,
//! [`CowMap`]). Any other write through `DerefMut` drops it. Same design as
//! [`crate::address_lists`] (G0.21).
//!
//! Serialized exactly like the list.

use std::collections::BTreeSet;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::OnceLock;

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::config::RouteEntry;
use crate::cow_list::CowList;
use crate::cow_map::CowMap;
use crate::types::{ItemId, RoutingTable};

/// A destination: the table and the prefix without host bits (the kernel's
/// key, so `10.0.0.1/24` and `10.0.0.0/24` are one).
pub type Dst = (RoutingTable, IpNet);

#[derive(Default)]
pub struct Routes {
    list: CowList<RouteEntry>,
    dsts: OnceLock<CowMap<Dst, Vec<ItemId>>>,
}

/// The destination of `r`.
pub fn dst(r: &RouteEntry) -> Dst {
    (r.routing_table.clone(), r.dst_address.trunc())
}

fn hold(m: &mut CowMap<Dst, Vec<ItemId>>, r: &RouteEntry) {
    let mut ids = m.get(&dst(r)).cloned().unwrap_or_default();
    ids.push(r.id);
    m.insert(dst(r), ids);
}

fn release(m: &mut CowMap<Dst, Vec<ItemId>>, r: &RouteEntry) {
    let k = dst(r);
    let Some(mut ids) = m.get(&k).cloned() else {
        return;
    };
    if let Some(i) = ids.iter().position(|id| *id == r.id) {
        ids.remove(i);
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
            dsts: OnceLock::new(),
        }
    }

    fn dsts(&self) -> &CowMap<Dst, Vec<ItemId>> {
        self.dsts.get_or_init(|| {
            let mut m = CowMap::new();
            for r in &self.list {
                hold(&mut m, r);
            }
            m
        })
    }

    /// The ids of the routes to `dst` (host bits ignored) in `table`, in
    /// list order, in O(1).
    pub fn to_dst(&self, table: &RoutingTable, dst: IpNet) -> &[ItemId] {
        self.dsts()
            .get(&(table.clone(), dst.trunc()))
            .map_or(&[], |ids| ids.as_slice())
    }

    /// The routes to the destination `d`.
    pub fn routes_to<'a>(&'a self, d: &Dst) -> impl Iterator<Item = &'a RouteEntry> + 'a {
        self.to_dst(&d.0, d.1).iter().filter_map(|id| self.by_id(*id))
    }

    /// The ids of the routes with the same table, destination and gateway
    /// as `r` (`r` itself among them if it is in the list).
    pub fn same_hop<'a>(&'a self, r: &'a RouteEntry) -> impl Iterator<Item = ItemId> + 'a {
        self.to_dst(&r.routing_table, r.dst_address)
            .iter()
            .filter_map(|id| self.by_id(*id))
            .filter(|o| o.dst_address == r.dst_address && o.gateway == r.gateway)
            .map(|o| o.id)
    }

    /// The destinations of the routes that are not in a block `self` and
    /// `other` share: every destination one of them added, changed or
    /// removed (and the others of the blocks they touched), without walking
    /// the shared blocks. One route changed among 60 000: one block, ~128.
    pub fn changed_dsts(&self, other: &Self) -> BTreeSet<Dst> {
        let mut out = BTreeSet::new();
        if Self::ptr_eq(self, other) {
            return out;
        }
        for r in self.list.unshared(&other.list).iter() {
            out.insert(dst(r));
        }
        for r in other.list.unshared(&self.list).iter() {
            out.insert(dst(r));
        }
        out
    }

    /// The route with id `id` (O(log n), see [`Routes::position`]).
    pub fn by_id(&self, id: ItemId) -> Option<&RouteEntry> {
        self.list.get(self.position(id)?)
    }

    /// Position of the route with id `id` (O(log n): new routes get the
    /// next id, so the list is in id order; a walk otherwise).
    pub fn position(&self, id: ItemId) -> Option<usize> {
        self.list.find_by_key(|r| r.id, &id)
    }

    /// Append, keeping the index.
    pub fn push(&mut self, r: RouteEntry) {
        if let Some(m) = self.dsts.get_mut() {
            hold(m, &r);
        }
        self.list.push(r);
    }

    /// Change the route at `i` with `f`, keeping the index.
    pub fn update<R>(&mut self, i: usize, f: impl FnOnce(&mut RouteEntry) -> R) -> Option<R> {
        let before = self.list.get(i)?.clone();
        let x = self.list.get_mut(i)?;
        let out = f(x);
        if (dst(&before), before.id) != (dst(x), x.id)
            && let Some(m) = self.dsts.get_mut()
        {
            release(m, &before);
            hold(m, x);
        }
        Some(out)
    }

    /// Remove the route at `i`, keeping the index.
    pub fn remove(&mut self, i: usize) -> Option<RouteEntry> {
        let r = self.list.remove(i)?;
        if let Some(m) = self.dsts.get_mut() {
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
        let dsts = OnceLock::new();
        if let Some(m) = self.dsts.get() {
            let _ = dsts.set(m.clone());
        }
        Self {
            list: self.list.clone(),
            dsts,
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
        self.dsts = OnceLock::new();
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
        let mut ids: Vec<u32> = l.same_hop(&r(0, dst, gw)).map(|i| i.0).collect();
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

    #[test]
    fn a_destination_holds_its_ecmp_paths_and_a_commit_sees_only_what_changed() {
        let mut l: Routes = (1..=1000)
            .map(|i| r(i, &format!("10.{}.{}.0/24", i / 256, i % 256), "192.0.2.1"))
            .collect();
        l.push(r(1001, "10.0.1.0/24", "192.0.2.9"));
        let main = RoutingTable::default();
        let ids: Vec<u32> = l
            .routes_to(&(main.clone(), "10.0.1.7/24".parse().unwrap()))
            .map(|x| x.id.0)
            .collect();
        assert_eq!(ids, [1, 1001], "host bits ignored, both paths, in list order");
        assert_eq!(l.by_id(ItemId(500)).map(|x| x.id), Some(ItemId(500)));
        let before = l.clone();
        assert!(l.changed_dsts(&before).is_empty());
        l.update(499, |x| x.dst_address = "172.16.0.0/12".parse().unwrap());
        l.remove(0);
        let changed = l.changed_dsts(&before);
        for d in ["10.1.244.0/24", "172.16.0.0/12", "10.0.1.0/24"] {
            assert!(changed.contains(&(main.clone(), d.parse().unwrap())), "{d} in {changed:?}");
        }
        assert!(changed.len() <= 2 * 128 + 2, "only the touched blocks: {}", changed.len());
        assert!(!changed.contains(&(main, "10.3.200.0/24".parse().unwrap())));
    }
}
