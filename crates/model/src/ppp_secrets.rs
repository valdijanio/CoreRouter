//! `/ppp secret` as a list with a name index (G4.3g).
//!
//! The list is a [`CowList`] (G4.3gb): a write copies one block, not the
//! 100 000 secrets of a big base. The index by name is built on the first
//! lookup and shared by the copies of the config (the PPPoE service clones
//! the config every second); it is a [`CowMap`] from the name to the
//! secret's id, kept up to date by [`Secrets::push`], [`Secrets::update`]
//! and [`Secrets::remove`] (a write copies one leaf of it). Any other write
//! through `DerefMut` drops it, and the next lookup rebuilds it. A config
//! with a name twice (edited by hand) keeps the old rule: the first wins,
//! and a write that touches such a name rebuilds.
//!
//! G4.3cd: an index of the secrets' `routes` the same way, so the overlap
//! check of an add is O(log n) instead of a walk of every secret. It maps
//! to ids too: removing a secret moves the ones after it.
//!
//! Serialized exactly like the list.

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use ipnet::IpNet;

use crate::cow_list::CowList;
use crate::cow_map::CowMap;
use crate::framed_route::RouteSet;
use crate::ppp::PppSecret;
use crate::types::ItemId;

/// Name → id; `dup`: some name is there twice (the index then gives up
/// on incremental updates of that name).
#[derive(Clone, Default)]
struct Index {
    by_name: CowMap<String, ItemId>,
    dup: bool,
}

/// Block → id; `.1`: two secrets claim one block (a config edited by
/// hand): a removal rebuilds, so the next claimant takes it over.
type RouteIndex = Arc<(RouteSet<ItemId>, bool)>;

/// Fixed `remote_address` → secrets, bucketed by /24 (the high 24 bits),
/// so a range of a few blocks reads a few buckets (G4.3cd).
type FixedIndex = CowMap<u32, Vec<(u32, ItemId)>>;

#[derive(Default)]
pub struct Secrets {
    list: CowList<PppSecret>,
    index: OnceLock<Index>,
    routes: OnceLock<RouteIndex>,
    fixed: OnceLock<FixedIndex>,
}

fn fixed_add(m: &mut FixedIndex, ip: std::net::Ipv4Addr, id: ItemId) {
    let ip = u32::from(ip);
    let mut v = m.get(&(ip >> 8)).cloned().unwrap_or_default();
    v.push((ip, id));
    m.insert(ip >> 8, v);
}

fn fixed_drop(m: &mut FixedIndex, ip: std::net::Ipv4Addr, id: ItemId) {
    let ip = u32::from(ip);
    let Some(mut v) = m.get(&(ip >> 8)).cloned() else {
        return;
    };
    v.retain(|&x| x != (ip, id));
    if v.is_empty() {
        m.remove(&(ip >> 8));
    } else {
        m.insert(ip >> 8, v);
    }
}

impl Secrets {
    pub fn new(list: Vec<PppSecret>) -> Self {
        Self::from_list(CowList::from(list))
    }

    pub fn from_list(list: CowList<PppSecret>) -> Self {
        Self {
            list,
            index: OnceLock::new(),
            routes: OnceLock::new(),
            fixed: OnceLock::new(),
        }
    }

    fn fixed_index(&self) -> &FixedIndex {
        self.fixed.get_or_init(|| {
            let mut m = FixedIndex::new();
            for s in &self.list {
                if let Some(ip) = s.remote_address {
                    fixed_add(&mut m, ip, s.id);
                }
            }
            m
        })
    }

    /// The secrets whose fixed `remote_address` is inside `net`, in list
    /// order (G4.3cd: a routed block must not take another subscriber's
    /// fixed address; a walk of every secret per block made an import of
    /// business secrets O(n²): 634 µs each over 100 000, **medido**). Reads
    /// one bucket per /24 of `net`, or every bucket when there are fewer.
    pub fn fixed_in(&self, net: &ipnet::Ipv4Net) -> Vec<&PppSecret> {
        let (a, b) = (u32::from(net.network()), u32::from(net.broadcast()));
        let m = self.fixed_index();
        let inside = |&(ip, _): &(u32, ItemId)| (a..=b).contains(&ip);
        let mut ids: Vec<ItemId> = if u64::from((b >> 8) - (a >> 8)) < m.len() as u64 {
            (a >> 8..=b >> 8)
                .filter_map(|k| m.get(&k))
                .flat_map(|v| v.iter().copied().filter(inside))
                .map(|(_, id)| id)
                .collect()
        } else {
            m.iter()
                .flat_map(|(_, v)| v.iter().copied().filter(inside))
                .map(|(_, id)| id)
                .collect()
        };
        ids.sort_unstable();
        ids.dedup();
        let mut out: Vec<(usize, &PppSecret)> = ids
            .into_iter()
            .filter_map(|id| self.position(id).and_then(|i| self.list.get(i).map(|s| (i, s))))
            .collect();
        out.sort_by_key(|(i, _)| *i);
        out.into_iter().map(|(_, s)| s).collect()
    }

    fn route_index(&self) -> &RouteIndex {
        self.routes.get_or_init(|| {
            let mut set = RouteSet::new();
            let mut clash = false;
            for s in &self.list {
                for r in &s.routes {
                    // An overlap the commands would have refused (a config
                    // edited by hand): the first secret keeps the block.
                    clash |= set.insert(r.dst, s.id).is_err();
                }
            }
            Arc::new((set, clash))
        })
    }

    /// The secret with id `id`, in O(log n) (the list is in id order:
    /// a new secret gets the next id).
    pub fn by_id(&self, id: ItemId) -> Option<&PppSecret> {
        self.position(id).and_then(|i| self.list.get(i))
    }

    /// Position of the secret with id `id`.
    pub fn position(&self, id: ItemId) -> Option<usize> {
        self.list.find_by_key(|s| s.id, &id)
    }

    fn owners<'a>(&'a self, hits: impl Iterator<Item = (&'a IpNet, &'a ItemId)>) -> Vec<(&'a IpNet, &'a PppSecret)> {
        hits.filter_map(|(n, &id)| self.by_id(id).map(|s| (n, s))).collect()
    }

    /// The secrets whose `routes` share an address with `dst`.
    pub fn route_owners(&self, dst: &IpNet) -> Vec<(&IpNet, &PppSecret)> {
        self.owners(self.route_index().0.overlapping(dst))
    }

    /// The secrets whose `routes` share an address with `first..=last`.
    pub fn route_owners_in(&self, first: std::net::IpAddr, last: std::net::IpAddr) -> Vec<(&IpNet, &PppSecret)> {
        self.owners(self.route_index().0.overlapping_range(first, last))
    }

    fn index(&self) -> &Index {
        self.index.get_or_init(|| {
            let mut ix = Index::default();
            for s in &self.list {
                // The first of a name wins, as a walk of the list would.
                if ix.by_name.contains_key(s.name.as_str()) {
                    ix.dup = true;
                } else {
                    ix.by_name.insert(s.name.clone(), s.id);
                }
            }
            ix
        })
    }

    /// The secret named `name`, in O(1) plus the O(log n) id lookup.
    pub fn by_name(&self, name: &str) -> Option<&PppSecret> {
        let &id = self.index().by_name.get(name)?;
        match self.by_id(id) {
            Some(s) if s.name == name => Some(s),
            // Two secrets with one id (never from the commands; a config
            // is repaired on load): the walk.
            _ => self.list.iter().find(|s| s.name == name),
        }
    }

    /// The first secret named `name` that `keep` accepts (the IPoE lookup:
    /// `service=ipoe` only), in O(1) through the name index. A walk only
    /// when the indexed one is refused and some name is in the list twice
    /// (a config edited by hand: another one of that name may come later).
    pub fn first_named(&self, name: &str, keep: impl Fn(&PppSecret) -> bool) -> Option<&PppSecret> {
        let s = self.by_name(name)?;
        if keep(s) {
            return Some(s);
        }
        if !self.index().dup {
            return None;
        }
        self.list.iter().find(|s| s.name == name && keep(s))
    }

    /// The indexes learn that `s` is in the list.
    fn index_add(&mut self, s: &PppSecret) {
        if let Some(fx) = self.fixed.get_mut()
            && let Some(ip) = s.remote_address
        {
            fixed_add(fx, ip, s.id);
        }
        if let Some(ix) = self.index.get_mut() {
            if ix.by_name.contains_key(s.name.as_str()) {
                // A name twice (the commands refuse it): which one is
                // first is the walk's to say.
                self.index = OnceLock::new();
            } else {
                ix.by_name.insert(s.name.clone(), s.id);
            }
        }
        if let Some(rx) = self.routes.get_mut()
            && !s.routes.is_empty()
        {
            let rx = Arc::make_mut(rx);
            if s.routes.iter().any(|r| rx.0.insert(r.dst, s.id).is_err()) {
                self.routes = OnceLock::new();
            }
        }
    }

    /// The indexes forget `s` (already out of the list, or about to be
    /// replaced). A duplicated name or route makes them rebuild instead.
    fn index_drop(&mut self, s: &PppSecret) {
        if let Some(fx) = self.fixed.get_mut()
            && let Some(ip) = s.remote_address
        {
            fixed_drop(fx, ip, s.id);
        }
        if let Some(ix) = self.index.get_mut() {
            if ix.dup {
                self.index = OnceLock::new();
            } else if ix.by_name.get(s.name.as_str()) == Some(&s.id) {
                ix.by_name.remove(s.name.as_str());
            }
        }
        if let Some(rx) = self.routes.get_mut()
            && !s.routes.is_empty()
        {
            let rx = Arc::make_mut(rx);
            if rx.1 {
                self.routes = OnceLock::new();
                return;
            }
            for r in &s.routes {
                match rx.0.remove(&r.dst) {
                    Some(id) if id == s.id => {}
                    _ => {
                        // Held by another secret (a config edited by
                        // hand): the walk decides who keeps it.
                        self.routes = OnceLock::new();
                        break;
                    }
                }
            }
        }
    }

    /// Append, keeping the indexes.
    pub fn push(&mut self, s: PppSecret) {
        self.index_add(&s);
        self.list.push(s);
    }

    /// Change the secret at `i` with `f`, keeping the indexes. Only its
    /// block of the list is copied.
    pub fn update<R>(&mut self, i: usize, f: impl FnOnce(&mut PppSecret) -> R) -> Option<R> {
        let old = self.list.get(i)?;
        let (name, routes, id, fixed) = (old.name.clone(), old.routes.clone(), old.id, old.remote_address);
        let x = self.list.get_mut(i)?;
        let r = f(x);
        let keys_moved = x.name != name || x.routes != routes || x.id != id || x.remote_address != fixed;
        if keys_moved {
            let now = x.clone();
            let before = PppSecret {
                id,
                name,
                routes,
                remote_address: fixed,
                ..PppSecret::default()
            };
            self.index_drop(&before);
            self.index_add(&now);
        }
        Some(r)
    }

    /// Remove the secret at `i`, keeping the indexes.
    pub fn remove(&mut self, i: usize) -> Option<PppSecret> {
        let s = self.list.remove(i)?;
        self.index_drop(&s);
        Some(s)
    }

    /// Both share the same list (nothing was copied between them).
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        CowList::ptr_eq(&a.list, &b.list)
    }

    /// The list itself (for a revision delta).
    pub fn list(&self) -> &CowList<PppSecret> {
        &self.list
    }
}

impl Clone for Secrets {
    fn clone(&self) -> Self {
        let index = OnceLock::new();
        if let Some(ix) = self.index.get() {
            let _ = index.set(ix.clone());
        }
        let routes = OnceLock::new();
        if let Some(rx) = self.routes.get() {
            let _ = routes.set(Arc::clone(rx));
        }
        let fixed = OnceLock::new();
        if let Some(fx) = self.fixed.get() {
            let _ = fixed.set(fx.clone());
        }
        Self {
            list: self.list.clone(),
            index,
            routes,
            fixed,
        }
    }
}

impl Deref for Secrets {
    type Target = CowList<PppSecret>;
    fn deref(&self) -> &CowList<PppSecret> {
        &self.list
    }
}

/// Any write but [`Secrets::push`], [`Secrets::update`] and
/// [`Secrets::remove`]: the indexes are dropped.
impl DerefMut for Secrets {
    fn deref_mut(&mut self) -> &mut CowList<PppSecret> {
        self.index = OnceLock::new();
        self.routes = OnceLock::new();
        self.fixed = OnceLock::new();
        &mut self.list
    }
}

impl From<Vec<PppSecret>> for Secrets {
    fn from(v: Vec<PppSecret>) -> Self {
        Self::new(v)
    }
}

impl FromIterator<PppSecret> for Secrets {
    fn from_iter<I: IntoIterator<Item = PppSecret>>(iter: I) -> Self {
        Self::new(iter.into_iter().collect())
    }
}

impl<'a> IntoIterator for &'a Secrets {
    type Item = &'a PppSecret;
    type IntoIter = crate::cow_list::Iter<'a, PppSecret>;
    fn into_iter(self) -> Self::IntoIter {
        self.list.iter()
    }
}

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.list.fmt(f)
    }
}

impl PartialEq for Secrets {
    fn eq(&self, other: &Self) -> bool {
        self.list == other.list
    }
}

impl Eq for Secrets {}

impl Serialize for Secrets {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.list.serialize(s)
    }
}

impl<'de> Deserialize<'de> for Secrets {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        CowList::<PppSecret>::deserialize(d).map(Self::from_list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ids in add order, as `ppp.secret.add` gives them.
    fn next_id() -> ItemId {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
        ItemId(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    fn s(name: &str, password: &str) -> PppSecret {
        PppSecret {
            id: next_id(),
            name: name.into(),
            password: password.into(),
            ..PppSecret::default()
        }
    }

    fn pw<'a>(v: &'a Secrets, name: &str) -> Option<&'a str> {
        v.by_name(name).map(|x| x.password.stored())
    }

    #[test]
    fn lookup_follows_push_and_any_other_write() {
        let mut v = Secrets::new(vec![s("a", "1"), s("b", "2")]);
        assert_eq!(pw(&v, "b"), Some("2"));
        v.push(s("c", "3"));
        assert_eq!(pw(&v, "c"), Some("3"));
        // A copy shares the index; a write to one leaves the other alone.
        let copy = v.clone();
        v.remove(0);
        assert_eq!(pw(&v, "a"), None);
        assert_eq!(pw(&v, "c"), Some("3"));
        assert_eq!(pw(&copy, "a"), Some("1"));
        if let Some(x) = v.get_mut(0) {
            x.name = "renamed".into();
        }
        assert_eq!(pw(&v, "b"), None);
        assert_eq!(pw(&v, "renamed"), Some("2"));
        // The first of a name wins, as the walk did.
        let mut d = Secrets::new(vec![s("x", "first")]);
        d.push(s("x", "second"));
        assert_eq!(pw(&d, "x"), Some("first"));
        // A copy made after the index exists, then pushed to.
        let mut e = d.clone();
        e.push(s("y", "9"));
        assert_eq!(pw(&e, "y"), Some("9"));
        assert_eq!(pw(&d, "y"), None);
    }

    #[test]
    fn first_named_skips_the_refused_only_with_a_name_twice() {
        let ipoe = |name: &str, pw: &str| PppSecret {
            service: crate::ppp::PppService::Ipoe,
            ..s(name, pw)
        };
        let is_ipoe = |x: &PppSecret| x.service == crate::ppp::PppService::Ipoe;
        let mut v = Secrets::new(vec![s("m", "pppoe"), ipoe("n", "1")]);
        assert_eq!(v.first_named("n", is_ipoe).map(|x| x.password.as_str()), Some("1"));
        assert!(v.first_named("m", is_ipoe).is_none());
        assert!(v.first_named("absent", is_ipoe).is_none());
        // A config edited by hand: the IPoE one of a name held twice.
        v.push(ipoe("m", "2"));
        assert_eq!(v.first_named("m", is_ipoe).map(|x| x.password.as_str()), Some("2"));
        assert_eq!(pw(&v, "m"), Some("pppoe"));
    }

    #[test]
    fn route_owners_follow_writes() {
        let with = |name: &str, routes: &str| PppSecret {
            id: next_id(),
            name: name.into(),
            routes: crate::framed_route::FramedRoute::parse_list(routes).unwrap(),
            ..PppSecret::default()
        };
        let net = |t: &str| t.parse::<IpNet>().unwrap();
        let mut v = Secrets::new(vec![with("a", "203.0.113.8/29"), s("b", "x")]);
        let hit = |v: &Secrets, t: &str| -> Vec<String> {
            v.route_owners(&net(t)).iter().map(|(_, s)| s.name.clone()).collect()
        };
        assert_eq!(hit(&v, "203.0.113.0/24"), ["a"]);
        v.push(with("c", "2001:db8:100::/48,203.0.113.16/28"));
        assert_eq!(hit(&v, "203.0.113.0/24"), ["a", "c"]);
        assert_eq!(hit(&v, "2001:db8:100:1::/64"), ["c"]);
        let copy = v.clone();
        v.remove(0);
        assert_eq!(hit(&v, "203.0.113.0/24"), ["c"]);
        assert_eq!(hit(&copy, "203.0.113.0/24"), ["a", "c"]);
        assert!(hit(&v, "198.51.100.0/24").is_empty());
    }

    #[test]
    fn fixed_addresses_by_range_follow_writes() {
        let fixed = |name: &str, ip: &str| PppSecret {
            id: next_id(),
            name: name.into(),
            remote_address: Some(ip.parse().unwrap()),
            ..PppSecret::default()
        };
        let net = |t: &str| t.parse::<ipnet::Ipv4Net>().unwrap();
        let names = |v: &Secrets, t: &str| -> Vec<String> { v.fixed_in(&net(t)).iter().map(|s| s.name.clone()).collect() };
        let mut v = Secrets::new(vec![fixed("a", "203.0.113.9"), s("b", "x")]);
        assert_eq!(names(&v, "203.0.113.8/29"), ["a"]);
        v.push(fixed("c", "203.0.113.10"));
        assert_eq!(names(&v, "203.0.113.8/29"), ["a", "c"]);
        assert!(names(&v, "203.0.113.16/29").is_empty());
        let copy = v.clone();
        v.remove(0);
        assert_eq!(names(&v, "203.0.113.0/24"), ["c"]);
        assert_eq!(names(&copy, "203.0.113.0/16"), ["a", "c"]);
        v.update(1, |x| x.remote_address = Some("198.51.100.1".parse().unwrap()));
        assert!(names(&v, "203.0.113.0/24").is_empty());
        assert_eq!(names(&v, "0.0.0.0/0"), ["c"]);
    }

    #[test]
    fn serialized_like_the_list() {
        let v = Secrets::new(vec![s("a", "1")]);
        let j = serde_json::to_value(&v).unwrap();
        assert!(j.is_array());
        let back: Secrets = serde_json::from_value(j).unwrap();
        assert_eq!(back, v);
    }

    proptest::proptest! {
        /// The kept indexes answer what a walk of the list answers, after
        /// any run of adds, renames, route changes and removals, with
        /// copies taken on the way.
        #[test]
        fn kept_indexes_match_a_walk(ops in proptest::collection::vec((0u8..4, 0u16..40, 0u8..8), 1..120)) {
            let net = |k: u8| format!("203.0.{k}.0/29");
            let mut v = Secrets::default();
            let mut copies = Vec::new();
            for (op, a, b) in ops {
                let n = v.len();
                match op {
                    0 => {
                        let mut x = s(&format!("u{a}"), "p");
                        if b > 4 {
                            x.routes = crate::framed_route::FramedRoute::parse_list(&net(b)).unwrap();
                        }
                        let _ = v.by_name("warm");
                        let _ = v.route_owners(&net(b).parse().unwrap());
                        v.push(x);
                    }
                    1 if n > 0 => { v.update(usize::from(a) % n, |x| x.name = format!("u{b}")); }
                    2 if n > 0 => {
                        let _ = v.fixed_in(&"10.0.0.0/24".parse().unwrap());
                        v.update(usize::from(a) % n, |x| {
                            x.routes = crate::framed_route::FramedRoute::parse_list(&net(b)).unwrap();
                            x.remote_address = (b > 2).then(|| std::net::Ipv4Addr::new(10, 0, 0, b));
                        });
                    }
                    3 if n > 0 => { v.remove(usize::from(a) % n); }
                    _ => {}
                }
                if b == 0 { copies.push(v.clone()); }
                copies.push(v.clone());
            }
            for c in &copies {
                let fixed: Vec<ItemId> = c.fixed_in(&"10.0.0.0/29".parse().unwrap()).iter().map(|x| x.id).collect();
                let walk: Vec<ItemId> = c.iter().filter(|x| x.remote_address.is_some_and(|ip| ip.octets()[3] < 8 && ip.octets()[..3] == [10, 0, 0])).map(|x| x.id).collect();
                proptest::prop_assert_eq!(fixed, walk);
                for k in 0..40 {
                    let name = format!("u{k}");
                    let walk = c.iter().find(|x| x.name == name).map(|x| x.id);
                    proptest::prop_assert_eq!(c.by_name(&name).map(|x| x.id), walk);
                }
                for k in 0..8u8 {
                    let dst: IpNet = net(k).parse().unwrap();
                    let mut got: Vec<ItemId> = c.route_owners(&dst).iter().map(|(_, x)| x.id).collect();
                    // The first secret holding the block keeps it.
                    let walk: Vec<ItemId> = c.iter().filter(|x| x.routes.iter().any(|r| r.dst == dst)).map(|x| x.id).take(1).collect();
                    got.truncate(1);
                    proptest::prop_assert_eq!(got, walk);
                }
            }
        }
    }
}
