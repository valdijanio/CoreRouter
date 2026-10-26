//! `/ppp secret` as a list with a name index (G4.3g).
//!
//! The list is a [`CowArc`] like every big section. The index by name is
//! built on the first lookup and shared by the copies of the config (the
//! PPPoE service clones the config every second). [`Secrets::push`] keeps
//! it up to date (an import of 100 000 subscribers stays O(n)); any other
//! write through `DerefMut` drops it, and the next lookup rebuilds it.
//!
//! G4.3cd: an index of the secrets' `routes` the same way, so the overlap
//! check of an add is O(log n) instead of a walk of every secret.
//!
//! Serialized exactly like the list.

use std::collections::HashMap;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use ipnet::IpNet;

use crate::cow::CowArc;
use crate::framed_route::RouteSet;
use crate::ppp::PppSecret;

type Index = Arc<HashMap<String, usize>>;
type RouteIndex = Arc<RouteSet<usize>>;
/// Fixed `remote_address` → secrets (by position), sorted by address.
type FixedIndex = Arc<std::collections::BTreeMap<u32, Vec<usize>>>;

#[derive(Default)]
pub struct Secrets {
    list: CowArc<Vec<PppSecret>>,
    index: OnceLock<Index>,
    routes: OnceLock<RouteIndex>,
    fixed: OnceLock<FixedIndex>,
}

impl Secrets {
    pub fn new(list: Vec<PppSecret>) -> Self {
        Self {
            list: CowArc::new(list),
            index: OnceLock::new(),
            routes: OnceLock::new(),
            fixed: OnceLock::new(),
        }
    }

    fn fixed_index(&self) -> &FixedIndex {
        self.fixed.get_or_init(|| {
            let mut m: std::collections::BTreeMap<u32, Vec<usize>> = std::collections::BTreeMap::new();
            for (k, s) in self.list.iter().enumerate() {
                if let Some(ip) = s.remote_address {
                    m.entry(u32::from(ip)).or_default().push(k);
                }
            }
            Arc::new(m)
        })
    }

    /// The secrets whose fixed `remote_address` is inside `net`, in
    /// O(log n + hits) (G4.3cd: a routed block must not take another
    /// subscriber's fixed address; a walk of every secret per block made an
    /// import of business secrets O(n²): 634 µs each over 100 000, **medido**).
    pub fn fixed_in(&self, net: &ipnet::Ipv4Net) -> Vec<&PppSecret> {
        let (a, b) = (u32::from(net.network()), u32::from(net.broadcast()));
        self.fixed_index()
            .range(a..=b)
            .flat_map(|(_, v)| v.iter())
            .filter_map(|&k| self.list.get(k))
            .collect()
    }

    fn route_index(&self) -> &RouteIndex {
        self.routes.get_or_init(|| {
            let mut set = RouteSet::new();
            for (k, s) in self.list.iter().enumerate() {
                for r in &s.routes {
                    // An overlap the commands would have refused (a config
                    // edited by hand): the first secret keeps the block.
                    let _ = set.insert(r.dst, k);
                }
            }
            Arc::new(set)
        })
    }

    /// The secrets whose `routes` share an address with `dst`.
    pub fn route_owners(&self, dst: &IpNet) -> Vec<(&IpNet, &PppSecret)> {
        self.route_index()
            .overlapping(dst)
            .filter_map(|(n, &k)| self.list.get(k).map(|s| (n, s)))
            .collect()
    }

    /// The secrets whose `routes` share an address with `first..=last`.
    pub fn route_owners_in(&self, first: std::net::IpAddr, last: std::net::IpAddr) -> Vec<(&IpNet, &PppSecret)> {
        self.route_index()
            .overlapping_range(first, last)
            .filter_map(|(n, &k)| self.list.get(k).map(|s| (n, s)))
            .collect()
    }

    fn index(&self) -> &Index {
        self.index.get_or_init(|| {
            let mut m = HashMap::with_capacity(self.list.len());
            for (k, s) in self.list.iter().enumerate() {
                // The first of a name wins, as a walk of the list would.
                m.entry(s.name.clone()).or_insert(k);
            }
            Arc::new(m)
        })
    }

    /// The secret named `name`, in O(1).
    pub fn by_name(&self, name: &str) -> Option<&PppSecret> {
        self.index()
            .get(name)
            .and_then(|&k| self.list.get(k))
            .filter(|s| s.name == name)
    }

    /// Append, keeping the index (copied once if another config shares it).
    pub fn push(&mut self, s: PppSecret) {
        let k = self.list.len();
        if let Some(ix) = self.index.get_mut() {
            Arc::make_mut(ix).entry(s.name.clone()).or_insert(k);
        }
        if let Some(fx) = self.fixed.get_mut()
            && let Some(ip) = s.remote_address
        {
            Arc::make_mut(fx).entry(u32::from(ip)).or_default().push(k);
        }
        if let Some(rx) = self.routes.get_mut()
            && !s.routes.is_empty()
        {
            let rx = Arc::make_mut(rx);
            for r in &s.routes {
                let _ = rx.insert(r.dst, k);
            }
        }
        self.list.push(s);
    }

    /// Both share the same list (nothing was copied between them).
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        CowArc::ptr_eq(&a.list, &b.list)
    }
}

impl Clone for Secrets {
    fn clone(&self) -> Self {
        let index = OnceLock::new();
        if let Some(ix) = self.index.get() {
            let _ = index.set(Arc::clone(ix));
        }
        let routes = OnceLock::new();
        if let Some(rx) = self.routes.get() {
            let _ = routes.set(Arc::clone(rx));
        }
        let fixed = OnceLock::new();
        if let Some(fx) = self.fixed.get() {
            let _ = fixed.set(Arc::clone(fx));
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
    type Target = Vec<PppSecret>;
    fn deref(&self) -> &Vec<PppSecret> {
        &self.list
    }
}

/// Any write but [`Secrets::push`]: the index is dropped.
impl DerefMut for Secrets {
    fn deref_mut(&mut self) -> &mut Vec<PppSecret> {
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
    type IntoIter = std::slice::Iter<'a, PppSecret>;
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
        Vec::<PppSecret>::deserialize(d).map(Self::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(name: &str, password: &str) -> PppSecret {
        PppSecret {
            name: name.into(),
            password: password.into(),
            ..PppSecret::default()
        }
    }

    fn pw<'a>(v: &'a Secrets, name: &str) -> Option<&'a str> {
        v.by_name(name).map(|x| x.password.as_str())
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
    fn route_owners_follow_writes() {
        let with = |name: &str, routes: &str| PppSecret {
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
        v.remove(0);
        assert_eq!(names(&v, "203.0.113.0/24"), ["c"]);
    }

    #[test]
    fn serialized_like_the_list() {
        let v = Secrets::new(vec![s("a", "1")]);
        let j = serde_json::to_value(&v).unwrap();
        assert!(j.is_array());
        let back: Secrets = serde_json::from_value(j).unwrap();
        assert_eq!(back, v);
    }
}
