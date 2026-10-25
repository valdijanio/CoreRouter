//! `/ppp secret` as a list with a name index (G4.3g).
//!
//! The list is a [`CowArc`] like every big section. The index by name is
//! built on the first lookup and shared by the copies of the config (the
//! PPPoE service clones the config every second). [`Secrets::push`] keeps
//! it up to date (an import of 100 000 subscribers stays O(n)); any other
//! write through `DerefMut` drops it, and the next lookup rebuilds it.
//!
//! Serialized exactly like the list.

use std::collections::HashMap;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, OnceLock};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::cow::CowArc;
use crate::ppp::PppSecret;

type Index = Arc<HashMap<String, usize>>;

#[derive(Default)]
pub struct Secrets {
    list: CowArc<Vec<PppSecret>>,
    index: OnceLock<Index>,
}

impl Secrets {
    pub fn new(list: Vec<PppSecret>) -> Self {
        Self {
            list: CowArc::new(list),
            index: OnceLock::new(),
        }
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
        Self {
            list: self.list.clone(),
            index,
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
    fn serialized_like_the_list() {
        let v = Secrets::new(vec![s("a", "1")]);
        let j = serde_json::to_value(&v).unwrap();
        assert!(j.is_array());
        let back: Secrets = serde_json::from_value(j).unwrap();
        assert_eq!(back, v);
    }
}
