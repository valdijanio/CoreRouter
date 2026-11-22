//! `CowArc<T>`: a config section shared between copies of the config until one
//! of them writes to it (G0.16).
//!
//! The store keeps several copies of the configuration: the candidate, the
//! running config, the revisions of the history and, while a command runs,
//! the rollback point. With the big sections (routes, address lists,
//! firewall rules, interfaces) behind a `CowArc`, cloning a [`crate::Config`]
//! costs a few reference counts, and a command that writes one section
//! copies that section only: a command costs what it touches, not the whole
//! config.
//!
//! Reading goes through `Deref`; writing through `DerefMut`, which copies the
//! section first when another config still shares it (`Arc::make_mut`), so
//! every copy keeps exactly what it had. Equality checks the pointer first:
//! two configs that share a section compare it in O(1).
//!
//! Serialized exactly like `T` (the saved files do not change).

use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub struct CowArc<T>(Arc<T>);

impl<T> CowArc<T> {
    pub fn new(value: T) -> Self {
        Self(Arc::new(value))
    }

    /// Both share the same section (nothing was copied between them).
    pub fn ptr_eq(a: &Self, b: &Self) -> bool {
        Arc::ptr_eq(&a.0, &b.0)
    }
}

impl<T: Clone> CowArc<T> {
    /// The section itself, copied out only if it is still shared.
    pub fn into_inner(self) -> T {
        Arc::unwrap_or_clone(self.0)
    }
}

impl<T> Clone for CowArc<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> Deref for CowArc<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Clone> DerefMut for CowArc<T> {
    fn deref_mut(&mut self) -> &mut T {
        Arc::make_mut(&mut self.0)
    }
}

impl<T> From<T> for CowArc<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T: Default> Default for CowArc<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: fmt::Debug> fmt::Debug for CowArc<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        T::fmt(self, f)
    }
}

impl<T: PartialEq> PartialEq for CowArc<T> {
    fn eq(&self, other: &Self) -> bool {
        Self::ptr_eq(self, other) || *self.0 == *other.0
    }
}

impl<T: Eq> Eq for CowArc<T> {}

impl<T: PartialEq> PartialEq<T> for CowArc<T> {
    fn eq(&self, other: &T) -> bool {
        *self.0 == *other
    }
}

impl<T: Hash> Hash for CowArc<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        T::hash(self, state);
    }
}

impl<T: Serialize> Serialize for CowArc<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        T::serialize(self, s)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for CowArc<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        T::deserialize(d).map(Self::new)
    }
}

impl<A, T: FromIterator<A>> FromIterator<A> for CowArc<T> {
    fn from_iter<I: IntoIterator<Item = A>>(iter: I) -> Self {
        Self::new(T::from_iter(iter))
    }
}

impl<'a, T> IntoIterator for &'a CowArc<T>
where
    &'a T: IntoIterator,
{
    type Item = <&'a T as IntoIterator>::Item;
    type IntoIter = <&'a T as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        (&**self).into_iter()
    }
}

impl<'a, T: Clone> IntoIterator for &'a mut CowArc<T>
where
    &'a mut T: IntoIterator,
{
    type Item = <&'a mut T as IntoIterator>::Item;
    type IntoIter = <&'a mut T as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        (&mut **self).into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_write_copies_only_a_shared_section() {
        let mut a = CowArc::new(vec![1, 2, 3]);
        let b = a.clone();
        assert!(CowArc::ptr_eq(&a, &b));
        a.push(4);
        assert!(!CowArc::ptr_eq(&a, &b));
        assert_eq!(*b, vec![1, 2, 3]);
        assert_eq!(*a, vec![1, 2, 3, 4]);
        // Not shared any more: the next write does not copy.
        let before = Arc::as_ptr(&a.0);
        a.push(5);
        assert_eq!(Arc::as_ptr(&a.0), before);
    }

    #[test]
    fn serialized_like_the_section_itself() {
        let a = CowArc::new(vec!["x".to_owned()]);
        assert_eq!(serde_json::to_string(&a).unwrap(), r#"["x"]"#);
        let back: CowArc<Vec<String>> = serde_json::from_str(r#"["x"]"#).unwrap();
        assert_eq!(back, a);
        assert_eq!(format!("{a:?}"), r#"["x"]"#);
    }
}
