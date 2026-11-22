//! Runtime state of a feature kept in the [`Session`](crate::Session)
//! without a field of its own: `s.ext::<NtpStatus>()`. Every feature that
//! added a field (and its initializer) to `Session` edited the same two lines
//! as every other one — the conflict of parallel PRs (docs/perf.md). The type
//! is the key, so two features never touch the same line.

use std::any::{Any, TypeId};
use std::collections::BTreeMap;

/// Values by type. Not configuration: never saved, gone on restart.
#[derive(Default)]
pub struct Extensions(BTreeMap<TypeId, Box<dyn Any + Send>>);

impl Extensions {
    /// The `T` stored, if any.
    pub fn get<T: Any + Send>(&self) -> Option<&T> {
        self.0.get(&TypeId::of::<T>())?.downcast_ref()
    }

    /// The `T` stored, created with `Default` the first time. `None` only if
    /// the map were corrupt (a value under another type's key), which the
    /// typed API never does.
    pub fn get_mut<T: Any + Send + Default>(&mut self) -> Option<&mut T> {
        self.0
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Box::new(T::default()))
            .downcast_mut()
    }

    /// Replace the `T` stored.
    pub fn set<T: Any + Send>(&mut self, value: T) {
        self.0.insert(TypeId::of::<T>(), Box::new(value));
    }
}

impl std::fmt::Debug for Extensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Extensions({} values)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default, Debug, PartialEq)]
    struct Clock(u32);
    #[derive(Default, Debug, PartialEq)]
    struct Other(u32);

    #[test]
    fn values_by_type() {
        let mut e = Extensions::default();
        assert_eq!(e.get::<Clock>(), None);
        if let Some(c) = e.get_mut::<Clock>() {
            c.0 += 2;
        }
        e.set(Other(7));
        assert_eq!(e.get::<Clock>(), Some(&Clock(2)));
        assert_eq!(e.get::<Other>(), Some(&Other(7)));
    }
}
