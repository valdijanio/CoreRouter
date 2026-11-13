//! G4.1o: equal lookups in flight are asked once. The first lookup of a
//! name, type and upstreams that misses the cache leads: it asks the
//! servers. The ones that arrive while it is out follow: they wait for its
//! result instead of sending the same query again.
//!
//! Why: N clients asking the same name outside the cache (a popular name
//! whose TTL just ran out, a flush, a name with TTL 0) sent N equal queries
//! upstream, each holding a `max_concurrent_queries` slot (measured in
//! `docs/dns-stress.md`: one query upstream per answer). Several equal
//! queries outstanding also make a forged answer easier to land (the
//! birthday attack of RFC 5452 §5). Unbound joins them in its mesh (one
//! state per name, type, class and flags); dnsmasq does since 2.83
//! (CVE-2020-25686).
//!
//! A follower waits at most until its own deadline (the leader's total
//! timeout plus a margin); the leader always publishes a result, even when
//! it unwinds (`Drop`). Waiting needs a clock only to count down after a
//! wake-up, so the caller's (the transport's) is used: no `Instant` here
//! (this crate also builds for WASM, where a follower never happens: one
//! thread).

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use hickory_proto::rr::RecordType;

use super::{ResolveError, Resolved, Upstreams};

/// Name (lowercase key), type, and where it goes (`None`: the configured
/// servers).
pub(super) type Key = (String, RecordType, Option<Upstreams>);
type Outcome = Result<Resolved, ResolveError>;

/// The lookups in flight. One entry per leader, so the map is as big as
/// the lookups waiting on the network (bounded by the callers' threads).
#[derive(Debug, Default)]
pub(super) struct Flights {
    map: Mutex<HashMap<Key, Arc<Flight>>>,
}

/// One lookup in flight: its result once the leader has it.
#[derive(Debug, Default)]
pub(super) struct Flight {
    result: Mutex<Option<Outcome>>,
    done: Condvar,
}

pub(super) enum Role<'a> {
    Lead(Lead<'a>),
    Follow(Arc<Flight>),
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic elsewhere never makes the resolver unusable.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Flights {
    /// Leads the lookup of `key`, or follows the one already in flight.
    pub(super) fn join(&self, key: Key) -> Role<'_> {
        let mut map = lock(&self.map);
        if let Some(f) = map.get(&key) {
            return Role::Follow(f.clone());
        }
        let flight = Arc::new(Flight::default());
        map.insert(key.clone(), flight.clone());
        Role::Lead(Lead {
            flights: self,
            key: Some(key),
            flight,
        })
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        lock(&self.map).len()
    }
}

/// The leader's duty: publish a result and leave the map.
pub(super) struct Lead<'a> {
    flights: &'a Flights,
    /// `None` once published.
    key: Option<Key>,
    flight: Arc<Flight>,
}

impl Lead<'_> {
    pub(super) fn finish(mut self, outcome: &Outcome) {
        self.publish(outcome.clone());
    }

    fn publish(&mut self, outcome: Outcome) {
        let Some(key) = self.key.take() else { return };
        // Out of the map first: a lookup that comes now leads a new flight
        // (or finds the answer in the cache) instead of following a
        // finished one.
        {
            let mut map = lock(&self.flights.map);
            if map.get(&key).is_some_and(|f| Arc::ptr_eq(f, &self.flight)) {
                map.remove(&key);
            }
        }
        *lock(&self.flight.result) = Some(outcome);
        self.flight.done.notify_all();
    }
}

impl Drop for Lead<'_> {
    /// A leader that never finished (it unwound) still frees its
    /// followers, with a failure.
    fn drop(&mut self) {
        if let Some((name, _, _)) = &self.key {
            let name = name.clone();
            self.publish(Err(ResolveError::Failed {
                name,
                why: "the lookup in flight ended without an answer".into(),
            }));
        }
    }
}

impl Flight {
    /// The leader's result, or `None` if it is not there by `until_ms` on
    /// the clock `now_ms`.
    pub(super) fn wait(&self, until_ms: u64, now_ms: &dyn Fn() -> u64) -> Option<Outcome> {
        let mut got = lock(&self.result);
        loop {
            if let Some(r) = got.as_ref() {
                return Some(r.clone());
            }
            let left = until_ms.saturating_sub(now_ms());
            if left == 0 {
                return None;
            }
            got = self
                .done
                .wait_timeout(got, Duration::from_millis(left))
                .map_or_else(|e| e.into_inner().0, |(g, _)| g);
        }
    }
}

#[cfg(test)]
mod tests;
