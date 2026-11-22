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
//! G4.1t: the map is also the count of lookups in flight. A new leader
//! past `max_concurrent_queries` is refused ([`Role::Busy`]); a follower
//! takes no slot. A follower either blocks ([`Follow::wait`], the router's
//! own tools) or leaves a callback ([`Follow::then`], the LAN forwarder's
//! event loop): no thread waits for it. Callbacks waiting are bounded
//! ([`MAX_WAITING`]).
//!
//! The leader always publishes a result, even when it unwinds or is
//! dropped unfinished (`Drop`). Waiting needs a clock only to count down
//! after a wake-up, so the caller's (the transport's) is used: no `Instant`
//! here (this crate also builds for WASM, where a follower never happens:
//! one thread).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use hickory_proto::rr::RecordType;

use super::{ResolveError, Resolved, Upstreams};

/// Name (lowercase key), type, and where it goes (`None`: the configured
/// servers).
pub(super) type Key = (String, RecordType, Option<Upstreams>);
type Outcome = Result<Resolved, ResolveError>;

/// What a follower's callback gets: the leader's result.
pub type Waiter = Box<dyn FnOnce(Outcome) + Send>;

/// Followers waiting with a callback, at most (each holds its client's
/// query, ~1 KiB: 16 MiB at worst). Past it a follower is refused like a
/// leader past `max_concurrent_queries`.
pub const MAX_WAITING: usize = 16_384;

/// The lookups in flight. One entry per leader, so the map is as big as
/// the lookups waiting on the network (at most `max_concurrent_queries`).
#[derive(Debug, Default)]
pub(super) struct Flights {
    map: Mutex<HashMap<Key, Arc<Flight>>>,
    /// Followers waiting with a callback.
    waiting: AtomicUsize,
}

/// One lookup in flight: its result once the leader has it, and who waits.
#[derive(Default)]
pub(super) struct Flight {
    state: Mutex<State>,
    done: Condvar,
}

#[derive(Default)]
struct State {
    result: Option<Outcome>,
    waiters: Vec<Waiter>,
}

impl std::fmt::Debug for Flight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Flight")
    }
}

pub(super) enum Role {
    Lead(Lead),
    Follow(Follow),
    /// No room: `max` leaders in flight, or [`MAX_WAITING`] followers.
    Busy,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic elsewhere never makes the resolver unusable.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Flights {
    /// Leads the lookup of `key` (if fewer than `max` are in flight), or
    /// follows the one already in flight.
    pub(super) fn join(self: &Arc<Self>, key: Key, max: usize) -> Role {
        let mut map = lock(&self.map);
        if let Some(f) = map.get(&key) {
            if self.waiting.load(Ordering::Relaxed) >= MAX_WAITING {
                return Role::Busy;
            }
            return Role::Follow(Follow {
                flight: f.clone(),
                flights: self.clone(),
            });
        }
        if map.len() >= max.max(1) {
            return Role::Busy;
        }
        let flight = Arc::new(Flight::default());
        map.insert(key.clone(), flight.clone());
        Role::Lead(Lead {
            flights: self.clone(),
            key: Some(key),
            flight,
        })
    }

    /// Lookups in flight (leaders) and followers waiting with a callback.
    pub(super) fn counts(&self) -> (usize, usize) {
        (lock(&self.map).len(), self.waiting.load(Ordering::Relaxed))
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        lock(&self.map).len()
    }
}

/// The leader's duty: publish a result and leave the map.
pub(super) struct Lead {
    flights: Arc<Flights>,
    /// `None` once published.
    key: Option<Key>,
    flight: Arc<Flight>,
}

impl std::fmt::Debug for Lead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lead").field("key", &self.key).finish()
    }
}

impl Lead {
    pub(super) fn finish(mut self, outcome: &Outcome) {
        self.publish(outcome.clone());
    }

    /// G4.1v (RFC 8767 §5): `outcome` (the stale answer) to every lookup
    /// waiting now, and to the ones that join from now on, while the
    /// lookup itself goes on: it stays in the map, so the equal ones still
    /// follow it instead of asking again, and its own result, when it
    /// comes, only fills the cache.
    pub(super) fn early(&self, outcome: &Outcome) {
        let waiters = {
            let mut st = lock(&self.flight.state);
            if st.result.is_some() {
                return;
            }
            st.result = Some(outcome.clone());
            std::mem::take(&mut st.waiters)
        };
        self.flight.done.notify_all();
        for w in waiters {
            self.flights.waiting.fetch_sub(1, Ordering::Relaxed);
            w(outcome.clone());
        }
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
        let waiters = {
            let mut st = lock(&self.flight.state);
            st.result = Some(outcome.clone());
            std::mem::take(&mut st.waiters)
        };
        self.flight.done.notify_all();
        // Outside the lock: a callback replies to its client (or queues).
        for w in waiters {
            self.flights.waiting.fetch_sub(1, Ordering::Relaxed);
            w(outcome.clone());
        }
    }
}

impl Drop for Lead {
    /// A leader that never finished (it unwound, or its lookup was dropped)
    /// still frees its followers, with a failure.
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

/// A place behind a leader.
pub struct Follow {
    flight: Arc<Flight>,
    flights: Arc<Flights>,
}

impl std::fmt::Debug for Follow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Follow")
    }
}

impl Follow {
    /// Calls `w` with the leader's result: now, on this thread, when it is
    /// already there; else on the leader's thread when it publishes (`w`
    /// should only reply or queue).
    pub fn then(self, w: Waiter) {
        let now = {
            let mut st = lock(&self.flight.state);
            match &st.result {
                Some(r) => Some(r.clone()),
                None => {
                    st.waiters.push(w);
                    self.flights.waiting.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        };
        if let Some(r) = now {
            w(r);
        }
    }

    /// The leader's result, or `None` if it is not there by `until_ms` on
    /// the clock `now_ms` (blocks this thread).
    pub fn wait(&self, until_ms: u64, now_ms: &dyn Fn() -> u64) -> Option<Outcome> {
        self.flight.wait(until_ms, now_ms)
    }
}

impl Flight {
    fn wait(&self, until_ms: u64, now_ms: &dyn Fn() -> u64) -> Option<Outcome> {
        let mut got = lock(&self.state);
        loop {
            if let Some(r) = got.result.as_ref() {
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
