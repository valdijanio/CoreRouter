//! The neighbor table: routers heard by the discovery protocols (CRDP,
//! LLDP, MNDP). Operational state like link counters: it is not config, is
//! never saved and is not part of a commit.
//!
//! Integration point for every protocol: build a [`NeighborEntry`] and call
//! [`Session::record_neighbor`]; call [`Session::expire_neighbors`] about
//! once a second with the same clock. The session keeps only neighbors heard
//! on interfaces where discovery is active (running config), so a protocol
//! runtime may hand it everything it hears.

use std::collections::{BTreeMap, BTreeSet};

use corerouter_model::neighbor::{HOLD_MULTIPLIER, INTERVAL_RANGE};
use corerouter_model::{IfName, NeighborDiscovery, NeighborEntry, NeighborProtocol};

use crate::Session;

/// Most entries kept: a flood of fake neighbors evicts instead of growing
/// without bound.
pub const MAX_NEIGHBORS: usize = 4096;
/// Most entries kept per interface: a flood on one port (an access port, an
/// uplink) evicts that port's rows, never the neighbors heard on the others.
pub const MAX_PER_INTERFACE: usize = 256;
/// Longest hold time accepted from the wire: what our own slowest setting
/// announces (3600 s × 4). LLDP allows 65 535 s and CRDP/MNDP as much; a
/// longer claim is cut so a flood cannot pin rows for 18 h.
pub const MAX_HOLD_SECS: u32 = *INTERVAL_RANGE.end() * HOLD_MULTIPLIER;

type Key = (IfName, NeighborProtocol, String);
/// Eviction order inside one interface: oldest `last_seen` first.
type AgeKey = (IfName, u64, NeighborProtocol, String);

fn age_key(key: &Key, last_seen: u64) -> AgeKey {
    (key.0.clone(), last_seen, key.1, key.2.clone())
}

#[derive(Debug, Default)]
pub struct NeighborTable {
    entries: BTreeMap<Key, NeighborEntry>,
    /// Same rows as `entries`, ordered by interface and age (eviction).
    by_age: BTreeSet<AgeKey>,
    /// Rows per interface (none at 0).
    per_iface: BTreeMap<IfName, usize>,
    /// Newest time seen from the recorder's clock.
    now: u64,
}

impl NeighborTable {
    /// Add or refresh one entry; `hold_secs == 0` removes it instead.
    /// Returns true when the neighbor is new (not a live row before), so a
    /// receive loop can log "neighbor appeared" without scanning the table.
    ///
    /// Full table (per interface or overall): the row heard longest ago
    /// goes, taken from the same interface, or else from the interface with
    /// the most rows; a flood on one port only ever evicts that port.
    pub fn record(&mut self, mut entry: NeighborEntry) -> bool {
        self.now = self.now.max(entry.last_seen);
        let key = entry.key();
        if entry.hold_secs == 0 {
            self.remove(&key);
            return false;
        }
        entry.hold_secs = entry.hold_secs.min(MAX_HOLD_SECS);
        let now = self.now;
        if let Some(old) = self.entries.get_mut(&key) {
            let was_live = !expired(old, now);
            if old.last_seen != entry.last_seen {
                self.by_age.remove(&age_key(&key, old.last_seen));
                self.by_age.insert(age_key(&key, entry.last_seen));
            }
            *old = entry;
            return !was_live;
        }
        let on_iface = self.per_iface.get(&key.0).copied().unwrap_or(0);
        if on_iface >= MAX_PER_INTERFACE {
            self.evict_oldest_on(&key.0);
        } else if self.entries.len() >= MAX_NEIGHBORS {
            let busiest = self
                .per_iface
                .iter()
                .max_by_key(|(_, n)| **n)
                .map(|(i, _)| i.clone());
            if let Some(iface) = busiest {
                self.evict_oldest_on(&iface);
            }
        }
        self.by_age.insert(age_key(&key, entry.last_seen));
        *self.per_iface.entry(key.0.clone()).or_insert(0) += 1;
        self.entries.insert(key, entry);
        true
    }

    /// Whether a live row with this key exists (no scan).
    pub fn contains(&self, key: &Key) -> bool {
        self.entries.get(key).is_some_and(|e| !expired(e, self.now))
    }

    fn evict_oldest_on(&mut self, iface: &IfName) {
        let from = (iface.clone(), 0, NeighborProtocol::Crdp, String::new());
        let oldest = self
            .by_age
            .range(from..)
            .next()
            .filter(|(i, ..)| i == iface)
            .map(|(i, _, p, who)| (i.clone(), *p, who.clone()));
        if let Some(k) = oldest {
            self.remove(&k);
        }
    }

    fn remove(&mut self, key: &Key) {
        let Some(old) = self.entries.remove(key) else {
            return;
        };
        self.by_age.remove(&age_key(key, old.last_seen));
        if let Some(n) = self.per_iface.get_mut(&key.0) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.per_iface.remove(&key.0);
            }
        }
    }

    fn remove_where(&mut self, gone: impl Fn(&Key, &NeighborEntry) -> bool) -> usize {
        let keys: Vec<Key> = self
            .entries
            .iter()
            .filter(|(k, e)| gone(k, e))
            .map(|(k, _)| k.clone())
            .collect();
        for k in &keys {
            self.remove(k);
        }
        keys.len()
    }

    /// Forget entries whose hold time ran out at `now`. Returns how many.
    pub fn expire(&mut self, now: u64) -> usize {
        self.now = self.now.max(now);
        let now = self.now;
        self.remove_where(|_, e| expired(e, now))
    }

    /// Forget entries on interfaces where discovery is no longer active.
    pub fn retain_active(&mut self, settings: &NeighborDiscovery) -> usize {
        self.remove_where(|(iface, ..), _| !settings.active_on(iface))
    }

    /// Live entries, ordered by interface, protocol and node.
    pub fn iter(&self) -> impl Iterator<Item = &NeighborEntry> {
        let now = self.now;
        self.entries.values().filter(move |e| !expired(e, now))
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The table's clock: the newest time recorded or expired with.
    pub fn now(&self) -> u64 {
        self.now
    }
}

fn expired(e: &NeighborEntry, now: u64) -> bool {
    e.last_seen.saturating_add(u64::from(e.hold_secs)) <= now
}

/// What [`Session::hear_neighbor`] did with an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Heard {
    /// Discovery is not active on the entry's interface: nothing kept.
    Ignored,
    /// A neighbor that was not in the table (log it).
    New,
    /// A refresh of a known neighbor, or a goodbye (hold 0).
    Known,
}

impl Session {
    /// Record a neighbor heard by any discovery protocol. Returns false (and
    /// keeps nothing) when discovery is not active on `entry.interface` in
    /// the running config.
    pub fn record_neighbor(&mut self, entry: NeighborEntry) -> bool {
        self.hear_neighbor(entry) != Heard::Ignored
    }

    /// [`Session::record_neighbor`] that also says whether the neighbor is
    /// new, in O(log n): receive loops call it per datagram under the
    /// session lock.
    pub fn hear_neighbor(&mut self, entry: NeighborEntry) -> Heard {
        if !self.discovery_settings().active_on(&entry.interface) {
            return Heard::Ignored;
        }
        if self.neighbors.record(entry) {
            Heard::New
        } else {
            Heard::Known
        }
    }

    /// Drop neighbors whose hold time ran out at `now` (same clock as
    /// `NeighborEntry::last_seen`), and those on interfaces where discovery
    /// was turned off. Returns how many went.
    pub fn expire_neighbors(&mut self, now: u64) -> usize {
        let settings = self.discovery_settings().clone();
        self.neighbors.expire(now) + self.neighbors.retain_active(&settings)
    }

    pub fn neighbors(&self) -> &NeighborTable {
        &self.neighbors
    }

    /// Discovery settings in force (running config, not the candidate).
    pub fn discovery_settings(&self) -> &NeighborDiscovery {
        &self.store().running().ip.neighbor_discovery
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(iface: &str, node: &str, seen: u64, hold: u32) -> NeighborEntry {
        NeighborEntry {
            interface: iface.parse().unwrap(),
            protocol: NeighborProtocol::Crdp,
            mac: None,
            addresses: Vec::new(),
            identity: node.into(),
            version: String::new(),
            platform: String::new(),
            board: String::new(),
            uptime_secs: None,
            node_id: Some(node.into()),
            remote_interface: None,
            mgmt: None,
            last_seen: seen,
            hold_secs: hold,
        }
    }

    #[test]
    fn entries_expire_after_their_hold_time() {
        let mut t = NeighborTable::default();
        t.record(entry("ether1", "a", 100, 120));
        t.record(entry("ether1", "b", 150, 120));
        assert_eq!(t.len(), 2);
        assert_eq!(t.expire(219), 0);
        assert_eq!(t.expire(220), 1, "a: 100 + 120");
        assert_eq!(t.iter().next().unwrap().identity, "b");
        // Heard again: refreshed, not duplicated.
        t.record(entry("ether1", "b", 260, 120));
        assert_eq!(t.expire(300), 0);
        assert_eq!(t.len(), 1);
        // Goodbye (hold 0) removes at once.
        t.record(entry("ether1", "b", 301, 0));
        assert!(t.is_empty());
    }

    #[test]
    fn same_node_on_two_interfaces_is_two_rows() {
        let mut t = NeighborTable::default();
        t.record(entry("ether1", "a", 1, 120));
        t.record(entry("ether2", "a", 1, 120));
        assert_eq!(t.len(), 2);
    }

    /// Interface of the i-th flood row: spread over enough ports that the
    /// per-interface cap does not bind before the global one.
    fn port(i: u64) -> String {
        format!("ether{}", i % 32)
    }

    #[test]
    fn a_flood_is_bounded() {
        let mut t = NeighborTable::default();
        for i in 0..(MAX_NEIGHBORS as u64 + 10) {
            t.record(entry(&port(i), &format!("n{i}"), i, 1000));
        }
        assert_eq!(t.entries.len(), MAX_NEIGHBORS);
        assert_eq!(t.by_age.len(), MAX_NEIGHBORS);
        assert_eq!(t.per_iface.values().sum::<usize>(), MAX_NEIGHBORS);
        // The oldest went first.
        assert!(!t.iter().any(|e| e.identity == "n0"));
        assert!(
            t.iter()
                .any(|e| e.identity == format!("n{}", MAX_NEIGHBORS + 9))
        );
    }

    #[test]
    fn record_says_whether_the_neighbor_is_new() {
        let mut t = NeighborTable::default();
        assert!(t.record(entry("ether1", "a", 10, 120)));
        assert!(!t.record(entry("ether1", "a", 20, 120)), "a refresh");
        assert!(t.contains(&entry("ether1", "a", 0, 0).key()));
        // Ran out but not purged yet: heard again counts as new.
        assert!(t.record(entry("ether1", "b", 30, 5)));
        t.record(entry("ether1", "c", 40, 120));
        assert!(!t.contains(&entry("ether1", "b", 0, 0).key()));
        assert!(t.record(entry("ether1", "b", 41, 120)));
        assert!(!t.record(entry("ether1", "b", 42, 0)), "goodbye");
        assert!(!t.contains(&entry("ether1", "b", 0, 0).key()));
        assert_eq!(t.by_age.len(), t.entries.len());
    }

    #[test]
    fn hold_from_the_wire_is_capped() {
        let mut t = NeighborTable::default();
        t.record(entry("ether1", "a", 0, u32::from(u16::MAX)));
        assert_eq!(t.iter().next().unwrap().hold_secs, MAX_HOLD_SECS);
        assert_eq!(t.expire(u64::from(MAX_HOLD_SECS)), 1);
    }

    /// audit-services #4: 4096 fakes with hold 65535 on one port used to
    /// evict every real neighbor (earliest expiry first) on every port.
    #[test]
    fn a_flood_on_one_port_does_not_evict_the_others() {
        let mut t = NeighborTable::default();
        t.record(entry("ether2", "core", 0, 120));
        for i in 0..MAX_NEIGHBORS as u64 {
            t.record(entry("ether1", &format!("fake{i}"), 1 + i / 100, 65535));
        }
        t.record(entry("ether3", "edge", 50, 120));
        t.record(entry("ether1", "one-more", 60, 65535));
        assert!(t.contains(&entry("ether2", "core", 0, 0).key()));
        assert!(t.contains(&entry("ether3", "edge", 0, 0).key()));
        assert_eq!(t.per_iface.get(&"ether1".parse().unwrap()), Some(&MAX_PER_INTERFACE));
        assert!(t.iter().filter(|e| e.interface.as_str() == "ether1").count() <= MAX_PER_INTERFACE);
        // On its own port, the row heard longest ago went first.
        assert!(!t.iter().any(|e| e.identity == "fake0"));
        assert!(t.iter().any(|e| e.identity == "one-more"));
    }

    /// Full table, rows spread over many ports: a new row evicts from the
    /// busiest port, never from a port with a single neighbor.
    #[test]
    fn a_full_table_evicts_from_the_busiest_port() {
        let mut t = NeighborTable::default();
        t.record(entry("lonely", "a", 0, 120));
        let mut i = 0u64;
        while t.entries.len() < MAX_NEIGHBORS {
            t.record(entry(&port(i), &format!("n{i}"), 1, 120));
            i += 1;
        }
        t.record(entry("other", "b", 2, 120));
        assert!(t.contains(&entry("lonely", "a", 0, 0).key()));
        assert!(t.contains(&entry("other", "b", 0, 0).key()));
        assert_eq!(t.entries.len(), MAX_NEIGHBORS);
    }

    /// audit-services #1: the receive path with a full table was ~120 µs per
    /// datagram (a scan cloning every key, then an O(n) eviction scan).
    #[test]
    fn recording_into_a_full_table_is_cheap() {
        let mut t = NeighborTable::default();
        for i in 0..MAX_NEIGHBORS as u64 {
            t.record(entry(&port(i), &format!("n{i}"), 1, 120));
        }
        let start = std::time::Instant::now();
        for i in 0..10_000u64 {
            let e = entry(&port(i), &format!("new{i}"), 2, 120);
            assert!(t.record(e));
        }
        let took = start.elapsed();
        // Debug build, shared CI machine: generous (release: ~1 ms).
        assert!(took < std::time::Duration::from_millis(500), "{took:?}");
    }
}
