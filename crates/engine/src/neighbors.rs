//! The neighbor table: routers heard by the discovery protocols (CRDP,
//! LLDP, MNDP). Operational state like link counters: it is not config, is
//! never saved and is not part of a commit.
//!
//! Integration point for every protocol: build a [`NeighborEntry`] and call
//! [`Session::record_neighbor`]; call [`Session::expire_neighbors`] about
//! once a second with the same clock. The session keeps only neighbors heard
//! on interfaces where discovery is active (running config), so a protocol
//! runtime may hand it everything it hears.

use std::collections::BTreeMap;

use corerouter_model::{IfName, NeighborDiscovery, NeighborEntry, NeighborProtocol};

use crate::Session;

/// Most entries kept: a flood of fake neighbors evicts the oldest instead of
/// growing without bound.
pub const MAX_NEIGHBORS: usize = 4096;

type Key = (IfName, NeighborProtocol, String);

#[derive(Debug, Default)]
pub struct NeighborTable {
    entries: BTreeMap<Key, NeighborEntry>,
    /// Newest time seen from the recorder's clock.
    now: u64,
}

impl NeighborTable {
    /// Add or refresh one entry; `hold_secs == 0` removes it instead.
    pub fn record(&mut self, entry: NeighborEntry) {
        self.now = self.now.max(entry.last_seen);
        let key = entry.key();
        if entry.hold_secs == 0 {
            self.entries.remove(&key);
            return;
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= MAX_NEIGHBORS {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_seen.saturating_add(u64::from(e.hold_secs)))
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                self.entries.remove(&k);
            }
        }
        self.entries.insert(key, entry);
    }

    /// Forget entries whose hold time ran out at `now`. Returns how many.
    pub fn expire(&mut self, now: u64) -> usize {
        self.now = self.now.max(now);
        let now = self.now;
        let before = self.entries.len();
        self.entries.retain(|_, e| !expired(e, now));
        before - self.entries.len()
    }

    /// Forget entries on interfaces where discovery is no longer active.
    pub fn retain_active(&mut self, settings: &NeighborDiscovery) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|(iface, ..), _| settings.active_on(iface));
        before - self.entries.len()
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

impl Session {
    /// Record a neighbor heard by any discovery protocol. Returns false (and
    /// keeps nothing) when discovery is not active on `entry.interface` in
    /// the running config.
    pub fn record_neighbor(&mut self, entry: NeighborEntry) -> bool {
        if !self.discovery_settings().active_on(&entry.interface) {
            return false;
        }
        self.neighbors.record(entry);
        true
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

    #[test]
    fn a_flood_is_bounded() {
        let mut t = NeighborTable::default();
        for i in 0..(MAX_NEIGHBORS as u64 + 10) {
            t.record(entry("ether1", &format!("n{i}"), i, 1000));
        }
        assert_eq!(t.entries.len(), MAX_NEIGHBORS);
        // The oldest went first.
        assert!(!t.iter().any(|e| e.identity == "n0"));
        assert!(
            t.iter()
                .any(|e| e.identity == format!("n{}", MAX_NEIGHBORS + 9))
        );
    }
}
