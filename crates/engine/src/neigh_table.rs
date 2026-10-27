//! The neighbor tables as the engine keeps them (G1.27d): ARP and IPv6 ND
//! entries of the data plane, for `ip.arp.list`, `ipv6.neighbor.list`, the
//! `incomplete` gateway of `ip.route.list` and the arpwatch-style alerts.
//!
//! The table has a lock of its own ([`NeighShared`]): the app's thread
//! applies the platform's events to it (one change is O(1): a hash lookup
//! and a slot) without ever taking the session lock, and the commands read
//! it under the session lock. Without such a thread (the in-browser lab,
//! `corerouter-cli run`, tests) a list reads the platform once per query.
//!
//! Memory: a row is 48 bytes and the index ~40 more per entry (**medido**
//! in `benches/neigh.rs`), so a million neighbors is ~90 MB.
//!
//! Alerts, as arpwatch reports them: a known address seen with another
//! MAC ("changed ethernet address"), and back to the MAC it had before
//! ("flip flop": two hosts answer for one address, a duplicate IP or an
//! ARP spoofer). They queue (bounded) until the app logs them.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use corerouter_hal::neigh::{NeighEvent, NeighState, Neighbor};
use corerouter_model::IfName;
use serde::Serialize;

/// Alerts kept until the app takes them; past this the oldest go.
pub const MAX_ALERTS: usize = 256;
/// MAC changes remembered per table (the detail panel's history), oldest
/// out first.
pub const MAX_HISTORY: usize = 4096;

/// The table is "nearly full" from this share of `gc_thresh3` (RFC 6583
/// §6: watch the table, an attacker can fill it from outside).
pub const NEAR_FULL_PCT: u64 = 80;
/// The kernel's table thresholds that would leave room for `n`
/// entries: t3 = 2·n rounded up to a power of two, t2 = t3/2, t1 = t3/8,
/// never below the kernel's defaults (128/512/1024).
pub fn suggest_gc(n: u64) -> [u64; 3] {
    let t3 = n
        .saturating_mul(2)
        .clamp(1024, 1 << 20)
        .checked_next_power_of_two()
        .unwrap_or(1 << 20);
    [(t3 / 8).max(128), (t3 / 2).max(512), t3]
}

/// One entry, compact: the interface is an index into the table's names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    pub iface: u16,
    pub address: IpAddr,
    /// `[0; 6]` with `has_mac` false: not resolved.
    pub mac: [u8; 6],
    pub has_mac: bool,
    pub state: NeighState,
    pub router: bool,
    /// Unix seconds of the last confirmation (reachable), when known.
    pub seen: u64,
    /// Unix seconds the entry took its MAC (the history's "since").
    pub mac_since: u64,
}

impl Row {
    pub fn mac(&self) -> Option<[u8; 6]> {
        self.has_mac.then_some(self.mac)
    }
}

/// What an alert says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AlertKind {
    /// A known address answered from another MAC.
    MacChanged,
    /// …and then back to the MAC before: two hosts claim the address.
    FlipFlop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Alert {
    pub kind: AlertKind,
    pub interface: IfName,
    pub address: IpAddr,
    pub old: [u8; 6],
    pub new: [u8; 6],
    pub time: u64,
}

/// One MAC change of an address (the detail panel's history).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    pub interface: IfName,
    pub address: IpAddr,
    pub mac: [u8; 6],
    /// When this MAC was first seen for the address.
    pub since: u64,
}

#[derive(Debug, Default)]
pub struct NeighTable {
    names: Vec<IfName>,
    name_idx: HashMap<IfName, u16>,
    index: HashMap<(u16, IpAddr), u32>,
    rows: Vec<Row>,
    /// Bumped by every change: a reader can tell whether to look again.
    pub generation: u64,
    /// A thread keeps the table from the platform's events.
    pub fed: bool,
    /// What feeds it (`netlink`, `lab`), and changes it lost.
    pub source: &'static str,
    pub lost: u64,
    alerts: VecDeque<Alert>,
    /// The previous MAC of each address that changed (flip-flop check).
    before: HashMap<(u16, IpAddr), [u8; 6]>,
    history: VecDeque<Change>,
}

impl NeighTable {
    fn iface(&mut self, name: &IfName) -> u16 {
        if let Some(i) = self.name_idx.get(name) {
            return *i;
        }
        // More than 65 535 interface names would be a hostile platform:
        // the last slot is shared then (names stay right for the rest).
        let i = u16::try_from(self.names.len()).unwrap_or(u16::MAX);
        if i < u16::MAX {
            self.names.push(name.clone());
            self.name_idx.insert(name.clone(), i);
        }
        i
    }

    pub fn name(&self, iface: u16) -> Option<&IfName> {
        self.names.get(usize::from(iface))
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    pub fn get(&self, name: &IfName, address: IpAddr) -> Option<&Row> {
        let i = *self.name_idx.get(name)?;
        let at = *self.index.get(&(i, address))?;
        self.rows.get(usize::try_from(at).ok()?)
    }

    /// The entry of `address` on any interface (a gateway's).
    pub fn find(&self, address: IpAddr) -> Option<&Row> {
        // Interfaces are few: one lookup each.
        (0..self.names.len())
            .filter_map(|i| u16::try_from(i).ok())
            .find_map(|i| self.index.get(&(i, address)))
            .and_then(|at| self.rows.get(usize::try_from(*at).ok()?))
    }

    /// Replace everything with a dump (taken with no lock held).
    pub fn load(&mut self, dump: Vec<Neighbor>, now: u64) {
        let old: HashMap<(u16, IpAddr), Row> = self
            .rows
            .drain(..)
            .map(|r| ((r.iface, r.address), r))
            .collect();
        self.index.clear();
        self.rows.reserve(dump.len());
        for n in dump {
            let i = self.iface(&n.interface);
            let mut row = to_row(i, &n, now);
            if let Some(o) = old.get(&(i, n.address))
                && o.mac == row.mac
            {
                row.mac_since = o.mac_since;
            }
            self.insert(row);
        }
        self.generation = self.generation.wrapping_add(1);
    }

    fn insert(&mut self, row: Row) {
        let key = (row.iface, row.address);
        if let Some(at) = self.index.get(&key).copied() {
            if let Some(slot) = usize::try_from(at).ok().and_then(|a| self.rows.get_mut(a)) {
                *slot = row;
            }
            return;
        }
        let Ok(at) = u32::try_from(self.rows.len()) else {
            return;
        };
        self.rows.push(row);
        self.index.insert(key, at);
    }

    fn remove(&mut self, iface: u16, address: IpAddr) {
        let Some(at) = self.index.remove(&(iface, address)) else {
            return;
        };
        let Ok(at) = usize::try_from(at) else { return };
        if at >= self.rows.len() {
            return;
        }
        self.rows.swap_remove(at);
        // The last row moved into the hole: point its key there.
        if let Some(moved) = self.rows.get(at)
            && let Ok(at32) = u32::try_from(at)
        {
            self.index.insert((moved.iface, moved.address), at32);
        }
    }

    /// Apply changes from the platform, O(1) each.
    pub fn apply(&mut self, events: &[NeighEvent], now: u64) {
        for e in events {
            match e {
                NeighEvent::Upsert(n) => self.upsert(n, now),
                NeighEvent::Remove { interface, address } => {
                    if let Some(i) = self.name_idx.get(interface).copied() {
                        self.remove(i, *address);
                    }
                }
            }
        }
        if !events.is_empty() {
            self.generation = self.generation.wrapping_add(1);
        }
    }

    fn upsert(&mut self, n: &Neighbor, now: u64) {
        let i = self.iface(&n.interface);
        let mut row = to_row(i, n, now);
        if let Some(old) = self.get(&n.interface, n.address).copied() {
            if !n.state.resolved() || !row.has_mac {
                // Re-resolving: the last MAC is kept for display.
                row.mac = old.mac;
                row.has_mac = old.has_mac;
            }
            if row.mac == old.mac {
                row.mac_since = old.mac_since;
                if n.confirmed_secs.is_none() {
                    row.seen = old.seen;
                }
            } else if old.has_mac && row.has_mac {
                self.changed(i, n, old.mac, row.mac, now);
            }
        } else if row.has_mac {
            self.remember(n, row.mac, now);
        }
        self.insert(row);
    }

    fn changed(&mut self, i: u16, n: &Neighbor, old: [u8; 6], new: [u8; 6], now: u64) {
        let key = (i, n.address);
        let kind = if self.before.get(&key) == Some(&new) {
            AlertKind::FlipFlop
        } else {
            AlertKind::MacChanged
        };
        self.before.insert(key, old);
        if self.before.len() > MAX_HISTORY {
            // A flood of changes: forget the flip-flop memory, not the
            // table (it is only for the alert's wording).
            self.before.clear();
        }
        if self.alerts.len() >= MAX_ALERTS {
            self.alerts.pop_front();
        }
        self.alerts.push_back(Alert {
            kind,
            interface: n.interface.clone(),
            address: n.address,
            old,
            new,
            time: now,
        });
        self.remember(n, new, now);
    }

    fn remember(&mut self, n: &Neighbor, mac: [u8; 6], now: u64) {
        if self.history.len() >= MAX_HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(Change {
            interface: n.interface.clone(),
            address: n.address,
            mac,
            since: now,
        });
    }

    /// The alerts since the last call.
    pub fn take_alerts(&mut self) -> Vec<Alert> {
        self.alerts.drain(..).collect()
    }

    /// The MACs `address` had, oldest first.
    pub fn history(&self, address: IpAddr) -> Vec<&Change> {
        self.history.iter().filter(|c| c.address == address).collect()
    }
}

fn to_row(iface: u16, n: &Neighbor, now: u64) -> Row {
    Row {
        iface,
        address: n.address,
        mac: n.mac.unwrap_or([0; 6]),
        has_mac: n.mac.is_some(),
        state: n.state,
        router: n.router,
        seen: n
            .confirmed_secs
            .map_or(0, |s| now.saturating_sub(u64::from(s))),
        mac_since: now,
    }
}

/// The shared table, kept in the session (`s.ext::<NeighShared>()`); the
/// app's thread holds a clone.
#[derive(Debug, Clone, Default)]
pub struct NeighShared(pub Arc<Mutex<NeighTable>>);

impl NeighShared {
    pub fn lock(&self) -> MutexGuard<'_, NeighTable> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl crate::Session {
    /// The table to hand to a feeding thread.
    pub fn neigh_shared(&mut self) -> NeighShared {
        self.ext_mut::<NeighShared>().cloned().unwrap_or_default()
    }

    /// The platform's live feed, for the app's thread (`Err`: this
    /// backend has none; the lists then read it per query).
    pub fn neighbor_feed(
        &mut self,
    ) -> std::result::Result<Box<dyn corerouter_hal::neigh::NeighborFeed>, String> {
        self.hal_mut().neighbor_feed().map_err(|e| e.to_string())
    }

    /// The kernel's ceiling of each table (`gc_thresh3`, IPv4 and IPv6).
    pub fn neigh_ceiling(&mut self) -> [Option<u64>; 2] {
        let names = [
            "net.ipv4.neigh.default.gc_thresh3",
            "net.ipv6.neigh.default.gc_thresh3",
        ];
        let got = self.hal_mut().sysctls(&names).unwrap_or_default();
        names.map(|n| {
            got.get(n)
                .copied()
                .flatten()
                .and_then(|v| u64::try_from(v).ok())
        })
    }

    /// Fill the table from the platform if no thread keeps it (one read
    /// per query; the lab and the CLI without a daemon).
    pub(crate) fn neigh_fresh(&mut self) -> NeighShared {
        let n = self.neigh_shared();
        if !n.lock().fed {
            match self.hal_mut().neighbors() {
                Ok(dump) => {
                    let now = self.now().unwrap_or(0);
                    let mut t = n.lock();
                    t.load(dump, now);
                    t.source = "query";
                }
                Err(e) => log::debug!("neighbors: {e}"),
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(iface: &str, ip: &str, mac: Option<u8>, state: NeighState) -> Neighbor {
        Neighbor {
            interface: iface.parse().unwrap(),
            address: ip.parse().unwrap(),
            mac: mac.map(|m| [2, 0, 0, 0, 0, m]),
            state,
            router: false,
            confirmed_secs: Some(1),
            updated_secs: Some(1),
        }
    }

    #[test]
    fn suggestions_leave_room_and_never_shrink_below_the_kernel() {
        assert_eq!(suggest_gc(10), [128, 512, 1024]);
        assert_eq!(suggest_gc(3000), [1024, 4096, 8192]);
        assert_eq!(suggest_gc(u64::MAX), [131_072, 524_288, 1 << 20]);
    }

    #[test]
    fn events_insert_update_and_remove_in_place() {
        let mut t = NeighTable::default();
        t.load(
            vec![
                n("ether1", "10.0.0.2", Some(2), NeighState::Reachable),
                n("ether1", "10.0.0.3", Some(3), NeighState::Stale),
                n("ether2", "10.1.0.2", Some(4), NeighState::Reachable),
            ],
            100,
        );
        assert_eq!(t.len(), 3);
        let g = t.generation;
        t.apply(
            &[
                NeighEvent::Remove {
                    interface: "ether1".parse().unwrap(),
                    address: "10.0.0.2".parse().unwrap(),
                },
                NeighEvent::Upsert(n("ether1", "10.0.0.9", None, NeighState::Incomplete)),
            ],
            101,
        );
        assert!(t.generation != g);
        assert_eq!(t.len(), 3);
        let e1: IfName = "ether1".parse().unwrap();
        assert!(t.get(&e1, "10.0.0.2".parse().unwrap()).is_none());
        // The swap kept every other key pointing at its own row.
        for r in t.rows() {
            let name = t.name(r.iface).unwrap().clone();
            assert_eq!(t.get(&name, r.address), Some(r));
        }
        let inc = t.find("10.0.0.9".parse().unwrap()).unwrap();
        assert_eq!((inc.state, inc.mac()), (NeighState::Incomplete, None));
    }

    #[test]
    fn a_new_mac_alerts_and_going_back_is_a_flip_flop() {
        let mut t = NeighTable::default();
        t.load(vec![n("ether1", "10.0.0.2", Some(2), NeighState::Reachable)], 10);
        t.apply(&[NeighEvent::Upsert(n("ether1", "10.0.0.2", Some(9), NeighState::Reachable))], 20);
        t.apply(&[NeighEvent::Upsert(n("ether1", "10.0.0.2", Some(2), NeighState::Reachable))], 30);
        let a = t.take_alerts();
        assert_eq!(
            a.iter().map(|a| a.kind).collect::<Vec<_>>(),
            [AlertKind::MacChanged, AlertKind::FlipFlop]
        );
        assert_eq!((a[0].old[5], a[0].new[5]), (2, 9));
        assert!(t.take_alerts().is_empty());
        // Going stale or re-resolving is not a change of MAC.
        t.apply(&[NeighEvent::Upsert(n("ether1", "10.0.0.2", None, NeighState::Probe))], 40);
        assert!(t.take_alerts().is_empty());
        let r = t.find("10.0.0.2".parse().unwrap()).unwrap();
        assert_eq!((r.mac(), r.mac_since), (Some([2, 0, 0, 0, 0, 2]), 30));
        assert_eq!(t.history("10.0.0.2".parse().unwrap()).len(), 2);
    }

    #[test]
    fn alerts_are_bounded() {
        let mut t = NeighTable::default();
        for i in 0..(MAX_ALERTS as u32 + 50) {
            let m = (i % 2) as u8 + 1;
            t.apply(&[NeighEvent::Upsert(n("ether1", "10.0.0.2", Some(m), NeighState::Reachable))], u64::from(i));
        }
        assert_eq!(t.take_alerts().len(), MAX_ALERTS);
    }
}
