//! Short-cycle protection (G4.3m, Junos `short-cycle-protection`): a host
//! whose sessions keep ending soon after they start is locked out for a
//! while, longer each time, so a CPE in a loop stops costing a RADIUS
//! request, an address and a line of history every few seconds.
//!
//! - A session that ends within [`SHORT_MS`] of its PADR is a *short cycle*
//!   (Junos: "terminated within 150 seconds"), unless the end was not the
//!   host's doing ([`counts`]: the operator, the Session-Timeout, RADIUS
//!   not answering).
//! - The n-th in a row locks the host out for `min × 2^(n-1)`, capped at
//!   `max` (Junos' formula: 1, 2, 4… 256, 300 s by default). A gap of more
//!   than `max(15 min, max)` between two cycles starts over at n = 1.
//! - While locked out its PADIs and PADRs are dropped in silence: RFC 2516
//!   §5.2 allows no PADO for what the AC will not serve, and a PADS error
//!   would only make it start over sooner.
//!
//! **Memory.** The table has a fixed size, allocated on the first short
//! cycle: [`SETS`] × [`WAYS`] entries, at most [`Table::bytes`] per server
//! and worker, whatever an attacker does. Only a host that finished a
//! PADI/PADO/PADR exchange with a valid AC-Cookie can get an entry, so
//! spoofed MACs write nothing; one that really cycles through MACs (each
//! one a session, under `new_session_rate`) only pushes out the entries
//! closest to expiring. The set comes from a keyed hash: it cannot aim at
//! somebody's set from outside.
//!
//! **Cost.** A lookup hashes the key and compares [`WAYS`] entries, whatever
//! the number of entries: O(1), without a timer (an entry past its time is
//! ignored and reused).

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;

use super::{DownReason, HostKey};
use crate::timer::Millis;
use crate::wire::Mac;

/// A session shorter than this that ends is a short cycle (Junos: 150 s).
pub const SHORT_MS: Millis = 150_000;
/// The gap between two short cycles that keeps them "in a row", unless
/// `max` is larger (Junos: 15 min).
pub const GRACE_MS: Millis = 15 * 60_000;
/// Sets of the table (a power of two).
const SETS: usize = 4096;
/// Entries per set.
const WAYS: usize = 4;

/// The lockout range, from the server's config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShortCycle {
    pub min_ms: Millis,
    pub max_ms: Millis,
}

impl Default for ShortCycle {
    /// Junos' default range: 1 to 300 s.
    fn default() -> Self {
        ShortCycle {
            min_ms: 1000,
            max_ms: 300_000,
        }
    }
}

impl ShortCycle {
    /// The lockout of the `n`-th short cycle in a row: `min × 2^(n-1)`, at
    /// most `max`.
    pub fn penalty(&self, n: u32) -> Millis {
        let doubled = 1u64
            .checked_shl(n.saturating_sub(1))
            .map_or(u64::MAX, |f| self.min_ms.saturating_mul(f));
        doubled.min(self.max_ms)
    }

    fn grace(&self) -> Millis {
        GRACE_MS.max(self.max_ms)
    }
}

/// Is this end the host's doing? Its RADIUS not answering, the operator
/// and the Session-Timeout are not (a RADIUS outage must not lock everyone
/// out on top); running out of addresses cannot be told from a CPE refusing
/// IPCP, and counts (the pool coming back ends the lockout in `max` at most,
/// `ppp.lockout.clear` at once).
pub(super) fn counts(reason: DownReason) -> bool {
    !matches!(
        reason,
        DownReason::Admin | DownReason::SessionTimeout | DownReason::AuthTimeout
    )
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    key: HostKey,
    /// Short cycles in a row.
    strikes: u32,
    /// The last one's time and end.
    at: Millis,
    cause: DownReason,
    until: Millis,
}

/// A host locked out now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lockout {
    pub ifindex: u32,
    pub vlans: crate::eth::Vlans,
    pub mac: Mac,
    pub strikes: u32,
    pub left_ms: Millis,
    /// How the last session ended.
    pub cause: DownReason,
}

pub(super) struct Table {
    /// Empty until the first short cycle; then `SETS * WAYS`.
    entries: Vec<Option<Entry>>,
    hasher: RandomState,
}

impl Table {
    pub(super) fn new() -> Table {
        Table {
            entries: Vec::new(),
            hasher: RandomState::new(),
        }
    }

    /// What the table takes once in use (the ceiling the module promises).
    #[cfg(test)]
    pub(super) fn bytes() -> usize {
        SETS * WAYS * size_of::<Option<Entry>>()
    }

    fn set(&self, key: &HostKey) -> std::ops::Range<usize> {
        let start = (self.hasher.hash_one(key) as usize & (SETS - 1)) * WAYS;
        start..start + WAYS
    }

    /// The lockout of `key` at `now`, if any: (time left, strikes, cause).
    pub(super) fn locked(&self, now: Millis, key: &HostKey) -> Option<(Millis, u32, DownReason)> {
        if self.entries.is_empty() {
            return None;
        }
        self.entries
            .get(self.set(key))?
            .iter()
            .flatten()
            .find(|e| e.key == *key && e.until > now)
            .map(|e| (e.until - now, e.strikes, e.cause))
    }

    /// A short cycle of `key`: its strikes, and the lockout it now serves.
    pub(super) fn strike(
        &mut self,
        now: Millis,
        cfg: &ShortCycle,
        key: HostKey,
        cause: DownReason,
    ) -> (u32, Millis) {
        if self.entries.is_empty() {
            self.entries = vec![None; SETS * WAYS];
        }
        let range = self.set(&key);
        let grace = cfg.grace();
        let Some(ways) = self.entries.get_mut(range) else {
            return (0, 0);
        };
        let held = ways.iter().flatten().find(|e| e.key == key);
        let strikes = held
            .filter(|e| now.saturating_sub(e.at) <= grace)
            .map_or(1, |e| e.strikes.saturating_add(1));
        let penalty = cfg.penalty(strikes);
        let fresh = Entry {
            key,
            strikes,
            at: now,
            cause,
            until: now + penalty,
        };
        // Its own place; else a free one; else the one closest to the end
        // of its lockout (the least to lose).
        let at = ways
            .iter()
            .position(|e| e.is_some_and(|e| e.key == key))
            .or_else(|| ways.iter().position(Option::is_none))
            .or_else(|| {
                ways.iter()
                    .enumerate()
                    .min_by_key(|(_, e)| e.map_or(0, |e| e.until))
                    .map(|(i, _)| i)
            });
        if let Some(slot) = at.and_then(|i| ways.get_mut(i)) {
            *slot = Some(fresh);
        }
        (strikes, penalty)
    }

    /// The hosts locked out now.
    pub(super) fn lockouts(&self, now: Millis) -> impl Iterator<Item = Lockout> + '_ {
        self.entries
            .iter()
            .flatten()
            .filter(move |e| e.until > now)
            .map(move |e| Lockout {
                ifindex: e.key.ifindex,
                vlans: e.key.vlans,
                mac: e.key.mac,
                strikes: e.strikes,
                left_ms: e.until - now,
                cause: e.cause,
            })
    }

    /// Forgets `mac` (all of them with `None`), lockout and history (Junos
    /// `clear pppoe lockout`). How many were locked out.
    pub(super) fn clear(&mut self, now: Millis, mac: Option<Mac>) -> usize {
        let mut n = 0;
        for slot in &mut self.entries {
            if let Some(e) = slot
                && mac.is_none_or(|m| e.key.mac == m)
            {
                n += usize::from(e.until > now);
                *slot = None;
            }
        }
        n
    }

    /// Entries in use, for the tests.
    #[cfg(test)]
    pub(super) fn used(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    #[cfg(test)]
    pub(super) fn capacity(&self) -> usize {
        self.entries.len()
    }
}

/// Sessions per outer VLAN shared by the workers of one server (G4.3m).
/// With one tag the workers split a VLAN's subscribers by MAC, so each
/// alone cannot hold `max_per_vlan`. One counter per VID: 4096 × 4 B, O(1)
/// per PADI and per PADR, written only when a session starts or ends.
#[derive(Debug, Clone)]
pub struct VlanShare(std::sync::Arc<Vec<std::sync::atomic::AtomicU32>>);

impl Default for VlanShare {
    fn default() -> Self {
        VlanShare(std::sync::Arc::new(
            (0..4096).map(|_| Default::default()).collect(),
        ))
    }
}

impl VlanShare {
    fn cell(&self, vid: u16) -> Option<&std::sync::atomic::AtomicU32> {
        self.0.get(usize::from(vid))
    }

    pub(super) fn get(&self, vid: u16) -> u32 {
        self.cell(vid)
            .map_or(0, |c| c.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// One more, if the VLAN holds fewer than `max` (two workers at the last
    /// place: one wins).
    pub(super) fn reserve(&self, vid: u16, max: u32) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        self.cell(vid).is_some_and(|c| {
            c.try_update(Relaxed, Relaxed, |n| (n < max).then_some(n + 1))
                .is_ok()
        })
    }

    pub(super) fn add(&self, vid: u16, n: u32) {
        if let Some(c) = self.cell(vid) {
            c.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub(super) fn sub(&self, vid: u16, n: u32) {
        use std::sync::atomic::Ordering::Relaxed;
        if let Some(c) = self.cell(vid) {
            let _ = c.try_update(Relaxed, Relaxed, |v| Some(v.saturating_sub(n)));
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use proptest::prelude::*;

    use super::*;
    use crate::eth::Vlans;

    fn key(i: u32) -> HostKey {
        let [a, b, c, d] = i.to_be_bytes();
        HostKey {
            ifindex: 1,
            vlans: Vlans::NONE,
            mac: Mac([2, 0, a, b, c, d]),
        }
    }

    /// Junos' examples: 1, 2, 4… 256 and then 300; with 20–120, 20, 40, 80, 120.
    #[test]
    fn the_penalty_doubles_up_to_the_cap() {
        let d = ShortCycle::default();
        let got: Vec<u64> = (1..=10).map(|n| d.penalty(n) / 1000).collect();
        assert_eq!(got, [1, 2, 4, 8, 16, 32, 64, 128, 256, 300]);
        let c = ShortCycle {
            min_ms: 20_000,
            max_ms: 120_000,
        };
        let got: Vec<u64> = (1..=5).map(|n| c.penalty(n) / 1000).collect();
        assert_eq!(got, [20, 40, 80, 120, 120]);
        // Equal ends: a fixed time. And no overflow, however many strikes.
        let f = ShortCycle {
            min_ms: 60_000,
            max_ms: 60_000,
        };
        assert_eq!(f.penalty(1), 60_000);
        assert_eq!(f.penalty(u32::MAX), 60_000);
        assert_eq!(d.penalty(0), 1000);
    }

    #[test]
    fn strikes_grow_in_a_row_and_start_over_after_the_grace() {
        let cfg = ShortCycle::default();
        let mut t = Table::new();
        let k = key(1);
        assert_eq!(t.strike(0, &cfg, k, DownReason::AuthFailed), (1, 1000));
        assert_eq!(t.locked(500, &k).map(|l| l.0), Some(500));
        assert_eq!(t.locked(1000, &k), None, "served");
        assert_eq!(t.strike(5000, &cfg, k, DownReason::AuthFailed), (2, 2000));
        // Within 15 minutes: still in a row.
        assert_eq!(
            t.strike(5000 + GRACE_MS, &cfg, k, DownReason::Keepalive),
            (3, 4000)
        );
        // Past them: n = 1 again.
        let later = 5000 + 2 * GRACE_MS + 1;
        assert_eq!(t.strike(later, &cfg, k, DownReason::Keepalive), (1, 1000));
    }

    /// A max above 15 minutes stretches the grace with it (Junos: "whichever
    /// is greater").
    #[test]
    fn the_grace_is_at_least_the_longest_lockout() {
        let cfg = ShortCycle {
            min_ms: 3_600_000,
            max_ms: 3_600_000,
        };
        let mut t = Table::new();
        let k = key(1);
        t.strike(0, &cfg, k, DownReason::PeerPadt);
        assert_eq!(t.strike(3_600_000, &cfg, k, DownReason::PeerPadt).0, 2);
    }

    #[test]
    fn what_was_not_the_hosts_doing_does_not_count() {
        for r in [
            DownReason::Admin,
            DownReason::SessionTimeout,
            DownReason::AuthTimeout,
        ] {
            assert!(!counts(r), "{r:?}");
        }
        for r in [
            DownReason::PeerPadt,
            DownReason::PeerTerminate,
            DownReason::AuthFailed,
            DownReason::LcpFailed,
            DownReason::NcpFailed,
            DownReason::Keepalive,
            DownReason::SetupTimeout,
            DownReason::Replaced,
        ] {
            assert!(counts(r), "{r:?}");
        }
    }

    /// An attacker that changes MAC: 200 000 hosts leave the table at its
    /// size, and take nothing from a host locked out for longer than they.
    #[test]
    fn a_flood_of_macs_does_not_grow_the_table() {
        let cfg = ShortCycle::default();
        let mut t = Table::new();
        assert_eq!(t.capacity(), 0, "nothing until the first short cycle");
        for i in 0..200_000u32 {
            t.strike(u64::from(i), &cfg, key(i), DownReason::PeerPadt);
        }
        assert_eq!(t.capacity(), SETS * WAYS);
        assert!(t.used() <= SETS * WAYS);
        assert_eq!(Table::bytes(), t.capacity() * size_of::<Option<Entry>>());
        assert!(Table::bytes() <= 1024 * 1024, "{} B", Table::bytes());
        // A long lockout outlives what the flood writes (1 s each): it
        // goes only once its whole set holds longer ones.
        let mut t = Table::new();
        let victim = key(u32::MAX);
        for _ in 0..8 {
            t.strike(0, &cfg, victim, DownReason::AuthFailed);
        }
        for i in 0..200_000u32 {
            t.strike(1, &cfg, key(i), DownReason::PeerPadt);
        }
        assert_eq!(t.locked(2, &victim).map(|l| l.1), Some(8));
    }

    #[test]
    fn clear_forgets_one_or_all() {
        let cfg = ShortCycle::default();
        let mut t = Table::new();
        for i in 0..3 {
            t.strike(0, &cfg, key(i), DownReason::PeerPadt);
        }
        assert_eq!(t.lockouts(0).count(), 3);
        assert_eq!(t.clear(0, Some(key(1).mac)), 1);
        assert_eq!(t.locked(0, &key(1)), None);
        assert_eq!(
            t.strike(0, &cfg, key(1), DownReason::PeerPadt).0,
            1,
            "history gone"
        );
        assert_eq!(t.clear(0, None), 3);
        assert_eq!(t.lockouts(0).count(), 0);
    }

    #[test]
    fn the_shared_count_never_passes_the_limit() {
        let s = VlanShare::default();
        let hits = std::thread::scope(|sc| {
            let ts: Vec<_> = (0..4)
                .map(|_| {
                    let s = s.clone();
                    sc.spawn(move || (0..1000).filter(|_| s.reserve(100, 777)).count())
                })
                .collect();
            ts.into_iter().map(|t| t.join().unwrap()).sum::<usize>()
        });
        assert_eq!(hits, 777);
        assert_eq!(s.get(100), 777);
        s.sub(100, 1000);
        assert_eq!(s.get(100), 0, "never below zero");
        assert!(!s.reserve(5000, 1), "a VID out of range holds nothing");
    }

    proptest! {
        /// Whatever the order of events: the lockout never passes `max`, and
        /// a host is locked out only after a strike of its own.
        #[test]
        fn lockout_stays_in_range(
            min in 1u64..100_000,
            extra in 0u64..1_000_000,
            ev in proptest::collection::vec((0u32..8, 0u64..2_000_000), 1..200),
        ) {
            let cfg = ShortCycle { min_ms: min, max_ms: min + extra };
            let mut t = Table::new();
            let mut now = 0;
            for (who, dt) in ev {
                now += dt;
                let (n, p) = t.strike(now, &cfg, key(who), DownReason::PeerPadt);
                prop_assert!(n >= 1);
                prop_assert!(p >= cfg.min_ms && p <= cfg.max_ms);
                prop_assert_eq!(t.locked(now, &key(who)).map(|l| l.0), Some(p));
                prop_assert!(t.locked(now, &key(100)).is_none());
            }
        }
    }
}
