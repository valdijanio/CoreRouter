//! Distributed brute force against one user name (G0.12).
//!
//! The per-source limits of [`crate::auth`] stop one address; an attacker
//! with many addresses only ever met the per-name delay (at most
//! [`Limits::max_delay`] per attempt). Here a user name that collects
//! [`Limits::lock_after`] failures from [`Limits::lock_sources`] distinct
//! sources (an IPv4 address or an IPv6 /64) within [`Limits::window`] is
//! **locked for network logins**: [`Limits::lock_base`] the first time,
//! twice as long each time it locks again within [`Limits::lock_memory`],
//! at most [`Limits::lock_max`]. A lock is never permanent (that would hand
//! any attacker the `admin` account's door) and never applies to:
//!
//! - loopback (`127.0.0.0/8`, `::1`) or a connection without an address:
//!   whoever is on the router itself can always log in;
//! - the local token, which never goes through `auth.login`;
//! - a **known source**: one this user logged in from before (within
//!   [`Limits::lock_memory`], at most [`MAX_KNOWN`] per user), so the
//!   operator's own workstation keeps working during an attack. Its
//!   failures (typos) do not count towards the lock either.
//!
//! Every attempt is counted when it starts (as in [`crate::auth`]), so
//! parallel attempts cannot all slip under the threshold; the one that
//! reaches it is refused too. A lock refuses before any Argon2 work.
//! Junos `retry-options lockout-period`, Cisco `aaa local authentication
//! attempts max-fail`, pam_faillock `deny`/`unlock_time`; the exemptions
//! follow Junos (the console is never locked) and NIST SP 800-63B-4 §3.2.2
//! (rate limiting must not let an attacker lock the real subscriber out).
//!
//! Cost per login: one hash lookup and a scan of at most [`MAX_SOURCES`]
//! sources and [`MAX_KNOWN`] known ones, under the lock the per-source
//! counting already takes; it does not grow with the number of users or
//! sources (the table is capped at [`MAX_USERS`]).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use corerouter_engine::login_lockout::UserLockout;

use crate::auth::Limits;

/// Most user names tracked at once.
pub(crate) const MAX_USERS: usize = 1024;
/// Distinct failing sources kept per name (enough to tell "several").
pub(crate) const MAX_SOURCES: usize = 32;
/// Known sources kept per name (the oldest goes first).
pub(crate) const MAX_KNOWN: usize = 16;

/// A source that is never locked out: the router itself, or no address.
pub(crate) fn exempt(peer: Option<IpAddr>) -> bool {
    peer.is_none_or(|p| p.to_canonical().is_loopback())
}

/// Whole seconds, rounded up (a lock with 0.2 s left says 1).
fn ceil_secs(d: Duration) -> u64 {
    d.as_secs().saturating_add(u64::from(d.subsec_nanos() > 0))
}

#[derive(Default)]
struct Entry {
    failures: u32,
    sources: Vec<String>,
    last_failure: Option<Instant>,
    until: Option<Instant>,
    blocks: u32,
    /// What started the current lock, shown while it lasts.
    lock_failures: u32,
    lock_sources: u32,
    /// Attempts refused during the current lock.
    refused: u32,
    known: Vec<(String, Instant)>,
}

impl Entry {
    fn locked(&self, now: Instant) -> Option<Duration> {
        self.until
            .map(|u| u.saturating_duration_since(now))
            .filter(|d| !d.is_zero())
    }

    fn is_known(&self, source: &str, now: Instant, l: &Limits) -> bool {
        self.known
            .iter()
            .any(|(s, t)| s == source && now.duration_since(*t) < l.lock_memory)
    }

    /// Nothing worth keeping: no failure in the window, no lock or lock
    /// worth remembering, no known source.
    fn idle(&self, now: Instant, l: &Limits) -> bool {
        let failing = self
            .last_failure
            .is_some_and(|t| now.duration_since(t) < l.window);
        let remembered = self
            .until
            .is_some_and(|u| now.saturating_duration_since(u) < l.lock_memory);
        let known = self
            .known
            .iter()
            .any(|(_, t)| now.duration_since(*t) < l.lock_memory);
        !failing && !remembered && !known
    }
}

/// A lock that began with this attempt, for the router's log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LockStarted {
    pub user: String,
    pub secs: u64,
    pub failures: u32,
    pub sources: Vec<String>,
    pub blocks: u32,
}

/// Why an attempt is refused before the password is looked at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Locked {
    pub secs: u64,
    /// Set when this very attempt started the lock.
    pub started: Option<LockStarted>,
}

impl Locked {
    pub(crate) fn message(&self) -> String {
        format!(
            "too many failed logins for this user from several addresses: its network logins \
             are held for {} more seconds (log in on the router itself, from an address it \
             logged in from before, or ask another full user for user.lockout.clear)",
            self.secs.max(1)
        )
    }
}

#[derive(Default)]
pub(crate) struct Lockouts {
    users: HashMap<String, Entry>,
}

impl Lockouts {
    /// Refuse `user` from `source` while it is locked, else count this
    /// attempt (exempt and known sources are not counted) and lock it if
    /// the attempt reaches the threshold.
    pub(crate) fn attempt(
        &mut self,
        user: &str,
        source: &str,
        exempt: bool,
        now: Instant,
        l: &Limits,
    ) -> Result<(), Locked> {
        if exempt || l.lock_after == 0 {
            return Ok(());
        }
        if let Some(e) = self.users.get_mut(user) {
            if e.is_known(source, now, l) {
                return Ok(());
            }
            if let Some(left) = e.locked(now) {
                e.refused = e.refused.saturating_add(1);
                return Err(Locked {
                    secs: ceil_secs(left),
                    started: None,
                });
            }
            if e.last_failure
                .is_some_and(|t| now.duration_since(t) >= l.window)
            {
                e.failures = 0;
                e.sources.clear();
            }
        } else {
            self.make_room(now, l);
        }
        let e = self.users.entry(user.to_owned()).or_default();
        e.failures = e.failures.saturating_add(1);
        e.last_failure = Some(now);
        if !e.sources.iter().any(|s| s == source) && e.sources.len() < MAX_SOURCES {
            e.sources.push(source.to_owned());
        }
        let distinct = u32::try_from(e.sources.len()).unwrap_or(u32::MAX);
        if e.failures < l.lock_after || distinct < l.lock_sources.max(1) {
            return Ok(());
        }
        // The escalation forgets locks that ended long ago.
        if e.until
            .is_some_and(|u| now.saturating_duration_since(u) >= l.lock_memory)
        {
            e.blocks = 0;
        }
        let factor = 1u32.checked_shl(e.blocks.min(16)).unwrap_or(u32::MAX);
        let length = l.lock_base.saturating_mul(factor).min(l.lock_max);
        e.blocks = e.blocks.saturating_add(1);
        e.lock_failures = e.failures;
        e.lock_sources = distinct;
        e.refused = 0;
        e.until = Some(now.checked_add(length).unwrap_or(now));
        let started = LockStarted {
            user: user.to_owned(),
            secs: length.as_secs(),
            failures: e.failures,
            sources: std::mem::take(&mut e.sources),
            blocks: e.blocks,
        };
        e.failures = 0;
        Err(Locked {
            secs: length.as_secs(),
            started: Some(started),
        })
    }

    /// `user` logged in from `source`: this attempt is forgiven and the
    /// source becomes known. The lock (if any) stays: the attack may go on.
    pub(crate) fn succeeded(&mut self, user: &str, source: &str, exempt: bool, now: Instant) {
        if exempt {
            return;
        }
        if !self.users.contains_key(user) && self.users.len() >= MAX_USERS {
            return;
        }
        let e = self.users.entry(user.to_owned()).or_default();
        e.failures = e.failures.saturating_sub(1);
        e.sources.retain(|s| s != source);
        e.known.retain(|(s, _)| s != source);
        if e.known.len() >= MAX_KNOWN && !e.known.is_empty() {
            e.known.remove(0);
        }
        e.known.push((source.to_owned(), now));
    }

    /// Keep the table under [`MAX_USERS`]: forget idle names; still full,
    /// the unlocked name whose last failure is oldest.
    fn make_room(&mut self, now: Instant, l: &Limits) {
        if self.users.len() < MAX_USERS {
            return;
        }
        self.users.retain(|_, e| !e.idle(now, l));
        if self.users.len() < MAX_USERS {
            return;
        }
        let victim = self
            .users
            .iter()
            .filter(|(_, e)| e.locked(now).is_none())
            .min_by_key(|(_, e)| e.last_failure)
            .or_else(|| self.users.iter().min_by_key(|(_, e)| e.until))
            .map(|(k, _)| k.clone());
        if let Some(k) = victim {
            self.users.remove(&k);
        }
    }

    pub(crate) fn rows(&self, now: Instant, l: &Limits) -> Vec<UserLockout> {
        self.users
            .iter()
            .filter_map(|(user, e)| {
                let failing = e
                    .last_failure
                    .is_some_and(|t| now.duration_since(t) < l.window);
                let locked = e.locked(now);
                if !failing && locked.is_none() {
                    return None;
                }
                // Locked: what started the lock; else the current window.
                let (failures, sources) = match (locked, failing) {
                    (Some(_), _) => (e.lock_failures, e.lock_sources),
                    (None, true) => (
                        e.failures,
                        u32::try_from(e.sources.len()).unwrap_or(u32::MAX),
                    ),
                    (None, false) => (0, 0),
                };
                Some(UserLockout {
                    user: user.clone(),
                    failures,
                    sources,
                    refused: if locked.is_some() { e.refused } else { 0 },
                    locked_secs: locked.map_or(0, ceil_secs),
                    blocks: e.blocks,
                    known_sources: u32::try_from(
                        e.known
                            .iter()
                            .filter(|(_, t)| now.duration_since(*t) < l.lock_memory)
                            .count(),
                    )
                    .unwrap_or(u32::MAX),
                })
            })
            .collect()
    }

    /// Lift the lock and forget the failures (known sources stay).
    pub(crate) fn clear(&mut self, user: Option<&str>) -> usize {
        let mut n = 0;
        for (name, e) in &mut self.users {
            if user.is_some_and(|u| u != name) {
                continue;
            }
            if e.failures > 0 || e.until.is_some() || e.blocks > 0 {
                n += 1;
            }
            e.failures = 0;
            e.sources.clear();
            e.last_failure = None;
            e.until = None;
            e.blocks = 0;
            e.refused = 0;
        }
        n
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.users.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    fn limits() -> Limits {
        Limits {
            lock_after: 4,
            lock_sources: 2,
            lock_base: Duration::from_secs(60),
            lock_max: Duration::from_secs(300),
            ..Limits::default()
        }
    }

    #[test]
    fn locks_after_k_failures_from_m_sources_and_grows() {
        let l = limits();
        let mut t = Lockouts::default();
        let now = Instant::now();
        // One source alone never locks the name (the per-source block
        // of auth.rs is for that).
        for _ in 0..10 {
            t.attempt("admin", "198.51.100.1", false, now, &l).unwrap();
        }
        t.clear(None);
        for i in 0..3 {
            t.attempt("admin", &format!("198.51.100.{}", i % 2), false, now, &l)
                .unwrap();
        }
        let e = t
            .attempt("admin", "198.51.100.1", false, now, &l)
            .unwrap_err();
        let started = e.started.clone().unwrap();
        assert_eq!((e.secs, started.failures, started.blocks), (60, 4, 1));
        assert_eq!(started.sources.len(), 2);
        // Locked: even a new source, with no counting.
        let e = t
            .attempt("admin", "203.0.113.7", false, now, &l)
            .unwrap_err();
        assert!(e.started.is_none());
        assert!(e.message().contains("60 more seconds"), "{}", e.message());
        // Other names are not touched.
        t.attempt("root", "203.0.113.7", false, now, &l).unwrap();
        // After the lock: 4 more failures from 2 sources lock it for twice
        // as long, then capped.
        let mut at = now + Duration::from_secs(61);
        for want in [120, 240, 300, 300] {
            for i in 0..3 {
                t.attempt("admin", &format!("192.0.2.{}", i % 2), false, at, &l)
                    .unwrap();
            }
            let e = t.attempt("admin", "192.0.2.1", false, at, &l).unwrap_err();
            assert_eq!(e.secs, want);
            at += Duration::from_secs(want + 1);
        }
    }

    #[test]
    fn loopback_and_known_sources_are_exempt() {
        let l = limits();
        let mut t = Lockouts::default();
        let now = Instant::now();
        assert!(exempt(None));
        assert!(exempt(Some("127.0.0.5".parse().unwrap())));
        assert!(exempt(Some("::1".parse().unwrap())));
        assert!(exempt(Some("::ffff:127.0.0.1".parse().unwrap())));
        assert!(!exempt(Some("10.0.0.1".parse().unwrap())));
        // The operator logged in from 10.0.0.9 before the attack.
        t.succeeded("admin", "10.0.0.9", false, now);
        for i in 0..3 {
            t.attempt("admin", &format!("198.51.100.{i}"), false, now, &l)
                .unwrap();
        }
        assert!(t.attempt("admin", "198.51.100.3", false, now, &l).is_err());
        // Locked for the attackers, open for loopback and the known source.
        assert!(t.attempt("admin", "198.51.100.9", false, now, &l).is_err());
        t.attempt("admin", "127.0.0.1", true, now, &l).unwrap();
        t.attempt("admin", "10.0.0.9", false, now, &l).unwrap();
        // A known source's typos never count.
        t.clear(None);
        for _ in 0..20 {
            t.attempt("admin", "10.0.0.9", false, now, &l).unwrap();
        }
        assert_eq!(t.rows(now, &l).len(), 0);
        // Known sources are forgotten after lock_memory.
        let later = now + l.lock_memory;
        for i in 0..3 {
            t.attempt("admin", &format!("198.51.100.{i}"), false, later, &l)
                .unwrap();
        }
        assert!(t.attempt("admin", "10.0.0.9", false, later, &l).is_err());
    }

    #[test]
    fn failures_outside_the_window_are_forgotten() {
        let l = limits();
        let mut t = Lockouts::default();
        let now = Instant::now();
        for i in 0..3 {
            t.attempt("admin", &format!("198.51.100.{i}"), false, now, &l)
                .unwrap();
        }
        let later = now + l.window;
        t.attempt("admin", "198.51.100.9", false, later, &l)
            .unwrap();
        let rows = t.rows(later, &l);
        assert_eq!((rows[0].failures, rows[0].sources), (1, 1));
    }

    #[test]
    fn rows_and_clear() {
        let l = limits();
        let mut t = Lockouts::default();
        let now = Instant::now();
        for i in 0..4 {
            let _ = t.attempt("admin", &format!("198.51.100.{i}"), false, now, &l);
        }
        t.attempt("root", "198.51.100.1", false, now, &l).unwrap();
        let mut rows = t.rows(now, &l);
        rows.sort_by(|a, b| a.user.cmp(&b.user));
        assert_eq!(rows[0].user, "admin");
        assert_eq!((rows[0].locked_secs, rows[0].blocks), (60, 1));
        // While locked: what started it, and the refusals since.
        assert_eq!(
            (rows[0].failures, rows[0].sources, rows[0].refused),
            (4, 4, 0)
        );
        let _ = t.attempt("admin", "203.0.113.1", false, now, &l);
        let rows = t.rows(now, &l);
        let admin = rows.iter().find(|r| r.user == "admin").unwrap();
        assert_eq!(admin.refused, 1);
        let mut rows = t.rows(now, &l);
        rows.sort_by(|a, b| a.user.cmp(&b.user));
        assert_eq!((rows[1].user.as_str(), rows[1].failures), ("root", 1));
        assert_eq!(t.clear(Some("admin")), 1);
        t.attempt("admin", "198.51.100.1", false, now, &l).unwrap();
        assert_eq!(t.clear(None), 2);
        assert!(t.rows(now, &l).is_empty());
    }

    #[test]
    fn the_table_stays_bounded_and_keeps_locked_names() {
        let l = limits();
        let mut t = Lockouts::default();
        let now = Instant::now();
        for i in 0..4 {
            let _ = t.attempt("admin", &format!("198.51.100.{i}"), false, now, &l);
        }
        for i in 0..(MAX_USERS * 3) {
            let _ = t.attempt(&format!("u{i}"), "198.51.100.1", false, now, &l);
        }
        assert!(t.len() <= MAX_USERS);
        assert!(t.attempt("admin", "203.0.113.1", false, now, &l).is_err());
        // Sources per name are capped too.
        for i in 0..200 {
            let _ = t.attempt("root", &format!("10.1.{i}.1"), false, now, &l);
        }
        assert!(
            t.users
                .get("root")
                .is_none_or(|e| e.sources.len() <= MAX_SOURCES)
        );
    }
}
