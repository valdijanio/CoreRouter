//! CGNAT capacity (G2.7b): how many ports the subscribers really use, and
//! what `ports_per_subscriber` that suggests.
//!
//! The usage scan (`cgnat_blocks`, every [`SCAN_SECS`]) hands each
//! subscriber's busiest protocol here; each subscriber keeps its daily
//! peak for [`DAYS`] days in a small ring ([`Peaks`], 20 bytes), so 64
//! thousand subscribers stay in about 2 MB (**estimado**; the bench
//! `cgnat_capacity` measures it). The exhaustion queues' refusals (G2.7)
//! are counted per pool and hour for the last 24 h.
//!
//! The store survives a restart: it is written to the journal
//! `journal-cgnat-capacity.log` every [`SAVE_SECS`] and read back at boot.
//!
//! [`SCAN_SECS`]: crate::cgnat_blocks::SCAN_SECS

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::net::Ipv4Addr;

use crate::Session;

/// Days of peaks kept per subscriber.
pub const DAYS: usize = 7;
/// The journal's name (`journal-cgnat-capacity.log`).
pub const JOURNAL: &str = "cgnat-capacity";
/// Subscribers whose peaks are kept at most (a spoofed storm cannot grow
/// the memory beyond it): 4 × 65 536.
pub const MAX_SUBSCRIBERS: usize = 262_144;
/// How often the store is written: a restart loses at most this much of
/// the 24 h counts (64 thousand subscribers are ~2.5 MB of text,
/// **estimado**).
pub const SAVE_SECS: u64 = 600;
const MAX_LINE: usize = 256;
/// Pools whose hourly rings a journal may bring back (the config has at
/// most a few dozen; a hostile journal cannot grow the map).
const MAX_POOL_RINGS: usize = 1024;

/// One subscriber's daily peaks: `v[d % DAYS]` is day `d`'s, for the
/// [`DAYS`] days up to `last` (day numbers since the Unix epoch).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Peaks {
    last: u32,
    v: [u16; DAYS],
}

impl Peaks {
    /// Fold in `used` ports seen on `day`.
    pub fn record(&mut self, day: u32, used: u16) {
        if day > self.last {
            // Days without a reading since `last` had no peak.
            let gap = (day - self.last).min(DAYS as u32);
            for k in 1..=gap {
                let d = self.last.wrapping_add(k) as usize % DAYS;
                if let Some(slot) = self.v.get_mut(d) {
                    *slot = 0;
                }
            }
            self.last = day;
        } else if self.last.saturating_sub(day) >= DAYS as u32 {
            return;
        }
        if let Some(slot) = self.v.get_mut(day as usize % DAYS) {
            *slot = (*slot).max(used);
        }
    }

    /// The highest peak of the [`DAYS`] days up to `today`.
    pub fn peak(&self, today: u32) -> u16 {
        (0..DAYS as u32)
            .filter_map(|k| self.last.checked_sub(k))
            .filter(|d| today.saturating_sub(*d) < DAYS as u32 && *d <= today)
            .filter_map(|d| self.v.get(d as usize % DAYS).copied())
            .max()
            .unwrap_or(0)
    }
}

/// Refusals of one pool in one hour.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Hour {
    hour: u64,
    refused: u64,
    icmp: u64,
}

#[derive(Debug, Default)]
pub struct CapacityStore {
    loaded: bool,
    peaks: HashMap<Ipv4Addr, Peaks>,
    /// Pool name → the last 24 hours, `hour % 24` each.
    hours: BTreeMap<String, [Hour; 24]>,
    /// Subscribers refused, with the time of the last refusal.
    refused: HashMap<Ipv4Addr, u64>,
    /// G2.7d: refusals because the pool had no free block (blocks mode),
    /// per pool and hour, apart from a subscriber out of its own ports.
    full_hours: BTreeMap<String, [Hour; 24]>,
    /// G2.7d: subscribers refused for lack of a free block, with the time.
    no_block: HashMap<Ipv4Addr, u64>,
    saved: Option<u64>,
    pub untracked: u64,
}

/// The refusals and ICMP of the 24 h before `now` in an hourly ring.
fn day_of_ring(ring: Option<&[Hour; 24]>, now: u64) -> (u64, u64) {
    let hour = now / 3600;
    ring.map_or((0, 0), |ring| {
        ring.iter()
            .filter(|h| h.hour + 24 > hour && h.hour <= hour)
            .fold((0, 0), |(r, i), h| (r + h.refused, i + h.icmp))
    })
}

pub fn day_of(t: u64) -> u32 {
    u32::try_from(t / 86_400).unwrap_or(u32::MAX)
}

impl CapacityStore {
    /// Record the busiest-protocol ports of each subscriber at `now`.
    pub fn record<'a>(&mut self, now: u64, used: impl IntoIterator<Item = (&'a Ipv4Addr, u64)>) {
        let day = day_of(now);
        for (sub, n) in used {
            let n = u16::try_from(n).unwrap_or(u16::MAX);
            if let Some(p) = self.peaks.get_mut(sub) {
                p.record(day, n);
            } else if self.peaks.len() < MAX_SUBSCRIBERS {
                let mut p = Peaks { last: day, ..Peaks::default() };
                p.record(day, n);
                self.peaks.insert(*sub, p);
            } else {
                self.untracked = self.untracked.saturating_add(1);
            }
        }
    }

    /// Refusals of `subscriber` in `pool` at `now`.
    pub fn refused(&mut self, now: u64, pool: &str, subscriber: Ipv4Addr, refused: u64, icmp: u64) {
        let hour = now / 3600;
        let ring = self.hours.entry(pool.to_owned()).or_default();
        if let Some(h) = ring.get_mut((hour % 24) as usize) {
            if h.hour != hour {
                *h = Hour { hour, ..Hour::default() };
            }
            h.refused = h.refused.saturating_add(refused);
            h.icmp = h.icmp.saturating_add(icmp);
        }
        if self.refused.len() < MAX_SUBSCRIBERS || self.refused.contains_key(&subscriber) {
            self.refused.insert(subscriber, now);
        }
    }

    /// G2.7d: refusals of `subscriber` at `now` because blocks-mode `pool`
    /// had no free block (it never had ports of its own to run out of).
    pub fn pool_full(&mut self, now: u64, pool: &str, subscriber: Ipv4Addr, refused: u64, icmp: u64) {
        let hour = now / 3600;
        let ring = self.full_hours.entry(pool.to_owned()).or_default();
        if let Some(h) = ring.get_mut((hour % 24) as usize) {
            if h.hour != hour {
                *h = Hour { hour, ..Hour::default() };
            }
            h.refused = h.refused.saturating_add(refused);
            h.icmp = h.icmp.saturating_add(icmp);
        }
        if self.no_block.len() < MAX_SUBSCRIBERS || self.no_block.contains_key(&subscriber) {
            self.no_block.insert(subscriber, now);
        }
    }

    /// G2.7d: whether `subscriber` found no free block in the 24 h before
    /// `now`.
    pub fn no_block_since(&self, subscriber: Ipv4Addr, since: u64) -> bool {
        self.no_block.get(&subscriber).is_some_and(|t| *t >= since)
    }

    /// G2.7d: refusals and ICMP of `pool` for lack of a free block, 24 h.
    pub fn pool_full_day(&self, pool: &str, now: u64) -> (u64, u64) {
        day_of_ring(self.full_hours.get(pool), now)
    }

    /// The 7-day peak of `subscriber`, if it was ever seen.
    pub fn peak(&self, subscriber: Ipv4Addr, now: u64) -> Option<u16> {
        self.peaks.get(&subscriber).map(|p| p.peak(day_of(now)))
    }

    /// Whether `subscriber` was refused in the 24 h before `now`.
    pub fn refused_since(&self, subscriber: Ipv4Addr, since: u64) -> bool {
        self.refused.get(&subscriber).is_some_and(|t| *t >= since)
    }

    /// Refusals and ICMP of `pool` in the 24 h before `now`.
    pub fn pool_day(&self, pool: &str, now: u64) -> (u64, u64) {
        day_of_ring(self.hours.get(pool), now)
    }

    pub fn subscribers(&self) -> usize {
        self.peaks.len()
    }

    /// Bytes the peaks take (keys and values, not the hash table's spare
    /// room).
    pub fn bytes(&self) -> usize {
        self.peaks.capacity() * (std::mem::size_of::<Ipv4Addr>() + std::mem::size_of::<Peaks>() + 1)
    }

    /// The journal text: `p <ip> <last> <v0> … <v6>`, `h <hour> <refused>
    /// <icmp> <pool>`, `r <ip> <time>`; G2.7d: `f <hour> <refused> <icmp>
    /// <pool>` and `n <ip> <time>` for the pool without a free block.
    fn text(&self, now: u64) -> String {
        let mut out = String::with_capacity(self.peaks.len() * 48);
        let today = day_of(now);
        for (ip, p) in &self.peaks {
            if today.saturating_sub(p.last) >= DAYS as u32 {
                continue;
            }
            let _ = write!(out, "p {ip} {}", p.last);
            for v in p.v {
                let _ = write!(out, " {v}");
            }
            out.push('\n');
        }
        for (pool, ring) in &self.hours {
            for h in ring.iter().filter(|h| h.hour + 24 > now / 3600) {
                let _ = writeln!(out, "h {} {} {} {pool}", h.hour, h.refused, h.icmp);
            }
        }
        for (ip, t) in self.refused.iter().filter(|(_, t)| **t + 86_400 > now) {
            let _ = writeln!(out, "r {ip} {t}");
        }
        for (pool, ring) in &self.full_hours {
            for h in ring.iter().filter(|h| h.hour + 24 > now / 3600) {
                let _ = writeln!(out, "f {} {} {} {pool}", h.hour, h.refused, h.icmp);
            }
        }
        for (ip, t) in self.no_block.iter().filter(|(_, t)| **t + 86_400 > now) {
            let _ = writeln!(out, "n {ip} {t}");
        }
        out
    }

    /// Read back a journal; how many lines were unreadable.
    fn replay(&mut self, text: &str) -> usize {
        let mut bad = 0;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            if line.len() > MAX_LINE || self.line(line).is_none() {
                bad += 1;
            }
        }
        bad
    }

    fn line(&mut self, line: &str) -> Option<()> {
        let mut w = line.split(' ');
        match w.next()? {
            "p" => {
                let ip: Ipv4Addr = w.next()?.parse().ok()?;
                let last: u32 = w.next()?.parse().ok()?;
                let mut v = [0u16; DAYS];
                for slot in &mut v {
                    *slot = w.next()?.parse().ok()?;
                }
                if self.peaks.len() < MAX_SUBSCRIBERS {
                    self.peaks.insert(ip, Peaks { last, v });
                }
            }
            kind @ ("h" | "f") => {
                let hour: u64 = w.next()?.parse().ok()?;
                let refused: u64 = w.next()?.parse().ok()?;
                let icmp: u64 = w.next()?.parse().ok()?;
                let pool: String = w.collect::<Vec<_>>().join(" ");
                if pool.is_empty() || pool.len() > 64 {
                    return None;
                }
                let rings = if kind == "h" { &mut self.hours } else { &mut self.full_hours };
                if rings.len() >= MAX_POOL_RINGS && !rings.contains_key(&pool) {
                    return None;
                }
                if let Some(h) = rings.entry(pool).or_default().get_mut((hour % 24) as usize) {
                    *h = Hour { hour, refused, icmp };
                }
            }
            kind @ ("r" | "n") => {
                let ip: Ipv4Addr = w.next()?.parse().ok()?;
                let t: u64 = w.next()?.parse().ok()?;
                let map = if kind == "r" { &mut self.refused } else { &mut self.no_block };
                if map.len() < MAX_SUBSCRIBERS {
                    map.insert(ip, t);
                }
            }
            _ => return None,
        }
        Some(())
    }
}

impl Session {
    /// The capacity store, read from its journal on first use.
    pub fn cgnat_capacity(&mut self) -> Option<&mut CapacityStore> {
        if !self.ext::<CapacityStore>().is_some_and(|c| c.loaded) {
            let text = self.storage_mut().load_journal(JOURNAL);
            if let Some(c) = self.ext_mut::<CapacityStore>() {
                c.loaded = true;
                match text {
                    Ok(Some(t)) => {
                        let bad = c.replay(&t);
                        if bad > 0 {
                            log::warn!("cgnat capacity: {bad} unreadable journal lines skipped");
                        }
                    }
                    Ok(None) => {}
                    Err(e) => log::warn!("cgnat capacity: journal not read: {e}"),
                }
            }
        }
        self.ext_mut::<CapacityStore>()
    }

    /// Write the store at most every [`SAVE_SECS`].
    pub(crate) fn cgnat_capacity_save(&mut self, now: u64) {
        let text = match self.cgnat_capacity() {
            Some(c) if c.saved.is_none_or(|t| now.saturating_sub(t) >= SAVE_SECS) => {
                c.saved = Some(now);
                c.text(now)
            }
            _ => return,
        };
        if let Err(e) = self.storage_mut().rewrite_journal(JOURNAL, &text) {
            log::warn!("cgnat capacity: journal not saved: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn peaks_keep_seven_days() {
        let mut p = Peaks::default();
        p.record(100, 300);
        p.record(100, 200);
        p.record(103, 50);
        assert_eq!(p.peak(103), 300);
        assert_eq!(p.peak(106), 300, "day 100 still in the window");
        assert_eq!(p.peak(107), 50, "day 100 left");
        p.record(120, 7);
        assert_eq!(p.peak(120), 7, "a long gap forgets everything");
        p.record(110, 999);
        assert_eq!(p.peak(120), 7, "too old to count");
    }

    #[test]
    fn the_store_round_trips_its_journal() {
        let t = 1_780_000_000;
        let mut s = CapacityStore::default();
        let a: Ipv4Addr = "100.64.0.1".parse().unwrap();
        s.record(t, [(&a, 640)]);
        s.refused(t, "c1", a, 4, 2);
        let text = s.text(t);
        let mut back = CapacityStore::default();
        assert_eq!(back.replay(&text), 0);
        assert_eq!(back.peak(a, t), Some(640));
        assert_eq!(back.pool_day("c1", t), (4, 2));
        assert!(back.refused_since(a, t - 10));
        assert_eq!(back.pool_day("c1", t + 25 * 3600), (0, 0), "a day later, gone");
    }

    /// G2.7d: a refusal for lack of a free block is counted apart from a
    /// subscriber out of its own ports, and survives the journal.
    #[test]
    fn a_full_pool_is_counted_apart_and_round_trips() {
        let t = 1_780_000_000;
        let mut s = CapacityStore::default();
        let a: Ipv4Addr = "100.64.7.236".parse().unwrap();
        s.pool_full(t, "teste", a, 3, 1);
        assert_eq!(s.pool_day("teste", t), (0, 0));
        assert!(!s.refused_since(a, t - 10));
        let mut back = CapacityStore::default();
        assert_eq!(back.replay(&s.text(t)), 0);
        assert_eq!(back.pool_full_day("teste", t), (3, 1));
        assert!(back.no_block_since(a, t - 10));
        assert_eq!(back.pool_full_day("teste", t + 25 * 3600), (0, 0));
    }

    proptest! {
        /// The 7-day peak is the max of the readings of the last 7 days.
        #[test]
        fn peak_is_the_max_of_the_window(
            readings in proptest::collection::vec((0u32..30, any::<u16>()), 0..60),
        ) {
            let mut sorted = readings.clone();
            sorted.sort_by_key(|r| r.0);
            let mut p = Peaks::default();
            for (d, v) in &sorted {
                p.record(*d, *v);
            }
            let today = sorted.last().map_or(0, |r| r.0);
            let want = sorted.iter().filter(|(d, _)| today - d < 7).map(|r| r.1).max().unwrap_or(0);
            prop_assert_eq!(p.peak(today), want);
        }

        #[test]
        fn hostile_journal_never_panics(text in "\\PC{0,400}") {
            let mut s = CapacityStore::default();
            let _ = s.replay(&text);
        }
    }
}
