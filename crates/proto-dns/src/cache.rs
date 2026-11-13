//! Answer cache by TTL, bounded by a byte budget (RouterOS `cache-size`,
//! in KiB), shared by the router's own lookups and the LAN forwarder. Any
//! record type, positive and negative (RFC 2308). Expired answers are kept
//! for `stale` more milliseconds, to be served when no server answers
//! (RFC 8767). The clock is the caller's (milliseconds of any monotonic
//! clock), so tests drive time and the crate stays wasm-safe.
//!
//! # What stays when it is full (G4.1x)
//!
//! W-TinyLFU (Einziger, Friedman, Manes, ACM ToS 2017; the policy of the
//! Caffeine cache), in bytes:
//!
//! - every lookup is counted in a [`frequency`] sketch (fixed memory, ~1 %
//!   of the budget);
//! - a new answer enters a small **window** (1 % of the budget, LRU), so a
//!   name asked a few times in a row is answered from the cache at once;
//! - leaving the window, it is a **candidate** for the main area: while the
//!   cache is over budget, it pushes out the least recently used entry of
//!   **probation** (then of **protected**) only if it was asked more often
//!   lately; otherwise it is the one that goes (counted as `rejected`);
//! - an entry hit in probation moves to **protected** (80 % of the main
//!   area, LRU; its overflow goes back to probation).
//!
//! A flood of unique names (the "water torture" of `docs/dns-stress.md`)
//! asks each name once: none beats an entry that was asked twice, so the
//! names the clients use stay. Before (G4.1r) the cache evicted by expiry,
//! which with equal TTLs is the order of arrival: 20 000 unique names a
//! second turned a 64 MiB cache over in ~5 s and the hot names went with
//! it. Answers past their stale window go first, before any of this (the
//! expiry index).
//!
//! Cost per lookup: one keyed hash (it finds the entry and its counters),
//! one hash-map probe, four counters in one cache line, and a few links of
//! the lists: O(1), whatever the size. A miss that stores its answer also
//! updates the expiry index, O(log n).

mod frequency;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{BuildHasher, BuildHasherDefault, RandomState};
use std::net::IpAddr;

use corerouter_model::dns::{CacheKind, CacheRow};
use hickory_proto::rr::RecordType;

use crate::message::Answer;
use crate::sketch::PassHasher;
use frequency::Frequency;

/// Negative answers live at most an hour, whatever the SOA says. RFC 2308
/// §5 suggests 1–3 hours as the cap; Unbound (`cache-max-negative-ttl`)
/// and VyOS (`negative-ttl`) both use 3600 s.
pub const MAX_NEGATIVE_TTL: u32 = 3600;
/// RFC 8767 §4: a stale answer goes out with TTL 30 s, so clients come
/// back soon for a fresh one.
pub const STALE_TTL: u32 = 30;
/// Book-keeping per entry on top of the records (slot, key, vectors, the
/// entry itself). With [`RECORD_OVERHEAD`], sized so `used_bytes` follows
/// the process's real memory: one A answer measured 690 bytes of RSS per
/// entry (200 000 entries, release build, 2026-10-22), the estimate gives
/// ~670.
const ENTRY_OVERHEAD: usize = 256;
/// Per record: hickory's `Record` (owner `Name` on the heap, header,
/// rdata), on top of its wire size.
const RECORD_OVERHEAD: usize = 256;
/// The hash index's and the expiry index's nodes per entry (estimated).
const INDEX_OVERHEAD: usize = 64;
/// An answer's usual size in the budget, to size the frequency sketch (one
/// A record: ~690 bytes measured, above).
const TYPICAL_ENTRY: usize = 700;
/// The window's share of the budget (Caffeine's starting point, 1 %).
const WINDOW_PERCENT: usize = 1;
/// The protected segment's share of the main area (80 %, as in Caffeine
/// and in SLRU).
const PROTECTED_PERCENT: usize = 80;
/// No slot.
const NIL: u32 = u32::MAX;

#[derive(Debug, Clone)]
struct Entry {
    answer: Answer,
    expires_ms: u64,
    server: Option<IpAddr>,
    hits: u64,
    size: usize,
}

/// Where an entry is (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Segment {
    Window,
    Probation,
    Protected,
}

/// An entry and its links in its segment's list.
#[derive(Debug)]
struct Slot {
    name: String,
    rtype: u16,
    hash: u64,
    entry: Entry,
    segment: Segment,
    /// Towards the most recently used (the head)…
    prev: u32,
    /// …and towards the least (the tail).
    next: u32,
}

/// One segment: a list through the slots, most recently used first.
#[derive(Debug, Clone, Copy)]
struct List {
    head: u32,
    tail: u32,
    bytes: usize,
}

impl Default for List {
    fn default() -> Self {
        Self {
            head: NIL,
            tail: NIL,
            bytes: 0,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Lists {
    window: List,
    probation: List,
    protected: List,
}

impl Lists {
    fn get_mut(&mut self, s: Segment) -> &mut List {
        match s {
            Segment::Window => &mut self.window,
            Segment::Probation => &mut self.probation,
            Segment::Protected => &mut self.protected,
        }
    }
}

type Slots = Vec<Option<Slot>>;

fn slot(slots: &Slots, i: u32) -> Option<&Slot> {
    slots.get(usize::try_from(i).ok()?)?.as_ref()
}

fn slot_mut(slots: &mut Slots, i: u32) -> Option<&mut Slot> {
    slots.get_mut(usize::try_from(i).ok()?)?.as_mut()
}

/// Takes slot `i` out of list `l` (it must be in it).
fn unlink(slots: &mut Slots, l: &mut List, i: u32) {
    let Some(s) = slot(slots, i) else { return };
    let (prev, next, size) = (s.prev, s.next, s.entry.size);
    match slot_mut(slots, prev) {
        Some(p) => p.next = next,
        None => l.head = next,
    }
    match slot_mut(slots, next) {
        Some(n) => n.prev = prev,
        None => l.tail = prev,
    }
    l.bytes = l.bytes.saturating_sub(size);
}

/// Puts slot `i` at the head (most recently used) of `l`.
fn push_front(slots: &mut Slots, l: &mut List, i: u32) {
    let old = l.head;
    let Some(s) = slot_mut(slots, i) else { return };
    s.prev = NIL;
    s.next = old;
    let size = s.entry.size;
    match slot_mut(slots, old) {
        Some(o) => o.prev = i,
        None => l.tail = i,
    }
    l.head = i;
    l.bytes = l.bytes.saturating_add(size);
}

/// A cached answer with its TTLs set to what is left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub answer: Answer,
    pub ttl: u32,
    pub server: Option<IpAddr>,
    pub stale: bool,
}

#[derive(Debug, Default)]
pub struct Cache {
    /// The entries; a freed slot is reused (`free`).
    slots: Slots,
    free: Vec<u32>,
    /// Keyed hash of (name, type) → slot. Two keys with the same 64-bit
    /// hash (2⁻⁶⁴) cannot both stay: the newer replaces the older, and a
    /// lookup checks the name, so the only effect is a miss.
    index: HashMap<u64, u32, BuildHasherDefault<PassHasher>>,
    /// Random per cache: clients cannot aim names at a slot of the index
    /// or at the sketch's counters of the hot names.
    hasher: RandomState,
    lists: Lists,
    sketch: Frequency,
    /// The same entries by expiry: the ones past their stale window are
    /// the first to go, in O(log n) (never a scan of the cache: it runs
    /// under the resolver's lock that every lookup also takes).
    by_expiry: BTreeSet<(u64, u32)>,
    used: usize,
    budget: usize,
    stale_ms: u64,
    /// G4.1h: entries by record type (cleared when the cache is found
    /// empty: a flush empties the index only).
    by_type: BTreeMap<u16, usize>,
    /// Entries pushed out to stay under the budget while still usable,
    /// those dropped once past their stale window, and new answers not
    /// kept because the entry they would push out is asked more (G4.1x).
    evicted: u64,
    expired: u64,
    rejected: u64,
}

/// What the cache holds and has thrown away (G4.1h).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub entries: usize,
    pub used_bytes: usize,
    pub budget_bytes: usize,
    /// Pushed out by newer answers while still fresh or stale-servable
    /// (the budget is too small for what the clients ask).
    pub evicted: u64,
    /// Dropped after their TTL and stale window.
    pub expired: u64,
    /// New answers not kept: the cache was full of names asked more often
    /// (G4.1x; a flood of unique names shows here).
    pub rejected: u64,
    /// Entries per record type, most first.
    pub by_type: Vec<(u16, usize)>,
}

/// What [`Cache::take`] took out; dropping it frees the entries.
#[must_use]
pub struct Flushed {
    _slots: Slots,
    _index: HashMap<u64, u32, BuildHasherDefault<PassHasher>>,
    _by_expiry: BTreeSet<(u64, u32)>,
}

impl Cache {
    pub fn new(budget_bytes: usize) -> Self {
        Self {
            budget: budget_bytes,
            sketch: Frequency::new(budget_bytes / TYPICAL_ENTRY),
            ..Self::default()
        }
    }

    /// A new budget (config change); evicts down to it. The sketch is
    /// sized again when the budget moves to another power of two.
    pub fn set_budget(&mut self, budget_bytes: usize) {
        self.budget = budget_bytes;
        let sketch = Frequency::new(budget_bytes / TYPICAL_ENTRY);
        if sketch.words() != self.sketch.words() {
            self.sketch = sketch;
        }
        self.shrink(None);
    }

    /// The window's bytes and the protected segment's.
    fn caps(&self) -> (usize, usize) {
        let window = self.budget / 100 * WINDOW_PERCENT;
        let main = self.budget.saturating_sub(window);
        (window, main / 100 * PROTECTED_PERCENT)
    }

    /// Entries, bytes and what was thrown away (G4.1h); O(types).
    pub fn stats(&self) -> CacheStats {
        let mut by_type: Vec<(u16, usize)> = if self.index.is_empty() {
            Vec::new()
        } else {
            self.by_type
                .iter()
                .filter(|(_, n)| **n > 0)
                .map(|(t, n)| (*t, *n))
                .collect()
        };
        by_type.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        CacheStats {
            entries: self.index.len(),
            used_bytes: self.used,
            budget_bytes: self.budget,
            evicted: self.evicted,
            expired: self.expired,
            rejected: self.rejected,
            by_type,
        }
    }

    /// How long past its TTL an answer is kept for serve-stale (0: not).
    pub fn set_stale(&mut self, stale_secs: u32) {
        self.stale_ms = u64::from(stale_secs) * 1000;
    }

    pub fn used_bytes(&self) -> usize {
        self.used
    }

    /// The frequency sketch's memory (fixed by the budget, outside it).
    pub fn sketch_bytes(&self) -> usize {
        self.sketch.bytes()
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn flush(&mut self) {
        drop(self.take());
    }

    /// Empties the cache and hands back what it held, for the caller to
    /// drop outside its lock: freeing a million entries took ~0,45 s, and
    /// every lookup waited for it (G4.1r, `docs/dns-stress.md`). The sketch
    /// stays: how often names are asked does not change with a flush.
    pub fn take(&mut self) -> Flushed {
        self.used = 0;
        self.lists = Lists::default();
        self.free = Vec::new();
        Flushed {
            _slots: std::mem::take(&mut self.slots),
            _index: std::mem::take(&mut self.index),
            _by_expiry: std::mem::take(&mut self.by_expiry),
        }
    }

    fn hash(&self, name: &str, rtype: u16) -> u64 {
        self.hasher.hash_one((name, rtype))
    }

    /// The slot holding `name`/`rtype`.
    fn find(&self, hash: u64, name: &str, rtype: u16) -> Option<u32> {
        let i = *self.index.get(&hash)?;
        let s = slot(&self.slots, i)?;
        (s.rtype == rtype && s.name == name).then_some(i)
    }

    /// The fresh answer for `name`/`rtype`, counted as a hit. An expired
    /// one stays while it may still be served stale. Every call counts in
    /// the sketch, found or not: it is how often the name is asked.
    pub fn get(&mut self, name: &str, rtype: RecordType, now_ms: u64) -> Option<Hit> {
        let t = u16::from(rtype);
        let h = self.hash(name, t);
        self.sketch.add(h);
        let i = self.find(h, name, t)?;
        let expires_ms = slot(&self.slots, i)?.entry.expires_ms;
        if expires_ms <= now_ms {
            if expires_ms.saturating_add(self.stale_ms) <= now_ms {
                self.remove(i);
                self.expired += 1;
            }
            return None;
        }
        let e = &mut slot_mut(&mut self.slots, i)?.entry;
        e.hits = e.hits.saturating_add(1);
        let left = secs_left(e.expires_ms, now_ms);
        let hit = Hit {
            answer: e.answer.with_ttl(left),
            ttl: left,
            server: e.server,
            stale: false,
        };
        self.touch(i);
        Some(hit)
    }

    /// RFC 8767 §4: an expired answer, while inside the serve-stale window,
    /// with TTL [`STALE_TTL`]. Only when no server answered.
    pub fn get_stale(&mut self, name: &str, rtype: RecordType, now_ms: u64) -> Option<Hit> {
        let t = u16::from(rtype);
        let i = self.find(self.hash(name, t), name, t)?;
        let stale_ms = self.stale_ms;
        let e = &mut slot_mut(&mut self.slots, i)?.entry;
        if e.expires_ms > now_ms || e.expires_ms.saturating_add(stale_ms) <= now_ms {
            return None;
        }
        e.hits = e.hits.saturating_add(1);
        Some(Hit {
            answer: e.answer.with_ttl(STALE_TTL),
            ttl: STALE_TTL,
            server: e.server,
            stale: true,
        })
    }

    /// A hit: to the head of its list; from probation to protected (whose
    /// overflow goes back to probation).
    fn touch(&mut self, i: u32) {
        let Some(seg) = slot(&self.slots, i).map(|s| s.segment) else {
            return;
        };
        unlink(&mut self.slots, self.lists.get_mut(seg), i);
        let seg = match seg {
            Segment::Probation => Segment::Protected,
            s => s,
        };
        if let Some(s) = slot_mut(&mut self.slots, i) {
            s.segment = seg;
        }
        push_front(&mut self.slots, self.lists.get_mut(seg), i);
        if seg != Segment::Protected {
            return;
        }
        let (_, protected_cap) = self.caps();
        while self.lists.protected.bytes > protected_cap {
            let t = self.lists.protected.tail;
            if t == NIL || t == i {
                break;
            }
            self.demote(t);
        }
    }

    /// Protected → head of probation.
    fn demote(&mut self, i: u32) {
        unlink(&mut self.slots, &mut self.lists.protected, i);
        if let Some(s) = slot_mut(&mut self.slots, i) {
            s.segment = Segment::Probation;
        }
        push_front(&mut self.slots, &mut self.lists.probation, i);
    }

    /// Keeps `answer` for its TTL capped at `max_ttl` (and negatives at
    /// [`MAX_NEGATIVE_TTL`]). A TTL of zero is not cached (RFC 1035 §3.2.1:
    /// "zero values are interpreted to mean that the RR can only be used
    /// for the transaction in progress"), nor a negative answer without SOA
    /// (RFC 2308 §5). `wire` is the reply's size, to charge the budget. A
    /// full cache may refuse it (module docs).
    #[allow(clippy::too_many_arguments)]
    pub fn put(
        &mut self,
        name: &str,
        rtype: RecordType,
        answer: &Answer,
        server: Option<IpAddr>,
        now_ms: u64,
        max_ttl: u32,
        wire: usize,
    ) {
        let Some(ttl) = answer.ttl else { return };
        let ttl = match answer.kind(rtype) {
            CacheKind::Records => ttl,
            CacheKind::NxDomain | CacheKind::NoData => ttl.min(MAX_NEGATIVE_TTL),
        }
        .min(max_ttl);
        if ttl == 0 {
            return;
        }
        let records = answer.records.len() + answer.authority.len();
        let size = ENTRY_OVERHEAD
            + INDEX_OVERHEAD
            + 2 * name.len()
            + records.saturating_mul(RECORD_OVERHEAD)
            + wire;
        if size > self.budget {
            return;
        }
        let t = u16::from(rtype);
        let h = self.hash(name, t);
        let expires_ms = now_ms.saturating_add(u64::from(ttl) * 1000);
        let entry = Entry {
            answer: answer.clone(),
            expires_ms,
            server,
            hits: 0,
            size,
        };
        if let Some(i) = self.find(h, name, t) {
            // A newer answer for an entry kept (it expired, or another
            // lookup raced this one): it keeps its place, refreshed.
            self.replace(i, entry);
            self.touch(i);
            self.shrink(Some(now_ms));
            return;
        }
        if let Some(old) = self.index.get(&h).copied() {
            // Another key with the same 64-bit hash: the newer stays.
            self.remove(old);
        }
        let s = Slot {
            name: name.to_owned(),
            rtype: t,
            hash: h,
            entry,
            segment: Segment::Window,
            prev: NIL,
            next: NIL,
        };
        let i = match self.free.pop() {
            Some(i) => {
                if let Some(free) = self.slots.get_mut(usize::try_from(i).unwrap_or(usize::MAX)) {
                    *free = Some(s);
                }
                i
            }
            None => {
                let Ok(i) = u32::try_from(self.slots.len()) else {
                    return;
                };
                if i == NIL {
                    return;
                }
                self.slots.push(Some(s));
                i
            }
        };
        if self.index.is_empty() {
            // Flushed since: the counts by type start again.
            self.by_type.clear();
        }
        *self.by_type.entry(t).or_default() += 1;
        self.index.insert(h, i);
        self.by_expiry.insert((expires_ms, i));
        self.used = self.used.saturating_add(size);
        push_front(&mut self.slots, &mut self.lists.window, i);
        self.shrink(Some(now_ms));
    }

    /// The entry of slot `i` replaced in place (size and expiry follow).
    fn replace(&mut self, i: u32, entry: Entry) {
        let Some(s) = slot_mut(&mut self.slots, i) else {
            return;
        };
        let (old_expiry, old_size, seg) = (s.entry.expires_ms, s.entry.size, s.segment);
        let (new_expiry, new_size) = (entry.expires_ms, entry.size);
        s.entry = entry;
        self.by_expiry.remove(&(old_expiry, i));
        self.by_expiry.insert((new_expiry, i));
        self.used = self.used.saturating_sub(old_size).saturating_add(new_size);
        let l = self.lists.get_mut(seg);
        l.bytes = l.bytes.saturating_sub(old_size).saturating_add(new_size);
    }

    fn remove(&mut self, i: u32) {
        let Some(seg) = slot(&self.slots, i).map(|s| s.segment) else {
            return;
        };
        unlink(&mut self.slots, self.lists.get_mut(seg), i);
        let Some(old) = self
            .slots
            .get_mut(usize::try_from(i).unwrap_or(usize::MAX))
            .and_then(Option::take)
        else {
            return;
        };
        if self.index.get(&old.hash) == Some(&i) {
            self.index.remove(&old.hash);
        }
        self.by_expiry.remove(&(old.entry.expires_ms, i));
        self.used = self.used.saturating_sub(old.entry.size);
        if let Some(n) = self.by_type.get_mut(&old.rtype) {
            *n = n.saturating_sub(1);
        }
        self.free.push(i);
    }

    fn is_dead(&self, i: u32, now_ms: Option<u64>) -> bool {
        let stale_ms = self.stale_ms;
        now_ms.is_some_and(|n| {
            slot(&self.slots, i).is_some_and(|s| s.entry.expires_ms.saturating_add(stale_ms) <= n)
        })
    }

    /// Back under budget (module docs): answers past their stale window
    /// first, then the window's overflow offered to the main area, then
    /// (a smaller budget) the least recently used of probation, protected
    /// and window. O(1) per entry moved, O(log n) per entry dropped.
    fn shrink(&mut self, now_ms: Option<u64>) {
        if let Some(now) = now_ms {
            while self.used > self.budget {
                let Some(&(expires, i)) = self.by_expiry.first() else {
                    break;
                };
                if expires.saturating_add(self.stale_ms) > now {
                    break;
                }
                self.remove(i);
                self.expired += 1;
            }
        }
        let (window_cap, _) = self.caps();
        while self.lists.window.bytes > window_cap {
            let c = self.lists.window.tail;
            if c == NIL {
                break;
            }
            unlink(&mut self.slots, &mut self.lists.window, c);
            if let Some(s) = slot_mut(&mut self.slots, c) {
                s.segment = Segment::Probation;
            }
            push_front(&mut self.slots, &mut self.lists.probation, c);
            self.admit(c, now_ms);
        }
        while self.used > self.budget {
            let v = [
                self.lists.probation.tail,
                self.lists.protected.tail,
                self.lists.window.tail,
            ]
            .into_iter()
            .find(|t| *t != NIL);
            let Some(v) = v else {
                // Nothing linked but bytes counted: start over.
                drop(self.take());
                break;
            };
            self.drop_victim(v, now_ms);
        }
    }

    /// TinyLFU's admission of candidate `c` (just put at the head of
    /// probation): while over budget, it pushes out the least recently
    /// used of the main area only if asked more often; a tie keeps the
    /// one already there (a unique name never displaces a name asked
    /// twice).
    fn admit(&mut self, c: u32, now_ms: Option<u64>) {
        let Some(fc) = slot(&self.slots, c).map(|s| self.sketch.estimate(s.hash)) else {
            return;
        };
        while self.used > self.budget {
            let p = self.lists.probation.tail;
            let v = if p != NIL && p != c {
                p
            } else if self.lists.protected.tail != NIL {
                self.lists.protected.tail
            } else {
                // Only the candidate in the main area: the last loop of
                // `shrink` takes from the window.
                return;
            };
            let fv = slot(&self.slots, v).map_or(0, |s| self.sketch.estimate(s.hash));
            if fc > fv {
                self.drop_victim(v, now_ms);
            } else {
                self.remove(c);
                self.rejected += 1;
                return;
            }
        }
    }

    fn drop_victim(&mut self, v: u32, now_ms: Option<u64>) {
        if self.is_dead(v, now_ms) {
            self.expired += 1;
        } else {
            self.evicted += 1;
        }
        self.remove(v);
    }

    /// Entries by name (`ip.dns.cache.print`), stale ones included.
    pub fn rows(&self, now_ms: u64) -> Vec<CacheRow> {
        self.rows_matching(now_ms, None, None, usize::MAX)
    }

    /// At most `limit` rows whose name contains `name` and whose type is
    /// `qtype`, sorted by name. Which ones, when more match than `limit`,
    /// is not said (the order the slots happen to be in). In one go: the
    /// resolver lists in pieces instead ([`Cache::copy_matching`]).
    pub fn rows_matching(
        &self,
        now_ms: u64,
        name: Option<&str>,
        qtype: Option<&str>,
        limit: usize,
    ) -> Vec<CacheRow> {
        let mut out = Vec::new();
        let filter = Filter::new(now_ms, name, qtype);
        self.copy_matching(&filter, 0, usize::MAX, limit, &mut out);
        rows_of(&out, now_ms)
    }

    /// One piece of a listing (G4.1y): copies of the entries that match
    /// `filter` among the slots `from..from + scan`, until `out` holds
    /// `room`; the slot to go on from, `None` at the end. Only copies under
    /// the caller's lock (the formatting is done after it, [`rows_of`]):
    /// the resolver lets the lock go between pieces, so listing a million
    /// entries never stops the lookups for more than one piece.
    pub fn copy_matching(
        &self,
        filter: &Filter<'_>,
        from: usize,
        scan: usize,
        room: usize,
        out: &mut Vec<Copied>,
    ) -> Option<usize> {
        let end = from.saturating_add(scan).min(self.slots.len());
        let piece = self.slots.get(from..end)?;
        let stale_ms = self.stale_ms;
        for (i, s) in piece.iter().enumerate() {
            if out.len() >= room {
                return Some(from + i);
            }
            let Some(s) = s else { continue };
            if s.entry.expires_ms.saturating_add(stale_ms) <= filter.now_ms
                || !filter.name.is_none_or(|f| s.name.contains(f))
                || !filter.qtype.matches(s.rtype)
            {
                continue;
            }
            out.push(Copied {
                name: s.name.clone(),
                rtype: s.rtype,
                entry: s.entry.clone(),
            });
        }
        (end < self.slots.len()).then_some(end)
    }

    /// Slots in the table (live or free): where a listing ends.
    pub fn slots(&self) -> usize {
        self.slots.len()
    }
}

/// What a listing looks for: entries alive or stale-servable at `now_ms`,
/// whose name contains `name` and whose type is `qtype` (its text, as
/// `A`, `MX` or `TYPE65`).
#[derive(Debug, Clone)]
pub struct Filter<'a> {
    now_ms: u64,
    name: Option<&'a str>,
    qtype: TypeFilter<'a>,
}

#[derive(Debug, Clone)]
enum TypeFilter<'a> {
    Any,
    /// A known type: compared by number.
    Code(u16),
    /// Text hickory does not parse: compared as text (rare).
    Text(&'a str),
}

impl TypeFilter<'_> {
    fn matches(&self, rtype: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Code(c) => *c == rtype,
            Self::Text(t) => RecordType::from(rtype).to_string() == *t,
        }
    }
}

impl<'a> Filter<'a> {
    pub fn new(now_ms: u64, name: Option<&'a str>, qtype: Option<&'a str>) -> Self {
        let qtype = match qtype {
            None => TypeFilter::Any,
            // The text a row shows (`RecordType`'s `Display`) is what the
            // filter is compared with: a parse that does not print back
            // the same falls to the text.
            Some(q) => match q.parse::<RecordType>() {
                Ok(t) if t.to_string() == q => TypeFilter::Code(u16::from(t)),
                _ => TypeFilter::Text(q),
            },
        };
        Self {
            now_ms,
            name,
            qtype,
        }
    }
}

/// An entry copied out of the cache under its lock, to be formatted after
/// it (G4.1y).
#[derive(Debug, Clone)]
pub struct Copied {
    name: String,
    rtype: u16,
    entry: Entry,
}

/// The rows of `copies`, sorted by name and type.
pub fn rows_of(copies: &[Copied], now_ms: u64) -> Vec<CacheRow> {
    let mut rows: Vec<(u16, CacheRow)> = copies
        .iter()
        .map(|c| (c.rtype, row(&c.name, c.rtype, &c.entry, now_ms)))
        .collect();
    rows.sort_by(|a, b| a.1.name.cmp(&b.1.name).then(a.0.cmp(&b.0)));
    rows.into_iter().map(|(_, r)| r).collect()
}

fn row(name: &str, rtype: u16, e: &Entry, now_ms: u64) -> CacheRow {
    let rtype = RecordType::from(rtype);
    CacheRow {
        name: name.to_owned(),
        qtype: rtype.to_string(),
        kind: e.answer.kind(rtype),
        data: e
            .answer
            .records
            .iter()
            .map(|r| format!("{} {}", r.record_type(), r.data))
            .collect(),
        addresses: e.answer.addresses(),
        ttl: if e.expires_ms > now_ms {
            secs_left(e.expires_ms, now_ms)
        } else {
            0
        },
        hits: e.hits,
        server: e.server,
        stale: e.expires_ms <= now_ms,
    }
}

fn secs_left(expires_ms: u64, now_ms: u64) -> u32 {
    u32::try_from(expires_ms.saturating_sub(now_ms).div_ceil(1000)).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Rcode;
    use crate::message::tests::a;

    fn addrs(ip: [u8; 4], ttl: u32) -> Answer {
        Answer::local(Rcode::NoError, vec![a("h.example", ttl, ip)])
    }

    fn negative(rcode: Rcode, ttl: Option<u32>) -> Answer {
        Answer {
            rcode,
            records: Vec::new(),
            authority: Vec::new(),
            ttl,
        }
    }

    const A: RecordType = RecordType::A;
    const WEEK: u32 = 604_800;

    #[test]
    fn entries_expire_with_their_ttl() {
        let mut c = Cache::new(1 << 20);
        c.put(
            "a.example",
            A,
            &addrs([192, 0, 2, 1], 60),
            None,
            0,
            WEEK,
            40,
        );
        let hit = c.get("a.example", A, 1_000).unwrap();
        assert_eq!(hit.ttl, 59);
        assert_eq!(hit.answer.records[0].ttl, 59, "TTL counts down for clients");
        assert!(c.get("a.example", RecordType::AAAA, 1_000).is_none());
        assert!(c.get("a.example", A, 60_000).is_none(), "expired");
        assert!(c.is_empty() && c.used_bytes() == 0);
    }

    #[test]
    fn ttl_is_capped_and_zero_is_not_kept() {
        let mut c = Cache::new(1 << 20);
        c.put("a", A, &addrs([192, 0, 2, 1], 86_400), None, 0, 300, 40);
        assert_eq!(c.get("a", A, 0).unwrap().ttl, 300, "cache_max_ttl");
        c.put("b", A, &addrs([192, 0, 2, 1], 0), None, 0, 300, 40);
        assert!(c.get("b", A, 0).is_none(), "RFC 1035 §3.2.1");
    }

    #[test]
    fn negative_answers_rfc2308() {
        let mut c = Cache::new(1 << 20);
        c.put(
            "nx",
            A,
            &negative(Rcode::NxDomain, Some(86_400)),
            None,
            0,
            WEEK,
            40,
        );
        let hit = c.get("nx", A, 0).unwrap();
        assert_eq!(
            (hit.answer.rcode, hit.ttl),
            (Rcode::NxDomain, MAX_NEGATIVE_TTL)
        );
        c.put(
            "bare",
            A,
            &negative(Rcode::NoError, None),
            None,
            0,
            WEEK,
            40,
        );
        assert!(c.get("bare", A, 0).is_none(), "no SOA, not cached");
    }

    impl Cache {
        fn flush_one(&mut self, name: &str) {
            let t = u16::from(A);
            if let Some(i) = self.find(self.hash(name, t), name, t) {
                self.remove(i);
            }
        }
    }

    /// Entry size of a 6-character name with one record (tests below).
    const ONE: usize = ENTRY_OVERHEAD + INDEX_OVERHEAD + 2 * 6 + RECORD_OVERHEAD + 40;

    /// A client's query: from the cache, or "asked" and stored.
    fn ask(c: &mut Cache, name: &str, ttl: u32, now: u64) -> bool {
        if c.get(name, A, now).is_some() {
            return true;
        }
        c.put(name, A, &addrs([192, 0, 2, 1], ttl), None, now, WEEK, 40);
        false
    }

    /// The structure agrees with itself: bytes, index, expiry index and
    /// the three lists (each live slot in exactly one, in its segment).
    fn check(c: &Cache) {
        let live: Vec<u32> = (0..c.slots.len() as u32)
            .filter(|i| slot(&c.slots, *i).is_some())
            .collect();
        let bytes: usize = live
            .iter()
            .map(|i| slot(&c.slots, *i).unwrap().entry.size)
            .sum();
        assert_eq!(c.used, bytes, "used");
        assert_eq!(c.index.len(), live.len(), "index");
        assert_eq!(c.by_expiry.len(), live.len(), "expiry index");
        assert!(c.used <= c.budget, "over budget: {} > {}", c.used, c.budget);
        let mut seen = 0;
        for (seg, l) in [
            (Segment::Window, c.lists.window),
            (Segment::Probation, c.lists.probation),
            (Segment::Protected, c.lists.protected),
        ] {
            let (mut i, mut prev, mut sum) = (l.head, NIL, 0);
            while i != NIL {
                let s = slot(&c.slots, i).unwrap();
                assert_eq!((s.segment, s.prev), (seg, prev));
                assert_eq!(c.index.get(&s.hash), Some(&i));
                sum += s.entry.size;
                seen += 1;
                prev = i;
                i = s.next;
            }
            assert_eq!((l.tail, l.bytes), (prev, sum), "{seg:?}");
        }
        assert_eq!(seen, live.len(), "every entry in one list");
    }

    #[test]
    fn a_flood_of_unique_names_leaves_the_hot_ones() {
        // G4.1x, the lab's torture in small: 50 hot names in a cache for
        // 100, then 20 000 unique names with a legit client asking a hot
        // name every second unique one (each hot name once per 100 unique
        // names: once per turn of the whole cache). Every legit query is
        // a hit. Evicting by arrival, as before, this missed most of them.
        let mut c = Cache::new(100 * ONE);
        for i in 0..50 {
            ask(&mut c, &format!("h{i:05}"), 3600, 0);
        }
        let mut missed = 0;
        for i in 0..20_000 {
            assert!(!ask(&mut c, &format!("u{i:05}"), 3600, 0));
            if i % 2 == 0 && !ask(&mut c, &format!("h{:05}", i / 2 % 50), 3600, 0) {
                missed += 1;
            }
            if i % 1000 == 0 {
                check(&c);
            }
        }
        check(&c);
        assert_eq!(missed, 0);
        let s = c.stats();
        assert_eq!(s.entries, 100);
        assert_eq!(s.evicted + s.rejected, 20_000 - 50, "{s:?}");
        assert!(s.rejected > 10_000, "{s:?}");
    }

    #[test]
    fn a_new_name_is_answered_from_the_window_at_once() {
        // A full cache of names asked twice; a new name asked three times
        // in a row is a hit from the second time (the window), and after
        // that it beats the entries asked once.
        let mut c = Cache::new(100 * ONE);
        for i in 0..100 {
            ask(&mut c, &format!("h{i:05}"), 3600, 0);
            ask(&mut c, &format!("h{i:05}"), 3600, 0);
        }
        for i in 0..1000 {
            ask(&mut c, &format!("u{i:05}"), 3600, 0);
        }
        assert!(!ask(&mut c, "burst1", 3600, 0));
        assert!(ask(&mut c, "burst1", 3600, 0), "from the window");
        assert!(ask(&mut c, "burst1", 3600, 0));
        // Pushed out of the window by the next newcomers: admitted.
        for i in 0..10 {
            ask(&mut c, &format!("v{i:05}"), 3600, 0);
        }
        assert!(ask(&mut c, "burst1", 3600, 0), "kept by frequency");
        check(&c);
    }

    #[test]
    fn answers_past_their_stale_window_go_first() {
        let mut c = Cache::new(10 * ONE);
        for i in 0..10u32 {
            let ttl = if i < 5 { 10 } else { 1000 };
            ask(&mut c, &format!("h{i:05}"), ttl, 0);
            ask(&mut c, &format!("h{i:05}"), ttl, 0);
        }
        // At 20 s the five with TTL 10 are dead (no serve-stale): five new
        // names take their place, nobody alive is pushed out or rejected.
        for i in 0..5 {
            ask(&mut c, &format!("n{i:05}"), 1000, 20_000);
        }
        check(&c);
        let s = c.stats();
        assert_eq!((s.entries, s.expired, s.evicted, s.rejected), (10, 5, 0, 0));
        for i in 5..10 {
            assert!(c.get(&format!("h{i:05}"), A, 20_000).is_some());
        }
        // With serve-stale they are not dead yet: a newcomer asked once
        // ties with them and is rejected.
        let mut c = Cache::new(10 * ONE);
        c.set_stale(3600);
        for i in 0..10u32 {
            ask(&mut c, &format!("h{i:05}"), 10, 0);
        }
        ask(&mut c, "n00000", 1000, 20_000);
        assert_eq!(c.stats().expired, 0);
        check(&c);
    }

    #[test]
    fn a_smaller_budget_evicts_and_zero_turns_it_off() {
        let mut c = Cache::new(100 * ONE);
        for i in 0..100 {
            ask(&mut c, &format!("h{i:05}"), 3600, 0);
        }
        c.set_budget(10 * ONE);
        check(&c);
        assert_eq!(c.len(), 10);
        // The window's newcomer offered to the smaller main area loses.
        assert_eq!((c.stats().evicted, c.stats().rejected), (89, 1));
        c.set_budget(0);
        assert!(c.is_empty() && c.sketch_bytes() == 0);
        c.put("x", A, &addrs([192, 0, 2, 9], 60), None, 0, WEEK, 40);
        assert!(c.is_empty(), "cache_size 0 turns the cache off");
        c.set_budget(64 << 20);
        assert_eq!(c.sketch_bytes(), 131_072 * 8, "one u64 per ~700 bytes");
    }

    #[test]
    fn a_new_answer_for_a_kept_name_replaces_it_in_place() {
        let mut c = Cache::new(100 * ONE);
        c.set_stale(3600);
        for _ in 0..3 {
            ask(&mut c, "h00001", 10, 0);
        }
        let seg = |c: &Cache| {
            slot(&c.slots, *c.index.values().next().unwrap())
                .unwrap()
                .segment
        };
        let before = seg(&c);
        assert!(c.get("h00001", A, 20_000).is_none(), "expired, kept stale");
        c.put(
            "h00001",
            A,
            &addrs([192, 0, 2, 7], 60),
            None,
            20_000,
            WEEK,
            40,
        );
        check(&c);
        assert_eq!(c.len(), 1);
        let hit = c.get("h00001", A, 21_000).unwrap();
        assert_eq!(hit.answer.addresses(), [IpAddr::from([192, 0, 2, 7])]);
        assert_eq!(seg(&c), before, "same segment");
    }

    #[test]
    fn evictions_expiries_refusals_and_types_are_counted() {
        let mut c = Cache::new(3 * ONE);
        for i in 0..3 {
            ask(&mut c, &format!("a{i:05}"), 60, 0);
        }
        // Two names asked twice: they push out two asked once.
        for i in 0..2 {
            assert!(!ask(&mut c, &format!("b{i:05}"), 600, 0));
            ask(&mut c, &format!("b{i:05}"), 600, 0);
        }
        c.put(
            "t00000",
            RecordType::TXT,
            &addrs([192, 0, 2, 9], 600),
            None,
            0,
            86_400,
            40,
        );
        let s = c.stats();
        assert_eq!(s.entries, 3);
        assert!(s.evicted >= 2 && s.rejected >= 1, "{s:?}");
        assert_eq!(s.expired, 0);
        assert_eq!(s.by_type.iter().map(|t| t.1).sum::<usize>(), 3);
        // Read past TTL and stale window (none here): expired.
        let kept_a = (0..3)
            .map(|i| format!("a{i:05}"))
            .find(|n| c.get(n, A, 0).is_some());
        if let Some(n) = kept_a {
            assert!(c.get(&n, A, 61_000).is_none());
            assert_eq!(c.stats().expired, 1);
        }
        // A flush empties it; the next answer starts the types again.
        c.flush();
        assert!(c.stats().by_type.is_empty());
        c.put("x", A, &addrs([192, 0, 2, 1], 60), None, 0, 86_400, 40);
        assert_eq!(c.stats().by_type, [(u16::from(A), 1)]);
        check(&c);
    }

    #[test]
    fn a_listing_in_pieces_is_the_listing_in_one_go() {
        // G4.1y: pieces of 7 slots or 3 copies, entries removed and added
        // between them as lookups would; nothing listed twice, filters on
        // name and type, the rows sorted.
        let mut c = Cache::new(1 << 20);
        for i in 0..100u32 {
            ask(&mut c, &format!("h{i:05}"), 3600, 0);
            c.put(
                &format!("h{i:05}"),
                RecordType::AAAA,
                &negative(Rcode::NoError, Some(60)),
                None,
                0,
                WEEK,
                40,
            );
        }
        let all = c.rows(0);
        assert_eq!(all.len(), 200);
        let f = Filter::new(0, Some("h0004"), Some("AAAA"));
        let (mut out, mut from, mut pieces) = (Vec::new(), Some(0), 0);
        while let Some(n) = from {
            from = c.copy_matching(&f, n, 7, out.len() + 3, &mut out);
            pieces += 1;
        }
        let rows = rows_of(&out, 0);
        assert_eq!(rows.len(), 10, "h00040..h00049, AAAA only");
        assert!(
            rows.iter()
                .all(|r| r.qtype == "AAAA" && r.name.starts_with("h0004"))
        );
        assert!(rows.windows(2).all(|w| w[0].name < w[1].name), "sorted");
        assert!(pieces > 200 / 7, "{pieces} pieces");
        // A type hickory does not know is compared as text.
        assert!(c.rows_matching(0, None, Some("TYPE65"), 10).is_empty());
        assert_eq!(c.rows_matching(0, None, Some("A"), 1000).len(), 100);
        // Changes between pieces: what was there all along is listed once.
        let f = Filter::new(0, None, Some("A"));
        let mut out = Vec::new();
        let next = c.copy_matching(&f, 0, 50, usize::MAX, &mut out).unwrap();
        for i in 0..10 {
            c.flush_one(&format!("h{i:05}"));
            ask(&mut c, &format!("n{i:05}"), 3600, 0);
        }
        let mut from = Some(next);
        while let Some(n) = from {
            from = c.copy_matching(&f, n, 50, usize::MAX, &mut out);
        }
        let names: std::collections::BTreeSet<String> =
            out.iter().map(|c| c.name.clone()).collect();
        assert_eq!(names.len(), out.len(), "no entry twice");
        assert!((10..100).all(|i| names.contains(&format!("h{i:05}"))));
    }

    #[derive(Debug, Clone)]
    enum Op {
        Ask(u8, u16),
        Put(u8, u16, u16),
        Budget(u8),
        Stale(u16),
        Flush,
        Wait(u16),
    }

    fn op() -> impl proptest::strategy::Strategy<Value = Op> {
        use proptest::prelude::*;
        prop_oneof![
            8 => (any::<u8>(), 0u16..200).prop_map(|(n, t)| Op::Ask(n, t)),
            4 => (any::<u8>(), 0u16..200, 0u16..2000).prop_map(|(n, t, w)| Op::Put(n, t, w)),
            1 => (0u8..40).prop_map(Op::Budget),
            1 => (0u16..100).prop_map(Op::Stale),
            1 => Just(Op::Flush),
            2 => (0u16..30_000).prop_map(Op::Wait),
        ]
    }

    proptest::proptest! {
        /// Any mix of lookups, answers, budgets, flushes and time keeps
        /// the bytes, the indexes and the lists in agreement, and the cache
        /// under budget.
        #[test]
        fn the_structure_holds(ops in proptest::collection::vec(op(), 1..300)) {
            let mut c = Cache::new(20 * ONE);
            let mut now = 0u64;
            for o in ops {
                match o {
                    Op::Ask(n, t) => { ask(&mut c, &format!("n{n:05}"), u32::from(t), now); }
                    Op::Put(n, t, w) => c.put(&format!("p{n}"), RecordType::AAAA,
                        &addrs([192, 0, 2, 1], u32::from(t)), None, now, WEEK, usize::from(w)),
                    Op::Budget(b) => c.set_budget(usize::from(b) * ONE),
                    Op::Stale(s) => c.set_stale(u32::from(s)),
                    Op::Flush => c.flush(),
                    Op::Wait(ms) => now += u64::from(ms),
                }
                check(&c);
            }
        }
    }

    #[test]
    fn stale_answers_rfc8767() {
        let mut c = Cache::new(1 << 20);
        c.set_stale(3600);
        c.put("s", A, &addrs([192, 0, 2, 1], 60), None, 0, WEEK, 40);
        assert!(c.get_stale("s", A, 10_000).is_none(), "fresh is not stale");
        assert!(c.get("s", A, 61_000).is_none(), "expired is not fresh");
        let hit = c.get_stale("s", A, 61_000).unwrap();
        assert!(hit.stale);
        assert_eq!(hit.answer.records[0].ttl, STALE_TTL, "RFC 8767 §4");
        assert!(c.rows(61_000)[0].stale);
        assert!(
            c.get_stale("s", A, 60_000 + 3_600_000).is_none(),
            "window over"
        );
        c.set_stale(0);
        c.put("t", A, &addrs([192, 0, 2, 1], 60), None, 0, WEEK, 40);
        assert!(c.get_stale("t", A, 61_000).is_none(), "serve_stale off");
    }

    #[test]
    fn rows_hits_and_flush() {
        let mut c = Cache::new(1 << 20);
        let srv: IpAddr = [192, 0, 2, 53].into();
        c.put("b", A, &addrs([192, 0, 2, 2], 60), Some(srv), 0, WEEK, 40);
        c.put(
            "a",
            RecordType::AAAA,
            &negative(Rcode::NoError, Some(30)),
            Some(srv),
            0,
            WEEK,
            40,
        );
        c.get("b", A, 1).unwrap();
        c.get("b", A, 2).unwrap();
        let rows = c.rows(10_000);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            (rows[0].name.as_str(), rows[0].ttl, rows[0].qtype.as_str()),
            ("a", 20, "AAAA")
        );
        assert_eq!(rows[0].kind, CacheKind::NoData);
        assert_eq!(rows[1].server, Some(srv));
        assert_eq!(rows[1].hits, 2);
        assert_eq!(rows[1].data, vec!["A 192.0.2.2".to_owned()]);
        c.flush();
        assert!(c.rows(0).is_empty() && c.used_bytes() == 0);
    }
}
