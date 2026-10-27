//! Traffic graphs (G4.5, RouterOS `/tool graphing`): a history of every
//! kept interface (bps, pps, errors, drops) and of the router itself (CPU,
//! memory, conntrack), at 1 s for an hour, 1 min for a day, 5 min for a
//! week and 1 h for a year ([`rrd`]).
//!
//! - **Collection** rides on the clock's [`Session::tick`]: the link poll
//!   it already makes carries the counters, so a second of history costs no
//!   extra netlink dump. Rates come from two readings (`delta / seconds`);
//!   a counter that went down (a reset, a recreated link) is unknown for
//!   that interval, never a spike (RRDtool `DERIVE` with `min = 0`); a gap
//!   longer than [`HEARTBEAT`] is unknown.
//! - **What is kept** is the config's `system.graphing`: physical ports by
//!   default, bridges, VLANs and tunnels when asked, names included or
//!   excluded, under a memory cap ([`Graphing::max_memory_mib`]): a series
//!   that does not fit is refused, logged once and listed by
//!   `system.graph.print`. A series that stops being kept (its interface
//!   gone or no longer chosen) is dropped after [`GRACE`] seconds, so a
//!   failed poll or a link that flaps does not lose a year of history.
//! - **Persistence** is the daemon's (`service/graphing.rs`): the engine
//!   does no I/O (wasm), it hands out [`Patch`]es — a new file whole, then
//!   only the buckets closed since the last store — and takes files back at
//!   boot ([`GraphDb::load`]). Without a daemon (GUI lab, tests) the
//!   history lives in memory only.
//! - **Reading** is `system.graph.query` (graphs and their statistics) and
//!   `system.graph.export` (every closed bucket after a cursor: what the
//!   ClickHouse exporter of G4.4f has not sent yet; also
//!   [`GraphDb::export`] for code in the daemon).

pub mod alert;
pub mod query;
pub mod rrd;

use std::collections::{BTreeMap, BTreeSet};

use corerouter_hal::LinkState;
use corerouter_hal::queue::QueueCounters;
use corerouter_hal::resources::Resources;
use corerouter_model::IfName;
use corerouter_model::graphing::Graphing;
use serde::Serialize;
use serde_json::json;

use crate::Session;
use rrd::Rrd;

/// Longest gap between two readings that still gives a rate (RRDtool's
/// heartbeat); longer is unknown.
pub const HEARTBEAT: u64 = 10;
/// Seconds a series may go unkept before it is dropped (and its file).
pub const GRACE: u64 = 600;
/// A rate above this is a counter gone wrong, not traffic (4 Tbit/s).
const MAX_RATE: f64 = 4e12;
/// Most series kept, whatever the memory cap.
pub const MAX_SERIES: usize = 4096;

/// The key of the router's own series.
pub const SYSTEM: &str = "system";
/// Prefix of an interface's series key (`interface:ether1`).
pub const INTERFACE: &str = "interface:";
/// Prefix of a queue's series key (`queue:camera`, `queue:<pppoe-ana>`,
/// G4.9g).
pub const QUEUE: &str = "queue:";

/// What one value of a series means: its key, unit and whether it is a
/// rate that adds up to a total.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Source {
    pub key: &'static str,
    pub unit: &'static str,
    /// Key of its total over a range (bytes, packets), if it has one.
    pub total: Option<&'static str>,
    /// What one unit of the rate adds to the total (bits → bytes: 1/8).
    #[serde(skip)]
    pub per_total: f64,
}

const fn src(key: &'static str, unit: &'static str, total: Option<&'static str>, per_total: f64) -> Source {
    Source { key, unit, total, per_total }
}

/// An interface's values: rates in bits and packets per second, errors and
/// drops per second (receive and transmit summed).
pub const INTERFACE_SOURCES: [Source; 6] = [
    src("rx_bps", "bps", Some("rx_bytes"), 0.125),
    src("tx_bps", "bps", Some("tx_bytes"), 0.125),
    src("rx_pps", "pps", Some("rx_packets"), 1.0),
    src("tx_pps", "pps", Some("tx_packets"), 1.0),
    src("errors", "/s", Some("errors"), 1.0),
    src("drops", "/s", Some("drops"), 1.0),
];

/// The router's values: CPU load (%), memory in use (bytes), conntrack
/// entries.
pub const SYSTEM_SOURCES: [Source; 3] = [
    src("cpu", "%", None, 0.0),
    src("memory", "bytes", None, 0.0),
    src("conntrack", "entries", None, 0.0),
];

/// A queue's values (G4.9g): its rates each way (`up` = from the target),
/// drops per second (both ways) and how long a packet entering the
/// download queue waits, ms.
pub const QUEUE_SOURCES: [Source; 4] = [
    src("up_bps", "bps", Some("up_bytes"), 0.125),
    src("down_bps", "bps", Some("down_bytes"), 0.125),
    src("drops", "/s", Some("drops"), 1.0),
    src("delay", "ms", None, 0.0),
];

/// The values of series `key`.
pub fn sources(key: &str) -> &'static [Source] {
    if key == SYSTEM {
        &SYSTEM_SOURCES
    } else if key.starts_with(QUEUE) {
        &QUEUE_SOURCES
    } else {
        &INTERFACE_SOURCES
    }
}

/// The series key of the queue named `name`; `None` when it does not fit
/// a series header ([`rrd::KEY_BYTES`]).
pub fn queue_key(name: &str) -> Option<String> {
    let key = format!("{QUEUE}{name}");
    (key.len() <= rrd::KEY_BYTES && !name.is_empty()).then_some(key)
}

/// A queue name in a file name: letters, digits, `.`, `_` and `-` as they
/// are, any other byte as `%XX` (names may hold `<`, `>`, spaces).
fn escape(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn unescape(text: &str) -> Option<String> {
    let mut out = Vec::with_capacity(text.len());
    let mut bytes = text.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = char::from(bytes.next()?).to_digit(16)?;
            let lo = char::from(bytes.next()?).to_digit(16)?;
            out.push(u8::try_from(hi * 16 + lo).ok()?);
        } else if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
            out.push(b);
        } else {
            return None;
        }
    }
    String::from_utf8(out).ok()
}

/// File name of series `key`: `system.rrd`, `interface-ether1.rrd`
/// (interface names are already safe in a file name).
pub fn file_name(key: &str) -> Option<String> {
    if key == SYSTEM {
        return Some("system.rrd".into());
    }
    if let Some(q) = key.strip_prefix(QUEUE) {
        return queue_key(q).map(|_| format!("queue-{}.rrd", escape(q)));
    }
    let name: IfName = key.strip_prefix(INTERFACE)?.parse().ok()?;
    Some(format!("interface-{name}.rrd"))
}

/// The series key a file holds (the inverse of [`file_name`]).
pub fn key_of_file(file: &str) -> Option<String> {
    let stem = file.strip_suffix(".rrd")?;
    if stem == SYSTEM {
        return Some(SYSTEM.into());
    }
    if let Some(q) = stem.strip_prefix("queue-") {
        return queue_key(&unescape(q)?);
    }
    let name: IfName = stem.strip_prefix("interface-")?.parse().ok()?;
    Some(format!("{INTERFACE}{name}"))
}

/// What a store writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Patch {
    /// A new series (or one started again): the whole file.
    Create { file: String, bytes: Vec<u8> },
    /// Byte ranges of an existing file.
    Write { file: String, writes: Vec<rrd::Write> },
    /// A series no longer kept.
    Remove { file: String },
}

/// The disk side, reported by the daemon (`system.graph.print`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DiskStatus {
    /// Where the files are; `None`: memory only (no daemon or no
    /// `--config-dir`).
    pub dir: Option<String>,
    pub files: usize,
    /// Unix time of the last store, bytes written and how long it took.
    pub last_store: Option<u64>,
    pub last_store_bytes: u64,
    pub last_store_ms: u64,
    pub stores: u64,
    pub bytes_written: u64,
    pub last_error: Option<String>,
    /// Files read at boot, and those refused (name: why).
    pub loaded: usize,
    pub load_errors: Vec<String>,
}

#[derive(Debug, Clone)]
struct Kept {
    rrd: Rrd,
    /// Not yet on disk: the next store writes it whole.
    new: bool,
    /// Since when nothing keeps it (dropped after [`GRACE`]).
    unkept_since: Option<u64>,
    /// A queue's (G4.9g): the second it was last kept, and its dropped
    /// packets then (drops per second are the difference).
    queue_seen: Option<(u64, u64)>,
}

/// The counters of an interface at a time: rx/tx bytes, rx/tx packets,
/// errors, drops (`None`: not counted).
#[derive(Debug, Clone, Copy)]
struct Reading {
    t: u64,
    c: [Option<u64>; 6],
}

/// The history (operational state in the session: `s.ext::<GraphDb>()`).
#[derive(Debug, Default)]
pub struct GraphDb {
    series: BTreeMap<String, Kept>,
    /// Interfaces that would be kept but do not fit under the cap.
    refused: BTreeSet<IfName>,
    /// Queues likewise (G4.9g): how many, the last second.
    refused_queues: usize,
    readings: BTreeMap<IfName, Reading>,
    resources: Option<(u64, Resources)>,
    /// Files to delete at the next store.
    removed: Vec<String>,
    /// The daemon stores the history (else memory only).
    persistent: bool,
    pub disk: DiskStatus,
    /// Bandwidth alerts: state by rule, link speeds by interface.
    alerts: BTreeMap<corerouter_model::ItemId, alert::AlertState>,
    speeds: alert::Speeds,
}

/// A bucket of [`GraphDb::export`]: series key, bucket start (Unix s),
/// averages and, when kept, maxima.
pub type ExportRow = (String, u64, Vec<f32>, Option<Vec<f32>>);

/// One interface as the sampler sees it.
pub struct Link<'a> {
    pub name: &'a IfName,
    /// The config's kind label, else the platform's link kind.
    pub kind: &'a str,
    pub live: Option<&'a LinkState>,
}

impl GraphDb {
    /// The series kept, by key.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.series.keys().map(String::as_str)
    }

    pub fn get(&self, key: &str) -> Option<&Rrd> {
        self.series.get(key).map(|k| &k.rrd)
    }

    pub fn refused(&self) -> &BTreeSet<IfName> {
        &self.refused
    }

    /// Bytes of history in memory (the same go to disk).
    pub fn memory_bytes(&self) -> u64 {
        self.series.values().map(|k| k.rrd.size() as u64).sum()
    }

    /// The daemon will store the history in `dir`. Series the clock
    /// started before (boot) are written whole by the first store.
    pub fn set_persistent(&mut self, dir: &str) {
        self.persistent = true;
        self.disk.dir = Some(dir.to_owned());
        for k in self.series.values_mut() {
            k.new = true;
        }
    }

    /// A file read at boot. A file of another layout, or whose name and
    /// contents disagree, is refused (and rewritten by the next store if
    /// the series is still kept).
    pub fn load(&mut self, file: &str, bytes: &[u8]) -> Result<(), String> {
        let key = key_of_file(file).ok_or_else(|| "not a graph file name".to_string())?;
        let rrd = Rrd::decode(bytes)?;
        if rrd.key() != key {
            return Err(format!("holds series '{}'", crate::logging::cut(rrd.key(), 64)));
        }
        if rrd.ds() != sources(&key).len() {
            return Err(format!("{} values per slot, expected {}", rrd.ds(), sources(&key).len()));
        }
        if self.series.len() >= MAX_SERIES && !self.series.contains_key(&key) {
            return Err("too many series".into());
        }
        self.series.insert(
            key,
            Kept {
                rrd,
                new: false,
                unkept_since: None,
                queue_seen: None,
            },
        );
        Ok(())
    }

    /// What changed since the last store (`seconds`: the 1 s rings too, on
    /// a clean shutdown). Nothing without persistence.
    pub fn take_patches(&mut self, seconds: bool) -> Vec<Patch> {
        let mut out: Vec<Patch> = self
            .removed
            .drain(..)
            .map(|file| Patch::Remove { file })
            .collect();
        for (key, kept) in &mut self.series {
            let Some(file) = file_name(key) else { continue };
            if kept.new {
                kept.new = false;
                kept.rrd.mark_stored();
                out.push(Patch::Create {
                    file,
                    bytes: kept.rrd.encode(),
                });
                continue;
            }
            let writes = kept.rrd.take_writes(seconds);
            if !writes.is_empty() {
                out.push(Patch::Write { file, writes });
            }
        }
        out
    }

    /// A series that could not be written (its file went missing or broke):
    /// the next store writes it whole.
    pub fn rewrite(&mut self, file: &str) {
        if let Some(k) = key_of_file(file).and_then(|k| self.series.get_mut(&k)) {
            k.new = true;
        }
    }

    /// Every bucket of resolution `step` (1, 60, 300 or 3600 s) closed after
    /// `since` (Unix seconds of the bucket's start), oldest first, at most
    /// `limit` rows: `(series key, bucket start, averages, maxima)`. A
    /// reader keeps the last start it got as its next `since`.
    pub fn export(
        &self,
        step: u64,
        since: u64,
        keys: Option<&[String]>,
        limit: usize,
    ) -> Vec<ExportRow> {
        let Some(tier) = rrd::TIERS.iter().position(|t| t.step == step) else {
            return Vec::new();
        };
        let mut rows = Vec::new();
        for (key, kept) in &self.series {
            if keys.is_some_and(|ks| !ks.iter().any(|k| k == key)) {
                continue;
            }
            let closed = kept.rrd.closed(tier);
            if closed == 0 {
                continue;
            }
            let rows_kept = rrd::TIERS.get(tier).map_or(0, |t| t.rows as u64);
            let first = (since / step + 1).max(closed.saturating_sub(rows_kept - 1));
            for k in first..=closed {
                if let Some((avg, max)) = kept.rrd.row(tier, k) {
                    if avg.iter().all(|v| v.is_nan()) {
                        continue;
                    }
                    rows.push((key.clone(), k * step, avg.to_vec(), max.map(<[f32]>::to_vec)));
                }
            }
        }
        rows.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        rows.truncate(limit);
        rows
    }

    /// One second of collection at `now`. Returns lines for the log
    /// (`true`: a warning).
    pub fn sample(
        &mut self,
        now: u64,
        cfg: &Graphing,
        links: &[Link<'_>],
        resources: Option<Resources>,
    ) -> Vec<(bool, String)> {
        let mut log = Vec::new();
        let cap = cfg.max_memory_bytes();
        let mut used = self.memory_bytes();
        let mut kept_now: BTreeSet<String> = BTreeSet::new();
        let mut refused = BTreeSet::new();

        if cfg.resources {
            kept_now.insert(SYSTEM.into());
            if self.admit(SYSTEM, cap, &mut used)
                && let Some(r) = resources
            {
                self.sample_resources(now, r);
            }
        }
        for link in links {
            if !cfg.keeps(link.name, link.kind) {
                continue;
            }
            let key = format!("{INTERFACE}{}", link.name);
            if !self.admit(&key, cap, &mut used) {
                refused.insert(link.name.clone());
                continue;
            }
            kept_now.insert(key.clone());
            if let Some(l) = link.live {
                self.sample_link(now, &key, l);
            }
        }
        for name in refused.difference(&self.refused) {
            log.push((
                true,
                format!(
                    "graphing: interface {name} not kept, the history would pass max-memory {} MiB",
                    cfg.max_memory_mib
                ),
            ));
        }
        self.refused = refused;

        // Series nobody keeps: dropped after the grace (not when the poll
        // came back empty, which is a failed poll, not every link gone).
        let polled = links.iter().any(|l| l.live.is_some());
        let mut drop = Vec::new();
        for (key, kept) in &mut self.series {
            if key.starts_with(QUEUE) {
                // `sample_queues` keeps those.
                continue;
            }
            if kept_now.contains(key) {
                kept.unkept_since = None;
            } else if polled || !key.starts_with(INTERFACE) {
                let since = *kept.unkept_since.get_or_insert(now);
                if now.saturating_sub(since) >= GRACE {
                    drop.push(key.clone());
                }
            }
        }
        for key in drop {
            self.series.remove(&key);
            if let Some(name) = key.strip_prefix(INTERFACE).and_then(|n| n.parse().ok()) {
                self.readings.remove::<IfName>(&name);
            }
            if self.persistent
                && let Some(f) = file_name(&key)
            {
                self.removed.push(f);
            }
            log.push((false, format!("graphing: history of {key} dropped (no longer kept)")));
        }
        self.readings.retain(|n, _| links.iter().any(|l| l.name == n));
        log
    }

    /// One second of the queues' history (G4.9g): `kept` are the queues
    /// kept now (series key and counters). A queue not in it for
    /// [`GRACE`] seconds is dropped (a session that reconnects within it
    /// goes on in the same series). Returns lines for the log.
    ///
    /// Once a second under the session lock, so nothing is allocated per
    /// queue: 10 000 queues past the cap cost 1,8 ms a second when their
    /// names were collected (**medido**, G4.9g).
    pub fn sample_queues(&mut self, now: u64, cfg: &Graphing, kept: &[(&str, QueueCounters)]) -> Vec<(bool, String)> {
        let mut log = Vec::new();
        let cap = cfg.max_memory_bytes();
        let size = Rrd::size_for(QUEUE_SOURCES.len()) as u64;
        let mut used = self.memory_bytes();
        let mut refused = 0usize;
        let mut first_refused: Option<&str> = None;
        for (key, c) in kept {
            if !self.series.contains_key(*key) {
                if used.saturating_add(size) > cap || self.series.len() >= MAX_SERIES {
                    refused += 1;
                    first_refused.get_or_insert(key);
                    continue;
                }
                used += size;
                self.series.insert(
                    (*key).to_owned(),
                    Kept {
                        rrd: Rrd::new(key, QUEUE_SOURCES.len()),
                        new: self.persistent,
                        unkept_since: None,
                        queue_seen: None,
                    },
                );
            }
            let Some(k) = self.series.get_mut(*key) else { continue };
            let dropped = c.dropped.iter().fold(0u64, |a, b| a.saturating_add(*b));
            let drops = match k.queue_seen.replace((now, dropped)) {
                Some((t, d)) if now > t && now - t <= HEARTBEAT && dropped >= d => (dropped - d) as f32 / (now - t) as f32,
                _ => f32::NAN,
            };
            let [up, down] = c.rate_bps;
            let delay = c.queued_us[QueueCounters::DOWNLOAD] as f32 / 1000.0;
            k.unkept_since = None;
            k.rrd.update(now, &[up as f32, down as f32, drops, delay]);
        }
        // One line when more are refused: 10 000 queues past the cap is
        // not 10 000 lines.
        if refused > self.refused_queues {
            let first = first_refused.and_then(|k| k.strip_prefix(QUEUE)).unwrap_or_default();
            log.push((
                true,
                format!(
                    "graphing: {refused} queue{} not kept ({first}…), the history would pass max-memory {} MiB",
                    if refused == 1 { "" } else { "s" },
                    cfg.max_memory_mib
                ),
            ));
        }
        self.refused_queues = refused;
        let mut drop = Vec::new();
        for (key, k) in self.series.range_mut::<str, _>((std::ops::Bound::Included(QUEUE), std::ops::Bound::Unbounded)) {
            if !key.starts_with(QUEUE) {
                break;
            }
            if k.queue_seen.is_some_and(|(t, _)| t == now) {
                continue;
            }
            let since = *k.unkept_since.get_or_insert(now);
            if now.saturating_sub(since) >= GRACE {
                drop.push(key.clone());
            }
        }
        for key in drop {
            self.series.remove(&key);
            if self.persistent
                && let Some(f) = file_name(&key)
            {
                self.removed.push(f);
            }
            log.push((false, format!("graphing: history of {key} dropped (no longer kept)")));
        }
        log
    }

    /// How many queues would be kept but did not fit under the cap.
    pub fn refused_queues(&self) -> usize {
        self.refused_queues
    }

    /// Whether series `key` is (now) kept under the cap.
    fn admit(&mut self, key: &str, cap: u64, used: &mut u64) -> bool {
        if self.series.contains_key(key) {
            return true;
        }
        let size = Rrd::size_for(sources(key).len()) as u64;
        if used.saturating_add(size) > cap || self.series.len() >= MAX_SERIES {
            return false;
        }
        *used += size;
        self.series.insert(
            key.to_owned(),
            Kept {
                rrd: Rrd::new(key, sources(key).len()),
                new: self.persistent,
                unkept_since: None,
                queue_seen: None,
            },
        );
        true
    }

    fn sample_link(&mut self, now: u64, key: &str, l: &LinkState) {
        let e = l.errors;
        let reading = Reading {
            t: now,
            c: [
                Some(l.rx_bytes),
                Some(l.tx_bytes),
                Some(l.rx_packets),
                Some(l.tx_packets),
                e.map(|e| e.rx_errors.saturating_add(e.tx_errors)),
                e.map(|e| e.rx_dropped.saturating_add(e.tx_dropped)),
            ],
        };
        let Some(prev) = self.readings.insert(l.name.clone(), reading) else {
            return;
        };
        if now <= prev.t {
            // Two polls in one second: keep the older reading.
            self.readings.insert(l.name.clone(), prev);
            return;
        }
        let dt = now - prev.t;
        if dt > HEARTBEAT {
            return;
        }
        let mut v = [f32::NAN; 6];
        for (i, (out, src)) in v.iter_mut().zip(&INTERFACE_SOURCES).enumerate() {
            let scale = if src.unit == "bps" { 8.0 } else { 1.0 };
            *out = rate(prev.c.get(i).copied().flatten(), reading.c.get(i).copied().flatten(), dt, scale);
        }
        if let Some(k) = self.series.get_mut(key) {
            for t in prev.t + 1..=now {
                k.rrd.update(t, &v);
            }
        }
    }

    fn sample_resources(&mut self, now: u64, r: Resources) {
        let Some((t, prev)) = self.resources.replace((now, r)) else {
            return;
        };
        if now <= t {
            self.resources = Some((t, prev));
            return;
        }
        let dt = now - t;
        if dt > HEARTBEAT {
            return;
        }
        let total = r.cpu_total.checked_sub(prev.cpu_total).filter(|d| *d > 0);
        let busy = r.cpu_busy.checked_sub(prev.cpu_busy);
        let cpu = match (busy, total) {
            (Some(b), Some(t)) => (b as f64 * 100.0 / t as f64).min(100.0) as f32,
            _ => f32::NAN,
        };
        let memory = if r.mem_total > 0 {
            r.mem_total.saturating_sub(r.mem_available) as f32
        } else {
            f32::NAN
        };
        let conntrack = r.conntrack.map_or(f32::NAN, |c| c as f32);
        if let Some(k) = self.series.get_mut(SYSTEM) {
            for s in t + 1..=now {
                k.rrd.update(s, &[cpu, memory, conntrack]);
            }
        }
    }

    /// Status for `system.graph.print`.
    pub fn status(&self, cfg: &Graphing) -> serde_json::Value {
        let kept: Vec<_> = self
            .series
            .iter()
            .map(|(k, v)| {
                json!({
                    "series": k,
                    "bytes": v.rrd.size(),
                    "last": v.rrd.last(),
                    "kept": v.unkept_since.is_none(),
                })
            })
            .collect();
        json!({
            "series": kept,
            "refused": self.refused,
            "refused_queues": self.refused_queues,
            "memory_bytes": self.memory_bytes(),
            "max_memory_bytes": cfg.max_memory_bytes(),
            "series_bytes": Rrd::size_for(INTERFACE_SOURCES.len()),
            "queue_series_bytes": Rrd::size_for(QUEUE_SOURCES.len()),
            "tiers": rrd::TIERS.iter().map(|t| json!({"step": t.step, "rows": t.rows, "window": t.window()})).collect::<Vec<_>>(),
            "disk": self.disk,
        })
    }
}

/// `(now - prev) / dt × scale`, unknown when either is missing, the
/// counter went down, or the rate is impossible.
fn rate(prev: Option<u64>, now: Option<u64>, dt: u64, scale: f64) -> f32 {
    match (prev, now) {
        (Some(p), Some(n)) if n >= p && dt > 0 => {
            let r = (n - p) as f64 * scale / dt as f64;
            if r > MAX_RATE { f32::NAN } else { r as f32 }
        }
        _ => f32::NAN,
    }
}

impl Session {
    /// One second of graph history from the tick's link poll (`live`).
    pub(crate) fn graph_sample(&mut self, live: &[LinkState]) {
        let cfg = &self.store().running().system.graphing;
        if !cfg.enabled {
            return;
        }
        let cfg = cfg.clone();
        let Some(now) = self.now() else { return };
        let resources = if cfg.resources {
            self.hal_mut().resources()
        } else {
            None
        };
        // Link speeds the alerts need (no capacity of their own), asked
        // once a minute, not every second.
        let stale: Vec<IfName> = {
            let known = self.ext::<GraphDb>().map(|d| &d.speeds);
            cfg.alerts
                .iter()
                .filter(|a| !a.disabled && a.capacity_mbps.is_none())
                .map(|a| &a.interface)
                .filter(|n| {
                    known
                        .and_then(|k| k.get(*n))
                        .is_none_or(|(at, _)| now.saturating_sub(*at) >= alert::SPEED_EVERY)
                })
                .cloned()
                .collect()
        };
        let speeds: Vec<(IfName, (u64, Option<u32>))> = stale
            .into_iter()
            .map(|n| {
                let s = self.hal_mut().ethernet_monitor(&n).ok().and_then(|m| m.speed_mbps);
                (n, (now, s))
            })
            .collect();
        // The history is taken out of the session while the store is
        // borrowed for the interface list.
        let mut db = self
            .ext_mut::<GraphDb>()
            .map(std::mem::take)
            .unwrap_or_default();
        let running = self.store().running();
        let by_name: BTreeMap<&IfName, &LinkState> = live.iter().map(|l| (&l.name, l)).collect();
        let mut links: Vec<Link<'_>> = running
            .interfaces
            .values()
            .map(|i| Link {
                name: &i.name,
                kind: i.kind.label(),
                live: by_name.get(&i.name).copied(),
            })
            .collect();
        links.extend(
            live.iter()
                .filter(|l| !running.interfaces.contains_key(&l.name))
                .map(|l| Link {
                    name: &l.name,
                    kind: l.kind.as_str(),
                    live: Some(l),
                }),
        );
        let log = db.sample(now, &cfg, &links, resources);
        drop(links);
        db.speeds.extend(speeds);
        let speeds = std::mem::take(&mut db.speeds);
        let alerts = db.judge_alerts(&cfg.alerts, &speeds);
        db.speeds = speeds;
        if let Some(slot) = self.ext_mut::<GraphDb>() {
            *slot = db;
        }
        for (topic, (warning, line)) in log
            .into_iter()
            .map(|l| ("system", l))
            .chain(alerts.into_iter().map(|l| ("interface", l)))
        {
            let level = if warning { "warning" } else { "info" };
            self.log_event(&[topic, level], "graphing", line, serde_json::Value::Null);
        }
    }
}

#[cfg(test)]
mod tests;
