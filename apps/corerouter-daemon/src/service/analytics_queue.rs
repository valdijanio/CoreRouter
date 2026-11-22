//! The ClickHouse exporter's queue (G4.4f): rows wait here, per table,
//! until a batch is full or old enough; sealed batches (compressed) wait
//! for the server. Both are bounded:
//!
//! - memory: `queue_size` MiB for the open rows and the sealed batches
//!   together;
//! - disk (optional, `disk_queue` MiB in the daemon's `--analytics-spool`
//!   directory): when memory is full, the oldest sealed batch moves there,
//!   and batches on disk survive a restart of the daemon.
//!
//! When both are full the **oldest** batch is dropped and counted (Fluent
//! Bit's `storage.total_limit_size` does the same): during an outage the
//! freshest data is the most useful once the server is back, and nothing
//! ever blocks the router. A single row larger than the whole memory queue
//! is dropped on arrival.
//!
//! Order: batches on disk are always older than those in memory (only the
//! oldest in memory move to disk), so the next batch to send is the first
//! on disk, else the first in memory.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use corerouter_model::analytics::{Compression, Table, TableCounters};

/// Extension of a batch file in the spool.
const EXT: &str = "batch";
/// Files of the spool read at start at most (a hostile or broken directory).
const MAX_FILES: usize = 100_000;

/// The limits the config sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    pub batch_rows: u64,
    pub flush: Duration,
    pub mem_bytes: usize,
    pub disk_bytes: u64,
    pub compression: Compression,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            batch_rows: 10_000,
            flush: Duration::from_secs(10),
            mem_bytes: 16 << 20,
            disk_bytes: 0,
            compression: Compression::Gzip,
        }
    }
}

/// A sealed batch: the INSERT body of one table.
#[derive(Debug, Clone)]
pub(crate) struct Batch {
    /// Rising number (the order), unique within this spool.
    pub seq: u64,
    /// Random: the `insert_deduplication_token`, so a retry after a lost
    /// answer is not stored twice.
    pub id: u64,
    pub table: Table,
    pub rows: u64,
    pub compression: Compression,
    /// `None` while it is on disk and not loaded.
    pub body: Option<Arc<Vec<u8>>>,
    /// Bytes of the body (in memory or on disk).
    pub size: u64,
}

impl Batch {
    fn file_name(&self) -> String {
        format!(
            "{:016x}-{:016x}-{}-{}-{}.{EXT}",
            self.seq,
            self.id,
            self.table.name(),
            self.rows,
            self.compression.as_str()
        )
    }

    /// A spool file name back to a batch (without body); `None` for any
    /// other file.
    fn from_file_name(name: &str, size: u64) -> Option<Self> {
        let stem = name.strip_suffix(&format!(".{EXT}"))?;
        let mut parts = stem.splitn(5, '-');
        let seq = u64::from_str_radix(parts.next()?, 16).ok()?;
        let id = u64::from_str_radix(parts.next()?, 16).ok()?;
        let table_name = parts.next()?;
        let table = Table::ALL.into_iter().find(|t| t.name() == table_name)?;
        let rows = parts.next()?.parse().ok()?;
        let compression = match parts.next()? {
            "gzip" => Compression::Gzip,
            "none" => Compression::None,
            _ => return None,
        };
        Some(Self {
            seq,
            id,
            table,
            rows,
            compression,
            body: None,
            size,
        })
    }
}

#[derive(Debug)]
struct Open {
    rows: u64,
    buf: Vec<u8>,
    since: Instant,
}

/// Random 64 bits (the batch id).
fn random_id() -> u64 {
    let n = crate::node_id::random().0;
    let mut b = [0u8; 8];
    b.copy_from_slice(n.get(..8).unwrap_or(&[0; 8]));
    u64::from_be_bytes(b)
}

pub(crate) fn compress(raw: &[u8], c: Compression) -> Vec<u8> {
    match c {
        Compression::None => raw.to_vec(),
        Compression::Gzip => {
            // Level 1: most of the gain at a fraction of the CPU (G4.4f, perf).
            let mut e = flate2::write::GzEncoder::new(Vec::with_capacity(raw.len() / 6), flate2::Compression::fast());
            match e.write_all(raw).and_then(|()| e.finish()) {
                Ok(v) => v,
                // Writing into a Vec does not fail; if it did, send it plain.
                Err(_) => raw.to_vec(),
            }
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct Queue {
    limits: Limits,
    open: BTreeMap<Table, Open>,
    ready: VecDeque<Batch>,
    disk: VecDeque<Batch>,
    mem: usize,
    disk_used: u64,
    spool: Option<PathBuf>,
    seq: u64,
    pub counters: BTreeMap<Table, TableCounters>,
    /// The last error of the spool (a full or read-only disk).
    pub spool_error: Option<String>,
}

impl Queue {
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    /// Use `dir` as the spool, taking the batches already there (a previous
    /// run's). The directory is created private (0700): the rows carry logs.
    pub(crate) fn open_spool(&mut self, dir: &Path) -> Result<(), String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let mut found = Vec::new();
        for entry in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?.take(MAX_FILES) {
            let Ok(entry) = entry else { continue };
            let Ok(meta) = entry.metadata() else { continue };
            let name = entry.file_name();
            if let (true, Some(b)) = (meta.is_file(), name.to_str().and_then(|n| Batch::from_file_name(n, meta.len()))) {
                found.push(b);
            } else if name.to_str().is_some_and(|n| n.ends_with(".tmp")) {
                let _ = fs::remove_file(entry.path());
            }
        }
        found.sort_by_key(|b| b.seq);
        self.seq = found.last().map_or(self.seq, |b| b.seq.saturating_add(1)).max(self.seq);
        self.disk_used = found.iter().map(|b| b.size).sum();
        self.disk = found.into();
        self.spool = Some(dir.to_path_buf());
        self.trim_disk(0);
        Ok(())
    }

    pub(crate) fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
        self.trim_disk(0);
        self.enforce();
    }

    fn count(&mut self, table: Table) -> &mut TableCounters {
        self.counters.entry(table).or_default()
    }

    fn drop_rows(&mut self, table: Table, rows: u64) {
        let c = self.count(table);
        c.dropped = c.dropped.saturating_add(rows);
    }

    /// One encoded row (a JSON line) for `table`.
    pub(crate) fn push(&mut self, table: Table, row: &[u8], now: Instant) {
        if row.len() > self.limits.mem_bytes {
            self.drop_rows(table, 1);
            return;
        }
        let open = self.open.entry(table).or_insert_with(|| Open {
            rows: 0,
            buf: Vec::new(),
            since: now,
        });
        if open.rows == 0 {
            open.since = now;
        }
        open.buf.extend_from_slice(row);
        open.rows += 1;
        let full = open.rows >= self.limits.batch_rows;
        self.mem += row.len();
        if full {
            self.seal(table);
        }
        self.enforce();
    }

    /// Seal the open rows of `table` into a batch.
    fn seal(&mut self, table: Table) {
        let Some(open) = self.open.remove(&table) else {
            return;
        };
        self.mem = self.mem.saturating_sub(open.buf.len());
        if open.rows == 0 {
            return;
        }
        let body = compress(&open.buf, self.limits.compression);
        self.mem += body.len();
        let b = Batch {
            seq: self.seq,
            id: random_id(),
            table,
            rows: open.rows,
            compression: self.limits.compression,
            size: body.len() as u64,
            body: Some(Arc::new(body)),
        };
        self.seq = self.seq.saturating_add(1);
        self.ready.push_back(b);
    }

    /// Seal what waited `flush` or longer (or everything, `all`).
    pub(crate) fn tick(&mut self, now: Instant, all: bool) {
        let due: Vec<Table> = self
            .open
            .iter()
            .filter(|(_, o)| all || now.saturating_duration_since(o.since) >= self.limits.flush)
            .map(|(t, _)| *t)
            .collect();
        for t in due {
            self.seal(t);
        }
        self.enforce();
    }

    /// Memory back under its limit: oldest sealed batches to disk, or
    /// dropped; open rows sealed (compressed) when they alone exceed it.
    fn enforce(&mut self) {
        while self.mem > self.limits.mem_bytes {
            if let Some(b) = self.ready.pop_front() {
                self.mem = self.mem.saturating_sub(usize::try_from(b.size).unwrap_or(usize::MAX));
                self.spill(b);
                continue;
            }
            let Some(biggest) = self.open.iter().max_by_key(|(_, o)| o.buf.len()).map(|(t, _)| *t) else {
                break;
            };
            self.seal(biggest);
        }
    }

    /// A batch out of memory: onto disk when there is a spool with room
    /// (oldest disk batches dropped to make it), else dropped.
    fn spill(&mut self, mut b: Batch) {
        let (Some(dir), Some(body)) = (self.spool.clone(), b.body.take()) else {
            self.drop_rows(b.table, b.rows);
            return;
        };
        if self.limits.disk_bytes < b.size {
            self.drop_rows(b.table, b.rows);
            return;
        }
        self.trim_disk(b.size);
        let path = dir.join(b.file_name());
        let tmp = dir.join(format!("{}.tmp", b.file_name()));
        let written = fs::write(&tmp, body.as_slice()).and_then(|()| fs::rename(&tmp, &path));
        match written {
            Ok(()) => {
                self.spool_error = None;
                self.disk_used += b.size;
                self.disk.push_back(b);
            }
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                self.spool_error = Some(format!("spool {}: {e}", dir.display()));
                self.drop_rows(b.table, b.rows);
            }
        }
    }

    /// Drop the oldest disk batches until `room` more bytes fit.
    fn trim_disk(&mut self, room: u64) {
        while self.disk_used.saturating_add(room) > self.limits.disk_bytes {
            let Some(b) = self.disk.pop_front() else {
                break;
            };
            self.disk_used = self.disk_used.saturating_sub(b.size);
            self.remove_file(&b);
            self.drop_rows(b.table, b.rows);
        }
    }

    fn remove_file(&self, b: &Batch) {
        if let Some(dir) = &self.spool {
            let _ = fs::remove_file(dir.join(b.file_name()));
        }
    }

    /// The next batch to send (its body loaded when it is on disk). A file
    /// that cannot be read is dropped and counted.
    pub(crate) fn front(&mut self) -> Option<Batch> {
        while let Some(b) = self.disk.front_mut() {
            if b.body.is_some() {
                return Some(b.clone());
            }
            let read = self
                .spool
                .as_ref()
                .map(|d| d.join(b.file_name()))
                .ok_or_else(|| "no spool".to_owned())
                .and_then(|p| fs::read(&p).map_err(|e| e.to_string()));
            match read {
                Ok(body) => {
                    b.body = Some(Arc::new(body));
                    return Some(b.clone());
                }
                Err(_) => {
                    if let Some(b) = self.disk.pop_front() {
                        self.disk_used = self.disk_used.saturating_sub(b.size);
                        self.drop_rows(b.table, b.rows);
                    }
                }
            }
        }
        self.ready.front().cloned()
    }

    /// Batch `seq` is done: accepted by the server (`sent`) or refused for
    /// good (dropped and counted).
    pub(crate) fn done(&mut self, seq: u64, sent: bool) {
        let b = if self.disk.front().is_some_and(|b| b.seq == seq) {
            let b = self.disk.pop_front();
            if let Some(b) = &b {
                self.disk_used = self.disk_used.saturating_sub(b.size);
                self.remove_file(b);
            }
            b
        } else if self.ready.front().is_some_and(|b| b.seq == seq) {
            let b = self.ready.pop_front();
            if let Some(b) = &b {
                self.mem = self.mem.saturating_sub(usize::try_from(b.size).unwrap_or(usize::MAX));
            }
            b
        } else {
            None
        };
        if let Some(b) = b {
            if sent {
                let c = self.count(b.table);
                c.sent = c.sent.saturating_add(b.rows);
            } else {
                self.drop_rows(b.table, b.rows);
            }
        }
    }

    /// Stopping: seal everything and, with a spool, write what is in memory
    /// to disk so the next run sends it.
    pub(crate) fn persist(&mut self) {
        self.tick(Instant::now(), true);
        if self.spool.is_none() {
            return;
        }
        while let Some(b) = self.ready.pop_front() {
            self.mem = self.mem.saturating_sub(usize::try_from(b.size).unwrap_or(usize::MAX));
            self.spill(b);
        }
    }

    pub(crate) fn queued_rows(&self) -> u64 {
        self.open.values().map(|o| o.rows).sum::<u64>() + self.ready.iter().map(|b| b.rows).sum::<u64>()
    }

    pub(crate) fn queued_bytes(&self) -> u64 {
        self.mem as u64
    }

    pub(crate) fn disk_rows(&self) -> u64 {
        self.disk.iter().map(|b| b.rows).sum()
    }

    pub(crate) fn disk_bytes(&self) -> u64 {
        self.disk_used
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.counters.values().map(|c| c.dropped).sum()
    }

    pub(crate) fn sent(&self) -> u64 {
        self.counters.values().map(|c| c.sent).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    fn limits(batch_rows: u64, mem_bytes: usize, disk_bytes: u64) -> Limits {
        Limits {
            batch_rows,
            flush: Duration::from_secs(10),
            mem_bytes,
            disk_bytes,
            compression: Compression::None,
        }
    }

    fn row(i: u64) -> Vec<u8> {
        format!("{{\"n\":{i:08}}}\n").into_bytes()
    }

    fn body(b: &Batch) -> String {
        String::from_utf8(b.body.as_ref().unwrap().to_vec()).unwrap()
    }

    #[test]
    fn rows_become_batches_by_count_and_by_age() {
        let t0 = Instant::now();
        let mut q = Queue::new(limits(3, 1 << 20, 0));
        for i in 0..4 {
            q.push(Table::Logs, &row(i), t0);
        }
        let b = q.front().unwrap();
        assert_eq!((b.rows, b.table), (3, Table::Logs));
        assert_eq!(body(&b).lines().count(), 3);
        assert_eq!(q.queued_rows(), 4, "3 sealed + 1 open");
        q.done(b.seq, true);
        assert!(q.front().is_none(), "the 4th waits for its batch");
        q.tick(t0 + Duration::from_secs(9), false);
        assert!(q.front().is_none());
        q.tick(t0 + Duration::from_secs(10), false);
        let b = q.front().unwrap();
        assert_eq!(b.rows, 1);
        q.done(b.seq, true);
        assert_eq!(q.counters[&Table::Logs].sent, 4);
        assert_eq!(q.queued_bytes(), 0);
    }

    #[test]
    fn a_failed_send_keeps_the_batch_for_the_retry() {
        let t0 = Instant::now();
        let mut q = Queue::new(limits(2, 1 << 20, 0));
        q.push(Table::Metrics, &row(1), t0);
        q.push(Table::Metrics, &row(2), t0);
        let first = q.front().unwrap();
        // The server did not answer: nothing is called, it stays first.
        let again = q.front().unwrap();
        assert_eq!((again.seq, again.id), (first.seq, first.id), "same dedup token");
        q.done(again.seq, false);
        assert_eq!(q.counters[&Table::Metrics].dropped, 2, "refused for good");
        assert!(q.front().is_none());
    }

    #[test]
    fn a_full_memory_queue_drops_the_oldest_and_counts() {
        let t0 = Instant::now();
        let r = row(0).len();
        // Room for 4 rows; batches of 2.
        let mut q = Queue::new(limits(2, 4 * r, 0));
        for i in 0..10 {
            q.push(Table::Flows, &row(i), t0);
        }
        assert!(q.queued_bytes() <= (4 * r) as u64);
        assert_eq!(q.dropped(), 6);
        let b = q.front().unwrap();
        assert!(body(&b).contains("00000006"), "the newest stay: {}", body(&b));
        // Bigger than the whole queue: dropped on arrival.
        q.push(Table::Logs, &vec![b'x'; 5 * r], t0);
        assert_eq!(q.counters[&Table::Logs].dropped, 1);
    }

    #[test]
    fn the_spool_takes_the_overflow_keeps_order_and_survives_a_restart() {
        let dir = std::env::temp_dir().join(format!("cr-analytics-spool-{}", random_id()));
        let t0 = Instant::now();
        let r = row(0).len();
        let mut q = Queue::new(limits(2, 2 * r, (6 * r) as u64));
        q.open_spool(&dir).unwrap();
        for i in 0..10 {
            q.push(Table::NatEvents, &row(i), t0);
        }
        // 2 rows in memory, 6 on disk (3 files), the oldest 2 dropped.
        assert_eq!(q.disk_rows(), 6);
        assert_eq!(q.disk_bytes(), (6 * r) as u64);
        assert_eq!(q.dropped(), 2);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 3);
        // Oldest first: the disk.
        let b = q.front().unwrap();
        assert!(body(&b).contains("00000002"), "{}", body(&b));
        q.done(b.seq, true);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);
        // Stop: memory goes to disk; a new queue finds everything, in order.
        q.persist();
        drop(q);
        let mut q = Queue::new(limits(2, 2 * r, (6 * r) as u64));
        q.open_spool(&dir).unwrap();
        assert_eq!(q.disk_rows(), 6);
        let mut seen = Vec::new();
        while let Some(b) = q.front() {
            seen.extend(body(&b).lines().map(str::to_owned));
            q.done(b.seq, true);
        }
        let want: Vec<String> = (4..10).map(|i| String::from_utf8(row(i)).unwrap().trim().to_owned()).collect();
        assert_eq!(seen, want);
        // New batches number after the old ones.
        q.push(Table::Logs, &row(1), t0);
        q.push(Table::Logs, &row(2), t0);
        assert!(q.front().unwrap().seq > 4);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn hostile_spool_files_are_ignored() {
        let dir = std::env::temp_dir().join(format!("cr-analytics-hostile-{}", random_id()));
        fs::create_dir_all(&dir).unwrap();
        for n in ["x.batch", "zz-00-logs-1-none.batch", "0000000000000001-0000000000000002-users-1-none.batch", "a.tmp"] {
            fs::write(dir.join(n), b"x").unwrap();
        }
        let mut q = Queue::new(limits(2, 1024, 1024));
        q.open_spool(&dir).unwrap();
        assert_eq!(q.disk_rows(), 0);
        assert!(!dir.join("a.tmp").exists(), "half-written files are removed");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn gzip_bodies_decompress_to_the_rows() {
        let mut l = limits(100, 1 << 20, 0);
        l.compression = Compression::Gzip;
        let mut q = Queue::new(l);
        let t0 = Instant::now();
        for i in 0..100 {
            q.push(Table::Logs, &row(i), t0);
        }
        let b = q.front().unwrap();
        assert_eq!(b.compression, Compression::Gzip);
        let mut out = String::new();
        flate2::read::GzDecoder::new(b.body.as_ref().unwrap().as_slice())
            .read_to_string(&mut out)
            .unwrap();
        assert_eq!(out.lines().count(), 100);
        assert!(b.size < (100 * row(0).len()) as u64 / 2);
    }
}
