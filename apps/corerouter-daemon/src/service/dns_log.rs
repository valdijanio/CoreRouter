//! The DNS query log's writer (G4.1zd, `ip.dns.log`): the queries the LAN
//! forwarder hands over ([`sink`], filled by `dns_server`) go to
//! `<config-dir>/dns-log/<first unix ms>.crql`, in the block format of
//! `corerouter_proto_dns::querylog::format`.
//!
//! One thread, "dns-log", under the supervisor. Every [`TICK`] it takes
//! what the answering threads queued (no lock of theirs is waited on),
//! anonymises each client as `client_address` says, and adds the queries to
//! the open block; a block closes at 65 536 queries or [`BLOCK_AGE`] and
//! goes to the end of the open segment in one write. A segment closes at an
//! hour (less when `max_age_hours` is short) or at an eighth of the
//! ceiling, so the oldest hour can go whole.
//!
//! Like the `disk` log action (G4.6g): writes reach the page cache at once
//! and the disk with an `fdatasync` every [`SYNC_EVERY`] (flash wears with
//! each one; a power cut loses at most that and the open block), and the
//! log never takes the room the config needs: the files stay under
//! `max_size_mib` and their share of `/config`
//! ([`corerouter_engine::config_disk::dns_log_budget`]), the oldest going
//! first, and before a write what the next config save needs must stay
//! free ([`corerouter_engine::config_disk::keep_free`]). When deleting old
//! segments does not make room, the block is dropped and counted.
//!
//! Reading (`ip.dns.log.search`, `export`) happens on the caller's thread
//! with only a copy of the index taken under the store's lock: the files
//! are append-only, and a block is in the index only once it is whole on
//! disk. Blocks are decoded a few at a time in parallel ([`READERS`]).
//! `clear` by client or time rewrites the closed segments into new files
//! (renamed over the old ones) outside the lock, after closing the open one.
//!
//! Retention applies with the log off too: turning it off does not keep
//! what it wrote forever. A stop closes the open block; a daemon killed
//! loses at most that block (≤ [`BLOCK_AGE`]), what reached the page cache
//! stays.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_engine::config_disk::{ConfigDisk, dns_log_budget, keep_free};
use corerouter_engine::dns_log::{Cleared, DnsLogBackend, Found, LogStatus};
use corerouter_engine::lock;
use corerouter_model::dns_log::DnsLog;
use corerouter_proto_dns::querylog::format::{self, BlockBuilder, HEADER, Header, Mode, Record};
use corerouter_proto_dns::querylog::{Anon, ClientMatch, Filter, Sink, decode_batch};
use corerouter_sysupdate::state::free_bytes;
use serde_json::json;

pub(crate) const SERVICE: super::Service = super::Service {
    name: "dns-log",
    flags: &[],
    topic: "dns",
    enable: "ip.dns.log.set enabled=yes acknowledge=marco-civil-art14",
    depends: &[],
    start,
};

/// The files' directory under `--config-dir`.
pub(crate) const DIR: &str = "dns-log";
const EXT: &str = "crql";
/// How often the queue is drained (G0.30: shorter in the unit tests).
const TICK: Duration = if cfg!(test) {
    Duration::from_millis(20)
} else {
    Duration::from_millis(200)
};
/// A block closes this old (a quiet router's queries reach the file).
const BLOCK_AGE: Duration = Duration::from_secs(10);
/// Between two `fdatasync`s.
const SYNC_EVERY: Duration = Duration::from_secs(60);
/// A segment holds at most an hour…
const SEGMENT_MS: u64 = 3_600_000;
/// …and at most this much, and an eighth of the ceiling.
const SEGMENT_MAX: u64 = 64 << 20;
const SEGMENT_MIN: u64 = 1 << 20;
/// Blocks decoded at once by a search.
const READERS: usize = 8;

/// Where the forwarder's threads put their queries (one per daemon; no
/// reference count is touched on the hot path).
pub(crate) fn sink() -> &'static Arc<Sink> {
    static SINK: OnceLock<Arc<Sink>> = OnceLock::new();
    SINK.get_or_init(|| Arc::new(Sink::default()))
}

/// Unix time now, in ms.
pub(crate) fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// What is free on the disk of a directory.
type Free = Box<dyn Fn(&Path) -> Option<u64> + Send>;

/// One block of a segment, as the index knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Block {
    offset: u64,
    header: Header,
}

#[derive(Debug, Clone)]
struct Segment {
    path: PathBuf,
    bytes: u64,
    blocks: Vec<Block>,
}

impl Segment {
    fn last_ms(&self) -> Option<u64> {
        self.blocks.iter().map(|b| b.header.last_ms).max()
    }

    fn first_ms(&self) -> Option<u64> {
        self.blocks.iter().map(|b| b.header.first_ms).min()
    }

    fn queries(&self) -> u64 {
        self.blocks.iter().map(|b| u64::from(b.header.count)).sum()
    }
}

/// The files and the open block.
struct Store {
    dir: PathBuf,
    capacity: Option<u64>,
    cfg: DnsLog,
    /// By the segment's name (its first query, unix ms).
    segments: BTreeMap<u64, Segment>,
    /// The segment being appended to, and when it started.
    open: Option<(u64, File)>,
    block: BlockBuilder,
    block_since: Instant,
    anon: Anon,
    key_since: Instant,
    dirty: bool,
    last_sync: Instant,
    written: u64,
    written_bytes: u64,
    dropped_disk: u64,
    rotated: u64,
    no_room: bool,
    error: Option<String>,
    free: Free,
}

fn new_key() -> [u8; 16] {
    let mut k = [0u8; 16];
    if getrandom::fill(&mut k).is_err() {
        // No randomness: a key from the clock still unlinks periods (it is
        // never written anywhere).
        k[..8].copy_from_slice(&unix_ms().to_le_bytes());
    }
    k
}

/// The blocks of the file at `path` and where each starts, up to the first
/// one that does not read (only headers are read).
fn index_file(path: &Path) -> io::Result<(u64, Vec<Block>)> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    let mut blocks = Vec::new();
    let mut at = 0u64;
    let mut head = [0u8; HEADER];
    while at.saturating_add(HEADER as u64) <= len {
        f.seek(SeekFrom::Start(at))?;
        if f.read_exact(&mut head).is_err() {
            break;
        }
        let Ok(h) = format::read_header(&head) else { break };
        let end = at.saturating_add(h.len() as u64);
        if end > len {
            break;
        }
        blocks.push(Block { offset: at, header: h });
        at = end;
    }
    Ok((len, blocks))
}

fn read_block(f: &mut File, b: &Block) -> Option<(Header, Vec<Record>)> {
    let mut buf = vec![0u8; b.header.len()];
    f.seek(SeekFrom::Start(b.offset)).ok()?;
    f.read_exact(&mut buf).ok()?;
    format::decode_block(&buf).ok()
}

fn segment_name(path: &Path) -> Option<u64> {
    let name = path.file_name()?.to_str()?;
    let stem = name.strip_suffix(".crql")?;
    if stem.is_empty() || !stem.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    stem.parse().ok()
}

impl Store {
    fn open(dir: PathBuf, cfg: DnsLog, capacity: Option<u64>, free: Free) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        }
        let anon = Anon::new(&cfg, new_key());
        let mut s = Self {
            dir,
            capacity,
            block: BlockBuilder::new(anon.mode()),
            anon,
            cfg,
            segments: BTreeMap::new(),
            open: None,
            block_since: Instant::now(),
            key_since: Instant::now(),
            dirty: false,
            last_sync: Instant::now(),
            written: 0,
            written_bytes: 0,
            dropped_disk: 0,
            rotated: 0,
            no_room: false,
            error: None,
            free,
        };
        s.scan();
        Ok(s)
    }

    /// Learn what is on disk (at start).
    fn scan(&mut self) {
        self.segments.clear();
        for e in fs::read_dir(&self.dir).into_iter().flatten().flatten() {
            let path = e.path();
            if let Some(name) = segment_name(&path) {
                match index_file(&path) {
                    Ok((bytes, blocks)) => {
                        self.segments.insert(name, Segment { path, bytes, blocks });
                    }
                    Err(e) => log::warn!("dns-log: {}: {e}", path.display()),
                }
            } else if path.extension().is_some_and(|x| x == "tmp") {
                // A clear that died half-way: the original is still there.
                let _ = fs::remove_file(&path);
            }
        }
    }

    fn budget(&self) -> u64 {
        dns_log_budget(self.capacity, self.cfg.max_size_mib)
    }

    fn total(&self) -> u64 {
        self.segments.values().map(|s| s.bytes).sum()
    }

    /// Settings from the running config. A new way of writing clients
    /// starts a new block (a block has one).
    fn configure(&mut self, cfg: &DnsLog) {
        if *cfg == self.cfg {
            return;
        }
        let anon_changed = cfg.client_address != self.cfg.client_address
            || cfg.ipv4_prefix != self.cfg.ipv4_prefix
            || cfg.ipv6_prefix != self.cfg.ipv6_prefix;
        self.cfg = cfg.clone();
        if anon_changed {
            self.close_block(unix_ms());
            self.anon = Anon::new(&self.cfg, new_key());
            self.key_since = Instant::now();
            self.block = BlockBuilder::new(self.anon.mode());
        }
    }

    /// `hashed`: a new key every `salt_rotation_hours`; the old one is
    /// forgotten (the block written with it closes first).
    fn rotate_key(&mut self, now_ms: u64) {
        let every = Duration::from_secs(u64::from(self.cfg.salt_rotation_hours) * 3600);
        if self.key_since.elapsed() >= every {
            self.close_block(now_ms);
            self.anon = Anon::new(&self.cfg, new_key());
            self.key_since = Instant::now();
        }
    }

    /// Queries from the sink into the open block.
    fn take(&mut self, batches: Vec<corerouter_proto_dns::querylog::Batch>) {
        let now_ms = unix_ms();
        if self.anon.mode() == Mode::Hashed {
            self.rotate_key(now_ms);
        }
        for b in batches {
            for (e, latency_us) in decode_batch(&b.bytes) {
                if self.block.is_empty() {
                    self.block_since = Instant::now();
                }
                self.block.push(&Record {
                    at_ms: e.at_ms,
                    client: self.anon.client(e.client),
                    name: e.name,
                    qtype: e.qtype,
                    rcode: e.rcode,
                    flags: e.flags,
                    by: e.by,
                    ede: e.ede,
                    latency_us,
                });
                if self.block.full() {
                    self.close_block(now_ms);
                }
            }
        }
        if !self.block.is_empty() && self.block_since.elapsed() >= BLOCK_AGE {
            self.close_block(now_ms);
        }
    }

    fn segment_ms(&self) -> u64 {
        SEGMENT_MS.min(u64::from(self.cfg.max_age_hours) * 3_600_000 / 4).max(60_000)
    }

    fn segment_max(&self) -> u64 {
        (self.budget() / 8).clamp(SEGMENT_MIN, SEGMENT_MAX)
    }

    /// The open block goes to the end of the open segment (a new one when
    /// it is old or large).
    fn close_block(&mut self, now_ms: u64) {
        let count = u64::from(self.block.count());
        let first = self.block.first_ms();
        let Some(bytes) = self.block.finish() else { return };
        let len = bytes.len() as u64;
        if !self.make_room(len) {
            self.dropped_disk = self.dropped_disk.saturating_add(count);
            self.no_room = true;
            return;
        }
        self.no_room = false;
        let roll = match &self.open {
            None => true,
            Some((start, _)) => {
                now_ms.saturating_sub(*start) >= self.segment_ms()
                    || self.segments.get(start).is_none_or(|s| s.bytes.saturating_add(len) > self.segment_max())
            }
        };
        if roll && let Err(e) = self.roll(first) {
            self.error = Some(format!("{}: {e}", self.dir.display()));
            self.dropped_disk = self.dropped_disk.saturating_add(count);
            return;
        }
        let Some((start, file)) = self.open.as_mut() else { return };
        let start = *start;
        let Some(seg) = self.segments.get_mut(&start) else { return };
        let offset = seg.bytes;
        match file.write_all(&bytes) {
            Ok(()) => {
                if let Ok(header) = format::read_header(&bytes) {
                    seg.blocks.push(Block { offset, header });
                }
                seg.bytes = seg.bytes.saturating_add(len);
                self.dirty = true;
                self.written = self.written.saturating_add(count);
                self.written_bytes = self.written_bytes.saturating_add(len);
                self.error = None;
            }
            Err(e) => {
                // What got there is taken back; a torn block would end the
                // file for readers.
                if file.set_len(offset).is_err() {
                    self.open = None;
                }
                self.error = Some(format!("write: {e}"));
                self.dropped_disk = self.dropped_disk.saturating_add(count);
            }
        }
    }

    /// A new segment named after its first query.
    fn roll(&mut self, first_ms: u64) -> io::Result<()> {
        self.sync();
        let mut name = first_ms;
        while self.segments.contains_key(&name) {
            name = name.saturating_add(1);
        }
        let path = self.dir.join(format!("{name}.{EXT}"));
        let mut o = OpenOptions::new();
        o.create_new(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // The owner only: who asked what is personal data.
            o.mode(0o600);
        }
        let f = o.open(&path)?;
        self.segments.insert(name, Segment { path, bytes: 0, blocks: Vec::new() });
        self.open = Some((name, f));
        Ok(())
    }

    /// What is free for the log past what must stay free for the config.
    fn room(&self) -> Option<u64> {
        let capacity = self.capacity?;
        let free = (self.free)(&self.dir)?;
        let slot = self
            .dir
            .parent()
            .and_then(|p| fs::metadata(p.join("running.json")).ok())
            .map_or(0, |m| m.len());
        Some(free.saturating_sub(keep_free(capacity, slot)))
    }

    /// Room for `need` bytes under the ceiling and the free space, the
    /// oldest segment going first (never the open one while others exist).
    fn make_room(&mut self, need: u64) -> bool {
        loop {
            let over_cap = self.total().saturating_add(need) > self.budget();
            let over_free = self.room().is_some_and(|r| r < need);
            if !over_cap && !over_free {
                return true;
            }
            if !self.drop_oldest() {
                return false;
            }
        }
    }

    fn drop_oldest(&mut self) -> bool {
        let Some((&oldest, _)) = self.segments.iter().next() else {
            return false;
        };
        if self.open.as_ref().is_some_and(|(o, _)| *o == oldest) {
            // The only segment left is the open one: start over.
            self.open = None;
        }
        self.remove(oldest);
        true
    }

    fn remove(&mut self, name: u64) {
        if let Some(s) = self.segments.remove(&name) {
            if self.open.as_ref().is_some_and(|(o, _)| *o == name) {
                self.open = None;
            }
            if let Err(e) = fs::remove_file(&s.path)
                && e.kind() != io::ErrorKind::NotFound
            {
                self.error = Some(format!("remove {}: {e}", s.path.display()));
            }
            self.rotated = self.rotated.saturating_add(1);
        }
    }

    /// Age and size, every tick (also with the log off).
    fn retain(&mut self, now_ms: u64) {
        let keep_from = now_ms.saturating_sub(u64::from(self.cfg.max_age_hours) * 3_600_000);
        let old: Vec<u64> = self
            .segments
            .iter()
            .filter(|(name, s)| {
                // An empty segment that is not open (a failed write) goes too.
                let open = self.open.as_ref().is_some_and(|(o, _)| o == *name);
                !open && s.last_ms().is_none_or(|l| l < keep_from)
            })
            .map(|(n, _)| *n)
            .collect();
        for n in old {
            self.remove(n);
        }
        while self.total() > self.budget() && self.segments.len() > 1 {
            self.drop_oldest();
        }
    }

    fn sync(&mut self) {
        if self.dirty
            && let Some((_, f)) = &self.open
            && let Err(e) = f.sync_data()
        {
            self.error = Some(format!("sync: {e}"));
        }
        self.dirty = false;
        self.last_sync = Instant::now();
        #[cfg(unix)]
        if let Err(e) = File::open(&self.dir).and_then(|d| d.sync_all()) {
            self.error = Some(format!("sync: {e}"));
        }
    }

    /// One tick of the writer.
    fn run(&mut self, batches: Vec<corerouter_proto_dns::querylog::Batch>, cfg: &DnsLog) {
        self.configure(cfg);
        if !batches.is_empty() {
            self.take(batches);
        } else if !self.block.is_empty() && self.block_since.elapsed() >= BLOCK_AGE {
            self.close_block(unix_ms());
        }
        if !cfg.enabled && !self.block.is_empty() {
            self.close_block(unix_ms());
        }
        self.retain(unix_ms());
        if self.dirty && self.last_sync.elapsed() >= SYNC_EVERY {
            self.sync();
        }
    }

    /// A clean shutdown: the open block and the files reach the disk.
    fn flush(&mut self) {
        self.close_block(unix_ms());
        self.sync();
    }

    fn status(&self) -> LogStatus {
        let reason = if self.no_room {
            Some("no room on /config past what the configuration needs: blocks are dropped".into())
        } else {
            self.error.clone()
        };
        LogStatus {
            writing: self.cfg.enabled && reason.is_none(),
            reason,
            files: u32::try_from(self.segments.len()).unwrap_or(u32::MAX),
            bytes: self.total(),
            oldest_ms: self.segments.values().filter_map(Segment::first_ms).min(),
            newest_ms: self.segments.values().filter_map(Segment::last_ms).max(),
            written: self.written,
            written_bytes: self.written_bytes,
            dropped_queue: 0,
            dropped_disk: self.dropped_disk,
            budget_bytes: self.budget(),
            rotated: self.rotated,
        }
    }
}

/// The writer as the engine reaches it.
pub(crate) struct Backend {
    store: Arc<Mutex<Store>>,
    sink: Arc<Sink>,
}

fn locked(m: &Mutex<Store>) -> MutexGuard<'_, Store> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A position in the log: segment, block, record (the next to look at,
/// going back in time).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pos {
    segment: u64,
    block: usize,
    record: usize,
}

impl Pos {
    fn parse(s: &str) -> Option<Self> {
        let mut it = s.split(':');
        let p = Self {
            segment: it.next()?.parse().ok()?,
            block: it.next()?.parse().ok()?,
            record: it.next()?.parse().ok()?,
        };
        it.next().is_none().then_some(p)
    }

    fn show(self) -> String {
        format!("{}:{}:{}", self.segment, self.block, self.record)
    }
}

/// Decodes `jobs` (segment path, block) at once, a thread each.
fn decode_many(jobs: &[(PathBuf, Block)]) -> Vec<Option<(Header, Vec<Record>)>> {
    if jobs.len() <= 1 {
        return jobs
            .iter()
            .map(|(p, b)| File::open(p).ok().and_then(|mut f| read_block(&mut f, b)))
            .collect();
    }
    std::thread::scope(|s| {
        let handles: Vec<_> = jobs
            .iter()
            .map(|(p, b)| {
                std::thread::Builder::new()
                    .name("dns-log-read".into())
                    .spawn_scoped(s, move || File::open(p).ok().and_then(|mut f| read_block(&mut f, b)))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.ok().and_then(|h| h.join().ok().flatten()))
            .collect()
    })
}

impl DnsLogBackend for Backend {
    fn status(&self) -> LogStatus {
        let mut st = locked(&self.store).status();
        st.dropped_queue = self.sink.counts().1;
        st
    }

    fn search(&self, f: &Filter, limit: usize, cursor: Option<&str>, budget: u64) -> Result<Found, String> {
        let start = match cursor {
            Some(c) => Some(Pos::parse(c).ok_or("bad cursor")?),
            None => None,
        };
        // A copy of the index; the files are read without the lock.
        let segments: Vec<(u64, Segment)> = {
            let s = locked(&self.store);
            s.segments.iter().rev().map(|(n, s)| (*n, s.clone())).collect()
        };
        // Candidate blocks, newest first, from the cursor on.
        let mut jobs: Vec<(u64, usize, PathBuf, Block)> = Vec::new();
        for (name, seg) in &segments {
            if start.is_some_and(|p| *name > p.segment) {
                continue;
            }
            for (i, b) in seg.blocks.iter().enumerate().rev() {
                if start.is_some_and(|p| *name == p.segment && i > p.block) {
                    continue;
                }
                if f.overlaps(b.header.first_ms, b.header.last_ms) {
                    jobs.push((*name, i, seg.path.clone(), *b));
                }
            }
        }
        let mut found = Found::default();
        let threads = std::thread::available_parallelism().map_or(2, |n| n.get()).clamp(1, READERS);
        for chunk in jobs.chunks(threads) {
            let batch: Vec<(PathBuf, Block)> = chunk.iter().map(|(_, _, p, b)| (p.clone(), *b)).collect();
            let decoded = decode_many(&batch);
            for ((name, bi, _, _), d) in chunk.iter().zip(decoded) {
                let Some((h, records)) = d else { continue };
                let top = match start {
                    Some(p) if p.segment == *name && p.block == *bi => p.record.min(records.len().saturating_sub(1)),
                    _ => records.len().saturating_sub(1),
                };
                for ri in (0..=top).rev() {
                    let Some(r) = records.get(ri) else { continue };
                    if found.rows.len() >= limit || found.scanned >= budget {
                        found.partial = found.rows.len() < limit;
                        found.next = Some(Pos { segment: *name, block: *bi, record: ri }.show());
                        return Ok(found);
                    }
                    found.scanned += 1;
                    if f.matches(r, h.mode) {
                        found.rows.push((r.clone(), h.mode));
                    }
                }
                // Past this block: the next one (older) from its end.
            }
        }
        Ok(found)
    }

    fn clear(&self, before_ms: Option<u64>, client: Option<&ClientMatch>) -> Result<Cleared, String> {
        let mut out = Cleared::default();
        // Everything: delete under the lock.
        if before_ms.is_none() && client.is_none() {
            let mut s = locked(&self.store);
            s.block = BlockBuilder::new(s.anon.mode());
            let names: Vec<u64> = s.segments.keys().copied().collect();
            for n in names {
                if let Some(seg) = s.segments.get(&n) {
                    out.files += 1;
                    out.bytes += seg.bytes;
                    out.queries += seg.queries();
                }
                s.remove(n);
            }
            s.sync();
            return Ok(out);
        }
        // Close the open block and segment; the next write opens another.
        let segments: Vec<(u64, Segment)> = {
            let mut s = locked(&self.store);
            s.close_block(unix_ms());
            s.sync();
            s.open = None;
            s.segments.iter().map(|(n, s)| (*n, s.clone())).collect()
        };
        // Both given: that client's queries before the time.
        let drop = |r: &Record, m: Mode| {
            before_ms.is_none_or(|b| r.at_ms < b) && client.is_none_or(|c| c.matches(&r.client, m))
        };
        for (name, seg) in segments {
            // Whole segment before the time, no client given: delete.
            if client.is_none() && before_ms.is_some_and(|b| seg.last_ms().is_some_and(|l| l < b)) {
                out.files += 1;
                out.bytes += seg.bytes;
                out.queries += seg.queries();
                locked(&self.store).remove(name);
                continue;
            }
            if before_ms.is_some_and(|b| seg.first_ms().is_some_and(|f| f >= b)) && client.is_none() {
                continue;
            }
            let (kept, removed) = rewrite(&seg, &drop).map_err(|e| format!("{}: {e}", seg.path.display()))?;
            if removed == 0 {
                if let Some(tmp) = kept {
                    let _ = fs::remove_file(tmp.0);
                }
                continue;
            }
            out.queries += removed;
            let mut s = locked(&self.store);
            if !s.segments.contains_key(&name) {
                // Retention took it meanwhile.
                if let Some((tmp, _)) = kept {
                    let _ = fs::remove_file(tmp);
                }
                continue;
            }
            match kept {
                Some((tmp, new)) => {
                    out.bytes += seg.bytes.saturating_sub(new.bytes);
                    if let Err(e) = fs::rename(&tmp, &seg.path) {
                        let _ = fs::remove_file(&tmp);
                        return Err(format!("{}: {e}", seg.path.display()));
                    }
                    s.segments.insert(name, Segment { path: seg.path.clone(), ..new });
                }
                None => {
                    out.files += 1;
                    out.bytes += seg.bytes;
                    s.remove(name);
                }
            }
        }
        locked(&self.store).sync();
        Ok(out)
    }
}

/// `seg` without the records `drop` says, into a `.tmp` beside it:
/// (the new file and its index, or `None` when nothing is left; queries
/// removed).
type Rewritten = (Option<(PathBuf, Segment)>, u64);

fn rewrite(seg: &Segment, drop: &dyn Fn(&Record, Mode) -> bool) -> io::Result<Rewritten> {
    let mut f = File::open(&seg.path)?;
    let tmp = seg.path.with_extension("tmp");
    let mut out: Option<File> = None;
    let mut blocks = Vec::new();
    let mut bytes = 0u64;
    let mut removed = 0u64;
    for b in &seg.blocks {
        let Some((h, records)) = read_block(&mut f, b) else { continue };
        let mut w = BlockBuilder::new(h.mode);
        for r in &records {
            if drop(r, h.mode) {
                removed += 1;
            } else {
                w.push(r);
            }
        }
        let Some(block) = w.finish() else { continue };
        let file = match &mut out {
            Some(f) => f,
            None => {
                let mut o = OpenOptions::new();
                o.create(true).write(true).truncate(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    o.mode(0o600);
                }
                out.insert(o.open(&tmp)?)
            }
        };
        file.write_all(&block)?;
        if let Ok(header) = format::read_header(&block) {
            blocks.push(Block { offset: bytes, header });
        }
        bytes += block.len() as u64;
    }
    match out {
        Some(f) => {
            f.sync_data()?;
            Ok((Some((tmp, Segment { path: seg.path.clone(), bytes, blocks })), removed))
        }
        None => Ok((None, removed)),
    }
}

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let sink = sink().clone();
    let store = match &ctx.config_dir {
        Some(config) => {
            let (cfg, capacity) = {
                let s = lock(&session);
                ((*s.store().running().ip.dns_log).clone(), s.ext::<ConfigDisk>().and_then(|d| d.capacity))
            };
            match Store::open(config.join(DIR), cfg, capacity, Box::new(free_bytes)) {
                Ok(st) => Some(Arc::new(Mutex::new(st))),
                Err(e) => {
                    log::error!("dns-log: cannot use {}: {e}; the query log stays off", config.join(DIR).display());
                    None
                }
            }
        }
        None => None,
    };
    if let Some(st) = &store {
        let backend = Arc::new(Backend { store: st.clone(), sink: sink.clone() });
        lock(&session).set_dns_log_backend(backend);
    }
    Ok(Box::new(move |health: &super::Health| {
        let Some(store) = &store else {
            sink.set_on(false);
            health.disabled(Some("no --config-dir: the query log is not written"));
            while health.sleep(super::IDLE_BEAT) {
                health.beat();
            }
            return Ok(());
        };
        let mut said: Option<bool> = None;
        while health.sleep(TICK) {
            health.beat();
            let cfg = (*lock(&session).store().running().ip.dns_log).clone();
            sink.set_on(cfg.enabled);
            health.disabled((!cfg.enabled).then_some("ip.dns.log enabled=no"));
            let batches = sink.drain();
            let mut st = locked(store);
            st.run(batches, &cfg);
            match &st.error {
                Some(e) => health.error(e.clone()),
                None => health.clear_error(),
            }
            let room = !st.no_room;
            drop(st);
            if said != Some(room) {
                if said.is_some() && !room {
                    lock(&session).log_event(
                        &["dns", "warning"],
                        "dns-log",
                        "Log de consultas DNS sem espaço: o que sobra no /config é da configuração; consultas descartadas".into(),
                        json!({}),
                    );
                }
                said = Some(room);
            }
        }
        sink.set_on(false);
        let batches = sink.drain();
        let mut st = locked(store);
        let cfg = st.cfg.clone();
        st.run(batches, &cfg);
        st.flush();
        Ok(())
    }))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use corerouter_model::dns_log::ClientAddress;
    use corerouter_proto_dns::querylog::{Entry, by_code};

    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cr-dns-log-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn on() -> DnsLog {
        DnsLog { enabled: true, client_address: ClientAddress::Full, ..DnsLog::default() }
    }

    fn store(dir: &Path, cfg: DnsLog) -> Store {
        Store::open(dir.to_path_buf(), cfg, None, Box::new(|_| None)).unwrap()
    }

    fn entry(at_ms: u64, client: [u8; 4], name: &str) -> Entry {
        Entry {
            at_ms,
            client: IpAddr::from(client),
            name: name.into(),
            qtype: 1,
            rcode: 0,
            flags: 0,
            by: by_code("cache"),
            ede: None,
        }
    }

    /// `n` queries a ms apart from `t0`, from 4 clients, into the store.
    fn feed(s: &mut Store, sink: &Sink, t0: u64, n: u64) {
        for i in 0..n {
            sink.push(&entry(t0 + i, [10, 0, 0, (i % 4) as u8], &format!("n{}.example.com", i % 10)), 50);
        }
        let cfg = s.cfg.clone();
        s.run(sink.drain(), &cfg);
        s.close_block(t0 + n);
    }

    fn backend(s: Store, sink: Arc<Sink>) -> Backend {
        Backend { store: Arc::new(Mutex::new(s)), sink }
    }

    #[test]
    fn writes_reads_back_newest_first_and_pages() {
        let dir = tmp("pages");
        let sink = Arc::new(Sink::default());
        sink.set_on(true);
        let mut s = store(&dir, on());
        let t0 = unix_ms() - 10_000;
        feed(&mut s, &sink, t0, 1000);
        feed(&mut s, &sink, t0 + 2000, 500);
        assert_eq!(s.written, 1500);
        let b = backend(s, sink);
        let f = Filter::default();
        let page = b.search(&f, 100, None, u64::MAX).unwrap();
        assert_eq!(page.rows.len(), 100);
        assert_eq!(page.rows[0].0.at_ms, t0 + 2000 + 499, "newest first");
        let mut seen = page.rows.len();
        let mut next = page.next.clone();
        let mut last = page.rows.last().unwrap().0.at_ms;
        while let Some(c) = next {
            let p = b.search(&f, 300, Some(&c), u64::MAX).unwrap();
            for (r, _) in &p.rows {
                assert!(r.at_ms < last, "strictly older, no repeat");
                last = r.at_ms;
            }
            seen += p.rows.len();
            next = p.next;
        }
        assert_eq!(seen, 1500);
        // Filters and the scan budget.
        let f = Filter { client: Some(ClientMatch::parse("10.0.0.1").unwrap()), name: Some("n3.".into()), ..Filter::default() };
        let p = b.search(&f, 1000, None, u64::MAX).unwrap();
        assert!(p.rows.iter().all(|(r, _)| r.name == "n3.example.com" && r.client.show(Mode::Full) == "10.0.0.1"));
        assert!(!p.rows.is_empty());
        let p = b.search(&Filter::default(), 1000, None, 10).unwrap();
        assert!(p.partial && p.rows.len() == 10 && p.next.is_some());
        assert!(b.search(&Filter::default(), 1, Some("nope"), 1).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_restart_reads_what_was_written_and_a_torn_tail_is_skipped() {
        let dir = tmp("restart");
        let sink = Arc::new(Sink::default());
        sink.set_on(true);
        let mut s = store(&dir, on());
        let t0 = unix_ms() - 5000;
        feed(&mut s, &sink, t0, 300);
        feed(&mut s, &sink, t0 + 1000, 300);
        s.flush();
        let path = s.segments.values().next().unwrap().path.clone();
        drop(s);
        // A power cut in the middle of the next block.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"CRQL\x01\x00\x20\x80garbage").unwrap();
        drop(f);
        let s = store(&dir, on());
        let b = backend(s, sink);
        let p = b.search(&Filter::default(), 10_000, None, u64::MAX).unwrap();
        assert_eq!(p.rows.len(), 600);
        let st = b.status();
        assert_eq!(st.files, 1);
        assert_eq!(st.oldest_ms, Some(t0));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn the_ceiling_and_the_age_drop_the_oldest_segment() {
        let dir = tmp("ceiling");
        let sink = Arc::new(Sink::default());
        sink.set_on(true);
        let mut s = store(&dir, DnsLog { max_size_mib: 1, max_age_hours: 1, ..on() });
        // Segments of 15 min (max_age/4): four of them, each ~1000 queries.
        let now = unix_ms();
        for k in 0..4u64 {
            let t = now - 3 * 3_600_000 + k * 1_000_000;
            for i in 0..1000 {
                sink.push(&entry(t + i, [10, 0, (i % 250) as u8, (i % 7) as u8], &format!("{i}.{k}.example")), 1);
            }
            let cfg = s.cfg.clone();
            s.take(sink.drain());
            s.close_block(t + 1000);
            let _ = cfg;
        }
        assert_eq!(s.segments.len(), 4, "a new segment every 15 min");
        s.retain(now);
        assert!(s.segments.is_empty() || s.segments.len() == 1, "older than an hour: gone ({})", s.segments.len());
        assert!(s.rotated >= 3);
        // The size ceiling: tiny budget, many blocks.
        let mut s = store(&tmp("ceiling2"), DnsLog { max_size_mib: 1, ..on() });
        for k in 0..40u64 {
            for i in 0..5000u64 {
                sink.push(&entry(now + k * 400_000 + i, [10, (k % 200) as u8, (i % 250) as u8, (i % 251) as u8], &format!("{i}-{k}.unique-name-{}.example", i * 31 + k)), 1);
            }
            s.take(sink.drain());
            s.close_block(now + k * 400_000);
        }
        s.retain(now);
        assert!(s.total() <= s.budget(), "{} > {}", s.total(), s.budget());
        assert!(s.rotated > 0);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn no_room_for_the_config_drops_and_counts() {
        let dir = tmp("room");
        let sink = Arc::new(Sink::default());
        sink.set_on(true);
        let mut s = Store::open(dir.clone(), on(), Some(1 << 30), Box::new(|_| Some(0))).unwrap();
        feed(&mut s, &sink, unix_ms(), 100);
        assert!(s.no_room);
        assert_eq!(s.written, 0);
        assert_eq!(s.dropped_disk, 100);
        assert!(s.status().reason.is_some());
        assert!(!s.status().writing);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn clear_by_client_by_time_and_everything() {
        let dir = tmp("clear");
        let sink = Arc::new(Sink::default());
        sink.set_on(true);
        let mut s = store(&dir, on());
        let t0 = unix_ms() - 100_000;
        feed(&mut s, &sink, t0, 400);
        s.open = None; // the next feed starts another segment
        feed(&mut s, &sink, t0 + 50_000, 400);
        let b = backend(s, sink);
        let c = ClientMatch::parse("10.0.0.2").unwrap();
        let out = b.clear(None, Some(&c)).unwrap();
        assert_eq!(out.queries, 200);
        let all = b.search(&Filter::default(), 10_000, None, u64::MAX).unwrap();
        assert_eq!(all.rows.len(), 600);
        assert!(all.rows.iter().all(|(r, _)| r.client.show(Mode::Full) != "10.0.0.2"));
        // Before a time: the first segment goes whole.
        let out = b.clear(Some(t0 + 50_000), None).unwrap();
        assert_eq!((out.files, out.queries), (1, 300));
        assert_eq!(b.search(&Filter::default(), 10_000, None, u64::MAX).unwrap().rows.len(), 300);
        let out = b.clear(None, None).unwrap();
        assert_eq!(out.queries, 300);
        assert_eq!(b.status().files, 0);
        assert!(fs::read_dir(&dir).unwrap().next().is_none(), "nothing left, no .tmp");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn clients_are_written_as_configured() {
        let dir = tmp("anon");
        let sink = Arc::new(Sink::default());
        sink.set_on(true);
        let mut s = store(&dir, DnsLog { enabled: true, ..DnsLog::default() });
        feed(&mut s, &sink, unix_ms() - 1000, 8);
        let cfg = DnsLog { client_address: ClientAddress::Hashed, ..s.cfg.clone() };
        s.run(Vec::new(), &cfg);
        feed(&mut s, &sink, unix_ms() - 500, 8);
        let b = backend(s, sink);
        let rows = b.search(&Filter::default(), 100, None, u64::MAX).unwrap().rows;
        assert!(rows.iter().any(|(r, m)| r.client.show(*m) == "10.0.0.0/24"));
        assert!(rows.iter().any(|(r, m)| r.client.show(*m).starts_with("h:")));
        assert!(!rows.iter().any(|(r, m)| r.client.show(*m) == "10.0.0.1"), "never the address");
        // The file holds no client address either.
        let raw: Vec<u8> = fs::read_dir(&dir).unwrap().flatten().flat_map(|e| fs::read(e.path()).unwrap()).collect();
        let (blocks, _) = format::decode_all(&raw);
        assert!(blocks.iter().flat_map(|(_, r)| r).all(|r| !matches!(r.client, format::Client::Addr(IpAddr::V4(a)) if a.octets()[3] != 0)));
        let _ = fs::remove_dir_all(dir);
    }
}
