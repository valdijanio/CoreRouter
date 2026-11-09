//! The `disk` action's writer (G4.6g, RouterOS `/system logging action
//! target=disk`): the events the rules send to `disk` go to
//! `<config-dir>/log/<disk_file_name>.<n>.txt`, `.0` being the file in use,
//! which becomes `.1` when it holds `disk_lines_per_file`; at most
//! `disk_file_count` files. The format and its parser are in
//! `corerouter_engine::log_disk`.
//!
//! One thread. Every second it takes what is new out of the session (a swap
//! under the lock; encoding and I/O outside it) and writes it to the page
//! cache: a daemon that crashes loses nothing. The `fsync` comes once a
//! minute, batched like journald's `SyncIntervalSec`, at once for a
//! `critical` line and at a clean shutdown ([`final_flush`]): flash wears
//! with each one; a power cut loses at most that minute.
//!
//! What must never happen is the log taking the room of the configuration.
//! The files stay under their share of `/config`
//! ([`corerouter_engine::config_disk::log_budget`]), the oldest going first
//! (files of an earlier `disk_file_name` before any other); and before a
//! write, what the next config save needs must stay free
//! ([`corerouter_engine::config_disk::keep_free`]). When deleting old files
//! does not make that room, lines are dropped and counted, never the config.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use corerouter_engine::config_disk::{ConfigDisk, keep_free, log_budget, mib};
use corerouter_engine::log_disk::{DIR, MAX_RESTORE_BYTES, WINDOW, decode_all, encode, file_name, file_number};
use corerouter_engine::logging::{DAEMON, LogBook};
use corerouter_engine::{Session, Shared, lock};
use corerouter_model::logging::{DISK_ACTION, DiskLog, LogEvent};
use corerouter_sysupdate::state::free_bytes;
use serde_json::json;

pub(crate) const SERVICE: super::Service = super::Service {
    name: "disk-log",
    flags: &[],
    topic: "system",
    enable: "system.logging.add action=disk",
    depends: &[],
    start,
};

const TICK: Duration = Duration::from_secs(1);
/// Between two `fsync`s of the files.
const SYNC_EVERY: Duration = Duration::from_secs(60);

/// The writer, once the service started (for [`final_flush`]).
static WRITER: OnceLock<Arc<Mutex<Pump>>> = OnceLock::new();

/// What is free on the disk of a directory (`None`: unknown, not checked).
type Free = Box<dyn Fn(&Path) -> Option<u64> + Send>;

/// The files of the action, and what it costs to keep them.
struct Writer {
    dir: PathBuf,
    cfg: DiskLog,
    /// The ceiling of all the files, in bytes.
    cap: u64,
    /// The filesystem's size.
    capacity: Option<u64>,
    /// Bytes by `n`, of the files of `cfg.file_name`.
    files: BTreeMap<u32, u64>,
    /// Files of an earlier name, oldest first: they go first.
    others: Vec<(PathBuf, u64)>,
    /// Lines in `.0`.
    lines: u64,
    file: Option<File>,
    /// `.0` may end in a torn line: the next write starts a new file.
    rotate_first: bool,
    dirty: bool,
    dir_dirty: bool,
    written: u64,
    dropped: u64,
    cut: u64,
    /// `disk_stop_on_full` reached.
    stopped: bool,
    /// The last batch did not fit what must stay free.
    no_room: bool,
    last_error: Option<String>,
    free: Free,
}

impl Writer {
    fn open(dir: PathBuf, cfg: DiskLog, capacity: Option<u64>) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        let mut w = Self {
            dir,
            cfg,
            cap: log_budget(capacity),
            capacity,
            files: BTreeMap::new(),
            others: Vec::new(),
            lines: 0,
            file: None,
            rotate_first: false,
            dirty: false,
            dir_dirty: false,
            written: 0,
            dropped: 0,
            cut: 0,
            stopped: false,
            no_room: false,
            last_error: None,
            free: Box::new(free_bytes),
        };
        w.scan();
        Ok(w)
    }

    /// Learn what is there, after a start or a change of name.
    fn scan(&mut self) {
        self.files.clear();
        self.others.clear();
        self.file = None;
        self.lines = 0;
        self.rotate_first = false;
        let mut others: Vec<(std::time::SystemTime, PathBuf, u64)> = Vec::new();
        for e in fs::read_dir(&self.dir).into_iter().flatten().flatten() {
            let (Some(name), Ok(m)) = (e.file_name().to_str().map(str::to_owned), e.metadata()) else {
                continue;
            };
            if !m.is_file() {
                continue;
            }
            if let Some(n) = file_number(&self.cfg.file_name, &name) {
                self.files.insert(n, m.len());
            } else if is_log_file(&name) {
                others.push((m.modified().unwrap_or(std::time::UNIX_EPOCH), e.path(), m.len()));
            }
        }
        others.sort();
        self.others = others.into_iter().map(|(_, p, n)| (p, n)).collect();
        if self.files.contains_key(&0) {
            let mut bytes = Vec::new();
            let read = File::open(self.path(0)).and_then(|f| f.take(MAX_RESTORE_BYTES).read_to_end(&mut bytes));
            match read {
                Ok(_) => {
                    self.lines = bytes.iter().filter(|b| **b == b'\n').count() as u64;
                    self.rotate_first = !bytes.is_empty() && bytes.last() != Some(&b'\n');
                }
                Err(_) => self.rotate_first = true,
            }
        }
    }

    fn path(&self, n: u32) -> PathBuf {
        self.dir.join(file_name(&self.cfg.file_name, n))
    }

    fn total(&self) -> u64 {
        let own: u64 = self.files.values().sum();
        let others: u64 = self.others.iter().map(|o| o.1).sum();
        own.saturating_add(others)
    }

    /// New settings from the config.
    fn configure(&mut self, cfg: &DiskLog) {
        if *cfg == self.cfg {
            return;
        }
        let renamed = cfg.file_name != self.cfg.file_name;
        if renamed {
            self.sync();
        }
        self.cfg = cfg.clone();
        self.stopped = false;
        if renamed {
            self.scan();
        }
    }

    /// `log.clear`: every log file goes.
    fn clear(&mut self) {
        self.file = None;
        self.dirty = false;
        let own: Vec<u32> = self.files.keys().copied().collect();
        for n in own {
            self.remove(n);
        }
        for (p, _) in std::mem::take(&mut self.others) {
            let _ = fs::remove_file(p);
        }
        self.lines = 0;
        self.rotate_first = false;
        self.stopped = false;
        self.dir_dirty = true;
    }

    fn remove(&mut self, n: u32) {
        if n == 0 {
            self.file = None;
            self.lines = 0;
        }
        match fs::remove_file(self.path(n)) {
            Ok(()) => {
                self.files.remove(&n);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.files.remove(&n);
            }
            Err(e) => self.last_error = Some(format!("{}: {e}", file_name(&self.cfg.file_name, n))),
        }
        self.dir_dirty = true;
    }

    /// `.0` becomes `.1`, and so on; past `disk_file_count`, the oldest go.
    /// `Err`: the files stay as they are and the lines are not written.
    fn rotate(&mut self) -> io::Result<()> {
        self.sync();
        self.file = None;
        let count = self.cfg.file_count.max(1) as usize;
        while self.files.len() >= count {
            let Some(oldest) = self.files.keys().next_back().copied() else { break };
            let before = self.files.len();
            self.remove(oldest);
            if self.files.len() == before {
                return Err(io::Error::other(format!("cannot delete {}", file_name(&self.cfg.file_name, oldest))));
            }
        }
        for n in self.files.keys().rev().copied().collect::<Vec<u32>>() {
            fs::rename(self.path(n), self.path(n + 1))?;
            if let Some(bytes) = self.files.remove(&n) {
                self.files.insert(n + 1, bytes);
            }
        }
        self.lines = 0;
        self.rotate_first = false;
        self.dir_dirty = true;
        Ok(())
    }

    /// The oldest file goes (never `.0`). `false`: nothing else can.
    fn evict(&mut self) -> bool {
        if !self.others.is_empty() {
            let (path, _) = self.others.remove(0);
            let _ = fs::remove_file(path);
            self.dir_dirty = true;
            self.cut = self.cut.saturating_add(1);
            return true;
        }
        let Some(oldest) = self.files.keys().next_back().copied().filter(|n| *n > 0) else {
            return false;
        };
        self.remove(oldest);
        self.cut = self.cut.saturating_add(1);
        !self.files.contains_key(&oldest)
    }

    /// What is free for the log on this disk, past what must stay free.
    fn room(&self) -> Option<u64> {
        let capacity = self.capacity?;
        let free = (self.free)(&self.dir)?;
        let slot = self.dir.parent().and_then(|p| fs::metadata(p.join("running.json")).ok()).map_or(0, |m| m.len());
        Some(free.saturating_sub(keep_free(capacity, slot)))
    }

    /// Room for `need` bytes, deleting what is oldest. In `stop_on_full`
    /// nothing goes for the ceiling, as it goes for a full disk.
    fn make_room(&mut self, need: u64) -> bool {
        loop {
            let over_cap = self.total().saturating_add(need) > self.cap;
            let over_free = self.room().is_some_and(|r| r < need);
            if !over_cap && !over_free {
                return true;
            }
            if over_cap && self.cfg.stop_on_full {
                self.stopped = true;
                return false;
            }
            if self.evict() {
                continue;
            }
            // Only `.0` is left: past the ceiling it goes too, the newest
            // lines matter more. It may be there is still no room.
            if self.files.get(&0).is_some_and(|b| *b > 0) {
                self.remove(0);
                self.cut = self.cut.saturating_add(1);
                if !self.files.contains_key(&0) {
                    continue;
                }
            }
            return false;
        }
    }

    /// Write `lines`, in order. What does not fit is counted, never fatal.
    fn write(&mut self, lines: &[String]) {
        self.no_room = false;
        if lines.is_empty() {
            return;
        }
        let per_file = u64::from(self.cfg.lines_per_file.max(1));
        let mut rest = lines;
        if !self.cfg.stop_on_full {
            // More than all the files hold: the older ones would be rotated
            // out in this very batch.
            let most = per_file.saturating_mul(u64::from(self.cfg.file_count.max(1)));
            let skip = (lines.len() as u64).saturating_sub(most);
            let skip = usize::try_from(skip).unwrap_or(0).min(lines.len());
            rest = lines.get(skip..).unwrap_or_default();
            self.written = self.written.saturating_add(skip as u64);
        }
        while !rest.is_empty() {
            if self.stopped {
                break;
            }
            if self.rotate_first || self.lines >= per_file {
                if self.cfg.stop_on_full && self.files.len() >= self.cfg.file_count.max(1) as usize && !self.rotate_first {
                    self.stopped = true;
                    break;
                }
                if let Err(e) = self.rotate() {
                    self.last_error = Some(format!("rotate: {e}"));
                    break;
                }
            }
            let fit = usize::try_from(per_file - self.lines).unwrap_or(usize::MAX).min(rest.len());
            let (now, later) = rest.split_at(fit);
            let text: String = now.concat();
            if !self.make_room(text.len() as u64) {
                self.no_room = !self.stopped;
                break;
            }
            match self.append(&text) {
                Ok(()) => {
                    self.lines += fit as u64;
                    self.written = self.written.saturating_add(fit as u64);
                    self.last_error = None;
                    rest = later;
                }
                Err(e) => {
                    self.last_error = Some(e.to_string());
                    break;
                }
            }
        }
        self.dropped = self.dropped.saturating_add(rest.len() as u64);
    }

    /// One write to `.0`; on a failure, what got there is taken back, or
    /// the next write starts another file.
    fn append(&mut self, text: &str) -> io::Result<()> {
        if self.file.is_none() {
            let mut o = OpenOptions::new();
            o.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                // Same reader as the config's: the owner.
                o.mode(0o600);
            }
            self.file = Some(o.open(self.path(0))?);
            self.dir_dirty = true;
        }
        let Some(f) = self.file.as_mut() else {
            return Err(io::Error::other("no file"));
        };
        let before = *self.files.get(&0).unwrap_or(&0);
        match f.write_all(text.as_bytes()) {
            Ok(()) => {
                self.files.insert(0, before.saturating_add(text.len() as u64));
                self.dirty = true;
                Ok(())
            }
            Err(e) => {
                if f.set_len(before).is_err() {
                    self.rotate_first = true;
                }
                self.files.entry(0).or_insert(before);
                Err(e)
            }
        }
    }

    /// The batch reaches the disk.
    fn sync(&mut self) {
        if self.dirty
            && let Some(f) = &self.file
            && let Err(e) = f.sync_data()
        {
            self.last_error = Some(format!("sync: {e}"));
        }
        self.dirty = false;
        if self.dir_dirty {
            #[cfg(unix)]
            if let Err(e) = File::open(&self.dir).and_then(|d| d.sync_all()) {
                self.last_error = Some(format!("sync: {e}"));
            }
            self.dir_dirty = false;
        }
    }
}

/// `anything.3.txt`: a file of this action under some name.
fn is_log_file(file: &str) -> bool {
    let Some(rest) = file.strip_suffix(".txt") else { return false };
    let Some((name, _)) = rest.rsplit_once('.') else { return false };
    file_number(name, file).is_some()
}

/// The writer between ticks.
struct Pump {
    w: Writer,
    /// `log.clear`s already done.
    clears: u64,
    last_sync: Instant,
    /// What was last said in the log, so it is said once.
    said_cut: bool,
    said_room: bool,
    said_error: Option<String>,
    /// The numbers reached the session at least once.
    reported: bool,
}

impl Pump {
    /// What is new goes to the files; `sync`: and to the disk.
    fn run(&mut self, session: &Shared, sync: bool) {
        let (events, clears, cfg) = {
            let mut s = lock(session);
            let cfg = s.store().running().system.logging.disk.clone();
            let (events, clears) = s.log_disk_take();
            (events, clears, cfg)
        };
        self.w.configure(&cfg);
        let cleared = clears != self.clears;
        if cleared {
            self.clears = clears;
            self.w.clear();
        }
        let urgent = events.iter().any(|e| e.topics.iter().any(|t| t == "critical"));
        let lines: Vec<String> = events.iter().filter_map(encode).collect();
        let unencoded = events.len().saturating_sub(lines.len());
        self.w.dropped = self.w.dropped.saturating_add(unencoded as u64);
        self.w.write(&lines);
        if sync || urgent || (self.w.dirty && self.last_sync.elapsed() >= SYNC_EVERY) {
            let was_dirty = self.w.dirty;
            self.w.sync();
            self.last_sync = Instant::now();
            if was_dirty {
                self.report(session, true);
                return;
            }
        }
        if !self.reported || !events.is_empty() || cleared || self.w.last_error != self.said_error {
            self.report(session, false);
        }
    }

    /// The numbers go to the session; what changed, to the log.
    fn report(&mut self, session: &Shared, flushed: bool) {
        self.reported = true;
        let w = &mut self.w;
        let dropped = std::mem::take(&mut w.dropped);
        let cut = w.cut > 0;
        let notes = (cut && !self.said_cut, w.no_room && !self.said_room, w.last_error.clone().filter(|e| Some(e) != self.said_error.as_ref()));
        self.said_cut |= cut;
        self.said_room = w.no_room;
        self.said_error.clone_from(&w.last_error);
        let dir = w.dir.display().to_string();
        let (files, bytes, cap, written, cuts, stopped, error) = (
            w.files.len().saturating_add(w.others.len()),
            w.total(),
            w.cap,
            std::mem::take(&mut w.written),
            w.cut,
            w.stopped,
            w.last_error.clone(),
        );
        let mut s = lock(session);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs());
        if let Some(b) = s.ext_mut::<LogBook>() {
            let d = &mut b.disk;
            d.dir = Some(dir);
            d.files = files;
            d.bytes = bytes;
            d.cap_bytes = cap;
            d.lines_written = d.lines_written.saturating_add(written);
            d.lines_dropped = d.lines_dropped.saturating_add(dropped);
            d.files_cut = cuts;
            d.stopped = stopped;
            d.last_error = error;
            if flushed {
                d.flushes = d.flushes.saturating_add(1);
                d.last_flush = now;
            }
        }
        if notes.0 {
            s.log_event(
                &["system", "info"],
                DAEMON,
                format!("Log em disco limitado a {}: arquivos antigos saem antes de disk_file_count", mib(cap)),
                json!({"cap_bytes": cap}),
            );
        }
        if notes.1 {
            s.log_event(
                &["system", "warning"],
                DAEMON,
                "Log em disco parado por falta de espaço: o que sobra é da configuração, e as linhas novas ficam só na memória".into(),
                json!({"dropped": dropped}),
            );
        }
        if let Some(e) = notes.2 {
            s.log_event(&["system", "warning"], DAEMON, format!("Log em disco: {e}"), json!({"error": e}));
        }
    }
}

/// G4.6g, at boot, before the session is shared and any service reads the
/// log: what the files hold comes back, and the writer exists from here on.
/// A bad line costs that line; an unreadable file, that file.
pub(crate) fn restore(session: &mut Session, config_dir: &Path) {
    let dir = config_dir.join(DIR);
    let name = session.store().running().system.logging.disk.file_name.clone();
    let mut numbers: Vec<u32> = fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| file_number(&name, e.file_name().to_str()?))
        .collect();
    numbers.sort_unstable();
    // Newest first, until `log.print` has all it could show.
    let (mut chunks, mut lines, mut bad) = (Vec::new(), 0usize, 0usize);
    for n in numbers {
        if lines >= WINDOW {
            break;
        }
        match read_lines(&dir.join(file_name(&name, n))) {
            Ok((events, b)) => {
                lines += events.len();
                bad += b;
                chunks.push(events);
            }
            Err(e) => {
                log::warn!("disk-log: {}: {e}", file_name(&name, n));
                bad += 1;
            }
        }
    }
    let events: Vec<LogEvent> = chunks.into_iter().rev().flatten().collect();
    if !events.is_empty() {
        log::info!("disk-log: {} lines read back from {}", events.len(), dir.display());
    }
    if bad > 0 {
        log::warn!("disk-log: {bad} damaged lines in {} left out", dir.display());
    }
    session.log_disk_attach(events, bad);
}

/// A file's events (the tail of a file too big to be ours), bad lines.
fn read_lines(path: &Path) -> io::Result<(Vec<LogEvent>, usize)> {
    let bytes = corerouter_storage_fs::read_tail(File::open(path)?, MAX_RESTORE_BYTES)?;
    Ok(decode_all(&bytes))
}

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let pump = match &ctx.config_dir {
        Some(config) => {
            let (cfg, capacity, clears) = {
                let s = lock(&session);
                let capacity = s.ext::<ConfigDisk>().and_then(|d| d.capacity);
                let cfg = s.store().running().system.logging.disk.clone();
                let clears = s.log_disk_clears();
                (cfg, capacity, clears)
            };
            match Writer::open(config.join(DIR), cfg, capacity) {
                Ok(w) => {
                    let pump = WRITER.get_or_init(|| Arc::new(Mutex::new(new_pump(w, clears))));
                    Some(pump.clone())
                }
                Err(e) => {
                    log::error!("disk-log: cannot use {}: {e}; the log stays in memory", config.join(DIR).display());
                    None
                }
            }
        }
        None => None,
    };
    Ok(Box::new(move |health: &super::Health| {
        let Some(pump) = &pump else {
            health.disabled(Some("no --config-dir: the log is kept in memory only"));
            while health.sleep(TICK) {
                health.beat();
            }
            return Ok(());
        };
        while health.sleep(TICK) {
            health.beat();
            let used = {
                let s = lock(&session);
                s.store().running().system.logging.rules.iter().any(|r| r.action == DISK_ACTION)
            };
            health.disabled((!used).then_some("no rule sends to disk (system.logging.add action=disk)"));
            let mut p = pump.lock().unwrap_or_else(PoisonError::into_inner);
            p.run(&session, false);
            match &p.w.last_error {
                Some(e) => health.error(e.clone()),
                None => health.clear_error(),
            }
        }
        Ok(())
    }))
}

fn new_pump(w: Writer, clears: u64) -> Pump {
    Pump {
        w,
        clears,
        last_sync: Instant::now(),
        said_cut: false,
        said_room: false,
        said_error: None,
        reported: false,
    }
}

/// What is left, to the disk, before the daemon exits (the shutdown in
/// `main.rs`).
pub(crate) fn final_flush(session: &Shared) {
    let Some(pump) = WRITER.get() else { return };
    let mut p = pump.lock().unwrap_or_else(PoisonError::into_inner);
    p.run(session, true);
    log::info!("shutting down: log files synced");
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use corerouter_engine::{Session, shared};

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cr-disk-log-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn cfg(lines: u32, count: u32) -> DiskLog {
        DiskLog {
            file_name: "log".into(),
            lines_per_file: lines,
            file_count: count,
            stop_on_full: false,
        }
    }

    fn line(i: usize) -> String {
        let e = LogEvent {
            seq: 0,
            time: 1_700_000_000,
            topics: vec!["info".into()],
            origin: "daemon".into(),
            message: format!("linha {i}"),
            detail: Value::Null,
        };
        encode(&e).unwrap()
    }

    fn lines(r: std::ops::Range<usize>) -> Vec<String> {
        r.map(line).collect()
    }

    fn messages(path: &Path) -> Vec<String> {
        let bytes = fs::read(path).unwrap();
        decode_all(&bytes).0.into_iter().map(|e| e.message).collect()
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    /// The package snapshots leave out the same directory.
    #[test]
    fn the_snapshots_know_the_directory() {
        assert_eq!(DIR, corerouter_sysupdate::state::LOG);
    }

    /// As in RouterOS: `.0` is in use, `.1` the one before; past the count,
    /// the oldest goes.
    #[test]
    fn rotation_keeps_the_newest_files_with_routeros_names() {
        let d = tmp("rotate");
        let mut w = Writer::open(d.clone(), cfg(3, 2), None).unwrap();
        w.write(&lines(0..2));
        assert_eq!(names(&d), ["log.0.txt"]);
        w.write(&lines(2..4));
        assert_eq!(names(&d), ["log.0.txt", "log.1.txt"]);
        assert_eq!(messages(&d.join("log.1.txt")), ["linha 0", "linha 1", "linha 2"]);
        assert_eq!(messages(&d.join("log.0.txt")), ["linha 3"]);
        w.write(&lines(4..8));
        assert_eq!(names(&d), ["log.0.txt", "log.1.txt"]);
        assert_eq!(messages(&d.join("log.1.txt")), ["linha 3", "linha 4", "linha 5"]);
        assert_eq!(messages(&d.join("log.0.txt")), ["linha 6", "linha 7"]);
        // A restart carries on in the same file.
        drop(w);
        let mut w = Writer::open(d.clone(), cfg(3, 2), None).unwrap();
        assert_eq!(w.lines, 2);
        w.write(&lines(8..9));
        assert_eq!(messages(&d.join("log.0.txt")), ["linha 6", "linha 7", "linha 8"]);
        fs::remove_dir_all(&d).unwrap();
    }

    /// A batch bigger than all the files: only what fits is written, with
    /// no pointless renames.
    #[test]
    fn a_batch_past_all_the_files_keeps_the_newest() {
        let d = tmp("burst");
        let mut w = Writer::open(d.clone(), cfg(2, 2), None).unwrap();
        w.write(&lines(0..100));
        assert_eq!(messages(&d.join("log.1.txt")), ["linha 96", "linha 97"]);
        assert_eq!(messages(&d.join("log.0.txt")), ["linha 98", "linha 99"]);
        assert_eq!(w.dropped, 0);
        fs::remove_dir_all(&d).unwrap();
    }

    /// One file only: it starts again.
    #[test]
    fn one_file_starts_over() {
        let d = tmp("one");
        let mut w = Writer::open(d.clone(), cfg(2, 1), None).unwrap();
        w.write(&lines(0..3));
        assert_eq!(names(&d), ["log.0.txt"]);
        assert_eq!(messages(&d.join("log.0.txt")), ["linha 1", "linha 2"]);
        w.write(&lines(3..4));
        assert_eq!(messages(&d.join("log.0.txt")), ["linha 3"]);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn stop_on_full_stops_and_counts() {
        let d = tmp("stop");
        let mut c = cfg(2, 2);
        c.stop_on_full = true;
        let mut w = Writer::open(d.clone(), c, None).unwrap();
        w.write(&lines(0..3));
        assert!(!w.stopped);
        w.write(&lines(3..7));
        assert!(w.stopped);
        assert_eq!(w.dropped, 3);
        assert_eq!(messages(&d.join("log.1.txt")), ["linha 0", "linha 1"]);
        assert_eq!(messages(&d.join("log.0.txt")), ["linha 2", "linha 3"]);
        fs::remove_dir_all(&d).unwrap();
    }

    /// The ceiling of bytes wins over `disk_file_count`: the oldest go,
    /// another name's first.
    #[test]
    fn the_bytes_ceiling_deletes_the_oldest_first() {
        let d = tmp("cap");
        fs::write(d.join("velho.0.txt"), vec![b'x'; 300]).unwrap();
        fs::write(d.join("notas.txt"), b"not ours").unwrap();
        let mut w = Writer::open(d.clone(), cfg(5, 100), None).unwrap();
        let one = line(0).len() as u64;
        w.cap = one * 12;
        assert_eq!(w.others.len(), 1);
        w.write(&lines(0..30));
        assert!(!d.join("velho.0.txt").exists(), "{:?}", names(&d));
        assert!(d.join("notas.txt").exists(), "only ours go");
        assert!(w.total() <= w.cap, "{} > {}", w.total(), w.cap);
        assert!(w.cut > 0);
        assert_eq!(w.dropped, 0, "the newest always get in");
        assert_eq!(messages(&d.join("log.0.txt")).last().unwrap(), "linha 29");
        fs::remove_dir_all(&d).unwrap();
    }

    /// A line bigger than the whole ceiling, or a disk that does not leave
    /// what the config needs: dropped and counted, nothing else breaks.
    #[test]
    fn a_full_disk_drops_lines_and_says_so() {
        let d = tmp("full");
        let config = d.join("cfg");
        fs::create_dir_all(&config).unwrap();
        fs::write(config.join("running.json"), vec![b'x'; 1000]).unwrap();
        let mut w = Writer::open(config.join(DIR), cfg(100, 2), Some(1_000_000)).unwrap();
        // keep_free: 100 000 of the disk (10 %, more than 3 × 1000).
        w.free = Box::new(|_| Some(100_500));
        w.write(&lines(0..1));
        assert_eq!(w.dropped, 0, "fits");
        w.free = Box::new(|_| Some(100_001));
        w.write(&lines(1..3));
        assert_eq!(w.dropped, 2);
        assert!(w.no_room);
        // Room again: it carries on, in order.
        w.free = Box::new(|_| Some(10_000_000));
        w.write(&lines(3..4));
        assert!(!w.no_room);
        assert_eq!(w.dropped, 2);
        assert_eq!(messages(&config.join(DIR).join("log.0.txt")).last().unwrap(), "linha 3");
        fs::remove_dir_all(&d).unwrap();
    }

    /// The whole way: a rule, a restart, `log.print` marks what came from
    /// the disk; a torn file does not stop the boot; `log.clear` deletes.
    #[test]
    fn the_log_comes_back_after_a_restart() {
        let d = tmp("restart");
        let mut first = Session::virtual_lab();
        first.execute("system.logging.add", &json!({"topics": ["warning"], "action": "disk"})).unwrap();
        first.tick(1_700_000_000);
        restore(&mut first, &d);
        let config = first.store().running().system.logging.clone();
        let s = shared(first);
        let w = Writer::open(d.join(DIR), config.disk.clone(), None).unwrap();
        let mut pump = new_pump(w, 0);
        lock(&s).log_event(&["system", "warning"], DAEMON, "antes de cair".into(), json!({"k": 1}));
        lock(&s).log_event(&["system", "info"], DAEMON, "só memória".into(), Value::Null);
        pump.run(&s, false);
        // In the page cache, before any sync: a daemon crash loses nothing.
        assert_eq!(messages(&d.join(DIR).join("log.0.txt")), ["antes de cair"]);
        pump.run(&s, true);
        let status = lock(&s).execute("system.logging.action.list", &json!({})).unwrap();
        let disk = status.as_array().unwrap().iter().find(|a| a["name"] == "disk").unwrap().clone();
        assert_eq!(disk["disk_status"]["lines_written"], 1, "{disk}");
        assert_eq!(disk["disk_status"]["files"], 1);
        assert!(disk["disk_status"]["flushes"].as_u64().unwrap() >= 1);

        // A torn last line and a damaged one, then a restart.
        let f = d.join(DIR).join("log.0.txt");
        let mut text = fs::read(&f).unwrap();
        text.extend_from_slice(b"\xff\xfedamaged\n{\"time\":1,\"topics\":[\"inf");
        fs::write(&f, text).unwrap();
        fs::write(d.join(DIR).join("log.1.txt"), line(7)).unwrap();
        let mut second = Session::virtual_lab();
        second.log_event(&["system", "info"], DAEMON, "da partida".into(), Value::Null);
        restore(&mut second, &d);
        let rows = second.execute("log.print", &json!({})).unwrap();
        let rows = rows.as_array().unwrap();
        assert_eq!(rows[0]["message"], "linha 7", "the older file first");
        assert_eq!(rows[1]["message"], "antes de cair");
        assert_eq!(rows[1]["from_disk"], true);
        assert_eq!(rows[1]["detail"]["k"], 1);
        assert_eq!(rows[2]["from_disk"], false);
        assert_eq!(rows[2]["message"], "da partida");
        assert_eq!(second.ext::<LogBook>().unwrap().disk.bad_lines, 1, "the torn line is not damage");

        // The torn tail: the next line starts a new file, not glued to it.
        let s = shared(second);
        let w = Writer::open(d.join(DIR), DiskLog::default(), None).unwrap();
        assert!(w.rotate_first);
        let mut pump = new_pump(w, 0);
        pump.run(&s, false);
        lock(&s).execute("log.clear", &json!({})).unwrap();
        pump.run(&s, true);
        assert!(names(&d.join(DIR)).is_empty(), "{:?}", names(&d.join(DIR)));
        fs::remove_dir_all(&d).unwrap();
    }

    /// An unreadable file (here a directory with its name) costs that file.
    #[test]
    fn a_strange_directory_does_not_stop_the_boot() {
        let d = tmp("strange");
        fs::create_dir_all(d.join(DIR).join("log.0.txt")).unwrap();
        fs::write(d.join(DIR).join("log.1.txt"), vec![0xffu8; 4096]).unwrap();
        let mut s = Session::virtual_lab();
        restore(&mut s, &d);
        assert!(s.execute("log.print", &json!({})).is_ok());
        let w = Writer::open(d.join(DIR), DiskLog::default(), None).unwrap();
        assert!(!w.files.contains_key(&0));
        fs::remove_dir_all(&d).unwrap();
    }
}
