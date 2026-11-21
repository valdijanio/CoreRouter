//! L4 — [`ConfigStorage`] on a directory (`/config` on the router image).
//!
//! Layout:
//!
//! | file | slot |
//! |---|---|
//! | `running.json` | [`Slot::Current`] |
//! | `running.json.prev` | [`Slot::Previous`] |
//! | `running.json.tmp` | write in progress (removed on open) |
//! | `rev-<n>.json` | revision `n` of the history as a difference to revision `n+1`, written once (G1.23, audit-history) |
//! | `rev-<n>.json.tmp` | revision write in progress (removed on open) |
//! | `*.corrupt`, `*.corrupt.<n>` | quarantined unreadable slot (each one kept) |
//! | `state-<name>.json` | operational state outside the revisions (DHCP client leases) |
//! | `journal-<name>.log` | append-only journal (the DHCP server's leases, G4.2a) |
//! | `checkpoint-<name>.json` | a named checkpoint: a whole config kept apart from the history (G0.33) |
//!
//! A save is: write `running.json.tmp`, fsync it, rename `running.json` →
//! `running.json.prev`, rename the temp file → `running.json`, fsync the
//! directory. Renames are atomic, so after a crash at any step each slot is a
//! complete file (old or new) or absent; the engine then loads the newest
//! readable one.
//!
//! A slot holds the running config and its newest revision; the older ones
//! are `rev-<n>.json` files (temp file, fsync, rename), each written once by
//! the commit after it, before the slot that needs it (the slot's
//! directory fsync makes both renames durable). See the engine's
//! `history_files` for the order and what a crash leaves.
//!
//! Slots, revisions, checkpoints and `state-*` files are never written in place: a new
//! content is a new file renamed over the old one. The A/B update's
//! configuration snapshot relies on it (G1.6u, `sysupdate::state`): it
//! hard-links these files instead of copying them. Only journals are
//! appended to.

use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use corerouter_engine::storage::{MAX_JOURNAL_BYTES, MAX_STATE_BYTES, state_name_ok};
use corerouter_engine::{ConfigStorage, Slot, StorageError};
use corerouter_model::persist::{MAX_FILE_BYTES, checkpoint_name_ok};

pub const CURRENT: &str = "running.json";
pub const PREVIOUS: &str = "running.json.prev";
pub const TEMP: &str = "running.json.tmp";
pub const CORRUPT_SUFFIX: &str = ".corrupt";
/// Revision files: `rev-<n>.json`.
pub const REVISION_PREFIX: &str = "rev-";
const REVISION_SUFFIX: &str = ".json";

/// File name of revision `number`.
pub fn revision_file(number: u32) -> String {
    format!("{REVISION_PREFIX}{number}{REVISION_SUFFIX}")
}

/// The revision a file name holds (`rev-12.json` gives 12), strictly: no
/// sign, no leading zero, nothing after.
/// Checkpoint files: `checkpoint-<name>.json`.
pub const CHECKPOINT_PREFIX: &str = "checkpoint-";

/// File name of checkpoint `name`, for a name the engine accepts only.
fn checkpoint_file(name: &str) -> Result<String, StorageError> {
    if checkpoint_name_ok(name) {
        Ok(format!("{CHECKPOINT_PREFIX}{name}.json"))
    } else {
        Err(StorageError(format!("bad checkpoint name '{name}'")))
    }
}

/// The checkpoint a file name holds (`checkpoint-x.json` gives `x`).
fn checkpoint_name(file: &str) -> Option<&str> {
    let name = file
        .strip_prefix(CHECKPOINT_PREFIX)?
        .strip_suffix(".json")?;
    checkpoint_name_ok(name).then_some(name)
}

fn revision_number(name: &str) -> Option<u32> {
    let digits = name
        .strip_prefix(REVISION_PREFIX)?
        .strip_suffix(REVISION_SUFFIX)?;
    let canonical = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'));
    if !canonical {
        return None;
    }
    digits.parse().ok()
}

#[derive(Debug, Clone)]
pub struct FileStorage {
    dir: PathBuf,
    /// G1.6zn: while this file exists the disk is gone, and its text says so.
    gone: Option<PathBuf>,
    /// G4.1zn: flushes past [`SLOW_FLUSH`], told in the log at most once
    /// every [`SLOW_LOG_EVERY`].
    slow: RefCell<SlowFlushes>,
}

/// A flush (fsync, fdatasync, a directory's fsync) that took longer than
/// this is logged: a commit waits for one or two of them, so slow flash (a
/// USB stick, a worn SD card) shows up here first (G4.1zn: ~15 ms each on
/// the phase C notebook's USB SSD, **estimado** from its command times).
pub const SLOW_FLUSH: Duration = Duration::from_millis(100);
const SLOW_LOG_EVERY: Duration = Duration::from_secs(10);

/// How many fsyncs [`FileStorage::sync_files`] runs at once (G0.30n): 8
/// and 16 measured the same, and a checkpoint writes at most 64 files.
const SYNC_THREADS: usize = 16;

/// `fsync` of every file of `paths`, [`SYNC_THREADS`] at a time, each
/// thread one share of them; the first error, if any. A thread that cannot
/// be started leaves its share to this one.
fn sync_all_at_once(paths: &[PathBuf]) -> io::Result<()> {
    fn sync(share: &[PathBuf]) -> io::Result<()> {
        for p in share {
            File::open(p)?.sync_all()?;
        }
        Ok(())
    }
    let per = paths.len().div_ceil(SYNC_THREADS).max(1);
    std::thread::scope(|s| {
        let mut started = Vec::new();
        let mut here = Ok(());
        for share in paths.chunks(per) {
            match std::thread::Builder::new()
                .name("config-fsync".into())
                .spawn_scoped(s, move || sync(share))
            {
                Ok(t) => started.push(t),
                Err(_) => here = here.and(sync(share)),
            }
        }
        started.into_iter().fold(here, |first, t| {
            let r = t
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("a config-fsync thread panicked")));
            first.and(r)
        })
    })
}

#[derive(Debug, Clone, Default)]
struct SlowFlushes {
    told: Option<Instant>,
    /// Since the last line: how many, the worst and what it was.
    count: u32,
    worst: Duration,
    worst_what: String,
}

impl FileStorage {
    /// Use `dir` (created if missing). A temp file left by a crashed save is
    /// discarded: it was never renamed into place, so it may be partial.
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        if !fs::metadata(&dir)?.is_dir() {
            return Err(io::Error::other(format!(
                "{} is not a directory",
                dir.display()
            )));
        }
        let me = Self {
            dir,
            gone: None,
            slow: RefCell::default(),
        };
        match fs::remove_file(me.path(TEMP)) {
            Ok(()) => log::warn!("removed {TEMP} left by an interrupted save"),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        // The same for state and journal rewrites (`state-x.json.tmp`,
        // `journal-x.log.tmp`): never renamed into place, so partial.
        for entry in fs::read_dir(&me.dir)? {
            let Ok(entry) = entry else { continue };
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let stale = (name.starts_with("state-")
                || name.starts_with("journal-")
                || name.starts_with(REVISION_PREFIX)
                || name.starts_with(CHECKPOINT_PREFIX))
                && name.ends_with(".tmp");
            if stale {
                match fs::remove_file(entry.path()) {
                    Ok(()) => log::warn!("removed {name} left by an interrupted save"),
                    Err(e) => log::warn!("cannot remove {name}: {e}"),
                }
            }
        }
        Ok(me)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// G1.6zn: refuse every write while `marker` exists, with its text
    /// (`corerouter-init` writes it when the system disk goes away:
    /// `corerouter_sysupdate::system_disk`). One `stat` per write.
    pub fn refuse_while(mut self, marker: impl Into<PathBuf>) -> Self {
        self.gone = Some(marker.into());
        self
    }

    /// The marker's line, while it exists.
    fn gone_text(&self) -> Option<String> {
        let f = File::open(self.gone.as_ref()?).ok()?;
        let mut text = String::new();
        let _ = f.take(4096).read_to_string(&mut text);
        let text = text.trim();
        Some(if text.is_empty() {
            "the disk of the configuration is gone: changes are no longer saved".to_owned()
        } else {
            text.to_owned()
        })
    }

    fn guard(&self) -> Result<(), StorageError> {
        match self.gone_text() {
            Some(t) => Err(StorageError(t)),
            None => Ok(()),
        }
    }

    pub fn path(&self, file: &str) -> PathBuf {
        self.dir.join(file)
    }

    fn slot_file(slot: Slot) -> &'static str {
        match slot {
            Slot::Current => CURRENT,
            Slot::Previous => PREVIOUS,
        }
    }

    fn err(&self, what: &str, e: &io::Error) -> StorageError {
        if e.kind() == io::ErrorKind::StorageFull {
            // The same word on every system (G1.6w, `storage::no_space`).
            return StorageError(format!(
                "{what} in {}: {e} ({})",
                self.dir.display(),
                corerouter_engine::storage::NO_SPACE
            ));
        }
        StorageError(format!("{what} in {}: {e}", self.dir.display()))
    }

    fn state_file(name: &str) -> Result<String, StorageError> {
        if state_name_ok(name) {
            Ok(format!("state-{name}.json"))
        } else {
            Err(StorageError(format!("bad state name '{name}'")))
        }
    }

    fn journal_file(name: &str) -> Result<String, StorageError> {
        if state_name_ok(name) {
            Ok(format!("journal-{name}.log"))
        } else {
            Err(StorageError(format!("bad journal name '{name}'")))
        }
    }

    fn write_temp(&self, data: &str) -> io::Result<()> {
        self.write_file(TEMP, data)
    }

    fn write_file(&self, file: &str, data: &str) -> io::Result<()> {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // The config will hold secrets (BGP/RADIUS keys): owner only.
            opts.mode(0o600);
        }
        let path = self.path(file);
        let mut f = opts.open(&path)?;
        let written = f
            .write_all(data.as_bytes())
            .and_then(|()| self.flush(file, || f.sync_all()));
        if written.is_err() {
            // A full disk must not also collect half-written temporaries,
            // one per failed commit (G1.6w).
            drop(f);
            let _ = fs::remove_file(&path);
        }
        written
    }

    /// [`Self::write_file`] without the flush: the caller makes it durable
    /// ([`Self::sync_files`]). A failed write removes the file.
    fn write_unsynced(&self, file: &str, data: &str) -> io::Result<()> {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let path = self.path(file);
        let written = opts
            .open(&path)
            .and_then(|mut f| f.write_all(data.as_bytes()));
        if written.is_err() {
            let _ = fs::remove_file(&path);
        }
        written
    }

    /// Make the renames durable (POSIX: a rename is only on disk once the
    /// directory is synced). Windows has no directory handle to sync.
    fn sync_dir(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            let d = File::open(&self.dir)?;
            self.flush("the directory", || d.sync_all())?;
        }
        Ok(())
    }

    /// `sync`, timed: a slow one goes to the log (G4.1zn).
    fn flush(&self, what: &str, sync: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        let started = Instant::now();
        let done = sync();
        let took = started.elapsed();
        if took >= SLOW_FLUSH {
            self.slow_flush(what, took);
        }
        done
    }

    fn slow_flush(&self, what: &str, took: Duration) {
        let Ok(mut s) = self.slow.try_borrow_mut() else {
            return;
        };
        s.count = s.count.saturating_add(1);
        if took > s.worst {
            s.worst = took;
            s.worst_what = what.to_owned();
        }
        if s.told.is_some_and(|t| t.elapsed() < SLOW_LOG_EVERY) {
            return;
        }
        log::warn!(
            "config disk slow: {} flush(es) over {} ms in {}, the worst {} ms ({}); every commit waits for one",
            s.count,
            SLOW_FLUSH.as_millis(),
            self.dir.display(),
            s.worst.as_millis(),
            s.worst_what
        );
        *s = SlowFlushes {
            told: Some(Instant::now()),
            ..SlowFlushes::default()
        };
    }

    /// G4.1zn: the files of `revs` durable together: their fsyncs at
    /// once, [`SYNC_THREADS`] at a time, so the filesystem joins them in
    /// one journal commit instead of one flush after another (64 files on
    /// a disk with 15 ms flushes took 1.8 s one after another, **medido**
    /// in the VM over dm-delay).
    ///
    /// G0.30n: not a `syncfs`. It flushes the whole filesystem and waits
    /// for what every other program wrote to it: a log, a graph store, a
    /// package being downloaded, another build on a shared disk. 64 files
    /// with another program leaving 2 GB to write on the same disk: syncfs
    /// 10.7–32 s, these fsyncs 0.10–0.23 s; on a quiet disk 16–114 ms
    /// against 68–112 ms (**medido**, NVMe ext4, 2026-11-21). The shutdown
    /// checkpoint hung on it past the tests' 10 s.
    fn sync_files(&self, files: &[String]) -> io::Result<()> {
        let paths: Vec<PathBuf> = files.iter().map(|f| self.path(f)).collect();
        self.flush("the revision files", || sync_all_at_once(&paths))
    }
}

impl ConfigStorage for FileStorage {
    fn describe(&self) -> String {
        format!("file {}", self.dir.display())
    }

    fn unavailable(&self) -> Option<String> {
        self.gone_text()
    }

    fn load(&mut self, slot: Slot) -> Result<Option<String>, StorageError> {
        let file = Self::slot_file(slot);
        let f = match File::open(self.path(file)) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(self.err(&format!("open {file}"), &e)),
        };
        // Read one byte past the limit: an oversized or non-UTF-8 file comes
        // back as text the decoder rejects, so the engine quarantines it.
        let limit = u64::try_from(MAX_FILE_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let mut bytes = Vec::new();
        f.take(limit)
            .read_to_end(&mut bytes)
            .map_err(|e| self.err(&format!("read {file}"), &e))?;
        Ok(Some(match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        }))
    }

    fn save(&mut self, data: &str) -> Result<(), StorageError> {
        self.guard()?;
        self.write_temp(data)
            .map_err(|e| self.err(&format!("write {TEMP}"), &e))?;
        match fs::rename(self.path(CURRENT), self.path(PREVIOUS)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(self.err(&format!("rename {CURRENT} → {PREVIOUS}"), &e)),
        }
        fs::rename(self.path(TEMP), self.path(CURRENT))
            .map_err(|e| self.err(&format!("rename {TEMP} → {CURRENT}"), &e))?;
        self.sync_dir().map_err(|e| self.err("sync", &e))
    }

    fn quarantine(&mut self, slot: Slot) -> Result<(), StorageError> {
        self.guard()?;
        let file = Self::slot_file(slot);
        // Never over an earlier copy: each one is evidence.
        let mut bad = format!("{file}{CORRUPT_SUFFIX}");
        let mut n = 0u32;
        while self.path(&bad).exists() && n < 1000 {
            n += 1;
            bad = format!("{file}{CORRUPT_SUFFIX}.{n}");
        }
        match fs::rename(self.path(file), self.path(&bad)) {
            Ok(()) => {
                log::warn!("moved unreadable {file} to {bad}");
                self.sync_dir().map_err(|e| self.err("sync", &e))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(self.err(&format!("rename {file} → {bad}"), &e)),
        }
    }

    fn load_state(&mut self, name: &str) -> Result<Option<String>, StorageError> {
        let file = Self::state_file(name)?;
        let f = match File::open(self.path(&file)) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(self.err(&format!("open {file}"), &e)),
        };
        let limit = u64::try_from(MAX_STATE_BYTES).unwrap_or(u64::MAX);
        let mut bytes = Vec::new();
        f.take(limit)
            .read_to_end(&mut bytes)
            .map_err(|e| self.err(&format!("read {file}"), &e))?;
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }

    fn save_state(&mut self, name: &str, data: &str) -> Result<(), StorageError> {
        self.guard()?;
        let file = Self::state_file(name)?;
        if data.len() > MAX_STATE_BYTES {
            return Err(StorageError(format!("{file}: too large")));
        }
        let temp = format!("{file}.tmp");
        self.write_file(&temp, data)
            .map_err(|e| self.err(&format!("write {temp}"), &e))?;
        fs::rename(self.path(&temp), self.path(&file))
            .map_err(|e| self.err(&format!("rename {temp} → {file}"), &e))?;
        self.sync_dir().map_err(|e| self.err("sync", &e))
    }

    fn load_journal(&mut self, name: &str) -> Result<Option<String>, StorageError> {
        let file = Self::journal_file(name)?;
        let f = match File::open(self.path(&file)) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(self.err(&format!("open {file}"), &e)),
        };
        let limit = u64::try_from(MAX_JOURNAL_BYTES).unwrap_or(u64::MAX);
        let bytes = read_tail(f, limit).map_err(|e| self.err(&format!("read {file}"), &e))?;
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }

    fn append_journal(&mut self, name: &str, lines: &str) -> Result<(), StorageError> {
        self.guard()?;
        let file = Self::journal_file(name)?;
        let mut opts = OpenOptions::new();
        opts.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(self.path(&file))
            .map_err(|e| self.err(&format!("open {file}"), &e))?;
        let fresh = f.metadata().map(|m| m.len() == 0).unwrap_or(false);
        f.write_all(lines.as_bytes())
            .map_err(|e| self.err(&format!("append {file}"), &e))?;
        // fdatasync: the lines (and the size) are on disk, not the times.
        self.flush(&file, || f.sync_data())
            .map_err(|e| self.err(&format!("sync {file}"), &e))?;
        if fresh {
            // A new file's directory entry must reach the disk too.
            self.sync_dir().map_err(|e| self.err("sync", &e))?;
        }
        Ok(())
    }

    fn rewrite_journal(&mut self, name: &str, text: &str) -> Result<(), StorageError> {
        self.guard()?;
        let file = Self::journal_file(name)?;
        let temp = format!("{file}.tmp");
        self.write_file(&temp, text)
            .map_err(|e| self.err(&format!("write {temp}"), &e))?;
        fs::rename(self.path(&temp), self.path(&file))
            .map_err(|e| self.err(&format!("rename {temp} → {file}"), &e))?;
        self.sync_dir().map_err(|e| self.err("sync", &e))
    }

    fn revision_files(&self) -> bool {
        true
    }

    fn config_journal(&self) -> bool {
        true
    }

    fn list_revisions(&mut self) -> Result<Vec<u32>, StorageError> {
        let entries = fs::read_dir(&self.dir).map_err(|e| self.err("list", &e))?;
        let mut found = Vec::new();
        for entry in entries {
            let Ok(entry) = entry else { continue };
            if let Some(n) = entry.file_name().to_str().and_then(revision_number) {
                found.push(n);
            }
        }
        Ok(found)
    }

    fn load_revision(&mut self, number: u32) -> Result<Option<String>, StorageError> {
        let file = revision_file(number);
        let f = match File::open(self.path(&file)) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(self.err(&format!("open {file}"), &e)),
        };
        // Like a slot: past the limit it comes back as text the decoder
        // refuses.
        let limit = u64::try_from(MAX_FILE_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let mut bytes = Vec::new();
        f.take(limit)
            .read_to_end(&mut bytes)
            .map_err(|e| self.err(&format!("read {file}"), &e))?;
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }

    fn save_revision(&mut self, number: u32, data: &str) -> Result<(), StorageError> {
        self.guard()?;
        let file = revision_file(number);
        let temp = format!("{file}.tmp");
        self.write_file(&temp, data)
            .map_err(|e| self.err(&format!("write {temp}"), &e))?;
        // Durable with the slot's directory fsync, which comes next.
        fs::rename(self.path(&temp), self.path(&file))
            .map_err(|e| self.err(&format!("rename {temp} → {file}"), &e))
    }

    /// Every file written and renamed without its own flush, then all made
    /// durable at once ([`Self::sync_files`]), before the slot that needs
    /// them is written. A crash before that leaves files the slot on disk
    /// does not need (the revisions its journal still holds, which the boot
    /// ignores); the next checkpoint writes them again. One file: the
    /// single path.
    fn save_revisions(&mut self, files: &[(u32, &str)]) -> Vec<Result<(), StorageError>> {
        if files.len() < 2 {
            return files
                .iter()
                .map(|(number, data)| self.save_revision(*number, data))
                .collect();
        }
        if let Err(e) = self.guard() {
            return files.iter().map(|_| Err(e.clone())).collect();
        }
        let mut done: Vec<Result<(), StorageError>> = Vec::with_capacity(files.len());
        let mut written: Vec<String> = Vec::new();
        for (number, data) in files {
            let file = revision_file(*number);
            let temp = format!("{file}.tmp");
            let wrote = self
                .write_unsynced(&temp, data)
                .map_err(|e| self.err(&format!("write {temp}"), &e))
                .and_then(|()| {
                    fs::rename(self.path(&temp), self.path(&file))
                        .map_err(|e| self.err(&format!("rename {temp} → {file}"), &e))
                });
            if wrote.is_ok() {
                written.push(file);
            }
            done.push(wrote);
        }
        if let Err(e) = self.sync_files(&written) {
            let e = self.err("sync the revision files", &e);
            return files.iter().map(|_| Err(e.clone())).collect();
        }
        done
    }

    fn remove_revision(&mut self, number: u32) -> Result<(), StorageError> {
        self.guard()?;
        let file = revision_file(number);
        match fs::remove_file(self.path(&file)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(self.err(&format!("remove {file}"), &e)),
        }
    }

    fn list_checkpoints(&mut self) -> Result<Vec<String>, StorageError> {
        let entries = fs::read_dir(&self.dir).map_err(|e| self.err("list", &e))?;
        let mut found = Vec::new();
        for entry in entries {
            let Ok(entry) = entry else { continue };
            if let Some(name) = entry.file_name().to_str().and_then(checkpoint_name) {
                found.push(name.to_owned());
            }
        }
        Ok(found)
    }

    fn load_checkpoint(&mut self, name: &str) -> Result<Option<String>, StorageError> {
        let file = checkpoint_file(name)?;
        let f = match File::open(self.path(&file)) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(self.err(&format!("open {file}"), &e)),
        };
        // Like a slot: past the limit it comes back as text the decoder
        // refuses.
        let limit = u64::try_from(MAX_FILE_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        let mut bytes = Vec::new();
        f.take(limit)
            .read_to_end(&mut bytes)
            .map_err(|e| self.err(&format!("read {file}"), &e))?;
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }

    fn save_checkpoint(&mut self, name: &str, data: &str) -> Result<(), StorageError> {
        self.guard()?;
        let file = checkpoint_file(name)?;
        let temp = format!("{file}.tmp");
        self.write_file(&temp, data)
            .map_err(|e| self.err(&format!("write {temp}"), &e))?;
        fs::rename(self.path(&temp), self.path(&file))
            .map_err(|e| self.err(&format!("rename {temp} → {file}"), &e))?;
        self.sync_dir().map_err(|e| self.err("sync", &e))
    }

    fn remove_checkpoint(&mut self, name: &str) -> Result<(), StorageError> {
        self.guard()?;
        let file = checkpoint_file(name)?;
        match fs::remove_file(self.path(&file)) {
            Ok(()) => self.sync_dir().map_err(|e| self.err("sync", &e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(self.err(&format!("remove {file}"), &e)),
        }
    }
}

/// The last `limit` bytes of `f`, from the first line that starts inside
/// them (the whole file when it is smaller). A journal is "the last line
/// wins": past the limit the newest lines are the ones to keep, never the
/// oldest (a journal that could not be compacted keeps growing).
pub fn read_tail(mut f: File, limit: u64) -> io::Result<Vec<u8>> {
    use std::io::{Seek, SeekFrom};
    let len = f.metadata()?.len();
    let mut bytes = Vec::new();
    if len <= limit {
        f.take(limit).read_to_end(&mut bytes)?;
        return Ok(bytes);
    }
    log::warn!("journal of {len} bytes is over {limit}: only its newest lines are read");
    f.seek(SeekFrom::Start(len - limit))?;
    f.take(limit).read_to_end(&mut bytes)?;
    // The first line is cut: it starts after the first newline.
    let start = bytes
        .iter()
        .position(|b| *b == b'\n')
        .map_or(bytes.len(), |i| i + 1);
    Ok(bytes.split_off(start))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// G0.33: checkpoints are files of their own, listed by name, and a
    /// temp file of an interrupted write is gone at the next open.
    #[test]
    fn checkpoints_on_disk() {
        let d = std::env::temp_dir().join(format!("storage-fs-ckpt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let mut st = FileStorage::open(&d).unwrap();
        assert_eq!(st.list_checkpoints().unwrap(), Vec::<String>::new());
        st.save_checkpoint("before-lab", "{}\n").unwrap();
        st.save_checkpoint("b_2", "x").unwrap();
        assert!(st.save_checkpoint("../x", "x").is_err());
        let mut names = st.list_checkpoints().unwrap();
        names.sort();
        assert_eq!(names, ["b_2", "before-lab"]);
        assert_eq!(
            st.load_checkpoint("before-lab").unwrap().as_deref(),
            Some("{}\n")
        );
        assert_eq!(st.load_checkpoint("none").unwrap(), None);
        st.remove_checkpoint("b_2").unwrap();
        st.remove_checkpoint("b_2").unwrap();
        assert_eq!(st.list_checkpoints().unwrap(), ["before-lab"]);
        fs::write(d.join("checkpoint-c.json.tmp"), "partial").unwrap();
        fs::write(d.join("checkpoint-bad name.json"), "x").unwrap();
        let mut st = FileStorage::open(&d).unwrap();
        assert!(!d.join("checkpoint-c.json.tmp").exists());
        assert_eq!(st.list_checkpoints().unwrap(), ["before-lab"]);
        fs::remove_dir_all(&d).unwrap();
    }

    /// G0.30n: every file gets its fsync, in shares over the threads (1,
    /// fewer than, as many as and more than [`SYNC_THREADS`] files), and a
    /// file that is gone fails the whole call while the rest still run.
    #[test]
    fn the_revision_files_are_synced_at_once() {
        let d = std::env::temp_dir().join(format!("storage-fs-sync-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let paths: Vec<PathBuf> = (0..SYNC_THREADS * 4 + 3)
            .map(|i| {
                let p = d.join(format!("f{i}"));
                fs::write(&p, "x").unwrap();
                p
            })
            .collect();
        for n in [0, 1, SYNC_THREADS - 1, SYNC_THREADS, paths.len()] {
            sync_all_at_once(&paths[..n]).unwrap();
        }
        let mut gone = paths.clone();
        gone.insert(5, d.join("missing"));
        let e = sync_all_at_once(&gone).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        // Through the storage: a checkpoint of many revisions.
        let mut st = FileStorage::open(&d).unwrap();
        let files: Vec<(u32, String)> = (0..40).map(|i| (i, format!("{{\"r\":{i}}}"))).collect();
        let refs: Vec<(u32, &str)> = files.iter().map(|(n, s)| (*n, s.as_str())).collect();
        assert!(st.save_revisions(&refs).iter().all(Result::is_ok));
        assert_eq!(
            fs::read_to_string(d.join(revision_file(39))).unwrap(),
            "{\"r\":39}"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn revision_names_are_strict() {
        assert_eq!(revision_number(&revision_file(0)), Some(0));
        assert_eq!(
            revision_number(&revision_file(4_000_000_000)),
            Some(4_000_000_000)
        );
        for bad in [
            "rev-.json",
            "rev-01.json",
            "rev-+1.json",
            "rev-1.json.tmp",
            "rev-1.jsonx",
            "rev-99999999999.json",
            "running.json",
        ] {
            assert_eq!(revision_number(bad), None, "{bad}");
        }
    }

    /// G1.6zn: the system disk went away: every write is refused with the
    /// line `corerouter-init` wrote, and what was saved still reads.
    #[test]
    fn a_missing_disk_refuses_writes_with_its_line() {
        let base = std::env::temp_dir().join(format!("cr-fs-gone-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let marker = base.join("system-disk-removed");
        let mut st = FileStorage::open(base.join("config"))
            .unwrap()
            .refuse_while(&marker);
        st.save("{}").unwrap();
        assert_eq!(st.unavailable(), None);
        fs::write(
            &marker,
            "system disk sda removed: changes are no longer saved\n",
        )
        .unwrap();
        let line = st.unavailable().unwrap();
        assert_eq!(line, "system disk sda removed: changes are no longer saved");
        assert!(st.save("{\"x\":1}").unwrap_err().0.contains("sda removed"));
        assert!(st.save_state("dhcp-leases", "[]").is_err());
        assert!(st.append_journal("config", "x\n").is_err());
        assert!(st.save_revision(3, "{}").is_err());
        assert_eq!(st.load(Slot::Current).unwrap().as_deref(), Some("{}"));
        fs::remove_file(&marker).unwrap();
        st.save("{\"x\":1}").unwrap();
        let _ = fs::remove_dir_all(&base);
    }
}
