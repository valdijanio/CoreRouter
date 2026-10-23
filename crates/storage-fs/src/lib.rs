//! L4 — [`ConfigStorage`] on a directory (`/config` on the router image).
//!
//! Layout:
//!
//! | file | slot |
//! |---|---|
//! | `running.json` | [`Slot::Current`] |
//! | `running.json.prev` | [`Slot::Previous`] |
//! | `running.json.tmp` | write in progress (removed on open) |
//! | `*.corrupt`, `*.corrupt.<n>` | quarantined unreadable slot (each one kept) |
//! | `state-<name>.json` | operational state outside the revisions (DHCP client leases) |
//! | `journal-<name>.log` | append-only journal (the DHCP server's leases, G4.2a) |
//!
//! A save is: write `running.json.tmp`, fsync it, rename `running.json` →
//! `running.json.prev`, rename the temp file → `running.json`, fsync the
//! directory. Renames are atomic, so after a crash at any step each slot is a
//! complete file (old or new) or absent; the engine then loads the newest
//! readable one.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use corerouter_engine::storage::{MAX_JOURNAL_BYTES, MAX_STATE_BYTES, state_name_ok};
use corerouter_engine::{ConfigStorage, Slot, StorageError};
use corerouter_model::persist::MAX_FILE_BYTES;

pub const CURRENT: &str = "running.json";
pub const PREVIOUS: &str = "running.json.prev";
pub const TEMP: &str = "running.json.tmp";
pub const CORRUPT_SUFFIX: &str = ".corrupt";

#[derive(Debug, Clone)]
pub struct FileStorage {
    dir: PathBuf,
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
        let me = Self { dir };
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
            let stale = (name.starts_with("state-") || name.starts_with("journal-"))
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
        let mut f = opts.open(self.path(file))?;
        f.write_all(data.as_bytes())?;
        f.sync_all()
    }

    /// Make the renames durable (POSIX: a rename is only on disk once the
    /// directory is synced). Windows has no directory handle to sync.
    fn sync_dir(&self) -> io::Result<()> {
        #[cfg(unix)]
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }
}

impl ConfigStorage for FileStorage {
    fn describe(&self) -> String {
        format!("file {}", self.dir.display())
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
        let mut bytes = Vec::new();
        f.take(limit)
            .read_to_end(&mut bytes)
            .map_err(|e| self.err(&format!("read {file}"), &e))?;
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }

    fn append_journal(&mut self, name: &str, lines: &str) -> Result<(), StorageError> {
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
        f.sync_data()
            .map_err(|e| self.err(&format!("sync {file}"), &e))?;
        if fresh {
            // A new file's directory entry must reach the disk too.
            self.sync_dir().map_err(|e| self.err("sync", &e))?;
        }
        Ok(())
    }

    fn rewrite_journal(&mut self, name: &str, text: &str) -> Result<(), StorageError> {
        let file = Self::journal_file(name)?;
        let temp = format!("{file}.tmp");
        self.write_file(&temp, text)
            .map_err(|e| self.err(&format!("write {temp}"), &e))?;
        fs::rename(self.path(&temp), self.path(&file))
            .map_err(|e| self.err(&format!("rename {temp} → {file}"), &e))?;
        self.sync_dir().map_err(|e| self.err("sync", &e))
    }
}
