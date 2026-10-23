//! Where the committed config lives between boots.
//!
//! The engine never does I/O itself (it must compile for wasm32): it hands
//! encoded bytes (`corerouter_model::persist`) to a [`ConfigStorage`] after
//! every commit and asks for them back at start-up. The daemon plugs in a
//! file backend (`corerouter-storage-fs`); the GUI, wasm and tests use
//! [`MemoryStorage`].
//!
//! Two slots are kept so a torn or corrupted write never loses everything:
//! [`Slot::Current`] is the last save, [`Slot::Previous`] the one before.
//!
//! A backend with [`ConfigStorage::revision_files`] keeps each older
//! revision in a file of its own, written once, as a difference to the
//! next newer revision (G1.23 and audit-history, see
//! `crate::history_files`): a slot then holds the running config and its
//! newest revision only, so a commit costs the size of the config, not of
//! the history.

use std::sync::{Arc, Mutex, PoisonError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// Last successful save (`running.json` on disk).
    Current,
    /// The save before it (`running.json.prev`).
    Previous,
}

impl Slot {
    pub fn name(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Previous => "previous",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("config storage: {0}")]
pub struct StorageError(pub String);

pub trait ConfigStorage: Send {
    /// "file /config", "memory": shown by `state.inspect`.
    fn describe(&self) -> String;

    /// Contents of `slot`, or `None` if it was never written.
    fn load(&mut self, slot: Slot) -> Result<Option<String>, StorageError>;

    /// Store `data` as [`Slot::Current`], moving the old current to
    /// [`Slot::Previous`]. Must be atomic: after a crash at any point, each
    /// slot holds either its old or its new contents, never a mix.
    fn save(&mut self, data: &str) -> Result<(), StorageError>;

    /// Move an unreadable `slot` out of the way (kept for forensics), so the
    /// next save does not rotate garbage over a good [`Slot::Previous`].
    fn quarantine(&mut self, slot: Slot) -> Result<(), StorageError>;

    /// Operational state kept across restarts but outside the config and
    /// its revisions (DHCP leases, G4.7c), by `name` (see [`state_name_ok`]).
    /// Default: nothing is kept.
    fn load_state(&mut self, name: &str) -> Result<Option<String>, StorageError> {
        let _ = name;
        Ok(None)
    }

    /// Replace state `name` with `data`, atomically like [`Self::save`].
    fn save_state(&mut self, name: &str, data: &str) -> Result<(), StorageError> {
        let _ = (name, data);
        Ok(())
    }

    /// The whole text of append-only journal `name` (the DHCP server's
    /// leases, G4.2a), or `None` if it was never written.
    fn load_journal(&mut self, name: &str) -> Result<Option<String>, StorageError> {
        let _ = name;
        Ok(None)
    }

    /// Append `lines` to journal `name`, on disk (synced) before it
    /// returns: a reply that depends on them goes out after. A crash may
    /// leave a torn last line, which the reader skips.
    fn append_journal(&mut self, name: &str, lines: &str) -> Result<(), StorageError> {
        let _ = (name, lines);
        Ok(())
    }

    /// Replace journal `name` with `text` (its compaction), atomically:
    /// after a crash it is either the old journal or the new one.
    fn rewrite_journal(&mut self, name: &str, text: &str) -> Result<(), StorageError> {
        let _ = (name, text);
        Ok(())
    }

    /// Whether older revisions are kept one per file (G1.23): a save then
    /// writes the running config and the new revision, not the whole
    /// history. `false` (the default): every save carries the history.
    fn revision_files(&self) -> bool {
        false
    }

    /// Numbers of the revision files present (any order).
    fn list_revisions(&mut self) -> Result<Vec<u32>, StorageError> {
        Ok(Vec::new())
    }

    /// Contents of revision file `number`, or `None` if there is none.
    fn load_revision(&mut self, number: u32) -> Result<Option<String>, StorageError> {
        let _ = number;
        Ok(None)
    }

    /// Write revision file `number` (complete and synced, or absent, after
    /// a crash; it becomes durable with the next [`Self::save`]).
    fn save_revision(&mut self, number: u32, data: &str) -> Result<(), StorageError> {
        let _ = (number, data);
        Err(StorageError("revision files are not supported".into()))
    }

    /// Delete revision file `number` (a revision past the history).
    fn remove_revision(&mut self, number: u32) -> Result<(), StorageError> {
        let _ = number;
        Ok(())
    }
}

/// Largest journal read back (**estimado**: a /12 of leases at ~200 bytes
/// a line, with room for the lines since the last compaction).
pub const MAX_JOURNAL_BYTES: usize = 512 << 20;

/// Largest state blob kept by [`ConfigStorage::save_state`] (hostile file
/// on the way back in; **estimado**: 256 leases of ~1 KiB).
pub const MAX_STATE_BYTES: usize = 1 << 20;

/// State names are short lowercase words (`dhcp-leases`): they become
/// file names.
pub fn state_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[derive(Debug, Default)]
struct Slots {
    current: Option<String>,
    previous: Option<String>,
    quarantined: Vec<String>,
    state: std::collections::BTreeMap<String, String>,
    journals: std::collections::BTreeMap<String, String>,
    revisions: std::collections::BTreeMap<u32, String>,
}

/// In-memory storage. Clones share the same slots, so a test can keep a
/// handle, drop the session and "reboot" a new one from it.
#[derive(Debug, Clone, Default)]
pub struct MemoryStorage(Arc<Mutex<Slots>>);

impl MemoryStorage {
    fn with<T>(&self, f: impl FnOnce(&mut Slots) -> T) -> T {
        f(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Overwrite a slot directly (tests: simulate corruption).
    pub fn put(&self, slot: Slot, data: Option<String>) {
        self.with(|s| match slot {
            Slot::Current => s.current = data,
            Slot::Previous => s.previous = data,
        });
    }

    pub fn get(&self, slot: Slot) -> Option<String> {
        self.with(|s| match slot {
            Slot::Current => s.current.clone(),
            Slot::Previous => s.previous.clone(),
        })
    }

    pub fn quarantined(&self) -> usize {
        self.with(|s| s.quarantined.len())
    }

    /// Revision file `number` (tests: inspect or corrupt it).
    pub fn revision(&self, number: u32) -> Option<String> {
        self.with(|s| s.revisions.get(&number).cloned())
    }

    /// Overwrite or delete revision file `number` (tests).
    pub fn put_revision(&self, number: u32, data: Option<String>) {
        self.with(|s| match data {
            Some(d) => {
                s.revisions.insert(number, d);
            }
            None => {
                s.revisions.remove(&number);
            }
        });
    }

    /// Bytes stored in revision files (tests: what the history costs).
    pub fn revision_bytes(&self) -> usize {
        self.with(|s| s.revisions.values().map(String::len).sum())
    }
}

impl ConfigStorage for MemoryStorage {
    fn describe(&self) -> String {
        "memory (not persistent)".into()
    }

    fn load(&mut self, slot: Slot) -> Result<Option<String>, StorageError> {
        Ok(self.get(slot))
    }

    fn save(&mut self, data: &str) -> Result<(), StorageError> {
        self.with(|s| {
            if let Some(old) = s.current.replace(data.to_owned()) {
                s.previous = Some(old);
            }
        });
        Ok(())
    }

    fn quarantine(&mut self, slot: Slot) -> Result<(), StorageError> {
        self.with(|s| {
            let taken = match slot {
                Slot::Current => s.current.take(),
                Slot::Previous => s.previous.take(),
            };
            if let Some(bad) = taken {
                s.quarantined.push(bad);
            }
        });
        Ok(())
    }

    fn load_state(&mut self, name: &str) -> Result<Option<String>, StorageError> {
        Ok(self.with(|s| s.state.get(name).cloned()))
    }

    fn save_state(&mut self, name: &str, data: &str) -> Result<(), StorageError> {
        if !state_name_ok(name) || data.len() > MAX_STATE_BYTES {
            return Err(StorageError(format!("state '{name}' refused")));
        }
        self.with(|s| s.state.insert(name.to_owned(), data.to_owned()));
        Ok(())
    }

    fn load_journal(&mut self, name: &str) -> Result<Option<String>, StorageError> {
        Ok(self.with(|s| s.journals.get(name).cloned()))
    }

    fn append_journal(&mut self, name: &str, lines: &str) -> Result<(), StorageError> {
        if !state_name_ok(name) {
            return Err(StorageError(format!("journal '{name}' refused")));
        }
        self.with(|s| {
            let j = s.journals.entry(name.to_owned()).or_default();
            if j.len() + lines.len() > MAX_JOURNAL_BYTES {
                return Err(StorageError(format!("journal '{name}' is full")));
            }
            j.push_str(lines);
            Ok(())
        })
    }

    fn rewrite_journal(&mut self, name: &str, text: &str) -> Result<(), StorageError> {
        if !state_name_ok(name) {
            return Err(StorageError(format!("journal '{name}' refused")));
        }
        self.with(|s| s.journals.insert(name.to_owned(), text.to_owned()));
        Ok(())
    }

    fn revision_files(&self) -> bool {
        true
    }

    fn list_revisions(&mut self) -> Result<Vec<u32>, StorageError> {
        Ok(self.with(|s| s.revisions.keys().copied().collect()))
    }

    fn load_revision(&mut self, number: u32) -> Result<Option<String>, StorageError> {
        Ok(self.revision(number))
    }

    fn save_revision(&mut self, number: u32, data: &str) -> Result<(), StorageError> {
        self.put_revision(number, Some(data.to_owned()));
        Ok(())
    }

    fn remove_revision(&mut self, number: u32) -> Result<(), StorageError> {
        self.put_revision(number, None);
        Ok(())
    }
}
