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
}

#[derive(Debug, Default)]
struct Slots {
    current: Option<String>,
    previous: Option<String>,
    quarantined: Vec<String>,
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
}
