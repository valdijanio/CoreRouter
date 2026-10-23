//! G1.23 — the revision history kept one file per revision, so a commit
//! writes the size of the config and not of the whole history.
//!
//! Layout on a [`ConfigStorage`] with `revision_files()`:
//!
//! - the slots (`running.json`, `running.json.prev`) hold the running
//!   config and its newest revision only (the same format an older build
//!   writes and reads, with a one-entry history);
//! - each revision of the history has a file of its own (`rev-<n>.json`,
//!   [`persist::encode_revision`]), written once by the commit that made it
//!   and deleted when it leaves the history.
//!
//! A save writes the missing revision files first, then the slot, then
//! deletes the files past the history. After a crash at any step the slot
//! is complete (the old or the new one) and every revision file it needs
//! older than itself was written by an earlier save; a file of a newer
//! revision than the slot (a save cut short) is ignored at boot and
//! overwritten by the next commit. A missing or unreadable revision file
//! costs that revision only: it is reported under `boot_errors` and left out.
//!
//! The commit serializes the new config once
//! ([`RevisionFiles::note_encoded`]); the save splices that text into the
//! slot (twice: `running` and the newest revision) and into the new
//! revision file, so nothing else is serialized (**medido**: see
//! `engine_scale/commit/*` in docs/changes/audit-perf.md).

use std::collections::{BTreeMap, BTreeSet};

use corerouter_model::persist;
use corerouter_model::store::Revision;
use corerouter_model::{ConfigStore, Users};

use crate::storage::ConfigStorage;

/// What the storage holds of the history (runtime state in the session's
/// extensions; rebuilt at boot from the files themselves).
#[derive(Debug, Default)]
pub(crate) struct RevisionFiles {
    /// Revision files present on the storage.
    present: BTreeSet<u32>,
    /// Files known to hold the in-memory revision of that number, by size.
    saved: BTreeMap<u32, usize>,
    /// Compact JSON of the config the last commit made (its revision), so
    /// the save that follows does not serialize it again.
    encoded: Option<(u32, String)>,
}

impl RevisionFiles {
    /// The commit that made revision `number` already serialized it.
    pub(crate) fn note_encoded(&mut self, number: u32, text: String) {
        self.encoded = Some((number, text));
    }
}

/// Complete a store restored from a slot with the revisions kept in files
/// (older than the slot's own history), and learn what the files hold.
/// Unreadable revision files are reported in `errors` and left out.
pub(crate) fn restore_history(
    storage: &mut dyn ConfigStorage,
    store: Option<ConfigStore>,
    errors: &mut Vec<String>,
) -> (Option<ConfigStore>, RevisionFiles) {
    let mut files = RevisionFiles::default();
    if !storage.revision_files() {
        return (store, files);
    }
    match storage.list_revisions() {
        Ok(found) => files.present = found.into_iter().collect(),
        Err(e) => {
            log::error!("cannot list the revision files: {e}");
            errors.push(format!("revisions: {e}"));
            return (store, files);
        }
    }
    let Some(store) = store else {
        return (None, files);
    };
    let Some(first) = store.history().first().map(|r| r.number) else {
        return (Some(store), files);
    };
    // The newest revision is in the slot itself; its file counts as saved
    // only if it holds the same config (it is rewritten otherwise).
    let newest = store.current_revision();
    if files.present.contains(&newest) {
        if let Some((rev, size)) = load(storage, newest, &mut Vec::new()) {
            if rev.config == *store.running() {
                files.saved.insert(newest, size);
            }
        }
    }
    let room = ConfigStore::DEFAULT_MAX_HISTORY.saturating_sub(store.history().len());
    let mut older: Vec<Revision> = Vec::new();
    for &n in files.present.range(..first).rev() {
        if older.len() >= room {
            break;
        }
        if let Some((rev, size)) = load(storage, n, errors) {
            files.saved.insert(n, size);
            older.push(rev);
        }
    }
    if older.is_empty() {
        return (Some(store), files);
    }
    older.reverse();
    log::info!(
        "{} older revision(s) restored from their files",
        older.len()
    );
    older.extend_from_slice(store.history());
    (
        Some(ConfigStore::restore(store.running().clone(), older)),
        files,
    )
}

/// Revision file `number` and its size, or `None` (reported in `errors`).
fn load(
    storage: &mut dyn ConfigStorage,
    number: u32,
    errors: &mut Vec<String>,
) -> Option<(Revision, usize)> {
    let fail = |errors: &mut Vec<String>, e: String| {
        log::error!("revision {number} file is unreadable, left out: {e}");
        errors.push(format!("revision {number}: {e}"));
    };
    match storage.load_revision(number) {
        Ok(Some(text)) => match persist::decode_revision(&text, number) {
            Ok(rev) => Some((rev, text.len())),
            Err(e) => {
                fail(errors, e.to_string());
                None
            }
        },
        Ok(None) => {
            fail(errors, "missing".into());
            None
        }
        Err(e) => {
            fail(errors, e.to_string());
            None
        }
    }
}

/// Save `store` as revision files + the slot: only the revisions without a
/// file are written (the new one, after a commit). Keeps the newest
/// revisions whose files fit in `budget` bytes and returns how many older
/// ones were left out, like [`persist::encode_bounded`].
pub(crate) fn save(
    storage: &mut dyn ConfigStorage,
    files: &mut RevisionFiles,
    store: &ConfigStore,
    users: &Users,
    budget: usize,
) -> Result<usize, String> {
    let history = store.history();
    let Some(newest) = history.last() else {
        return Err("empty history".into());
    };
    let config = match files.encoded.take() {
        Some((n, text)) if n == newest.number => text,
        _ => persist::encode_config(&newest.config).map_err(|e| e.to_string())?,
    };
    // The newest revision is always kept; then the newest older ones that
    // fit. Only the ones without a file are serialized.
    let mut used = config.len();
    let mut write: Vec<(&Revision, String)> = Vec::new();
    let mut keep: BTreeSet<u32> = BTreeSet::from([newest.number]);
    for rev in history.iter().rev().skip(1) {
        let (size, text) = match files.saved.get(&rev.number) {
            Some(size) => (*size, None),
            None => {
                let text = persist::encode_config(&rev.config).map_err(|e| e.to_string())?;
                (text.len(), Some(text))
            }
        };
        if used.saturating_add(size) > budget {
            break;
        }
        used = used.saturating_add(size);
        keep.insert(rev.number);
        if let Some(text) = text {
            write.push((rev, text));
        }
    }
    let skipped = history.len().saturating_sub(keep.len());
    for (rev, text) in &write {
        put(storage, files, rev, text)?;
    }
    if !files.saved.contains_key(&newest.number) {
        put(storage, files, newest, &config)?;
    }
    let text = persist::encode_running(newest, &config, users).map_err(|e| e.to_string())?;
    storage.save(&text).map_err(|e| e.to_string())?;
    // Past the history now: the slot that needed them was just replaced.
    let stale: Vec<u32> = files.present.difference(&keep).copied().collect();
    for n in stale {
        match storage.remove_revision(n) {
            Ok(()) => {
                files.present.remove(&n);
                files.saved.remove(&n);
            }
            Err(e) => log::warn!("cannot delete revision {n} file: {e}"),
        }
    }
    Ok(skipped)
}

fn put(
    storage: &mut dyn ConfigStorage,
    files: &mut RevisionFiles,
    rev: &Revision,
    config: &str,
) -> Result<(), String> {
    let text = persist::encode_revision(rev, config).map_err(|e| e.to_string())?;
    // Whatever was there is replaced: until it is written, no file counts.
    files.saved.remove(&rev.number);
    files.present.insert(rev.number);
    storage
        .save_revision(rev.number, &text)
        .map_err(|e| e.to_string())?;
    files.saved.insert(rev.number, text.len());
    Ok(())
}
