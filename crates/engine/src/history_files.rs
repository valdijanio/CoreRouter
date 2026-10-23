//! G1.23 — the revision history kept one file per revision, so a commit
//! writes the size of the config and not of the whole history; and
//! (audit-history) each file holds the difference to the next newer
//! revision, not a full copy, so the 64 revisions of a big config fit the
//! save budget (full copies kept 6 of a 5 MiB config, 3 of a 10 MiB one).
//!
//! Layout on a [`ConfigStorage`] with `revision_files()`:
//!
//! - the slots (`running.json`, `running.json.prev`) hold the running
//!   config and its newest revision only (the same format an older build
//!   writes and reads, with a one-entry history);
//! - each older revision `k` of the history has a file of its own
//!   (`rev-<k>.json`, [`persist::encode_revision_delta`]): a
//!   [`json_delta`] that builds its config from the config of the next
//!   newer revision (its `base`). The newest revision has no file: the
//!   slot holds it whole. File `k` is written by the save after `k` stops
//!   being the newest, once, and deleted when `k` leaves the history.
//!
//! At boot the chain is walked from the slot's revision down: each file
//! applied to the tree of its base gives the next older one. A save writes
//! the missing revision files first, then the slot, then deletes the files
//! past the history. After a crash at any step the slot is complete (the
//! old or the new one) and every file it needs was written before it; a
//! file of the slot's revision or newer (a save cut short, or a boot from
//! the previous slot) is ignored at boot and rewritten by the next save.
//! A missing or unreadable file breaks the chain: it costs that revision
//! and every older one (they depend on it), reported under `boot_errors`;
//! the running config and the newer revisions are unaffected. A full-copy
//! file from a G1.23 build stands on its own (it restarts the chain) and
//! is rewritten as a difference by the next save (migration).
//!
//! The commit serializes the new config once
//! ([`RevisionFiles::note_encoded`]) for the slot; the file of the previous
//! newest revision costs two JSON trees and their comparison (**medido**:
//! `storage_fs/history64/*` in docs/changes/audit-history.md).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use corerouter_model::persist::{self, RevisionFile};
use corerouter_model::store::Revision;
use corerouter_model::{ConfigStore, Users, json_delta};
use serde_json::Value;

use crate::storage::ConfigStorage;

/// A revision file the storage holds for the in-memory revision of the
/// same number.
#[derive(Debug, Clone, Copy)]
struct Saved {
    size: usize,
    /// The revision it is a difference against; `None`: a full copy.
    base: Option<u32>,
}

/// What the storage holds of the history (runtime state in the session's
/// extensions; rebuilt at boot from the files themselves).
#[derive(Debug, Default)]
pub(crate) struct RevisionFiles {
    /// Revision files present on the storage.
    present: BTreeSet<u32>,
    /// Files known to hold the in-memory revision of that number.
    saved: BTreeMap<u32, Saved>,
    /// Compact JSON of the config the last commit made (its revision), so
    /// the save that follows does not serialize it again.
    encoded: Option<(u32, String)>,
    /// Compact JSON of the newest revision the last save wrote: the next
    /// commit turns it into a revision file (compared with the new text,
    /// so neither is serialized again).
    previous: Option<(u32, String)>,
}

impl RevisionFiles {
    /// The commit that made revision `number` already serialized it.
    pub(crate) fn note_encoded(&mut self, number: u32, text: String) {
        self.encoded = Some((number, text));
    }
}

/// Complete a store restored from a slot with the revisions kept in files
/// (older than the slot's own history), and learn what the files hold.
/// Unreadable revision files, and the older ones that depend on them, are
/// reported in `errors` and left out.
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
    let Some(oldest) = store.history().first() else {
        return (Some(store), files);
    };
    let first = oldest.number;
    let room = ConfigStore::DEFAULT_MAX_HISTORY.saturating_sub(store.history().len());
    let mut older: Vec<Revision> = Vec::new();
    // The newer end of the chain: a revision number and its tree (built
    // when a difference first needs it), or `None` once the chain broke.
    let mut chain: Option<(u32, Option<Value>)> = Some((first, None));
    let mut lost: Vec<u32> = Vec::new();
    for &n in files.present.range(..first).rev() {
        if older.len() >= room {
            break;
        }
        let (file, size) = match read(storage, n) {
            Ok(read) => read,
            Err(e) => {
                log::error!("revision {n} file is unreadable, left out: {e}");
                errors.push(format!("revision {n}: {e}"));
                chain = None;
                continue;
            }
        };
        let (rev, tree, base) = match file {
            // A full copy (G1.23) needs nothing newer.
            RevisionFile::Full(rev) => (rev, None, None),
            RevisionFile::Delta {
                mut rev,
                base,
                delta,
            } => {
                let Some((_, tree)) = chain.take().filter(|(newer, _)| *newer == base) else {
                    lost.push(n);
                    continue;
                };
                let tree = match tree {
                    Some(t) => Ok(t),
                    None => {
                        let cfg = older.last().map_or(&oldest.config, |r| &r.config);
                        persist::config_value(cfg)
                    }
                };
                match tree.and_then(|t| persist::apply_revision_delta(t, &delta)) {
                    Ok((cfg, tree)) => {
                        rev.config = cfg;
                        (rev, Some(tree), Some(base))
                    }
                    Err(e) => {
                        log::error!("revision {n} file does not apply, left out: {e}");
                        errors.push(format!("revision {n}: {e}"));
                        continue;
                    }
                }
            }
        };
        files.saved.insert(n, Saved { size, base });
        chain = Some((n, tree));
        older.push(rev);
    }
    if let (Some(hi), Some(lo)) = (lost.first(), lost.last()) {
        log::error!("revisions {lo}..={hi} depend on a lost revision file, left out");
        errors.push(format!(
            "revisions {lo}..{hi}: {} left out, they depend on a newer revision that was lost",
            lost.len()
        ));
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

/// Revision file `number`, parsed, and its size.
fn read(storage: &mut dyn ConfigStorage, number: u32) -> Result<(RevisionFile, usize), String> {
    match storage.load_revision(number) {
        Ok(Some(text)) => persist::decode_revision_file(&text, number)
            .map(|file| (file, text.len()))
            .map_err(|e| e.to_string()),
        Ok(None) => Err("missing".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// Save `store` as revision files + the slot: only the revisions without a
/// file (the previous newest, after a commit) are written. Keeps the
/// newest revisions whose files fit in `budget` bytes and returns how many
/// older ones were left out, like [`persist::encode_bounded`].
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
    // Newest first: each revision is a difference against the next newer
    // one, so the chain stops at the first that does not fit (an older
    // file without its base would be useless).
    let mut used = 0usize;
    let mut keep: BTreeSet<u32> = BTreeSet::new();
    let mut write: Vec<(u32, String, u32)> = Vec::new();
    // The text of the revision just encoded: the base of the next one.
    let mut newer: Option<(u32, String)> = None;
    for pair in history.windows(2).rev() {
        let [rev, base] = pair else { continue };
        let size = match files.saved.get(&rev.number) {
            Some(f) if f.base == Some(base.number) => {
                newer = None;
                f.size
            }
            _ => {
                let base_text: Cow<'_, str> = match newer.take() {
                    Some((n, t)) if n == base.number => Cow::Owned(t),
                    _ if base.number == newest.number => Cow::Borrowed(&config),
                    _ => Cow::Owned(persist::encode_config(&base.config).map_err(|e| e.to_string())?),
                };
                let text = match files.previous.take() {
                    // The newest of the save before: its text is at hand.
                    Some((n, t)) if n == rev.number => t,
                    _ => persist::encode_config(&rev.config).map_err(|e| e.to_string())?,
                };
                let delta = json_delta::diff_text(&base_text, &text).map_err(|e| e.to_string())?;
                drop(base_text);
                let file = persist::encode_revision_delta(rev, base.number, &delta)
                    .map_err(|e| e.to_string())?;
                newer = Some((rev.number, text));
                let size = file.len();
                write.push((rev.number, file, base.number));
                size
            }
        };
        if used.saturating_add(size) > budget {
            write.retain(|(n, _, _)| *n != rev.number);
            break;
        }
        used = used.saturating_add(size);
        keep.insert(rev.number);
    }
    drop(newer);
    // The newest revision is in the slot.
    let skipped = history.len().saturating_sub(keep.len()).saturating_sub(1);
    for (number, text, base) in &write {
        // Whatever was there is replaced: until it is written, no file counts.
        files.saved.remove(number);
        files.present.insert(*number);
        storage
            .save_revision(*number, text)
            .map_err(|e| e.to_string())?;
        files.saved.insert(
            *number,
            Saved {
                size: text.len(),
                base: Some(*base),
            },
        );
    }
    let text = persist::encode_running(newest, &config, users).map_err(|e| e.to_string())?;
    storage.save(&text).map_err(|e| e.to_string())?;
    drop(text);
    // The base of the next save's revision file.
    files.previous = Some((newest.number, config));
    // Past the history now, or the newest (whole in the slot): the slot
    // that needed them was just replaced.
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
