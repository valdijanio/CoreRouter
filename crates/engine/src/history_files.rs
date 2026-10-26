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
//!   `model::json_delta` that builds its config from the config of the next
//!   newer revision (its `base`). The newest revision has no file: the
//!   slot holds it whole. File `k` is written by the save after `k` stops
//!   being the newest, once, and deleted when `k` leaves the history.
//!
//! At boot the chain is walked from the slot's revision down: each file
//! applied to the config of its base gives the next older one, sharing
//! every section the difference does not touch (`model::config_delta`),
//! so 64 revisions in memory cost about one config. A save writes
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
//! newest revision serializes only the sections the commit changed (the
//! others are shared with the new revision, G0.16) (**medido**:
//! `storage_fs/history64/*` in docs/changes/audit-history.md).
//!
//! G0.22, the config journal (a storage with `config_journal()`): the slot
//! is not rewritten by every commit. The commit's delta from the revision
//! before goes to journal `config` as one line
//! ([`RevisionFiles::note_line`], `persist::encode_journal_line`), and the
//! slot is written only at a checkpoint: past [`MAX_JOURNAL_LINES`] lines
//! or a quarter of the config in lines, when the users changed, when the
//! store is not the one logged (Safe Mode, a restore), or while the two
//! slots do not both exist. A checkpoint first journals the newest
//! revision (if it builds on the journal), writes the slot, then keeps in
//! the journal only the lines past the revision now in the previous slot:
//! at every step either slot plus the journal gives the newest revision
//! saved. The boot replays the lines that build on the slot it loaded
//! ([`replay_journal`]); a torn last line (a crash in an append) is left
//! out, and the next save checkpoints instead of appending after it.

use std::collections::{BTreeMap, BTreeSet};

use corerouter_model::persist::{self, RevisionFile};
use corerouter_model::store::Revision;
use corerouter_model::{Config, ConfigStore, Users};

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
    /// The config journal (G0.22), on a storage that keeps one.
    journal: Journal,
    /// The journal line of the last commit: (revision, base, line).
    line: Option<(u32, u32, String)>,
}

/// What the slot and the config journal hold (G0.22).
#[derive(Debug, Default)]
struct Journal {
    /// The revision (and its config) the slot plus the journal give: the
    /// next line must build on it. `None`: unknown, the next save writes
    /// the slot.
    logged: Option<(u32, Config)>,
    /// Bytes of the config in the slot (at least: the slot file holds it
    /// twice, as `running` and as the newest revision).
    slot: usize,
    /// Bytes and lines appended since.
    bytes: usize,
    lines: usize,
    /// The users written with the slot (a change rewrites it).
    users: Option<Users>,
    /// Revisions in the current and the previous slot. A commit is
    /// journaled only with both there: the previous slot plus the journal
    /// (which keeps every line past it) rebuild the newest revision when
    /// the current slot is lost.
    current: Option<u32>,
    previous: Option<u32>,
}

/// Lines after which the next save writes the slot (a checkpoint): bounds
/// the boot's replay (**estimado**: ~1 ms a line with 100 000 secrets).
pub(crate) const MAX_JOURNAL_LINES: usize = 1024;

/// Journal bytes past which the next save writes the slot: a quarter of the
/// config, at least 1 MiB. Amortized, a commit writes ~4× its own delta.
fn journal_budget(slot: usize) -> usize {
    (slot / 4).max(1 << 20)
}

impl RevisionFiles {
    /// The commit that made revision `number` already serialized it.
    pub(crate) fn note_encoded(&mut self, number: u32, text: String) {
        self.encoded = Some((number, text));
    }

    /// The commit that made revision `number` from `base` wrote its
    /// journal line (G0.22).
    pub(crate) fn note_line(&mut self, number: u32, base: u32, line: String) {
        self.line = Some((number, base, line));
    }

    /// An upper bound of the config's size in bytes once a commit adds
    /// `delta` bytes: the slot's config grows by at most what each line
    /// carries (a copy run adds nothing, a removal shrinks it). `None`
    /// when no journal is kept (the commit then measures the config).
    pub(crate) fn size_bound(&self, delta: usize) -> Option<usize> {
        self.journal.logged.as_ref()?;
        Some(self.journal.slot.saturating_add(self.journal.bytes).saturating_add(delta))
    }

    /// The journal state after a boot: the slot (`slot` bytes) and the
    /// journal (`bytes`, `lines`) give revision `logged`; `slots`: the
    /// revisions of the current and the previous slot.
    pub(crate) fn note_boot(
        &mut self,
        logged: (u32, Config),
        slot: usize,
        journal: (usize, usize),
        users: Users,
        slots: (Option<u32>, Option<u32>),
    ) {
        self.journal = Journal {
            logged: Some(logged),
            slot,
            bytes: journal.0,
            lines: journal.1,
            users: Some(users),
            current: slots.0,
            previous: slots.1,
        };
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
    // The revisions the config journal rebuilt (G0.22) already have their
    // files: kept when they rebuild the same config, so the next save does
    // not write them again.
    for pair in store.history().windows(2) {
        let [rev, newer] = pair else { continue };
        if !files.present.contains(&rev.number) {
            continue;
        }
        if let Ok((RevisionFile::Delta { base, delta, .. }, size)) = read(storage, rev.number)
            && base == newer.number
            && persist::apply_revision_delta(&newer.config, &delta).is_ok_and(|c| c == rev.config)
        {
            files.saved.insert(rev.number, Saved { size, base: Some(base) });
        }
    }
    let room = ConfigStore::DEFAULT_MAX_HISTORY.saturating_sub(store.history().len());
    let mut older: Vec<Revision> = Vec::new();
    // The newer end of the chain (the revision `older.last()`, or the
    // slot's oldest), or `None` once the chain broke.
    let mut chain: Option<u32> = Some(first);
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
        let (rev, base) = match file {
            // A full copy (G1.23) needs nothing newer.
            RevisionFile::Full(rev) => (rev, None),
            RevisionFile::Delta {
                mut rev,
                base,
                delta,
            } => {
                if chain.take() != Some(base) {
                    lost.push(n);
                    continue;
                }
                // Built from the newer revision: what the delta does not
                // touch stays shared with it.
                let newer = older.last().map_or(&oldest.config, |r| &r.config);
                match persist::apply_revision_delta(newer, &delta) {
                    Ok(cfg) => {
                        rev.config = cfg;
                        (rev, Some(base))
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
        chain = Some(n);
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
/// older ones were left out, like [`persist::encode_bounded`]. `slot`: the
/// newest revision goes to the slot even when the journal could take it
/// (G0.27, the checkpoint of a clean shutdown).
pub(crate) fn save(
    storage: &mut dyn ConfigStorage,
    files: &mut RevisionFiles,
    store: &ConfigStore,
    users: &Users,
    budget: usize,
    slot: bool,
) -> Result<usize, String> {
    let history = store.history();
    let Some(newest) = history.last() else {
        return Err("empty history".into());
    };
    // Newest first: each revision is a difference against the next newer
    // one, so the chain stops at the first that does not fit (an older
    // file without its base would be useless).
    let mut used = 0usize;
    let mut keep: BTreeSet<u32> = BTreeSet::new();
    let mut write: Vec<(u32, String, u32)> = Vec::new();
    for pair in history.windows(2).rev() {
        let [rev, base] = pair else { continue };
        let size = match files.saved.get(&rev.number) {
            Some(f) if f.base == Some(base.number) => f.size,
            _ => {
                // Only the sections the two do not share are serialized.
                let delta = persist::revision_delta(&base.config, &rev.config)
                    .map_err(|e| e.to_string())?;
                let file = persist::encode_revision_delta(rev, base.number, &delta)
                    .map_err(|e| e.to_string())?;
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
    if slot || !(storage.config_journal() && journal_append(storage, files, store, users)?) {
        checkpoint(storage, files, newest, users)?;
    }
    // Past the history now, or the newest (whole in the slot or built by
    // the journal).
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

/// Whether the slot already holds the newest revision of `store` (no
/// journal line is past it): a shutdown checkpoint has nothing to write
/// (G0.27).
pub(crate) fn slot_is_newest(storage: &dyn ConfigStorage, files: &RevisionFiles, store: &ConfigStore) -> bool {
    let newest = store.history().last().map(|r| r.number);
    !storage.config_journal() || (newest.is_some() && files.journal.current == newest)
}

/// The newest revision as one more journal line, when the storage holds
/// the one before it: `Ok(true)` when nothing else is needed (appended, or
/// already there). `Ok(false)`: the slot must be written instead (the
/// journal is long, the users changed, the store is not the one logged).
fn journal_append(
    storage: &mut dyn ConfigStorage,
    files: &mut RevisionFiles,
    store: &ConfigStore,
    users: &Users,
) -> Result<bool, String> {
    let history = store.history();
    let (Some(newest), Some((logged, cfg))) = (history.last(), files.journal.logged.as_ref()) else {
        return Ok(false);
    };
    let j = &files.journal;
    if j.users.as_ref() != Some(users) || j.current.is_none() || j.previous.is_none() {
        return Ok(false);
    }
    let holds = |n: u32| {
        history
            .iter()
            .find(|r| r.number == n)
            .is_some_and(|r| corerouter_model::sections::changed(&r.config, cfg).is_empty())
    };
    if newest.number == *logged {
        return Ok(holds(*logged));
    }
    let Some((number, base, line)) = files.line.take() else {
        return Ok(false);
    };
    let fits = j.lines < MAX_JOURNAL_LINES && j.bytes.saturating_add(line.len()) <= journal_budget(j.slot);
    if number != newest.number || base != *logged || !holds(base) || !fits {
        // The checkpoint still journals it (the previous slot needs it).
        files.line = Some((number, base, line));
        return Ok(false);
    }
    storage
        .append_journal(crate::storage::CONFIG_JOURNAL, &line)
        .map_err(|e| e.to_string())?;
    files.journal.logged = Some((newest.number, newest.config.clone()));
    files.journal.bytes = files.journal.bytes.saturating_add(line.len());
    files.journal.lines = files.journal.lines.saturating_add(1);
    Ok(true)
}

/// The whole newest revision in the slot (a checkpoint). With the config
/// journal: the newest revision's line goes to the journal first when it
/// builds on what is there, and after the slot is written the journal keeps
/// only the lines past the revision that is now in the previous slot. At
/// any step of a crash, the current slot plus the journal, or the previous
/// slot plus the journal, give the newest revision saved.
fn checkpoint(
    storage: &mut dyn ConfigStorage,
    files: &mut RevisionFiles,
    newest: &Revision,
    users: &Users,
) -> Result<(), String> {
    let line = files.line.take();
    let config = match files.encoded.take() {
        Some((n, text)) if n == newest.number => text,
        _ => persist::encode_config(&newest.config).map_err(|e| e.to_string())?,
    };
    let text = persist::encode_running(newest, &config, users).map_err(|e| e.to_string())?;
    if !storage.config_journal() {
        return storage.save(&text).map_err(|e| e.to_string());
    }
    let j = std::mem::take(&mut files.journal);
    if let (Some((number, base, line)), Some((logged, _))) = (line, j.logged.as_ref())
        && number == newest.number
        && base == *logged
    {
        storage
            .append_journal(crate::storage::CONFIG_JOURNAL, &line)
            .map_err(|e| e.to_string())?;
    }
    storage.save(&text).map_err(|e| e.to_string())?;
    // The storage moved the current slot to the previous one.
    let previous = if j.current.is_some() { j.current } else { j.previous };
    let kept = match previous {
        Some(p) => {
            let old = storage
                .load_journal(crate::storage::CONFIG_JOURNAL)
                .map_err(|e| e.to_string())?
                .unwrap_or_default();
            old.lines()
                .filter(|l| persist::decode_journal_line(l).is_ok_and(|(rev, _, _)| rev.number > p))
                .fold(String::new(), |mut out, l| {
                    out.push_str(l);
                    out.push('\n');
                    out
                })
        }
        None => String::new(),
    };
    storage
        .rewrite_journal(crate::storage::CONFIG_JOURNAL, &kept)
        .map_err(|e| e.to_string())?;
    files.journal = Journal {
        logged: Some((newest.number, newest.config.clone())),
        slot: config.len(),
        bytes: 0,
        lines: 0,
        users: Some(users.clone()),
        current: Some(newest.number),
        previous,
    };
    Ok(())
}

/// The revision a slot holds, from the head of its text (written first by
/// `persist::encode_running`).
pub(crate) fn slot_revision(text: &str) -> Option<u32> {
    let head = text.get(..text.len().min(128))?;
    let at = head.find("\"revision\":")?;
    let rest = head.get(at + "\"revision\":".len()..)?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// The revisions the config journal adds to a store restored from the slot
/// (G0.22): each line built on the newest so far. A line the slot already
/// holds is skipped; a torn or unreadable line, or one that does not chain,
/// ends the replay (reported in `errors` unless it is a torn last line,
/// what a crash during an append leaves). Returns the store and, when every
/// line was used or skipped, the journal's size in bytes and lines; `None`
/// when some were left out (the next save then writes the slot and a
/// journal without them, instead of appending after them).
pub(crate) fn replay_journal(
    storage: &mut dyn ConfigStorage,
    store: ConfigStore,
    errors: &mut Vec<String>,
) -> (ConfigStore, Option<(usize, usize)>) {
    if !storage.config_journal() {
        return (store, Some((0, 0)));
    }
    let text = match storage.load_journal(crate::storage::CONFIG_JOURNAL) {
        Ok(Some(text)) => text,
        Ok(None) => return (store, Some((0, 0))),
        Err(e) => {
            log::error!("cannot read the config journal: {e}");
            errors.push(format!("journal: {e}"));
            return (store, None);
        }
    };
    let mut clean = true;
    let mut history: Vec<Revision> = store.history().to_vec();
    let (mut bytes, mut lines) = (0usize, 0usize);
    let total = text.lines().count();
    for (i, line) in text.lines().enumerate() {
        let Some(newest) = history.last() else { break };
        let parsed = persist::decode_journal_line(line);
        let (mut rev, base, delta) = match parsed {
            Ok(p) => p,
            Err(e) => {
                if i + 1 < total || text.ends_with('\n') {
                    log::error!("config journal line {} is unreadable, the rest left out: {e}", i + 1);
                    errors.push(format!("journal line {}: {e}", i + 1));
                } else {
                    log::warn!("config journal ends in a torn line (a crash while writing it): left out");
                }
                clean = false;
                break;
            }
        };
        if rev.number <= newest.number {
            continue;
        }
        if base != newest.number {
            log::error!("config journal line {} builds on revision {base}, not {}: the rest left out", i + 1, newest.number);
            errors.push(format!("journal line {}: builds on revision {base}, not {}", i + 1, newest.number));
            clean = false;
            break;
        }
        match persist::apply_revision_delta(&newest.config, &delta) {
            Ok(cfg) => rev.config = cfg,
            Err(e) => {
                log::error!("config journal line {} does not apply, the rest left out: {e}", i + 1);
                errors.push(format!("journal line {}: {e}", i + 1));
                clean = false;
                break;
            }
        }
        bytes = bytes.saturating_add(line.len()).saturating_add(1);
        lines += 1;
        history.push(rev);
    }
    let size = clean.then_some((text.len(), total));
    if lines == 0 {
        return (store, size);
    }
    log::info!("{lines} revision(s) replayed from the config journal ({bytes} bytes)");
    let running = history.last().map(|r| r.config.clone()).unwrap_or_default();
    (ConfigStore::restore(running, history), size)
}
