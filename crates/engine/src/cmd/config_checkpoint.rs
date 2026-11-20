//! G0.33 — named checkpoints: a point to go back to before long work.
//!
//! The revision history keeps the newest 64 revisions; a lab that makes
//! hundreds of commits pushes the revision from before it out, and
//! `config.rollback` to it fails. A checkpoint is a whole copy of the
//! running config under a name, kept apart from the history (its own file,
//! `ConfigStorage::save_checkpoint`), so it stays until it is removed: no
//! commit, no history limit and no history disk share takes it. Arista
//! EOS `configure checkpoint save/restore` and the Junos rescue config work
//! the same way: a full copy, not a difference, so it needs no other file.
//!
//! Restoring loads the copy into the candidate, like `config.rollback`: in
//! immediate mode it is committed at once (with the lockout check), in
//! transactional mode it waits for `config.commit`. The checkpoint stays
//! (none of the others delete it on use) unless `remove: true`.
//!
//! Costs: a commit pays nothing for the checkpoints (they are not in the
//! history). `add` serializes the running config once and writes it;
//! `restore` and `diff` read and parse it. Nothing is held in memory but
//! the list (name, revision, size): the first `config.checkpoint.*` of the
//! process reads each file's head (the config is skipped, not built), and
//! each restore or diff parses the whole file.
//! Accounts are not in the config, so a restore never brings back an old
//! password (as with `config.rollback`).

use std::collections::BTreeMap;

use corerouter_model::persist::{self, CheckpointInfo};
use corerouter_model::Config;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_text, req_str};
use super::{CommandSpec, always};
use crate::{CommitMode, EngineError, Result, Session};

/// Checkpoints kept at most (Arista EOS keeps 20 by default, SR Linux 10):
/// each is a whole config on a `/config` that may be 56 MB.
pub const MAX_CHECKPOINTS: usize = 16;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "config.checkpoint.add",
        "Save Checkpoint",
        ["System", "History"],
        None,
        "{name: string (letters, digits, - and _, up to 32), comment?: string} → {name, revision, bytes, pending}",
        always,
        add
    ),
    cmd!(query "config.checkpoint.list", "Checkpoints", ["System", "History"], None,
        "{} → [{name, comment, revision, timestamp, bytes, error?}]",
        always, list),
    cmd!(query "config.checkpoint.diff", "Changes Since Checkpoint", ["System", "History"], None,
        "{name: string} → [{op: add|remove|change, path, value | from, to}]",
        always, diff),
    cmd!(
        "config.checkpoint.restore",
        "Restore Checkpoint",
        ["System", "History"],
        None,
        "{name: string, remove?: bool (delete the checkpoint once restored; immediate mode only), force?: bool (restore even if the firewall would cut your management connection)} → {loaded, revision, pending, removed}",
        always,
        restore
    ),
    cmd!(
        "config.checkpoint.remove",
        "Remove Checkpoint",
        ["System", "History"],
        None,
        "{name: string} → {removed}",
        always,
        remove
    ),
];

/// What the storage holds (session extension), read on first use.
#[derive(Debug, Default)]
struct Checkpoints {
    loaded: bool,
    by_name: BTreeMap<String, Entry>,
}

#[derive(Debug, Clone)]
struct Entry {
    info: CheckpointInfo,
    /// Size of the file.
    bytes: usize,
    /// Why the file cannot be used (unreadable, not a checkpoint).
    error: Option<String>,
}

fn storage_error(e: impl std::fmt::Display) -> EngineError {
    EngineError::NotSaved(format!("checkpoints: {e}"))
}

/// The list, read from the storage the first time.
fn entries(s: &mut Session) -> Result<&mut BTreeMap<String, Entry>> {
    let loaded = s.ext::<Checkpoints>().is_some_and(|c| c.loaded);
    if !loaded {
        let mut by_name = BTreeMap::new();
        let names = s.storage_mut().list_checkpoints().map_err(storage_error)?;
        for name in names.into_iter().take(MAX_CHECKPOINTS.saturating_mul(4)) {
            let entry = match head(s, &name) {
                Ok((info, bytes)) => Entry { info, bytes, error: None },
                Err(e) => {
                    log::warn!("checkpoint {name}: {e}");
                    Entry {
                        info: CheckpointInfo {
                            name: name.clone(),
                            comment: String::new(),
                            revision: 0,
                            timestamp: None,
                        },
                        bytes: 0,
                        error: Some(e),
                    }
                }
            };
            by_name.insert(name, entry);
        }
        if let Some(c) = s.ext_mut::<Checkpoints>() {
            *c = Checkpoints { loaded: true, by_name };
        }
    }
    s.ext_mut::<Checkpoints>()
        .map(|c| &mut c.by_name)
        .ok_or_else(|| EngineError::Internal("config.checkpoint".into()))
}

/// What checkpoint `name` says of itself, and its size, without building
/// its config (`persist::decode_checkpoint_info`).
fn head(s: &mut Session, name: &str) -> std::result::Result<(CheckpointInfo, usize), String> {
    let text = s
        .storage_mut()
        .load_checkpoint(name)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "its file is gone".to_owned())?;
    let info = persist::decode_checkpoint_info(&text, name).map_err(|e| e.to_string())?;
    Ok((info, text.len()))
}

/// Checkpoint `name` from the storage: its info, config and size.
fn read(s: &mut Session, name: &str) -> std::result::Result<(CheckpointInfo, Config, usize), String> {
    let text = s
        .storage_mut()
        .load_checkpoint(name)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "its file is gone".to_owned())?;
    let (info, cfg) = persist::decode_checkpoint(&text, name).map_err(|e| e.to_string())?;
    Ok((info, cfg, text.len()))
}

fn name_param(p: &Value) -> Result<&str> {
    let name = req_str(p, "name")?;
    if persist::checkpoint_name_ok(name) {
        Ok(name)
    } else {
        Err(EngineError::bad(
            "name",
            format!(
                "'{}' is not a checkpoint name: letters, digits, - and _, starting with a \
                 letter or digit, up to {} characters",
                name.chars().take(40).collect::<String>(),
                persist::MAX_CHECKPOINT_NAME
            ),
        ))
    }
}

/// The checkpoint's config, refused when its file is not usable.
fn config_of(s: &mut Session, name: &str) -> Result<(CheckpointInfo, Config)> {
    if !entries(s)?.contains_key(name) {
        let known: Vec<String> = entries(s)?.keys().cloned().collect();
        return Err(EngineError::bad(
            "name",
            if known.is_empty() {
                format!("no checkpoint '{name}' (there are none; config.checkpoint.add saves one)")
            } else {
                format!("no checkpoint '{name}' (there are: {})", known.join(", "))
            },
        ));
    }
    match read(s, name) {
        Ok((info, cfg, _)) => Ok((info, cfg)),
        Err(e) => {
            if let Some(entry) = entries(s)?.get_mut(name) {
                entry.error = Some(e.clone());
            }
            Err(EngineError::bad(
                "name",
                format!("checkpoint '{name}' cannot be used: {e} (config.checkpoint.remove deletes it)"),
            ))
        }
    }
}

/// Disk the checkpoints may take: a share of `/config` like the history's
/// (G1.6w), or the history's fixed ceiling when the disk was not measured.
fn budget(s: &Session) -> usize {
    let capacity = s
        .ext::<crate::config_disk::ConfigDisk>()
        .and_then(|d| d.capacity);
    capacity.map_or(persist::SAVE_BUDGET_BYTES, |c| {
        usize::try_from(crate::config_disk::share(c, crate::config_disk::CHECKPOINT_PERCENT))
            .map_or(persist::SAVE_BUDGET_BYTES, |b| b.min(persist::SAVE_BUDGET_BYTES))
    })
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = name_param(p)?;
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    if s.in_safe_mode() {
        return Err(EngineError::bad(
            "name",
            "not in Safe Mode: its changes are not kept yet (leave it with \
             config.safe-mode.exit first, then save the checkpoint)",
        ));
    }
    if let Some(why) = s.storage_mut().unavailable() {
        return Err(EngineError::NotSaved(why));
    }
    let list = entries(s)?;
    if list.contains_key(name) {
        return Err(EngineError::bad(
            "name",
            format!(
                "checkpoint '{name}' already exists: restore it (config.checkpoint.restore) \
                 or remove it first (config.checkpoint.remove)"
            ),
        ));
    }
    if list.len() >= MAX_CHECKPOINTS {
        return Err(EngineError::bad(
            "name",
            format!(
                "there are already {MAX_CHECKPOINTS} checkpoints, the most kept: remove one \
                 first (config.checkpoint.list)"
            ),
        ));
    }
    let used: usize = list.values().map(|e| e.bytes).sum();
    let info = CheckpointInfo {
        name: name.to_owned(),
        comment,
        revision: s.store().current_revision(),
        timestamp: s.now(),
    };
    let unencodable = |e: persist::PersistError| EngineError::Internal(format!("checkpoint: {e}"));
    let config = persist::encode_config(s.store().running()).map_err(unencodable)?;
    let text = persist::encode_checkpoint(&info, &config).map_err(unencodable)?;
    let cap = budget(s);
    if used.saturating_add(text.len()) > cap {
        return Err(EngineError::NotSaved(format!(
            "checkpoint '{name}' needs {}, and the checkpoints already take {} of the {} \
             they may use on /config: remove one first (config.checkpoint.list)",
            crate::config_disk::mib(text.len() as u64),
            crate::config_disk::mib(used as u64),
            crate::config_disk::mib(cap as u64)
        )));
    }
    s.storage_mut()
        .save_checkpoint(name, &text)
        .map_err(storage_error)?;
    let bytes = text.len();
    let revision = info.revision;
    entries(s)?.insert(
        name.to_owned(),
        Entry {
            info,
            bytes,
            error: None,
        },
    );
    log::info!("checkpoint {name} saved at revision {revision} ({bytes} bytes)");
    Ok(json!({
        "name": name,
        "revision": revision,
        "bytes": bytes,
        // Uncommitted changes are not in it: the checkpoint is the running config.
        "pending": s.store().is_dirty(),
    }))
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    let mut rows: Vec<Entry> = entries(s)?.values().cloned().collect();
    rows.sort_by(|a, b| (a.info.revision, &a.info.name).cmp(&(b.info.revision, &b.info.name)));
    Ok(Value::Array(
        rows.into_iter()
            .map(|e| {
                let mut row = json!({
                    "name": e.info.name,
                    "comment": e.info.comment,
                    "revision": e.info.revision,
                    "timestamp": e.info.timestamp,
                    "bytes": e.bytes,
                });
                if let (Some(error), Some(o)) = (e.error, row.as_object_mut()) {
                    o.insert("error".into(), json!(error));
                }
                row
            })
            .collect(),
    ))
}

/// What changed since the checkpoint: checkpoint → running.
fn diff(s: &mut Session, p: &Value) -> Result<Value> {
    let name = name_param(p)?;
    let (_, cfg) = config_of(s, name)?;
    let lines = corerouter_model::store::diff_configs(&cfg, s.store().running());
    super::config::masked(s, &lines)
}

fn restore(s: &mut Session, p: &Value) -> Result<Value> {
    crate::lockout::take_force(s, p)?;
    let name = name_param(p)?;
    let remove_after = opt_bool(p, "remove")?.unwrap_or(false);
    let transactional = s.mode() == CommitMode::Transactional;
    if remove_after && transactional {
        return Err(EngineError::bad(
            "remove",
            "only in immediate mode: in transactional mode the restore waits for \
             config.commit; remove the checkpoint after it (config.checkpoint.remove)",
        ));
    }
    let (info, cfg) = config_of(s, name)?;
    s.store_mut().set_candidate(cfg);
    let mut removed = false;
    if !transactional {
        // Committed here, not by `execute`, so the checkpoint goes only
        // once the restore is in (a refused commit keeps it).
        if s.store().is_dirty() {
            s.commit_candidate(&format!("config.checkpoint.restore {name}"))?;
        }
        if remove_after {
            // The commit is in: a failure here must not undo it.
            match s.storage_mut().remove_checkpoint(name) {
                Ok(()) => {
                    entries(s)?.remove(name);
                    removed = true;
                }
                Err(e) => log::warn!("checkpoint {name} restored but not removed: {e}"),
            }
        }
    }
    Ok(json!({
        "loaded": name,
        "revision": info.revision,
        "pending": transactional,
        "removed": removed,
    }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let name = name_param(p)?;
    if !entries(s)?.contains_key(name) {
        return Err(EngineError::bad("name", format!("no checkpoint '{name}'")));
    }
    s.storage_mut()
        .remove_checkpoint(name)
        .map_err(storage_error)?;
    entries(s)?.remove(name);
    Ok(json!({ "removed": name }))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::storage::MemoryStorage;
    use corerouter_hal::VirtualHal;

    use crate::Session;

    fn boot(storage: &MemoryStorage) -> Session {
        Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()))
    }

    fn identity(s: &mut Session) -> String {
        s.execute("system.identity.get", &json!({})).unwrap()["name"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn rename(s: &mut Session, name: &str) {
        s.execute("system.identity.set", &json!({ "name": name })).unwrap();
    }

    /// The case of the gap: more commits than the history keeps, then
    /// back to before them, across a restart.
    #[test]
    fn a_checkpoint_outlives_the_history_and_a_restart() {
        let storage = MemoryStorage::default();
        let mut s = boot(&storage);
        rename(&mut s, "before");
        let before = s.store().current_revision();
        let r = s
            .execute("config.checkpoint.add", &json!({"name": "lab", "comment": "antes"}))
            .unwrap();
        assert_eq!(r["revision"], before);
        assert_eq!(r["pending"], false);
        let n = corerouter_model::ConfigStore::DEFAULT_MAX_HISTORY + 10;
        for i in 0..n {
            rename(&mut s, &format!("lab-{i}"));
        }
        let err = s
            .execute("config.rollback", &json!({"revision": before}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not found") && err.contains("config.checkpoint"), "{err}");
        // A restart in the middle: the checkpoint is on the storage.
        drop(s);
        let mut s = boot(&storage);
        let list = s.execute("config.checkpoint.list", &json!({})).unwrap();
        assert_eq!(list[0]["name"], "lab");
        assert_eq!(list[0]["comment"], "antes");
        assert_eq!(list[0]["revision"], before);
        let diff = s.execute("config.checkpoint.diff", &json!({"name": "lab"})).unwrap();
        assert!(diff.to_string().contains("lab-"), "{diff}");
        let r = s.execute("config.checkpoint.restore", &json!({"name": "lab"})).unwrap();
        assert_eq!(r["pending"], false);
        assert_eq!(r["removed"], false);
        assert_eq!(identity(&mut s), "before");
        let last = s.store().history().last().unwrap();
        assert_eq!(last.comment, "config.checkpoint.restore lab");
        let diff = s.execute("config.checkpoint.diff", &json!({"name": "lab"})).unwrap();
        assert_eq!(diff, json!([]));
        // It stays until removed.
        assert_eq!(s.execute("config.checkpoint.list", &json!({})).unwrap().as_array().unwrap().len(), 1);
        s.execute("config.checkpoint.remove", &json!({"name": "lab"})).unwrap();
        assert!(storage.checkpoint("lab").is_none());
        assert_eq!(s.execute("config.checkpoint.list", &json!({})).unwrap(), json!([]));
    }

    #[test]
    fn restore_and_remove_in_one_step() {
        let storage = MemoryStorage::default();
        let mut s = boot(&storage);
        s.execute("config.checkpoint.add", &json!({"name": "x"})).unwrap();
        rename(&mut s, "after");
        let r = s
            .execute("config.checkpoint.restore", &json!({"name": "x", "remove": true}))
            .unwrap();
        assert_eq!(r["removed"], true);
        assert_eq!(identity(&mut s), "CoreRouter");
        assert!(storage.checkpoint("x").is_none());
        // Nothing to change: still fine, and nothing is committed.
        s.execute("config.checkpoint.add", &json!({"name": "y"})).unwrap();
        let rev = s.store().current_revision();
        s.execute("config.checkpoint.restore", &json!({"name": "y"})).unwrap();
        assert_eq!(s.store().current_revision(), rev);
    }

    #[test]
    fn transactional_restore_waits_for_the_commit() {
        let storage = MemoryStorage::default();
        let mut s = boot(&storage);
        s.execute("config.checkpoint.add", &json!({"name": "x"})).unwrap();
        rename(&mut s, "after");
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        let err = s
            .execute("config.checkpoint.restore", &json!({"name": "x", "remove": true}))
            .unwrap_err();
        assert!(err.to_string().contains("immediate mode"), "{err}");
        let r = s.execute("config.checkpoint.restore", &json!({"name": "x"})).unwrap();
        assert_eq!(r["pending"], true);
        assert_eq!(s.store().running().system.identity, "after");
        assert_eq!(s.store().candidate().system.identity, "CoreRouter");
        // Discarded: running untouched, the checkpoint still there.
        s.execute("config.discard", &json!({})).unwrap();
        s.execute("config.commit", &json!({})).unwrap_err();
        s.execute("config.checkpoint.restore", &json!({"name": "x"})).unwrap();
        s.execute("config.commit", &json!({})).unwrap();
        assert_eq!(s.store().running().system.identity, "CoreRouter");
        assert!(storage.checkpoint("x").is_some());
    }

    #[test]
    fn validation_errors() {
        let storage = MemoryStorage::default();
        let mut s = boot(&storage);
        for bad in ["", "../etc", "a b", "-x", &"x".repeat(33)] {
            let e = s.execute("config.checkpoint.add", &json!({"name": bad})).unwrap_err();
            assert!(e.to_string().contains("parameter 'name'"), "{bad}: {e}");
        }
        s.execute("config.checkpoint.add", &json!({"name": "a"})).unwrap();
        let e = s.execute("config.checkpoint.add", &json!({"name": "a"})).unwrap_err();
        assert!(e.to_string().contains("already exists"), "{e}");
        for id in ["config.checkpoint.restore", "config.checkpoint.diff", "config.checkpoint.remove"] {
            let e = s.execute(id, &json!({"name": "none"})).unwrap_err();
            assert!(e.to_string().contains("no checkpoint 'none'"), "{id}: {e}");
        }
        for i in 1..super::MAX_CHECKPOINTS {
            s.execute("config.checkpoint.add", &json!({"name": format!("c{i}")})).unwrap();
        }
        let e = s.execute("config.checkpoint.add", &json!({"name": "more"})).unwrap_err();
        assert!(e.to_string().contains("remove one"), "{e}");
        // Safe Mode: the running config is not kept yet.
        s.execute("config.checkpoint.remove", &json!({"name": "a"})).unwrap();
        s.execute("config.safe-mode.enter", &json!({})).unwrap();
        let e = s.execute("config.checkpoint.add", &json!({"name": "sm"})).unwrap_err();
        assert!(e.to_string().contains("Safe Mode"), "{e}");
    }

    /// A restore is a commit like any other: Safe Mode undoes it.
    #[test]
    fn safe_mode_undoes_a_restore() {
        let storage = MemoryStorage::default();
        let mut s = boot(&storage);
        s.execute("config.checkpoint.add", &json!({"name": "x"})).unwrap();
        rename(&mut s, "after");
        s.execute("config.safe-mode.enter", &json!({})).unwrap();
        s.execute("config.checkpoint.restore", &json!({"name": "x"})).unwrap();
        assert_eq!(identity(&mut s), "CoreRouter");
        s.execute("config.safe-mode.cancel", &json!({})).unwrap();
        assert_eq!(identity(&mut s), "after");
    }

    /// A restore whose commit is refused changes nothing, and `remove`
    /// keeps the checkpoint (rollback of the command).
    #[test]
    fn a_refused_restore_changes_nothing() {
        let storage = MemoryStorage::default();
        let mut s = boot(&storage);
        s.execute("config.checkpoint.add", &json!({"name": "x"})).unwrap();
        rename(&mut s, "after");
        let rev = s.store().current_revision();
        storage.set_unavailable(Some("the disk is gone".into()));
        let e = s
            .execute("config.checkpoint.restore", &json!({"name": "x", "remove": true}))
            .unwrap_err();
        assert!(e.to_string().contains("disk is gone"), "{e}");
        assert_eq!(s.store().current_revision(), rev);
        assert!(!s.store().is_dirty(), "the candidate went back");
        assert_eq!(identity(&mut s), "after");
        storage.set_unavailable(None);
        assert!(storage.checkpoint("x").is_some());
    }

    /// Writing a file cannot be undone by a later failed step.
    #[test]
    fn not_inside_an_atomic_batch() {
        let mut s = boot(&MemoryStorage::default());
        let steps = json!([{"command": "config.checkpoint.add", "params": {"name": "x"}}]);
        let e = s.batch(&steps, true).unwrap_err();
        assert!(e.to_string().contains("atomic batch"), "{e}");
        s.batch(&steps, false).unwrap();
    }

    /// A damaged file is listed with its error and refused, never loaded.
    #[test]
    fn a_damaged_checkpoint_is_refused() {
        let storage = MemoryStorage::default();
        let mut s = boot(&storage);
        s.execute("config.checkpoint.add", &json!({"name": "x"})).unwrap();
        let text = storage.checkpoint("x").unwrap();
        storage.put_checkpoint("x", Some(text.get(..text.len() / 2).unwrap().to_owned()));
        storage.put_checkpoint("y", Some(text.replacen("\"name\":\"x\"", "\"name\":\"z\"", 1)));
        drop(s);
        let mut s = boot(&storage);
        let list = s.execute("config.checkpoint.list", &json!({})).unwrap();
        assert!(list[0]["error"].is_string() && list[1]["error"].is_string(), "{list}");
        rename(&mut s, "after");
        let e = s.execute("config.checkpoint.restore", &json!({"name": "x"})).unwrap_err();
        assert!(e.to_string().contains("cannot be used"), "{e}");
        assert_eq!(identity(&mut s), "after");
        s.execute("config.checkpoint.remove", &json!({"name": "x"})).unwrap();
        assert!(storage.checkpoint("x").is_none());
    }

    /// The share of `/config`: a checkpoint that does not fit is refused.
    #[test]
    fn checkpoints_keep_to_their_disk_share() {
        let storage = MemoryStorage::default();
        let mut s = boot(&storage);
        s.execute("config.checkpoint.add", &json!({"name": "a"})).unwrap();
        let size = storage.checkpoint("a").unwrap().len() as u64;
        // A disk whose share holds one and a half of them.
        let capacity = size * 3 / 2 * 100 / crate::config_disk::CHECKPOINT_PERCENT;
        s.set_config_capacity(Some(capacity));
        let e = s.execute("config.checkpoint.add", &json!({"name": "b"})).unwrap_err();
        assert!(e.to_string().contains("remove one first"), "{e}");
        assert!(storage.checkpoint("b").is_none());
    }

    /// A storage without checkpoints (the default of the trait) says so.
    #[test]
    fn a_storage_without_checkpoints_refuses_them() {
        struct Plain(MemoryStorage);
        impl crate::ConfigStorage for Plain {
            fn describe(&self) -> String {
                "plain".into()
            }
            fn load(&mut self, slot: crate::Slot) -> Result<Option<String>, crate::StorageError> {
                self.0.load(slot)
            }
            fn save(&mut self, data: &str) -> Result<(), crate::StorageError> {
                self.0.save(data)
            }
            fn quarantine(&mut self, slot: crate::Slot) -> Result<(), crate::StorageError> {
                self.0.quarantine(slot)
            }
        }
        let mut s = Session::with_storage(
            Box::new(VirtualHal::default()),
            Box::new(Plain(MemoryStorage::default())),
        );
        let e = s.execute("config.checkpoint.add", &json!({"name": "a"})).unwrap_err();
        assert!(e.to_string().contains("not supported"), "{e}");
        assert_eq!(s.execute("config.checkpoint.list", &json!({})).unwrap(), json!([]));
    }
}
