//! What survives the reboot between "install" and "confirmed": the trial
//! in progress and the last outcome, in `/config/package/state.json`, and
//! the configuration snapshots taken before a slot change
//! (`/config/package/config-<slot>/`).
//!
//! Two writers, never at the same time: `corerouter-init` at boot (before
//! the daemon starts: marks the trial booted, restores the configuration
//! after a failed trial) and the daemon afterwards (arms a trial, confirms).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::SlotId;

pub const STATE_FILE: &str = "state.json";
/// The folder under `/config` that holds this module's files; never part of
/// a configuration snapshot.
pub const DIR: &str = "package";
const SNAPSHOT_META: &str = "snapshot.json";
const MAX_STATE: u64 = 64 << 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    Update,
    Downgrade,
    BootParams,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confirm {
    /// The daemon confirms once it is healthy and management is reachable.
    Auto,
    /// An operator runs `system.package.confirm` (like Junos `commit confirmed`).
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trial {
    pub slot: SlotId,
    pub from: SlotId,
    pub version: String,
    pub reason: Reason,
    pub confirm: Confirm,
    /// Seconds from the start of the trial boot to confirm, or the previous
    /// slot boots again.
    pub timeout_s: u64,
    pub started_unix: u64,
    /// Set by init when the trial slot came up (a second boot of it
    /// without confirmation is not a new trial).
    #[serde(default)]
    pub booted: bool,
    /// Interfaces that were running with an address when the trial was
    /// armed: auto-confirm waits for each to run again ("management
    /// reachable").
    #[serde(default)]
    pub mgmt: Vec<String>,
    /// Snapshot put in place before the trial slot's daemon starts (a
    /// downgrade boots the configuration that slot last ran).
    #[serde(default)]
    pub config_swap: Option<String>,
    /// Snapshot of the configuration as it was on `from`, restored if the
    /// trial fails.
    #[serde(default)]
    pub config_backup: Option<String>,
    /// How the install went (bytes, write and verify times), kept for the
    /// operator to read after the reboot.
    #[serde(default)]
    pub stats: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    /// `confirmed`, `rolled-back`, `refused`.
    pub result: String,
    pub slot: SlotId,
    pub version: String,
    pub at_unix: u64,
    pub detail: String,
    /// The install's numbers ([`Trial::stats`]).
    #[serde(default)]
    pub stats: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub trial: Option<Trial>,
    #[serde(default)]
    pub last: Option<Outcome>,
    /// Slots whose last trial failed, and why (cleared by a new install).
    #[serde(default)]
    pub failed: BTreeMap<SlotId, String>,
}

impl State {
    /// Missing or unreadable state is the empty state (and said so).
    pub fn load(dir: &Path) -> (State, Option<String>) {
        use std::io::Read;
        let path = dir.join(STATE_FILE);
        let mut text = String::new();
        match std::fs::File::open(&path) {
            Ok(f) => {
                if let Err(e) = f.take(MAX_STATE).read_to_string(&mut text) {
                    return (State::default(), Some(format!("{}: {e}", path.display())));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (State::default(), None),
            Err(e) => return (State::default(), Some(format!("{}: {e}", path.display()))),
        }
        match serde_json::from_str(&text) {
            Ok(s) => (s, None),
            Err(e) => (State::default(), Some(format!("{}: {e}", path.display()))),
        }
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        let text = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        write_atomic(&dir.join(STATE_FILE), &text)
    }
}

/// temp file, fsync, rename, fsync the directory.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let dir = path.parent().ok_or("no parent directory")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = path.with_extension("tmp");
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    let mut f = std::fs::File::create(&tmp).map_err(err)?;
    f.write_all(data).map_err(err)?;
    f.sync_all().map_err(err)?;
    std::fs::rename(&tmp, path).map_err(err)?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// What a snapshot says about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMeta {
    /// `format_version` of the `running.json` saved (the schema).
    pub format_version: Option<u64>,
    pub slot: SlotId,
    pub version: String,
    pub at_unix: u64,
    pub files: usize,
    pub bytes: u64,
}

fn skip(name: &str) -> bool {
    name == DIR || name == "lost+found"
}

fn copy_tree(from: &Path, to: &Path, files: &mut usize, bytes: &mut u64) -> Result<(), String> {
    std::fs::create_dir_all(to).map_err(|e| format!("{}: {e}", to.display()))?;
    let rd = std::fs::read_dir(from).map_err(|e| format!("{}: {e}", from.display()))?;
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(n) = name.to_str() else { continue };
        if skip(n) || n == SNAPSHOT_META {
            continue;
        }
        let Ok(ft) = e.file_type() else { continue };
        let dst = to.join(&name);
        if ft.is_dir() {
            copy_tree(&e.path(), &dst, files, bytes)?;
        } else if ft.is_file() {
            *bytes += std::fs::copy(e.path(), &dst)
                .map_err(|err| format!("{}: {err}", e.path().display()))?;
            *files += 1;
        }
    }
    Ok(())
}

pub fn snapshot_dir(config: &Path, slot: SlotId) -> (String, PathBuf) {
    let name = format!("config-{}", slot.as_str());
    let path = config.join(DIR).join(&name);
    (name, path)
}

/// Copies the configuration directory (all but [`DIR`]) to
/// `package/config-<slot>/`, replacing an older snapshot only once the new
/// one is complete.
pub fn snapshot(
    config: &Path,
    slot: SlotId,
    version: &str,
    now: u64,
) -> Result<(String, SnapshotMeta), String> {
    let (name, dst) = snapshot_dir(config, slot);
    let tmp = dst.with_extension("new");
    let _ = std::fs::remove_dir_all(&tmp);
    let (mut files, mut bytes) = (0, 0);
    copy_tree(config, &tmp, &mut files, &mut bytes)?;
    let format_version = std::fs::read(config.join("running.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("format_version")?.as_u64());
    let meta = SnapshotMeta {
        format_version,
        slot,
        version: version.to_owned(),
        at_unix: now,
        files,
        bytes,
    };
    let text = serde_json::to_vec_pretty(&meta).map_err(|e| e.to_string())?;
    write_atomic(&tmp.join(SNAPSHOT_META), &text)?;
    let _ = std::fs::remove_dir_all(&dst);
    std::fs::rename(&tmp, &dst).map_err(|e| format!("{}: {e}", dst.display()))?;
    Ok((name, meta))
}

pub fn snapshot_meta(config: &Path, name: &str) -> Option<SnapshotMeta> {
    let text = std::fs::read(config.join(DIR).join(name).join(SNAPSHOT_META)).ok()?;
    serde_json::from_slice(&text).ok()
}

/// Puts snapshot `name` back as the configuration: every entry of `config`
/// but [`DIR`] is replaced by the snapshot's.
pub fn restore(config: &Path, name: &str) -> Result<usize, String> {
    let src = config.join(DIR).join(name);
    if snapshot_meta(config, name).is_none() {
        return Err(format!("{}: not a complete snapshot", src.display()));
    }
    let rd = std::fs::read_dir(config).map_err(|e| format!("{}: {e}", config.display()))?;
    for e in rd.flatten() {
        let n = e.file_name();
        if n.to_str().is_some_and(skip) {
            continue;
        }
        let p = e.path();
        let r = if e.file_type().is_ok_and(|t| t.is_dir()) {
            std::fs::remove_dir_all(&p)
        } else {
            std::fs::remove_file(&p)
        };
        r.map_err(|err| format!("{}: {err}", p.display()))?;
    }
    let (mut files, mut bytes) = (0, 0);
    copy_tree(&src, config, &mut files, &mut bytes)?;
    if let Ok(d) = std::fs::File::open(config) {
        let _ = d.sync_all();
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sysupdate-state-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn state_round_trip() {
        let d = tmp("rt");
        assert_eq!(State::load(&d), (State::default(), None));
        let mut s = State {
            trial: None,
            last: None,
            failed: BTreeMap::new(),
        };
        s.trial = Some(Trial {
            slot: SlotId::B,
            from: SlotId::A,
            version: "1".into(),
            reason: Reason::Update,
            confirm: Confirm::Auto,
            timeout_s: 300,
            started_unix: 5,
            booted: false,
            mgmt: vec!["ether1".into()],
            config_swap: None,
            config_backup: Some("config-a".into()),
            stats: None,
        });
        s.failed.insert(SlotId::A, "x".into());
        s.save(&d).unwrap();
        assert_eq!(State::load(&d).0, s);
        std::fs::write(d.join(STATE_FILE), "{nope").unwrap();
        assert!(State::load(&d).1.is_some());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn snapshot_and_restore() {
        let d = tmp("snap");
        std::fs::write(d.join("running.json"), r#"{"format_version":1}"#).unwrap();
        std::fs::create_dir_all(d.join("certs")).unwrap();
        std::fs::write(d.join("certs/key.pem"), "k").unwrap();
        let (name, meta) = snapshot(&d, SlotId::A, "0.1", 9).unwrap();
        assert_eq!(name, "config-a");
        assert_eq!((meta.files, meta.format_version), (2, Some(1)));
        // The trial slot rewrites the config and adds a file.
        std::fs::write(d.join("running.json"), r#"{"format_version":2}"#).unwrap();
        std::fs::write(d.join("rev-9.json"), "{}").unwrap();
        assert_eq!(restore(&d, &name).unwrap(), 2);
        assert_eq!(
            std::fs::read_to_string(d.join("running.json")).unwrap(),
            r#"{"format_version":1}"#
        );
        assert!(!d.join("rev-9.json").exists());
        assert!(d.join("certs/key.pem").exists());
        assert!(d.join(DIR).join(&name).exists());
        assert!(restore(&d, "config-b").is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
