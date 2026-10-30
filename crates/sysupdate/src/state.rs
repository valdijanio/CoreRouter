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

/// Traffic history (`system.graph`, G4.5): kept across a slot change as it
/// is, never part of a snapshot nor replaced by a restore (G1.6u: it is
/// not configuration, and going back would lose the trial's hours).
pub const GRAPHS: &str = "graphs";
/// Room left beyond the snapshot itself (the trial state, a revision the
/// daemon writes while the update runs).
pub const SPACE_MARGIN: u64 = 1 << 20;
/// Allocation unit counted per copied file and directory (ext4's block).
const BLOCK: u64 = 4096;
/// Entries named in a refusal.
const BIGGEST: usize = 4;

fn skip(name: &str) -> bool {
    name == DIR || name == "lost+found" || name == GRAPHS
}

/// Files the configuration storage (`storage-fs`) only ever replaces by
/// rename and never writes in place: a hard link shares them with the
/// snapshot for free (G1.6u), and the snapshot still holds the old content
/// after the next save. Everything else (`journal-*.log` is appended to)
/// is copied.
fn linkable(name: &str) -> bool {
    matches!(name, "running.json" | "running.json.prev")
        || (name.ends_with(".json") && (name.starts_with("rev-") || name.starts_with("state-")))
}

fn round_up(n: u64) -> u64 {
    n.div_ceil(BLOCK).saturating_mul(BLOCK)
}

#[derive(Debug, Default)]
struct Tally {
    files: usize,
    /// Bytes of the files copied (what the snapshot costs the disk).
    copied: u64,
    /// Bytes of the files linked (shared with the configuration).
    linked: u64,
}

/// Links `from` to `to` when `link` and the filesystem allows it, copies
/// otherwise; returns whether it linked.
fn put(from: &Path, to: &Path, link: bool) -> Result<(bool, u64), String> {
    if link && std::fs::hard_link(from, to).is_ok() {
        let n = std::fs::metadata(to).map(|m| m.len()).unwrap_or(0);
        return Ok((true, n));
    }
    let n = std::fs::copy(from, to).map_err(|e| format!("{}: {e}", from.display()))?;
    Ok((false, n))
}

fn copy_tree(from: &Path, to: &Path, top: bool, t: &mut Tally) -> Result<(), String> {
    std::fs::create_dir_all(to).map_err(|e| format!("{}: {e}", to.display()))?;
    let rd = std::fs::read_dir(from).map_err(|e| format!("{}: {e}", from.display()))?;
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(n) = name.to_str() else { continue };
        if (top && skip(n)) || n == SNAPSHOT_META {
            continue;
        }
        let Ok(ft) = e.file_type() else { continue };
        let dst = to.join(&name);
        if ft.is_dir() {
            copy_tree(&e.path(), &dst, false, t)?;
        } else if ft.is_file() {
            let (linked, n) = put(&e.path(), &dst, top && linkable(n))?;
            if linked {
                t.linked += n;
            } else {
                t.copied += n;
            }
            t.files += 1;
        }
    }
    Ok(())
}

/// What a snapshot of `config` would write: the bytes of the files it
/// copies, rounded to blocks, and one block per directory.
pub fn snapshot_need(config: &Path) -> Result<u64, String> {
    fn walk(dir: &Path, top: bool, need: &mut u64) -> Result<(), String> {
        let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        *need += BLOCK;
        for e in rd.flatten() {
            let name = e.file_name();
            let Some(n) = name.to_str() else { continue };
            if top && skip(n) {
                continue;
            }
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                walk(&e.path(), false, need)?;
            } else if ft.is_file() && !(top && linkable(n)) {
                *need += round_up(e.metadata().map(|m| m.len()).unwrap_or(0));
            }
        }
        Ok(())
    }
    let mut need = 0;
    walk(config, true, &mut need)?;
    Ok(need)
}

/// Bytes free for an unprivileged writer on the filesystem of `path`
/// (`None`: unknown, not checked).
pub fn free_bytes(path: &Path) -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let s = rustix::fs::statvfs(path).ok()?;
        Some(s.f_bavail.saturating_mul(s.f_frsize))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        None
    }
}

/// Bytes a file or a tree takes; `own`: files with another link (shared
/// with the configuration or another snapshot) count nothing, as removing
/// them frees nothing.
fn tree_bytes(path: &Path, own: bool) -> u64 {
    let Ok(m) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if m.is_file() {
        return if own && links(&m) > 1 {
            0
        } else {
            round_up(m.len())
        };
    }
    if !m.is_dir() {
        return 0;
    }
    let mut n = BLOCK;
    if let Ok(rd) = std::fs::read_dir(path) {
        for e in rd.flatten() {
            n = n.saturating_add(tree_bytes(&e.path(), own));
        }
    }
    n
}

#[cfg(unix)]
fn links(m: &std::fs::Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::nlink(m)
}

#[cfg(not(unix))]
fn links(_: &std::fs::Metadata) -> u64 {
    1
}

/// One thing that takes room in `/config`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Use {
    /// `rev-81.json`, `graphs`, `package/config-b`, `package/config-a.new`.
    pub path: String,
    pub bytes: u64,
    /// `snapshot`, `partial` (a snapshot cut short), `graphs`, `config`.
    pub kind: &'static str,
}

/// What takes room in `config`, biggest first: each top-level entry (a file
/// shared with a snapshot counts here), each snapshot and each partial one
/// (bytes of their own: what removing it frees).
pub fn usage(config: &Path) -> Vec<Use> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(config) {
        for e in rd.flatten() {
            let Some(n) = e.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if n == "lost+found" {
                continue;
            }
            if n == DIR {
                for s in std::fs::read_dir(e.path()).into_iter().flatten().flatten() {
                    let Some(sn) = s.file_name().to_str().map(str::to_owned) else {
                        continue;
                    };
                    if !s.file_type().is_ok_and(|t| t.is_dir()) {
                        continue;
                    }
                    let kind = if sn.ends_with(".new") {
                        "partial"
                    } else {
                        "snapshot"
                    };
                    out.push(Use {
                        path: format!("{DIR}/{sn}"),
                        bytes: tree_bytes(&s.path(), true),
                        kind,
                    });
                }
                continue;
            }
            let kind = if n == GRAPHS { "graphs" } else { "config" };
            out.push(Use {
                path: n,
                bytes: tree_bytes(&e.path(), false),
                kind,
            });
        }
    }
    out.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    out
}

fn mib(n: u64) -> String {
    format!("{:.1} MiB", n as f64 / f64::from(1u32 << 20))
}

/// Refuses a snapshot that does not fit (G1.6u): what it needs, what is
/// free, and the biggest entries, with the command that frees room.
pub fn check_space(config: &Path) -> Result<(), String> {
    let need = snapshot_need(config)?.saturating_add(SPACE_MARGIN);
    let Some(free) = free_bytes(config) else {
        return Ok(());
    };
    if free >= need {
        return Ok(());
    }
    let biggest: Vec<String> = usage(config)
        .into_iter()
        .filter(|u| u.bytes > 0)
        .take(BIGGEST)
        .map(|u| format!("{} {}", u.path, mib(u.bytes)))
        .collect();
    Err(format!(
        "{}: the configuration snapshot needs {} and {} is free (biggest: {}); nothing was written. \
         Free room with system.package.snapshot.remove (dry_run first) or lower the graph history",
        config.display(),
        mib(need),
        mib(free),
        biggest.join(", ")
    ))
}

pub fn snapshot_dir(config: &Path, slot: SlotId) -> (String, PathBuf) {
    let name = format!("config-{}", slot.as_str());
    let path = config.join(DIR).join(&name);
    (name, path)
}

/// Copies the configuration directory (all but [`DIR`] and [`GRAPHS`]) to
/// `package/config-<slot>/`, replacing an older snapshot only once the new
/// one is complete. Files the storage only replaces by rename are hard
/// links (G1.6u: the 64 revisions of a big config cost nothing twice).
/// Checks the room first; a copy that fails anyway (the disk filled
/// meanwhile) is removed, never left to fill `/config`.
pub fn snapshot(
    config: &Path,
    slot: SlotId,
    version: &str,
    now: u64,
) -> Result<(String, SnapshotMeta), String> {
    let (name, dst) = snapshot_dir(config, slot);
    let tmp = dst.with_extension("new");
    let _ = std::fs::remove_dir_all(&tmp);
    check_space(config)?;
    let written = write_snapshot(config, &tmp, slot, version, now);
    let meta = match written {
        Ok(m) => m,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(e);
        }
    };
    let _ = std::fs::remove_dir_all(&dst);
    std::fs::rename(&tmp, &dst).map_err(|e| format!("{}: {e}", dst.display()))?;
    Ok((name, meta))
}

fn write_snapshot(
    config: &Path,
    tmp: &Path,
    slot: SlotId,
    version: &str,
    now: u64,
) -> Result<SnapshotMeta, String> {
    let mut t = Tally::default();
    copy_tree(config, tmp, true, &mut t)?;
    let format_version = std::fs::read(config.join("running.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("format_version")?.as_u64());
    let meta = SnapshotMeta {
        format_version,
        slot,
        version: version.to_owned(),
        at_unix: now,
        files: t.files,
        bytes: t.copied + t.linked,
    };
    let text = serde_json::to_vec_pretty(&meta).map_err(|e| e.to_string())?;
    write_atomic(&tmp.join(SNAPSHOT_META), &text)?;
    Ok(meta)
}

pub fn snapshot_meta(config: &Path, name: &str) -> Option<SnapshotMeta> {
    let text = std::fs::read(config.join(DIR).join(name).join(SNAPSHOT_META)).ok()?;
    serde_json::from_slice(&text).ok()
}

/// A snapshot or partial copy [`remove`] may delete: `config-a`,
/// `config-b`, or one of them with `.new`.
fn removable(name: &str) -> bool {
    let base = name.strip_suffix(".new").unwrap_or(name);
    SlotId::ALL
        .iter()
        .any(|s| base == format!("config-{}", s.as_str()))
}

/// What [`remove`] did (or, `dry_run`, would do) to one snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Removal {
    pub name: String,
    /// Bytes it frees (its own: links shared with the configuration free
    /// nothing).
    pub bytes: u64,
    pub removed: bool,
    /// Why it stays (`None`: it goes).
    pub kept: Option<String>,
}

/// Removes snapshots of `config` (G1.6u, `system.package.snapshot.remove`):
/// `names` (empty: every partial copy, plus every snapshot when `all`),
/// never one in `protected` (the trial's backup and the configuration a
/// downgrade boots). `dry_run`: only says what would go.
pub fn remove(
    config: &Path,
    names: &[String],
    all: bool,
    protected: &[String],
    dry_run: bool,
) -> Result<Vec<Removal>, String> {
    let dir = config.join(DIR);
    let mut pick: Vec<String> = names.to_vec();
    if pick.is_empty() {
        for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let Some(n) = e.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if removable(&n) && (all || n.ends_with(".new")) {
                pick.push(n);
            }
        }
        pick.sort();
    }
    let mut out = Vec::new();
    for name in pick {
        if !removable(&name) {
            return Err(format!(
                "'{}' is not a snapshot: config-a, config-b, or a partial config-<slot>.new",
                name.chars().take(32).collect::<String>()
            ));
        }
        let path = dir.join(&name);
        let bytes = tree_bytes(&path, true);
        let kept = if protected.contains(&name) {
            Some("the trial boot in progress needs it to go back".to_owned())
        } else if !path.exists() {
            Some("no such snapshot".to_owned())
        } else {
            None
        };
        let removed = kept.is_none() && !dry_run;
        if removed {
            std::fs::remove_dir_all(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        out.push(Removal {
            name,
            bytes,
            removed,
            kept,
        });
    }
    if let Ok(d) = std::fs::File::open(&dir) {
        let _ = d.sync_all();
    }
    Ok(out)
}

/// Puts snapshot `name` back as the configuration: every entry of `config`
/// but [`DIR`] and [`GRAPHS`] is replaced by the snapshot's (linked where
/// the snapshot linked).
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
    let mut t = Tally::default();
    copy_tree(&src, config, true, &mut t)?;
    if let Ok(d) = std::fs::File::open(config) {
        let _ = d.sync_all();
    }
    Ok(t.files)
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
        // The trial slot rewrites the config (by rename, as the storage
        // does: the snapshot's link keeps the old one) and adds a file.
        std::fs::write(d.join("running.json.tmp"), r#"{"format_version":2}"#).unwrap();
        std::fs::rename(d.join("running.json.tmp"), d.join("running.json")).unwrap();
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

    fn nlink(p: &Path) -> u64 {
        std::os::unix::fs::MetadataExt::nlink(&std::fs::metadata(p).unwrap())
    }

    #[test]
    fn snapshot_links_what_is_replaced_by_rename_and_skips_graphs() {
        let d = tmp("link");
        std::fs::write(d.join("running.json"), r#"{"format_version":1}"#).unwrap();
        std::fs::write(d.join("rev-81.json"), vec![b'x'; 300_000]).unwrap();
        std::fs::write(d.join("journal-config.log"), "a\n").unwrap();
        std::fs::create_dir_all(d.join(GRAPHS)).unwrap();
        std::fs::write(d.join(GRAPHS).join("system.rrd"), vec![0u8; 200_000]).unwrap();
        let need = snapshot_need(&d).unwrap();
        assert!(
            need < 64 << 10,
            "only the journal and directories are copied: {need}"
        );
        let (name, meta) = snapshot(&d, SlotId::A, "0.1", 1).unwrap();
        let snap = d.join(DIR).join(&name);
        assert_eq!(meta.files, 3);
        assert_eq!(nlink(&snap.join("rev-81.json")), 2, "linked");
        assert_eq!(
            nlink(&snap.join("journal-config.log")),
            1,
            "appended to: copied"
        );
        assert!(!snap.join(GRAPHS).exists(), "graphs are not configuration");
        // The storage saves by rename: the snapshot keeps the old content.
        std::fs::write(d.join("running.json.tmp"), r#"{"format_version":2}"#).unwrap();
        std::fs::rename(d.join("running.json"), d.join("running.json.prev")).unwrap();
        std::fs::rename(d.join("running.json.tmp"), d.join("running.json")).unwrap();
        std::fs::remove_file(d.join("rev-81.json")).unwrap();
        let u = usage(&d);
        let own = u.iter().find(|u| u.path == "package/config-a").unwrap();
        assert!(
            own.bytes >= 300_000,
            "rev-81 is the snapshot's alone now: {u:?}"
        );
        // A restore puts the configuration back and leaves the graphs.
        std::fs::write(d.join(GRAPHS).join("system.rrd"), b"newer").unwrap();
        restore(&d, &name).unwrap();
        assert_eq!(
            std::fs::read_to_string(d.join("running.json")).unwrap(),
            r#"{"format_version":1}"#
        );
        assert!(d.join("rev-81.json").exists());
        assert!(!d.join("running.json.prev").exists());
        assert_eq!(
            std::fs::read(d.join(GRAPHS).join("system.rrd")).unwrap(),
            b"newer"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_failed_snapshot_leaves_no_partial_copy() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("partial");
        std::fs::write(d.join("running.json"), "{}").unwrap();
        std::fs::write(d.join("a-key.pem"), "k").unwrap();
        std::fs::write(d.join("z-key.pem"), "k").unwrap();
        std::fs::set_permissions(d.join("z-key.pem"), std::fs::Permissions::from_mode(0o000))
            .unwrap();
        if std::fs::read(d.join("z-key.pem")).is_ok() {
            return; // root reads anything: no failure to provoke here
        }
        // An older complete snapshot stays as it was.
        std::fs::create_dir_all(d.join(DIR).join("config-a")).unwrap();
        let e = snapshot(&d, SlotId::A, "0.1", 1).unwrap_err();
        assert!(e.contains("z-key.pem"), "{e}");
        assert!(!d.join(DIR).join("config-a.new").exists());
        assert!(d.join(DIR).join("config-a").exists());
        std::fs::set_permissions(d.join("z-key.pem"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn remove_takes_partials_by_default_and_never_a_protected_snapshot() {
        let d = tmp("remove");
        std::fs::write(d.join("running.json"), "{}").unwrap();
        snapshot(&d, SlotId::A, "0.1", 1).unwrap();
        snapshot(&d, SlotId::B, "0.1", 1).unwrap();
        std::fs::create_dir_all(d.join(DIR).join("config-b.new")).unwrap();
        std::fs::write(
            d.join(DIR).join("config-b.new/rev-1.json"),
            vec![0u8; 10_000],
        )
        .unwrap();
        let protect = vec!["config-a".to_owned()];
        // Dry run: says, deletes nothing.
        let r = remove(&d, &[], true, &protect, true).unwrap();
        let names: Vec<_> = r
            .iter()
            .map(|x| (x.name.as_str(), x.kept.is_none(), x.removed))
            .collect();
        assert_eq!(
            names,
            [
                ("config-a", false, false),
                ("config-b", true, false),
                ("config-b.new", true, false)
            ]
        );
        assert!(r.iter().find(|x| x.name == "config-b.new").unwrap().bytes >= 10_000);
        assert!(d.join(DIR).join("config-b.new").exists());
        // Default: partial copies only.
        let r = remove(&d, &[], false, &protect, false).unwrap();
        assert_eq!(r.len(), 1);
        assert!(r[0].removed && !d.join(DIR).join("config-b.new").exists());
        // By name; the protected one stays.
        let r = remove(
            &d,
            &["config-a".into(), "config-b".into()],
            false,
            &protect,
            false,
        )
        .unwrap();
        assert_eq!(
            r.iter().map(|x| x.removed).collect::<Vec<_>>(),
            [false, true]
        );
        assert!(d.join(DIR).join("config-a").exists() && !d.join(DIR).join("config-b").exists());
        assert!(
            d.join("running.json").exists(),
            "the configuration is never touched"
        );
        assert!(remove(&d, &["../running.json".into()], false, &[], false).is_err());
        assert!(remove(&d, &["state.json".into()], false, &[], false).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
