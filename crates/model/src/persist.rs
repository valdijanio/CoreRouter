//! On-disk form of the [`ConfigStore`]: running config + revision history as
//! versioned JSON. Pure functions only (no I/O), so it stays wasm-safe; the
//! engine's `ConfigStorage` decides where the bytes live.
//!
//! The file is hostile input: [`decode`] bounds its size, checks
//! `format_version` before anything else and verifies the store invariants
//! (revision numbers strictly increasing, running = newest revision), so a
//! truncated or hand-edited file is rejected instead of half-loaded.

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::store::{ConfigStore, Revision};
use crate::users::Users;

/// Version written by this build. Bump it when the layout changes and teach
/// [`decode`] to migrate the older ones.
pub const FORMAT_VERSION: u32 = 1;

/// Larger files are refused before parsing. Well above what a save writes
/// ([`SAVE_BUDGET_BYTES`]), so a file written by an older build (pretty
/// JSON, history never trimmed) still loads.
pub const MAX_FILE_BYTES: usize = 256 * 1024 * 1024;

/// What a save may write: [`encode_bounded`] leaves the oldest revisions
/// out until the file fits (audit: 64 full copies of a big config made a
/// file the next boot refused, and the router came up blank).
pub const SAVE_BUDGET_BYTES: usize = 32 * 1024 * 1024;

/// Largest running config a commit may produce: it is written twice (as
/// `running` and as the newest revision) and must leave room for the
/// accounts. About 50 000 firewall rules (**estimado**).
pub const MAX_CONFIG_BYTES: usize = SAVE_BUDGET_BYTES / 2 - 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PersistError {
    #[error("file is {0} bytes (limit {MAX_FILE_BYTES})")]
    TooLarge(usize),
    #[error("not a CoreRouter config file: {0}")]
    Malformed(String),
    #[error("unknown format_version {0} (this build reads {FORMAT_VERSION})")]
    UnknownVersion(u64),
    #[error("inconsistent file: {0}")]
    Inconsistent(String),
}

#[derive(Serialize)]
struct FileOut<'a> {
    format_version: u32,
    revision: u32,
    running: &'a Config,
    history: Vec<RevisionOut<'a>>,
    /// Router accounts (G0.3): hashes only, outside the revisions so a
    /// rollback never restores an old password.
    #[serde(skip_serializing_if = "Users::is_empty")]
    users: &'a Users,
}

#[derive(Serialize)]
struct RevisionOut<'a> {
    number: u32,
    comment: &'a str,
    timestamp: Option<u64>,
    config: &'a Config,
}

#[derive(Deserialize)]
struct VersionProbe {
    format_version: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIn {
    #[serde(rename = "format_version")]
    _format_version: u32, // checked by VersionProbe first
    revision: u32,
    running: Config,
    history: Vec<RevisionIn>,
    #[serde(default)]
    users: Users,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevisionIn {
    number: u32,
    comment: String,
    timestamp: Option<u64>,
    config: Config,
}

/// Serialize running + history (the candidate is never persisted: an
/// uncommitted edit does not survive a reboot, as on Junos/VyOS).
pub fn encode(store: &ConfigStore) -> Result<String, PersistError> {
    encode_with_users(store, &Users::default())
}

/// [`encode`] plus the router accounts (whole history, no size bound).
pub fn encode_with_users(store: &ConfigStore, users: &Users) -> Result<String, PersistError> {
    encode_from(store, users, 0)
}

/// The file of `store` and `users` in at most `budget` bytes, and how many
/// of the oldest revisions were left out to fit. Compact JSON; the newest
/// revision (the running config) is always kept, and when even that does
/// not fit the result is [`PersistError::TooLarge`] (nothing to write).
pub fn encode_bounded(
    store: &ConfigStore,
    users: &Users,
    budget: usize,
) -> Result<(String, usize), PersistError> {
    let text = encode_from(store, users, 0)?;
    if text.len() <= budget {
        return Ok((text, 0));
    }
    // Too big: keep the newest revisions that fit next to the rest. The
    // sizes are measured, so the result is exact.
    let history = store.history();
    let rest = text.len().saturating_sub(
        history
            .iter()
            .map(|r| encoded_len(&r.config).saturating_add(r.comment.len()))
            .sum::<usize>(),
    );
    let mut used = rest;
    let mut keep = 0usize;
    for r in history.iter().rev() {
        let size = encoded_len(&r.config)
            .saturating_add(r.comment.len())
            .saturating_add(64);
        if keep > 0 && used.saturating_add(size) > budget {
            break;
        }
        used = used.saturating_add(size);
        keep += 1;
    }
    let mut skip = history.len().saturating_sub(keep);
    loop {
        let text = encode_from(store, users, skip)?;
        if text.len() <= budget {
            return Ok((text, skip));
        }
        // The estimate was short (escaped comments): one more out.
        if skip.saturating_add(1) >= history.len() {
            return Err(PersistError::TooLarge(text.len()));
        }
        skip += 1;
    }
}

/// Bytes of `cfg` as compact JSON, counted without building the text.
pub fn encoded_len(cfg: &Config) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(buf.len());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut n = Count(0);
    // Plain serde data: it cannot fail; a failure counts as "too big".
    match serde_json::to_writer(&mut n, cfg) {
        Ok(()) => n.0,
        Err(_) => usize::MAX,
    }
}

fn encode_from(store: &ConfigStore, users: &Users, skip: usize) -> Result<String, PersistError> {
    let file = FileOut {
        format_version: FORMAT_VERSION,
        revision: store.current_revision(),
        running: store.running(),
        history: store
            .history()
            .iter()
            .skip(skip)
            .map(|r| RevisionOut {
                number: r.number,
                comment: &r.comment,
                timestamp: r.timestamp,
                config: &r.config,
            })
            .collect(),
        users,
    };
    // Compact: 21% smaller than pretty-printed (**medido**: 4000
    // address-list entries, 1.16 MB against 1.47 MB a copy).
    let mut out =
        serde_json::to_string(&file).map_err(|e| PersistError::Malformed(e.to_string()))?;
    out.push('\n');
    Ok(out)
}

/// `cfg` as compact JSON: the text a save splices into its files, so a
/// commit serializes its config once (G1.23).
pub fn encode_config(cfg: &Config) -> Result<String, PersistError> {
    serde_json::to_string(cfg).map_err(|e| PersistError::Malformed(e.to_string()))
}

/// The running file of a store whose older revisions live in revision
/// files (G1.23): the same layout as [`encode_with_users`], with the
/// newest revision as the only history entry, so an older build still
/// loads it. `config` is [`encode_config`] of the running config; it is
/// spliced in twice instead of serialized twice.
pub fn encode_running(newest: &Revision, config: &str, users: &Users) -> Result<String, PersistError> {
    let mut out = String::with_capacity(config.len().saturating_mul(2).saturating_add(512));
    out.push_str("{\"format_version\":");
    out.push_str(&FORMAT_VERSION.to_string());
    out.push_str(",\"revision\":");
    out.push_str(&newest.number.to_string());
    out.push_str(",\"running\":");
    out.push_str(config);
    out.push_str(",\"history\":[");
    push_revision(&mut out, newest, config)?;
    out.push(']');
    if !users.is_empty() {
        out.push_str(",\"users\":");
        out.push_str(&to_json(users)?);
    }
    out.push_str("}\n");
    Ok(out)
}

/// One revision as `{"number","comment","timestamp","config"}`.
fn push_revision(out: &mut String, rev: &Revision, config: &str) -> Result<(), PersistError> {
    out.push_str("{\"number\":");
    out.push_str(&rev.number.to_string());
    out.push_str(",\"comment\":");
    out.push_str(&to_json(&rev.comment)?);
    out.push_str(",\"timestamp\":");
    out.push_str(&to_json(&rev.timestamp)?);
    out.push_str(",\"config\":");
    out.push_str(config);
    out.push('}');
    Ok(())
}

fn to_json<T: Serialize + ?Sized>(v: &T) -> Result<String, PersistError> {
    serde_json::to_string(v).map_err(|e| PersistError::Malformed(e.to_string()))
}

/// A revision file (G1.23): one older revision, written once when it is
/// committed and read back at boot. `config` is [`encode_config`] of it.
/// Self-describing (it carries its number), so the files need no index.
pub fn encode_revision(rev: &Revision, config: &str) -> Result<String, PersistError> {
    let mut out = String::with_capacity(config.len().saturating_add(320));
    out.push_str("{\"format_version\":");
    out.push_str(&FORMAT_VERSION.to_string());
    out.push(',');
    // The revision's fields follow, inside the same object.
    let mut body = String::new();
    push_revision(&mut body, rev, config)?;
    out.push_str(body.get(1..).unwrap_or_default());
    out.push('\n');
    Ok(out)
}

/// A revision file stored as a difference (audit-history): how to build
/// revision `number` from revision `base`, the next newer one, as a
/// [`crate::json_delta`] of their configs. Same header as [`encode_revision`];
/// `base` and `delta` instead of `config` tell the two apart.
pub fn encode_revision_delta(
    rev: &Revision,
    base: u32,
    delta: &serde_json::Value,
) -> Result<String, PersistError> {
    let mut out = String::new();
    out.push_str("{\"format_version\":");
    out.push_str(&FORMAT_VERSION.to_string());
    out.push_str(",\"number\":");
    out.push_str(&rev.number.to_string());
    out.push_str(",\"comment\":");
    out.push_str(&to_json(&rev.comment)?);
    out.push_str(",\"timestamp\":");
    out.push_str(&to_json(&rev.timestamp)?);
    out.push_str(",\"base\":");
    out.push_str(&base.to_string());
    out.push_str(",\"delta\":");
    out.push_str(&to_json(delta)?);
    out.push_str("}\n");
    Ok(out)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevisionFileIn {
    #[serde(rename = "format_version")]
    _format_version: u32, // checked by VersionProbe first
    number: u32,
    comment: String,
    timestamp: Option<u64>,
    #[serde(default)]
    config: Option<Config>,
    #[serde(default)]
    base: Option<u32>,
    #[serde(default)]
    delta: Option<serde_json::Value>,
}

/// What a revision file holds.
#[derive(Debug, Clone)]
pub enum RevisionFile {
    /// The whole config ([`encode_revision`], G1.23 builds).
    Full(Revision),
    /// A difference against the newer revision `base`
    /// ([`encode_revision_delta`]); `rev.config` is left default until
    /// [`apply_revision_delta`] builds it.
    Delta {
        rev: Revision,
        base: u32,
        delta: serde_json::Value,
    },
}

/// Parse a revision file written by [`encode_revision`] or
/// [`encode_revision_delta`]; it must hold revision `number` (a file is
/// hostile input like the running file).
pub fn decode_revision_file(text: &str, number: u32) -> Result<RevisionFile, PersistError> {
    check_version(text)?;
    let file: RevisionFileIn = serde_json::from_str(text).map_err(malformed)?;
    if file.number != number {
        return Err(PersistError::Inconsistent(format!(
            "holds revision {} instead of {number}",
            file.number
        )));
    }
    let mut rev = Revision {
        number,
        comment: file.comment.chars().take(256).collect(),
        timestamp: file.timestamp,
        config: Config::default(),
    };
    match (file.config, file.base, file.delta) {
        (Some(config), None, None) => {
            rev.config = config;
            Ok(RevisionFile::Full(rev))
        }
        (None, Some(base), Some(delta)) if base > number => {
            Ok(RevisionFile::Delta { rev, base, delta })
        }
        (None, Some(base), Some(_)) => Err(PersistError::Inconsistent(format!(
            "revision {number} is a difference against {base}, which is not newer"
        ))),
        _ => Err(PersistError::Malformed(
            "a revision file holds either config or base + delta".into(),
        )),
    }
}

/// A line of the config journal (G0.22): how to build revision `rev` from
/// revision `base`, the one before it, as a delta of their configs (the
/// opposite direction of a revision file). Same fields as
/// [`encode_revision_delta`], one line.
pub fn encode_journal_line(rev: &Revision, base: u32, delta: &serde_json::Value) -> Result<String, PersistError> {
    encode_revision_delta(rev, base, delta)
}

/// A journal line parsed: the revision (config left default until the
/// delta is applied to `base`'s), `base`, and the delta. Hostile input like
/// any saved file.
pub fn decode_journal_line(text: &str) -> Result<(Revision, u32, serde_json::Value), PersistError> {
    check_version(text)?;
    let line: RevisionFileIn = serde_json::from_str(text).map_err(malformed)?;
    let (None, Some(base), Some(delta)) = (line.config, line.base, line.delta) else {
        return Err(PersistError::Malformed("a journal line holds base + delta".into()));
    };
    if base >= line.number {
        return Err(PersistError::Inconsistent(format!(
            "journal line for revision {} builds on {base}, which is not older",
            line.number
        )));
    }
    let rev = Revision {
        number: line.number,
        comment: line.comment.chars().take(256).collect(),
        timestamp: line.timestamp,
        config: Config::default(),
    };
    Ok((rev, base, delta))
}

/// Parse a full revision file (see [`decode_revision_file`]).
pub fn decode_revision(text: &str, number: u32) -> Result<Revision, PersistError> {
    match decode_revision_file(text, number)? {
        RevisionFile::Full(rev) => Ok(rev),
        RevisionFile::Delta { base, .. } => Err(PersistError::Inconsistent(format!(
            "revision {number} is a difference against {base}"
        ))),
    }
}

/// `cfg` as a JSON tree, what [`crate::json_delta`] compares.
pub fn config_value(cfg: &Config) -> Result<serde_json::Value, PersistError> {
    serde_json::to_value(cfg).map_err(|e| PersistError::Malformed(e.to_string()))
}

/// The delta a revision file stores: how to build `rev` from `base`, the
/// config of the next newer revision. Sections the two share are not
/// serialized ([`crate::config_delta::diff`]).
pub fn revision_delta(base: &Config, rev: &Config) -> Result<serde_json::Value, PersistError> {
    crate::config_delta::diff(base, rev)
}

/// The config of a revision file stored as a difference: `delta` applied
/// to `base`, the config of the newer revision. The sections the delta
/// does not touch stay shared with `base` ([`crate::config_delta`]).
pub fn apply_revision_delta(base: &Config, delta: &serde_json::Value) -> Result<Config, PersistError> {
    crate::config_delta::apply(base, delta)
}

/// Size bound, then `format_version` before anything else.
fn check_version(text: &str) -> Result<(), PersistError> {
    if text.len() > MAX_FILE_BYTES {
        return Err(PersistError::TooLarge(text.len()));
    }
    let probe: VersionProbe = serde_json::from_str(text).map_err(malformed)?;
    match probe.format_version {
        None => Err(PersistError::Malformed("missing format_version".into())),
        Some(v) => match v.as_u64() {
            Some(n) if n == u64::from(FORMAT_VERSION) => Ok(()),
            Some(n) => Err(PersistError::UnknownVersion(n)),
            None => Err(PersistError::Malformed(
                "format_version must be an integer".into(),
            )),
        },
    }
}

/// Parse and verify a file written by [`encode`] (accounts are dropped).
pub fn decode(text: &str) -> Result<ConfigStore, PersistError> {
    decode_with_users(text).map(|(store, _)| store)
}

/// Parse and verify a file written by [`encode_with_users`]. A file
/// without `users` (older builds) gives an empty list.
pub fn decode_with_users(text: &str) -> Result<(ConfigStore, Users), PersistError> {
    check_version(text)?;
    let file: FileIn = serde_json::from_str(text).map_err(malformed)?;

    let mut history = Vec::with_capacity(file.history.len());
    let mut last: Option<u32> = None;
    for r in file.history {
        if last.is_some_and(|prev| r.number <= prev) {
            return Err(PersistError::Inconsistent(format!(
                "revision {} after {} (numbers must increase)",
                r.number,
                last.unwrap_or_default()
            )));
        }
        last = Some(r.number);
        history.push(Revision {
            number: r.number,
            comment: r.comment.chars().take(256).collect(),
            timestamp: r.timestamp,
            config: r.config,
        });
    }
    let newest = history
        .last()
        .ok_or_else(|| PersistError::Inconsistent("empty history".into()))?;
    if newest.number != file.revision {
        return Err(PersistError::Inconsistent(format!(
            "revision is {} but the newest history entry is {}",
            file.revision, newest.number
        )));
    }
    if newest.config != file.running {
        return Err(PersistError::Inconsistent(
            "running differs from the newest revision".into(),
        ));
    }
    file.users.check().map_err(PersistError::Inconsistent)?;
    // A hand-edited or restored file may have counters behind its items:
    // the next `add` would reuse an id. Repaired the same way in both
    // copies, so they stay equal.
    let running = repair_ids(file.running);
    if let Some(newest) = history.last_mut() {
        newest.config = running.clone();
    }
    Ok((ConfigStore::restore(running, history), file.users))
}

/// `cfg` with every `next_*` id counter at least the largest id it hands
/// out, and duplicate ids inside one list renumbered (they would collapse
/// into one entry in `config.diff`). A counter `next_<word>_id` covers the
/// lists named after `<word>` (`next_route_id` → `routes`); `next_id`
/// covers the other lists of the same object. Unchanged when consistent.
pub fn repair_ids(cfg: Config) -> Config {
    let Ok(mut v) = serde_json::to_value(&cfg) else {
        return cfg;
    };
    if !repair_value(&mut v, 0) {
        return cfg;
    }
    serde_json::from_value(v).unwrap_or(cfg)
}

fn item_id(item: &serde_json::Value) -> Option<u32> {
    let hex = item.get("id")?.as_str()?.strip_prefix('*')?;
    u32::from_str_radix(hex, 16).ok()
}

/// Repair one object and what it holds; `true` when anything changed.
fn repair_value(v: &mut serde_json::Value, depth: usize) -> bool {
    use serde_json::Value;
    // Config nesting is shallow; a bound keeps hostile input harmless.
    if depth > 32 {
        return false;
    }
    let mut changed = false;
    match v {
        Value::Array(items) => {
            for item in items {
                changed |= repair_value(item, depth + 1);
            }
        }
        Value::Object(map) => {
            for child in map.values_mut() {
                changed |= repair_value(child, depth + 1);
            }
            let counters: Vec<String> = map
                .keys()
                .filter(|k| k.starts_with("next_") && k.ends_with("id"))
                .cloned()
                .collect();
            let lists: Vec<String> = map
                .iter()
                .filter(|(_, x)| x.as_array().is_some_and(|a| a.iter().any(|i| item_id(i).is_some())))
                .map(|(k, _)| k.clone())
                .collect();
            let word = |c: &str| -> Option<String> {
                c.strip_prefix("next_")
                    .and_then(|w| w.strip_suffix("_id"))
                    .map(str::to_owned)
            };
            // Words that name a list here (`route` → `routes`), empty or not.
            let named: Vec<String> = counters
                .iter()
                .filter_map(|c| word(c))
                .filter(|w| {
                    map.iter()
                        .any(|(k, x)| x.is_array() && k.starts_with(w.as_str()))
                })
                .collect();
            for c in &counters {
                let mine: Vec<&String> = match word(c).filter(|w| named.contains(w)) {
                    Some(w) => lists.iter().filter(|l| l.starts_with(w.as_str())).collect(),
                    // `next_id`, or a counter shared by lists of other
                    // names (`next_rule_id` → filter, nat, mangle).
                    None => lists
                        .iter()
                        .filter(|l| !named.iter().any(|w| l.starts_with(w.as_str())))
                        .collect(),
                };
                if mine.is_empty() {
                    continue;
                }
                let Some(mut next) = map.get(c).and_then(Value::as_u64) else {
                    continue;
                };
                let max = mine
                    .iter()
                    .filter_map(|l| map.get(l.as_str()).and_then(Value::as_array))
                    .flatten()
                    .filter_map(item_id)
                    .max()
                    .map_or(0, u64::from);
                if max > next {
                    next = max;
                    changed = true;
                }
                for l in &mine {
                    let Some(Value::Array(items)) = map.get_mut(l.as_str()) else {
                        continue;
                    };
                    let mut seen = std::collections::HashSet::new();
                    for item in items.iter_mut() {
                        let Some(id) = item_id(item) else {
                            continue;
                        };
                        if seen.insert(id) {
                            continue;
                        }
                        let Some(fresh) = next.checked_add(1).filter(|n| *n <= u64::from(u32::MAX))
                        else {
                            continue;
                        };
                        next = fresh;
                        if let Some(o) = item.as_object_mut() {
                            o.insert("id".into(), Value::String(format!("*{fresh:X}")));
                            changed = true;
                        }
                    }
                }
                map.insert(c.clone(), Value::from(next));
            }
        }
        _ => {}
    }
    changed
}

fn malformed(e: serde_json::Error) -> PersistError {
    // serde_json messages quote at most a short token, never the whole input.
    let msg: String = e.to_string().chars().take(200).collect();
    PersistError::Malformed(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json_delta;

    fn sample() -> ConfigStore {
        let mut st = ConfigStore::default();
        st.candidate_mut().system.identity = "edge-1".into();
        st.commit("rename", Some(1_700_000_000)).unwrap();
        st.candidate_mut().system.identity = "edge-2".into();
        st.commit("again", None).unwrap();
        st
    }

    #[test]
    fn round_trip() {
        let st = sample();
        let text = encode(&st).unwrap();
        let back = decode(&text).unwrap();
        assert_eq!(back.running(), st.running());
        assert_eq!(back.candidate(), st.running());
        assert!(!back.is_dirty());
        assert_eq!(back.current_revision(), 2);
        let h: Vec<_> = back
            .history()
            .iter()
            .map(|r| (r.number, r.comment.as_str(), r.timestamp))
            .collect();
        assert_eq!(
            h,
            [
                (0, "initial", None),
                (1, "rename", Some(1_700_000_000)),
                (2, "again", None)
            ]
        );
        assert_eq!(back.history()[1].config.system.identity, "edge-1");
        // Byte-stable: re-encoding the decoded store gives the same file.
        assert_eq!(encode(&back).unwrap(), text);
    }

    #[test]
    fn users_round_trip_and_are_checked() {
        use crate::users::{Group, User};
        let st = sample();
        assert!(!encode(&st).unwrap().contains("users"), "no users: no key");
        let mut users = Users::default();
        users.put(User {
            name: "admin".into(),
            group: Group::Full,
            password_hash: Some("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into()),
            disabled: false,
            comment: String::new(),
        });
        let text = encode_with_users(&st, &users).unwrap();
        let (back, u) = decode_with_users(&text).unwrap();
        assert_eq!((back.current_revision(), u), (2, users));
        let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["users"]["admin"]["password_hash"] = "plain".into();
        assert!(matches!(
            decode_with_users(&v.to_string()),
            Err(PersistError::Inconsistent(_))
        ));
    }

    #[test]
    fn next_commit_continues_numbering() {
        let mut back = decode(&encode(&sample()).unwrap()).unwrap();
        back.candidate_mut().system.identity = "edge-3".into();
        assert_eq!(back.commit("", None).unwrap(), 3);
        back.rollback(1).unwrap();
        assert_eq!(back.candidate().system.identity, "edge-1");
    }

    #[test]
    fn version_is_checked_first() {
        assert_eq!(
            decode(r#"{"format_version": 99, "whatever": true}"#).err(),
            Some(PersistError::UnknownVersion(99))
        );
        assert!(matches!(
            decode(r#"{"running": {}}"#),
            Err(PersistError::Malformed(_))
        ));
        assert!(matches!(
            decode(r#"{"format_version": "1"}"#),
            Err(PersistError::Malformed(_))
        ));
    }

    #[test]
    fn inconsistent_files_are_rejected() {
        let text = encode(&sample()).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["running"]["system"]["identity"] = "tampered".into();
        assert!(matches!(
            decode(&v.to_string()),
            Err(PersistError::Inconsistent(_))
        ));

        let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["history"][2]["number"] = 1.into();
        v["revision"] = 1.into();
        assert!(matches!(
            decode(&v.to_string()),
            Err(PersistError::Inconsistent(_))
        ));

        let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["history"] = serde_json::json!([]);
        assert!(matches!(
            decode(&v.to_string()),
            Err(PersistError::Inconsistent(_))
        ));
    }

    #[test]
    fn oversized_input_is_refused_unparsed() {
        let big = " ".repeat(MAX_FILE_BYTES + 1);
        assert_eq!(
            decode(&big).err(),
            Some(PersistError::TooLarge(MAX_FILE_BYTES + 1))
        );
    }

    /// A store with `n` more revisions, each a config of `rules` rules.
    fn big(n: usize, rules: u32) -> ConfigStore {
        use crate::firewall::FirewallRule;
        let mut st = ConfigStore::default();
        for i in 0..rules {
            let mut r: FirewallRule =
                serde_json::from_value(serde_json::json!({"id": "*1", "chain": "forward", "action": {"type": "accept"}}))
                    .unwrap();
            r.id = crate::ItemId(i + 1);
            r.comment = "c".repeat(100);
            st.candidate_mut().ip.firewall.filter.push(r);
        }
        st.candidate_mut().ip.firewall.next_rule_id = rules;
        for i in 0..n {
            st.candidate_mut().system.identity = format!("r{i}");
            st.commit("", None).unwrap();
        }
        st
    }

    #[test]
    fn bounded_encoding_leaves_the_oldest_revisions_out() {
        let st = big(10, 50);
        let (full, skipped) = encode_bounded(&st, &Users::default(), usize::MAX).unwrap();
        assert_eq!(skipped, 0);
        assert!(!full.contains("\n "), "compact JSON");
        let one = encoded_len(st.running());
        let budget = one * 4;
        let (text, skipped) = encode_bounded(&st, &Users::default(), budget).unwrap();
        assert!(text.len() <= budget, "{} > {budget}", text.len());
        assert!(skipped >= 8, "{skipped}");
        let back = decode(&text).unwrap();
        assert_eq!(back.running(), st.running());
        assert_eq!(back.current_revision(), 10);
        assert_eq!(back.history().len(), st.history().len() - skipped);
        // Not even the running config fits: nothing to write.
        assert!(matches!(
            encode_bounded(&st, &Users::default(), one),
            Err(PersistError::TooLarge(_))
        ));
    }

    #[test]
    fn spliced_running_file_is_the_one_revision_file() {
        use crate::users::{Group, User};
        let st = sample();
        let newest = st.history().last().unwrap().clone();
        let mut users = Users::default();
        let config = encode_config(st.running()).unwrap();
        for with_users in [false, true] {
            if with_users {
                users.put(User {
                    name: "admin".into(),
                    group: Group::Full,
                    password_hash: None,
                    disabled: false,
                    comment: String::new(),
                });
            }
            let text = encode_running(&newest, &config, &users).unwrap();
            // Byte for byte what an older build writes for a one-revision
            // store, so it loads there too.
            let one = ConfigStore::restore(st.running().clone(), vec![newest.clone()]);
            assert_eq!(text, encode_with_users(&one, &users).unwrap());
            let (back, u) = decode_with_users(&text).unwrap();
            assert_eq!((back.current_revision(), back.running()), (2, st.running()));
            assert_eq!(u, users);
        }
    }

    #[test]
    fn revision_files_round_trip_and_are_checked() {
        let st = sample();
        let rev = st.history()[1].clone();
        let text = encode_revision(&rev, &encode_config(&rev.config).unwrap()).unwrap();
        let back = decode_revision(&text, 1).unwrap();
        assert_eq!(
            (back.number, back.comment.as_str(), back.timestamp),
            (1, "rename", Some(1_700_000_000))
        );
        assert_eq!(back.config, rev.config);
        assert!(matches!(
            decode_revision(&text, 2),
            Err(PersistError::Inconsistent(_))
        ));
        let cut = text.get(..text.len() / 2).unwrap();
        assert!(matches!(decode_revision(cut, 1), Err(PersistError::Malformed(_))));
        assert!(matches!(
            decode_revision(&text.replacen("\"format_version\":1", "\"format_version\":9", 1), 1),
            Err(PersistError::UnknownVersion(9))
        ));
    }

    #[test]
    fn revision_differences_round_trip_and_are_told_apart() {
        let st = sample();
        let (old, new) = (&st.history()[1], &st.history()[2]);
        let base = config_value(&new.config).unwrap();
        let delta = json_delta::diff(&base, &config_value(&old.config).unwrap());
        let text = encode_revision_delta(old, 2, &delta).unwrap();
        let RevisionFile::Delta { rev, base: b, delta: d } = decode_revision_file(&text, 1).unwrap()
        else {
            panic!("not a delta: {text}");
        };
        assert_eq!((rev.number, rev.comment.as_str(), b), (1, "rename", 2));
        let cfg = apply_revision_delta(&new.config, &d).unwrap();
        assert_eq!(cfg, old.config);
        // A full file is still a full file; the two never mix.
        let full = encode_revision(old, &encode_config(&old.config).unwrap()).unwrap();
        assert!(matches!(decode_revision_file(&full, 1), Ok(RevisionFile::Full(_))));
        assert!(matches!(decode_revision(&text, 1), Err(PersistError::Inconsistent(_))));
        for bad in [
            text.replace("\"base\":2", "\"base\":1"),
            text.replace(",\"base\":2", ""),
            full.replace("\"timestamp\"", "\"base\":2,\"delta\":{},\"timestamp\""),
        ] {
            assert!(decode_revision_file(&bad, 1).is_err(), "{bad}");
        }
        // A delta that builds something that is not a config.
        let wrong = serde_json::json!({"o": {"system": {"=": 7}}});
        assert!(apply_revision_delta(&new.config, &wrong).is_err());
    }

    #[test]
    fn encoded_len_is_exact() {
        let st = big(0, 7);
        assert_eq!(
            encoded_len(st.running()),
            serde_json::to_string(st.running()).unwrap().len()
        );
    }

    #[test]
    fn counters_behind_their_items_are_repaired() {
        let mut st = big(1, 3);
        let mut cfg = st.running().clone();
        cfg.ip.firewall.next_rule_id = 1;
        cfg.ip.firewall.filter.get_mut(2).unwrap().id = crate::ItemId(2); // *1 *2 *2
        let fixed = repair_ids(cfg);
        let ids: Vec<u32> = fixed.ip.firewall.filter.iter().map(|r| r.id.0).collect();
        assert_eq!(ids, [1, 2, 3]);
        assert_eq!(fixed.ip.firewall.next_rule_id, 3);
        // A consistent config is left as it is.
        let same = st.running().clone();
        assert_eq!(crate::store::diff_configs(&same, &repair_ids(same.clone())), []);
        // Through decode: the next id handed out is a new one.
        let mut v: serde_json::Value = serde_json::from_str(&encode(&st).unwrap()).unwrap();
        v["running"]["ip"]["firewall"]["next_rule_id"] = 0.into();
        v["history"][1]["config"]["ip"]["firewall"]["next_rule_id"] = 0.into();
        st = decode(&v.to_string()).unwrap();
        assert_eq!(st.running().ip.firewall.next_rule_id, 3);
    }

    #[test]
    fn error_messages_are_bounded() {
        let junk = format!("{{\"format_version\": 1, \"{}\": 1}}", "k".repeat(10_000));
        let err = decode(&junk).unwrap_err().to_string();
        assert!(err.len() < 400, "{err}");
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(512))]

            #[test]
            fn garbage_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
                let text = String::from_utf8_lossy(&bytes);
                let _ = decode(&text);
            }

            #[test]
            fn truncated_file_is_rejected(cut in 0usize..10_000) {
                let text = encode(&sample()).unwrap();
                let body = text.trim_end();
                let cut = cut % body.len();
                let prefix = body.get(..cut).unwrap_or("");
                prop_assert!(decode(prefix).is_err());
            }

            #[test]
            fn byte_flip_never_panics(pos in 0usize..10_000, byte in any::<u8>()) {
                let mut bytes = encode(&sample()).unwrap().into_bytes();
                let len = bytes.len();
                if let Some(b) = bytes.get_mut(pos % len) {
                    *b = byte;
                }
                let _ = decode(&String::from_utf8_lossy(&bytes));
            }
        }
    }
}
