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

/// Larger files are refused before parsing (64 revisions of a big config fit
/// with plenty of room; **estimado**).
pub const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;

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

/// [`encode`] plus the router accounts.
pub fn encode_with_users(store: &ConfigStore, users: &Users) -> Result<String, PersistError> {
    let file = FileOut {
        format_version: FORMAT_VERSION,
        revision: store.current_revision(),
        running: store.running(),
        history: store
            .history()
            .iter()
            .map(|r| RevisionOut {
                number: r.number,
                comment: &r.comment,
                timestamp: r.timestamp,
                config: &r.config,
            })
            .collect(),
        users,
    };
    let mut out =
        serde_json::to_string_pretty(&file).map_err(|e| PersistError::Malformed(e.to_string()))?;
    out.push('\n');
    Ok(out)
}

/// Parse and verify a file written by [`encode`] (accounts are dropped).
pub fn decode(text: &str) -> Result<ConfigStore, PersistError> {
    decode_with_users(text).map(|(store, _)| store)
}

/// Parse and verify a file written by [`encode_with_users`]. A file
/// without `users` (older builds) gives an empty list.
pub fn decode_with_users(text: &str) -> Result<(ConfigStore, Users), PersistError> {
    if text.len() > MAX_FILE_BYTES {
        return Err(PersistError::TooLarge(text.len()));
    }
    let probe: VersionProbe = serde_json::from_str(text).map_err(malformed)?;
    match probe.format_version {
        None => return Err(PersistError::Malformed("missing format_version".into())),
        Some(v) => match v.as_u64() {
            Some(n) if n == u64::from(FORMAT_VERSION) => {}
            Some(n) => return Err(PersistError::UnknownVersion(n)),
            None => {
                return Err(PersistError::Malformed(
                    "format_version must be an integer".into(),
                ));
            }
        },
    }
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
    Ok((ConfigStore::restore(file.running, history), file.users))
}

fn malformed(e: serde_json::Error) -> PersistError {
    // serde_json messages quote at most a short token, never the whole input.
    let msg: String = e.to_string().chars().take(200).collect();
    PersistError::Malformed(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

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
