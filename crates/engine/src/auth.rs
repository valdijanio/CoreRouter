//! Users, groups and permissions (G0.3), RouterOS style.
//!
//! Every command needs a [`Group`]: queries need `read`, changes need
//! `write`, user management needs `full` ([`required_group`]). Who sends a
//! command is the [`Principal`] of its [`Caller`](crate::Caller): the
//! process itself and the local token are [`Principal::Local`] (full), a
//! logged-in account is [`Principal::User`] (its group is looked up on
//! every command, so a demoted or disabled user loses rights at once), and
//! a connection that has not logged in is [`Principal::Anonymous`] (no
//! rights). The engine enforces this in `Session::execute`, `inspect` and
//! `list` (where a forbidden command shows `enabled: false` with the
//! reason, so the GUI greys it out as in G1.16).
//!
//! Passwords are hashed here with Argon2id (PHC string, random salt); the
//! plain text is never stored, journaled or logged (see [`mask_secrets`]).
//! The login itself (tokens, rate limit) lives in the control channel,
//! which verifies with [`verify_password`] outside the session lock.

use std::sync::OnceLock;

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use serde::Serialize;
use serde_json::Value;

pub use corerouter_model::{Group, User, Users};

/// Shortest accepted password.
pub const MIN_PASSWORD: usize = 8;
/// Longest accepted password (bounds the hashing work per request).
pub const MAX_PASSWORD: usize = 256;
/// Parameter and config field names whose values never reach the journal
/// or the log, and that only group `full` reads back (TSIG `secret`, and
/// the keys of features to come: `psk`, `private_key`, `passphrase`).
pub const SECRET_KEYS: &[&str] = &[
    "password",
    "old_password",
    "new_password",
    "token",
    "secret",
    "psk",
    "private_key",
    "passphrase",
    // BGP TCP MD5 key (G3.2a).
    "tcp_md5_key",
];

/// A `config.diff` path that ends in a secret field (`ip.dns_tsig.keys[*1].secret`).
pub fn is_secret_path(path: &str) -> bool {
    let last = path.rsplit('.').next().unwrap_or(path);
    SECRET_KEYS.contains(&last)
}

/// Who sends a command.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(tag = "kind", content = "name", rename_all = "lowercase")]
pub enum Principal {
    /// This process, or a client holding the local token: group `full`.
    Local,
    /// A connection that has not logged in: nothing but the login.
    #[default]
    Anonymous,
    /// A logged-in account.
    User(String),
}

impl Principal {
    /// "admin", "local", "(not logged in)".
    pub fn label(&self) -> &str {
        match self {
            Self::Local => "local",
            Self::Anonymous => "(not logged in)",
            Self::User(name) => name,
        }
    }
}

/// Commands that change state although they are not journaled.
const WRITE_QUERIES: &[&str] = &["config.mode.set"];

/// The group a command needs.
pub fn required_group(id: &str, journal: bool) -> Group {
    if id.starts_with("user.") {
        Group::Full
    } else if journal || WRITE_QUERIES.contains(&id) {
        Group::Write
    } else {
        Group::Read
    }
}

/// `Ok` when `have` covers `need`, else the reason (shown greyed out).
pub fn permit(principal: &Principal, have: Option<Group>, need: Group) -> Result<(), String> {
    match have {
        Some(g) if g >= need => Ok(()),
        Some(g) => Err(format!(
            "needs group {need}; {} is in group {g}",
            principal.label()
        )),
        None if *principal == Principal::Anonymous => {
            Err("not logged in: call auth.login first".into())
        }
        None => Err(format!(
            "user '{}' no longer exists or is disabled",
            principal.label()
        )),
    }
}

/// Fill `buf` from the operating system's random source. The browser lab
/// (wasm) has none here, so it cannot create passwords.
pub fn random_bytes(buf: &mut [u8]) -> Result<(), String> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        getrandom::fill(buf).map_err(|e| format!("no random source: {e}"))
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = buf;
        Err("passwords cannot be set in the browser lab (no random source)".into())
    }
}

/// Bounds and characters of a new password (the value is never echoed).
pub fn check_password(password: &str) -> Result<(), String> {
    let n = password.chars().count();
    if n < MIN_PASSWORD {
        return Err(format!("must have at least {MIN_PASSWORD} characters"));
    }
    if password.len() > MAX_PASSWORD {
        return Err(format!("must have at most {MAX_PASSWORD} bytes"));
    }
    if password.chars().any(char::is_control) {
        return Err("control characters are not allowed".into());
    }
    Ok(())
}

/// Argon2id hash (PHC string) of `password` with a fresh random salt.
pub fn hash_password(password: &str) -> Result<String, String> {
    let mut salt = [0u8; 16];
    random_bytes(&mut salt)?;
    hash_with_salt(password, &salt)
}

fn hash_with_salt(password: &str, salt: &[u8]) -> Result<String, String> {
    let salt = SaltString::encode_b64(salt).map_err(|e| format!("salt: {e}"))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("hashing failed: {e}"))
}

/// Does `password` match the PHC string `phc`? Any malformed hash or an
/// over-long password is a plain `false`.
pub fn verify_password(phc: &str, password: &str) -> bool {
    if password.len() > MAX_PASSWORD {
        return false;
    }
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Spend the time of one verification, for a user that does not exist, so
/// the reply time does not tell which user names are real.
pub fn burn_verification(password: &str) {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let phc = DUMMY.get_or_init(|| {
        hash_with_salt("corerouter-dummy-password", b"corerouter-dummy").unwrap_or_default()
    });
    let _ = verify_password(phc, password);
}

/// Parameters that are secret for one command only: `ppp.secret.import`'s
/// `text` is a whole export with every subscriber's password (G4.3n).
pub const SECRET_PARAMS: &[(&str, &str)] = &[("ppp.secret.import", "text")];

/// [`mask_secrets`] of the parameters of command `id`, and its own
/// [`SECRET_PARAMS`] (the journal and the log keep this).
pub fn mask_params(id: &str, params: &Value) -> Value {
    let mut v = mask_secrets(params);
    if let Some(o) = v.as_object_mut() {
        for (_, key) in SECRET_PARAMS.iter().filter(|(c, _)| *c == id) {
            if let Some(x) = o.get_mut(*key) {
                let n = x.as_str().map_or(0, str::len);
                *x = Value::String(format!("*** ({n} bytes)"));
            }
        }
    }
    v
}

/// A copy of command parameters with every secret replaced by `"***"`
/// (journal, logs). Walks nested objects and arrays.
pub fn mask_secrets(v: &Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, x)| {
                    let masked = if SECRET_KEYS.contains(&k.as_str()) && !x.is_null() {
                        Value::String("***".into())
                    } else {
                        mask_secrets(x)
                    };
                    (k.clone(), masked)
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(mask_secrets).collect()),
        other => other.clone(),
    }
}

/// The answer to `auth.whoami` (control channel, and the UI's in-process
/// lab): user, group, how it is connected and, for group `full`, the
/// accounts of group full without a password (G0.3b).
pub fn whoami(s: &crate::Session, principal: &Principal, via: &str) -> Value {
    let group = s.group_of(principal);
    let mut out = serde_json::json!({
        "user": principal.label(),
        "group": group,
        "via": via,
    });
    if group == Some(Group::Full)
        && let Some(o) = out.as_object_mut()
    {
        o.insert(
            "no_password".into(),
            Value::from(s.admins_without_password()),
        );
    }
    out
}

/// One logged-in session, for `user.active.list` (no token here: the
/// control channel keeps those).
#[derive(Debug, Clone, Serialize)]
pub struct Login {
    pub id: u64,
    pub user: String,
    /// "tcp 10.0.0.2:50412", "ws 127.0.0.1:41000".
    pub via: String,
    pub since: Option<u64>,
    pub last_seen: Option<u64>,
}

/// Most logins tracked at once; the oldest is dropped beyond it.
pub const MAX_LOGINS: usize = 256;
/// Most logins of one user: beyond it that user's oldest is dropped, so no
/// account can push the others out by logging in over and over.
pub const MAX_LOGINS_PER_USER: usize = 16;

#[derive(Debug, Clone, Default)]
pub(crate) struct Logins {
    pub(crate) list: Vec<Login>,
    next: u64,
}

impl Logins {
    pub(crate) fn begin(&mut self, user: &str, via: &str, now: Option<u64>) -> u64 {
        self.next = self.next.saturating_add(1);
        let mine = self.list.iter().filter(|l| l.user == user).count();
        if mine >= MAX_LOGINS_PER_USER {
            if let Some(i) = self.list.iter().position(|l| l.user == user) {
                self.list.remove(i);
            }
        } else if self.list.len() >= MAX_LOGINS && !self.list.is_empty() {
            self.list.remove(0);
        }
        self.list.push(Login {
            id: self.next,
            user: user.to_owned(),
            via: via.chars().take(128).collect(),
            since: now,
            last_seen: now,
        });
        self.next
    }

    pub(crate) fn touch(&mut self, id: u64, now: Option<u64>) -> bool {
        match self.list.iter_mut().find(|l| l.id == id) {
            Some(l) => {
                l.last_seen = now.or(l.last_seen);
                true
            }
            None => false,
        }
    }

    pub(crate) fn end(&mut self, id: u64) {
        self.list.retain(|l| l.id != id);
    }

    pub(crate) fn end_user(&mut self, user: &str) {
        self.list.retain(|l| l.user != user);
    }

    /// [`Self::end_user`], keeping the logins made over `via`.
    pub(crate) fn end_user_except(&mut self, user: &str, via: &str) {
        self.list.retain(|l| l.user != user || l.via == via);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hash_and_verify() {
        let h = hash_password("correct horse").unwrap();
        assert!(h.starts_with("$argon2id$"), "{h}");
        assert!(!h.contains("correct horse"));
        assert!(verify_password(&h, "correct horse"));
        assert!(!verify_password(&h, "correct horsE"));
        assert!(!verify_password("garbage", "x"));
        assert_ne!(h, hash_password("correct horse").unwrap(), "salted");
        burn_verification("x");
    }

    #[test]
    fn groups_per_command() {
        assert_eq!(required_group("interface.list", false), Group::Read);
        assert_eq!(required_group("ip.address.add", true), Group::Write);
        assert_eq!(required_group("config.mode.set", false), Group::Write);
        assert_eq!(required_group("user.list", false), Group::Full);
        assert_eq!(required_group("user.add", true), Group::Full);
        let bob = Principal::User("bob".into());
        assert!(permit(&bob, Some(Group::Write), Group::Read).is_ok());
        assert!(
            permit(&bob, Some(Group::Read), Group::Write)
                .unwrap_err()
                .contains("needs group write")
        );
        assert!(
            permit(&Principal::Anonymous, None, Group::Read)
                .unwrap_err()
                .contains("auth.login")
        );
        assert!(permit(&bob, None, Group::Read).is_err());
    }

    #[test]
    fn secrets_are_masked_everywhere() {
        let v = json!({"name": "bob", "password": "s3cret!!",
                       "steps": [{"params": {"new_password": "x", "token": null}}]});
        let m = mask_secrets(&v).to_string();
        assert!(!m.contains("s3cret") && !m.contains("\"x\""), "{m}");
        assert!(m.contains("bob") && m.contains("null"));
    }

    #[test]
    fn password_rules() {
        assert!(check_password("short").is_err());
        assert!(check_password("long enough").is_ok());
        assert!(check_password("tab\there!").is_err());
        assert!(check_password(&"x".repeat(MAX_PASSWORD + 1)).is_err());
    }

    /// Audit (control finding 7): a user logging in over and over drops
    /// only its own oldest logins, never another account's.
    #[test]
    fn repeated_logins_evict_only_the_same_user() {
        let mut l = Logins::default();
        let admin = l.begin("admin", "tcp 10.0.0.1:1", None);
        for _ in 0..MAX_LOGINS + 5 {
            l.begin("noc", "tcp 10.0.0.2:1", None);
        }
        assert!(l.touch(admin, None), "admin's login was evicted");
        let noc = l.list.iter().filter(|x| x.user == "noc").count();
        assert_eq!(noc, MAX_LOGINS_PER_USER);
    }
}
