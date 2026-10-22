//! Router users and groups, RouterOS style (`/user`).
//!
//! Users are **not** part of the versioned [`Config`](crate::Config): a
//! `config.rollback` must never bring back a removed account or an old
//! password, and `config.diff` must never carry a password hash. They are
//! saved in the same file as the config (see [`crate::persist`]) and change
//! at once, outside the candidate/commit cycle.
//!
//! Only the Argon2id hash of a password is kept (PHC string, made by the
//! engine); the model never sees a plain password. An account with **no
//! password** (the first `admin`, RouterOS style) has `password_hash: None`,
//! never the hash of an empty string: the control channel then lets it in
//! only from loopback, and refuses every network login while an account of
//! group `full` is in that state (G0.3b).

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Most users a router keeps (**estimado**: far above any real ISP team).
pub const MAX_USERS: usize = 256;
/// Longest user name.
pub const MAX_NAME: usize = 64;
/// Longest stored hash (an Argon2id PHC string is ~100 characters).
pub const MAX_HASH: usize = 256;

/// What a user may do. Ordered: `Read < Write < Full`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Group {
    /// Queries only: look, never change.
    Read,
    /// Queries and configuration changes.
    Write,
    /// Everything, including users and security settings.
    Full,
}

impl Group {
    pub const ALL: [Group; 3] = [Group::Read, Group::Write, Group::Full];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Full => "full",
        }
    }
}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Group {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "full" => Ok(Self::Full),
            _ => Err("must be read, write or full".into()),
        }
    }
}

/// One account. `password_hash` is an Argon2id PHC string, or `None` for
/// an account without a password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub name: String,
    pub group: Group,
    pub password_hash: Option<String>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

/// All accounts, by name.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Users(BTreeMap<String, User>);

impl Users {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn get(&self, name: &str) -> Option<&User> {
        self.0.get(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &User> {
        self.0.values()
    }

    /// Insert or replace `user` (keyed by its name).
    pub fn put(&mut self, user: User) {
        self.0.insert(user.name.clone(), user);
    }

    pub fn remove(&mut self, name: &str) -> Option<User> {
        self.0.remove(name)
    }

    /// Enabled users of group `full`: the ones who can manage users. The
    /// engine never lets this drop to zero (no lock-out).
    pub fn admins(&self) -> usize {
        self.iter()
            .filter(|u| u.group == Group::Full && !u.disabled)
            .count()
    }

    /// Enabled users of group `full` without a password, by name. While
    /// there is one, the router refuses logins from the network.
    pub fn admins_without_password(&self) -> Vec<String> {
        self.iter()
            .filter(|u| u.group == Group::Full && !u.disabled && u.password_hash.is_none())
            .map(|u| u.name.clone())
            .collect()
    }

    /// Checks a loaded list (the config file is hostile input).
    pub fn check(&self) -> Result<(), String> {
        if self.0.len() > MAX_USERS {
            return Err(format!("{} users (limit {MAX_USERS})", self.0.len()));
        }
        for (key, u) in &self.0 {
            check_name(key)?;
            if key != &u.name {
                return Err(format!("user listed as '{key}' is named '{}'", u.name));
            }
            if let Some(h) = &u.password_hash
                && (h.len() > MAX_HASH || !h.starts_with("$argon2id$"))
            {
                return Err(format!(
                    "user '{key}': password_hash is not an Argon2id hash"
                ));
            }
            if u.comment.chars().count() > 256 || u.comment.chars().any(char::is_control) {
                return Err(format!("user '{key}': bad comment"));
            }
        }
        Ok(())
    }
}

/// A user name: 1..=64 of `A-Z a-z 0-9 . _ -`, not starting with `-` or `.`.
pub fn check_name(name: &str) -> Result<(), String> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME
        && !name.starts_with(['-', '.'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "user names are 1..={MAX_NAME} of A-Z a-z 0-9 . _ - (not starting with - or .)"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str, group: Group) -> User {
        User {
            name: name.into(),
            group,
            password_hash: Some("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into()),
            disabled: false,
            comment: String::new(),
        }
    }

    #[test]
    fn groups_are_ordered_and_round_trip() {
        assert!(Group::Read < Group::Write && Group::Write < Group::Full);
        for g in Group::ALL {
            assert_eq!(g.as_str().parse::<Group>().unwrap(), g);
        }
        assert!("admin".parse::<Group>().is_err());
    }

    #[test]
    fn names_are_checked() {
        for good in ["admin", "noc.team", "a_b-c", "X1"] {
            assert!(check_name(good).is_ok(), "{good}");
        }
        for bad in ["", "-x", ".x", "a b", "a/b", "é", &"a".repeat(65)] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn check_refuses_tampered_lists() {
        let mut u = Users::default();
        u.put(user("admin", Group::Full));
        assert!(u.check().is_ok());
        assert_eq!(u.admins(), 1);
        let mut plain = user("bob", Group::Read);
        plain.password_hash = Some("hunter2".into());
        u.put(plain);
        assert!(u.check().is_err());
        let json = r#"{"x": {"name": "y", "group": "read", "password_hash": "$argon2id$"}}"#;
        let bad: Users = serde_json::from_str(json).unwrap();
        assert!(bad.check().is_err());
    }

    #[test]
    fn no_password_is_explicit_and_round_trips() {
        let mut u = Users::default();
        let mut admin = user("admin", Group::Full);
        admin.password_hash = None;
        u.put(admin);
        u.put(user("noc", Group::Full));
        assert!(u.check().is_ok());
        assert_eq!(u.admins_without_password(), ["admin"]);
        let text = serde_json::to_string(&u).unwrap();
        assert!(text.contains(r#""password_hash":null"#), "{text}");
        let back: Users = serde_json::from_str(&text).unwrap();
        assert_eq!(back, u);
        // A disabled or non-full account does not count.
        let mut ro = user("ro", Group::Read);
        ro.password_hash = None;
        u.put(ro);
        if let Some(mut a) = u.get("admin").cloned() {
            a.disabled = true;
            u.put(a);
        }
        assert!(u.admins_without_password().is_empty());
    }
}
