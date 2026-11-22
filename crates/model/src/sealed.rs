//! A secret the router needs in clear but never stores in clear (G4.3n).
//!
//! CHAP and MS-CHAP need the subscriber's password itself (RFC 1994 §2.2:
//! the secret is hashed with the challenge), so a hash is not enough. The
//! config holds it sealed instead: `$cr1$` and the base64 of an AEAD box
//! made by the engine (`corerouter_engine::sealing`) with a key kept
//! outside the config. Every copy of the config — revisions, the history
//! files on disk, `config.diff`, `state.inspect` — carries the box, never
//! the password; only the engine opens it (the PPPoE login, `export
//! show-sensitive` for group full).
//!
//! A value without the prefix is a password from before G4.3n (or a test's
//! literal): it still works, and the engine seals it at start-up.

use std::fmt;

use serde::{Deserialize, Serialize};

/// What a sealed value starts with (version 1: AES-256-GCM).
pub const PREFIX: &str = "$cr1$";

#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sealed(String);

impl Sealed {
    /// A box as the engine made it (`$cr1$…`).
    pub fn from_box(text: String) -> Self {
        Self(text)
    }

    /// No password at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A box (not a password kept in clear from before G4.3n).
    pub fn is_sealed(&self) -> bool {
        self.0.starts_with(PREFIX)
    }

    /// The text as stored: the box, or a legacy clear password. Only the
    /// engine's sealing reads it.
    pub fn stored(&self) -> &str {
        &self.0
    }
}

/// A clear password (tests, configs from before G4.3n): the engine seals
/// it on the next start.
impl From<&str> for Sealed {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl From<String> for Sealed {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Never the contents: a `{:?}` of a config goes to logs and panics.
impl fmt::Debug for Sealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.is_empty(), self.is_sealed()) {
            (true, _) => f.write_str("Sealed(empty)"),
            (false, true) => f.write_str("Sealed(***)"),
            (false, false) => f.write_str("Sealed(clear ***)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_shows_the_text_and_serde_is_the_string() {
        let s = Sealed::from("s3nh4");
        assert!(!format!("{s:?}").contains("s3nh4"));
        assert!(!s.is_sealed() && !s.is_empty());
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"s3nh4\"");
        let b = Sealed::from_box(format!("{PREFIX}abc"));
        assert!(b.is_sealed());
        let back: Sealed = serde_json::from_str("\"$cr1$abc\"").unwrap();
        assert_eq!(back, b);
    }
}
