//! `/certificate` (G1.6zs): the TLS certificates the router serves with.
//!
//! A certificate is either made here (`certificate.add`, self-signed, as
//! RouterOS `add` + `sign`) or brought by the operator (`certificate.import`,
//! PEM with its chain and key). A service picks one by name, as RouterOS
//! `/ip service set www-ssl certificate=<name>`: `www-ssl` now, the DNS over
//! TLS and HTTPS server next (G4.1zf). Without one a service keeps the
//! router's own certificate (the one of the control port, made at first
//! boot).
//!
//! The private key is [`Sealed`] at rest, like a WireGuard key: every copy
//! of the config (revisions, `config.diff`, `state.inspect`, `/export`)
//! carries the box, never the key. The certificate itself is public and is
//! stored as PEM.
//!
//! The engine parses and checks what goes in (the PEM, the key against the
//! certificate); the model only bounds sizes and names.

use serde::{Deserialize, Serialize};

use crate::sealed::Sealed;
use crate::types::ItemId;

/// Certificates in the store (RouterOS has no fixed limit; a router serves
/// with a handful).
pub const MAX_CERTIFICATES: usize = 64;
/// Largest PEM accepted for one certificate with its chain (a chain of
/// four 4096-bit RSA certificates is ~9 KiB).
pub const MAX_PEM_BYTES: usize = 64 * 1024;
/// Largest PEM private key (an 8192-bit RSA key is ~6.4 KiB).
pub const MAX_KEY_BYTES: usize = 16 * 1024;
/// Certificates in one chain (leaf + intermediates + root).
pub const MAX_CHAIN: usize = 8;

/// Where a certificate came from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    /// Made by `certificate.add` (self-signed).
    #[default]
    Generated,
    /// Brought by `certificate.import`.
    Imported,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generated => "generated",
            Self::Imported => "imported",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub id: ItemId,
    /// How services name it (`certificate=<name>`).
    pub name: String,
    /// PEM: the certificate first, then the rest of its chain.
    pub certificate: String,
    /// The PEM private key, sealed. Empty: a certificate without its key
    /// (no service can serve with it).
    #[serde(default, skip_serializing_if = "Sealed::is_empty")]
    pub private_key: Sealed,
    #[serde(default)]
    pub origin: Origin,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Certificates {
    pub list: Vec<Certificate>,
    pub next_id: u32,
}

impl Certificates {
    pub fn is_default(&self) -> bool {
        self.list.is_empty() && self.next_id == 0
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    pub fn get(&self, name: &str) -> Option<&Certificate> {
        self.list.iter().find(|c| c.name == name)
    }
}

/// A certificate name: what RouterOS allows, without spaces (names appear
/// unquoted in the terminal), at most 63 bytes.
pub fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_bounded() {
        assert!(name_ok("dns-lan"));
        assert!(name_ok("router.lan_2026"));
        assert!(!name_ok(""));
        assert!(!name_ok("with space"));
        assert!(!name_ok(&"x".repeat(64)));
    }

    #[test]
    fn an_old_config_without_certificates_loads() {
        let c: Certificates = serde_json::from_str("{}").unwrap();
        assert!(c.is_default());
        let c: Certificate = serde_json::from_str(
            r#"{"id": "*1", "name": "a", "certificate": "-----BEGIN CERTIFICATE-----"}"#,
        )
        .unwrap();
        assert!(c.private_key.is_empty());
        assert_eq!(c.origin, Origin::Generated);
    }

    #[test]
    fn debug_never_shows_the_key() {
        let c = Certificate {
            id: ItemId(1),
            name: "a".into(),
            certificate: String::new(),
            private_key: Sealed::from_box("$cr1$secret".into()),
            origin: Origin::Imported,
            comment: String::new(),
        };
        assert!(!format!("{c:?}").contains("secret"));
    }
}
