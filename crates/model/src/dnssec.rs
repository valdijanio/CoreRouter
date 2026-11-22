//! DNSSEC signing keys of the authoritative zones (G4.1c-2), and the
//! signing state.
//!
//! **Not** part of the versioned [`Config`](crate::Config), like the users
//! (`users.rs`): a `config.rollback` must never take a key away while its
//! DS sits at the parent (the zone would go bogus for every validating
//! resolver), and `config.diff` must never carry a private key. The engine
//! keeps this in the storage's operational state (`dnssec-keys`, a 0600
//! file next to the config) and changes it at once; the daemon generates
//! the keys and signs.
//!
//! Rollover (RFC 6781 §4.1): a ZSK by pre-publication — the new key is
//! published, then signs, then the old one leaves; a KSK by double
//! signature — the new key signs the DNSKEY set next to the old one, the
//! operator puts its DS at the parent and says so (`ds-published`), then
//! the old one leaves.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Keys kept for all zones together (a few per zone).
pub const MAX_KEYS: usize = 2000;

/// RFC 8624 §3.1: ECDSAP256SHA256 (13) is MUST for signing, Ed25519 (15)
/// RECOMMENDED. RSA is left out (bigger answers, slower signing).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnssecAlgorithm {
    #[default]
    EcdsaP256,
    Ed25519,
}

impl DnssecAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaP256 => "ecdsa-p256",
            Self::Ed25519 => "ed25519",
        }
    }

    /// The IANA algorithm number (RFC 8624 §3.1).
    pub fn number(self) -> u8 {
        match self {
            Self::EcdsaP256 => 13,
            Self::Ed25519 => 15,
        }
    }
}

impl std::str::FromStr for DnssecAlgorithm {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim() {
            "ecdsa-p256" | "ecdsap256sha256" | "13" => Ok(Self::EcdsaP256),
            "ed25519" | "15" => Ok(Self::Ed25519),
            _ => Err("must be ecdsa-p256 or ed25519".into()),
        }
    }
}

/// What a key does (RFC 6781 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyRole {
    /// Key signing key: signs the DNSKEY set; its DS goes to the parent
    /// (DNSKEY flags 257, SEP).
    Ksk,
    /// Zone signing key: signs everything else (flags 256).
    Zsk,
}

impl KeyRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ksk => "ksk",
            Self::Zsk => "zsk",
        }
    }
}

impl std::str::FromStr for KeyRole {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim() {
            "ksk" => Ok(Self::Ksk),
            "zsk" => Ok(Self::Zsk),
            _ => Err("must be ksk or zsk".into()),
        }
    }
}

/// Where a key is in its life (RFC 7583 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyState {
    /// In the DNSKEY set, not signing yet (a new ZSK waiting for the old
    /// DNSKEY set to leave the caches).
    Published,
    /// Signing.
    Active,
    /// In the DNSKEY set, no longer signing (until the signatures it made
    /// leave the caches), then removed.
    Retired,
}

impl KeyState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Active => "active",
            Self::Retired => "retired",
        }
    }
}

/// One key. The private part never leaves the engine and the daemon:
/// `print` and the GUI show the rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnssecKey {
    pub id: u32,
    pub zone: String,
    pub role: KeyRole,
    pub algorithm: DnssecAlgorithm,
    pub key_tag: u16,
    pub state: KeyState,
    /// PKCS#8, base64.
    pub private_key: String,
    /// The DNSKEY rdata as a zone file writes it (`257 3 13 …`).
    pub dnskey: String,
    /// KSK: the DS rdata with SHA-256 (RFC 4509), for the parent.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ds: String,
    pub created_unix: u64,
    /// When `state` last changed.
    pub changed_unix: u64,
}

/// A rollover the operator asked for, not started yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloverRequest {
    pub zone: String,
    pub role: KeyRole,
}

/// Everything kept in the `dnssec-keys` state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnssecState {
    pub keys: Vec<DnssecKey>,
    pub next_id: u32,
    /// The serial of each zone's last signed version: a re-signing bumps
    /// it even when the config's serial did not move (the secondaries must
    /// fetch the new signatures), and it never goes back across restarts.
    pub signed_serial: BTreeMap<String, u32>,
    pub rollovers: Vec<RolloverRequest>,
    /// Zones whose new KSK has its DS at the parent (`ds-published`).
    pub ds_published: Vec<String>,
}

impl DnssecState {
    pub fn next_id(&mut self) -> u32 {
        self.next_id = self.next_id.saturating_add(1);
        self.next_id
    }

    pub fn keys_of<'a>(&'a self, zone: &'a str) -> impl Iterator<Item = &'a DnssecKey> + 'a {
        self.keys.iter().filter(move |k| k.zone == zone)
    }

    /// Why this state cannot be loaded (a hostile or damaged file).
    pub fn problem(&self) -> Option<String> {
        if self.keys.len() > MAX_KEYS {
            return Some(format!("more than {MAX_KEYS} DNSSEC keys"));
        }
        let mut ids = std::collections::HashSet::new();
        for k in &self.keys {
            if !ids.insert(k.id) {
                return Some(format!("DNSSEC key {} twice", k.id));
            }
            if k.private_key.is_empty() || k.private_key.len() > 4096 || k.dnskey.len() > 4096 {
                return Some(format!("DNSSEC key {}: bad key material", k.id));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_numbers() {
        assert_eq!("ecdsa-p256".parse::<DnssecAlgorithm>().unwrap().number(), 13);
        assert_eq!("15".parse::<DnssecAlgorithm>().unwrap(), DnssecAlgorithm::Ed25519);
        assert!("rsasha1".parse::<DnssecAlgorithm>().is_err());
        assert_eq!("ksk".parse::<KeyRole>(), Ok(KeyRole::Ksk));
        let s = DnssecState::default();
        assert!(serde_json::to_string(&s).unwrap().len() < 120);
        assert_eq!(s.problem(), None);
    }
}
