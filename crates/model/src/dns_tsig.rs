//! `/ip dns tsig-key` (G4.1c-3): shared secrets that sign DNS messages
//! (TSIG, RFC 8945). A zone lists the keys allowed to change it by RFC 2136
//! UPDATE (`update_keys`): a DHCP server (Kea's dhcp-ddns, ISC dhcpd) then
//! adds and removes the records of its leases.
//!
//! The secret is config, like a WireGuard key in RouterOS: `print` and
//! `/export` never show it in clear.

use serde::{Deserialize, Serialize};

use crate::dns_static::host_name_ok;
use crate::types::ItemId;

pub const MAX_KEYS: usize = 64;
/// RFC 8945 §6: a key at least half as long as the hash; 16 bytes is the
/// floor here (HMAC-SHA256 wants 32, `tsig-keygen` makes 32).
pub const MIN_SECRET_BYTES: usize = 16;
pub const MAX_SECRET_BYTES: usize = 256;

/// RFC 8945 §6: HMAC-SHA256 is MUST; SHA-1 and MD5 are left out.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TsigAlgorithm {
    #[default]
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl TsigAlgorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HmacSha256 => "hmac-sha256",
            Self::HmacSha384 => "hmac-sha384",
            Self::HmacSha512 => "hmac-sha512",
        }
    }
}

impl std::str::FromStr for TsigAlgorithm {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().trim_end_matches('.') {
            "hmac-sha256" => Ok(Self::HmacSha256),
            "hmac-sha384" => Ok(Self::HmacSha384),
            "hmac-sha512" => Ok(Self::HmacSha512),
            _ => Err("must be hmac-sha256, hmac-sha384 or hmac-sha512".into()),
        }
    }
}

/// RFC 4648 §4 base64 (padding optional), without a dependency: the
/// secret's bytes, or `None` for anything else.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let t = text.trim().trim_end_matches('=');
    let mut out = Vec::with_capacity(t.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in t.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// RFC 4648 §4 base64 with padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                let idx = usize::try_from((n >> (18 - 6 * i)) & 63).unwrap_or(0);
                out.push(char::from(*A.get(idx).unwrap_or(&b'A')));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TsigKey {
    pub id: ItemId,
    /// The key name both sides use (`dhcp-ddns`), lowercase.
    pub name: String,
    #[serde(default)]
    pub algorithm: TsigAlgorithm,
    /// Base64, as `tsig-keygen` and Kea write it.
    pub secret: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl TsigKey {
    pub fn problem(&self) -> Option<String> {
        if !host_name_ok(&self.name) {
            let shown: String = self.name.chars().take(64).collect();
            return Some(format!("name: '{shown}' is not a DNS name"));
        }
        match base64_decode(&self.secret) {
            Some(b) if (MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&b.len()) => None,
            Some(_) => Some(format!(
                "secret: {MIN_SECRET_BYTES}..={MAX_SECRET_BYTES} bytes (RFC 8945 §6)"
            )),
            None => Some("secret: not base64".into()),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsTsig {
    pub keys: Vec<TsigKey>,
    pub next_id: u32,
}

impl DnsTsig {
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.next_id == 0
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    pub fn get(&self, name: &str) -> Option<&TsigKey> {
        self.keys.iter().find(|k| k.name == name)
    }

    pub fn problem(&self) -> Option<String> {
        if self.keys.len() > MAX_KEYS {
            return Some(format!("at most {MAX_KEYS} TSIG keys"));
        }
        let mut names = std::collections::HashSet::new();
        for k in &self.keys {
            if let Some(p) = k.problem() {
                return Some(format!("TSIG key {}: {p}", k.name));
            }
            if !names.insert(k.name.as_str()) {
                return Some(format!("TSIG key {} defined twice", k.name));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        // RFC 4648 §10.
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_decode("Zm9vYmE=").unwrap(), b"fooba");
        assert_eq!(base64_decode("Zm9vYmE").unwrap(), b"fooba");
        assert!(base64_decode("Zm9!").is_none());
    }

    #[test]
    fn keys_are_checked() {
        let mut k = TsigKey {
            id: ItemId(1),
            name: "dhcp-ddns".into(),
            algorithm: TsigAlgorithm::HmacSha256,
            secret: base64_encode(&[7u8; 32]),
            comment: String::new(),
        };
        assert_eq!(k.problem(), None);
        k.secret = base64_encode(&[7u8; 8]);
        assert!(k.problem().unwrap().contains("bytes"));
        k.secret = "not base64!".into();
        assert!(k.problem().is_some());
        assert_eq!("HMAC-SHA256.".parse::<TsigAlgorithm>(), Ok(TsigAlgorithm::HmacSha256));
        assert!("hmac-md5".parse::<TsigAlgorithm>().is_err());
    }
}
