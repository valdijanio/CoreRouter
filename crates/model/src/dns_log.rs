//! `/ip dns log` (G4.1zd): the LAN forwarder's query log, kept on the
//! router's disk. RouterOS has none (only the `dns` topic of
//! `/system logging`); the knobs follow Pi-hole (`maxDBdays`, privacy
//! levels), AdGuard Home (`anonymize_client_ip`) and Unbound
//! (`log-queries`), plus a ceiling in bytes, which none of them has and
//! which is what bounds an ISP's log (20 000 queries/s write ~21 GB a day).
//!
//! Off by default: a log of who asked what and when is, at a connection
//! provider, the kind of application access record Marco Civil (Lei
//! 12.965/2014) art. 14 forbids keeping, and personal data under the LGPD.
//! Turning it on takes an explicit acknowledgement (`ip.dns.log.set`), and
//! the client address is truncated by default (`docs/dns-query-log.md`).

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// What `ip.dns.log.set` must be given to turn the log on.
pub const ACKNOWLEDGE: &str = "marco-civil-art14";
/// Entries of `exclude`, `only_from` and `except_from`, each.
pub const MAX_LIST: usize = 64;
/// Longest `exclude` name.
pub const MAX_NAME: usize = 253;
/// `max_size_mib` at most: 1 TiB.
pub const MAX_SIZE_MIB: u32 = 1 << 20;
/// `max_age_hours` at most: a year.
pub const MAX_AGE_HOURS: u32 = 8760;

/// How a client's address is written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientAddress {
    /// The whole address.
    Full,
    /// Its network: `ipv4_prefix` / `ipv6_prefix` bits kept, the rest
    /// zero (RFC 6235 §4.1.1, truncation).
    #[default]
    Truncated,
    /// A keyed hash (SipHash-1-3, 64 bits) whose key lives only in memory
    /// and changes every `salt_rotation_hours`: the same client is one
    /// value inside a period and unrelated across periods (RFC 6235 §4.1.4).
    Hashed,
    /// No client at all.
    None,
}

impl ClientAddress {
    pub const ALL: [&'static str; 4] = ["full", "truncated", "hashed", "none"];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Truncated => "truncated",
            Self::Hashed => "hashed",
            Self::None => "none",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "full" => Ok(Self::Full),
            "truncated" => Ok(Self::Truncated),
            "hashed" => Ok(Self::Hashed),
            "none" => Ok(Self::None),
            _ => Err("must be full, truncated, hashed or none".into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsLog {
    /// Write the queries the LAN forwarder answers (and drops) to disk.
    pub enabled: bool,
    pub client_address: ClientAddress,
    /// Bits of an IPv4 client kept by `truncated` (AdGuard Home keeps 16).
    pub ipv4_prefix: u8,
    /// Bits of an IPv6 client kept by `truncated` (56: the subscriber's
    /// delegated prefix, not the device; AdGuard Home keeps 48).
    pub ipv6_prefix: u8,
    /// `hashed`: hours one key is used for.
    pub salt_rotation_hours: u32,
    /// The log takes at most this much disk (also capped by its share of
    /// `/config`): the oldest hour goes first.
    pub max_size_mib: u32,
    /// Hours a query is kept (also when the log is off: turning it off
    /// does not keep what it wrote forever).
    pub max_age_hours: u32,
    /// Names never logged, with everything under them (`example.com`
    /// also drops `www.example.com`).
    pub exclude: Vec<String>,
    /// Only clients inside these networks are logged (empty: all).
    pub only_from: Vec<IpNet>,
    /// Clients inside these networks are never logged.
    pub except_from: Vec<IpNet>,
}

impl Default for DnsLog {
    fn default() -> Self {
        Self {
            enabled: false,
            client_address: ClientAddress::Truncated,
            ipv4_prefix: 24,
            ipv6_prefix: 56,
            salt_rotation_hours: 24,
            max_size_mib: 1024,
            max_age_hours: 24,
            exclude: Vec::new(),
            only_from: Vec::new(),
            except_from: Vec::new(),
        }
    }
}

impl DnsLog {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Why this section cannot be committed, if anything is wrong (a
    /// hand-edited config reaches here without the command's checks).
    pub fn problem(&self) -> Option<String> {
        if !(8..=32).contains(&self.ipv4_prefix) {
            return Some("ipv4_prefix must be 8..32".into());
        }
        if !(16..=128).contains(&self.ipv6_prefix) {
            return Some("ipv6_prefix must be 16..128".into());
        }
        if !(1..=MAX_AGE_HOURS).contains(&self.salt_rotation_hours) {
            return Some(format!("salt_rotation_hours must be 1..{MAX_AGE_HOURS}"));
        }
        if !(1..=MAX_SIZE_MIB).contains(&self.max_size_mib) {
            return Some(format!("max_size_mib must be 1..{MAX_SIZE_MIB}"));
        }
        if !(1..=MAX_AGE_HOURS).contains(&self.max_age_hours) {
            return Some(format!("max_age_hours must be 1..{MAX_AGE_HOURS}"));
        }
        for (key, n) in [
            ("exclude", self.exclude.len()),
            ("only_from", self.only_from.len()),
            ("except_from", self.except_from.len()),
        ] {
            if n > MAX_LIST {
                return Some(format!("{key}: at most {MAX_LIST} entries"));
            }
        }
        if let Some(bad) = self.exclude.iter().find(|n| exclude_problem(n).is_some()) {
            let why = exclude_problem(bad).unwrap_or_default();
            return Some(format!("exclude: {why}"));
        }
        None
    }

    /// Whether `name` (lowercase, no trailing dot) is excluded.
    pub fn excludes(&self, name: &str) -> bool {
        self.exclude.iter().any(|e| is_under(name, e))
    }
}

/// `name` is `parent` or a name under it (both lowercase, no trailing dot).
pub fn is_under(name: &str, parent: &str) -> bool {
    match name.strip_suffix(parent) {
        Some("") => true,
        Some(rest) => rest.ends_with('.'),
        None => false,
    }
}

/// Why `name` cannot be an `exclude` entry (lowercase, no trailing dot).
pub fn exclude_problem(name: &str) -> Option<String> {
    if name.is_empty() || name.len() > MAX_NAME {
        return Some(format!("a name of 1..{MAX_NAME} characters"));
    }
    let ok = name.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    });
    if ok {
        None
    } else {
        let shown: String = name.chars().take(64).collect();
        Some(format!("'{shown}' is not a DNS name (lowercase labels, no trailing dot)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_by_default_and_truncated() {
        let d = DnsLog::default();
        assert!(!d.enabled);
        assert_eq!(d.client_address, ClientAddress::Truncated);
        assert_eq!((d.ipv4_prefix, d.ipv6_prefix), (24, 56));
        assert!(d.problem().is_none());
    }

    #[test]
    fn excludes_names_under() {
        let d = DnsLog {
            exclude: vec!["example.com".into(), "arpa".into()],
            ..DnsLog::default()
        };
        assert!(d.excludes("example.com"));
        assert!(d.excludes("www.example.com"));
        assert!(d.excludes("1.0.0.127.in-addr.arpa"));
        assert!(!d.excludes("badexample.com"));
        assert!(!d.excludes("example.org"));
    }

    #[test]
    fn problems() {
        let bad = |f: fn(&mut DnsLog)| {
            let mut d = DnsLog::default();
            f(&mut d);
            d.problem()
        };
        assert!(bad(|d| d.ipv4_prefix = 7).is_some());
        assert!(bad(|d| d.ipv6_prefix = 129).is_some());
        assert!(bad(|d| d.max_size_mib = 0).is_some());
        assert!(bad(|d| d.max_age_hours = 0).is_some());
        assert!(bad(|d| d.exclude = vec!["Example.com".into()]).is_some());
        assert!(bad(|d| d.exclude = vec!["a..b".into()]).is_some());
        assert!(bad(|d| d.exclude = vec!["x".into(); MAX_LIST + 1]).is_some());
    }

    #[test]
    fn old_configs_load_without_the_section() {
        let d: DnsLog = serde_json::from_str("{}").unwrap();
        assert_eq!(d, DnsLog::default());
        let d: DnsLog = serde_json::from_str(r#"{"enabled":true,"client_address":"hashed"}"#).unwrap();
        assert!(d.enabled);
        assert_eq!(d.client_address, ClientAddress::Hashed);
    }
}
