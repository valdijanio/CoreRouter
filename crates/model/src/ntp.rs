//! `/system ntp client` (G4.6): which time servers the router asks, and
//! what the last answer said (operational state, never saved).
//!
//! The client is SNTP (RFC 5905 §14, formerly RFC 4330): it measures the
//! offset to the best server it hears. Poll intervals are powers of two, in
//! seconds, like RouterOS `min-poll`/`max-poll`.

use serde::{Deserialize, Serialize};

/// At most this many servers (RouterOS has no fixed limit; 8 is plenty and
/// bounds one poll round).
pub const MAX_SERVERS: usize = 8;
/// Accepted `min_poll`/`max_poll` exponents. RouterOS accepts 3..17, but
/// RFC 4330 §5 says requests must never go out more often than once a
/// minute: 2^6 = 64 s is the first exponent that honors it.
pub const POLL_RANGE: std::ops::RangeInclusive<u8> = 6..=17;
pub const DEFAULT_MIN_POLL: u8 = 6;
pub const DEFAULT_MAX_POLL: u8 = 10;
/// Longest server name (a DNS name is at most 253 characters).
pub const MAX_SERVER_LEN: usize = 253;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NtpClient {
    /// RouterOS default: off.
    pub enabled: bool,
    /// IP addresses or DNS names, asked in every poll round.
    pub servers: Vec<String>,
    pub min_poll: u8,
    pub max_poll: u8,
}

impl Default for NtpClient {
    fn default() -> Self {
        Self {
            enabled: false,
            servers: Vec::new(),
            min_poll: DEFAULT_MIN_POLL,
            max_poll: DEFAULT_MAX_POLL,
        }
    }
}

impl NtpClient {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// Checks a server entry: an IP address or a DNS name (letters, digits,
/// `-` and `.`, labels of 1..=63 characters).
pub fn valid_server(s: &str) -> Result<(), String> {
    if s.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    if s.is_empty() || s.len() > MAX_SERVER_LEN {
        return Err(format!(
            "expected an IP address or a DNS name of 1..={MAX_SERVER_LEN} characters"
        ));
    }
    let name = s.strip_suffix('.').unwrap_or(s);
    for label in name.split('.') {
        let ok = (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            return Err(format!("'{label}' is not a valid DNS label"));
        }
    }
    Ok(())
}

/// RouterOS `status` of the NTP client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NtpState {
    /// Disabled, or no daemon runs the client (headless lab, tests).
    #[default]
    Stopped,
    /// Enabled, no good answer yet (or the last round got none).
    Waiting,
    /// The last round got a good answer.
    Synchronized,
}

/// What the client learned (operational, filled by the daemon).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct NtpStatus {
    pub status: NtpState,
    /// Server of the sample in use, as configured, and its address.
    pub synced_server: Option<String>,
    pub synced_address: Option<String>,
    pub synced_stratum: Option<u8>,
    /// Server clock minus ours, in milliseconds (positive: ours is behind).
    pub system_offset_ms: Option<f64>,
    pub round_trip_ms: Option<f64>,
    /// Unix time of the last good answer.
    pub last_sync: Option<u64>,
    /// Why the last round failed, one line per server that failed.
    pub last_error: Option<String>,
    /// Seconds until the next round.
    pub poll_secs: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn servers_are_ips_or_dns_names() {
        assert!(valid_server("192.0.2.1").is_ok());
        assert!(valid_server("2001:db8::1").is_ok());
        assert!(valid_server("pool.ntp.org").is_ok());
        assert!(valid_server("a.b-c.example.").is_ok());
        assert!(valid_server("").is_err());
        assert!(valid_server("bad name").is_err());
        assert!(valid_server("-x.org").is_err());
        assert!(valid_server("a..b").is_err());
        assert!(valid_server(&"a".repeat(300)).is_err());
    }

    #[test]
    fn defaults_follow_routeros_and_rfc() {
        let c = NtpClient::default();
        assert!(!c.enabled);
        assert_eq!((c.min_poll, c.max_poll), (6, 10));
        assert!(POLL_RANGE.contains(&c.min_poll));
        let back: NtpClient = serde_json::from_str("{}").unwrap();
        assert_eq!(back, c);
    }
}
