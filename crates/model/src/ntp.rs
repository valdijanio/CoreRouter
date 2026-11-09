//! `/system ntp client` (G4.6): which time servers the router asks, and
//! what the last answer said (operational state, never saved).
//!
//! The client is SNTP (RFC 5905 §14, formerly RFC 4330): it measures the
//! offset to the best server it hears and, on a real machine, disciplines
//! the system clock (G4.6b, docs/ntp.md). `/system ntp server` (G4.6c) answers
//! the LAN's clients. Poll intervals are powers of two, in
//! seconds, like RouterOS `min-poll`/`max-poll`.

use std::net::IpAddr;

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
    /// VRF the servers are reached through (RouterOS `vrf`; `main` is the
    /// main table).
    #[serde(skip_serializing_if = "is_main")]
    pub vrf: String,
    /// Apply what is measured to the system clock (G4.6b). Off only measures:
    /// for a general-purpose host where chrony or timesyncd owns the clock.
    /// RouterOS has no such switch: its client always sets the clock.
    #[serde(skip_serializing_if = "is_true")]
    pub set_system_clock: bool,
}

pub const MAIN_VRF: &str = "main";

fn is_main(v: &str) -> bool {
    v == MAIN_VRF
}

fn is_true(v: &bool) -> bool {
    *v
}

impl Default for NtpClient {
    fn default() -> Self {
        Self {
            enabled: false,
            servers: Vec::new(),
            min_poll: DEFAULT_MIN_POLL,
            max_poll: DEFAULT_MAX_POLL,
            vrf: MAIN_VRF.to_owned(),
            set_system_clock: true,
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
    /// No good answer, and `/system ntp server` serves this router's own
    /// clock in the meantime (`use_local_clock`, RouterOS's name).
    UsingLocalClock,
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
    /// Servers learned from DHCP clients with `use_peer_ntp` (RouterOS
    /// `dynamic-servers`).
    pub dynamic_servers: Vec<String>,
    /// What the client is doing to the system clock.
    pub clock: ClockState,
    /// The last correction: size of the slew or step, in milliseconds
    /// (RouterOS `last-adjustment`).
    pub last_adjustment_ms: Option<f64>,
    /// The drift learned (RouterOS `freq-drift`), in ppm.
    pub freq_drift_ppm: Option<f64>,
    /// A step above the panic threshold waiting for
    /// `system.ntp.client.confirm-step`, in milliseconds.
    pub pending_step_ms: Option<f64>,
    /// Why the clock could not be changed.
    pub clock_error: Option<String>,
    /// From the answer in use, for the server's own header (G4.6c).
    pub root_delay_ms: Option<f64>,
    pub root_dispersion_ms: Option<f64>,
    /// Leap indicator of the answer in use (RFC 5905 §7.3).
    pub leap: Option<u8>,
}

/// What the client does to the clock. RFC 5905 §11.3 names in parentheses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClockState {
    /// Measuring only: switched off, or this backend or process cannot.
    #[default]
    NotSet,
    /// Within reach: the frequency corrects it (SYNC).
    Slewing,
    /// The last answer moved the clock at once.
    Stepped,
    /// A big offset in a clock in sync, held for 900 s (SPIK).
    HoldingSpike,
    /// Above 1000 s (PANICT): waits for the operator.
    AwaitingConfirmation,
    /// The answer would put the clock before 2026: never applied.
    Refused,
}

/// Most networks in `allowed`: read per packet, by the server's readers.
pub const MAX_ALLOWED: usize = 64;
/// Most `broadcast_addresses`.
pub const MAX_BROADCAST: usize = 16;
/// RFC 5905 Figure 11: 1 is a reference clock, 2..=15 are servers, 16 none.
pub const LOCAL_STRATUM_RANGE: std::ops::RangeInclusive<u8> = 1..=15;
/// RouterOS's default `local-clock-stratum`.
pub const DEFAULT_LOCAL_STRATUM: u8 = 5;

/// VyOS's default `allow-client`, RFC 8633 §5.1: loopback, link-local and
/// private networks. A public address gets silence until the operator says
/// otherwise, so a WAN address never answers by accident.
pub fn default_allowed() -> Vec<String> {
    [
        "127.0.0.0/8",
        "169.254.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fe80::/10",
        "fc00::/7",
    ]
    .map(str::to_owned)
    .to_vec()
}

/// `/system ntp server` (G4.6c).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NtpServer {
    /// RouterOS default: off.
    pub enabled: bool,
    /// Send time to `broadcast_addresses` (mode 5). RFC 8633 §5.5: only on a
    /// trusted network; nothing authenticates it.
    pub broadcast: bool,
    pub broadcast_addresses: Vec<IpAddr>,
    /// Serve this router's own clock when it has no better source.
    pub use_local_clock: bool,
    /// The stratum announced for that clock.
    pub local_clock_stratum: u8,
    /// Who may ask: prefixes, ranges and names of firewall address lists
    /// (`crate::source_set`). VyOS's `allow-client`, with RouterOS's lists;
    /// RouterOS's NTP server has no such thing.
    pub allowed: Vec<String>,
    /// Per-source limit with Kiss-o'-Death RATE (RFC 5905 §7.4). Off only
    /// for many clients behind one address.
    pub rate_limit: bool,
    pub vrf: String,
}

impl Default for NtpServer {
    fn default() -> Self {
        Self {
            enabled: false,
            broadcast: false,
            broadcast_addresses: Vec::new(),
            use_local_clock: false,
            local_clock_stratum: DEFAULT_LOCAL_STRATUM,
            allowed: default_allowed(),
            rate_limit: true,
            vrf: MAIN_VRF.to_owned(),
        }
    }
}

impl NtpServer {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// Whose time the server gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NtpServing {
    /// Nobody's: silent until the client synchronizes.
    #[default]
    No,
    /// What the client synchronized to.
    Upstream,
    /// This router's own clock (`use_local_clock`).
    LocalClock,
}

/// The server's counters and state (operational, filled by the daemon).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NtpServerStats {
    pub listening: bool,
    pub serving: NtpServing,
    pub stratum: Option<u8>,
    /// Well-formed requests from allowed sources.
    pub requests: u64,
    pub replies: u64,
    /// RATE kisses sent.
    pub kisses: u64,
    /// Not in `allowed`: dropped in silence.
    pub denied: u64,
    /// Over the rate, kiss already sent: dropped in silence.
    pub limited: u64,
    /// Not a request (modes 6 and 7 included), or a bad source.
    pub malformed: u64,
    /// Asked while the clock was not good: dropped in silence.
    pub unsynchronized: u64,
    pub last_error: Option<String>,
    /// Address lists in `allowed` with nothing in them (or that do not
    /// exist): they let nobody in.
    pub empty_lists: Vec<String>,
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
    fn server_defaults_are_safe() {
        let c = NtpServer::default();
        assert!(!c.enabled && !c.broadcast && !c.use_local_clock);
        assert_eq!(c.local_clock_stratum, 5);
        assert!(c.rate_limit);
        let set = crate::source_set::SourceSet::new(
            c.allowed.iter().map(|n| n.parse::<crate::firewall::AddrMatch>().unwrap()),
        );
        let has = |ip: &str| set.contains(ip.parse().unwrap());
        for private in ["127.0.0.1", "10.1.2.3", "172.31.0.1", "192.168.88.2", "169.254.1.1", "::1", "fe80::1", "fd00::1"] {
            assert!(has(private), "{private}");
        }
        for public in ["8.8.8.8", "100.64.0.1", "172.32.0.1", "2001:db8::1"] {
            assert!(!has(public), "{public}");
        }
        let back: NtpServer = serde_json::from_str("{}").unwrap();
        assert_eq!(back, c);
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
