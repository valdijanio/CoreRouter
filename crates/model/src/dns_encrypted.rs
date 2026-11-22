//! `/ip dns encrypted-service` (G4.1zf): the router as a DNS over TLS
//! (RFC 7858, TCP 853) and DNS over HTTPS (RFC 8484) server for the LAN, on
//! top of the forwarder of `allow_remote_requests` (same chain, cache and
//! `allowed_from`).
//!
//! RouterOS has no such server (only the `use-doh-server` client); the
//! names follow Unbound (`tls-port`, `tls-service-pem`) and RouterOS's
//! `certificate=` of `/ip service`.
//!
//! Who uses it without being told: Android's "Private DNS" in its default
//! automatic mode tries TCP 853 on the DNS server DHCP gave it and, when the
//! TLS handshake works, asks there (opportunistic: the certificate is not
//! checked). So turning it on moves the LAN's Android phones to it at once.

use serde::{Deserialize, Serialize};

pub const DEFAULT_DOT_PORT: u16 = 853;
/// RFC 9461 §4.2: the default port of DoH; DDR leaves `port` out on it.
pub const DEFAULT_DOH_PORT: u16 = 443;
/// RFC 8484 §3 leaves the path to the server; `/dns-query` is what every
/// client and server uses by convention (Unbound, AdGuard, dnsdist).
pub const DEFAULT_DOH_PATH: &str = "/dns-query";
pub const MAX_DOH_PATH: usize = 64;
/// Above Android's 20 s (`DnsTlsSocket::kIdleTimeout`), so its connection is
/// reused instead of a new handshake for each burst; Unbound and dnsdist
/// use 30 s.
pub const DEFAULT_IDLE_SECS: u32 = 30;
pub const IDLE_SECS: std::ops::RangeInclusive<u32> = 1..=3600;
/// A LAN of a thousand phones, each with one connection.
pub const DEFAULT_MAX_SESSIONS: u32 = 1000;
pub const MAX_SESSIONS: std::ops::RangeInclusive<u32> = 1..=100_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EncryptedService {
    /// DNS over TLS (RFC 7858). Needs `allow_remote_requests` (the same
    /// forwarder answers).
    pub dot: bool,
    /// RFC 7858 §3.1: 853 unless both sides agree otherwise; never 53.
    pub dot_port: u16,
    /// DNS over HTTPS (RFC 8484): HTTP/2, and HTTP/1.1 for clients that
    /// only speak it.
    pub doh: bool,
    /// Its own listener (www-ssl keeps its port): 443 by default (RFC 9461
    /// §4.2), so it cannot share 443 with an enabled www-ssl.
    pub doh_port: u16,
    /// The path of the URI template (`/dns-query{?dns}`).
    pub doh_path: String,
    /// The `/certificate` both serve with; empty until the first `dot=yes`
    /// or `doh=yes`, which makes `dns-server` (self-signed) when none is
    /// named.
    pub certificate: String,
    /// A connection with no query in flight is closed after this long.
    pub idle_timeout_secs: u32,
    /// TLS connections at once (all clients); a quarter per address.
    pub max_sessions: u32,
    /// Answer `_dns.resolver.arpa` SVCB (RFC 9462 DDR) so clients can find
    /// the encrypted service by themselves.
    pub announce_ddr: bool,
}

impl Default for EncryptedService {
    fn default() -> Self {
        Self {
            dot: false,
            dot_port: DEFAULT_DOT_PORT,
            doh: false,
            doh_port: DEFAULT_DOH_PORT,
            doh_path: DEFAULT_DOH_PATH.to_owned(),
            certificate: String::new(),
            idle_timeout_secs: DEFAULT_IDLE_SECS,
            max_sessions: DEFAULT_MAX_SESSIONS,
            announce_ddr: true,
        }
    }
}

impl EncryptedService {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Why this section cannot be committed, if anything is wrong.
    pub fn problem(&self) -> Option<String> {
        if self.dot_port == 0 || self.dot_port == 53 {
            return Some("dot_port: 1..65535 and never 53 (RFC 7858 §3.1)".into());
        }
        if !IDLE_SECS.contains(&self.idle_timeout_secs) {
            return Some(format!("idle_timeout_secs must be {IDLE_SECS:?}"));
        }
        if !MAX_SESSIONS.contains(&self.max_sessions) {
            return Some(format!("max_sessions must be {MAX_SESSIONS:?}"));
        }
        if self.doh_port == 0 || self.doh_port == 53 {
            return Some("doh_port: 1..65535 and not 53".into());
        }
        if (self.dot || self.doh) && self.dot_port == self.doh_port {
            return Some(format!("doh_port: DNS over TLS already uses {}", self.dot_port));
        }
        if let Some(why) = doh_path_problem(&self.doh_path) {
            return Some(format!("doh_path: {why}"));
        }
        if (self.dot || self.doh) && self.certificate.is_empty() {
            return Some("certificate: DNS over TLS and HTTPS need one".into());
        }
        None
    }

    /// Either server is on.
    pub fn any(&self) -> bool {
        self.dot || self.doh
    }
}

/// Why `p` cannot be the DoH path: it starts with `/`, has no query or
/// fragment, is short and plain ASCII (it goes into DDR's `dohpath`).
pub fn doh_path_problem(p: &str) -> Option<&'static str> {
    if !p.starts_with('/') {
        return Some("must start with /");
    }
    if p.len() > MAX_DOH_PATH {
        return Some("at most 64 characters");
    }
    if !p.bytes().all(|b| b.is_ascii_alphanumeric() || b"/-._~".contains(&b)) {
        return Some("letters, digits and / - . _ ~ only");
    }
    None
}

/// What the DNS over TLS listener is doing (operational, filled by the
/// daemon, kept in the session with `ext_mut`, never saved).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EncryptedStatus {
    /// `stopped`, `listening` or `error`.
    pub status: String,
    /// The socket addresses listened on.
    pub listening: Vec<String>,
    pub last_error: Option<String>,
    /// The certificate served (its SHA-256 fingerprint).
    pub fingerprint: Option<String>,
    /// TLS connections open now.
    pub sessions: u64,
    /// Since the listener opened:
    pub accepted: u64,
    pub handshakes: u64,
    /// Resumed with a session ticket (RFC 8446 §2.2; RFC 8310 §9).
    pub resumed: u64,
    /// Handshakes that failed (not TLS, an alert, too slow).
    pub handshake_failures: u64,
    /// Queries answered over TLS (DoT).
    pub queries: u64,
    /// Queries answered over HTTPS (DoH), and the requests refused (bad
    /// path, method or media type).
    pub doh_queries: u64,
    pub doh_errors: u64,
    /// DoH connections that negotiated HTTP/2 (the rest, HTTP/1.1).
    pub http2: u64,
    /// Connections closed at accept: not in `allowed_from`.
    pub refused: u64,
    /// Connections closed at accept or evicted: over `max_sessions`.
    pub over_limit: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_bounds() {
        let e = EncryptedService::default();
        assert!(e.is_default() && e.problem().is_none());
        assert_eq!((e.dot_port, e.idle_timeout_secs), (853, 30));
        let bad = EncryptedService { dot_port: 53, ..EncryptedService::default() };
        assert!(bad.problem().unwrap().contains("never 53"));
        let bad = EncryptedService { dot: true, ..EncryptedService::default() };
        assert!(bad.problem().unwrap().contains("certificate"));
        let bad = EncryptedService { doh_path: "dns-query".into(), ..EncryptedService::default() };
        assert!(bad.problem().unwrap().contains("start with /"));
        let bad = EncryptedService { doh: true, doh_port: 853, certificate: "x".into(), ..EncryptedService::default() };
        assert!(bad.problem().unwrap().contains("already uses 853"));
        assert_eq!(doh_path_problem("/dns-query?x"), Some("letters, digits and / - . _ ~ only"));
        let old: EncryptedService = serde_json::from_str("{}").unwrap();
        assert!(old.is_default());
    }
}
