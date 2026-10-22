//! The Prometheus `/metrics` endpoint as a service of the config (G4.4c),
//! in the spirit of RouterOS `/ip service`: on or off, the address and port
//! it listens on, and the networks allowed to scrape it (`available-from`,
//! RouterOS `address`). The daemon applies a change without restarting.
//!
//! The `--metrics` command-line flag of the daemon still opens a listener of
//! its own, outside the config (for a lab or a first boot).

use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// node_exporter's port (and VyOS `service monitoring prometheus
/// node-exporter`): a Prometheus job written for one finds us.
pub const DEFAULT_PORT: u16 = 9100;
/// Most `available_from` entries (RouterOS has no fixed limit; a scrape
/// checks every entry).
pub const MAX_AVAILABLE_FROM: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsService {
    /// Off by default, like node_exporter is absent until installed.
    pub enabled: bool,
    /// Address the listener binds to; `0.0.0.0`/`::` is every address.
    /// Loopback by default: the endpoint has no login.
    pub address: IpAddr,
    pub port: u16,
    /// Networks allowed to connect; empty is everyone who reaches the port
    /// (RouterOS `address` of `/ip service`). Others are disconnected
    /// without an answer.
    pub available_from: Vec<IpNet>,
}

impl Default for MetricsService {
    fn default() -> Self {
        Self {
            enabled: false,
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: DEFAULT_PORT,
            available_from: Vec::new(),
        }
    }
}

impl MetricsService {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Whether a client at `peer` may scrape. An IPv4 client of a `::`
    /// listener arrives as `::ffff:a.b.c.d` and is matched as IPv4.
    pub fn allows(&self, peer: IpAddr) -> bool {
        let peer = peer.to_canonical();
        self.available_from.is_empty() || self.available_from.iter().any(|n| n.contains(&peer))
    }
}

/// `status` of the metrics service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MetricsState {
    /// Disabled, or no daemon runs the service (headless lab, tests).
    #[default]
    Stopped,
    Listening,
    /// Enabled but the port could not be opened (`last_error` says why).
    Error,
}

/// What the service is doing (operational, filled by the daemon, never
/// saved; kept in the session with `ext_mut`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MetricsStatus {
    pub status: MetricsState,
    /// The socket address actually listened on.
    pub listening: Option<String>,
    pub last_error: Option<String>,
    /// Requests answered since the listener opened.
    pub requests: u64,
    /// Connections dropped because the client is not in `available_from`.
    pub refused: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_from_matches_prefixes_and_mapped_v4() {
        let mut m = MetricsService::default();
        assert!(m.allows("203.0.113.9".parse().unwrap()), "empty list: anyone");
        m.available_from = vec!["192.0.2.0/24".parse().unwrap(), "2001:db8::/32".parse().unwrap()];
        assert!(m.allows("192.0.2.10".parse().unwrap()));
        assert!(m.allows("::ffff:192.0.2.10".parse().unwrap()));
        assert!(m.allows("2001:db8::1".parse().unwrap()));
        assert!(!m.allows("198.51.100.1".parse().unwrap()));
        assert!(!m.allows("::ffff:198.51.100.1".parse().unwrap()));
    }

    #[test]
    fn default_is_loopback_9100_and_off() {
        let m = MetricsService::default();
        assert!(!m.enabled && m.address.is_loopback() && m.port == 9100);
        let back: MetricsService = serde_json::from_str("{}").unwrap();
        assert!(back.is_default());
    }
}
