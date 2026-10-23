//! `/tool bandwidth-server` (G6.4b): the router answering bandwidth tests
//! with the iperf3 protocol, so any `iperf3 -c` (or another CoreRouter's
//! Tools › Bandwidth Test) can measure the path to it.
//!
//! Off by default, and only for the prefixes in `allowed_addresses`: a
//! test fills links, so who may start one is the operator's choice. Each
//! test is bounded in time, streams and (optionally) rate.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// iperf3's port.
pub const DEFAULT_PORT: u16 = 5201;
pub const DEFAULT_MAX_DURATION: u32 = 60;
pub const MAX_DURATION: u32 = 3600;
pub const DEFAULT_MAX_STREAMS: u32 = 8;
pub const MAX_STREAMS: u32 = 128;
/// Prefixes in the allow list.
pub const MAX_ALLOWED: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BandwidthServer {
    pub enabled: bool,
    pub port: u16,
    /// Who may run a test; an enabled server needs at least one prefix
    /// (`0.0.0.0/0` and `::/0` for anyone).
    pub allowed_addresses: Vec<IpNet>,
    /// Longest test accepted, seconds (time + omit).
    pub max_duration: u32,
    pub max_streams: u32,
    /// Total rate one test may ask for, bit/s; 0 = no cap (an uncapped TCP
    /// test is refused when there is one).
    pub max_rate: u64,
}

impl Default for BandwidthServer {
    fn default() -> Self {
        Self {
            enabled: false,
            port: DEFAULT_PORT,
            allowed_addresses: Vec::new(),
            max_duration: DEFAULT_MAX_DURATION,
            max_streams: DEFAULT_MAX_STREAMS,
            max_rate: 0,
        }
    }
}

impl BandwidthServer {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Whether `ip` may run a test (IPv4-mapped IPv6 counts as IPv4).
    pub fn allows(&self, ip: std::net::IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.allowed_addresses.iter().any(|n| n.contains(&ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_and_mapped_addresses() {
        let s = BandwidthServer {
            allowed_addresses: vec!["100.64.0.0/10".parse().unwrap()],
            ..BandwidthServer::default()
        };
        assert!(s.allows("100.64.1.2".parse().unwrap()));
        assert!(s.allows("::ffff:100.64.1.2".parse().unwrap()));
        assert!(!s.allows("8.8.8.8".parse().unwrap()));
        assert!(!BandwidthServer::default().allows("127.0.0.1".parse().unwrap()));
        assert!(BandwidthServer::default().is_default());
    }
}
