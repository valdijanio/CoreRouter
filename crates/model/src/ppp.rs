//! `/ppp` (G4.3): what PPP (PPPoE, G4.3d) shares across its servers. For
//! now `/ppp aaa` (G4.3j): whether PPP asks RADIUS and how it accounts.

use serde::{Deserialize, Serialize};

/// Spread of the interim updates, % of the interval (RFC 5080 §2.2.1 asks
/// for jitter against synchronized clients).
pub const DEFAULT_INTERIM_JITTER: u8 = 20;
/// Longest `interim_update` accepted, seconds (one day).
pub const MAX_INTERIM: u32 = 86_400;

fn yes() -> bool {
    true
}

fn jitter() -> u8 {
    DEFAULT_INTERIM_JITTER
}

/// RouterOS `/ppp aaa`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PppAaa {
    /// Ask `/radius` (service=ppp) for users not in `/ppp secret`.
    pub use_radius: bool,
    /// Send Accounting-Request Start/Interim/Stop.
    #[serde(default = "yes")]
    pub accounting: bool,
    /// Seconds between Interim-Updates; 0 = only when the Access-Accept
    /// carries Acct-Interim-Interval. At least 60 (RFC 2869 §5.16).
    pub interim_update: u32,
    /// Spread of the interims, % of the interval (not in RouterOS).
    #[serde(default = "jitter")]
    pub interim_jitter: u8,
    /// NAS-Port-Id carries the DHCP/PPPoE circuit id (RFC 4679
    /// Agent-Circuit-Id) instead of the interface name.
    pub use_circuit_id_in_nas_port_id: bool,
    /// Count IPv4 and IPv6 separately (MikroTik attributes).
    pub enable_ipv6_accounting: bool,
}

impl Default for PppAaa {
    fn default() -> Self {
        Self {
            use_radius: false,
            accounting: true,
            interim_update: 0,
            interim_jitter: DEFAULT_INTERIM_JITTER,
            use_circuit_id_in_nas_port_id: false,
            enable_ipv6_accounting: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ppp {
    #[serde(skip_serializing_if = "PppAaa::is_default")]
    pub aaa: PppAaa,
}

impl PppAaa {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

impl Ppp {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}
