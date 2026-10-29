//! Web access to the router (G1.6o), RouterOS `/ip service` `www-ssl` and
//! `www`: the GUI in a browser (`https://<router>/`, the WebFig model) and
//! the control channel over WebSocket on the same port.
//!
//! - `www_ssl`: HTTPS + WSS with the router's own certificate (the one of
//!   the TLS control port). Off in this default; the router image turns it
//!   on for a config made at first boot (the daemon's `--web-factory-on`),
//!   so a router that is updated keeps what it had.
//! - `www`: plain HTTP, only a redirect to `www_ssl` (logins never travel
//!   in clear text, unlike RouterOS `www`). Off by default.
//!
//! The daemon follows the running config: a commit opens, moves or closes
//! a listener without a restart.

use std::net::{IpAddr, Ipv6Addr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Most `available_from` entries (as `/ip service metrics`).
pub const MAX_AVAILABLE_FROM: usize = 64;
pub const DEFAULT_HTTPS_PORT: u16 = 443;
pub const DEFAULT_HTTP_PORT: u16 = 80;

/// One listener; the port has no default of its own (it depends on the row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebListener {
    #[serde(default)]
    pub enabled: bool,
    /// Address the listener binds to; `::` (the default) is every IPv6 and
    /// IPv4 address.
    #[serde(default = "any_address")]
    pub address: IpAddr,
    pub port: u16,
    /// Networks allowed to connect (RouterOS `address`); empty is everyone
    /// who reaches the port. Others are disconnected without an answer.
    #[serde(default)]
    pub available_from: Vec<IpNet>,
}

fn any_address() -> IpAddr {
    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
}

impl WebListener {
    fn off(port: u16) -> Self {
        Self {
            enabled: false,
            address: any_address(),
            port,
            available_from: Vec::new(),
        }
    }

    /// Whether a client at `peer` may connect. An IPv4 client of a `::`
    /// listener arrives as `::ffff:a.b.c.d` and is matched as IPv4.
    pub fn allows(&self, peer: IpAddr) -> bool {
        let peer = peer.to_canonical();
        self.available_from.is_empty() || self.available_from.iter().any(|n| n.contains(&peer))
    }
}

/// `www-ssl` and `www` of `/ip service`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebService {
    pub www_ssl: WebListener,
    pub www: WebListener,
}

impl Default for WebService {
    fn default() -> Self {
        Self {
            www_ssl: WebListener::off(DEFAULT_HTTPS_PORT),
            www: WebListener::off(DEFAULT_HTTP_PORT),
        }
    }
}

impl WebService {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// What the router image ships with: HTTPS on 443 on every address.
    pub fn factory() -> Self {
        let mut w = Self::default();
        w.www_ssl.enabled = true;
        w
    }
}

/// `status` of one web listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WebState {
    /// Disabled, or no daemon runs the service (headless lab, tests).
    #[default]
    Stopped,
    Listening,
    /// Enabled but the port could not be opened (`last_error` says why).
    Error,
}

/// What a listener is doing (operational, filled by the daemon, never saved).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WebListenerStatus {
    pub status: WebState,
    /// The socket address actually listened on.
    pub listening: Option<String>,
    pub last_error: Option<String>,
    /// Connections dropped because the client is not in `available_from`.
    pub refused: u64,
}

/// Both listeners' status, kept in the session with `ext_mut`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WebStatus {
    pub www_ssl: WebListenerStatus,
    pub www: WebListenerStatus,
    /// Whether the daemon has the GUI files (`--web-files`); without them
    /// the HTTPS port only speaks WebSocket.
    pub gui_files: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_off_and_factory_turns_https_on() {
        let w = WebService::default();
        assert!(!w.www_ssl.enabled && !w.www.enabled);
        assert_eq!((w.www_ssl.port, w.www.port), (443, 80));
        let back: WebService = serde_json::from_str("{}").unwrap();
        assert!(back.is_default());
        let f = WebService::factory();
        assert!(f.www_ssl.enabled && !f.www.enabled);
        assert!(f.www_ssl.address.is_unspecified());
    }

    #[test]
    fn available_from_matches_mapped_v4() {
        let mut l = WebService::default().www_ssl;
        assert!(l.allows("203.0.113.9".parse().unwrap()));
        l.available_from = vec!["192.0.2.0/24".parse().unwrap()];
        assert!(l.allows("::ffff:192.0.2.10".parse().unwrap()));
        assert!(!l.allows("198.51.100.1".parse().unwrap()));
    }
}
