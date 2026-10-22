//! Neighbor discovery: what the router hears on its links (operational
//! state, never saved) and the settings that say where it listens and
//! announces (configuration, saved like any other).
//!
//! Every discovery protocol fills the same [`NeighborEntry`]: CRDP (ours,
//! docs/discovery.md, G5.1), LLDP and passive MNDP (G5.2).

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::types::{IfName, MacAddr, ParseError};

/// Seconds between announcements unless configured otherwise.
pub const DEFAULT_INTERVAL_SECS: u32 = 30;
/// Accepted range of `interval_secs`.
pub const INTERVAL_RANGE: std::ops::RangeInclusive<u32> = 1..=3600;
/// A neighbor is forgotten after this many intervals without news
/// (30 s × 4 = 120 s by default), unless its protocol says otherwise.
pub const HOLD_MULTIPLIER: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NeighborProtocol {
    /// CoreRouter Discovery Protocol (docs/discovery.md).
    Crdp,
    /// IEEE 802.1AB.
    Lldp,
    /// MikroTik Neighbor Discovery, received only (never announced).
    Mndp,
}

impl NeighborProtocol {
    pub const ALL: [NeighborProtocol; 3] = [Self::Crdp, Self::Lldp, Self::Mndp];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Crdp => "crdp",
            Self::Lldp => "lldp",
            Self::Mndp => "mndp",
        }
    }
}

impl fmt::Display for NeighborProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NeighborProtocol {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        Self::ALL
            .into_iter()
            .find(|p| p.as_str().eq_ignore_ascii_case(s))
            .ok_or_else(|| ParseError::new("protocol", s, "expected crdp, lldp or mndp"))
    }
}

/// Management ports a neighbor advertises (CRDP only, today).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MgmtPorts {
    /// TCP control channel (`corerouter-daemon --control`).
    pub control: Option<u16>,
    /// WebSocket for the web GUI (`corerouter-daemon --ws`).
    pub ws: Option<u16>,
}

/// One neighbor heard on one of our interfaces with one protocol.
///
/// Operational state: lives in the engine's neighbor table, is never part of
/// [`crate::Config`] and is never saved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborEntry {
    /// Our interface the announcement arrived on.
    pub interface: IfName,
    pub protocol: NeighborProtocol,
    /// Neighbor's MAC on that link, when the protocol carries it.
    pub mac: Option<MacAddr>,
    /// Neighbor's addresses (announced ones first, then the packet source).
    pub addresses: Vec<IpAddr>,
    pub identity: String,
    /// Software version.
    pub version: String,
    /// Software/OS family, e.g. "CoreRouter", "MikroTik".
    pub platform: String,
    /// Hardware or board, e.g. "x86_64", "RB5009".
    pub board: String,
    pub uptime_secs: Option<u64>,
    /// Stable id of the neighbor node when the protocol has one (CRDP node
    /// id as 32 hex digits; LLDP chassis id as text).
    pub node_id: Option<String>,
    /// Neighbor's own name for the interface it sent on.
    pub remote_interface: Option<String>,
    pub mgmt: Option<MgmtPorts>,
    /// When it was heard, in seconds of the recorder's clock (Unix time).
    pub last_seen: u64,
    /// Forget it `hold_secs` after `last_seen`; 0 removes it at once (a
    /// neighbor saying goodbye).
    pub hold_secs: u32,
}

impl NeighborEntry {
    /// Identity of the row in the neighbor table: the same node heard again
    /// on the same interface with the same protocol replaces its entry.
    pub fn key(&self) -> (IfName, NeighborProtocol, String) {
        let who = self
            .node_id
            .clone()
            .or_else(|| self.mac.map(|m| m.to_string()))
            .or_else(|| self.addresses.first().map(ToString::to_string))
            .unwrap_or_else(|| self.identity.clone());
        (self.interface.clone(), self.protocol, who)
    }
}

/// Where the router listens for and sends announcements (`ip.neighbor.discovery.set`).
///
/// Default: enabled with **no interfaces**. CoreRouter has no LAN/WAN
/// interface lists yet, so it cannot tell a WAN port from a LAN port; the
/// safe default is to stay quiet until the operator names the LAN-side
/// interfaces. Announcing on a WAN port would tell the internet our
/// identity, version and management ports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NeighborDiscovery {
    pub enabled: bool,
    pub interfaces: BTreeSet<IfName>,
    pub interval_secs: u32,
}

impl Default for NeighborDiscovery {
    fn default() -> Self {
        Self {
            enabled: true,
            interfaces: BTreeSet::new(),
            interval_secs: DEFAULT_INTERVAL_SECS,
        }
    }
}

impl NeighborDiscovery {
    /// True when announcements may be sent and heard on `interface`.
    pub fn active_on(&self, interface: &IfName) -> bool {
        self.enabled && self.interfaces.contains(interface)
    }

    /// Hold time we announce for ourselves.
    pub fn hold_secs(&self) -> u32 {
        self.interval_secs.saturating_mul(HOLD_MULTIPLIER)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_text() {
        assert_eq!(
            "LLDP".parse::<NeighborProtocol>().unwrap(),
            NeighborProtocol::Lldp
        );
        assert!("cdp".parse::<NeighborProtocol>().is_err());
        assert_eq!(
            serde_json::to_string(&NeighborProtocol::Crdp).unwrap(),
            "\"crdp\""
        );
    }

    #[test]
    fn default_settings_announce_nowhere() {
        let d = NeighborDiscovery::default();
        assert!(d.enabled);
        assert!(!d.active_on(&"ether1".parse().unwrap()));
        assert_eq!(d.hold_secs(), 120);
    }

    #[test]
    fn key_prefers_node_id_then_mac() {
        let mut e = NeighborEntry {
            interface: "ether1".parse().unwrap(),
            protocol: NeighborProtocol::Mndp,
            mac: Some("02:00:00:00:00:01".parse().unwrap()),
            addresses: vec!["10.0.0.2".parse().unwrap()],
            identity: "r2".into(),
            version: String::new(),
            platform: String::new(),
            board: String::new(),
            uptime_secs: None,
            node_id: None,
            remote_interface: None,
            mgmt: None,
            last_seen: 0,
            hold_secs: 120,
        };
        assert_eq!(e.key().2, "02:00:00:00:00:01");
        e.node_id = Some("ab".into());
        assert_eq!(e.key().2, "ab");
    }
}
