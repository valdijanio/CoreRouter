//! Operational state of the routing daemons (G3.1): what `hal-frr` reads
//! from FRR and `routing.bgp.session.list` shows. Not configuration: the
//! daemon's `frr` service fills it, outside the session lock, and it is gone
//! on restart.

use serde::{Deserialize, Serialize};

/// One BGP session, as RouterOS v7 `/routing bgp session print` shows it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BgpSession {
    /// The BGP instance (`routing.bgp` key) the session belongs to.
    pub instance: String,
    /// VRF of the instance as the routing daemon names it (`default`).
    pub vrf: String,
    pub remote_address: String,
    pub remote_as: u32,
    pub local_as: u32,
    /// The neighbor's BGP identifier, once it sent an OPEN.
    pub remote_id: Option<String>,
    /// RFC 4271 §8.2.2 state, lowercase: idle, connect, active, opensent,
    /// openconfirm, established (plus the daemon's own, e.g. `clearing`).
    pub state: String,
    pub established: bool,
    /// Seconds in the current state (established: the session's uptime).
    pub uptime_secs: Option<u64>,
    /// Prefixes accepted from the neighbor and sent to it, all families.
    pub prefix_count: Option<u64>,
    pub prefix_sent: Option<u64>,
    pub messages_received: Option<u64>,
    pub messages_sent: Option<u64>,
    /// The daemon's reason for a session that is down (`Admin. shutdown`,
    /// `(Policy)`: RFC 8212 without a filter).
    pub reason: Option<String>,
    pub description: Option<String>,
    /// The `routing.bgp_connections` entry (G3.2a: CoreRouter renders the
    /// connection's name as the neighbor's description).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<String>,
    /// Negotiated timers, seconds (RFC 4271 §4.2: the smaller hold time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_time: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_time: Option<u64>,
    /// The last NOTIFICATION (sent or received), or why it last went down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Times the session went down after being established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flaps: Option<u64>,
    /// BFD state of the neighbor (`up`, `down`), when BFD watches it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bfd: Option<String>,
    /// Families the session carries (`ipv4`, `ipv6`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub afi: Vec<String>,
    /// Inbound and outbound policy (route-maps) in force, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_in: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_out: Option<String>,
}

/// What the routing backend is doing, for the session list and the log.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RoutingStatus {
    /// `frr 10.7.1`, or empty while no routing daemon is attached (the
    /// virtual lab).
    pub backend: String,
    /// Unix time of the last good read.
    pub updated: Option<u64>,
    /// Why the last read or sync failed.
    pub error: Option<String>,
    pub bgp_sessions: Vec<BgpSession>,
}
