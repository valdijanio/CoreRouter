//! Services of the daemon under its supervisor (G0.10, `system.service`):
//! the DNS resolver and forwarder, the NTP client, remote logging, the
//! metrics endpoint, the control channel. Operational state only, filled by
//! the daemon and kept in the session with `ext_mut`; never saved.
//!
//! Not RouterOS `/ip service` (the management ports: api, ssh, winbox…):
//! this is closer to pfSense's Status › Services or `systemctl status`.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Requests queued at most between two supervisor ticks.
pub const MAX_REQUESTS: usize = 64;
/// Longest event text kept (a service's error can quote a peer).
pub const MAX_EVENT: usize = 256;

/// Where a service is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceState {
    /// Running but idle: the config turns it off (`reason` says how).
    Disabled,
    /// Started, no heartbeat yet (or waiting for a dependency).
    #[default]
    Starting,
    Running,
    /// Ended or crashed; starts again in `restart_in_secs`.
    Restarting,
    /// Stopped by the admin, until started again or the daemon restarts.
    Stopped,
    /// Too many failures in a row; the supervisor gave up (`reset-failures`
    /// or `start` tries again).
    Failed,
}

impl ServiceState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Restarting => "restarting",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }

    /// Whether the service does its job (`corerouter_service_up`).
    pub fn is_up(self) -> bool {
        matches!(self, Self::Running | Self::Disabled)
    }
}

/// Who can reach a listening socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ListenScope {
    /// `0.0.0.0` / `::`: every address of the router.
    All,
    /// Loopback: this machine only.
    Local,
    /// A private, unique-local or link-local address.
    Lan,
    /// A public address of the router.
    Public,
}

impl ListenScope {
    pub fn of(ip: IpAddr) -> Self {
        let ip = ip.to_canonical();
        if ip.is_unspecified() {
            return Self::All;
        }
        if ip.is_loopback() {
            return Self::Local;
        }
        let lan = match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_link_local() || is_shared(v4),
            IpAddr::V6(v6) => {
                let first = v6.segments().first().copied().unwrap_or(0);
                // fc00::/7 (RFC 4193) and fe80::/10.
                first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
            }
        };
        if lan { Self::Lan } else { Self::Public }
    }
}

/// 100.64.0.0/10 (RFC 6598, CGNAT): inside the provider's network.
fn is_shared(ip: std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 100 && (64..128).contains(&b)
}

/// One socket a service listens on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listen {
    /// `udp`, `tcp`, `tls`, `http`…
    pub proto: String,
    pub address: String,
    pub scope: ListenScope,
}

impl Listen {
    pub fn new(proto: &str, at: SocketAddr) -> Self {
        Self {
            proto: proto.to_owned(),
            address: at.to_string(),
            scope: ListenScope::of(at.ip()),
        }
    }
}

/// One row of `system.service.print`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceRow {
    pub name: String,
    pub state: ServiceState,
    /// Why it is disabled, or what it waits for while starting.
    pub reason: Option<String>,
    /// Seconds until the next start (`restarting`).
    pub restart_in_secs: Option<u64>,
    /// Since the current run started (`running`, `disabled`).
    pub uptime_secs: Option<u64>,
    /// Restarts after a failure since the daemon started (or the last
    /// `reset-failures`); an admin restart does not count.
    pub restarts: u32,
    /// Failures in the current window (the policy's limit gives up).
    pub recent_failures: u32,
    /// Threads the service runs now (its main loop included).
    pub threads: u32,
    /// Milliseconds since its main loop last said it is alive.
    pub heartbeat_age_ms: Option<u64>,
    pub listen: Vec<Listen>,
    /// The last thing it reported, or the supervisor's last word on it.
    pub last_event: String,
    pub last_error: Option<String>,
    /// Services that must run first.
    pub depends: Vec<String>,
    /// The config command that turns it on (or "always on").
    pub enable: String,
    /// Topic of its lines in the router's log (`log.print topics=…`).
    pub topic: String,
    /// Restart policy, for people ("always, 1 s → 60 s; gives up after 5
    /// failures in 60 s").
    pub policy: String,
    /// Cannot be stopped or restarted by a command (the control channel
    /// carries the very session that would ask).
    pub protected: bool,
}

/// What `system.service.start|stop|restart|reset-failures` ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
    ResetFailures,
}

impl ServiceAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::ResetFailures => "reset-failures",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRequest {
    pub name: String,
    pub action: ServiceAction,
}

/// The supervisor's table in the session: rows it publishes, requests the
/// commands queue for it. Empty without a daemon (lab, browser).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServiceTable {
    /// A daemon supervises services in this session.
    pub supervised: bool,
    pub rows: Vec<ServiceRow>,
    pub requests: Vec<ServiceRequest>,
}

impl ServiceTable {
    pub fn row(&self, name: &str) -> Option<&ServiceRow> {
        self.rows.iter().find(|r| r.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_scope_by_address() {
        let s = |a: &str| ListenScope::of(a.parse().unwrap());
        assert_eq!(s("0.0.0.0"), ListenScope::All);
        assert_eq!(s("::"), ListenScope::All);
        assert_eq!(s("127.0.0.1"), ListenScope::Local);
        assert_eq!(s("::1"), ListenScope::Local);
        assert_eq!(s("192.168.88.1"), ListenScope::Lan);
        assert_eq!(s("100.64.1.1"), ListenScope::Lan);
        assert_eq!(s("fd00::1"), ListenScope::Lan);
        assert_eq!(s("fe80::1"), ListenScope::Lan);
        assert_eq!(s("::ffff:10.0.0.1"), ListenScope::Lan);
        assert_eq!(s("203.0.113.1"), ListenScope::Public);
        assert_eq!(s("2001:db8::1"), ListenScope::Public);
    }

    #[test]
    fn states_spell_like_the_commands() {
        let v = serde_json::to_value(ServiceState::Restarting).unwrap();
        assert_eq!(v, "restarting");
        assert_eq!(ServiceAction::ResetFailures.as_str(), "reset-failures");
        assert!(ServiceState::Disabled.is_up() && !ServiceState::Failed.is_up());
    }
}
