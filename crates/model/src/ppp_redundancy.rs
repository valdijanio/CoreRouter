//! `/ppp redundancy` (G4.3h): two BNGs as an active/standby pair for the
//! same subscribers. Not in RouterOS (its PPPoE server has no redundancy);
//! the knobs follow its VRRP (`priority`, preemption) and the BNGs that have
//! it (Cisco SRG, Nokia MC-Sync/SRRP). The daemon's `pppoe` service reads
//! it; what it knows at run time is [`RedundancyStatus`]. Design:
//! `docs/bng-ha.md`.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::types::{IfName, MacAddr, ParseError};

/// Stateless: the standby answers after a takeover and the subscribers
/// redial (Nokia's stateless mode). Hot standby: every session is copied
/// and survives the takeover.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HaMode {
    Stateless,
    #[default]
    HotStandby,
}

impl HaMode {
    pub const ALL: [Self; 2] = [Self::Stateless, Self::HotStandby];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stateless => "stateless",
            Self::HotStandby => "hot-standby",
        }
    }
}

impl fmt::Display for HaMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HaMode {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|v| v.as_str() == s.trim())
            .ok_or_else(|| ParseError::new("mode", s, "expected stateless or hot-standby"))
    }
}

/// How a node proves it is not isolated before it takes the role over
/// (`docs/bng-ha.md` §2.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fencing {
    /// Takes over only while it reaches a witness (the gateway).
    Witness,
    /// The peer must be silent on the access network too (no witness).
    Access,
    /// Both: the peer silent on the sync link and on the access network,
    /// and the witness reachable.
    #[default]
    WitnessAndAccess,
}

impl Fencing {
    pub const ALL: [Self; 3] = [Self::Witness, Self::Access, Self::WitnessAndAccess];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Witness => "witness",
            Self::Access => "access",
            Self::WitnessAndAccess => "witness-and-access",
        }
    }

    pub fn uses_witness(self) -> bool {
        matches!(self, Self::Witness | Self::WitnessAndAccess)
    }

    pub fn uses_access(self) -> bool {
        matches!(self, Self::Access | Self::WitnessAndAccess)
    }
}

impl fmt::Display for Fencing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Fencing {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL.into_iter().find(|v| v.as_str() == s.trim()).ok_or_else(|| {
            ParseError::new("fencing", s, "expected witness, access or witness-and-access")
        })
    }
}

/// Defaults (**estimado** against false takeovers under load: 4 hellos
/// lost in a row; measured takeover in the simulation ≈ dead interval).
pub const DEFAULT_HELLO_MS: u32 = 300;
pub const DEFAULT_DEAD_MS: u32 = 1200;
pub const DEFAULT_PRIORITY: u8 = 100;
pub const DEFAULT_PORT: u16 = 8730;
pub const MIN_HELLO_MS: u32 = 50;
pub const MAX_HELLO_MS: u32 = 10_000;
pub const MAX_WITNESSES: usize = 4;
pub const MAX_INTERFACES: usize = 64;
pub const MIN_SECRET: usize = 16;
pub const MAX_SECRET: usize = 256;

fn default_hello() -> u32 {
    DEFAULT_HELLO_MS
}

fn default_dead() -> u32 {
    DEFAULT_DEAD_MS
}

fn default_priority() -> u8 {
    DEFAULT_PRIORITY
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

fn default_init_hold() -> u32 {
    5
}

fn default_recover_hold() -> u32 {
    3
}

fn default_preempt_delay() -> u32 {
    60
}

fn default_group() -> u8 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Redundancy {
    pub enabled: bool,
    pub mode: HaMode,
    /// The pair: both nodes use the same group (and so the same default
    /// virtual MAC).
    #[serde(default = "default_group")]
    pub group: u8,
    /// The peer's sync address, `host:port` (TLS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    /// Where this node accepts the peer's sync connection.
    #[serde(default = "default_port")]
    pub listen_port: u16,
    /// Shared by both nodes: authenticates the sync link and the access
    /// hellos, and keys the AC-Cookie both accept. Write-only (masked in
    /// `get` and in the journal).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub secret: String,
    /// Higher wins an election (VRRP: 1..254).
    #[serde(default = "default_priority")]
    pub priority: u8,
    /// The higher priority takes the role back once in sync (VRRP
    /// `preemption-mode`; off by default here: a takeover is not undone by
    /// itself).
    pub preempt: bool,
    #[serde(default = "default_preempt_delay")]
    pub preempt_delay: u32,
    /// The AC MAC the subscribers see; `None` = `02:43:52:48:41:<group>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_mac: Option<MacAddr>,
    /// Access ports (hellos and the virtual MAC); empty = every interface
    /// with a `pppoe-server`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<IfName>,
    pub fencing: Fencing,
    /// Any of them reachable = the witness is up (the gateway is a good one).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub witness: Vec<IpAddr>,
    /// A port of these down fences the node (it cannot serve).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub track: Vec<IfName>,
    #[serde(default = "default_hello")]
    pub hello_interval: u32,
    #[serde(default = "default_dead")]
    pub dead_interval: u32,
    /// Seconds a starting node listens before it claims the role.
    #[serde(default = "default_init_hold")]
    pub init_hold: u32,
    /// Seconds a fenced node waits, stable, before it may take over.
    #[serde(default = "default_recover_hold")]
    pub recover_hold: u32,
    /// BFD profile on the sync path (G3.6h), to the `peer`'s address;
    /// empty = hellos only. BFD brings the detection forward (`fast`:
    /// 50 ms × 3 = 150 ms instead of `dead_interval`); the takeover rule
    /// does not change.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub bfd: String,
    /// BFD profile on the access path, to `access_peer`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub access_bfd: String,
    /// The peer's address on the access network (BFD of the access path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_peer: Option<IpAddr>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl Default for Redundancy {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: HaMode::default(),
            group: default_group(),
            peer: None,
            listen_port: DEFAULT_PORT,
            secret: String::new(),
            priority: DEFAULT_PRIORITY,
            preempt: false,
            preempt_delay: default_preempt_delay(),
            virtual_mac: None,
            interfaces: Vec::new(),
            fencing: Fencing::default(),
            witness: Vec::new(),
            track: Vec::new(),
            hello_interval: DEFAULT_HELLO_MS,
            dead_interval: DEFAULT_DEAD_MS,
            init_hold: default_init_hold(),
            recover_hold: default_recover_hold(),
            bfd: String::new(),
            access_bfd: String::new(),
            access_peer: None,
            comment: String::new(),
        }
    }
}

impl Redundancy {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// The virtual MAC in force.
    pub fn mac(&self) -> MacAddr {
        self.virtual_mac
            .unwrap_or(MacAddr([0x02, 0x43, 0x52, 0x48, 0x41, self.group]))
    }

    /// What makes the pair unsafe or unusable, `(parameter, why)`; empty
    /// = fine. Only checked when enabled: a disabled pair may be half done.
    pub fn problems(&self) -> Vec<(&'static str, String)> {
        let mut p = Vec::new();
        if !(MIN_HELLO_MS..=MAX_HELLO_MS).contains(&self.hello_interval) {
            p.push(("hello_interval", format!("{MIN_HELLO_MS}..={MAX_HELLO_MS} ms")));
        }
        if self.dead_interval < self.hello_interval.saturating_mul(3) {
            p.push((
                "dead_interval",
                "at least 3 × hello_interval (one lost hello must not be a failover)".into(),
            ));
        }
        if self.dead_interval > 60_000 {
            p.push(("dead_interval", "at most 60000 ms".into()));
        }
        if self.priority == 0 || self.priority == 255 {
            p.push(("priority", "1..=254".into()));
        }
        if self.group == 0 {
            p.push(("group", "1..=255".into()));
        }
        if let Some(m) = self.virtual_mac
            && m.0.first().is_some_and(|b| b & 1 != 0)
        {
            p.push(("virtual_mac", "must be unicast (the first octet even)".into()));
        }
        if self.witness.len() > MAX_WITNESSES {
            p.push(("witness", format!("at most {MAX_WITNESSES} addresses")));
        }
        if self.interfaces.len() > MAX_INTERFACES || self.track.len() > MAX_INTERFACES {
            p.push(("interfaces", format!("at most {MAX_INTERFACES}")));
        }
        if self.secret.len() > MAX_SECRET {
            p.push(("secret", format!("at most {MAX_SECRET} characters")));
        }
        if let Some(peer) = &self.peer
            && !valid_peer(peer)
        {
            p.push(("peer", "host:port (a name or an address, then the port)".into()));
        }
        if !self.bfd.is_empty() && self.peer.is_some() && self.sync_bfd_peer().is_none() {
            p.push((
                "bfd",
                "BFD on the sync path needs peer as an address (ip:port or [ipv6]:port), not a name".into(),
            ));
        }
        if !self.access_bfd.is_empty() && self.access_peer.is_none() {
            p.push(("access_peer", "access_bfd needs the peer's address on the access network".into()));
        }
        if self.enabled {
            if self.peer.is_none() {
                p.push(("peer", "required to enable: the other node's host:port".into()));
            }
            if self.secret.len() < MIN_SECRET {
                p.push((
                    "secret",
                    format!("required to enable: at least {MIN_SECRET} characters, the same on both nodes"),
                ));
            }
            if self.fencing.uses_witness() && self.witness.is_empty() {
                p.push((
                    "witness",
                    format!(
                        "fencing={} needs a witness (the gateway's address), or use fencing=access",
                        self.fencing
                    ),
                ));
            }
        }
        p
    }
}

impl Redundancy {
    /// The sync path's BFD target: the address in `peer`.
    pub fn sync_bfd_peer(&self) -> Option<IpAddr> {
        let (host, _) = self.peer.as_deref()?.trim().rsplit_once(':')?;
        host.trim_start_matches('[').trim_end_matches(']').parse().ok()
    }

    /// The BFD sessions the pair asks the `bfd` service for (G3.6h):
    /// `(peer address, profile, path)`, path `"sync"` or `"access"`.
    pub fn bfd_sessions(&self) -> Vec<(IpAddr, &str, &'static str)> {
        let mut v = Vec::new();
        if !self.enabled {
            return v;
        }
        if !self.bfd.is_empty()
            && let Some(a) = self.sync_bfd_peer()
        {
            v.push((a, self.bfd.as_str(), "sync"));
        }
        if !self.access_bfd.is_empty()
            && let Some(a) = self.access_peer
            && v.iter().all(|(b, _, _)| *b != a)
        {
            v.push((a, self.access_bfd.as_str(), "access"));
        }
        v
    }
}

fn valid_peer(s: &str) -> bool {
    let Some((host, port)) = s.trim().rsplit_once(':') else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
        && port.parse::<u16>().is_ok_and(|p| p != 0)
}

// --- At run time (`ppp.redundancy.monitor`): not config, never stored. ---

/// What the service knows about the pair now.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RedundancyStatus {
    /// `init`, `standby`, `active`, `fenced`, `yielding`.
    pub role: String,
    pub epoch: u64,
    pub role_since_secs: u64,
    /// Answering subscribers now.
    pub answering: bool,
    pub peer: PeerStatus,
    pub witness: bool,
    pub track: bool,
    /// Hot standby: this node's replica is complete (standby), or the peer's
    /// (active).
    pub in_sync: bool,
    pub sync: SyncStatus,
    /// Config sections that differ from the peer's (`ppp.profile`,
    /// `ip.pool`…): the pair would serve differently after a takeover.
    pub drift: Vec<String>,
    /// Seconds left of a simulated failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulating_secs: Option<u64>,
    pub duplicate_node_id: bool,
    /// Last role changes, newest first.
    pub history: Vec<RoleChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// BFD on the sync and on the access path (G3.6h).
    pub bfd: Vec<PathBfdStatus>,
    /// BFD found the peer silent: the takeover waits for a fresh witness
    /// answer.
    pub confirming: bool,
    /// The witness answered this long ago (ms).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_age_ms: Option<u64>,
    /// Takeovers by this node, newest first, with their timeline.
    pub takeovers: Vec<Takeover>,
    /// The peer's last takeover, as it reported over the sync link (after
    /// a test from this node, where the result is).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_takeover: Option<Takeover>,
    /// Warnings that call for a look before the pair fails: BFD jitter,
    /// a damped path.
    pub alerts: Vec<String>,
    /// A takeover test under way or done (`ppp.redundancy.test-takeover`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test: Option<TakeoverTest>,
}

/// BFD on one path of the pair.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PathBfdStatus {
    /// `sync` or `access`.
    pub path: String,
    pub peer: Option<IpAddr>,
    pub profile: String,
    /// `up`, `down`, `init`, `admin-down` (the BFD session), `none` (not
    /// started yet).
    pub state: String,
    pub detect_ms: u64,
    /// p99 of the gap between packets received from the peer, and of how
    /// late ours left (µs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_gap_p99_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_jitter_p99_us: Option<u64>,
    /// Damped: its losses are ignored (hellos only).
    pub suppressed: bool,
    pub penalty: u32,
    pub losses: u64,
    pub false_alarms: u64,
}

/// One takeover's timeline (ms after the failure's best estimate: the
/// last time the peer was heard).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Takeover {
    /// Unix seconds.
    pub at: u64,
    /// English key of the role change (`peer-dead`, `switchover`…).
    pub reason: String,
    pub epoch: u64,
    /// `bfd` (and on which paths), `dead-interval`, `handover`.
    pub detected_by: String,
    /// Milestones from the last sign of life of the peer, ms: detected,
    /// witness confirmed, active, announced (virtual MAC hello), sessions
    /// adopted, first subscriber frame.
    pub detected_ms: Option<u64>,
    pub witness_ms: Option<u64>,
    pub active_ms: Option<u64>,
    pub announced_ms: Option<u64>,
    pub adopted_ms: Option<u64>,
    pub first_frame_ms: Option<u64>,
    /// Sessions kept and lost: the replica handed over, the ones the
    /// workers adopted, the ones that did not fit, and the peer's last
    /// count minus the adopted ones (changes not synced in time).
    pub stateful: bool,
    pub handed: u64,
    pub adopted: u64,
    pub skipped: u64,
    pub lost: u64,
    /// A test (`ppp.redundancy.test-takeover`), not a failure.
    pub test: bool,
}

/// `ppp.redundancy.test-takeover`: what was checked and what happened.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TakeoverTest {
    /// Unix seconds.
    pub started: u64,
    /// `failure` (this node goes silent, the peer detects it as a crash)
    /// or `switchover` (planned handover).
    pub method: String,
    /// `running`, `passed`, `failed`, `refused`.
    pub state: String,
    pub checks: Vec<TestCheck>,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TestCheck {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PeerStatus {
    pub connected: bool,
    /// The peer's role as it last said.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub role: String,
    pub priority: u8,
    /// Heard on the sync link / on the access network within the dead
    /// interval.
    pub sync_path: bool,
    pub access_path: bool,
    pub witness: bool,
    /// The peer's TLS certificate (SHA-256, hex), pinned on first use.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SyncStatus {
    /// Sessions the active holds and the standby has (`N/N`).
    pub sessions: u64,
    pub synced: u64,
    /// Changes not acknowledged by the standby, and how long the last one
    /// took from the change to the ack (ms).
    pub lag: u64,
    pub delay_ms: u64,
    pub snapshots: u64,
    /// `(received, total)` of a snapshot under way.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<(u32, u32)>,
    pub gaps: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RoleChange {
    /// Unix seconds.
    pub at: u64,
    pub from: String,
    pub to: String,
    pub epoch: u64,
    /// English key: `peer-dead`, `switchover`, `isolated`…
    pub reason: String,
    /// The sessions were kept (hot standby with a complete replica).
    pub stateful: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe_and_round_trip() {
        let r = Redundancy::default();
        assert!(r.is_default() && r.problems().is_empty());
        assert_eq!(r.mac().to_string().to_lowercase(), "02:43:52:48:41:01");
        let back: Redundancy = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        let from_empty: Redundancy = serde_json::from_str("{}").unwrap();
        assert_eq!(from_empty, r);
    }

    #[test]
    fn enabling_needs_peer_secret_and_witness() {
        let mut r = Redundancy {
            enabled: true,
            ..Redundancy::default()
        };
        let keys: Vec<&str> = r.problems().iter().map(|p| p.0).collect();
        assert_eq!(keys, ["peer", "secret", "witness"]);
        r.peer = Some("10.0.0.2:8730".into());
        r.secret = "0123456789abcdef".into();
        r.witness = vec!["10.0.0.254".parse().unwrap()];
        assert!(r.problems().is_empty());
        r.fencing = Fencing::Access;
        r.witness.clear();
        assert!(r.problems().is_empty(), "access fencing needs no witness");
        r.dead_interval = 500;
        r.virtual_mac = Some(MacAddr([1, 0, 0, 0, 0, 1]));
        r.peer = Some("no port".into());
        let keys: Vec<&str> = r.problems().iter().map(|p| p.0).collect();
        assert_eq!(keys, ["dead_interval", "virtual_mac", "peer"]);
        assert!(valid_peer("[2001:db8::2]:8730") && valid_peer("bng2.isp:1"));
        assert!(!valid_peer("bng2:0") && !valid_peer(":8730"));
    }

    #[test]
    fn bfd_sessions_need_addresses() {
        let mut r = Redundancy {
            enabled: true,
            peer: Some("bng2.isp:8730".into()),
            secret: "0123456789abcdef".into(),
            witness: vec!["10.0.0.254".parse().unwrap()],
            bfd: "fast".into(),
            ..Redundancy::default()
        };
        assert_eq!(r.problems().first().map(|p| p.0), Some("bfd"), "a name has no BFD address");
        r.peer = Some("[2001:db8::2]:8730".into());
        assert!(r.problems().is_empty());
        r.access_bfd = "fast".into();
        assert_eq!(r.problems().first().map(|p| p.0), Some("access_peer"));
        r.access_peer = Some("100.64.0.2".parse().unwrap());
        assert!(r.problems().is_empty());
        let s = r.bfd_sessions();
        assert_eq!(
            s,
            [
                ("2001:db8::2".parse().unwrap(), "fast", "sync"),
                ("100.64.0.2".parse().unwrap(), "fast", "access"),
            ]
        );
        r.enabled = false;
        assert!(r.bfd_sessions().is_empty(), "a disabled pair runs no BFD");
        let back: Redundancy = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }
}
