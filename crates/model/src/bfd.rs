//! BFD (G3.6): profiles (FRR `bfd profile`, Cisco `bfd-template`, Junos
//! `bfd-liveness-detection`) and peers (FRR `bfd peer`), plus the live
//! state the daemon's `bfd` service publishes. RouterOS v7 has
//! `/routing bfd configuration` (match by interface/address) and
//! `/routing bfd session`; we keep its session view and names, and use
//! profiles so BGP, OSPF and static routes share the same timers.
//!
//! Intervals are milliseconds in the config (RFC 5880 carries µs).

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// The two profiles every router has (they can be changed, not removed).
pub const PROFILE_DEFAULT: &str = "default";
pub const PROFILE_FAST: &str = "fast";
/// 10 ms..=60 s (RFC 7419 common intervals from 10 ms; ours is userspace).
pub const INTERVAL_MS: (u32, u32) = (10, 60_000);
/// Below this, the add/set answer warns about CPU (§ docs/bfd.md).
pub const FAST_WARN_MS: u32 = 100;
pub const MAX_PROFILES: usize = 64;
pub const MAX_PEERS: usize = 4096;
/// History kept by the service (newest last).
pub const MAX_HISTORY: usize = 1000;
/// RFC 5880 §4.4: up to 20 bytes.
pub const MAX_KEY: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BfdAuth {
    #[default]
    None,
    KeyedSha1,
    MeticulousKeyedSha1,
}

impl BfdAuth {
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::KeyedSha1 => "keyed-sha1",
            Self::MeticulousKeyedSha1 => "meticulous-keyed-sha1",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "none" => Self::None,
            "keyed-sha1" | "sha1" => Self::KeyedSha1,
            "meticulous-keyed-sha1" | "meticulous-sha1" => Self::MeticulousKeyedSha1,
            _ => return None,
        })
    }
}

/// The authentication key: kept in the config like the RADIUS secret,
/// never in `Debug` output.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BfdKeyText(pub String);

impl BfdKeyText {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for BfdKeyText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_empty() { "\"\"" } else { "***" })
    }
}

/// Dampening (on by default): seconds and penalties as Cisco's `bfd
/// dampening` (1000 per flap).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BfdDampening {
    pub enabled: bool,
    pub half_life: u32,
    pub suppress: u32,
    pub reuse: u32,
    pub max_suppress: u32,
}

impl Default for BfdDampening {
    fn default() -> Self {
        Self {
            enabled: true,
            half_life: 15,
            suppress: 2500,
            reuse: 800,
            max_suppress: 120,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BfdProfile {
    pub name: String,
    /// Desired Min TX once Up (ms).
    pub min_tx: u32,
    /// Required Min RX (ms).
    pub min_rx: u32,
    pub multiplier: u8,
    /// RFC 5880 §6.1 passive role.
    #[serde(default)]
    pub passive: bool,
    #[serde(default)]
    pub dampening: BfdDampening,
    #[serde(default)]
    pub auth: BfdAuth,
    #[serde(default)]
    pub auth_key_id: u8,
    /// Write-only: commands show `***`.
    #[serde(default, skip_serializing_if = "BfdKeyText::is_empty")]
    pub auth_secret: BfdKeyText,
    /// Multihop only (RFC 5883 §5): the lowest TTL accepted.
    #[serde(default = "default_min_ttl")]
    pub min_ttl: u8,
    #[serde(default)]
    pub comment: String,
}

fn default_min_ttl() -> u8 {
    254
}

impl BfdProfile {
    pub fn new(name: &str, ms: u32, multiplier: u8) -> Self {
        Self {
            name: name.to_owned(),
            min_tx: ms,
            min_rx: ms,
            multiplier,
            passive: false,
            dampening: BfdDampening::default(),
            auth: BfdAuth::None,
            auth_key_id: 0,
            auth_secret: BfdKeyText::default(),
            min_ttl: default_min_ttl(),
            comment: String::new(),
        }
    }

    /// Detection time this side asks of the peer, if both use these timers.
    pub fn detect_ms(&self) -> u64 {
        u64::from(self.multiplier) * u64::from(self.min_rx.max(self.min_tx))
    }
}

/// The built-in profiles: conservative (300 ms × 3, 900 ms) and fast
/// (50 ms × 3, 150 ms; RFC 7419 common interval).
pub fn builtin_profiles() -> [BfdProfile; 2] {
    let mut d = BfdProfile::new(PROFILE_DEFAULT, 300, 3);
    d.comment = "built-in: 300 ms x 3".into();
    let mut f = BfdProfile::new(PROFILE_FAST, 50, 3);
    f.comment = "built-in: 50 ms x 3".into();
    [d, f]
}

/// An explicit BFD peer (FRR `peer <addr> [multihop] [local-address]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BfdPeer {
    pub name: String,
    pub address: IpAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_address: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(default)]
    pub multihop: bool,
    #[serde(default = "default_profile")]
    pub profile: String,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

fn default_profile() -> String {
    PROFILE_DEFAULT.to_owned()
}

/// `routing.bfd` in the config.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BfdConfig {
    /// Overrides of the built-ins and the operator's own.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub profiles: BTreeMap<String, BfdProfile>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub peers: BTreeMap<String, BfdPeer>,
}

impl BfdConfig {
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty() && self.peers.is_empty()
    }

    /// The profile in force by name (an override, else the built-in).
    pub fn profile(&self, name: &str) -> Option<BfdProfile> {
        self.profiles
            .get(name)
            .cloned()
            .or_else(|| builtin_profiles().into_iter().find(|p| p.name == name))
    }

    /// Every profile in force, built-ins first.
    pub fn all_profiles(&self) -> Vec<BfdProfile> {
        let mut out: Vec<BfdProfile> = builtin_profiles()
            .into_iter()
            .map(|b| self.profiles.get(&b.name).cloned().unwrap_or(b))
            .collect();
        out.extend(
            self.profiles
                .values()
                .filter(|p| p.name != PROFILE_DEFAULT && p.name != PROFILE_FAST)
                .cloned(),
        );
        out
    }
}

/// One session the engine wants: who asked for it and with which timers.
/// Built from the peers here, and later from BGP, OSPF and static routes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BfdKey {
    pub peer: IpAddr,
    pub multihop: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<IpAddr>,
}

/// The sessions the config asks for, each with its users ("peer bfd1",
/// later "BGP upstream-a", "OSPF ether1") and the profile of the first
/// user (sorted).
pub fn wanted_sessions(cfg: &BfdConfig) -> BTreeMap<BfdKey, (BfdProfile, Vec<String>)> {
    let mut out: BTreeMap<BfdKey, (BfdProfile, Vec<String>)> = BTreeMap::new();
    for p in cfg.peers.values().filter(|p| !p.disabled) {
        let Some(prof) = cfg.profile(&p.profile) else {
            continue;
        };
        let key = BfdKey {
            peer: p.address,
            multihop: p.multihop,
            local: p.local_address,
        };
        out.entry(key)
            .or_insert_with(|| (prof, Vec::new()))
            .1
            .push(format!("peer {}", p.name));
    }
    out
}

/// What `routing.bfd.session.list` shows of one session (published by the
/// service; µs timings as the protocol carries them).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct BfdSessionStatus {
    pub peer: Option<IpAddr>,
    pub local: Option<IpAddr>,
    pub multihop: bool,
    pub users: Vec<String>,
    pub profile: String,
    /// up | down | init | admin-down
    pub state: String,
    pub remote_state: String,
    pub diag: String,
    /// Reported down to clients while dampened.
    pub dampened: bool,
    pub penalty: u32,
    pub local_discr: u32,
    pub remote_discr: u32,
    pub tx_interval_us: u32,
    pub remote_min_rx_us: u32,
    pub remote_desired_tx_us: u32,
    pub multiplier: u8,
    pub remote_multiplier: u8,
    pub detect_time_us: u64,
    pub packets_tx: u64,
    pub packets_rx: u64,
    pub dropped: u64,
    pub state_changes: u64,
    pub flaps_24h: u32,
    /// Unix seconds of the last state change.
    pub last_change: Option<u64>,
    /// p99 of how late our periodic packets left (engine load), µs.
    pub tx_jitter_p99_us: Option<u64>,
    /// p99 of the gap between received packets, µs (margin to the detect time).
    pub rx_gap_p99_us: Option<u64>,
    pub thread: u16,
}

/// One state change (`routing.bfd.history.list`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BfdEvent {
    /// Unix milliseconds.
    pub at_ms: u64,
    pub peer: IpAddr,
    pub multihop: bool,
    pub from: String,
    pub to: String,
    pub diag: String,
    pub users: Vec<String>,
    /// The detection time in force when it went down, µs.
    pub detect_time_us: u64,
    pub dampened: bool,
}

/// Per engine thread: what it carries and how busy it is.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct BfdThreadStatus {
    pub index: u16,
    pub sessions: u32,
    /// CPU used by the thread, % of one core (last interval).
    pub cpu_percent: f32,
    pub packets_in: u64,
    pub packets_out: u64,
    /// Packets handed to another thread (the reuseport program missed).
    pub forwarded: u64,
}

/// The service's state, kept in the session (`ext::<BfdState>`).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct BfdState {
    /// The service runs (false in a GUI without daemon).
    pub running: bool,
    pub sessions: Vec<BfdSessionStatus>,
    pub history: VecDeque<BfdEvent>,
    pub threads: Vec<BfdThreadStatus>,
    /// How packets reach their thread: "reuseport-cbpf" or "hash".
    pub steering: String,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_and_overrides() {
        let mut c = BfdConfig::default();
        assert_eq!(c.profile("fast").unwrap().min_tx, 50);
        assert_eq!(c.profile("default").unwrap().detect_ms(), 900);
        assert!(c.profile("nope").is_none());
        let mut f = BfdProfile::new("fast", 100, 3);
        f.comment = "mine".into();
        c.profiles.insert("fast".into(), f);
        c.profiles.insert("wan".into(), BfdProfile::new("wan", 500, 5));
        let all = c.all_profiles();
        assert_eq!(all.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["default", "fast", "wan"]);
        assert_eq!(all[1].min_tx, 100);
    }

    #[test]
    fn peers_become_sessions_with_users() {
        let mut c = BfdConfig::default();
        for (n, a) in [("a", "10.0.0.2"), ("b", "10.0.0.2"), ("c", "10.0.0.3")] {
            c.peers.insert(
                n.into(),
                BfdPeer {
                    name: n.into(),
                    address: a.parse().unwrap(),
                    local_address: None,
                    interface: None,
                    multihop: false,
                    profile: "fast".into(),
                    disabled: n == "c",
                    comment: String::new(),
                },
            );
        }
        let w = wanted_sessions(&c);
        assert_eq!(w.len(), 1);
        let (p, users) = w.values().next().unwrap();
        assert_eq!(p.name, "fast");
        assert_eq!(users, &["peer a", "peer b"]);
    }

    #[test]
    fn key_stays_out_of_debug_json_when_empty() {
        let mut p = BfdProfile::new("x", 300, 3);
        assert!(!serde_json::to_string(&p).unwrap().contains("auth_secret\""));
        p.auth_secret = BfdKeyText("hunter2".into());
        assert!(!format!("{p:?}").contains("hunter2"));
    }
}
