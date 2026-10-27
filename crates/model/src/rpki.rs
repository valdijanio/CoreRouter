//! RPKI origin validation (G3.2c), as RouterOS v7 `/routing rpki` models
//! it: each entry is one RPKI-to-Router (RTR, RFC 8210) connection to a
//! validator (Routinator, rpki-client, StayRTR, FORT…), in a group.
//!
//! What a BGP connection does with an invalid route is its `rpki_invalid`
//! parameter (`crate::bgp::BgpParams`): `reject` unless set otherwise, as
//! soon as one validator is configured (RFC 8481 §5: the policy applies
//! only with operator configuration, and adding a validator is it; the
//! add answer and the window say so). See `docs/bgp.md` ("RPKI").

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// IANA port of `rpki-rtr` over TCP (RFC 6810, IANA Considerations).
pub const DEFAULT_PORT: u16 = 323;
/// The group an entry joins when none is given.
pub const DEFAULT_GROUP: &str = "default";
/// RFC 8210 §6 ranges, seconds.
pub const REFRESH_RANGE: (u32, u32) = (1, 86_400);
pub const RETRY_RANGE: (u32, u32) = (1, 7_200);
pub const EXPIRE_RANGE: (u32, u32) = (600, 172_800);
/// RFC 8210 §6 defaults, seconds (used until the cache's End of Data
/// gives its own).
pub const DEFAULT_REFRESH: u32 = 3_600;
pub const DEFAULT_RETRY: u32 = 600;
pub const DEFAULT_EXPIRE: u32 = 7_200;
/// Most validators configured (each is a TCP session and a table).
pub const MAX_CACHES: usize = 16;

/// One RTR connection to a validator (RouterOS `/routing rpki` entry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpkiCache {
    pub name: String,
    /// RouterOS `group`: the database the entry feeds.
    #[serde(default = "default_group")]
    pub group: String,
    pub address: IpAddr,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Seconds between polls; unset: the cache's own (End of Data).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_interval: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_interval: Option<u32>,
    /// How long the data stays usable without a successful poll.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_interval: Option<u32>,
    /// Higher is preferred (RouterOS); unset: the lowest address wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preference: Option<u8>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

fn default_group() -> String {
    DEFAULT_GROUP.to_owned()
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

/// What a BGP connection does with a route RPKI says is invalid
/// (RFC 6811 §2): `reject` (the default) or `accept` (validated and
/// shown, not dropped).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RpkiInvalid {
    #[default]
    Reject,
    Accept,
}

impl RpkiInvalid {
    pub fn name(self) -> &'static str {
        match self {
            RpkiInvalid::Reject => "reject",
            RpkiInvalid::Accept => "accept",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "reject" => Some(RpkiInvalid::Reject),
            "accept" => Some(RpkiInvalid::Accept),
            _ => None,
        }
    }
}

/// RFC 6811 §2 validation state, with RouterOS names (`unknown` is the
/// RFC's NotFound) and RouterOS' `unverified`: no validator of the group
/// is in sync, so nothing can be said.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RpkiState {
    Valid,
    Invalid,
    Unknown,
    Unverified,
}

impl RpkiState {
    pub const ALL: [RpkiState; 4] = [
        RpkiState::Valid,
        RpkiState::Invalid,
        RpkiState::Unknown,
        RpkiState::Unverified,
    ];

    pub fn name(self) -> &'static str {
        match self {
            RpkiState::Valid => "valid",
            RpkiState::Invalid => "invalid",
            RpkiState::Unknown => "unknown",
            RpkiState::Unverified => "unverified",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "notfound" | "not-found" => Some(RpkiState::Unknown),
            _ => Self::ALL.into_iter().find(|r| r.name() == s),
        }
    }
}

/// One RTR session as `routing.rpki.session.list` shows it (RouterOS
/// `/routing rpki session`), filled by the daemon's `rpki` service.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RpkiSession {
    pub name: String,
    pub group: String,
    pub address: String,
    pub port: u16,
    /// RouterOS states: `idle`, `connecting`, `loading` (Reset Query
    /// answered, data arriving), `sync` (End of Data seen), `error`.
    pub state: String,
    /// RTR protocol version spoken (0: RFC 6810, 1: RFC 8210).
    pub version: Option<u8>,
    /// The cache's Session ID and the serial of the data held.
    pub session_id: Option<u16>,
    pub serial: Option<u32>,
    /// VRPs held, per family (RouterOS: the "ROAs"; one ROA may give many).
    pub ipv4: u64,
    pub ipv6: u64,
    /// Router keys (BGPsec, RFC 8210 §5.10) the cache sent; kept counted.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub router_keys: u64,
    /// Unix time of the last End of Data, and when the data expires.
    pub last_update: Option<u64>,
    pub expires: Option<u64>,
    /// Timers in force (the cache's, or the entry's when set).
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    /// Why the session is down, or the last Error Report.
    pub error: Option<String>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// What the RPKI side knows, for the windows and the commands.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RpkiStatus {
    /// Unix time of the last sample.
    pub updated: Option<u64>,
    pub sessions: Vec<RpkiSession>,
    /// FRR's own RTR state (`show rpki cache-connection`), when FRR runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frr: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_names() {
        let c: RpkiCache = serde_json::from_str(r#"{"name":"r1","address":"192.0.2.10"}"#).unwrap();
        assert_eq!((c.port, c.group.as_str()), (DEFAULT_PORT, DEFAULT_GROUP));
        assert_eq!(RpkiState::parse("notfound"), Some(RpkiState::Unknown));
        for s in RpkiState::ALL {
            assert_eq!(RpkiState::parse(s.name()), Some(s));
        }
        assert_eq!(RpkiInvalid::default(), RpkiInvalid::Reject);
        assert_eq!(RpkiInvalid::parse("accept"), Some(RpkiInvalid::Accept));
    }
}
