//! `/ip dns` (G4.1a): the servers the router asks and how it caches the
//! answers. The same section configures the LAN forwarder (G4.1b,
//! `allow_remote_requests`) and the full server (G4.1c), so it holds only
//! what both share; static records and zones get sections of their own.
//!
//! Names and defaults follow RouterOS v7 (`/ip dns`); times are in
//! milliseconds or seconds (the suffix says which) instead of `2s`/`1w`
//! strings, like the rest of the config.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// At most this many static servers (RouterOS has no fixed limit; a lookup
/// asks them one by one, so a long list only adds waiting).
pub const MAX_SERVERS: usize = 8;
/// `cache_size` range, in KiB. RouterOS default 2048.
pub const CACHE_SIZE_KIB: std::ops::RangeInclusive<u32> = 0..=1_048_576;
pub const DEFAULT_CACHE_SIZE_KIB: u32 = 2048;
/// RouterOS `cache-max-ttl` default: one week.
pub const DEFAULT_CACHE_MAX_TTL_SECS: u32 = 604_800;
/// RFC 2181 §8: a TTL is at most 2^31 − 1 seconds.
pub const MAX_TTL_SECS: u32 = i32::MAX as u32;
pub const DEFAULT_SERVER_TIMEOUT_MS: u32 = 2000;
pub const DEFAULT_TOTAL_TIMEOUT_MS: u32 = 10_000;
pub const SERVER_TIMEOUT_MS: std::ops::RangeInclusive<u32> = 100..=60_000;
pub const TOTAL_TIMEOUT_MS: std::ops::RangeInclusive<u32> = 100..=600_000;
/// EDNS(0) payload we advertise (RFC 6891 §6.2.5). RouterOS defaults to
/// 4096; 1232 is the DNS Flag Day 2020 value, which avoids IP fragmentation
/// (lost fragments look like a dead server).
pub const DEFAULT_MAX_UDP_PACKET_SIZE: u16 = 1232;
/// RFC 1035 §2.3.4: 512 is the classic limit; 65507 the UDP maximum.
pub const UDP_PACKET_SIZE: std::ops::RangeInclusive<u16> = 512..=65_507;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dns {
    /// Static upstream servers, asked in order before the dynamic ones.
    pub servers: Vec<IpAddr>,
    /// Answer queries from the LAN (G4.1b). Accepted now, no listener yet.
    pub allow_remote_requests: bool,
    /// Cache budget in KiB; 0 turns the cache off.
    pub cache_size: u32,
    /// Answers are kept at most this long, whatever their TTL says.
    pub cache_max_ttl_secs: u32,
    /// How long to wait for one server before asking the next.
    pub query_server_timeout_ms: u32,
    /// How long one lookup may take in total, all servers included.
    pub query_total_timeout_ms: u32,
    pub max_udp_packet_size: u16,
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            allow_remote_requests: false,
            cache_size: DEFAULT_CACHE_SIZE_KIB,
            cache_max_ttl_secs: DEFAULT_CACHE_MAX_TTL_SECS,
            query_server_timeout_ms: DEFAULT_SERVER_TIMEOUT_MS,
            query_total_timeout_ms: DEFAULT_TOTAL_TIMEOUT_MS,
            max_udp_packet_size: DEFAULT_MAX_UDP_PACKET_SIZE,
        }
    }
}

impl Dns {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Why this section cannot be committed, if anything is wrong.
    pub fn problem(&self) -> Option<String> {
        if self.servers.len() > MAX_SERVERS {
            return Some(format!("at most {MAX_SERVERS} DNS servers"));
        }
        if let Some(bad) = self.servers.iter().find(|ip| !usable_server(**ip)) {
            return Some(format!(
                "{bad} cannot be a DNS server (unspecified, multicast or broadcast)"
            ));
        }
        if !CACHE_SIZE_KIB.contains(&self.cache_size) {
            return Some(format!("cache_size must be {CACHE_SIZE_KIB:?} KiB"));
        }
        if self.cache_max_ttl_secs > MAX_TTL_SECS {
            return Some(format!(
                "cache_max_ttl_secs must be at most {MAX_TTL_SECS} (RFC 2181 §8)"
            ));
        }
        if !SERVER_TIMEOUT_MS.contains(&self.query_server_timeout_ms) {
            return Some(format!(
                "query_server_timeout_ms must be {SERVER_TIMEOUT_MS:?}"
            ));
        }
        if !TOTAL_TIMEOUT_MS.contains(&self.query_total_timeout_ms) {
            return Some(format!("query_total_timeout_ms must be {TOTAL_TIMEOUT_MS:?}"));
        }
        if self.query_total_timeout_ms < self.query_server_timeout_ms {
            return Some(format!(
                "query_total_timeout_ms ({}) must not be below query_server_timeout_ms ({}): \
                 not even the first server would get its full wait",
                self.query_total_timeout_ms, self.query_server_timeout_ms
            ));
        }
        if !UDP_PACKET_SIZE.contains(&self.max_udp_packet_size) {
            return Some(format!("max_udp_packet_size must be {UDP_PACKET_SIZE:?}"));
        }
        None
    }
}

/// An address that can answer queries.
pub fn usable_server(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
}

/// Record type of a cached answer (the resolver asks only for addresses).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum QType {
    A,
    Aaaa,
}

impl QType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
        }
    }
}

/// What the cache holds for one name and type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum CachedData {
    /// Addresses, and the canonical name when the answer came via CNAME.
    Addresses {
        addresses: Vec<IpAddr>,
        canonical: Option<String>,
    },
    /// RFC 2308 §2.1: the name does not exist.
    NxDomain,
    /// RFC 2308 §2.2: the name exists, without records of this type.
    NoData,
}

/// One row of `ip.dns.cache.print`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheRow {
    pub name: String,
    #[serde(rename = "type")]
    pub qtype: QType,
    #[serde(flatten)]
    pub data: CachedData,
    /// Seconds left.
    pub ttl: u32,
    /// The server that answered.
    pub server: Option<IpAddr>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_follow_routeros() {
        let d = Dns::default();
        assert!(d.servers.is_empty() && !d.allow_remote_requests);
        assert_eq!(d.cache_size, 2048);
        assert_eq!(d.cache_max_ttl_secs, 7 * 24 * 3600);
        assert_eq!((d.query_server_timeout_ms, d.query_total_timeout_ms), (2000, 10_000));
        assert_eq!(d.problem(), None);
        let back: Dns = serde_json::from_str("{}").unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn problems_are_found() {
        let bad = |f: fn(&mut Dns)| {
            let mut d = Dns::default();
            f(&mut d);
            d.problem().is_some()
        };
        assert!(bad(|d| d.servers = vec!["0.0.0.0".parse().unwrap()]));
        assert!(bad(|d| d.servers = vec!["224.0.0.1".parse().unwrap()]));
        assert!(bad(|d| d.servers = vec!["255.255.255.255".parse().unwrap()]));
        assert!(bad(|d| d.query_total_timeout_ms = 1000));
        assert!(bad(|d| d.cache_max_ttl_secs = u32::MAX));
        assert!(bad(|d| d.max_udp_packet_size = 100));
        assert!(!bad(|d| d.servers = vec!["2001:db8::53".parse().unwrap()]));
    }

    #[test]
    fn cache_rows_serialize_flat() {
        let row = CacheRow {
            name: "example.com".into(),
            qtype: QType::Aaaa,
            data: CachedData::NxDomain,
            ttl: 5,
            server: None,
        };
        let v = serde_json::to_value(&row).unwrap();
        assert_eq!(v["type"], "AAAA");
        assert_eq!(v["kind"], "nx-domain");
    }
}
