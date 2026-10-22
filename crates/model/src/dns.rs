//! `/ip dns` (G4.1a): the servers the router asks and how it caches the
//! answers. The same section configures the LAN forwarder (G4.1b,
//! `allow_remote_requests`, `allowed_from`, limits) and the full server
//! (G4.1c), so it holds only what both share; static records
//! (`dns_static`) and zones get sections of their own.
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
/// Who may ask the LAN forwarder by default: the interface list `LAN`
/// (the RouterOS default configuration has it). Never an open resolver.
pub const DEFAULT_ALLOWED_FROM: &str = "LAN";
pub const MAX_ALLOWED_FROM: usize = 32;
/// Queries per second one client may send (a burst of twice that is
/// allowed). A browser opening a heavy page asks ~50 names; 200/s stops
/// only floods and reflection.
pub const DEFAULT_MAX_QUERIES_PER_CLIENT: u32 = 200;
pub const QUERIES_PER_CLIENT: std::ops::RangeInclusive<u32> = 0..=100_000;
/// RFC 8767 §5: serve stale for "1 to 3 days" after the TTL; 1 day here.
pub const DEFAULT_SERVE_STALE_SECS: u32 = 86_400;
pub const SERVE_STALE_SECS: std::ops::RangeInclusive<u32> = 0..=604_800;
/// RouterOS defaults.
pub const DEFAULT_MAX_CONCURRENT_QUERIES: u32 = 100;
pub const DEFAULT_MAX_CONCURRENT_TCP_SESSIONS: u32 = 20;
/// Each concurrent query or TCP session is a thread of the daemon.
pub const CONCURRENCY: std::ops::RangeInclusive<u32> = 1..=1000;

/// How the upstream servers are tried.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServerSelection {
    /// The fastest server that answers (latency measured on every
    /// answer); a failing one drops to the end until it answers again.
    #[default]
    Fastest,
    /// RouterOS: in list order, the last one that answered first.
    Sequential,
}

impl ServerSelection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fastest => "fastest",
            Self::Sequential => "sequential",
        }
    }
}

impl std::str::FromStr for ServerSelection {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim() {
            "fastest" => Ok(Self::Fastest),
            "sequential" => Ok(Self::Sequential),
            _ => Err("must be fastest or sequential".into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dns {
    /// Static upstream servers, asked in order before the dynamic ones.
    pub servers: Vec<IpAddr>,
    /// Answer queries from the LAN on UDP/TCP 53 (G4.1b).
    pub allow_remote_requests: bool,
    /// Who may ask: interface lists (`LAN`: the networks of its
    /// interfaces' addresses) and prefixes. Anyone else gets REFUSED.
    /// The router itself (loopback) may always ask.
    pub allowed_from: Vec<String>,
    /// Queries per second per client (IPv6: per /64); 0 = no limit.
    pub max_queries_per_client: u32,
    pub server_selection: ServerSelection,
    /// RFC 8767: when no upstream answers, an expired answer is served for
    /// up to this long after its TTL ran out; 0 = never.
    pub serve_stale_secs: u32,
    /// Upstream lookups in flight for the LAN; more get SERVFAIL.
    pub max_concurrent_queries: u32,
    pub max_concurrent_tcp_sessions: u32,
    /// Added to the TTL of an address put in a firewall address list by a
    /// static entry's `address_list` (RouterOS `address-list-extra-time`).
    pub address_list_extra_time_secs: u32,
    /// Cache budget in KiB; 0 turns the cache off.
    pub cache_size: u32,
    /// Answers are kept at most this long, whatever their TTL says.
    pub cache_max_ttl_secs: u32,
    /// How long to wait for one server before asking the next.
    pub query_server_timeout_ms: u32,
    /// How long one lookup may take in total, all servers included.
    pub query_total_timeout_ms: u32,
    pub max_udp_packet_size: u16,
    /// G4.1d: ask this encrypted server instead of `servers` (which then
    /// only resolve its name): `https://host/path` (DoH, RFC 8484) or
    /// `tls://host[:853][#name]` (DoT, RFC 7858). Empty: off.
    pub use_doh_server: String,
    /// Check the encrypted server's certificate (RFC 8310 strict profile).
    /// RouterOS defaults to no; the Mozilla roots are built in here.
    pub verify_doh_cert: bool,
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            allow_remote_requests: false,
            allowed_from: vec![DEFAULT_ALLOWED_FROM.to_owned()],
            max_queries_per_client: DEFAULT_MAX_QUERIES_PER_CLIENT,
            server_selection: ServerSelection::default(),
            serve_stale_secs: DEFAULT_SERVE_STALE_SECS,
            max_concurrent_queries: DEFAULT_MAX_CONCURRENT_QUERIES,
            max_concurrent_tcp_sessions: DEFAULT_MAX_CONCURRENT_TCP_SESSIONS,
            address_list_extra_time_secs: 0,
            cache_size: DEFAULT_CACHE_SIZE_KIB,
            cache_max_ttl_secs: DEFAULT_CACHE_MAX_TTL_SECS,
            query_server_timeout_ms: DEFAULT_SERVER_TIMEOUT_MS,
            query_total_timeout_ms: DEFAULT_TOTAL_TIMEOUT_MS,
            max_udp_packet_size: DEFAULT_MAX_UDP_PACKET_SIZE,
            use_doh_server: String::new(),
            verify_doh_cert: true,
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
        if let Some(why) = secure_url_problem(&self.use_doh_server) {
            return Some(format!("use_doh_server: {why}"));
        }
        if !UDP_PACKET_SIZE.contains(&self.max_udp_packet_size) {
            return Some(format!("max_udp_packet_size must be {UDP_PACKET_SIZE:?}"));
        }
        if self.allowed_from.len() > MAX_ALLOWED_FROM {
            return Some(format!("allowed_from takes at most {MAX_ALLOWED_FROM} items"));
        }
        if let Some(bad) = self.allowed_from.iter().find(|a| AllowedFrom::parse(a).is_err()) {
            let shown: String = bad.chars().take(64).collect();
            return Some(format!(
                "allowed_from: '{shown}' is neither a prefix (192.168.88.0/24) nor an interface list name"
            ));
        }
        if !QUERIES_PER_CLIENT.contains(&self.max_queries_per_client) {
            return Some(format!("max_queries_per_client must be {QUERIES_PER_CLIENT:?}"));
        }
        if !SERVE_STALE_SECS.contains(&self.serve_stale_secs) {
            return Some(format!("serve_stale_secs must be {SERVE_STALE_SECS:?}"));
        }
        if !CONCURRENCY.contains(&self.max_concurrent_queries)
            || !CONCURRENCY.contains(&self.max_concurrent_tcp_sessions)
        {
            return Some(format!(
                "max_concurrent_queries and max_concurrent_tcp_sessions must be {CONCURRENCY:?}"
            ));
        }
        if self.address_list_extra_time_secs > MAX_TTL_SECS {
            return Some(format!("address_list_extra_time_secs must be at most {MAX_TTL_SECS}"));
        }
        None
    }
}

/// One item of `allowed_from`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedFrom {
    Net(ipnet::IpNet),
    /// An interface list: the networks of its interfaces' addresses.
    List(String),
}

impl AllowedFrom {
    pub fn parse(text: &str) -> Result<Self, String> {
        let t = text.trim();
        if let Ok(ip) = t.parse::<IpAddr>() {
            return Ok(Self::Net(ipnet::IpNet::from(ip)));
        }
        if let Ok(net) = t.parse::<ipnet::IpNet>() {
            return Ok(Self::Net(net.trunc()));
        }
        let name_ok = (1..=64).contains(&t.len())
            && t
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
        if name_ok && !t.contains('/') {
            Ok(Self::List(t.to_owned()))
        } else {
            Err("not a prefix or a list name".into())
        }
    }
}

/// Longest encrypted server address.
pub const MAX_SECURE_URL_LEN: usize = 512;

/// Why `url` cannot name an encrypted DNS server (`""` is fine: none).
/// The full parse is `proto-dns` (`encrypted.rs`); this is the shape.
pub fn secure_url_problem(url: &str) -> Option<String> {
    if url.is_empty() {
        return None;
    }
    let shown: String = url.chars().take(64).collect();
    if url.len() > MAX_SECURE_URL_LEN {
        return Some(format!("at most {MAX_SECURE_URL_LEN} characters"));
    }
    if !(url.starts_with("https://") || url.starts_with("tls://")) {
        return Some(format!(
            "'{shown}' must be https://host/path (DoH) or tls://host[#name] (DoT)"
        ));
    }
    if url.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Some(format!("'{shown}' has spaces or control characters"));
    }
    None
}

/// An address that can answer queries.
pub fn usable_server(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
}

/// What a cache entry says (RFC 2308 for the negative ones).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheKind {
    /// Records of the type asked (maybe behind a CNAME chain).
    Records,
    /// RFC 2308 §2.1: the name does not exist.
    NxDomain,
    /// RFC 2308 §2.2: the name exists, without records of this type.
    NoData,
}

/// One row of `ip.dns.cache.print`: one name and type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheRow {
    pub name: String,
    /// Record type asked (`A`, `MX`, `TYPE65`…).
    #[serde(rename = "type")]
    pub qtype: String,
    pub kind: CacheKind,
    /// The records, as text (`CNAME edge.example`, `A 192.0.2.7`).
    pub data: Vec<String>,
    /// The addresses among them (A/AAAA), for a quick look.
    pub addresses: Vec<IpAddr>,
    /// Seconds left (0 for a stale one).
    pub ttl: u32,
    /// Answers given from this entry.
    pub hits: u64,
    /// The server that answered.
    pub server: Option<IpAddr>,
    /// Expired, kept to be served stale if the servers fail (RFC 8767).
    pub stale: bool,
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
        assert!(bad(|d| d.allowed_from = vec!["10.0.0.0/33".into()]));
        assert!(bad(|d| d.allowed_from = vec!["bad list!".into()]));
        assert!(!bad(|d| d.allowed_from = vec!["10.0.0.0/8".into(), "LAN".into(), "2001:db8::1".into()]));
        assert!(bad(|d| d.max_concurrent_queries = 0));
        assert!(bad(|d| d.serve_stale_secs = 999_999));
    }

    #[test]
    fn allowed_from_items() {
        assert_eq!(AllowedFrom::parse("LAN"), Ok(AllowedFrom::List("LAN".into())));
        assert_eq!(
            AllowedFrom::parse("192.168.88.7/24"),
            Ok(AllowedFrom::Net("192.168.88.0/24".parse().unwrap()))
        );
        assert_eq!(
            AllowedFrom::parse("192.0.2.1"),
            Ok(AllowedFrom::Net("192.0.2.1/32".parse().unwrap()))
        );
    }

    #[test]
    fn cache_rows_serialize_flat() {
        let row = CacheRow {
            name: "example.com".into(),
            qtype: "AAAA".into(),
            kind: CacheKind::NxDomain,
            data: Vec::new(),
            addresses: Vec::new(),
            ttl: 5,
            hits: 0,
            server: None,
            stale: false,
        };
        let v = serde_json::to_value(&row).unwrap();
        assert_eq!(v["type"], "AAAA");
        assert_eq!(v["kind"], "nx-domain");
    }
}
