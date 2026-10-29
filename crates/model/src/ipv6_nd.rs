//! `/ipv6 nd` and `/ipv6 nd prefix` (G3.9ha): where CoreRouter sends
//! Router Advertisements and what they say (RFC 4861 §6.2). Only the
//! configuration lives here; which interfaces actually advertise, the
//! counters and the deprecated prefixes are the engine's and the daemon's.
//!
//! Defaults are RouterOS v7's: `ra-interval` 3m20s-10m, `ra-delay` 3s,
//! `ra-lifetime` 30m, `hop-limit` 64 (RouterOS: unspecified), prefixes
//! valid 4w2d and preferred 1w with L and A set. Unlike RouterOS a new
//! config has **no** `interface=all` entry: RA on a WAN port makes the
//! provider's hosts take this router as their gateway.

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

use ipnet::Ipv6Net;
use serde::{Deserialize, Serialize};

use crate::types::{IfName, ItemId, ParseError};

/// At most this many `/ipv6 nd` entries and static prefixes
/// (**estimado**: one per VLAN of a large access switch).
pub const MAX_INTERFACES: usize = 4096;
pub const MAX_PREFIXES: usize = 4096;
/// Prefix Information options in one RA (RFC 4861 §4.6.2 sets no limit;
/// 8 keeps the RA well under the 1280-byte minimum MTU, RFC 6980).
pub const MAX_PREFIXES_PER_RA: usize = 8;

/// The interface name of the entry that covers every interface.
pub const ALL: &str = "all";

/// RDNSS addresses and DNSSL names one entry carries (RFC 8106 sets no
/// limit; the BNG's codec sends at most 8 of each).
pub const MAX_DNS: usize = 8;
/// RFC 9096 §3.4 (L-16): a prefix from DHCPv6-PD is advertised with at
/// most these lifetimes, so a CE router that lost its PD stops a LAN
/// from using a dead prefix within 45 min.
pub const ND_PREFERRED_LIMIT: u32 = 2700;
pub const ND_VALID_LIMIT: u32 = 5400;

/// RFC 4861 §6.2.1 (as updated by RFC 8319 §4): MaxRtrAdvInterval 4..=65535 s.
pub const MAX_INTERVAL_RANGE: (u32, u32) = (4, 65_535);
/// MinRtrAdvInterval: at least 3 s and at most 0.75 × Max.
pub const MIN_INTERVAL_FLOOR: u32 = 3;
/// AdvDefaultLifetime: 0 or Max..=65535 s (RFC 8319 §4; RFC 4861 had 9000).
pub const MAX_ROUTER_LIFETIME: u32 = 65_535;
/// AdvReachableTime: at most 3 600 000 ms (§6.2.1).
pub const MAX_REACHABLE_MS: u32 = 3_600_000;
/// "infinity" for a prefix lifetime (§4.6.2: all ones).
pub const INFINITY: u32 = u32::MAX;

/// Default Router Preference (RFC 4191 §2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RaPreference {
    Low,
    #[default]
    Medium,
    High,
}

impl RaPreference {
    pub fn as_str(self) -> &'static str {
        match self {
            RaPreference::Low => "low",
            RaPreference::Medium => "medium",
            RaPreference::High => "high",
        }
    }

    /// The two Prf bits (RFC 4191 §2.2: 01 high, 00 medium, 11 low).
    pub fn bits(self) -> u8 {
        match self {
            RaPreference::High => 0b01,
            RaPreference::Medium => 0b00,
            RaPreference::Low => 0b11,
        }
    }
}

impl FromStr for RaPreference {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "low" => Ok(RaPreference::Low),
            "medium" => Ok(RaPreference::Medium),
            "high" => Ok(RaPreference::High),
            _ => Err(ParseError::new("ra-preference", s, "low | medium | high")),
        }
    }
}

impl fmt::Display for RaPreference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Nd {
    /// `/ipv6 nd`: at most one entry per interface (and one `all`).
    pub interfaces: Vec<NdInterface>,
    /// `/ipv6 nd prefix`, the static ones. The dynamic ones come from the
    /// interface's own global /64 addresses; a static entry with the same
    /// prefix and interface replaces the dynamic one (a disabled one hides
    /// it).
    pub prefixes: Vec<NdPrefix>,
    pub next_id: u32,
    pub next_prefix_id: u32,
}

impl Nd {
    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty() && self.prefixes.is_empty()
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    pub fn next_prefix_id(&mut self) -> ItemId {
        self.next_prefix_id = self.next_prefix_id.saturating_add(1);
        ItemId(self.next_prefix_id)
    }
}

/// One `/ipv6 nd` entry: the RA of `interface` (or of every eligible
/// interface, with `all`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NdInterface {
    pub id: ItemId,
    /// An interface name, or [`ALL`].
    pub interface: IfName,
    /// MinRtrAdvInterval and MaxRtrAdvInterval, seconds.
    #[serde(default = "default_min")]
    pub ra_interval_min: u32,
    #[serde(default = "default_max")]
    pub ra_interval_max: u32,
    /// RouterOS `ra-delay`: the least time between two multicast RAs
    /// (RFC 4861 MIN_DELAY_BETWEEN_RAS, 3 s), seconds.
    #[serde(default = "default_delay")]
    pub ra_delay: u32,
    /// AdvDefaultLifetime, seconds (0: not a default router).
    #[serde(default = "default_lifetime")]
    pub ra_lifetime: u32,
    #[serde(default)]
    pub ra_preference: RaPreference,
    /// AdvCurHopLimit (0: unspecified).
    #[serde(default = "default_hop_limit")]
    pub hop_limit: u8,
    /// AdvLinkMTU (None: no MTU option).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    /// AdvReachableTime and AdvRetransTimer, milliseconds (0: unspecified).
    #[serde(default)]
    pub reachable_time: u32,
    #[serde(default)]
    pub retransmit_interval: u32,
    /// M flag: addresses by DHCPv6.
    #[serde(default)]
    pub managed_address_configuration: bool,
    /// O flag: other configuration by DHCPv6.
    #[serde(default)]
    pub other_configuration: bool,
    /// Source Link-Layer Address option (RFC 4861 §4.2: SHOULD be sent).
    #[serde(default = "yes")]
    pub advertise_mac_address: bool,
    /// RDNSS (RFC 8106 §5.1): `dns`, or else the router itself when it
    /// answers queries (`ip.dns allow_remote_requests`), or else the IPv6
    /// servers of `/ip dns` and those learned by DHCPv6.
    #[serde(default)]
    pub advertise_dns: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<Ipv6Addr>,
    /// DNSSL (RFC 8106 §5.2): search domains, sent with `advertise_dns`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dnssl: Vec<String>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

fn yes() -> bool {
    true
}
fn default_min() -> u32 {
    200
}
fn default_max() -> u32 {
    600
}
fn default_delay() -> u32 {
    3
}
fn default_lifetime() -> u32 {
    1800
}
fn default_hop_limit() -> u8 {
    64
}

impl NdInterface {
    pub fn new(id: ItemId, interface: IfName) -> Self {
        Self {
            id,
            interface,
            ra_interval_min: default_min(),
            ra_interval_max: default_max(),
            ra_delay: default_delay(),
            ra_lifetime: default_lifetime(),
            ra_preference: RaPreference::Medium,
            hop_limit: default_hop_limit(),
            mtu: None,
            reachable_time: 0,
            retransmit_interval: 0,
            managed_address_configuration: false,
            other_configuration: false,
            advertise_mac_address: true,
            advertise_dns: false,
            dns: Vec::new(),
            dnssl: Vec::new(),
            disabled: false,
            comment: String::new(),
        }
    }

    pub fn is_all(&self) -> bool {
        self.interface.as_str() == ALL
    }

    /// What is wrong with the entry's numbers, as (field, why); RFC 4861
    /// §6.2.1 with RFC 8319.
    pub fn issues(&self) -> Option<(&'static str, String)> {
        let (lo, hi) = MAX_INTERVAL_RANGE;
        let max = self.ra_interval_max;
        if !(lo..=hi).contains(&max) {
            return Some((
                "ra_interval",
                format!("the maximum must be {lo}s..{hi}s (RFC 4861 §6.2.1, RFC 8319)"),
            ));
        }
        // §6.2.1: MinRtrAdvInterval ≥ 3 s and ≤ 0.75 × MaxRtrAdvInterval.
        let top = max.saturating_mul(3) / 4;
        if self.ra_interval_min < MIN_INTERVAL_FLOOR || self.ra_interval_min > top {
            return Some((
                "ra_interval",
                format!(
                    "the minimum must be 3s..{top}s, at most 0.75 × the maximum (RFC 4861 §6.2.1)"
                ),
            ));
        }
        if self.ra_lifetime != 0
            && (self.ra_lifetime < max || self.ra_lifetime > MAX_ROUTER_LIFETIME)
        {
            return Some((
                "ra_lifetime",
                format!(
                    "0 (not a default router) or {max}s..{MAX_ROUTER_LIFETIME}s, at least the \
                     maximum interval (RFC 4861 §6.2.1, RFC 8319)"
                ),
            ));
        }
        if !(1..=60).contains(&self.ra_delay) {
            return Some(("ra_delay", "1s..60s".into()));
        }
        if self.reachable_time > MAX_REACHABLE_MS {
            return Some((
                "reachable_time",
                "at most 3600000 ms (1h, RFC 4861 §6.2.1)".into(),
            ));
        }
        if self.dns.len() > MAX_DNS || self.dnssl.len() > MAX_DNS {
            return Some(("dns", format!("at most {MAX_DNS} servers and {MAX_DNS} search domains")));
        }
        if let Some(a) = self.dns.iter().find(|a| a.is_multicast() || a.is_unspecified() || a.is_loopback()) {
            return Some(("dns", format!("{a} is not a unicast server address")));
        }
        if let Some(d) = self.dnssl.iter().find(|d| !valid_domain(d)) {
            return Some(("dnssl", format!("'{}' is not a domain name (RFC 1035 labels)", d.chars().take(64).collect::<String>())));
        }
        if let Some(m) = self.mtu
            && !(1280..=65_535).contains(&m)
        {
            return Some(("mtu", "1280..65535 (RFC 8200 §5: the IPv6 minimum is 1280)".into()));
        }
        None
    }
}

/// A search domain the DNSSL option can carry (RFC 1035 §3.1).
pub fn valid_domain(d: &str) -> bool {
    let d = d.trim_end_matches('.');
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// RDNSS/DNSSL lifetime for MaxRtrAdvInterval `max` seconds: RFC 8106
/// §5.1 says at least 3 × MaxRtrAdvInterval by default.
pub fn dns_lifetime(max: u32) -> u32 {
    max.saturating_mul(3)
}

/// One `/ipv6 nd prefix` (Prefix Information option, RFC 4861 §4.6.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NdPrefix {
    pub id: ItemId,
    pub prefix: Ipv6Net,
    pub interface: IfName,
    /// Seconds; [`INFINITY`] is all ones.
    #[serde(default = "default_valid")]
    pub valid_lifetime: u32,
    #[serde(default = "default_preferred")]
    pub preferred_lifetime: u32,
    /// L flag.
    #[serde(default = "yes")]
    pub on_link: bool,
    /// A flag (SLAAC, RFC 4862 §5.5.3; hosts use it only on a /64).
    #[serde(default = "yes")]
    pub autonomous: bool,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

/// 4w2d (RouterOS).
pub fn default_valid() -> u32 {
    2_592_000
}
/// 1w (RouterOS).
pub fn default_preferred() -> u32 {
    604_800
}

impl NdPrefix {
    pub fn new(id: ItemId, prefix: Ipv6Net, interface: IfName) -> Self {
        Self {
            id,
            prefix: prefix.trunc(),
            interface,
            valid_lifetime: default_valid(),
            preferred_lifetime: default_preferred(),
            on_link: true,
            autonomous: true,
            disabled: false,
            comment: String::new(),
        }
    }

    pub fn issues(&self) -> Option<(&'static str, String)> {
        if self.preferred_lifetime > self.valid_lifetime {
            return Some((
                "preferred_lifetime",
                "must not exceed valid_lifetime (RFC 4861 §4.6.2)".into(),
            ));
        }
        let a = self.prefix.addr();
        if a.is_multicast() || a.is_unicast_link_local() || a.is_loopback() {
            return Some((
                "prefix",
                "link-local, multicast and loopback prefixes are not advertised (RFC 4861 §6.2.1)"
                    .into(),
            ));
        }
        None
    }
}

/// A lifetime as RouterOS writes it: `infinity`, or a duration.
pub fn lifetime_text(secs: u32) -> String {
    if secs == INFINITY {
        return "infinity".into();
    }
    let s = u64::from(secs);
    if s == 0 {
        return "0s".into();
    }
    let (w, d, h, m, x) = (
        s / 604_800,
        s / 86_400 % 7,
        s / 3600 % 24,
        s / 60 % 60,
        s % 60,
    );
    let mut out = String::new();
    for (n, unit) in [(w, "w"), (d, "d"), (h, "h"), (m, "m"), (x, "s")] {
        if n > 0 {
            out.push_str(&format!("{n}{unit}"));
        }
    }
    out
}

/// `infinity` or a RouterOS duration, as seconds that fit an option field.
pub fn parse_lifetime(text: &str) -> Option<u32> {
    let t = text.trim();
    if t == "infinity" {
        return Some(INFINITY);
    }
    let secs = crate::dhcp_server::parse_duration(t)?;
    u32::try_from(secs).ok().filter(|s| *s != INFINITY)
}

/// RouterOS' `ra-interval` (`3m20s-10m`, `3s-5s`) as (min, max) seconds.
pub fn parse_interval(text: &str) -> Option<(u32, u32)> {
    let (a, b) = text.trim().split_once('-')?;
    let a = u32::try_from(crate::dhcp_server::parse_duration(a)?).ok()?;
    let b = u32::try_from(crate::dhcp_server::parse_duration(b)?).ok()?;
    Some((a, b))
}

pub fn interval_text(min: u32, max: u32) -> String {
    format!("{}-{}", lifetime_text(min), lifetime_text(max))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> NdInterface {
        NdInterface::new(ItemId(1), "ether2".parse().unwrap())
    }

    #[test]
    fn defaults_follow_routeros_and_pass_rfc_4861() {
        let e = entry();
        assert_eq!(interval_text(e.ra_interval_min, e.ra_interval_max), "3m20s-10m");
        assert_eq!(lifetime_text(e.ra_lifetime), "30m");
        assert_eq!(e.issues(), None);
        let p = NdPrefix::new(ItemId(1), "2001:db8:1::5/64".parse().unwrap(), "ether2".parse().unwrap());
        assert_eq!(p.prefix.to_string(), "2001:db8:1::/64");
        assert_eq!(lifetime_text(p.valid_lifetime), "4w2d");
        assert_eq!(lifetime_text(p.preferred_lifetime), "1w");
        assert_eq!(p.issues(), None);
    }

    #[test]
    fn interval_rules_of_rfc_4861_6_2_1() {
        let mut e = entry();
        // Min ≤ 0.75 × Max: 3s-4s is valid (0.75 × 4 = 3).
        (e.ra_interval_min, e.ra_interval_max) = (3, 4);
        e.ra_lifetime = 0;
        assert_eq!(e.issues(), None);
        (e.ra_interval_min, e.ra_interval_max) = (4, 5);
        assert_eq!(e.issues().unwrap().0, "ra_interval");
        (e.ra_interval_min, e.ra_interval_max) = (2, 10);
        assert_eq!(e.issues().unwrap().0, "ra_interval");
        (e.ra_interval_min, e.ra_interval_max) = (3, 3);
        assert_eq!(e.issues().unwrap().0, "ra_interval");
        // Router lifetime 0, or at least Max, at most 65535 (RFC 8319).
        (e.ra_interval_min, e.ra_interval_max) = (200, 600);
        e.ra_lifetime = 300;
        assert_eq!(e.issues().unwrap().0, "ra_lifetime");
        e.ra_lifetime = 65_535;
        assert_eq!(e.issues(), None);
        e.ra_lifetime = 65_536;
        assert_eq!(e.issues().unwrap().0, "ra_lifetime");
    }

    #[test]
    fn texts_parse_back() {
        assert_eq!(parse_interval("3m20s-10m"), Some((200, 600)));
        assert_eq!(parse_interval("3s-5s"), Some((3, 5)));
        assert_eq!(parse_interval("10m"), None);
        assert_eq!(parse_lifetime("infinity"), Some(INFINITY));
        assert_eq!(parse_lifetime("4w2d"), Some(2_592_000));
        assert_eq!(lifetime_text(INFINITY), "infinity");
        assert_eq!(parse_lifetime("x"), None);
    }

    #[test]
    fn preference_bits_of_rfc_4191() {
        assert_eq!(RaPreference::High.bits(), 1);
        assert_eq!(RaPreference::Medium.bits(), 0);
        assert_eq!(RaPreference::Low.bits(), 3);
    }

    #[test]
    fn dns_checks_and_lifetime_of_rfc_8106() {
        let mut e = entry();
        e.dns = vec!["2001:db8::53".parse().unwrap()];
        e.dnssl = vec!["isp.example.".into()];
        assert_eq!(e.issues(), None);
        e.dnssl = vec!["bad domain".into()];
        assert_eq!(e.issues().unwrap().0, "dnssl");
        e.dnssl.clear();
        e.dns = vec!["ff02::1".parse().unwrap()];
        assert_eq!(e.issues().unwrap().0, "dns");
        assert_eq!(dns_lifetime(600), 1800);
    }

    #[test]
    fn prefix_checks() {
        let mut p = NdPrefix::new(ItemId(1), "fe80::/64".parse().unwrap(), "e".parse().unwrap());
        assert_eq!(p.issues().unwrap().0, "prefix");
        p.prefix = "2001:db8::/64".parse().unwrap();
        p.preferred_lifetime = p.valid_lifetime + 1;
        assert_eq!(p.issues().unwrap().0, "preferred_lifetime");
    }
}
