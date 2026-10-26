//! `/ppp` (G4.3) with RouterOS v7's names: `/ppp aaa` (G4.3j: whether PPP
//! asks RADIUS and how it accounts), `/ppp profile`, `/ppp secret` and
//! `/interface pppoe-server server` (G4.3d). The daemon's `pppoe` service
//! follows the running config; what it knows at run time (active sessions,
//! why one fell, the history) is in the types at the end of this file, the
//! shape `ppp.active.list`, `ppp.why` and `ppp.history` return.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::Ipv6Net;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ppp_secrets::Secrets;
use crate::types::{IfName, ItemId, MacAddr, ParseError};

/// Spread of the interim updates, % of the interval (RFC 5080 §2.2.1 asks
/// for jitter against synchronized clients).
pub const DEFAULT_INTERIM_JITTER: u8 = 20;
/// Longest `interim_update` accepted, seconds (one day).
pub const MAX_INTERIM: u32 = 86_400;

fn yes() -> bool {
    true
}

fn jitter() -> u8 {
    DEFAULT_INTERIM_JITTER
}

/// RouterOS `/ppp profile use-ipv6` (G4.3e): `default` follows the
/// fallback profiles and ends as `yes` (RouterOS: on when the IPv6 package
/// is installed, and IPv6 is always built in here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UseIpv6 {
    #[default]
    Default,
    Yes,
    No,
    /// IPv6CP must open, or the session ends.
    Require,
}

impl UseIpv6 {
    pub const ALL: [Self; 4] = [Self::Default, Self::Yes, Self::No, Self::Require];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Yes => "yes",
            Self::No => "no",
            Self::Require => "require",
        }
    }

    pub fn parse(t: &str) -> Option<Self> {
        match t.trim() {
            "default" => Some(Self::Default),
            "yes" | "true" => Some(Self::Yes),
            "no" | "false" => Some(Self::No),
            "require" => Some(Self::Require),
            _ => None,
        }
    }
}

/// RouterOS `dhcpv6-lease-time` default: one day.
pub const DEFAULT_DHCPV6_LEASE: u32 = 86_400;
/// IPv6 DNS servers a profile lists at most (RDNSS and DHCPv6 option 23).
pub const MAX_DNS6: usize = 4;

/// RouterOS `/ppp aaa`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PppAaa {
    /// Ask `/radius` (service=ppp) for users not in `/ppp secret`.
    pub use_radius: bool,
    /// Send Accounting-Request Start/Interim/Stop.
    #[serde(default = "yes")]
    pub accounting: bool,
    /// Seconds between Interim-Updates; 0 = only when the Access-Accept
    /// carries Acct-Interim-Interval. At least 60 (RFC 2869 §5.16).
    pub interim_update: u32,
    /// Spread of the interims, % of the interval (not in RouterOS).
    #[serde(default = "jitter")]
    pub interim_jitter: u8,
    /// NAS-Port-Id carries the DHCP/PPPoE circuit id (RFC 4679
    /// Agent-Circuit-Id) instead of the interface name.
    pub use_circuit_id_in_nas_port_id: bool,
    /// Count IPv4 and IPv6 separately (MikroTik attributes).
    pub enable_ipv6_accounting: bool,
}

impl Default for PppAaa {
    fn default() -> Self {
        Self {
            use_radius: false,
            accounting: true,
            interim_update: 0,
            interim_jitter: DEFAULT_INTERIM_JITTER,
            use_circuit_id_in_nas_port_id: false,
            enable_ipv6_accounting: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ppp {
    #[serde(skip_serializing_if = "PppAaa::is_default")]
    pub aaa: PppAaa,
    /// `/ppp profile` the operator added or changed. The built-in `default`
    /// and `default-encryption` exist without an entry ([`Ppp::profile`]);
    /// an entry with their name is the edited copy.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<PppProfile>,
    /// Copy-on-write: a config of 100 k subscribers is not copied by every
    /// command that clones the config.
    #[serde(skip_serializing_if = "no_secrets")]
    pub secrets: Secrets,
    /// `/interface pppoe-server server`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pppoe_servers: Vec<PppoeServer>,
    /// Next id of the three tables (never reused).
    #[serde(skip_serializing_if = "is_zero")]
    pub next_id: u32,
    /// Control-plane workers of the PPPoE service (G4.3g), one per core:
    /// 0 = auto ([`pppoe_workers_auto`]). Read when the service starts.
    #[serde(default, skip_serializing_if = "is_zero16")]
    pub pppoe_workers: u16,
}

fn is_zero16(v: &u16) -> bool {
    *v == 0
}

/// Most workers the PPPoE service runs.
pub const PPPOE_WORKERS_MAX: u16 = 64;

/// `workers=auto` on a machine of `cpus` CPUs: all but two (the reader
/// thread and the rest of the router, including the data plane's softirqs),
/// at most 8 (past that the reader is the limit, measured in G4.3g).
pub fn pppoe_workers_auto(cpus: usize) -> u16 {
    u16::try_from(cpus.saturating_sub(2).clamp(1, 8)).unwrap_or(1)
}

fn no_secrets(v: &Secrets) -> bool {
    v.is_empty()
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

impl PppAaa {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

impl Ppp {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// Profiles in the config (**estimado**, hostile-input bound).
pub const MAX_PROFILES: usize = 1024;
/// Local secrets: a small ISP keeps its subscribers here instead of in
/// RADIUS (**estimado**: 200 k × ~200 B = 40 MB of config at most).
pub const MAX_SECRETS: usize = 200_000;
/// `/interface pppoe-server server` entries.
pub const MAX_PPPOE_SERVERS: usize = 256;
/// Commands in one `on_up` / `on_down` list.
pub const MAX_HOOKS: usize = 8;
/// Names (secret, profile, service-name), bytes. RFC 1334 §2.2.1 and RFC
/// 1994 §4.1 allow 255; RouterOS shows long names fine.
pub const MAX_NAME: usize = 64;
pub const MAX_PASSWORD: usize = 128;
/// RFC 2516 §5.4 / RFC 1661 §6.1: the MRU over PPPoE is at most 1492
/// (RFC 4638 raises it; MRU and MTU above it are refused here).
pub const MAX_MTU: u16 = 1492;
/// RFC 1661 §6.1: the default MRU is 1500; smaller than 64 is pointless.
pub const MIN_MTU: u16 = 64;
/// Safe defaults against PADI floods and mass reconnects (**estimado**:
/// the control plane sets up ≈ 159 k sessions/s, **medido** in G4.3a; the
/// RADIUS does ≈ 72 k/s, G4.3j; 2000/s leaves room for both and brings
/// 20 k subscribers back in 10 s).
pub const DEFAULT_PADI_LIMIT: u32 = 2000;
pub const DEFAULT_MAC_PADI_LIMIT: u32 = 1;
pub const DEFAULT_NEW_SESSION_RATE: u32 = 2000;
/// The built-in profiles, as RouterOS has them (they cannot be removed).
pub const DEFAULT_PROFILE: &str = "default";
pub const DEFAULT_ENCRYPTION: &str = "default-encryption";
/// Placeholders an `on_up` / `on_down` parameter may hold; the service
/// replaces them (the RouterOS script variables, as text).
pub const HOOK_VARS: &[&str] = &[
    "$user",
    "$remote-address",
    "$local-address",
    "$caller-id",
    "$interface",
    "$service",
];

/// RouterOS `yes | no | default` (default: what the server's
/// `default-profile` says).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tri {
    #[default]
    Default,
    Yes,
    No,
}

impl Tri {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Yes => "yes",
            Self::No => "no",
        }
    }

    pub fn parse(t: &str) -> Option<Self> {
        match t.trim() {
            "default" => Some(Self::Default),
            "yes" | "true" => Some(Self::Yes),
            "no" | "false" => Some(Self::No),
            _ => None,
        }
    }

    /// The value, with `default` taken from `fallback`.
    pub fn or(self, fallback: bool) -> bool {
        match self {
            Self::Default => fallback,
            Self::Yes => true,
            Self::No => false,
        }
    }
}

/// `local-address` / `remote-address` of a profile: one address or a pool
/// name (`/ip pool`). RouterOS: a single address wins over a pool.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AddrOrPool {
    Address(Ipv4Addr),
    Pool(String),
}

impl FromStr for AddrOrPool {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        if let Ok(ip) = t.parse::<Ipv4Addr>() {
            return Ok(Self::Address(ip));
        }
        if crate::ip_pool::name_ok(t) {
            return Ok(Self::Pool(t.to_owned()));
        }
        Err(ParseError::new("address", s, "an IPv4 address or the name of an /ip pool"))
    }
}

impl fmt::Display for AddrOrPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address(ip) => write!(f, "{ip}"),
            Self::Pool(p) => f.write_str(p),
        }
    }
}

impl Serialize for AddrOrPool {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for AddrOrPool {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
    }
}

/// One command of `on_up` / `on_down`: the operator's RouterOS script
/// becomes a list of commands of the engine (validated when set, run by the
/// service with [`HOOK_VARS`] replaced in the string parameters). No
/// interpreter, nothing the journal cannot show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PppHook {
    pub command: String,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub params: serde_json::Map<String, serde_json::Value>,
}

/// RouterOS `/ppp profile`. Unset fields come from the server's
/// `default-profile`, then from the built-in `default`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PppProfile {
    pub id: ItemId,
    pub name: String,
    /// Our side of the link (IPCP). Unset: the router is unnumbered towards
    /// the subscriber (the address of the access interface is used).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_address: Option<AddrOrPool>,
    /// The subscriber's address (IPCP), or the pool it comes from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_address: Option<AddrOrPool>,
    /// Up to two (RFC 1877: primary and secondary).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns_server: Vec<Ipv4Addr>,
    /// RouterOS rate-limit text (`10M/50M 20M/80M 8M/40M 10/10 8`), from
    /// the router's view: rx = the subscriber's upload. Checked by the
    /// engine with `proto_radius::rate_limit`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<String>,
    /// Firewall address list the subscriber's address joins while up.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_list: Option<String>,
    pub only_one: Tri,
    pub change_tcp_mss: Tri,
    /// Seconds without traffic before the session is dropped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_timeout: Option<u32>,
    /// Longest session, seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_timeout: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub on_up: Vec<PppHook>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub on_down: Vec<PppHook>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub comment: String,
    /// IPv6CP for the session (G4.3e).
    #[serde(skip_serializing_if = "is_default_v6")]
    pub use_ipv6: UseIpv6,
    /// `/ipv6 pool` (prefix-length 64) of the link's /64, advertised in the
    /// session's RA (SLAAC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ipv6_prefix_pool: Option<String>,
    /// `/ipv6 pool` (prefix-length 48–64) of the prefix delegated by the
    /// session's DHCPv6 (IA_PD).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcpv6_pd_pool: Option<String>,
    /// Valid lifetime of the /64 and the delegated prefix, seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcpv6_lease_time: Option<u32>,
    /// IPv6 DNS servers (RA RDNSS and DHCPv6), CoreRouter's addition: the
    /// RouterOS profile has IPv4 ones only.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns_server_ipv6: Vec<Ipv6Addr>,
}

fn is_default_v6(v: &UseIpv6) -> bool {
    *v == UseIpv6::Default
}

impl PppProfile {
    /// The built-in profile `name`, as RouterOS ships it (`default`:
    /// only-one=no, change-tcp-mss=yes; `default-encryption`: everything
    /// default). Ids `*0` and `*FFFFFFFE` mark them (RouterOS shows `*0` and
    /// `*FFFFFFFE`).
    pub fn builtin(name: &str) -> Option<Self> {
        match name {
            DEFAULT_PROFILE => Some(Self {
                id: ItemId(0),
                name: DEFAULT_PROFILE.into(),
                only_one: Tri::No,
                change_tcp_mss: Tri::Yes,
                ..Self::default()
            }),
            DEFAULT_ENCRYPTION => Some(Self {
                id: ItemId(0xFFFF_FFFE),
                name: DEFAULT_ENCRYPTION.into(),
                ..Self::default()
            }),
            _ => None,
        }
    }

    pub fn is_builtin_name(name: &str) -> bool {
        name == DEFAULT_PROFILE || name == DEFAULT_ENCRYPTION
    }
}

/// Which PPP services a secret may log in through (RouterOS `service`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PppService {
    #[default]
    Any,
    Pppoe,
    L2tp,
    Pptp,
    Sstp,
    Ovpn,
    Async,
    /// An IPoE subscriber (G4.3f): a DHCP client named by its MAC or
    /// option 82 (`ip.dhcp-server ipoe_username`); no password. Only this
    /// value matches IPoE (`any` does not: a PPP login named like a MAC
    /// must not become an IPoE grant).
    Ipoe,
}

impl PppService {
    pub const ALL: [Self; 8] = [
        Self::Any,
        Self::Pppoe,
        Self::L2tp,
        Self::Pptp,
        Self::Sstp,
        Self::Ovpn,
        Self::Async,
        Self::Ipoe,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Pppoe => "pppoe",
            Self::L2tp => "l2tp",
            Self::Pptp => "pptp",
            Self::Sstp => "sstp",
            Self::Ovpn => "ovpn",
            Self::Async => "async",
            Self::Ipoe => "ipoe",
        }
    }

    pub fn parse(t: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == t.trim())
    }

    pub fn allows(self, service: Self) -> bool {
        (self == Self::Any && service != Self::Ipoe) || self == service
    }
}

/// RouterOS `/ppp secret`: a local subscriber. The password is kept in
/// clear text because CHAP and MS-CHAP need it (RFC 1994 §4.1: the secret
/// itself is hashed with the challenge); commands never read it back.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PppSecret {
    pub id: ItemId,
    pub name: String,
    pub password: String,
    pub service: PppService,
    pub profile: String,
    /// Our side; wins over the profile's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_address: Option<Ipv4Addr>,
    /// A fixed address for this subscriber; wins over the profile's pool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_address: Option<Ipv4Addr>,
    /// PPPoE: only from this MAC (RouterOS `caller-id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_id: Option<MacAddr>,
    /// Bytes per session the subscriber may send / receive; 0 = no limit.
    #[serde(skip_serializing_if = "is_zero64")]
    pub limit_bytes_in: u64,
    #[serde(skip_serializing_if = "is_zero64")]
    pub limit_bytes_out: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub comment: String,
    pub disabled: bool,
}

fn is_zero64(v: &u64) -> bool {
    *v == 0
}

/// `authentication` of a PPPoE server, in RouterOS order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PppAuth {
    Mschap2,
    Mschap1,
    Chap,
    Pap,
}

impl PppAuth {
    pub const ALL: [Self; 4] = [Self::Mschap2, Self::Mschap1, Self::Chap, Self::Pap];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mschap2 => "mschap2",
            Self::Mschap1 => "mschap1",
            Self::Chap => "chap",
            Self::Pap => "pap",
        }
    }

    pub fn parse(t: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.as_str() == t.trim())
    }
}

/// One range of `pppoe-over-vlan-range` (`100-115`, `120`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VlanRange {
    pub first: u16,
    pub last: u16,
}

impl FromStr for VlanRange {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        let (a, b) = t.split_once('-').unwrap_or((t, t));
        let parse = |x: &str| {
            x.trim()
                .parse::<u16>()
                .ok()
                .filter(|v| (1..=4094).contains(v))
                .ok_or_else(|| ParseError::new("VLAN range", s, "VLAN ids are 1..=4094 (100-115 or 120)"))
        };
        let (first, last) = (parse(a)?, parse(b)?);
        if first > last {
            return Err(ParseError::new("VLAN range", s, "the first VLAN is after the last"));
        }
        Ok(Self { first, last })
    }
}

impl fmt::Display for VlanRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.first == self.last {
            write!(f, "{}", self.first)
        } else {
            write!(f, "{}-{}", self.first, self.last)
        }
    }
}

impl Serialize for VlanRange {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for VlanRange {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
    }
}

fn auth_default() -> Vec<PppAuth> {
    PppAuth::ALL.to_vec()
}
fn mtu_default() -> u16 {
    1480
}
fn keepalive_default() -> Option<u32> {
    Some(10)
}
fn padi_default() -> u32 {
    DEFAULT_PADI_LIMIT
}
fn mac_padi_default() -> u32 {
    DEFAULT_MAC_PADI_LIMIT
}
fn rate_default() -> u32 {
    DEFAULT_NEW_SESSION_RATE
}
fn profile_default() -> String {
    DEFAULT_PROFILE.into()
}

/// RouterOS `/interface pppoe-server server`: a concentrator on one access
/// interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PppoeServer {
    pub id: ItemId,
    /// RouterOS names it `pppoe-in1`… in the list; ours is the entry name.
    #[serde(default)]
    pub name: String,
    pub interface: IfName,
    /// Empty: any Service-Name (and the empty one) is served.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub service_name: String,
    #[serde(default = "mtu_default")]
    pub max_mtu: u16,
    #[serde(default = "mtu_default")]
    pub max_mru: u16,
    /// Multilink over one link (RFC 1990); `None` = disabled. Read only by
    /// the LCP for now (MRRU is refused when off).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mrru: Option<u16>,
    #[serde(default = "auth_default")]
    pub authentication: Vec<PppAuth>,
    /// Seconds without traffic before LCP echoes start; the subscriber is
    /// dropped after twice that. `None` = disabled.
    #[serde(default = "keepalive_default")]
    pub keepalive_timeout: Option<u32>,
    /// A new session from a MAC replaces its old one. RouterOS default is
    /// `no`; ours is `yes` (a CPE that reboots without PADT would hold two
    /// addresses until the keepalive notices).
    #[serde(default = "yes")]
    pub one_session_per_host: bool,
    /// 0 = no limit (at most 65 534 per server, RFC 2516 §4).
    #[serde(default)]
    pub max_sessions: u32,
    /// Milliseconds before the PADO (a backup BNG answers later).
    #[serde(default)]
    pub pado_delay: u32,
    #[serde(default = "profile_default")]
    pub default_profile: String,
    /// PPPoE inside these 802.1Q VLANs of `interface` (empty: untagged only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pppoe_over_vlan_range: Vec<VlanRange>,
    /// With a VLAN range: still serve untagged PPPoE.
    #[serde(default = "yes")]
    pub accept_untagged: bool,
    /// PADR only with the AC-Cookie of our PADO (RFC 2516 §9: no state per
    /// PADI, forged PADRs create nothing). Not in RouterOS.
    #[serde(default = "yes")]
    pub ac_cookie: bool,
    /// PADIs answered per second on this server; 0 = no limit (accel-ppp
    /// `padi-limit`).
    #[serde(default = "padi_default")]
    pub padi_limit: u32,
    /// PADIs answered per second from one MAC (burst 3); 0 = no limit.
    #[serde(default = "mac_padi_default")]
    pub mac_padi_limit: u32,
    /// Sessions accepted per second (PADRs that create one); the rest wait
    /// their CPE's retry. Spreads a mass reconnect over the RADIUS and the
    /// pool instead of a burst; 0 = no limit (Cisco `pppoe throttle`).
    #[serde(default = "rate_default")]
    pub new_session_rate: u32,
    /// `new_session_rate=auto` (G4.3g): the rate follows the RADIUS
    /// server's health (AIMD on its answer time and timeouts), from 1000/s
    /// up to 20 000/s; `new_session_rate` is not used then. Not in RouterOS.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub new_session_rate_auto: bool,
    /// `pado-delay` by load: from this many sessions, wait this long before
    /// the PADO (accel-ppp `pado-delay=0,100:100,200:5000`), so a loaded BNG
    /// lets a lighter one answer first. Added to `pado_delay`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pado_delay_by_load: Vec<LoadDelay>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

/// One tier of `pado_delay_by_load`: `sessions:delay_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LoadDelay {
    pub sessions: u32,
    pub delay_ms: u32,
}

impl FromStr for LoadDelay {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (a, b) = s
            .trim()
            .split_once(':')
            .ok_or_else(|| ParseError::new("pado delay tier", s, "sessions:delay_ms (5000:100)"))?;
        let (Ok(sessions), Ok(delay_ms)) = (a.trim().parse(), b.trim().parse::<u32>()) else {
            return Err(ParseError::new("pado delay tier", s, "sessions:delay_ms (5000:100)"));
        };
        if delay_ms > MAX_PADO_DELAY {
            return Err(ParseError::new("pado delay tier", s, "delay at most 30000 ms"));
        }
        Ok(Self { sessions, delay_ms })
    }
}

impl fmt::Display for LoadDelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.sessions, self.delay_ms)
    }
}

impl Serialize for LoadDelay {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for LoadDelay {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
    }
}

/// Longest PADO delay, ms (a CPE gives up on PADO after ~5 s × retries).
pub const MAX_PADO_DELAY: u32 = 30_000;

impl PppoeServer {
    /// The delay before a PADO with `sessions` up: `pado_delay` plus the
    /// highest tier reached.
    pub fn pado_delay_at(&self, sessions: u32) -> u32 {
        let tier = self
            .pado_delay_by_load
            .iter()
            .filter(|t| sessions >= t.sessions)
            .map(|t| t.delay_ms)
            .max()
            .unwrap_or(0);
        self.pado_delay.saturating_add(tier).min(MAX_PADO_DELAY)
    }

    pub fn vlan_allowed(&self, vid: Option<u16>) -> bool {
        match vid {
            None => self.pppoe_over_vlan_range.is_empty() || self.accept_untagged,
            Some(v) => self.pppoe_over_vlan_range.iter().any(|r| (r.first..=r.last).contains(&v)),
        }
    }
}

/// What a session gets, resolved: secret, then its profile, then the
/// server's `default-profile`, then the built-in `default` (RouterOS
/// precedence; RADIUS attributes go on top in the service).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct Effective {
    pub profile: String,
    pub local_address: Option<AddrOrPool>,
    pub remote_address: Option<AddrOrPool>,
    pub dns_server: Vec<Ipv4Addr>,
    pub rate_limit: Option<String>,
    pub address_list: Option<String>,
    pub only_one: bool,
    pub change_tcp_mss: bool,
    pub idle_timeout: Option<u32>,
    pub session_timeout: Option<u32>,
    pub on_up: Vec<PppHook>,
    pub on_down: Vec<PppHook>,
    /// Resolved: never `Default` (that ends as `Yes`).
    pub use_ipv6: UseIpv6,
    pub remote_ipv6_prefix_pool: Option<String>,
    pub dhcpv6_pd_pool: Option<String>,
    pub dhcpv6_lease_time: u32,
    pub dns_server_ipv6: Vec<Ipv6Addr>,
}

impl Ppp {
    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    /// Profile `name`: the stored one, or the built-in.
    pub fn profile(&self, name: &str) -> Option<PppProfile> {
        self.profiles
            .iter()
            .find(|p| p.name == name)
            .cloned()
            .or_else(|| PppProfile::builtin(name))
    }

    /// Every profile, the built-ins first (as `/ppp profile print`).
    pub fn all_profiles(&self) -> Vec<PppProfile> {
        let mut out: Vec<PppProfile> = [DEFAULT_PROFILE, DEFAULT_ENCRYPTION]
            .into_iter()
            .filter_map(|n| self.profile(n))
            .collect();
        out.extend(
            self.profiles
                .iter()
                .filter(|p| !PppProfile::is_builtin_name(&p.name))
                .cloned(),
        );
        out
    }

    /// O(1): the list's name index (`crate::ppp_secrets`).
    pub fn secret(&self, name: &str) -> Option<&PppSecret> {
        self.secrets.by_name(name)
    }

    /// `profile` over `fallback` (the server's default profile) over the
    /// built-in `default`, with the secret's own addresses on top.
    pub fn effective(&self, secret: Option<&PppSecret>, profile: &str, fallback: &str) -> Effective {
        let chain: Vec<PppProfile> = [profile, fallback, DEFAULT_PROFILE]
            .into_iter()
            .filter_map(|n| self.profile(n))
            .collect();
        fn pick<T>(chain: &[PppProfile], f: impl Fn(&PppProfile) -> Option<T>) -> Option<T> {
            chain.iter().find_map(f)
        }
        let tri = |f: fn(&PppProfile) -> Tri| {
            chain.iter().map(f).find(|t| *t != Tri::Default).unwrap_or(Tri::No) == Tri::Yes
        };
        let mut e = Effective {
            profile: chain.first().map(|p| p.name.clone()).unwrap_or_else(|| DEFAULT_PROFILE.into()),
            local_address: pick(&chain, |p| p.local_address.clone()),
            remote_address: pick(&chain, |p| p.remote_address.clone()),
            dns_server: chain
                .iter()
                .map(|p| p.dns_server.clone())
                .find(|d| !d.is_empty())
                .unwrap_or_default(),
            rate_limit: pick(&chain, |p| p.rate_limit.clone()),
            address_list: pick(&chain, |p| p.address_list.clone()),
            only_one: tri(|p| p.only_one),
            change_tcp_mss: tri(|p| p.change_tcp_mss),
            idle_timeout: pick(&chain, |p| p.idle_timeout),
            session_timeout: pick(&chain, |p| p.session_timeout),
            on_up: chain.first().map(|p| p.on_up.clone()).unwrap_or_default(),
            on_down: chain.first().map(|p| p.on_down.clone()).unwrap_or_default(),
            use_ipv6: chain
                .iter()
                .map(|p| p.use_ipv6)
                .find(|u| *u != UseIpv6::Default)
                .unwrap_or(UseIpv6::Yes),
            remote_ipv6_prefix_pool: pick(&chain, |p| p.remote_ipv6_prefix_pool.clone()),
            dhcpv6_pd_pool: pick(&chain, |p| p.dhcpv6_pd_pool.clone()),
            dhcpv6_lease_time: pick(&chain, |p| p.dhcpv6_lease_time).unwrap_or(DEFAULT_DHCPV6_LEASE),
            dns_server_ipv6: chain
                .iter()
                .map(|p| p.dns_server_ipv6.clone())
                .find(|d| !d.is_empty())
                .unwrap_or_default(),
        };
        if let Some(s) = secret {
            if let Some(ip) = s.local_address {
                e.local_address = Some(AddrOrPool::Address(ip));
            }
            if let Some(ip) = s.remote_address {
                e.remote_address = Some(AddrOrPool::Address(ip));
            }
        }
        e
    }

    /// Who names profile `name` (refuses its removal or rename).
    pub fn profile_users(&self, name: &str) -> Vec<String> {
        self.secrets
            .iter()
            .filter(|s| s.profile == name)
            .map(|s| format!("secret {}", s.name))
            .chain(
                self.pppoe_servers
                    .iter()
                    .filter(|v| v.default_profile == name)
                    .map(|v| format!("pppoe-server {}", v.name)),
            )
            .collect()
    }
}

// --- What the service knows at run time (`ppp.active.list`, `ppp.why`,
// `ppp.history`): not config, never stored. ---

/// The stage a session reached or failed in, in the order of a login.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    /// PADI seen, PADO sent (or not: limit, service name, max sessions).
    Padi,
    /// PADR seen, PADS sent.
    Padr,
    Lcp,
    Auth,
    /// IPCP / IPv6CP.
    Ncp,
    /// Opened, traffic flowing.
    Up,
    /// IPoE (G4.3f): the DHCP DISCOVER/REQUEST was heard (the PADI of an
    /// IPoE subscriber); then `auth` and `up`.
    Dhcp,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Padi => "padi",
            Self::Padr => "padr",
            Self::Lcp => "lcp",
            Self::Auth => "auth",
            Self::Ncp => "ncp",
            Self::Up => "up",
            Self::Dhcp => "dhcp",
        }
    }
}

/// An active session (`/ppp active`), with the extras of the PPP window.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ActiveSession {
    /// `*<server id>-<sid>`: unique while up.
    pub id: String,
    pub name: String,
    pub service: String,
    /// The subscriber's MAC.
    pub caller_id: String,
    pub address: Option<Ipv4Addr>,
    pub uptime_secs: u64,
    pub session_id: u16,
    pub server: String,
    pub interface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub circuit_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_id: Option<String>,
    /// The rate limit in force (RADIUS or profile), RouterOS text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<String>,
    pub profile: String,
    /// `pap`, `chap`, `mschap1`, `mschap2`.
    pub encoding: String,
    /// Authorized by RADIUS (RouterOS shows `R`).
    pub radius: bool,
    /// Bytes and packets from the router's view: rx = from the subscriber.
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    /// Over the last second, bits per second (rx = from the subscriber).
    pub rx_bps: u64,
    pub tx_bps: u64,
    pub mtu: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_bytes_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_bytes_out: Option<u64>,
    /// G4.3e: the link's /64 (RA), the delegated prefix (DHCPv6 IA_PD) and
    /// the subscriber's link-local (IPv6CP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_prefix: Option<Ipv6Net>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_prefix: Option<Ipv6Net>,
    /// The DHCPv6 client holds the delegated prefix (else it is reserved).
    pub delegated_bound: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_local: Option<Ipv6Addr>,
}

/// One line of `ppp.history`: a login that came up, failed or ended.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HistoryEntry {
    /// Unix seconds.
    pub at: u64,
    pub name: String,
    pub caller_id: String,
    pub server: String,
    /// `up`, `down` or `failed`.
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<Stage>,
    /// The cause in plain words (English key, for i18n and MCP).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// What to do about it, in Portuguese (the "Why?" panel).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hint: String,
    /// The RADIUS Reply-Message, if one came.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Ipv4Addr>,
    pub uptime_secs: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// `ppp.why`: where the logins of a user or MAC get to, and why the last
/// one stopped.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Why {
    /// What was asked (`name` or `mac`).
    pub query: String,
    /// Up now (the active session's id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<String>,
    /// Attempts per stage reached in the window kept (PADI… Up).
    pub attempts: Vec<(Stage, u32)>,
    /// The furthest stage of the last attempt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_stage: Option<Stage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<HistoryEntry>,
}

/// The service's counters (`ppp.pppoe-server.monitor`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceStats {
    pub sessions: u64,
    pub padi: u64,
    pub pado: u64,
    pub padr: u64,
    pub pads: u64,
    pub padt_rx: u64,
    pub padt_tx: u64,
    pub auth_accept: u64,
    pub auth_reject: u64,
    pub throttled: u64,
    pub dataplane: bool,
    /// Control-plane workers of the service (G4.3g; 1 = one thread).
    #[serde(default)]
    pub workers: u32,
    /// `new_session_rate=auto`: the rate now (0: no server uses it) and why.
    #[serde(default)]
    pub admission_rate: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// G4.3e: sessions with IPv6CP up, delegated prefixes held by a
    /// DHCPv6 client, and IPv6 control packets refused (bad ND, DHCPv6
    /// for another server, RS too often).
    pub ipv6_sessions: u64,
    pub delegated: u64,
    pub ipv6_dropped: u64,
    /// G4.3g: discovery and session frames lost before the BNG read them
    /// (a socket's or a worker's queue full: a PADI burst bigger than the
    /// service holds).
    #[serde(default)]
    pub rx_dropped: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> PppoeServer {
        serde_json::from_value(serde_json::json!({"id": "*1", "interface": "ether2"})).unwrap()
    }

    #[test]
    fn server_defaults_are_routeros_plus_safe_ones() {
        let s = server();
        assert_eq!((s.max_mtu, s.max_mru), (1480, 1480));
        assert_eq!(s.authentication, PppAuth::ALL);
        assert_eq!(s.keepalive_timeout, Some(10));
        assert!(s.one_session_per_host && s.ac_cookie && s.accept_untagged);
        assert_eq!(s.padi_limit, DEFAULT_PADI_LIMIT);
        assert_eq!(s.default_profile, "default");
        let back: PppoeServer = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn vlan_ranges_and_pado_tiers_parse() {
        let r: VlanRange = "100-115".parse().unwrap();
        assert_eq!((r.first, r.last), (100, 115));
        assert_eq!("120".parse::<VlanRange>().unwrap().to_string(), "120");
        assert!("0".parse::<VlanRange>().is_err());
        assert!("20-10".parse::<VlanRange>().is_err());
        let mut s = server();
        s.pppoe_over_vlan_range = vec![r];
        assert!(s.vlan_allowed(Some(110)) && !s.vlan_allowed(Some(116)));
        assert!(s.vlan_allowed(None));
        s.accept_untagged = false;
        assert!(!s.vlan_allowed(None));
        s.pado_delay = 10;
        s.pado_delay_by_load = vec!["1000:50".parse().unwrap(), "5000:200".parse().unwrap()];
        assert_eq!(s.pado_delay_at(10), 10);
        assert_eq!(s.pado_delay_at(1000), 60);
        assert_eq!(s.pado_delay_at(9000), 210);
        assert!("1:99999".parse::<LoadDelay>().is_err());
    }

    #[test]
    fn precedence_is_secret_profile_default_profile_builtin() {
        let mut ppp = Ppp::default();
        ppp.profiles.push(PppProfile {
            id: ItemId(1),
            name: "plano".into(),
            rate_limit: Some("10M/50M".into()),
            remote_address: Some(AddrOrPool::Pool("clientes".into())),
            ..PppProfile::default()
        });
        ppp.profiles.push(PppProfile {
            id: ItemId(2),
            name: "base".into(),
            dns_server: vec![Ipv4Addr::new(1, 1, 1, 1)],
            only_one: Tri::Yes,
            ..PppProfile::default()
        });
        let secret = PppSecret {
            name: "joao".into(),
            remote_address: Some(Ipv4Addr::new(100, 64, 0, 9)),
            ..PppSecret::default()
        };
        let e = ppp.effective(Some(&secret), "plano", "base");
        assert_eq!(e.rate_limit.as_deref(), Some("10M/50M"));
        assert_eq!(e.dns_server, [Ipv4Addr::new(1, 1, 1, 1)]);
        assert!(e.only_one, "plano says default: base says yes");
        assert!(e.change_tcp_mss, "the built-in default says yes");
        assert_eq!(e.remote_address, Some(AddrOrPool::Address(Ipv4Addr::new(100, 64, 0, 9))));
        let e = ppp.effective(None, "plano", "base");
        assert_eq!(e.remote_address, Some(AddrOrPool::Pool("clientes".into())));
        assert_eq!(ppp.all_profiles().len(), 4);
        assert_eq!(ppp.profile("default").unwrap().id, ItemId(0));
    }

    #[test]
    fn addr_or_pool_and_config_round_trip() {
        assert_eq!("10.0.0.1".parse::<AddrOrPool>().unwrap(), AddrOrPool::Address(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!("pool1".parse::<AddrOrPool>().unwrap(), AddrOrPool::Pool("pool1".into()));
        assert!("bad name".parse::<AddrOrPool>().is_err());
        let mut ppp = Ppp::default();
        assert!(ppp.is_default());
        let id = ppp.next_id();
        ppp.secrets.push(PppSecret { id, name: "a".into(), password: "x".into(), profile: "default".into(), ..PppSecret::default() });
        ppp.pppoe_servers.push(server());
        let back: Ppp = serde_json::from_str(&serde_json::to_string(&ppp).unwrap()).unwrap();
        assert_eq!(back, ppp);
        assert_eq!(ppp.profile_users("default"), ["secret a", "pppoe-server "]);
    }
}
