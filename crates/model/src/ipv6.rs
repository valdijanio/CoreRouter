//! `/ipv6` (G4.7b): the DHCPv6 clients (`/ipv6 dhcp-client`) and the
//! Router Advertisement policy (`/ipv6 settings`). Only configuration lives
//! here; leases, the delegated prefixes ("pools") and what the kernel
//! learned from Router Advertisements are operational state kept by the
//! engine and the HAL (never saved, never in a revision).

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

use ipnet::Ipv6Net;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::firewall::Name;
use crate::types::{IfName, ItemId, MacAddr, ParseError};
use crate::{DEFAULT_DISTANCE, route};

/// At most this many DHCPv6 clients (one per interface; **estimado**).
pub const MAX_CLIENTS: usize = 256;
pub const MAX_ALLOWED: usize = 16;
/// `custom_duid`: at most 128 bytes after the 2-byte type (RFC 9915 §11.1).
pub const MAX_DUID: usize = 130;

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ipv6 {
    pub settings: Ipv6Settings,
    /// `/ipv6 dhcp-client`: at most one per interface.
    pub dhcp_clients: Vec<Dhcp6Client>,
    pub next_dhcp_client_id: u32,
}

impl Ipv6 {
    pub fn next_dhcp_client_id(&mut self) -> ItemId {
        self.next_dhcp_client_id = self.next_dhcp_client_id.saturating_add(1);
        ItemId(self.next_dhcp_client_id)
    }
}

/// Whether an interface takes Router Advertisements (RouterOS
/// `accept-router-advertisements`, plus our `auto`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AcceptRa {
    /// Only where an enabled DHCPv6 client runs (the WAN: the default route
    /// comes from RA there, RFC 7084 W-3); nowhere else, so a rogue RA on a
    /// LAN cannot renumber the router or steal its default route.
    #[default]
    Auto,
    /// On every interface of `accept_router_advertisements_on`, even while
    /// forwarding (kernel `accept_ra=2`).
    Yes,
    /// Nowhere (kernel `accept_ra=0`).
    No,
    /// RouterOS' default: only while IPv6 forwarding is off (kernel
    /// `accept_ra=1`; the kernel decides).
    YesIfForwardingDisabled,
}

impl AcceptRa {
    pub const ALL: [Self; 4] = [
        Self::Auto,
        Self::Yes,
        Self::No,
        Self::YesIfForwardingDisabled,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Yes => "yes",
            Self::No => "no",
            Self::YesIfForwardingDisabled => "yes-if-forwarding-disabled",
        }
    }
}

impl fmt::Display for AcceptRa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AcceptRa {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|v| v.as_str() == s.trim())
            .ok_or_else(|| {
                ParseError::new(
                    "accept-router-advertisements",
                    s,
                    "expected auto, yes, no or yes-if-forwarding-disabled",
                )
            })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ipv6Settings {
    pub accept_router_advertisements: AcceptRa,
    /// Interface list the policy applies to (RouterOS
    /// `accept-router-advertisements-on`): `all`, `none` or a list of
    /// `/interface list`.
    pub accept_router_advertisements_on: Name,
}

impl Default for Ipv6Settings {
    fn default() -> Self {
        Self {
            accept_router_advertisements: AcceptRa::Auto,
            accept_router_advertisements_on: Name::all(),
        }
    }
}

/// What the kernel is told for one interface (`net.ipv6.conf.<if>.accept_ra`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RaMode {
    Off,
    /// Only while forwarding is off (`1`).
    IfNotForwarding,
    /// Always (`2`).
    On,
}

impl RaMode {
    /// The `accept_ra` sysctl value.
    pub fn sysctl(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::IfNotForwarding => 1,
            Self::On => 2,
        }
    }

    pub fn accepts(self) -> bool {
        self != Self::Off
    }
}

/// Whether `iface` is in interface list `list` (`all`, `none` or a list).
pub fn in_list(cfg: &Config, list: &str, iface: &IfName) -> bool {
    match list {
        "all" => true,
        "none" => false,
        l => cfg.interface_lists.interfaces_of(l).any(|i| i == iface),
    }
}

/// What interface `iface` does with Router Advertisements under `cfg`, and
/// why (for `ipv6.settings.get`).
pub fn ra_mode(cfg: &Config, iface: &IfName) -> (RaMode, String) {
    let s = &cfg.ipv6.settings;
    let list = s.accept_router_advertisements_on.as_str();
    if !in_list(cfg, list, iface) {
        return (
            RaMode::Off,
            format!("not in accept-router-advertisements-on ({list})"),
        );
    }
    match s.accept_router_advertisements {
        AcceptRa::No => (RaMode::Off, "accept-router-advertisements=no".into()),
        AcceptRa::Yes => (RaMode::On, "accept-router-advertisements=yes".into()),
        AcceptRa::YesIfForwardingDisabled => (
            RaMode::IfNotForwarding,
            "only while IPv6 forwarding is off (the kernel decides)".into(),
        ),
        AcceptRa::Auto => match cfg
            .ipv6
            .dhcp_clients
            .iter()
            .find(|c| !c.disabled && c.interface == *iface)
        {
            Some(c) => (
                RaMode::On,
                format!("auto: DHCPv6 client {} runs here (WAN)", c.id),
            ),
            None => (RaMode::Off, "auto: no DHCPv6 client here".into()),
        },
    }
}

/// What a client asks the server for (RouterOS `request`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Request6 {
    Address,
    Prefix,
    /// `address,prefix`.
    Both,
}

impl Request6 {
    pub const ALL: [Self; 3] = [Self::Address, Self::Prefix, Self::Both];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Address => "address",
            Self::Prefix => "prefix",
            Self::Both => "address,prefix",
        }
    }

    pub fn address(self) -> bool {
        matches!(self, Self::Address | Self::Both)
    }

    pub fn prefix(self) -> bool {
        matches!(self, Self::Prefix | Self::Both)
    }
}

impl fmt::Display for Request6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Request6 {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut address = false;
        let mut prefix = false;
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match part {
                "address" => address = true,
                "prefix" => prefix = true,
                "both" => (address, prefix) = (true, true),
                "info" => {
                    return Err(ParseError::new(
                        "request",
                        s,
                        "info (stateless DHCPv6) is not supported yet; ask for address and/or prefix",
                    ));
                }
                _ => {
                    return Err(ParseError::new(
                        "request",
                        s,
                        "expected address, prefix or address,prefix",
                    ));
                }
            }
        }
        match (address, prefix) {
            (true, true) => Ok(Self::Both),
            (true, false) => Ok(Self::Address),
            (false, true) => Ok(Self::Prefix),
            (false, false) => Err(ParseError::new(
                "request",
                s,
                "expected address, prefix or address,prefix",
            )),
        }
    }
}

/// A DHCPv6 server the client accepts: by its DUID, by the address its
/// messages come from, or by the MAC inside its DUID (DUID-LL/LLT).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum AllowedServer6 {
    Ip(Ipv6Addr),
    Mac(MacAddr),
    Duid(Vec<u8>),
}

/// `0x0a0b…` → bytes.
pub fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let h = s.trim().strip_prefix("0x")?;
    if h.is_empty() || !h.len().is_multiple_of(2) {
        return None;
    }
    (0..h.len())
        .step_by(2)
        .map(|i| h.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect()
}

pub fn hex(data: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

impl FromStr for AllowedServer6 {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        if let Ok(ip) = t.parse::<Ipv6Addr>() {
            return Ok(Self::Ip(ip));
        }
        if let Some(d) = parse_hex(t).filter(|d| (3..=MAX_DUID).contains(&d.len())) {
            return Ok(Self::Duid(d));
        }
        t.parse::<MacAddr>().map(Self::Mac).map_err(|_| {
            ParseError::new(
                "allowed server",
                s,
                "expected an IPv6 address (fe80::1), a DUID (0x00030001…) or a MAC",
            )
        })
    }
}

impl fmt::Display for AllowedServer6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Mac(mac) => write!(f, "{mac}"),
            Self::Duid(d) => f.write_str(&hex(d)),
        }
    }
}

impl TryFrom<String> for AllowedServer6 {
    type Error = ParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<AllowedServer6> for String {
    fn from(a: AllowedServer6) -> Self {
        a.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dhcp6Client {
    pub id: ItemId,
    pub interface: IfName,
    pub request: Request6,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
    /// Name of the pool the delegated prefix becomes (addresses use it with
    /// `ip.address.add from_pool=…`). Required when a prefix is requested.
    #[serde(default)]
    pub pool_name: String,
    /// Hint in the Solicit: `::/56` asks for a /56, a whole prefix asks for
    /// that one. `None` (RouterOS `::/0`): no hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_hint: Option<Ipv6Net>,
    /// RouterOS `accept-prefix-without-address`: with both requested, bind
    /// a prefix even when the server gives no address (RFC 7084 WPD-6).
    #[serde(default = "yes")]
    pub accept_prefix_without_address: bool,
    /// `::/0` via the server's (or relay's) link-local address. Off by
    /// default: on most links the default route comes from RA.
    #[serde(default)]
    pub add_default_route: bool,
    #[serde(default = "default_distance")]
    pub default_route_distance: u8,
    #[serde(default = "yes")]
    pub use_peer_dns: bool,
    #[serde(default = "yes")]
    pub rapid_commit: bool,
    /// Our DUID as `0x…`; empty: DUID-LL of the interface's MAC.
    #[serde(default)]
    pub custom_duid: String,
    /// Empty: any server.
    #[serde(default)]
    pub allowed_servers: Vec<AllowedServer6>,
}

fn yes() -> bool {
    true
}

fn default_distance() -> u8 {
    DEFAULT_DISTANCE
}

impl Dhcp6Client {
    /// A client with RouterOS' defaults.
    pub fn new(id: ItemId, interface: IfName, request: Request6) -> Self {
        Self {
            id,
            interface,
            request,
            disabled: false,
            comment: String::new(),
            pool_name: String::new(),
            prefix_hint: None,
            accept_prefix_without_address: true,
            add_default_route: false,
            default_route_distance: DEFAULT_DISTANCE,
            use_peer_dns: true,
            rapid_commit: true,
            custom_duid: String::new(),
            allowed_servers: Vec::new(),
        }
    }

    /// Whether a server with DUID `duid`, seen from `src` (with Ethernet
    /// source `mac`, if known) may answer.
    pub fn allows(&self, duid: &[u8], src: Ipv6Addr, mac: Option<[u8; 6]>) -> bool {
        allows6(&self.allowed_servers, duid, src, mac)
    }
}

/// The Ethernet address inside a DUID-LLT (1) or DUID-LL (3), if any.
pub fn duid_mac(duid: &[u8]) -> Option<[u8; 6]> {
    let kind = u16::from_be_bytes(duid.get(..2)?.try_into().ok()?);
    let hw = u16::from_be_bytes(duid.get(2..4)?.try_into().ok()?);
    let at = match kind {
        1 => 8,
        3 => 4,
        _ => return None,
    };
    if hw != 1 || duid.len() != at + 6 {
        return None;
    }
    duid.get(at..at + 6)?.try_into().ok()
}

pub fn allows6(list: &[AllowedServer6], duid: &[u8], src: Ipv6Addr, mac: Option<[u8; 6]>) -> bool {
    let inner = duid_mac(duid);
    list.is_empty()
        || list.iter().any(|a| match a {
            AllowedServer6::Ip(ip) => *ip == src,
            AllowedServer6::Mac(m) => mac == Some(m.0) || inner == Some(m.0),
            AllowedServer6::Duid(d) => d.as_slice() == duid,
        })
}

/// The address `entry` asks for when taken from delegated prefix `pool`:
/// the pool's bits, then the entry's own bits beyond the pool's length
/// (`::1/64` → `<prefix>::1/64`, `0:0:0:5::1/64` → subnet 5). Like a
/// Cisco general prefix: the subnet is the operator's choice, stable
/// across renumbering. `Err` says why it does not fit.
pub fn from_pool(entry: Ipv6Net, pool: Ipv6Net) -> Result<Ipv6Net, String> {
    if entry.prefix_len() < pool.prefix_len() {
        return Err(format!(
            "/{} is shorter than the delegated {pool}",
            entry.prefix_len()
        ));
    }
    let mask = u128::MAX
        .checked_shl(u32::from(128 - pool.prefix_len()))
        .unwrap_or(0);
    let bits = u128::from(entry.addr());
    if bits & mask != 0 {
        return Err(format!(
            "{} has bits inside the delegated {pool}; the subnet does not fit",
            entry.addr()
        ));
    }
    let addr = Ipv6Addr::from((u128::from(pool.network()) & mask) | bits);
    Ipv6Net::new(addr, entry.prefix_len()).map_err(|e| e.to_string())
}

/// Routing table of the client's routes (the interface's).
pub fn table_of(cfg: &Config, c: &Dhcp6Client) -> crate::RoutingTable {
    route::table_of(cfg, &c.interface)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Interface, InterfaceKind};

    #[test]
    fn minimal_json_gets_the_defaults() {
        let c: Dhcp6Client =
            serde_json::from_str(r#"{"id": "*1", "interface": "ether1", "request": "prefix"}"#)
                .unwrap();
        assert_eq!(
            c,
            Dhcp6Client::new(ItemId(1), "ether1".parse().unwrap(), Request6::Prefix)
        );
        let back: Dhcp6Client = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
        let s: Ipv6Settings = serde_json::from_str("{}").unwrap();
        assert_eq!(s.accept_router_advertisements, AcceptRa::Auto);
        assert_eq!(s.accept_router_advertisements_on.as_str(), "all");
    }

    #[test]
    fn request_parses_routeros_spellings() {
        assert_eq!(
            "address,prefix".parse::<Request6>().unwrap(),
            Request6::Both
        );
        assert_eq!(
            "prefix, address".parse::<Request6>().unwrap(),
            Request6::Both
        );
        assert_eq!("prefix".parse::<Request6>().unwrap(), Request6::Prefix);
        assert!(
            "info"
                .parse::<Request6>()
                .unwrap_err()
                .to_string()
                .contains("not supported")
        );
        assert!("".parse::<Request6>().is_err());
    }

    #[test]
    fn allowed_servers_match_duid_address_or_mac() {
        let duid = [0, 3, 0, 1, 2, 0xdc, 0, 0, 0, 1];
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let list: Vec<AllowedServer6> = ["0x0003000102dc00000001", "fe80::9", "AA:BB:CC:DD:EE:FF"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        assert!(allows6(&list, &duid, "fe80::2".parse().unwrap(), None));
        assert!(allows6(
            &list,
            &[0, 2, 0, 0],
            "fe80::9".parse().unwrap(),
            None
        ));
        let by_mac: Vec<AllowedServer6> = vec!["02:DC:00:00:00:01".parse().unwrap()];
        assert!(allows6(&by_mac, &duid, src, None), "MAC inside the DUID-LL");
        assert!(!allows6(&by_mac, &[0, 2, 0, 0, 0, 9], src, Some([0; 6])));
        assert_eq!(list[0].to_string(), "0x0003000102dc00000001");
        assert!(allows6(&[], &[], src, None));
        assert!("0x0".parse::<AllowedServer6>().is_err());
    }

    #[test]
    fn pool_addresses_keep_the_subnet_the_operator_wrote() {
        let pool: Ipv6Net = "2001:db8:1:100::/56".parse().unwrap();
        let a = |s: &str| from_pool(s.parse().unwrap(), pool);
        assert_eq!(a("::1/64").unwrap().to_string(), "2001:db8:1:100::1/64");
        assert_eq!(
            a("0:0:0:5::1/64").unwrap().to_string(),
            "2001:db8:1:105::1/64"
        );
        assert!(a("0:0:0:100::1/64").unwrap_err().contains("does not fit"));
        assert!(a("::1/48").unwrap_err().contains("shorter"));
    }

    #[test]
    fn ra_policy_follows_the_dhcp_client_by_default() {
        let mut cfg = Config::default();
        for n in ["ether1", "ether2"] {
            cfg.interfaces.insert(
                n.parse().unwrap(),
                Interface::new(n.parse().unwrap(), InterfaceKind::Ethernet),
            );
        }
        let e1: IfName = "ether1".parse().unwrap();
        let e2: IfName = "ether2".parse().unwrap();
        assert_eq!(ra_mode(&cfg, &e1).0, RaMode::Off, "safe default");
        cfg.ipv6
            .dhcp_clients
            .push(Dhcp6Client::new(ItemId(1), e1.clone(), Request6::Both));
        assert_eq!(ra_mode(&cfg, &e1).0, RaMode::On);
        assert_eq!(ra_mode(&cfg, &e2).0, RaMode::Off);
        cfg.ipv6.settings.accept_router_advertisements = AcceptRa::Yes;
        assert_eq!(ra_mode(&cfg, &e2).0, RaMode::On);
        cfg.ipv6.settings.accept_router_advertisements_on = "WAN".parse().unwrap();
        assert_eq!(ra_mode(&cfg, &e2).0, RaMode::Off, "WAN list is empty");
        cfg.ipv6.settings.accept_router_advertisements = AcceptRa::YesIfForwardingDisabled;
        cfg.ipv6.settings.accept_router_advertisements_on = "all".parse().unwrap();
        assert_eq!(ra_mode(&cfg, &e2).0.sysctl(), 1);
    }
}
