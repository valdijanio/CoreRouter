//! `/ip dhcp-server` (G4.2a): the DHCPv4 server's configuration, with
//! RouterOS v7's menus and names:
//!
//! - servers (`/ip dhcp-server`): one per interface (or relay), with the
//!   pool, lease time and how authoritative it is;
//! - networks (`/ip dhcp-server network`): what a client of a subnet
//!   learns (gateway, DNS, domain, NTP, options) and, here, the DNS zone
//!   its leases are named in;
//! - static leases (`/ip dhcp-server lease`): fixed addresses by MAC or
//!   client id, with `block-access` and `address-lists`;
//! - options, option sets and matchers (`/ip dhcp-server option`,
//!   `option sets`, `matcher`): extra options, chosen per server, network,
//!   lease, or by what the client sends (its vendor class);
//! - alerts (`/ip dhcp-server alert`): DHCP servers that should not be on
//!   a link.
//!
//! The dynamic leases, the counters and the alerts seen are operational
//! state of the engine (`ip.dhcp-server.lease.print`), kept in their own
//! journal, never in a revision.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::firewall::Name;
use crate::types::{IfName, ItemId, MacAddr, ParseError};

/// Hostile-input bounds (**estimado**).
pub const MAX_SERVERS: usize = 256;
pub const MAX_NETWORKS: usize = 1024;
pub const MAX_STATIC_LEASES: usize = 65_536;
pub const MAX_OPTIONS: usize = 1024;
pub const MAX_OPTION_SETS: usize = 256;
pub const MAX_MATCHERS: usize = 256;
pub const MAX_ALERTS: usize = 256;
/// Entries of one list field (DNS servers, options of a set, address lists).
pub const MAX_LIST: usize = 16;
/// One option value as written.
pub const MAX_VALUE_TEXT: usize = 512;

/// RouterOS v7's `lease-time` default: 30 minutes.
pub const DEFAULT_LEASE_TIME: u32 = 1800;
/// Lease time bounds: 1 minute (shorter churns the journal and the DNS) to
/// a year.
pub const MIN_LEASE_TIME: u32 = 60;
pub const MAX_LEASE_TIME: u32 = 365 * 86_400;
/// Default of `/ip dhcp-server alert`'s `alert-timeout`: an hour.
pub const DEFAULT_ALERT_TIMEOUT: u32 = 3600;
/// Messages per second one client may send before being dropped (a DORA
/// is 2; a confused client retrying every second is 1; **estimado**).
pub const DEFAULT_CLIENT_RATE: u32 = 10;

/// How the server treats a client asking for an address it does not know
/// (RouterOS `authoritative`, RFC 2131 §4.3.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Authoritative {
    /// NAK at once: the client starts over and gets one of ours (the right
    /// choice when this is the only server on the link).
    #[default]
    Yes,
    /// Stay silent (another server may own that address).
    No,
    /// Silent for the client's first 2 s of asking (its `secs` field), then
    /// NAK.
    After2SecDelay,
    /// The same after 10 s.
    After10SecDelay,
}

impl Authoritative {
    pub const ALL: [Self; 4] = [
        Self::Yes,
        Self::No,
        Self::After2SecDelay,
        Self::After10SecDelay,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::After2SecDelay => "after-2sec-delay",
            Self::After10SecDelay => "after-10sec-delay",
        }
    }

    /// Whether a REQUEST that waited `secs` (the client's field) is NAKed.
    pub fn naks_after(self, secs: u16) -> bool {
        match self {
            Self::Yes => true,
            Self::No => false,
            Self::After2SecDelay => secs >= 2,
            Self::After10SecDelay => secs >= 10,
        }
    }
}

impl fmt::Display for Authoritative {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Authoritative {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|v| v.as_str() == s.trim())
            .ok_or_else(|| {
                ParseError::new(
                    "authoritative",
                    s,
                    "expected yes, no, after-2sec-delay or after-10sec-delay",
                )
            })
    }
}

/// One `/ip dhcp-server`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DhcpServer {
    pub id: ItemId,
    /// `dhcp1`, …: leases and alerts name their server by it.
    pub name: String,
    pub interface: IfName,
    /// `None`: static-only (RouterOS `static-only`): only static leases
    /// get an address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_pool: Option<String>,
    #[serde(default = "default_lease_time")]
    pub lease_time: u32,
    #[serde(default)]
    pub authoritative: Authoritative,
    /// ARP probe each address before offering it (RFC 2131 §3.1, §4.4.1):
    /// one that answers is marked `conflict` and another is offered.
    #[serde(default = "yes")]
    pub conflict_detection: bool,
    /// Reply by broadcast even to clients that can take unicast.
    #[serde(default)]
    pub always_broadcast: bool,
    /// The address the server answers from and names itself with (option
    /// 54); `None` picks the interface's address inside the client's
    /// network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_address: Option<Ipv4Addr>,
    /// Serve only requests relayed by this agent (`giaddr`); `None` serves
    /// clients on the link. G4.2b brings the router's own relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<Ipv4Addr>,
    /// Option set every client of this server gets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp_option_set: Option<String>,
    /// Firewall address lists every bound address joins while bound.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub address_lists: Vec<Name>,
    /// Leases one MAC may hold at once (different client ids behind the
    /// same MAC: a VM host, or a starvation attack); `None`: unlimited
    /// (RouterOS `client-mac-limit`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_mac_limit: Option<u32>,
    /// Messages per second one client may send; the rest are dropped and
    /// counted (`rate-limited`). 0: no limit.
    #[serde(default = "default_client_rate")]
    pub client_rate_limit: u32,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

fn default_lease_time() -> u32 {
    DEFAULT_LEASE_TIME
}

fn default_client_rate() -> u32 {
    DEFAULT_CLIENT_RATE
}

fn yes() -> bool {
    true
}

impl DhcpServer {
    /// A server with RouterOS' defaults.
    pub fn new(id: ItemId, name: String, interface: IfName) -> Self {
        Self {
            id,
            name,
            interface,
            address_pool: None,
            lease_time: DEFAULT_LEASE_TIME,
            authoritative: Authoritative::Yes,
            conflict_detection: true,
            always_broadcast: false,
            server_address: None,
            relay: None,
            dhcp_option_set: None,
            address_lists: Vec::new(),
            client_mac_limit: None,
            client_rate_limit: DEFAULT_CLIENT_RATE,
            disabled: false,
            comment: String::new(),
        }
    }
}

/// One `/ip dhcp-server network`: what a client whose address falls in
/// `address` learns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DhcpNetwork {
    pub id: ItemId,
    pub address: Ipv4Net,
    /// Option 3. Empty: no router (an isolated network).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gateway: Vec<Ipv4Addr>,
    /// Option 1 when it differs from `address`'s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netmask: Option<u8>,
    /// Option 6. Empty: the server's own address when the router's
    /// resolver serves the LAN (`ip.dns allow_remote_requests`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_server: Vec<Ipv4Addr>,
    /// Send no DNS server at all.
    #[serde(default)]
    pub dns_none: bool,
    /// Option 15.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    /// Option 42.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ntp_server: Vec<Ipv4Addr>,
    /// Option 44.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wins_server: Vec<Ipv4Addr>,
    /// `siaddr` (PXE / TFTP).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_server: Option<Ipv4Addr>,
    /// `file` (PXE).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub boot_file_name: String,
    /// Options (by name) every client of this network gets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dhcp_option: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp_option_set: Option<String>,
    /// DNS zone the leases are named in (`<host>.<zone>` A record and the
    /// PTR in the reverse zone that covers the address, G4.1c-3). `None`:
    /// no DNS. Must be a primary zone of `/ip dns zone`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_zone: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl DhcpNetwork {
    pub fn new(id: ItemId, address: Ipv4Net) -> Self {
        Self {
            id,
            address: address.trunc(),
            gateway: Vec::new(),
            netmask: None,
            dns_server: Vec::new(),
            dns_none: false,
            domain: String::new(),
            ntp_server: Vec::new(),
            wins_server: Vec::new(),
            next_server: None,
            boot_file_name: String::new(),
            dhcp_option: Vec::new(),
            dhcp_option_set: None,
            dns_zone: None,
            comment: String::new(),
        }
    }
}

/// A static lease (`/ip dhcp-server lease` without the D flag): `address`
/// for the client with this MAC or client id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticLease {
    pub id: ItemId,
    /// Server it belongs to; `None`: any (RouterOS `all`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    pub address: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<MacAddr>,
    /// Option 61 as RouterOS prints it (`1:aa:bb:cc:dd:ee:ff`); when set it
    /// identifies the client instead of the MAC (RFC 2131 §4.2).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_id: String,
    /// `None`: the server's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_time: Option<u32>,
    /// The client gets its address but no gateway nor DNS, and is shown
    /// `blocked` (RouterOS `block-access`).
    #[serde(default)]
    pub block_access: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub address_lists: Vec<Name>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dhcp_option: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp_option_set: Option<String>,
    #[serde(default)]
    pub always_broadcast: bool,
    /// Name in the DNS when the client sends none (Kea's reservation
    /// hostname); empty: the client's.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host_name: String,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl StaticLease {
    pub fn new(id: ItemId, address: Ipv4Addr) -> Self {
        Self {
            id,
            server: None,
            address,
            mac_address: None,
            client_id: String::new(),
            lease_time: None,
            block_access: false,
            address_lists: Vec::new(),
            dhcp_option: Vec::new(),
            dhcp_option_set: None,
            always_broadcast: false,
            host_name: String::new(),
            disabled: false,
            comment: String::new(),
        }
    }
}

/// `/ip dhcp-server option`: a named option, its value in RouterOS'
/// syntax (`'text'`, `0x0a0b`, `s'…'`, `$(NETWORK_GATEWAY)`…).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionDef {
    pub id: ItemId,
    pub name: String,
    pub code: u8,
    pub value: String,
    /// Send it even when the client did not ask (option 55).
    #[serde(default)]
    pub force: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

/// `/ip dhcp-server option sets`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionSet {
    pub id: ItemId,
    pub name: String,
    pub options: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

/// How a matcher compares the client's option with its value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MatchingType {
    #[default]
    Exact,
    Substring,
}

impl MatchingType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Substring => "substring",
        }
    }
}

impl FromStr for MatchingType {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "exact" => Ok(Self::Exact),
            "substring" => Ok(Self::Substring),
            _ => Err(ParseError::new(
                "matching-type",
                s,
                "expected exact or substring",
            )),
        }
    }
}

/// `/ip dhcp-server matcher` (RouterOS v7): when the client's option
/// `code` (60, its vendor class, typically) matches `value`, it gets
/// `option_set` and/or an address from `address_pool`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    pub id: ItemId,
    pub name: String,
    /// `None`: every server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    pub code: u8,
    /// RouterOS option syntax (`'MSFT 5.0'`, `0x…`).
    pub value: String,
    #[serde(default)]
    pub matching_type: MatchingType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub option_set: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_pool: Option<String>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

/// `/ip dhcp-server alert`: watch `interface` for DHCP servers other than
/// the router's and those in `valid_server`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alert {
    pub id: ItemId,
    pub interface: IfName,
    /// MACs of servers allowed on the link.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub valid_server: Vec<MacAddr>,
    /// A server not heard from for this long leaves the list (and is logged
    /// again when it comes back).
    #[serde(default = "default_alert_timeout")]
    pub alert_timeout: u32,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

fn default_alert_timeout() -> u32 {
    DEFAULT_ALERT_TIMEOUT
}

/// Everything under `/ip dhcp-server`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DhcpServers {
    pub servers: Vec<DhcpServer>,
    pub networks: Vec<DhcpNetwork>,
    pub leases: Vec<StaticLease>,
    pub options: Vec<OptionDef>,
    pub option_sets: Vec<OptionSet>,
    pub matchers: Vec<Matcher>,
    pub alerts: Vec<Alert>,
    /// One counter for every kind of item here (ids never reused).
    pub next_id: u32,
}

impl DhcpServers {
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
            && self.networks.is_empty()
            && self.leases.is_empty()
            && self.options.is_empty()
            && self.option_sets.is_empty()
            && self.matchers.is_empty()
            && self.alerts.is_empty()
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    pub fn server(&self, name: &str) -> Option<&DhcpServer> {
        self.servers.iter().find(|s| s.name == name)
    }

    pub fn option(&self, name: &str) -> Option<&OptionDef> {
        self.options.iter().find(|o| o.name == name)
    }

    pub fn option_set(&self, name: &str) -> Option<&OptionSet> {
        self.option_sets.iter().find(|o| o.name == name)
    }

    /// The most specific network that holds `ip`.
    pub fn network_of(&self, ip: Ipv4Addr) -> Option<&DhcpNetwork> {
        self.networks
            .iter()
            .filter(|n| n.address.contains(&ip))
            .max_by_key(|n| n.address.prefix_len())
    }
}

/// RouterOS' client-id text (`1:aa:bb:cc:dd:ee:ff`, hex bytes separated by
/// `:`, leading zeros optional) as bytes; also `0x…`.
pub fn parse_client_id(text: &str) -> Option<Vec<u8>> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(hex) = t.strip_prefix("0x") {
        if hex.is_empty() || hex.len() % 2 != 0 || hex.len() > 2 * 255 {
            return None;
        }
        return (0..hex.len())
            .step_by(2)
            .map(|i| hex.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
            .collect();
    }
    let out: Option<Vec<u8>> = t
        .split(':')
        .map(|p| {
            (!p.is_empty() && p.len() <= 2)
                .then(|| u8::from_str_radix(p, 16).ok())
                .flatten()
        })
        .collect();
    out.filter(|v| (2..=255).contains(&v.len()))
}

/// Bytes of a client id as RouterOS prints it.
pub fn format_client_id(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_json_gets_the_routeros_defaults() {
        let s: DhcpServer = serde_json::from_str(
            r#"{"id": "*1", "name": "dhcp1", "interface": "bridge1"}"#,
        )
        .unwrap();
        assert_eq!(
            s,
            DhcpServer::new(ItemId(1), "dhcp1".into(), "bridge1".parse().unwrap())
        );
        assert_eq!(s.lease_time, 1800);
        assert!(s.conflict_detection);
        let all = DhcpServers {
            servers: vec![s],
            ..DhcpServers::default()
        };
        let back: DhcpServers =
            serde_json::from_str(&serde_json::to_string(&all).unwrap()).unwrap();
        assert_eq!(back, all);
    }

    #[test]
    fn authoritative_delays() {
        assert!(Authoritative::Yes.naks_after(0));
        assert!(!Authoritative::No.naks_after(60));
        assert!(!Authoritative::After2SecDelay.naks_after(1));
        assert!(Authoritative::After2SecDelay.naks_after(2));
        assert!(!Authoritative::After10SecDelay.naks_after(9));
        assert_eq!(
            "after-10sec-delay".parse::<Authoritative>().unwrap(),
            Authoritative::After10SecDelay
        );
    }

    #[test]
    fn client_ids_round_trip() {
        let id = parse_client_id("1:2:0:0:ab:cd:ef").unwrap();
        assert_eq!(id, [1, 2, 0, 0, 0xab, 0xcd, 0xef]);
        assert_eq!(format_client_id(&id), "1:2:0:0:ab:cd:ef");
        assert_eq!(parse_client_id("0xff00").unwrap(), [0xff, 0]);
        for bad in ["", "1", "1::2", "xyz:1", "0x1", "123:1"] {
            assert!(parse_client_id(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn the_most_specific_network_wins() {
        let mut d = DhcpServers::default();
        d.networks
            .push(DhcpNetwork::new(ItemId(1), "10.0.0.0/16".parse().unwrap()));
        d.networks
            .push(DhcpNetwork::new(ItemId(2), "10.0.1.0/24".parse().unwrap()));
        assert_eq!(
            d.network_of("10.0.1.9".parse().unwrap()).unwrap().id,
            ItemId(2)
        );
        assert_eq!(
            d.network_of("10.0.2.9".parse().unwrap()).unwrap().id,
            ItemId(1)
        );
        assert!(d.network_of("10.1.0.1".parse().unwrap()).is_none());
    }
}
