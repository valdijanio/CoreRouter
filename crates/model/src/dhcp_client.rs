//! `/ip dhcp-client` (G4.7): one DHCPv4 client per interface, configured
//! like RouterOS'. Only the configuration lives here; the lease, the
//! address and routes it brings and the event history are operational
//! state kept by the engine (never saved, never in a revision).

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::DEFAULT_DISTANCE;
use crate::types::{IfName, ItemId, MacAddr, ParseError, RoutingTable};

/// At most this many clients (one per interface; **estimado**, hostile-input
/// bound).
pub const MAX_CLIENTS: usize = 256;
/// Entries of `allowed_servers` and of `extra_options`.
pub const MAX_ALLOWED: usize = 16;
pub const MAX_EXTRA: usize = 16;
/// `host_name`: one DNS label set, as option 12 allows.
pub const MAX_HOST_NAME: usize = 63;
/// `client_id`, `vendor_class` and one `extra_options` value, as written.
pub const MAX_VALUE_TEXT: usize = 255;

/// What the lease's routes do (RouterOS `add-default-route`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddDefaultRoute {
    /// Classless routes (option 121) when the server sends them — the router
    /// option (3) is then ignored, as RFC 3442 says — else a default route
    /// via the router option.
    #[default]
    Yes,
    /// No route at all from the lease.
    No,
    /// Classless routes *and* the default route via option 3 (servers that
    /// send a default route only in option 3 and other routes in 121).
    SpecialClassless,
}

impl AddDefaultRoute {
    pub const ALL: [Self; 3] = [Self::Yes, Self::No, Self::SpecialClassless];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yes => "yes",
            Self::No => "no",
            Self::SpecialClassless => "special-classless",
        }
    }
}

impl fmt::Display for AddDefaultRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AddDefaultRoute {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|v| v.as_str() == s.trim())
            .ok_or_else(|| {
                ParseError::new(
                    "add-default-route",
                    s,
                    "expected yes, no or special-classless",
                )
            })
    }
}

/// How a gateway is checked (RouterOS `check-gateway`): the DHCP client's
/// lease gateway (G4.7c) and static routes (G1.27f, `RouteEntry`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckGateway {
    /// No check: the routes stay while the lease does.
    #[default]
    None,
    /// An ARP request every 10 s: the gateway must answer it.
    Arp,
    /// An ICMP echo every 10 s from the lease's address.
    Ping,
    /// A BFD session to the gateway (RFC 5880/5881), static routes only:
    /// the profile's detect time instead of 10 s × 2 (G3.6g).
    Bfd,
}

impl CheckGateway {
    /// No check (serde: left out of a route that has none).
    pub fn is_none(&self) -> bool {
        *self == Self::None
    }

    pub const ALL: [Self; 4] = [Self::None, Self::Arp, Self::Ping, Self::Bfd];
    /// What a DHCP client can use (no BFD to a lease's gateway).
    pub const DHCP: [Self; 3] = [Self::None, Self::Arp, Self::Ping];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Arp => "arp",
            Self::Ping => "ping",
            Self::Bfd => "bfd",
        }
    }
}

impl fmt::Display for CheckGateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CheckGateway {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|v| v.as_str() == s.trim())
            .ok_or_else(|| ParseError::new("check-gateway", s, "expected none, arp, ping or bfd"))
    }
}

/// `fallback_timeout` bounds and default, in seconds (dhcpcd waits 30 s
/// before its fallback; **estimado** good for a WAN).
pub const MIN_FALLBACK_TIMEOUT: u32 = 5;
pub const MAX_FALLBACK_TIMEOUT: u32 = 3_600;
pub const DEFAULT_FALLBACK_TIMEOUT: u32 = 30;

/// A server the client accepts: by its IP (server identifier or packet
/// source) or by the MAC its answers come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum AllowedServer {
    Ip(Ipv4Addr),
    Mac(MacAddr),
}

impl FromStr for AllowedServer {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        if let Ok(ip) = t.parse::<Ipv4Addr>() {
            return Ok(Self::Ip(ip));
        }
        t.parse::<MacAddr>().map(Self::Mac).map_err(|_| {
            ParseError::new(
                "allowed server",
                s,
                "expected an IPv4 address (192.0.2.1) or a MAC (AA:BB:CC:DD:EE:FF)",
            )
        })
    }
}

impl fmt::Display for AllowedServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Mac(mac) => write!(f, "{mac}"),
        }
    }
}

impl TryFrom<String> for AllowedServer {
    type Error = ParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<AllowedServer> for String {
    fn from(a: AllowedServer) -> Self {
        a.to_string()
    }
}

/// One option the client sends in every message. `value` uses RouterOS'
/// option syntax (`0x0a0b`, `'text'`, `s'10.0.0.1'`, `'10.0.0.1'`, `'10'`,
/// `$(HOSTNAME)`, concatenated); `proto-dhcp` turns it into bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtraOption {
    pub code: u8,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DhcpClient {
    pub id: ItemId,
    pub interface: IfName,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub add_default_route: AddDefaultRoute,
    /// Distance of every route the lease brings (1..=255).
    #[serde(default = "default_distance")]
    pub default_route_distance: u8,
    /// Table of the lease's routes; `None` follows the interface (main, or
    /// its VRF). When set it must be the interface's table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_route_table: Option<RoutingTable>,
    #[serde(default = "yes")]
    pub use_peer_dns: bool,
    #[serde(default = "yes")]
    pub use_peer_ntp: bool,
    /// Option 12; empty sends the system identity.
    #[serde(default)]
    pub host_name: String,
    /// Option 61 in the option syntax; empty sends `0x01` + the MAC.
    #[serde(default)]
    pub client_id: String,
    /// Option 60 in the option syntax; empty sends none.
    #[serde(default)]
    pub vendor_class: String,
    #[serde(default)]
    pub extra_options: Vec<ExtraOption>,
    /// Empty: any server.
    #[serde(default)]
    pub allowed_servers: Vec<AllowedServer>,
    /// Withhold the lease's routes while their gateway does not answer.
    #[serde(default)]
    pub check_gateway: CheckGateway,
    /// Address put on the interface while no server answers (a modem's
    /// management network, say); removed when a lease comes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_address: Option<Ipv4Net>,
    /// Seconds without a lease before the fallback address goes up.
    #[serde(default = "default_fallback_timeout")]
    pub fallback_timeout: u32,
}

fn default_fallback_timeout() -> u32 {
    DEFAULT_FALLBACK_TIMEOUT
}

fn default_distance() -> u8 {
    DEFAULT_DISTANCE
}

fn yes() -> bool {
    true
}

impl DhcpClient {
    /// A client with RouterOS' defaults.
    pub fn new(id: ItemId, interface: IfName) -> Self {
        Self {
            id,
            interface,
            disabled: false,
            comment: String::new(),
            add_default_route: AddDefaultRoute::Yes,
            default_route_distance: DEFAULT_DISTANCE,
            default_route_table: None,
            use_peer_dns: true,
            use_peer_ntp: true,
            host_name: String::new(),
            client_id: String::new(),
            vendor_class: String::new(),
            extra_options: Vec::new(),
            allowed_servers: Vec::new(),
            check_gateway: CheckGateway::None,
            fallback_address: None,
            fallback_timeout: DEFAULT_FALLBACK_TIMEOUT,
        }
    }

    /// Whether `ip` / `mac` may answer this client.
    pub fn allows(&self, ip: &[Ipv4Addr], mac: Option<[u8; 6]>) -> bool {
        allows(&self.allowed_servers, ip, mac)
    }
}

/// Whether a server seen as `ip` (its identifier and the packet source)
/// with Ethernet source `mac` is in `list` (empty: any server is).
pub fn allows(list: &[AllowedServer], ip: &[Ipv4Addr], mac: Option<[u8; 6]>) -> bool {
    list.is_empty()
        || list.iter().any(|a| match a {
            AllowedServer::Ip(want) => ip.contains(want),
            AllowedServer::Mac(want) => mac == Some(want.0),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_json_gets_the_routeros_defaults() {
        let c: DhcpClient = serde_json::from_str(r#"{"id": "*1", "interface": "ether1"}"#).unwrap();
        assert_eq!(c, DhcpClient::new(ItemId(1), "ether1".parse().unwrap()));
        let back: DhcpClient = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn allowed_servers_parse_ips_and_macs() {
        let ip: AllowedServer = "192.0.2.1".parse().unwrap();
        let mac: AllowedServer = "aa-bb-cc-dd-ee-ff".parse().unwrap();
        assert_eq!(mac.to_string(), "AA:BB:CC:DD:EE:FF");
        assert!("nope".parse::<AllowedServer>().is_err());
        let mut c = DhcpClient::new(ItemId(1), "ether1".parse().unwrap());
        assert!(c.allows(&[], None), "empty list: anyone");
        c.allowed_servers = vec![ip, mac];
        assert!(c.allows(&["192.0.2.1".parse().unwrap()], None));
        assert!(c.allows(&[], Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])));
        assert!(!c.allows(&["192.0.2.2".parse().unwrap()], Some([0; 6])));
        assert_eq!(
            "special-classless".parse::<AddDefaultRoute>().unwrap(),
            AddDefaultRoute::SpecialClassless
        );
    }
}
