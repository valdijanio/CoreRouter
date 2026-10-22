//! `/ipv6 dhcp-server` (G4.2c): the DHCPv6 server (RFC 9915, ex-8415) with
//! addresses (IA_NA) and prefix delegation (IA_PD, the CPE's LAN prefix),
//! its pools (`/ipv6 pool`: a prefix cut in prefixes of `prefix_length`;
//! 128 hands out single addresses), static bindings by DUID, and the
//! DHCPv6 relay (`/ipv6 dhcp-relay`). The bindings the server makes are
//! operational state, in their own journal.

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;
use serde::{Deserialize, Serialize};

use crate::types::{IfName, ItemId};

pub const MAX_POOLS: usize = 256;
pub const MAX_SERVERS: usize = 256;
pub const MAX_BINDINGS: usize = 65_536;
pub const MAX_RELAYS: usize = 256;
pub const MAX_LIST: usize = 8;
/// A pool holds at most 2^20 prefixes of its `prefix_length` (the server
/// scans it; **estimado**). Address pools (128) are hashed, not scanned.
pub const MAX_POOL_BITS: u8 = 20;
/// Default valid lifetime of a binding: a day (**estimado**; Kea's default
/// valid lifetime is 4000 s, a CPE's prefix should outlive short outages).
pub const DEFAULT_LEASE_TIME: u32 = 86_400;
pub const MIN_LEASE_TIME: u32 = 60;
pub const MAX_LEASE_TIME: u32 = 365 * 86_400;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ipv6Pool {
    pub id: ItemId,
    pub name: String,
    pub prefix: Ipv6Net,
    /// Length of what is handed out: 48..=64 for delegated prefixes, 128
    /// for addresses.
    pub prefix_length: u8,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dhcp6Server {
    pub id: ItemId,
    pub name: String,
    pub interface: IfName,
    /// Pool of addresses (`prefix_length` 128) for IA_NA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_pool: Option<String>,
    /// Pool of prefixes for IA_PD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_pool: Option<String>,
    /// Valid lifetime; the preferred one is ⅔ of it, T1 and T2 0.5 and 0.8
    /// of the preferred (RFC 9915 §21.4).
    #[serde(default = "default_lease_time")]
    pub lease_time: u32,
    /// Preference option (RFC 9915 §21.8): 255 makes a client stop looking.
    #[serde(default = "default_preference")]
    pub preference: u8,
    /// Two-message exchange when the client asks (RFC 9915 §18.3.1).
    #[serde(default = "yes")]
    pub rapid_commit: bool,
    /// Distance of the route to each delegated prefix.
    #[serde(default = "one")]
    pub route_distance: u8,
    /// Serve only requests relayed from this link (the relay's
    /// link-address); `None`: clients on the interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<Ipv6Addr>,
    /// Option 23 (RFC 3646).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_server: Vec<Ipv6Addr>,
    /// Option 24 (RFC 3646).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    /// Zone the addresses are named in (AAAA + PTR, G4.1c-3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_zone: Option<String>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

fn default_lease_time() -> u32 {
    DEFAULT_LEASE_TIME
}
fn default_preference() -> u8 {
    255
}
fn yes() -> bool {
    true
}
fn one() -> u8 {
    1
}

impl Dhcp6Server {
    pub fn new(id: ItemId, name: String, interface: IfName) -> Self {
        Self {
            id,
            name,
            interface,
            address_pool: None,
            prefix_pool: None,
            lease_time: DEFAULT_LEASE_TIME,
            preference: 255,
            rapid_commit: true,
            route_distance: 1,
            relay: None,
            dns_server: Vec::new(),
            domain: String::new(),
            dns_zone: None,
            disabled: false,
            comment: String::new(),
        }
    }
}

/// A static binding: this DUID (and IAID) gets this address and/or prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dhcp6Binding {
    pub id: ItemId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// The client's DUID, `0x…` hex.
    pub duid: String,
    /// `None`: any IAID of that client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iaid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Ipv6Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<Ipv6Net>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

/// `/ipv6 dhcp-relay`: client messages heard on `interface` go to the
/// servers as Relay-Forw (RFC 9915 §19).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dhcp6Relay {
    pub id: ItemId,
    pub name: String,
    pub interface: IfName,
    /// Servers (unicast); empty: All_DHCP_Servers ff05::1:3.
    #[serde(default)]
    pub dhcp_server: Vec<Ipv6Addr>,
    /// The link-address the servers pick the link by; `None`: a global
    /// address of the interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_address: Option<Ipv6Addr>,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Dhcp6Servers {
    pub pools: Vec<Ipv6Pool>,
    pub servers: Vec<Dhcp6Server>,
    pub bindings: Vec<Dhcp6Binding>,
    pub relays: Vec<Dhcp6Relay>,
    pub next_id: u32,
}

impl Dhcp6Servers {
    pub fn is_empty(&self) -> bool {
        self.pools.is_empty() && self.servers.is_empty() && self.bindings.is_empty() && self.relays.is_empty()
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    pub fn pool(&self, name: &str) -> Option<&Ipv6Pool> {
        self.pools.iter().find(|p| p.name == name)
    }

    pub fn server(&self, name: &str) -> Option<&Dhcp6Server> {
        self.servers.iter().find(|s| s.name == name)
    }
}

/// A DUID as written (`0x0003000102…`, or `00:03:00:01:…`) → bytes.
pub fn parse_duid(text: &str) -> Option<Vec<u8>> {
    let t = text.trim();
    let hex: String = match t.strip_prefix("0x") {
        Some(h) => h.to_owned(),
        None => t.split(':').collect(),
    };
    if hex.is_empty() || hex.len() % 2 != 0 || hex.len() > 2 * crate::ipv6::MAX_DUID {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| hex.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect::<Option<Vec<u8>>>()
        .filter(|d| d.len() >= 3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_duids() {
        let s: Dhcp6Server =
            serde_json::from_str(r#"{"id": "*1", "name": "v6", "interface": "bridge1"}"#).unwrap();
        assert_eq!(s, Dhcp6Server::new(ItemId(1), "v6".into(), "bridge1".parse().unwrap()));
        assert_eq!(parse_duid("0x00030001020000000001").unwrap().len(), 10);
        assert_eq!(parse_duid("00:03:00:01:02:00:00:00:00:01").unwrap().len(), 10);
        assert!(parse_duid("0x01").is_none());
        assert!(parse_duid("zz").is_none());
    }
}
