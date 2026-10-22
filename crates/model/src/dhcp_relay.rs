//! `/ip dhcp-relay` (G4.2b): the router passes the DHCP requests it hears
//! on an interface to DHCP servers elsewhere (RFC 2131 §4.1 relay agent,
//! BOOTP's RFC 1542), optionally adding option 82 (RFC 3046) so the server
//! knows the port and the line the client is on.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::types::{IfName, ItemId};

pub const MAX_RELAYS: usize = 256;
/// Servers one relay forwards to.
pub const MAX_SERVERS: usize = 8;
/// A relayed message that went through this many agents is dropped
/// (RFC 1542 §4.1.1 suggests 4 as a default, 16 at most).
pub const MAX_HOPS: u8 = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DhcpRelay {
    pub id: ItemId,
    pub name: String,
    /// Where the clients are.
    pub interface: IfName,
    /// Servers each request goes to (all of them, as RouterOS does).
    pub dhcp_server: Vec<Ipv4Addr>,
    /// `giaddr`: the router's address the servers answer to and pick the
    /// client's network by; `None`: the interface's first address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_address: Option<Ipv4Addr>,
    /// Add option 82: circuit id = the interface's name, remote id = the
    /// client's MAC (or `relay_info_remote_id`).
    #[serde(default)]
    pub add_relay_info: bool,
    /// Remote id to send instead of the client's MAC.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub relay_info_remote_id: String,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl DhcpRelay {
    pub fn new(id: ItemId, name: String, interface: IfName) -> Self {
        Self {
            id,
            name,
            interface,
            dhcp_server: Vec::new(),
            local_address: None,
            add_relay_info: false,
            relay_info_remote_id: String::new(),
            disabled: false,
            comment: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DhcpRelays {
    pub relays: Vec<DhcpRelay>,
    pub next_id: u32,
}

impl DhcpRelays {
    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let r: DhcpRelay = serde_json::from_str(
            r#"{"id": "*1", "name": "relay1", "interface": "vlan20", "dhcp_server": ["10.0.0.2"]}"#,
        )
        .unwrap();
        assert!(!r.add_relay_info);
        let all = DhcpRelays { relays: vec![r], next_id: 1 };
        let back: DhcpRelays = serde_json::from_str(&serde_json::to_string(&all).unwrap()).unwrap();
        assert_eq!(back, all);
    }
}
