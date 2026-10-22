//! The configuration tree. `Config` is plain data: cloning it is how the store
//! snapshots candidate/running and how the engine guard rolls back.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::types::{Asn, IfName, ItemId, MacAddr, VlanId};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub system: System,
    pub interfaces: BTreeMap<IfName, Interface>,
    pub ip: Ip,
    pub routing: Routing,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct System {
    pub identity: String,
}

impl Default for System {
    fn default() -> Self {
        Self {
            identity: "CoreRouter".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    pub name: IfName,
    pub kind: InterfaceKind,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub mac: Option<MacAddr>,
    #[serde(default)]
    pub comment: String,
}

fn default_mtu() -> u16 {
    1500
}

impl Interface {
    pub fn new(name: IfName, kind: InterfaceKind) -> Self {
        Self {
            name,
            kind,
            mtu: default_mtu(),
            disabled: false,
            mac: None,
            comment: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum InterfaceKind {
    Ethernet,
    Vlan { parent: IfName, vlan_id: VlanId },
    Bridge,
    Loopback,
}

impl InterfaceKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ethernet => "ether",
            Self::Vlan { .. } => "vlan",
            Self::Bridge => "bridge",
            Self::Loopback => "loopback",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ip {
    pub addresses: Vec<AddressEntry>,
    /// Next id handed out by `next_address_id` (never reused, like RouterOS).
    pub next_id: u32,
}

impl Ip {
    pub fn next_address_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressEntry {
    pub id: ItemId,
    pub address: IpNet,
    pub interface: IfName,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Routing {
    pub bgp: BTreeMap<String, BgpInstance>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpInstance {
    pub name: String,
    pub asn: Asn,
    pub router_id: Ipv4Addr,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}
