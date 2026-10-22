//! L0 — CoreRouter data model.
//!
//! Pure data: network types, the configuration tree, and the transactional
//! candidate/running store with commit history. No I/O, no clock, no UI, so it
//! compiles everywhere (including `wasm32-unknown-unknown`).

pub mod config;
pub mod dhcp_client;
pub mod firewall;
pub mod interface_list;
pub mod neighbor;
pub mod persist;
pub mod route;
pub mod store;
pub mod types;
pub mod users;
pub mod validate;

pub use config::{
    AddressEntry, BgpInstance, Config, DEFAULT_DISTANCE, EthernetSettings, FlowControl, Interface,
    InterfaceKind, Ip, RouteEntry, Routing, System,
};
pub use dhcp_client::{AddDefaultRoute, AllowedServer, DhcpClient, ExtraOption};
pub use firewall::{Firewall, FirewallRule, Table};
pub use interface_list::InterfaceLists;
pub use neighbor::{MgmtPorts, NeighborDiscovery, NeighborEntry, NeighborProtocol};
pub use persist::{FORMAT_VERSION, PersistError};
pub use route::Reach;
pub use store::{ConfigStore, DiffLine, Revision, StoreError};
pub use types::{
    Asn, Gateway, IfName, ItemId, MacAddr, ParseError, RoutingTable, VlanId, parse_destination,
};
pub use users::{Group, User, Users};
pub use validate::Issue;
