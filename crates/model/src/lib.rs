//! L0 — CoreRouter data model.
//!
//! Pure data: network types, the configuration tree, and the transactional
//! candidate/running store with commit history. No I/O, no clock, no UI, so it
//! compiles everywhere (including `wasm32-unknown-unknown`).

// Every `src/<name>.rs` and `src/<name>/mod.rs` is a public module, generated
// by build.rs (build-support/root_modules.rs): a new module is a new file.
include!(concat!(env!("OUT_DIR"), "/modules.rs"));

pub use bonding::{BondMode, HashPolicy, LacpRate};
pub use config::{
    AddressEntry, BgpInstance, Config, DEFAULT_DISTANCE, EthernetSettings, FlowControl, Interface,
    InterfaceKind, Ip, RouteEntry, Routing, System,
};
pub use dhcp_client::{AddDefaultRoute, AllowedServer, DhcpClient, ExtraOption};
pub use firewall::{Firewall, FirewallRule, Table};
pub use interface_list::InterfaceLists;
pub use ipv6::{AcceptRa, AllowedServer6, Dhcp6Client, Ipv6, Ipv6Settings, Request6};
pub use neighbor::{MgmtPorts, NeighborDiscovery, NeighborEntry, NeighborProtocol};
pub use persist::{FORMAT_VERSION, PersistError};
pub use route::Reach;
pub use store::{ConfigStore, DiffLine, Revision, StoreError};
pub use types::{
    Asn, Gateway, IfName, ItemId, MacAddr, ParseError, RoutingTable, VlanId, parse_destination,
};
pub use users::{Group, User, Users};
pub use validate::Issue;
