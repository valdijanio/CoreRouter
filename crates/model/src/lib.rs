//! L0 — CoreRouter data model.
//!
//! Pure data: network types, the configuration tree, and the transactional
//! candidate/running store with commit history. No I/O, no clock, no UI, so it
//! compiles everywhere (including `wasm32-unknown-unknown`).

pub mod config;
pub mod neighbor;
pub mod persist;
pub mod route;
pub mod store;
pub mod types;
pub mod validate;

pub use config::{
    AddressEntry, BgpInstance, Config, DEFAULT_DISTANCE, Interface, InterfaceKind, Ip, RouteEntry,
    Routing, System,
};
pub use neighbor::{MgmtPorts, NeighborDiscovery, NeighborEntry, NeighborProtocol};
pub use persist::{FORMAT_VERSION, PersistError};
pub use route::Reach;
pub use store::{ConfigStore, DiffLine, Revision, StoreError};
pub use types::{
    Asn, Gateway, IfName, ItemId, MacAddr, ParseError, RoutingTable, VlanId, parse_destination,
};
pub use validate::Issue;
