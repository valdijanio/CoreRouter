//! L0 — CoreRouter data model.
//!
//! Pure data: network types, the configuration tree, and the transactional
//! candidate/running store with commit history. No I/O, no clock, no UI, so it
//! compiles everywhere (including `wasm32-unknown-unknown`).

pub mod config;
pub mod neighbor;
pub mod persist;
pub mod store;
pub mod types;
pub mod validate;

pub use config::{
    AddressEntry, BgpInstance, Config, Interface, InterfaceKind, Ip, Routing, System,
};
pub use neighbor::{MgmtPorts, NeighborDiscovery, NeighborEntry, NeighborProtocol};
pub use persist::{FORMAT_VERSION, PersistError};
pub use store::{ConfigStore, DiffLine, Revision, StoreError};
pub use types::{Asn, IfName, ItemId, MacAddr, ParseError, VlanId};
pub use validate::Issue;
