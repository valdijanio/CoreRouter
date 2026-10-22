//! L4 — CRDP runtime (docs/discovery.md): the UDP sockets and std threads
//! around the pure codec of `corerouter-proto-discovery`.
//!
//! - [`Agent`] (daemon): announces on the interfaces where discovery is
//!   active and records what it hears with `Session::record_neighbor`.
//! - [`Listener`] (native GUI): only listens, on every interface of the
//!   workstation, for the connect screen.
//!
//! Not for wasm (sockets and threads); the web GUI reads `ip.neighbor.list`.

pub mod agent;
pub mod ifaces;
pub mod listen;
pub mod sock;

pub use agent::{Agent, AgentConfig};
pub use corerouter_proto_discovery::{NodeId, PORT};
pub use listen::{Heard, Listener};
