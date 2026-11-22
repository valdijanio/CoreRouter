//! L2 — high availability for the BNG (G4.3h): two CoreRouters as an
//! active/standby pair for the same subscribers. Pure: no sockets, no
//! clock, no `unsafe`; compiles for `wasm32-unknown-unknown`.
//!
//! - [`role::Ha`] decides who is active: a role machine (init, standby,
//!   active, fenced, yielding) with hold timers and fencing by a majority
//!   of three (this node, the peer, a witness). Two paths to hear the peer:
//!   the sync stream and the authenticated access-side [`hello`].
//! - [`sync::Publisher`] and [`sync::Replica`] keep the standby's copy of
//!   the session table (hot standby): snapshot, deltas with sequence
//!   numbers, batched acks, resync after a hole.
//! - [`msg`] is the versioned, length-framed codec of the sync stream;
//!   [`record::SessionRecord`] what one session needs to move to the other
//!   node without the subscriber noticing (TLV, forward compatible).
//! - [`lab`] runs two nodes in memory with a fake clock and hostile links;
//!   [`fuzz`] holds the oracles of the proptests and of libFuzzer.
//!
//! The daemon's `pppoe` service drives it (sockets, TLS, the XDP maps).
//! Design, research and numbers: `docs/bng-ha.md`.

pub mod fuzz;
pub mod hello;
pub mod lab;
pub mod msg;
pub mod node;
pub mod record;
pub mod role;
pub mod sync;
pub mod wire;

/// Milliseconds of the caller's monotonic clock.
pub type Millis = u64;
