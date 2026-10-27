//! L2 — flow export (G4.4b), as RouterOS `/ip traffic-flow` does it: flow
//! records and NAT events in IPFIX or NetFlow v9, built from the kernel's
//! connection tracking rather than from sampled packets.
//!
//! - [`meter`]: conntrack events and table reads → [`Record`]s (active and
//!   inactive timeouts, sampling, NAT44 session events);
//! - [`export`]: records → IPFIX or v9 messages, templates refreshed by time
//!   and by count;
//! - [`decode`]: messages → records again (tests and the test collector).
//!
//! Pure: no I/O, no clock (every call takes `now_ms`), so it compiles to
//! wasm. The sockets are the daemon's (`service/traffic_flow.rs`).
//!
//! References (read 2026-10-23; the full list is in `docs/traffic-flow.md`):
//! - RFC 7011 (IPFIX protocol) §3 (message, set and template formats), §8
//!   (template management), §10.3 (UDP: template refresh, message size);
//!   RFC 7012 and the IANA registry (element numbers and types).
//! - RFC 3954 (NetFlow v9) §5 (packet layout), §6.1 (options template), §8
//!   (field types).
//! - RFC 8158 (IPFIX elements for NAT events) §4: `natEvent` values and the
//!   NAT44 session and port block templates.
//! - RFC 5103 (bidirectional flows) §6.3: `biflowDirection`.

pub mod decode;
pub mod export;
pub mod ie;
pub mod meter;
pub mod record;
pub mod template;

pub use export::{Exporter, MIN_MESSAGE};
pub use meter::{Meter, MeterConfig, Router};
pub use record::{
    Direction, EndReason, Flow, Meta, NatEvent, NatEventType, NatLimit, PortBlock, Record,
};
pub use template::Version;

#[cfg(test)]
mod tests;
