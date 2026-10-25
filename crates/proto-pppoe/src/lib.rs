//! L2 — PPPoE (RFC 2516) and PPP for a pure-Rust BNG (G4.3a). Pure: no
//! sockets, no clock, no `unsafe`; compiles for `wasm32-unknown-unknown`.
//!
//! - Codecs ([`eth`], [`discovery`], [`ppp`], [`lcp`], [`auth`], [`ncp`])
//!   read borrowed views of the frame and never panic on hostile input.
//! - [`fsm`] is the RFC 1661 §4 option negotiation automaton; [`layers`]
//!   holds LCP/IPCP/IPv6CP's option logic for both ends.
//! - [`server::Server`] is the access concentrator and [`client::Client`]
//!   the subscriber (the load generator): sans-IO, driven by frames, an
//!   explicit clock ([`timer::Millis`]) and the caller's answers, returning
//!   frames and events in an [`output::Output`].
//! - [`descriptor::SessionDescriptor`] is what the XDP data plane (G4.3c)
//!   mirrors; [`lab`] and [`fuzz`] are the mass simulation and the fuzz
//!   oracles.
//!
//! The AF_PACKET sockets live in `hal-linux` and the service in the daemon
//! (G4.3d). Design, research and the RFC rule table: `docs/pppoe.md`.

pub mod auth;
pub mod client;
pub mod descriptor;
pub mod discovery;
pub mod eth;
pub mod fsm;
pub mod fuzz;
pub mod guard;
pub mod lab;
pub mod layers;
pub mod lcp;
pub mod ncp;
pub mod nd;
pub mod output;
pub mod ppp;
pub mod server;
pub mod timer;
pub mod wire;
