//! L2 — PPPoE (RFC 2516) and PPP for a pure-Rust BNG (G4.3a). Pure: no
//! sockets, no clock, no `unsafe`; compiles for `wasm32-unknown-unknown`.

pub mod auth;
pub mod client;
pub mod descriptor;
pub mod discovery;
pub mod eth;
pub mod fsm;
pub mod guard;
pub mod lab;
pub mod layers;
pub mod lcp;
pub mod ncp;
pub mod output;
pub mod ppp;
pub mod server;
pub mod timer;
pub mod wire;
