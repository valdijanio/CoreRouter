//! L4 — Control channel.
//!
//! One JSON request per line: `{"id","method","params","token"}` →
//! `{"id","ok":true,"result"}` | `{"id","ok":false,"error"}`.
//! At most 16 connections per endpoint, any non-JSON line closes the
//! connection (this blocks a browser `fetch` from a web page).
//!
//! G0.3: every request but `ping`/`server.info`/`auth.login` needs a token
//! ([`auth`]): a session token from `auth.login`, or the [`local_token`]
//! file. Plain TCP is loopback only; any other address is TLS ([`tls`]),
//! and clients pin the certificate on first use ([`known_hosts`], [`dial`]).
//!
//! [`ws`] serves the same methods over WebSocket for the GUI in a browser,
//! with an `Origin` allow-list so an arbitrary page cannot reach the router.
//!
//! The same method names are served by the GUI (`--control`), the daemon and
//! the MCP headless backend, so MCP tools are written once.

pub mod auth;
pub mod client;
pub mod clock;
pub mod dial;
pub mod dispatch;
pub mod known_hosts;
pub mod local_token;
pub mod server;
pub mod tasks;
pub mod tls;
pub mod wire;
pub mod ws;

pub use auth::{Gate, Limits, UNAUTHORIZED};
pub use client::{Client, reply_result};
pub use clock::spawn_clock;
pub use dial::{Login, Target, Trust, dial};
pub use dispatch::{Host, NO_UI, SharedHost, dispatch, dispatch_as, hang_up, new_caller};
pub use known_hosts::KnownHosts;
pub use server::{Endpoint, Shutdown, bind_loopback, serve, serve_until, spawn, spawn_until};
pub use tasks::{ThreadRunner, thread_runner};
pub use ws::{WsPolicy, serve_ws, serve_ws_until, spawn_ws, spawn_ws_until};

pub const DEFAULT_PORT: u16 = 7979;
/// Suggested port of the TLS endpoint (`--listen`), as RouterOS' api-ssl.
pub const DEFAULT_TLS_PORT: u16 = 8729;
