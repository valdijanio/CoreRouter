//! L4 — Control channel.
//!
//! One JSON request per line: `{"id","method","params"}` →
//! `{"id","ok":true,"result"}` | `{"id","ok":false,"error"}`.
//! Loopback only, at most 16 connections, any non-JSON line closes the
//! connection (this blocks a browser `fetch` from a web page).
//!
//! [`ws`] serves the same methods over WebSocket for the GUI in a browser,
//! with an `Origin` allow-list so an arbitrary page cannot reach the router.
//!
//! The same method names are served by the GUI (`--control`), the daemon and
//! the MCP headless backend, so MCP tools are written once.

pub mod client;
pub mod clock;
pub mod dispatch;
pub mod server;
pub mod tasks;
pub mod wire;
pub mod ws;

pub use client::{Client, reply_result};
pub use clock::spawn_clock;
pub use dispatch::{Host, NO_UI, SharedHost, dispatch, dispatch_as, hang_up, new_caller};
pub use server::{Shutdown, bind_loopback, serve, serve_until, spawn};
pub use tasks::{ThreadRunner, thread_runner};
pub use ws::{WsPolicy, serve_ws, serve_ws_until, spawn_ws, spawn_ws_until};

pub const DEFAULT_PORT: u16 = 7979;
