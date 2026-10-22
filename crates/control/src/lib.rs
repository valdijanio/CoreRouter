//! L4 — Control channel.
//!
//! One JSON request per line: `{"id","method","params"}` →
//! `{"id","ok":true,"result"}` | `{"id","ok":false,"error"}`.
//! Loopback only, at most 16 connections, any non-JSON line closes the
//! connection (this blocks a browser `fetch` from a web page).
//!
//! The same method names are served by the GUI (`--control`), the daemon and
//! the MCP headless backend, so MCP tools are written once.

pub mod client;
pub mod dispatch;
pub mod server;
pub mod wire;

pub use client::Client;
pub use dispatch::{Host, NO_UI, SharedHost, dispatch};
pub use server::{bind_loopback, serve, spawn};

pub const DEFAULT_PORT: u16 = 7979;
