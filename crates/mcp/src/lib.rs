//! L4 — MCP server.
//!
//! JSON-RPC 2.0 over stdio, written by hand: no SDK, no async runtime. It has
//! no router logic: tools translate into control-channel method calls on a
//! [`Backend`], which ends in the same `Session::execute` the UI uses.
//! stdout carries protocol only; logs go to stderr.

pub mod backend;
#[doc(hidden)]
pub mod fuzz;
pub mod server;
pub mod tools;

pub use backend::{Backend, Headless, Remote};
pub use server::{handle_message, serve};
