//! L4 — MCP server.
//!
//! JSON-RPC 2.0 over stdio, written by hand: no SDK, no async runtime. It has
//! no router logic: tools, resources and prompts translate into control-channel method calls on a
//! [`Backend`], which ends in the same `Session::execute` the UI uses.
//! stdout carries protocol only; logs go to stderr.

// Every `src/<name>.rs` and `src/<name>/mod.rs` is a public module, generated
// by build.rs (build-support/root_modules.rs): a new module is a new file.
include!(concat!(env!("OUT_DIR"), "/modules.rs"));

pub use backend::{Backend, Headless, Remote};
pub use server::{handle_message, serve};
