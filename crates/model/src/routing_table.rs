//! `/routing table` (G1.27e): a named kernel routing table that is not a
//! VRF. Routes go in with `routing_table: <name>`; packets reach it through
//! `/routing rule` or a mangle routing mark of the same name.
//!
//! Unlike a VRF's table it has no interfaces of its own: a gateway resolves
//! through the main table's connected networks (RouterOS v7 does the same
//! with `@main`; Linux's `fib_check_nh` falls back to a full lookup when the
//! route's own table does not reach the gateway).

use serde::{Deserialize, Serialize};

use crate::types::IfName;

/// RouterOS v7's limit ("4096 unique routing tables").
pub const MAX_TABLES: usize = 4096;

/// The names of the kernel's own tables, which a named table cannot take.
pub const RESERVED: [&str; 4] = ["main", "local", "default", "unspec"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedTable {
    pub name: IfName,
    /// Kernel table id, from the same range as the VRFs', kept across
    /// reboots.
    pub table: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}
