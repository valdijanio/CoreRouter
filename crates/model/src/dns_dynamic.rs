//! Dynamic records of the authoritative zones (G4.1c-3): what RFC 2136
//! UPDATE (a DHCP server's dhcp-ddns) and the router's own services (the
//! DHCP server of G4.2, through `Session::dns_dynamic_*`) put in a primary
//! zone, next to the configured records.
//!
//! **Not** config: a lease is not a revision, a rollback must not bring
//! back an expired lease's name, and `config.diff` would drown in them.
//! The engine keeps this in the storage's operational state
//! (`dns-dynamic`) and changes it at once, like the DHCP client's leases.
//! A record may expire (a lease's end); the configured records are never
//! touched by an UPDATE.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::dns_zone::ZoneRecord;

/// Dynamic records of all zones together (a big LAN's leases, twice: A
/// and PTR).
pub const MAX_DYNAMIC: usize = 20_000;
/// Records one UPDATE message may change (RFC 2136 has no limit; a DHCP
/// server sends a few).
pub const MAX_PER_UPDATE: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicRecord {
    /// The record (its own `id` space, `D` in `print`).
    pub record: ZoneRecord,
    /// When it goes by itself (a lease's end); `None`: until removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_unix: Option<u64>,
    /// Who put it there (`update 192.0.2.5 key dhcp-ddns`, `dhcp lan`).
    pub source: String,
    pub created_unix: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DynamicState {
    pub records: Vec<DynamicRecord>,
    pub next_id: u32,
    /// The serial each zone was last served with after a dynamic change:
    /// the next one is larger, even after a restart (RFC 2136 §3.6 / RFC
    /// 1982).
    pub serials: BTreeMap<String, u32>,
}

impl DynamicState {
    pub fn records_of<'a>(&'a self, zone: &'a str) -> impl Iterator<Item = &'a DynamicRecord> + 'a {
        self.records.iter().filter(move |r| r.record.zone == zone)
    }

    /// Why this state cannot be loaded (a damaged or hostile file).
    pub fn problem(&self) -> Option<String> {
        if self.records.len() > MAX_DYNAMIC {
            return Some(format!("more than {MAX_DYNAMIC} dynamic records"));
        }
        self.records
            .iter()
            .find_map(|r| r.record.problem().map(|p| format!("dynamic record {}: {p}", r.record.id)))
    }
}

/// One change of an UPDATE (RFC 2136 §2.5), in zone terms: names relative
/// to the zone (`@` the apex).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicOp {
    /// §2.5.1: add to an RRset (an equal record only gets the new TTL).
    Add(ZoneRecord),
    /// §2.5.2: delete an RRset.
    DeleteRrset { name: String, rtype: crate::dns_zone::RecordType },
    /// §2.5.3: delete every RRset of a name.
    DeleteName { name: String },
    /// §2.5.4: delete one record.
    DeleteRecord(ZoneRecord),
}
