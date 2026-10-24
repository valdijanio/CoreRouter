// SPDX-License-Identifier: GPL-2.0-or-later
//! The maps of the XDP filter: names (the loader finds them by name in the
//! object), sizes and value layouts. Keys and values are plain integers or
//! byte arrays, which both aya sides already treat as plain data.
//!
//! | map | type | key | value |
//! |---|---|---|---|
//! | `SETTINGS` | array | index | `u64` ([`crate::filter::Settings::to_words`]) |
//! | `BLOCK_V4` / `BLOCK_V6` | LPM trie | prefix of `[u8; 4]` / `[u8; 16]` | block list index `u32` |
//! | `ALLOW_V4` / `ALLOW_V6` | LPM trie | same | allow list index `u32` |
//! | `RATE` | LRU hash | source ([`crate::parse::Addr::mapped`]) | [`crate::bucket::Bucket`] |
//! | `COUNTERS` | per-CPU hash | [`counter_key`] | [`Counter`] |
//! | `TOP` | LRU per-CPU hash | dropped source (mapped) | [`Top`] |
//! | `NAT_FLOWS` | LRU hash | [`crate::fastnat::FlowKey`] | [`crate::fastnat::FlowValue`] |
//! | `PPPOE_KEYS` | hash | [`crate::pppoe::SessionKey::to_bytes`] | session index `u32` |
//! | `PPPOE_SESSIONS` | array | session index | [`crate::pppoe::SessionWords`] |
//! | `PPPOE_V4` | hash | subscriber IPv4 | session index |
//! | `PPPOE_V6` | LPM trie | subscriber /64 or delegated prefix | session index |
//! | `PPPOE_POLICER` | array | index × 2 + direction | [`crate::policer::State`] |
//! | `PPPOE_COUNTERS` | array | session index | [`crate::pppoe::Counters`] |
//! | `PPPOE_STATS` | per-CPU array | [`crate::pppoe::Stat`] | packets `u64` |

use crate::filter::Reason;

pub const SETTINGS: &str = "SETTINGS";
pub const BLOCK_V4: &str = "BLOCK_V4";
pub const BLOCK_V6: &str = "BLOCK_V6";
pub const ALLOW_V4: &str = "ALLOW_V4";
pub const ALLOW_V6: &str = "ALLOW_V6";
pub const RATE: &str = "RATE";
pub const COUNTERS: &str = "COUNTERS";
pub const TOP: &str = "TOP";
pub const NAT_FLOWS: &str = "NAT_FLOWS";
pub const NAT_MISS: &str = "NAT_MISS";
pub const PPPOE_KEYS: &str = "PPPOE_KEYS";
pub const PPPOE_SESSIONS: &str = "PPPOE_SESSIONS";
pub const PPPOE_V4: &str = "PPPOE_V4";
pub const PPPOE_V6: &str = "PPPOE_V6";
pub const PPPOE_POLICER: &str = "PPPOE_POLICER";
pub const PPPOE_COUNTERS: &str = "PPPOE_COUNTERS";
pub const PPPOE_STATS: &str = "PPPOE_STATS";
/// The PPPoE maps sized by the session count (1 entry while PPPoE is off).
pub const PPPOE_SIZED: [&str; 4] = [PPPOE_KEYS, PPPOE_SESSIONS, PPPOE_V4, PPPOE_COUNTERS];
/// The XDP program's name in the object.
pub const PROGRAM: &str = "corerouter_xdp";

/// Prefixes the IPv4 block (and allow) trie holds. An LPM trie is not
/// preallocated: memory follows the entries (~64 bytes per node in the
/// kernel, **estimated**), so this is a ceiling, not a cost.
pub const PREFIXES_V4: u32 = 1 << 20;
pub const PREFIXES_V6: u32 = 1 << 18;
/// Sources with a rate-limit bucket. Preallocated (LRU): ~100 bytes each
/// with the kernel's per-element overhead, **estimated** ~25 MiB. Past it
/// the least recently seen source loses its bucket (and starts full again).
pub const RATE_SOURCES: u32 = 1 << 18;
/// Dropped sources remembered for the top-sources table (LRU).
pub const TOP_SOURCES: u32 = 1 << 14;
/// Flow directions the CGNAT fast path holds (two per connection) when it
/// is on (G2.5b). LRU, so preallocated: ~100 bytes each with the kernel's
/// per-element overhead, **estimated** ~50 MiB; the loader sizes the map
/// to 1 entry while the fast path is off. Past it the least recently used
/// flow falls back to the kernel (still correct, slower).
pub const NAT_FLOWS_MAX: u32 = 1 << 19;
/// Interfaces × reasons of the counters map.
pub const MAX_INTERFACES: u32 = 256;
pub const COUNTER_ENTRIES: u32 = MAX_INTERFACES * Reason::ALL.len() as u32;
/// Array slots of `SETTINGS`.
pub const SETTINGS_SLOTS: u32 = 8;

/// `[packets, bytes]`, per CPU.
pub type Counter = [u64; 2];
/// `[packets, bytes, last_ns, last reason | block list index << 8]`, per
/// CPU (the loader sums the counts and keeps the latest tag).
pub type Top = [u64; 4];

/// The counters map key of interface `ifindex`, reason `reason`.
pub fn counter_key(ifindex: u32, reason: Reason) -> u64 {
    (u64::from(ifindex) << 8) | reason as u64
}

/// Back from [`counter_key`].
pub fn split_counter_key(key: u64) -> (u32, Option<Reason>) {
    let ifindex = u32::try_from(key >> 8).unwrap_or(u32::MAX);
    (ifindex, Reason::from_u8((key & 0xff) as u8))
}

/// The last word of [`Top`].
pub fn top_tag(reason: Reason, list: Option<u32>) -> u64 {
    let list = u64::from(list.map_or(0xff_ffff, |l| l.min(0xff_fffe)));
    reason as u64 | (list << 8)
}

/// Back from [`top_tag`].
pub fn split_top_tag(tag: u64) -> (Option<Reason>, Option<u32>) {
    let list = u32::try_from((tag >> 8) & 0xff_ffff).unwrap_or(0xff_ffff);
    (
        Reason::from_u8((tag & 0xff) as u8),
        (list != 0xff_ffff).then_some(list),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip() {
        for r in Reason::ALL {
            assert_eq!(split_counter_key(counter_key(7, r)), (7, Some(r)));
            assert_eq!(split_top_tag(top_tag(r, Some(3))), (Some(r), Some(3)));
            assert_eq!(split_top_tag(top_tag(r, None)), (Some(r), None));
        }
    }
}
