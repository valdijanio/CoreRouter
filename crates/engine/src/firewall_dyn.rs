//! Dynamic address-list entries (with a timeout): operational state, like
//! the neighbor table — never in the config, never saved, gone after a
//! restart (RouterOS' dynamic entries behave the same). The data plane gets
//! each one through `Hal::address_list_dynamic` and expires it by itself;
//! this table only mirrors it for `ip.firewall.address-list.list`.

use corerouter_hal::DynamicChange;
use corerouter_model::ItemId;
use corerouter_model::firewall::{AddrMatch, DynamicAddress, Name};

use crate::Session;

/// Dynamic ids live apart from the config's (`*D0000001`…), so a static
/// entry and a dynamic one never share an id.
pub const ID_BASE: u32 = 0xD000_0000;
/// Hostile-input bound (**estimado**).
pub const MAX_DYNAMIC: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicEntry {
    pub id: ItemId,
    pub list: Name,
    pub address: AddrMatch,
    pub timeout_secs: u64,
    /// When it was added (session clock); `None` until a clock is known —
    /// then the countdown starts at the first tick (wasm lab has no clock).
    pub added: Option<u64>,
    pub comment: String,
}

impl DynamicEntry {
    pub fn left(&self, now: Option<u64>) -> u64 {
        match (self.added, now) {
            (Some(at), Some(now)) => self.timeout_secs.saturating_sub(now.saturating_sub(at)),
            _ => self.timeout_secs,
        }
    }

    pub fn data_plane(&self, now: Option<u64>) -> DynamicAddress {
        DynamicAddress {
            list: self.list.clone(),
            address: self.address,
            timeout_secs: self.left(now).max(1),
            added_by_rule: false,
        }
    }
}

#[derive(Debug, Default)]
pub struct DynamicLists {
    entries: Vec<DynamicEntry>,
    next: u32,
}

impl DynamicLists {
    pub fn entries(&self) -> &[DynamicEntry] {
        &self.entries
    }

    pub fn find(&self, list: &Name, address: &AddrMatch) -> Option<&DynamicEntry> {
        self.entries
            .iter()
            .find(|e| e.list == *list && e.address == *address)
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next = self.next.wrapping_add(1) & 0x0FFF_FFFF;
        ItemId(ID_BASE | self.next)
    }

    pub fn push(&mut self, e: DynamicEntry) {
        self.entries.push(e);
    }

    pub fn remove(&mut self, id: ItemId) -> Option<DynamicEntry> {
        let pos = self.entries.iter().position(|e| e.id == id)?;
        Some(self.entries.remove(pos))
    }

    /// Drop the entries whose time ran out at `now`; start the countdown of
    /// those added before a clock was known.
    pub fn expire(&mut self, now: u64) -> Vec<DynamicEntry> {
        for e in &mut self.entries {
            e.added.get_or_insert(now);
        }
        let (gone, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.entries)
            .into_iter()
            .partition(|e| e.left(Some(now)) == 0);
        self.entries = keep;
        gone
    }
}

impl Session {
    /// Expire dynamic address-list entries (called on every clock tick).
    pub(crate) fn expire_dynamic_addresses(&mut self) {
        let Some(now) = self.now() else { return };
        for e in self.dynamic_addresses.expire(now) {
            // The kernel already dropped it; the lab backend needs telling.
            let d = e.data_plane(Some(now));
            if let Err(err) = self
                .hal_mut()
                .address_list_dynamic(DynamicChange::Remove(&d))
            {
                log::debug!("expired {} from {}: {err}", e.address, e.list);
            }
        }
    }
}
