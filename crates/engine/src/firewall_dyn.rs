//! Dynamic address-list entries (with a timeout): operational state, like
//! the neighbor table — never in the config, never saved, gone after a
//! restart (RouterOS' dynamic entries behave the same). The data plane gets
//! each one through `Hal::address_list_dynamic` and expires it by itself;
//! this table only mirrors it for `ip.firewall.address-list.list`.

use std::collections::BTreeMap;

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
    /// (list, address) → position in `entries`: the duplicate check of
    /// every add was a scan of up to [`MAX_DYNAMIC`] entries.
    index: BTreeMap<(Name, AddrMatch), usize>,
    next: u32,
}

impl DynamicLists {
    pub fn entries(&self) -> &[DynamicEntry] {
        &self.entries
    }

    pub fn find(&self, list: &Name, address: &AddrMatch) -> Option<&DynamicEntry> {
        let pos = self.index.get(&(list.clone(), *address))?;
        self.entries.get(*pos)
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next = self.next.wrapping_add(1) & 0x0FFF_FFFF;
        ItemId(ID_BASE | self.next)
    }

    pub fn push(&mut self, e: DynamicEntry) {
        self.index
            .insert((e.list.clone(), e.address), self.entries.len());
        self.entries.push(e);
    }

    pub fn remove(&mut self, id: ItemId) -> Option<DynamicEntry> {
        let pos = self.entries.iter().position(|e| e.id == id)?;
        let e = self.entries.remove(pos);
        self.reindex();
        Some(e)
    }

    /// Remove many at once: one reindex for all (a mass reconnect of the
    /// PPP service removes thousands; one by one was O(n²)).
    pub fn remove_many(&mut self, ids: &std::collections::HashSet<ItemId>) -> Vec<DynamicEntry> {
        if ids.is_empty() {
            return Vec::new();
        }
        let (gone, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.entries)
            .into_iter()
            .partition(|e| ids.contains(&e.id));
        self.entries = kept;
        self.reindex();
        gone
    }

    fn reindex(&mut self) {
        self.index = self
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| ((e.list.clone(), e.address), i))
            .collect();
    }

    /// Drop the entries whose time ran out at `now`; start the countdown of
    /// those added before a clock was known.
    pub fn expire(&mut self, now: u64) -> Vec<DynamicEntry> {
        for e in &mut self.entries {
            e.added.get_or_insert(now);
        }
        if !self.entries.iter().any(|e| e.left(Some(now)) == 0) {
            return Vec::new();
        }
        let (gone, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.entries)
            .into_iter()
            .partition(|e| e.left(Some(now)) == 0);
        self.entries = keep;
        self.reindex();
        gone
    }
}

impl Session {
    /// Expire dynamic address-list entries (called on every clock tick).
    pub(crate) fn expire_dynamic_addresses(&mut self) {
        let Some(now) = self.now() else { return };
        let gone: Vec<DynamicAddress> = self
            .dynamic_addresses
            .expire(now)
            .iter()
            .map(|e| e.data_plane(Some(now)))
            .collect();
        if gone.is_empty() {
            return;
        }
        // The kernel already dropped them (its set has the same timeout);
        // one call for all of them, so the lab backend forgets them and a
        // backend that must act does it in one go, not once per entry
        // under the session lock.
        if let Err(err) = self
            .hal_mut()
            .address_list_dynamic(DynamicChange::Expired(&gone))
        {
            log::debug!("expired {} dynamic address-list entries: {err}", gone.len());
        }
    }
}
