//! Dynamic records of the zones (G4.1c-3), as the engine keeps them:
//! operational state outside the config (`dns-dynamic` in the storage),
//! changed at once and saved, never a revision.
//!
//! Two doors in:
//!
//! - [`Session::dns_dynamic_apply`]: an RFC 2136 UPDATE, already checked
//!   by the daemon (TSIG, ACL, prerequisites), applied all or nothing
//!   (§3.7) with the §3.4.2 rules: an equal record only gets the new TTL,
//!   a CNAME never joins other data nor other data a CNAME (ignored, as
//!   §3.4.2.2 says), the SOA and the apex NS are ours (ignored).
//! - [`Session::dns_dynamic_lease`] / [`Session::dns_dynamic_release`]:
//!   for the router's own DHCP server (G4.2): a lease's A/AAAA in its zone
//!   and the PTR in the reverse zone that covers the address, gone when the
//!   lease ends.
//!
//! The configured records are never changed by either: an UPDATE that
//! deletes a configured name only deletes its dynamic records. Every change
//! moves the zone's served serial (§3.6), past the config's.

use std::collections::HashMap;
use std::net::IpAddr;

use corerouter_model::dns_dynamic::{DynamicOp, DynamicRecord, DynamicState, MAX_DYNAMIC};
use corerouter_model::dns_zone::{
    RecordType, ZoneRecord, ZoneType, next_serial, serial_gt,
};
use corerouter_model::ItemId;

use crate::Session;

/// Name of the state in [`crate::ConfigStorage::save_state`].
pub const STATE: &str = "dns-dynamic";

#[derive(Default)]
struct DynamicRuntime {
    loaded: bool,
    state: DynamicState,
    /// Bumped on every change: the daemon copies the state when it moved.
    version: u64,
    /// Changes are kept in memory and saved by `dns_dynamic_flush` (a DHCP
    /// round names hundreds of leases: one save, not two per lease).
    deferred: bool,
    /// Zones changed while deferred (their serial moves at the flush).
    dirty: Vec<String>,
    /// While deferred: where each (zone, name) is in `state.records`. A DHCP
    /// round names hundreds of leases, and walking every record per update
    /// took ~1 s of session lock per round at the cap (G4.2h, **medido**).
    /// Built once a round; gone at the flush or when the state is replaced.
    index: Option<RecordIndex>,
}

type RecordIndex = HashMap<(String, String), Vec<usize>>;

fn index_of(state: &DynamicState) -> RecordIndex {
    let mut ix: RecordIndex = HashMap::with_capacity(state.records.len());
    for (i, d) in state.records.iter().enumerate() {
        ix.entry((d.record.zone.clone(), d.record.name.clone())).or_default().push(i);
    }
    ix
}

/// Where the records of `name` in `zone` are.
fn places(next: &DynamicState, index: Option<&RecordIndex>, zone: &str, name: &str) -> Vec<usize> {
    match index {
        Some(ix) => ix.get(&(zone.to_owned(), name.to_owned())).cloned().unwrap_or_default(),
        None => next
            .records
            .iter()
            .enumerate()
            .filter(|(_, d)| d.record.zone == zone && d.record.name == name)
            .map(|(i, _)| i)
            .collect(),
    }
}

/// Removes the records at `gone`. With an index, by swapping the last into
/// the hole (O(1); the order means nothing to DNS, RFC 2181 §5: an RRset has
/// no order); without one, keeping the order.
fn remove_at(next: &mut DynamicState, index: Option<&mut RecordIndex>, mut gone: Vec<usize>) -> usize {
    let n = gone.len();
    gone.sort_unstable();
    let Some(ix) = index else {
        let mut at = 0;
        next.records.retain(|_| {
            let keep = gone.binary_search(&at).is_err();
            at += 1;
            keep
        });
        return n;
    };
    // From the back: the swap only moves a record from behind the holes left.
    for &i in gone.iter().rev() {
        let last = next.records.len().saturating_sub(1);
        if i >= next.records.len() {
            continue;
        }
        let leaving = next.records.swap_remove(i);
        let key = (leaving.record.zone, leaving.record.name);
        if let Some(list) = ix.get_mut(&key) {
            list.retain(|p| *p != i);
            if list.is_empty() {
                ix.remove(&key);
            }
        }
        if let Some(moved) = next.records.get(i).filter(|_| i != last)
            && let Some(list) = ix.get_mut(&(moved.record.zone.clone(), moved.record.name.clone()))
            && let Some(p) = list.iter_mut().find(|p| **p == last)
        {
            *p = i;
        }
    }
    n
}

/// A lease for [`Session::dns_dynamic_lease`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseName {
    /// The forward zone (`lan.example`).
    pub zone: String,
    /// The host label (`laptop`): `laptop.lan.example`.
    pub host: String,
    pub address: IpAddr,
    pub ttl_secs: u32,
    /// The lease's end.
    pub expires_unix: Option<u64>,
    /// `dhcp <server>`.
    pub source: String,
}

impl Session {
    fn dyn_rt(&mut self) -> Option<&mut DynamicRuntime> {
        if self.ext::<DynamicRuntime>().is_none_or(|r| !r.loaded) {
            let state = self.dyn_read();
            let rt = self.ext_mut::<DynamicRuntime>()?;
            rt.loaded = true;
            rt.state = state;
            rt.version = rt.version.wrapping_add(1);
        }
        self.ext_mut::<DynamicRuntime>()
    }

    fn dyn_read(&mut self) -> DynamicState {
        let text = match self.storage_mut().load_state(STATE) {
            Ok(Some(t)) => t,
            Ok(None) => return DynamicState::default(),
            Err(e) => {
                log::error!("dynamic DNS records not read: {e}");
                return DynamicState::default();
            }
        };
        match serde_json::from_str::<DynamicState>(&text) {
            Ok(s) if s.problem().is_none() => s,
            Ok(s) => {
                log::error!("dynamic DNS records refused: {}", s.problem().unwrap_or_default());
                DynamicState::default()
            }
            Err(e) => {
                log::error!("dynamic DNS records unreadable: {e}");
                DynamicState::default()
            }
        }
    }

    /// The dynamic records and their version (a copy).
    pub fn dns_dynamic(&mut self) -> (u64, DynamicState) {
        self.dyn_rt()
            .map(|r| (r.version, r.state.clone()))
            .unwrap_or_default()
    }

    /// The version only (cheap: the daemon polls it).
    pub fn dns_dynamic_version(&mut self) -> u64 {
        self.dyn_rt().map_or(0, |r| r.version)
    }

    /// The serial a zone was last served with after a dynamic change.
    pub fn dns_dynamic_serial(&mut self, zone: &str) -> Option<u32> {
        self.dyn_rt()?.state.serials.get(zone).copied()
    }

    /// Replaces the state with `next` (when it differs), moving the serial
    /// of `zones`, and saves it.
    fn dyn_commit(&mut self, mut next: DynamicState, zones: &[String], now: u64) -> Result<(), String> {
        if self.ext::<DynamicRuntime>().is_some_and(|r| r.deferred) {
            let rt = self.dyn_rt().ok_or("no dynamic DNS state")?;
            rt.state = next;
            rt.index = None;
            rt.version = rt.version.wrapping_add(1);
            for z in zones {
                if !rt.dirty.contains(z) {
                    rt.dirty.push(z.clone());
                }
            }
            return Ok(());
        }
        self.dyn_bump_and_save(&mut next, zones, now)?;
        let rt = self.dyn_rt().ok_or("no dynamic DNS state")?;
        rt.state = next;
        rt.version = rt.version.wrapping_add(1);
        Ok(())
    }

    /// Changes from now on are saved by [`Session::dns_dynamic_flush`].
    pub(crate) fn dns_dynamic_defer(&mut self) {
        if let Some(rt) = self.ext_mut::<DynamicRuntime>() {
            rt.deferred = true;
        }
    }

    /// Save what changed since [`Session::dns_dynamic_defer`] (once), the
    /// serials of the changed zones moved.
    pub(crate) fn dns_dynamic_flush(&mut self, now: u64) {
        let Some(zones) = self.ext_mut::<DynamicRuntime>().map(|r| {
            r.deferred = false;
            r.index = None;
            std::mem::take(&mut r.dirty)
        }) else {
            return;
        };
        if zones.is_empty() {
            return;
        }
        let Some(mut next) = self.ext_mut::<DynamicRuntime>().map(|r| std::mem::take(&mut r.state)) else {
            return;
        };
        if let Err(e) = self.dyn_bump_and_save(&mut next, &zones, now) {
            log::error!("{e}");
        }
        if let Some(rt) = self.ext_mut::<DynamicRuntime>() {
            rt.state = next;
            rt.version = rt.version.wrapping_add(1);
        }
    }

    /// The serials of `zones` moved in `next` (§3.6), then saved.
    fn dyn_bump_and_save(&mut self, next: &mut DynamicState, zones: &[String], now: u64) -> Result<(), String> {
        for zone in zones {
            let Some(z) = self.store().running().ip.dns_zones.zone(zone).cloned() else {
                continue;
            };
            let last = next.serials.get(zone).copied();
            let base = match last {
                Some(l) if serial_gt(l, z.serial) => l,
                _ => z.serial,
            };
            next.serials.insert(zone.clone(), next_serial(z.serial_policy, base, now));
        }
        let text = serde_json::to_string(&*next).map_err(|e| e.to_string())?;
        self.storage_mut()
            .save_state(STATE, &text)
            .map_err(|e| format!("dynamic DNS records not saved: {e}"))
    }

    /// An RFC 2136 UPDATE of primary `zone` (already authorised and its
    /// prerequisites met), all or nothing. Returns how many records changed.
    pub fn dns_dynamic_apply(
        &mut self,
        zone: &str,
        ops: &[DynamicOp],
        source: &str,
        expires_unix: Option<u64>,
        now: u64,
    ) -> Result<usize, String> {
        let primary = self
            .store()
            .running()
            .ip
            .dns_zones
            .zone(zone)
            .is_some_and(|z| z.ztype == ZoneType::Primary && !z.disabled);
        if !primary {
            return Err(format!("{zone} is not a running primary zone"));
        }
        let config: Vec<ZoneRecord> = self
            .store()
            .running()
            .ip
            .dns_zones
            .records_of(zone)
            .filter(|r| !r.disabled)
            .cloned()
            .collect();
        // Deferred (a DHCP round naming hundreds of leases): ops that cannot
        // fail are applied in place, without copying the whole state per
        // update (that copy was most of a storm round, **medido**). Only an
        // invalid record or the cap can fail an update, both known before.
        let adds = ops.iter().filter(|o| matches!(o, DynamicOp::Add(_))).count();
        let valid = ops.iter().all(|o| match o {
            DynamicOp::Add(r) => {
                let mut r = r.clone();
                r.zone = zone.to_owned();
                r.problem().is_none()
            }
            _ => true,
        });
        let deferred = self.dyn_rt().is_some_and(|r| r.deferred);
        if valid && deferred {
            let Some(rt) = self.dyn_rt() else {
                return Err("no dynamic DNS state".into());
            };
            // At the cap an update that adds fails unless it also takes one
            // away (a lease's new name replacing the old): known from the
            // index, without copying the state to find out.
            let ix = rt.index.get_or_insert_with(|| index_of(&rt.state));
            let goes: usize = ops
                .iter()
                .map(|o| match o {
                    DynamicOp::Add(_) => 0,
                    DynamicOp::DeleteRrset { name, rtype } => places(&rt.state, Some(ix), zone, name)
                        .iter()
                        .filter(|i| rt.state.records.get(**i).is_some_and(|d| d.record.rtype == *rtype))
                        .count(),
                    DynamicOp::DeleteName { name } => places(&rt.state, Some(ix), zone, name).len(),
                    DynamicOp::DeleteRecord(r) => {
                        let mut r = r.clone();
                        r.zone = zone.to_owned();
                        places(&rt.state, Some(ix), zone, &r.name)
                            .iter()
                            .filter(|i| rt.state.records.get(**i).is_some_and(|d| d.record.same_data(&r)))
                            .count()
                    }
                })
                .sum();
            if rt.state.records.len() + adds > MAX_DYNAMIC + goes {
                return Err(format!("more than {MAX_DYNAMIC} dynamic records"));
            }
            let mut changed = 0usize;
            let mut index = rt.index.take();
            for op in ops {
                changed += apply(&mut rt.state, index.as_mut(), &config, zone, op, source, expires_unix, now)?;
            }
            rt.index = index;
            if changed > 0 {
                rt.version = rt.version.wrapping_add(1);
                if !rt.dirty.iter().any(|z| z == zone) {
                    rt.dirty.push(zone.to_owned());
                }
            }
            return Ok(changed);
        }
        let (_, mut next) = self.dns_dynamic();
        let mut changed = 0usize;
        for op in ops {
            changed += apply(&mut next, None, &config, zone, op, source, expires_unix, now)?;
        }
        if next.records.len() > MAX_DYNAMIC {
            return Err(format!("more than {MAX_DYNAMIC} dynamic records"));
        }
        if changed > 0 {
            self.dyn_commit(next, &[zone.to_owned()], now)?;
        }
        Ok(changed)
    }

    /// An RFC 2136 UPDATE whose prerequisites were checked against
    /// version `seen` of the dynamic records: applied only if they are
    /// still at that version (§3.7: prerequisites and update are atomic).
    /// `Ok(None)`: they moved in between (another UPDATE, a lease, an
    /// expiry); check the prerequisites again.
    pub fn dns_dynamic_update(
        &mut self,
        zone: &str,
        ops: &[DynamicOp],
        source: &str,
        seen: u64,
        now: u64,
    ) -> Result<Option<usize>, String> {
        if self.dns_dynamic_version() != seen {
            return Ok(None);
        }
        self.dns_dynamic_apply(zone, ops, source, None, now).map(Some)
    }

    /// A DHCP lease's names (G4.2 calls this): the A/AAAA `host.zone`
    /// (replacing what an earlier lease of that host put there) and, when
    /// one of our primary zones covers the address's reverse name, its PTR.
    /// A host that is a configured name is left alone (the operator's
    /// record wins, as Kea's conflict resolution keeps a name it does not
    /// own).
    pub fn dns_dynamic_lease(&mut self, lease: &LeaseName, now: u64) -> Result<(), String> {
        let host = lease.host.trim().trim_end_matches('.').to_ascii_lowercase();
        let rtype = match lease.address {
            IpAddr::V4(_) => RecordType::A,
            IpAddr::V6(_) => RecordType::Aaaa,
        };
        let mut a = ZoneRecord::new(ItemId(0), &lease.zone, &host);
        a.rtype = rtype;
        a.address = Some(lease.address);
        a.ttl_secs = Some(lease.ttl_secs);
        if let Some(p) = a.problem() {
            return Err(p);
        }
        let configured = self
            .store()
            .running()
            .ip
            .dns_zones
            .records_of(&lease.zone)
            .any(|r| r.name == host);
        if configured {
            return Err(format!("{host}.{} is a configured name: not replaced", lease.zone));
        }
        let fqdn = format!("{host}.{}", lease.zone);
        self.dns_dynamic_apply(
            &lease.zone,
            &[
                DynamicOp::DeleteRrset { name: host.clone(), rtype },
                DynamicOp::Add(a),
            ],
            &lease.source,
            lease.expires_unix,
            now,
        )?;
        if let Some((rev, name)) = self.reverse_zone(lease.address) {
            let mut ptr = ZoneRecord::new(ItemId(0), &rev, &name);
            ptr.rtype = RecordType::Ptr;
            ptr.target = fqdn;
            ptr.ttl_secs = Some(lease.ttl_secs);
            self.dns_dynamic_apply(
                &rev,
                &[
                    DynamicOp::DeleteRrset { name, rtype: RecordType::Ptr },
                    DynamicOp::Add(ptr),
                ],
                &lease.source,
                lease.expires_unix,
                now,
            )?;
        }
        Ok(())
    }

    /// The lease ended or was released: its A/AAAA and PTR go. Returns how
    /// many records went.
    pub fn dns_dynamic_release(&mut self, zone: &str, host: &str, address: IpAddr, now: u64) -> Result<usize, String> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let mut gone = 0;
        let mut a = ZoneRecord::new(ItemId(0), zone, &host);
        a.rtype = match address {
            IpAddr::V4(_) => RecordType::A,
            IpAddr::V6(_) => RecordType::Aaaa,
        };
        a.address = Some(address);
        gone += self.dns_dynamic_apply(zone, &[DynamicOp::DeleteRecord(a)], "release", None, now)?;
        if let Some((rev, name)) = self.reverse_zone(address) {
            let mut ptr = ZoneRecord::new(ItemId(0), &rev, &name);
            ptr.rtype = RecordType::Ptr;
            ptr.target = format!("{host}.{zone}");
            gone += self.dns_dynamic_apply(&rev, &[DynamicOp::DeleteRecord(ptr)], "release", None, now)?;
        }
        Ok(gone)
    }

    /// Removes dynamic records matching `keep == false`; returns how many.
    pub fn dns_dynamic_remove(&mut self, mut drop: impl FnMut(&DynamicRecord) -> bool, now: u64) -> Result<usize, String> {
        let (_, mut next) = self.dns_dynamic();
        let mut zones: Vec<String> = Vec::new();
        next.records.retain(|r| {
            let d = drop(r);
            if d && !zones.contains(&r.record.zone) {
                zones.push(r.record.zone.clone());
            }
            !d
        });
        if zones.is_empty() {
            return Ok(0);
        }
        let (_, before) = self.dns_dynamic();
        let n = before.records.len() - next.records.len();
        self.dyn_commit(next, &zones, now)?;
        Ok(n)
    }

    /// Expired records go (the daemon calls this every second).
    pub fn dns_dynamic_tick(&mut self, now: u64) -> Result<usize, String> {
        let expired = self
            .dyn_rt()
            .is_some_and(|r| r.state.records.iter().any(|d| d.expires_unix.is_some_and(|e| e <= now)));
        if !expired {
            return Ok(0);
        }
        self.dns_dynamic_remove(|d| d.expires_unix.is_some_and(|e| e <= now), now)
    }

    /// The primary zone holding the reverse name of `ip` (RFC 1035 §3.5,
    /// RFC 3596 §2.5), and the name relative to it.
    fn reverse_zone(&self, ip: IpAddr) -> Option<(String, String)> {
        let full = reverse_name(ip);
        self.store()
            .running()
            .ip
            .dns_zones
            .zones
            .iter()
            .filter(|z| z.ztype == ZoneType::Primary && !z.disabled)
            .filter_map(|z| {
                let rel = full.strip_suffix(&format!(".{}", z.name))?;
                Some((z.name.clone(), rel.to_owned()))
            })
            .max_by_key(|(z, _)| z.len())
    }
}

/// `in-addr.arpa` / `ip6.arpa` name of `ip`, without the final dot.
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::new();
            for b in v6.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0xf, b >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

/// One op on `next`; the configured records `config` are only read.
/// `index`: keep it with the records (and use it instead of walking them).
#[allow(clippy::too_many_arguments)]
fn apply(
    next: &mut DynamicState,
    mut index: Option<&mut RecordIndex>,
    config: &[ZoneRecord],
    zone: &str,
    op: &DynamicOp,
    source: &str,
    expires_unix: Option<u64>,
    now: u64,
) -> Result<usize, String> {
    match op {
        DynamicOp::Add(r) => {
            let mut r = r.clone();
            r.zone = zone.to_owned();
            if let Some(p) = r.problem() {
                return Err(format!("{} {}: {p}", r.name, r.rtype.as_str()));
            }
            // §3.4.2.3/§3.4.2.4: the SOA and the apex NS are ours.
            if r.name == "@" && r.rtype == RecordType::Ns {
                return Ok(0);
            }
            if config.iter().any(|c| c.same_data(&r)) {
                return Ok(0);
            }
            let here = places(next, index.as_deref(), zone, &r.name);
            // §3.4.2.2: a CNAME and other data never share a name.
            let others = config
                .iter()
                .filter(|c| c.name == r.name)
                .chain(here.iter().filter_map(|i| next.records.get(*i)).map(|d| &d.record))
                .any(|c| (c.rtype == RecordType::Cname) != (r.rtype == RecordType::Cname));
            if others {
                return Ok(0);
            }
            let same = here.iter().copied().find(|i| next.records.get(*i).is_some_and(|d| d.record.same_data(&r)));
            if let Some(d) = same.and_then(|i| next.records.get_mut(i)) {
                if d.record.ttl_secs == r.ttl_secs && d.expires_unix == expires_unix {
                    return Ok(0);
                }
                d.record.ttl_secs = r.ttl_secs;
                d.expires_unix = expires_unix;
                return Ok(1);
            }
            next.next_id = next.next_id.saturating_add(1);
            r.id = ItemId(next.next_id);
            if let Some(ix) = index.as_deref_mut() {
                ix.entry((r.zone.clone(), r.name.clone())).or_default().push(next.records.len());
            }
            next.records.push(DynamicRecord {
                record: r,
                expires_unix,
                source: source.chars().take(128).collect(),
                created_unix: now,
            });
            Ok(1)
        }
        DynamicOp::DeleteRrset { name, rtype } => {
            if name == "@" && *rtype == RecordType::Ns {
                return Ok(0);
            }
            let gone = places(next, index.as_deref(), zone, name)
                .into_iter()
                .filter(|i| next.records.get(*i).is_some_and(|d| d.record.rtype == *rtype))
                .collect();
            Ok(remove_at(next, index, gone))
        }
        DynamicOp::DeleteName { name } => {
            let gone = places(next, index.as_deref(), zone, name)
                .into_iter()
                .filter(|i| next.records.get(*i).is_some_and(|d| !(name == "@" && d.record.rtype == RecordType::Ns)))
                .collect();
            Ok(remove_at(next, index, gone))
        }
        DynamicOp::DeleteRecord(r) => {
            let mut r = r.clone();
            r.zone = zone.to_owned();
            let gone = places(next, index.as_deref(), zone, &r.name)
                .into_iter()
                .filter(|i| next.records.get(*i).is_some_and(|d| d.record.same_data(&r)))
                .collect();
            Ok(remove_at(next, index, gone))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn sorted(s: &DynamicState) -> Vec<(String, String, u8, String, Option<u32>)> {
        let mut v: Vec<_> = s
            .records
            .iter()
            .map(|d| {
                let r = &d.record;
                (r.zone.clone(), r.name.clone(), u8::from(r.rtype == RecordType::Ptr), r.data(), r.ttl_secs)
            })
            .collect();
        v.sort();
        v
    }

    fn op_of(kind: u8, name: u8, ip: u8) -> DynamicOp {
        let name = format!("h{name}");
        let mut r = ZoneRecord::new(ItemId(0), "z.example", &name);
        r.address = Some(IpAddr::from([10, 0, 0, ip]));
        r.ttl_secs = Some(300 + u32::from(ip % 3));
        match kind % 4 {
            0 | 1 => DynamicOp::Add(r),
            2 => DynamicOp::DeleteRrset { name, rtype: RecordType::A },
            _ => DynamicOp::DeleteRecord(r),
        }
    }

    proptest! {
        /// G4.2h: with the index or walking the records, the same updates
        /// give the same records, and the index stays true.
        #[test]
        fn the_index_changes_nothing_but_the_cost(
            ops in proptest::collection::vec((0u8..4, 0u8..6, 0u8..4), 0..200),
        ) {
            let (mut plain, mut fast) = (DynamicState::default(), DynamicState::default());
            let mut ix = index_of(&fast);
            for (k, n, ip) in ops {
                let op = op_of(k, n, ip);
                let a = apply(&mut plain, None, &[], "z.example", &op, "t", None, 0).unwrap();
                let b = apply(&mut fast, Some(&mut ix), &[], "z.example", &op, "t", None, 0).unwrap();
                prop_assert_eq!(a, b);
                prop_assert_eq!(sorted(&plain), sorted(&fast));
                let mut got: Vec<_> = ix.iter().map(|(k, v)| { let mut v = v.clone(); v.sort_unstable(); (k.clone(), v) }).collect();
                got.sort();
                let mut want: Vec<_> = index_of(&fast).into_iter().map(|(k, mut v)| { v.sort_unstable(); (k, v) }).collect();
                want.sort();
                prop_assert_eq!(got, want);
            }
        }
    }

    /// At the cap, deferred: a new name is refused without copying the state,
    /// and a name that replaces its old record still goes through.
    #[test]
    fn the_cap_holds_while_deferred() {
        let mut s = lab();
        s.dns_dynamic_defer();
        let z = "lan.example";
        for i in 0..MAX_DYNAMIC as u32 {
            let [_, _, b, c] = i.to_be_bytes();
            s.dns_dynamic_apply(z, &[DynamicOp::Add(a(&format!("h{i}"), &format!("10.0.{b}.{c}")))], "t", None, 0).unwrap();
        }
        let e = s.dns_dynamic_apply(z, &[DynamicOp::Add(a("new", "10.9.9.9"))], "t", None, 0).unwrap_err();
        assert!(e.contains("more than"), "{e}");
        let swap = [DynamicOp::DeleteRrset { name: "h7".into(), rtype: RecordType::A }, DynamicOp::Add(a("h7", "10.9.9.9"))];
        assert_eq!(s.dns_dynamic_apply(z, &swap, "t", None, 0).unwrap(), 2);
        s.dns_dynamic_flush(0);
        assert_eq!(s.dns_dynamic().1.records.len(), MAX_DYNAMIC);
    }

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        for z in ["lan.example", "88.168.192.in-addr.arpa"] {
            s.execute("ip.dns.zone.add", &json!({"name": z})).unwrap();
        }
        s.execute(
            "ip.dns.zone.record.add",
            &json!({"zone": "lan.example", "name": "nas", "address": "192.168.88.2"}),
        )
        .unwrap();
        s
    }

    fn a(name: &str, ip: &str) -> ZoneRecord {
        let mut r = ZoneRecord::new(ItemId(0), "lan.example", name);
        r.address = Some(ip.parse().unwrap());
        r.ttl_secs = Some(300);
        r
    }

    fn names(s: &mut Session) -> Vec<String> {
        s.dns_dynamic()
            .1
            .records
            .iter()
            .map(|d| format!("{} {} {}", d.record.zone, d.record.name, d.record.data()))
            .collect()
    }

    #[test]
    fn update_rules_of_rfc2136() {
        let mut s = lab();
        let z = "lan.example";
        let serial = s.store().running().ip.dns_zones.zones[0].serial;
        assert_eq!(s.dns_dynamic_apply(z, &[DynamicOp::Add(a("pc", "192.168.88.50"))], "test", None, 0).unwrap(), 1);
        let after = s.dns_dynamic_serial(z).unwrap();
        assert!(serial_gt(after, serial), "§3.6: the serial moved");
        // Equal record: only the TTL (§3.4.2.2).
        let mut again = a("pc", "192.168.88.50");
        again.ttl_secs = Some(600);
        assert_eq!(s.dns_dynamic_apply(z, &[DynamicOp::Add(again)], "test", None, 0).unwrap(), 1);
        assert_eq!(s.dns_dynamic().1.records.len(), 1);
        // A CNAME next to data is ignored; data next to a CNAME too.
        let mut c = ZoneRecord::new(ItemId(0), z, "pc");
        c.rtype = RecordType::Cname;
        c.target = "nas.lan.example".into();
        assert_eq!(s.dns_dynamic_apply(z, &[DynamicOp::Add(c)], "test", None, 0).unwrap(), 0);
        // A configured record is never touched.
        let n = s
            .dns_dynamic_apply(z, &[DynamicOp::DeleteName { name: "nas".into() }], "test", None, 0)
            .unwrap();
        assert_eq!(n, 0);
        assert_eq!(s.store().running().ip.dns_zones.records.len(), 1);
        // The apex NS is ours.
        let mut ns = ZoneRecord::new(ItemId(0), z, "@");
        ns.rtype = RecordType::Ns;
        ns.target = "evil.example".into();
        assert_eq!(s.dns_dynamic_apply(z, &[DynamicOp::Add(ns)], "test", None, 0).unwrap(), 0);
        // All or nothing (§3.7): a bad record fails the whole update.
        let mut bad = a("x", "192.168.88.9");
        bad.address = None;
        assert!(s
            .dns_dynamic_apply(z, &[DynamicOp::Add(a("y", "192.168.88.8")), DynamicOp::Add(bad)], "t", None, 0)
            .is_err());
        assert_eq!(names(&mut s), ["lan.example pc 192.168.88.50"]);
        // Deletes.
        assert_eq!(
            s.dns_dynamic_apply(z, &[DynamicOp::DeleteRrset { name: "pc".into(), rtype: RecordType::A }], "t", None, 0)
                .unwrap(),
            1
        );
        assert!(names(&mut s).is_empty());
        // Not ours, or a secondary: refused.
        assert!(s.dns_dynamic_apply("other.example", &[], "t", None, 0).is_err());
    }

    /// RFC 2136 §3.7: an UPDATE checked against an older version of the
    /// records is not applied (the caller checks again).
    #[test]
    fn an_update_checked_against_old_records_waits() {
        let mut s = lab();
        let z = "lan.example";
        let seen = s.dns_dynamic_version();
        let add = |n: &str| [DynamicOp::Add(a(n, "192.168.88.50"))];
        assert_eq!(s.dns_dynamic_update(z, &add("pc"), "t", seen, 0).unwrap(), Some(1));
        assert_eq!(s.dns_dynamic_update(z, &add("pc2"), "t", seen, 0).unwrap(), None);
        assert_eq!(names(&mut s), ["lan.example pc 192.168.88.50"]);
        let now = s.dns_dynamic_version();
        assert_eq!(s.dns_dynamic_update(z, &add("pc2"), "t", now, 0).unwrap(), Some(1));
    }

    #[test]
    fn leases_make_a_and_ptr_and_go_when_they_end() {
        let mut s = lab();
        let lease = LeaseName {
            zone: "lan.example".into(),
            host: "Laptop".into(),
            address: "192.168.88.77".parse().unwrap(),
            ttl_secs: 300,
            expires_unix: Some(1000),
            source: "dhcp lan".into(),
        };
        s.dns_dynamic_lease(&lease, 0).unwrap();
        assert_eq!(
            names(&mut s),
            [
                "lan.example laptop 192.168.88.77",
                "88.168.192.in-addr.arpa 77 laptop.lan.example."
            ]
        );
        // A new address for the same host replaces the A.
        let moved = LeaseName {
            address: "192.168.88.78".parse().unwrap(),
            ..lease.clone()
        };
        s.dns_dynamic_lease(&moved, 10).unwrap();
        assert!(names(&mut s).contains(&"lan.example laptop 192.168.88.78".to_owned()));
        assert!(!names(&mut s).contains(&"lan.example laptop 192.168.88.77".to_owned()));
        // A configured name is not taken over.
        let nas = LeaseName {
            host: "nas".into(),
            ..lease.clone()
        };
        assert!(s.dns_dynamic_lease(&nas, 10).is_err());
        // Expiry.
        assert_eq!(s.dns_dynamic_tick(999).unwrap(), 0);
        assert!(s.dns_dynamic_tick(1000).unwrap() >= 2);
        assert!(names(&mut s).iter().all(|n| !n.contains("laptop")));
        // Release.
        s.dns_dynamic_lease(&lease, 0).unwrap();
        assert_eq!(
            s.dns_dynamic_release("lan.example", "laptop", "192.168.88.77".parse().unwrap(), 5)
                .unwrap(),
            2
        );
        assert_eq!(reverse_name("2001:db8::1".parse().unwrap()).len(), 72);
    }

    #[test]
    fn dynamic_records_survive_a_restart() {
        let storage = crate::MemoryStorage::default();
        let mut s = Session::with_storage(
            Box::new(corerouter_hal::virt::VirtualHal::default()),
            Box::new(storage.clone()),
        );
        s.execute("ip.dns.zone.add", &json!({"name": "lan.example"})).unwrap();
        s.dns_dynamic_apply("lan.example", &[DynamicOp::Add(a("pc", "192.168.88.50"))], "t", None, 0)
            .unwrap();
        drop(s);
        let mut back = Session::with_storage(
            Box::new(corerouter_hal::virt::VirtualHal::default()),
            Box::new(storage),
        );
        assert_eq!(back.dns_dynamic().1.records.len(), 1);
    }
}
