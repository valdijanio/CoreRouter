//! PPPoE subscriber data plane (G4.3c): the session maps of the XDP
//! program (`dataplane-ebpf-common::pppoe`). The daemon's BNG service
//! (G4.3d) calls [`XdpState::set_pppoe`] once and then
//! [`XdpState::pppoe_upsert`] / [`XdpState::pppoe_remove`] per session; the
//! session map lives here too, so a reload of the object (the fast path or
//! PPPoE switched, a crash of a link) writes every session back.
//!
//! Order of writes, so the data path never sees half a session: on insert
//! the session words and its policer first, then the keys that point at
//! it (upstream key, IPv4, IPv6 prefixes); on removal the keys first, then
//! the session is cleared (`F_ACTIVE` off: a stale index is refused).

use std::collections::BTreeMap;

use aya::Ebpf;
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, HashMap, PerCpuArray};
use corerouter_dataplane_ebpf_common::ipoe::{self, F_IPOE};
use corerouter_dataplane_ebpf_common::maps as m;
use corerouter_dataplane_ebpf_common::policer;
use corerouter_dataplane_ebpf_common::pppoe::{
    self, COUNTER_WORDS, Counters, F_ACTIVE, F_IPV4, F_IPV6, F_PD, KEY_LEN, SESSIONS_MAX, Session,
    SessionWords, Stat,
};
use corerouter_hal::HalError;

use super::{XdpState, monotonic_ns, rejected};

/// What the loader keeps of PPPoE between reloads.
#[derive(Debug, Default)]
pub(super) struct PppoeState {
    pub on: bool,
    sessions: BTreeMap<u32, Session>,
    /// IPoE access ports (G4.3f, `IPOE_PORTS`): IPoE is on when any.
    pub ipoe_ports: std::collections::BTreeSet<u32>,
}

impl PppoeState {
    /// The session maps are needed (sized for sessions).
    pub fn maps(&self) -> bool {
        self.on || !self.ipoe_ports.is_empty()
    }

    /// The `SETTINGS` word of the subscriber switches.
    pub fn word(&self) -> u64 {
        let ipoe = if self.ipoe_ports.is_empty() {
            0
        } else {
            ipoe::SETTINGS_BIT
        };
        u64::from(self.on) | ipoe
    }
}

/// A session's counters, summed (`pppoe::C_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PppoeCounters {
    pub up_packets: u64,
    pub up_bytes: u64,
    pub down_packets: u64,
    pub down_bytes: u64,
    pub up_policed: u64,
    pub down_policed: u64,
    pub spoofed: u64,
    pub to_kernel: u64,
}

impl PppoeCounters {
    fn of(c: Counters) -> Self {
        let [
            up_packets,
            up_bytes,
            down_packets,
            down_bytes,
            up_policed,
            down_policed,
            spoofed,
            to_kernel,
        ] = c;
        PppoeCounters {
            up_packets,
            up_bytes,
            down_packets,
            down_bytes,
            up_policed,
            down_policed,
            spoofed,
            to_kernel,
        }
    }
}

fn map_err(what: &'static str) -> impl Fn(aya::maps::MapError) -> HalError {
    move |e| rejected(what, &e)
}

fn the_map<'a>(ebpf: &'a mut Ebpf, name: &str) -> Result<&'a mut aya::maps::Map, HalError> {
    ebpf.map_mut(name)
        .ok_or_else(|| HalError::Rejected(format!("XDP: no {name} map")))
}

/// The /64 and delegated prefix of `s`, as LPM keys.
fn v6_keys(s: &Session) -> Vec<Key<[u8; 16]>> {
    let mut keys = Vec::new();
    let full = |p: [u8; 8]| {
        let mut a = [0u8; 16];
        for (d, b) in a.iter_mut().zip(p) {
            *d = b;
        }
        a
    };
    if s.flags & F_IPV6 != 0 {
        keys.push(Key::new(64, full(s.ipv6_prefix)));
    }
    if s.flags & F_PD != 0 && (1..=64).contains(&s.pd_len) {
        keys.push(Key::new(u32::from(s.pd_len), full(s.pd_prefix)));
    }
    keys
}

/// Why `s` cannot go in at `idx`, if it cannot.
fn invalid(idx: u32, s: &Session) -> Option<String> {
    if idx >= SESSIONS_MAX {
        return Some(format!("session index {idx} ≥ {SESSIONS_MAX}"));
    }
    if s.flags & F_ACTIVE == 0 {
        return Some("session without F_ACTIVE".into());
    }
    if s.ifindex == 0 {
        return Some("session without an access port".into());
    }
    if s.flags & F_PD != 0 && !(1..=64).contains(&s.pd_len) {
        return Some(format!(
            "delegated prefix length {} not in 1..=64",
            s.pd_len
        ));
    }
    if s.flags & F_IPOE != 0 && (s.sid != ipoe::SID || s.vlan != 0 || s.inner_vlan != 0) {
        return Some(
            "an IPoE session has SESSION_ID 0 and no VLAN tag (attach XDP to the VLAN interface)"
                .into(),
        );
    }
    if s.flags & F_IPOE == 0 && s.sid == ipoe::SID {
        return Some("a PPPoE session never has SESSION_ID 0 (RFC 2516 §5)".into());
    }
    if s.mtu != 0 && !(576..=9000).contains(&s.mtu) {
        return Some(format!("MTU {} not in 576..=9000", s.mtu));
    }
    for r in [s.up, s.down] {
        if r.rate > policer::MAX_RATE || r.depth > policer::MAX_DEPTH {
            return Some("rate or bucket depth too large".into());
        }
    }
    None
}

/// Remove the keys of `s` (upstream key, IPv4, IPv6 prefixes) that still
/// point at `idx`.
fn drop_keys(ebpf: &mut Ebpf, idx: u32, s: &Session) -> Result<(), HalError> {
    let mut keys = HashMap::<_, [u8; KEY_LEN], u32>::try_from(the_map(ebpf, m::PPPOE_KEYS)?)
        .map_err(map_err("PPPOE_KEYS map"))?;
    let k = s.key().to_bytes();
    if keys.get(&k, 0).ok() == Some(idx) {
        keys.remove(&k).map_err(map_err("PPPOE_KEYS remove"))?;
    }
    if s.flags & F_IPV4 != 0 {
        let mut v4 = HashMap::<_, [u8; 4], u32>::try_from(the_map(ebpf, m::PPPOE_V4)?)
            .map_err(map_err("PPPOE_V4 map"))?;
        if v4.get(&s.ipv4, 0).ok() == Some(idx) {
            v4.remove(&s.ipv4).map_err(map_err("PPPOE_V4 remove"))?;
        }
    }
    let mut v6 = LpmTrie::<_, [u8; 16], u32>::try_from(the_map(ebpf, m::PPPOE_V6)?)
        .map_err(map_err("PPPOE_V6 map"))?;
    for k in v6_keys(s) {
        if v6.get(&k, 0).ok() == Some(idx) {
            v6.remove(&k).map_err(map_err("PPPOE_V6 remove"))?;
        }
    }
    Ok(())
}

/// Write session `s` at `idx`: words, policers (full buckets), counters
/// (zeroed when `fresh`), then its keys.
fn put(ebpf: &mut Ebpf, idx: u32, s: &Session, fresh: bool) -> Result<(), HalError> {
    let mut sessions = Array::<_, SessionWords>::try_from(the_map(ebpf, m::PPPOE_SESSIONS)?)
        .map_err(map_err("PPPOE_SESSIONS map"))?;
    sessions
        .set(idx, s.to_words(), 0)
        .map_err(map_err("PPPOE_SESSIONS set"))?;
    let now = monotonic_ns();
    let mut pol = Array::<_, policer::State>::try_from(the_map(ebpf, m::PPPOE_POLICER)?)
        .map_err(map_err("PPPOE_POLICER map"))?;
    pol.set(idx * 2, policer::fresh(&s.up, now), 0)
        .map_err(map_err("PPPOE_POLICER set"))?;
    pol.set(idx * 2 + 1, policer::fresh(&s.down, now), 0)
        .map_err(map_err("PPPOE_POLICER set"))?;
    if fresh {
        let mut c = Array::<_, Counters>::try_from(the_map(ebpf, m::PPPOE_COUNTERS)?)
            .map_err(map_err("PPPOE_COUNTERS map"))?;
        c.set(idx, [0u64; COUNTER_WORDS], 0)
            .map_err(map_err("PPPOE_COUNTERS set"))?;
    }
    let mut keys = HashMap::<_, [u8; KEY_LEN], u32>::try_from(the_map(ebpf, m::PPPOE_KEYS)?)
        .map_err(map_err("PPPOE_KEYS map"))?;
    keys.insert(s.key().to_bytes(), idx, 0)
        .map_err(map_err("PPPOE_KEYS insert"))?;
    if s.flags & F_IPV4 != 0 {
        let mut v4 = HashMap::<_, [u8; 4], u32>::try_from(the_map(ebpf, m::PPPOE_V4)?)
            .map_err(map_err("PPPOE_V4 map"))?;
        v4.insert(s.ipv4, idx, 0)
            .map_err(map_err("PPPOE_V4 insert"))?;
    }
    let mut v6 = LpmTrie::<_, [u8; 16], u32>::try_from(the_map(ebpf, m::PPPOE_V6)?)
        .map_err(map_err("PPPOE_V6 map"))?;
    for k in v6_keys(s) {
        v6.insert(&k, idx, 0).map_err(map_err("PPPOE_V6 insert"))?;
    }
    Ok(())
}

/// Clear session `idx` (keys of `old` first).
fn clear(ebpf: &mut Ebpf, idx: u32, old: &Session) -> Result<(), HalError> {
    drop_keys(ebpf, idx, old)?;
    let mut sessions = Array::<_, SessionWords>::try_from(the_map(ebpf, m::PPPOE_SESSIONS)?)
        .map_err(map_err("PPPOE_SESSIONS map"))?;
    sessions
        .set(idx, [0u64; pppoe::SESSION_WORDS], 0)
        .map_err(map_err("PPPOE_SESSIONS clear"))
}

/// After a load: every known session back into the fresh maps.
pub(super) fn refill(ebpf: &mut Ebpf, st: &PppoeState) -> Result<(), HalError> {
    if !st.maps() {
        return Ok(());
    }
    for (idx, s) in &st.sessions {
        put(ebpf, *idx, s, true)?;
    }
    Ok(())
}

/// `IPOE_PORTS` as `st` says (≤ `ipoe::PORTS_MAX` entries).
pub(super) fn sync_ports(ebpf: &mut Ebpf, st: &PppoeState) -> Result<(), HalError> {
    let mut ports = HashMap::<_, u32, u32>::try_from(the_map(ebpf, m::IPOE_PORTS)?)
        .map_err(map_err("IPOE_PORTS map"))?;
    let old: Vec<u32> = ports.keys().filter_map(Result::ok).collect();
    for k in old.iter().filter(|k| !st.ipoe_ports.contains(k)) {
        ports.remove(k).map_err(map_err("IPOE_PORTS remove"))?;
    }
    for k in st.ipoe_ports.iter().filter(|k| !old.contains(k)) {
        ports
            .insert(*k, 0, 0)
            .map_err(map_err("IPOE_PORTS insert"))?;
    }
    Ok(())
}

impl XdpState {
    /// Switch the PPPoE data plane on or off. The session maps are
    /// preallocated (~64 MiB, **estimated**), so a change reloads the
    /// object (links come back in the same call); sessions stay known and
    /// go back in.
    pub fn set_pppoe(&mut self, on: bool) -> Result<(), HalError> {
        if self.pppoe.on == on {
            return Ok(());
        }
        self.pppoe.on = on;
        let Some(cfg) = self.cfg.clone() else {
            return Ok(());
        };
        let plan = corerouter_hal::xdp::XdpPlan::of(&cfg, &self.dynamic);
        // Force `reach` past its "nothing changed" shortcut.
        self.applied = corerouter_hal::xdp::XdpPlan::default();
        self.reach(plan)
    }

    pub fn pppoe_on(&self) -> bool {
        self.pppoe.on
    }

    /// The IPoE access ports (by ifindex, G4.3f); empty switches IPoE off.
    /// The session maps are shared with PPPoE: sizing them reloads the
    /// object, as [`XdpState::set_pppoe`].
    pub fn set_ipoe(&mut self, ports: std::collections::BTreeSet<u32>) -> Result<(), HalError> {
        if ports.len() > ipoe::PORTS_MAX as usize {
            return Err(HalError::Rejected(format!(
                "IPoE: at most {} access ports",
                ipoe::PORTS_MAX
            )));
        }
        if self.pppoe.ipoe_ports == ports {
            return Ok(());
        }
        self.pppoe.ipoe_ports = ports;
        let Some(cfg) = self.cfg.clone() else {
            return Ok(());
        };
        let plan = corerouter_hal::xdp::XdpPlan::of(&cfg, &self.dynamic);
        self.applied = corerouter_hal::xdp::XdpPlan::default();
        self.reach(plan)
    }

    pub fn ipoe_ports(&self) -> &std::collections::BTreeSet<u32> {
        &self.pppoe.ipoe_ports
    }

    /// Sessions known (in the maps when loaded).
    pub fn pppoe_sessions(&self) -> usize {
        self.pppoe.sessions.len()
    }

    /// Put session `s` at index `idx` (the daemon allocates indexes below
    /// [`SESSIONS_MAX`]). Replacing the same subscriber (same key: a rate
    /// change, an address learned) keeps its counters; another
    /// subscriber at that index starts from zero.
    pub fn pppoe_upsert(&mut self, idx: u32, s: &Session) -> Result<(), HalError> {
        if let Some(why) = invalid(idx, s) {
            return Err(HalError::Rejected(format!("PPPoE: {why}")));
        }
        let old = self.pppoe.sessions.get(&idx).copied();
        let fresh = old.is_none_or(|o| o.key() != s.key());
        if let Some(l) = self.loaded.as_mut().filter(|_| self.pppoe.maps()) {
            if let Some(o) = &old {
                drop_keys(&mut l.ebpf, idx, o)?;
            }
            put(&mut l.ebpf, idx, s, fresh)?;
        }
        self.pppoe.sessions.insert(idx, *s);
        Ok(())
    }

    /// Remove session `idx` (nothing if unknown).
    pub fn pppoe_remove(&mut self, idx: u32) -> Result<(), HalError> {
        let Some(old) = self.pppoe.sessions.remove(&idx) else {
            return Ok(());
        };
        if let Some(l) = self.loaded.as_mut().filter(|_| self.pppoe.maps()) {
            clear(&mut l.ebpf, idx, &old)?;
        }
        Ok(())
    }

    /// Counters of session `idx` (accounting interims, graphs).
    pub fn pppoe_counters(&mut self, idx: u32) -> Option<PppoeCounters> {
        let l = self.loaded.as_mut()?;
        let map = l.ebpf.map_mut(m::PPPOE_COUNTERS)?;
        let arr = Array::<_, Counters>::try_from(map).ok()?;
        arr.get(&idx, 0).ok().map(PppoeCounters::of)
    }

    /// The global PPPoE statistics (`pppoe::Stat`), summed over CPUs; only
    /// non-zero ones.
    pub fn pppoe_stats(&mut self) -> Vec<(&'static str, u64)> {
        let Some(map) = self
            .loaded
            .as_mut()
            .and_then(|l| l.ebpf.map_mut(m::PPPOE_STATS))
        else {
            return Vec::new();
        };
        let Ok(arr) = PerCpuArray::<_, u64>::try_from(map) else {
            return Vec::new();
        };
        Stat::ALL
            .iter()
            .filter_map(|s| {
                let total: u64 = arr.get(&(*s as u32), 0).ok()?.iter().sum();
                (total > 0).then_some((s.name(), total))
            })
            .collect()
    }
}

/// The map entry of a session the BNG service describes (`hal::pppoe`).
pub fn session_of(p: &corerouter_hal::pppoe::PppoeSession) -> Session {
    let rate = |r: &corerouter_hal::pppoe::Rate| {
        policer::Rate::mikrotik(
            r.rate_bps,
            r.burst_bps,
            r.threshold_bps,
            u64::from(r.burst_secs) * 1_000_000_000,
        )
    };
    let mut flags = F_ACTIVE;
    if p.ipv4.is_some() {
        flags |= F_IPV4;
    }
    if p.fast_up {
        flags |= pppoe::F_FAST_UP;
    }
    if p.fast_down {
        flags |= pppoe::F_FAST_DOWN;
    }
    if p.ipoe {
        flags |= F_IPOE;
    }
    if p.ipv6_prefix.is_some() {
        flags |= F_IPV6;
    }
    if p.delegated.is_some() {
        flags |= F_PD;
    }
    let (pd_prefix, pd_len) = p.delegated.unwrap_or(([0; 8], 0));
    Session {
        flags,
        ifindex: p.ifindex,
        sid: p.sid,
        vlan: p.vlan,
        inner_vlan: p.inner_vlan,
        outer_tpid: p.outer_tpid,
        mtu: p.mtu,
        client_mac: p.client_mac,
        server_mac: p.server_mac,
        ipv4: p.ipv4.map_or([0; 4], |ip| ip.octets()),
        ipv6_prefix: p.ipv6_prefix.unwrap_or([0; 8]),
        pd_prefix,
        pd_len,
        up: rate(&p.up),
        down: rate(&p.down),
    }
}

impl XdpState {
    /// The XDP program is attached to every one of `ports` (PPPoE needs it
    /// on the access side).
    pub fn pppoe_ready(&self, ports: &[corerouter_model::IfName]) -> Result<(), HalError> {
        let Some(l) = self.loaded.as_ref() else {
            return Err(HalError::Unsupported(
                "the XDP program is not loaded (ip.firewall.xdp: add the access and uplink interfaces)".into(),
            ));
        };
        match ports.iter().find(|p| !l.links.contains_key(*p)) {
            Some(p) => Err(HalError::Unsupported(format!(
                "XDP is not attached to {p} (ip.firewall.xdp)"
            ))),
            None => Ok(()),
        }
    }

    /// The BNG service's changes, in order.
    pub fn pppoe_apply(&mut self, ops: &[corerouter_hal::pppoe::PppoeOp]) -> Result<(), HalError> {
        for op in ops {
            match op {
                corerouter_hal::pppoe::PppoeOp::Upsert(idx, s) => {
                    self.pppoe_upsert(*idx, &session_of(s))?
                }
                corerouter_hal::pppoe::PppoeOp::Remove(idx) => self.pppoe_remove(*idx)?,
            }
        }
        Ok(())
    }

    /// Counters of `slots`, in the HAL's terms.
    pub fn pppoe_counters_of(
        &mut self,
        slots: &[u32],
    ) -> Vec<(u32, corerouter_hal::pppoe::PppoeCounters)> {
        slots
            .iter()
            .filter_map(|i| {
                let c = self.pppoe_counters(*i)?;
                Some((
                    *i,
                    corerouter_hal::pppoe::PppoeCounters {
                        up_packets: c.up_packets,
                        up_bytes: c.up_bytes,
                        down_packets: c.down_packets,
                        down_bytes: c.down_bytes,
                        up_policed: c.up_policed,
                        down_policed: c.down_policed,
                        spoofed: c.spoofed,
                        to_kernel: c.to_kernel,
                    },
                ))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_dataplane_ebpf_common::policer::Rate;

    fn sess() -> Session {
        Session {
            flags: F_ACTIVE | F_IPV4 | F_IPV6 | F_PD,
            ifindex: 3,
            sid: 1,
            ipv4: [100, 64, 0, 1],
            ipv6_prefix: [0x20, 1, 0xd, 0xb8, 0, 0, 0, 1],
            pd_prefix: [0x20, 1, 0xd, 0xb8, 0x10, 0, 0, 0],
            pd_len: 56,
            up: Rate::mikrotik(10_000_000, 0, 0, 0),
            ..Session::default()
        }
    }

    #[test]
    fn validation_and_offline_bookkeeping() {
        let mut x = XdpState::default();
        // Not loaded: kept for when it is.
        x.pppoe_upsert(5, &sess()).unwrap();
        assert_eq!(x.pppoe_sessions(), 1);
        assert!(x.pppoe_counters(5).is_none());
        for bad in [
            Session { flags: 0, ..sess() },
            Session {
                ifindex: 0,
                ..sess()
            },
            Session {
                pd_len: 65,
                ..sess()
            },
            Session { mtu: 100, ..sess() },
        ] {
            assert!(x.pppoe_upsert(6, &bad).is_err(), "{bad:?}");
        }
        assert!(x.pppoe_upsert(SESSIONS_MAX, &sess()).is_err());
        x.pppoe_remove(5).unwrap();
        x.pppoe_remove(5).unwrap();
        assert_eq!(x.pppoe_sessions(), 0);
        let keys = v6_keys(&sess());
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[1].prefix_len(), 56);
    }

    /// G4.3e: the HAL's /64 and delegated prefix become the flags and the
    /// LPM keys of the session.
    #[test]
    fn hal_ipv6_prefixes_reach_the_session_words() {
        let h = corerouter_hal::pppoe::PppoeSession {
            ifindex: 3,
            sid: 9,
            ipv6_prefix: Some([0x20, 1, 0xd, 0xb8, 0, 0, 0, 9]),
            delegated: Some(([0x20, 1, 0xd, 0xb8, 0x80, 0, 9, 0], 56)),
            ..corerouter_hal::pppoe::PppoeSession::default()
        };
        let s = session_of(&h);
        assert_eq!(s.flags & (F_IPV4 | F_IPV6 | F_PD), F_IPV6 | F_PD);
        assert_eq!(s.pd_len, 56);
        let keys = v6_keys(&s);
        assert_eq!(
            keys.iter().map(|k| k.prefix_len()).collect::<Vec<_>>(),
            vec![64, 56]
        );
        let none = session_of(&corerouter_hal::pppoe::PppoeSession {
            ifindex: 3,
            ..Default::default()
        });
        assert_eq!(none.flags & (F_IPV6 | F_PD), 0);
        assert!(v6_keys(&none).is_empty());
    }

    /// The object has the PPPoE maps the loader drives.
    #[test]
    fn the_object_has_the_pppoe_maps() {
        let obj = aya_obj::Object::parse(super::super::OBJECT).unwrap();
        for name in [
            m::PPPOE_KEYS,
            m::PPPOE_SESSIONS,
            m::PPPOE_V4,
            m::PPPOE_V6,
            m::PPPOE_POLICER,
            m::PPPOE_COUNTERS,
            m::PPPOE_STATS,
            m::IPOE_PORTS,
        ] {
            assert!(obj.maps.contains_key(name), "map {name}");
        }
    }
}
