//! DNSSEC keys of the authoritative zones (G4.1c-2), as the engine keeps
//! them: operational state outside the config and its revisions
//! (`dnssec-keys` in the storage, a 0600 file next to the config), so a
//! rollback never takes away a key whose DS is at the parent, and the
//! private keys never show in `config.diff` or an export.
//!
//! The engine has no cryptography (it compiles for wasm32): the daemon
//! calls [`Session::dnssec_tick`] every second with a key generator, and
//! the key life cycle (RFC 6781 §4.1, timings of RFC 7583) is decided here,
//! testable with a fake clock and fake keys:
//!
//! - a signed zone without keys gets a KSK and a ZSK, both active;
//! - ZSK rollover (pre-publication, RFC 6781 §4.1.1.1): the new ZSK is
//!   published; after Ipub = TTL(DNSKEY) + propagation it signs and the old
//!   one retires; after Iret = max TTL + propagation the old one goes;
//! - KSK rollover (double signature, §4.1.2): the new KSK signs the DNSKEY
//!   set at once next to the old one; once the operator put its DS at the
//!   parent (`ds-published`), the old one retires, and goes after the
//!   parent's DS TTL (one day, BIND `parent-ds-ttl`) + propagation.

use corerouter_model::dns_zone::ZoneType;
use corerouter_model::dnssec::{DnssecAlgorithm, DnssecKey, DnssecState, KeyRole, KeyState};

use crate::Session;

/// Name of the state in [`crate::ConfigStorage::save_state`].
pub const STATE: &str = "dnssec-keys";
/// RFC 7583 Dprp: how long a change takes to reach every secondary and
/// cache (BIND `zone-propagation-delay` + safety; Knot `propagation-delay`).
pub const PROPAGATION_SECS: u64 = 3600;
/// The parent's DS TTL, unknown to us (BIND `parent-ds-ttl` 1 day).
pub const PARENT_DS_TTL_SECS: u64 = 86_400;

/// A key the daemon just made (the engine never sees the generator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewKey {
    pub private_key: String,
    pub dnskey: String,
    pub ds: String,
    pub key_tag: u16,
}

/// What the daemon brings to [`Session::dnssec_tick`].
pub type Generate<'a> = dyn FnMut(&str, DnssecAlgorithm, KeyRole) -> Result<NewKey, String> + 'a;

#[derive(Default)]
struct DnssecRuntime {
    loaded: bool,
    state: DnssecState,
}

impl Session {
    fn dnssec_rt(&mut self) -> Option<&mut DnssecRuntime> {
        let first = self.ext::<DnssecRuntime>().is_none_or(|r| !r.loaded);
        if first {
            let state = self.dnssec_read();
            let rt = self.ext_mut::<DnssecRuntime>()?;
            rt.loaded = true;
            rt.state = state;
        }
        self.ext_mut::<DnssecRuntime>()
    }

    fn dnssec_read(&mut self) -> DnssecState {
        let text = match self.storage_mut().load_state(STATE) {
            Ok(Some(t)) => t,
            Ok(None) => return DnssecState::default(),
            Err(e) => {
                log::error!("DNSSEC keys not read: {e}");
                return DnssecState::default();
            }
        };
        match serde_json::from_str::<DnssecState>(&text) {
            Ok(s) if s.problem().is_none() => s,
            Ok(s) => {
                log::error!("DNSSEC keys refused: {}", s.problem().unwrap_or_default());
                DnssecState::default()
            }
            Err(e) => {
                log::error!("DNSSEC keys unreadable: {e}");
                DnssecState::default()
            }
        }
    }

    fn dnssec_save(&mut self) -> Result<(), String> {
        let state = self.dnssec_state();
        let text = serde_json::to_string(&state).map_err(|e| e.to_string())?;
        self.storage_mut()
            .save_state(STATE, &text)
            .map_err(|e| format!("DNSSEC keys not saved: {e}"))
    }

    /// The keys and signing state (a copy).
    pub fn dnssec_state(&mut self) -> DnssecState {
        self.dnssec_rt().map(|r| r.state.clone()).unwrap_or_default()
    }

    /// Changes the state and saves it at once (it is not config: no
    /// commit, no revision).
    pub(crate) fn dnssec_update<T>(&mut self, f: impl FnOnce(&mut DnssecState) -> T) -> Result<T, String> {
        let rt = self.dnssec_rt().ok_or("no DNSSEC state")?;
        let out = f(&mut rt.state);
        self.dnssec_save()?;
        Ok(out)
    }

    /// The daemon signed `zone` at `serial`: kept so the next signed
    /// serial is larger, even after a restart.
    pub fn dnssec_signed(&mut self, zone: &str, serial: u32) -> Result<(), String> {
        if self
            .dnssec_rt()
            .is_some_and(|r| r.state.signed_serial.get(zone) == Some(&serial))
        {
            return Ok(());
        }
        self.dnssec_update(|s| {
            s.signed_serial.insert(zone.to_owned(), serial);
        })
    }

    /// One step of the key life cycle at `now` (see the module doc).
    /// Returns whether anything changed (and was saved).
    pub fn dnssec_tick(&mut self, now: u64, generate: &mut Generate<'_>) -> Result<bool, String> {
        let zones: Vec<(String, DnssecAlgorithm, u64, u64)> = {
            let dz = &self.store().running().ip.dns_zones;
            dz.zones
                .iter()
                .filter(|z| z.dnssec && !z.disabled && z.ztype == ZoneType::Primary)
                .map(|z| {
                    let max_ttl = dz
                        .records_of(&z.name)
                        .filter_map(|r| r.ttl_secs)
                        .chain([z.ttl_secs, z.minimum_secs])
                        .max()
                        .unwrap_or(z.ttl_secs);
                    (
                        z.name.clone(),
                        z.dnssec_algorithm,
                        u64::from(z.ttl_secs),
                        u64::from(max_ttl),
                    )
                })
                .collect()
        };
        let mut state = self.dnssec_state();
        let before = state.clone();
        for (zone, alg, dnskey_ttl, max_ttl) in zones {
            step(&mut state, &zone, alg, dnskey_ttl, max_ttl, now, generate)?;
        }
        if state == before {
            return Ok(false);
        }
        self.dnssec_update(|s| *s = state)?;
        Ok(true)
    }
}

fn new_key(
    state: &mut DnssecState,
    zone: &str,
    alg: DnssecAlgorithm,
    role: KeyRole,
    key_state: KeyState,
    now: u64,
    generate: &mut Generate<'_>,
) -> Result<(), String> {
    let k = generate(zone, alg, role)?;
    let id = state.next_id();
    log::info!(
        "DNSSEC: zone {zone}: new {} {} (tag {}), {}",
        alg.as_str(),
        role.as_str(),
        k.key_tag,
        key_state.as_str()
    );
    state.keys.push(DnssecKey {
        id,
        zone: zone.to_owned(),
        role,
        algorithm: alg,
        key_tag: k.key_tag,
        state: key_state,
        private_key: k.private_key,
        dnskey: k.dnskey,
        ds: k.ds,
        created_unix: now,
        changed_unix: now,
    });
    Ok(())
}

fn count(state: &DnssecState, zone: &str, role: KeyRole, st: KeyState) -> usize {
    state
        .keys_of(zone)
        .filter(|k| k.role == role && k.state == st)
        .count()
}

/// The key life cycle of one zone.
fn step(
    state: &mut DnssecState,
    zone: &str,
    alg: DnssecAlgorithm,
    dnskey_ttl: u64,
    max_ttl: u64,
    now: u64,
    generate: &mut Generate<'_>,
) -> Result<(), String> {
    for role in [KeyRole::Ksk, KeyRole::Zsk] {
        if count(state, zone, role, KeyState::Active) == 0
            && count(state, zone, role, KeyState::Published) == 0
        {
            new_key(state, zone, alg, role, KeyState::Active, now, generate)?;
        }
    }
    // Rollovers asked for.
    let asked: Vec<KeyRole> = state
        .rollovers
        .iter()
        .filter(|r| r.zone == zone)
        .map(|r| r.role)
        .collect();
    state.rollovers.retain(|r| r.zone != zone);
    for role in asked {
        match role {
            KeyRole::Zsk if count(state, zone, KeyRole::Zsk, KeyState::Published) == 0 => {
                new_key(state, zone, alg, KeyRole::Zsk, KeyState::Published, now, generate)?;
            }
            KeyRole::Ksk if count(state, zone, KeyRole::Ksk, KeyState::Active) < 2 => {
                new_key(state, zone, alg, KeyRole::Ksk, KeyState::Active, now, generate)?;
            }
            _ => {}
        }
    }
    // ZSK pre-publication (RFC 7583 §3.2.1): Ipub = Dprp + TTL(DNSKEY).
    let ipub = dnskey_ttl + PROPAGATION_SECS;
    let ready = state.keys.iter().any(|k| {
        k.zone == zone
            && k.role == KeyRole::Zsk
            && k.state == KeyState::Published
            && now.saturating_sub(k.changed_unix) >= ipub
    });
    if ready {
        for k in state.keys.iter_mut().filter(|k| k.zone == zone && k.role == KeyRole::Zsk) {
            match k.state {
                KeyState::Active => {
                    k.state = KeyState::Retired;
                    k.changed_unix = now;
                }
                KeyState::Published => {
                    k.state = KeyState::Active;
                    k.changed_unix = now;
                }
                KeyState::Retired => {}
            }
        }
    }
    // KSK double signature: the DS of the newest one is at the parent.
    if state.ds_published.iter().any(|z| z == zone) {
        state.ds_published.retain(|z| z != zone);
        let newest = state
            .keys_of(zone)
            .filter(|k| k.role == KeyRole::Ksk && k.state == KeyState::Active)
            .map(|k| k.id)
            .max();
        for k in state
            .keys
            .iter_mut()
            .filter(|k| k.zone == zone && k.role == KeyRole::Ksk && k.state == KeyState::Active)
        {
            if Some(k.id) != newest {
                k.state = KeyState::Retired;
                k.changed_unix = now;
            }
        }
    }
    // Retired keys leave once what they signed, or their DS, is out of the
    // caches (RFC 7583 Iret).
    let zsk_iret = max_ttl + PROPAGATION_SECS;
    let ksk_iret = PARENT_DS_TTL_SECS + PROPAGATION_SECS;
    state.keys.retain(|k| {
        let iret = if k.role == KeyRole::Zsk { zsk_iret } else { ksk_iret };
        let gone = k.zone == zone && k.state == KeyState::Retired && now.saturating_sub(k.changed_unix) >= iret;
        if gone {
            log::info!("DNSSEC: zone {zone}: {} tag {} removed", k.role.as_str(), k.key_tag);
        }
        !gone
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fake() -> impl FnMut(&str, DnssecAlgorithm, KeyRole) -> Result<NewKey, String> {
        let mut n = 0u16;
        move |_, _, role| {
            n += 1;
            Ok(NewKey {
                private_key: format!("key{n}"),
                dnskey: format!("{} 3 13 AAAA{n}", if role == KeyRole::Ksk { 257 } else { 256 }),
                ds: if role == KeyRole::Ksk { format!("{n} 13 2 ABCD") } else { String::new() },
                key_tag: n,
            })
        }
    }

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.execute("ip.dns.zone.add", &json!({"name": "example.com", "dnssec": true}))
            .unwrap();
        s
    }

    fn states(s: &mut Session) -> Vec<(KeyRole, KeyState, u16)> {
        s.dnssec_state()
            .keys
            .iter()
            .map(|k| (k.role, k.state, k.key_tag))
            .collect()
    }

    #[test]
    fn a_signed_zone_gets_its_keys_once() {
        let mut s = lab();
        let mut g = fake();
        assert!(s.dnssec_tick(1000, &mut g).unwrap());
        assert_eq!(
            states(&mut s),
            [(KeyRole::Ksk, KeyState::Active, 1), (KeyRole::Zsk, KeyState::Active, 2)]
        );
        assert!(!s.dnssec_tick(1001, &mut g).unwrap(), "nothing more");
        // Saved outside the config: a rollback keeps them.
        assert!(s.store().running().ip.dns_zones.zones[0].dnssec);
        assert_eq!(s.dnssec_state().keys.len(), 2);
    }

    #[test]
    fn zsk_rollover_by_pre_publication() {
        let mut s = lab();
        let mut g = fake();
        s.dnssec_tick(0, &mut g).unwrap();
        s.execute("ip.dns.zone.dnssec.rollover", &json!({"zone": "example.com", "key": "zsk"}))
            .unwrap();
        s.dnssec_tick(10, &mut g).unwrap();
        assert!(states(&mut s).contains(&(KeyRole::Zsk, KeyState::Published, 3)));
        // Ipub = TTL(DNSKEY) 3600 + 3600.
        s.dnssec_tick(10 + 7199, &mut g).unwrap();
        assert!(states(&mut s).contains(&(KeyRole::Zsk, KeyState::Published, 3)));
        s.dnssec_tick(10 + 7200, &mut g).unwrap();
        let st = states(&mut s);
        assert!(st.contains(&(KeyRole::Zsk, KeyState::Active, 3)), "{st:?}");
        assert!(st.contains(&(KeyRole::Zsk, KeyState::Retired, 2)), "{st:?}");
        // Iret = max TTL 3600 + 3600 later, the old one goes.
        s.dnssec_tick(10 + 7200 + 7200, &mut g).unwrap();
        assert!(!states(&mut s).iter().any(|k| k.2 == 2));
    }

    #[test]
    fn ksk_rollover_waits_for_the_ds() {
        let mut s = lab();
        let mut g = fake();
        s.dnssec_tick(0, &mut g).unwrap();
        assert!(
            s.execute("ip.dns.zone.dnssec.ds-published", &json!({"zone": "example.com"}))
                .is_err(),
            "no rollover going on"
        );
        s.execute("ip.dns.zone.dnssec.rollover", &json!({"zone": "example.com", "key": "ksk"}))
            .unwrap();
        s.dnssec_tick(10, &mut g).unwrap();
        let rows = s.execute("ip.dns.zone.dnssec.print", &json!({})).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 3);
        assert!(rows.to_string().contains("3 13 2 ABCD"), "the new DS is shown");
        assert!(!rows.to_string().contains("key3"), "never the private key");
        // Days later, still both: the operator has not said the DS is in.
        s.dnssec_tick(10 + 30 * 86_400, &mut g).unwrap();
        assert_eq!(count(&s.dnssec_state(), "example.com", KeyRole::Ksk, KeyState::Active), 2);
        s.execute("ip.dns.zone.dnssec.ds-published", &json!({"zone": "example.com"}))
            .unwrap();
        s.dnssec_tick(100_000_000, &mut g).unwrap();
        let st = states(&mut s);
        assert!(st.contains(&(KeyRole::Ksk, KeyState::Retired, 1)), "{st:?}");
        assert!(st.contains(&(KeyRole::Ksk, KeyState::Active, 3)), "{st:?}");
        s.dnssec_tick(100_000_000 + 86_400 + 3600, &mut g).unwrap();
        assert!(!states(&mut s).iter().any(|k| k.2 == 1));
    }

    #[test]
    fn keys_survive_a_restart() {
        let storage = crate::MemoryStorage::default();
        let mut s = Session::with_storage(
            Box::new(corerouter_hal::virt::VirtualHal::default()),
            Box::new(storage.clone()),
        );
        s.execute("ip.dns.zone.add", &json!({"name": "example.com", "dnssec": true}))
            .unwrap();
        s.dnssec_tick(0, &mut fake()).unwrap();
        s.dnssec_signed("example.com", 77).unwrap();
        drop(s);
        let mut back = Session::with_storage(
            Box::new(corerouter_hal::virt::VirtualHal::default()),
            Box::new(storage),
        );
        let st = back.dnssec_state();
        assert_eq!(st.keys.len(), 2);
        assert_eq!(st.signed_serial.get("example.com"), Some(&77));
    }
}
