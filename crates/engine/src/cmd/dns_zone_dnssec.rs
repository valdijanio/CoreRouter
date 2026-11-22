//! /ip dns zone dnssec (G4.1c-2): the signing keys of the zones, their DS
//! for the parent, and the rollovers (RFC 6781 §4.1). The keys are
//! operational state (`crate::dnssec`), not config: these commands change
//! it at once, outside transactions, and never show a private key.

use corerouter_model::dns_zone::{ZoneType, normalize_host};
use corerouter_model::dnssec::{KeyRole, KeyState, RolloverRequest};
use serde_json::{Value, json};

use super::args::{opt_str, req_parse, req_str};
use super::{CommandSpec, always};
use crate::dnssec::{PARENT_DS_TTL_SECS, PROPAGATION_SECS};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "ip.dns.zone.dnssec.print", "DNSSEC Keys", [], None,
        "{zone?: name} → [{id, zone, role: ksk|zsk, algorithm, key_tag, state: published|active|retired, dnskey, ds? (KSK: for the parent, SHA-256), created_unix, changed_unix, next (what happens next)}]",
        always, print),
    cmd!(
        "ip.dns.zone.dnssec.rollover",
        "DNSSEC Rollover",
        [],
        None,
        "{zone: name, key: ksk | zsk} → {zone, key} (ZSK: pre-publication, done by itself; KSK: the new key signs next to the old one until ds-published)",
        always,
        rollover
    ),
    cmd!(
        "ip.dns.zone.dnssec.ds-published",
        "DS Published",
        [],
        None,
        "{zone: name} → {zone} (the new KSK's DS is at the parent: the old KSK retires)",
        always,
        ds_published
    ),
    cmd!(
        "ip.dns.zone.dnssec.forget",
        "Forget DNSSEC Keys",
        [],
        None,
        "{zone: name (not signed any more, or removed)} → {zone, keys (removed)}",
        always,
        forget
    ),
];

fn zone_param(p: &Value) -> Result<String> {
    let z = normalize_host(req_str(p, "zone")?);
    if z.is_empty() {
        return Err(EngineError::bad("zone", "is required"));
    }
    Ok(z)
}

/// The zone, committed, primary and signed.
fn signed_zone(s: &Session, p: &Value) -> Result<String> {
    let name = zone_param(p)?;
    let z = s
        .store()
        .running()
        .ip
        .dns_zones
        .zone(&name)
        .ok_or_else(|| EngineError::bad("zone", format!("no committed DNS zone {name}")))?;
    if z.ztype != ZoneType::Primary || !z.dnssec {
        return Err(EngineError::bad(
            "zone",
            format!("zone {name} is not signed (ip.dns.zone.set dnssec=yes, committed)"),
        ));
    }
    Ok(name)
}

fn next_step(
    k: &corerouter_model::dnssec::DnssecKey,
    ttl: u64,
    max_ttl: u64,
    ksks: usize,
    newest: bool,
) -> String {
    match (k.role, k.state) {
        (KeyRole::Zsk, KeyState::Published) => format!(
            "signs from {}",
            k.changed_unix + ttl + PROPAGATION_SECS
        ),
        (KeyRole::Zsk, KeyState::Retired) => format!(
            "removed at {}",
            k.changed_unix + max_ttl + PROPAGATION_SECS
        ),
        (KeyRole::Ksk, KeyState::Retired) => format!(
            "removed at {}",
            k.changed_unix + PARENT_DS_TTL_SECS + PROPAGATION_SECS
        ),
        (KeyRole::Ksk, KeyState::Active) if ksks > 1 && newest => {
            "new KSK: put its DS at the parent, then ds-published".into()
        }
        (KeyRole::Ksk, KeyState::Active) if ksks > 1 => {
            "retires once the new KSK's DS is published".into()
        }
        _ => String::new(),
    }
}

fn print(s: &mut Session, p: &Value) -> Result<Value> {
    let filter = opt_str(p, "zone")?.map(normalize_host);
    let state = s.dnssec_state();
    let dz = s.store().running().ip.dns_zones.clone();
    let rows: Vec<Value> = state
        .keys
        .iter()
        .filter(|k| filter.as_ref().is_none_or(|f| k.zone == *f))
        .map(|k| {
            let (ttl, max_ttl) = dz.zone(&k.zone).map_or((3600, 3600), |z| {
                let max = dz
                    .records_of(&z.name)
                    .filter_map(|r| r.ttl_secs)
                    .chain([z.ttl_secs, z.minimum_secs])
                    .max()
                    .unwrap_or(z.ttl_secs);
                (u64::from(z.ttl_secs), u64::from(max))
            });
            let active_ksks: Vec<u32> = state
                .keys_of(&k.zone)
                .filter(|x| x.role == KeyRole::Ksk && x.state == KeyState::Active)
                .map(|x| x.id)
                .collect();
            let ksks = active_ksks.len();
            let newest = active_ksks.iter().max() == Some(&k.id);
            let mut v = json!({
                "id": k.id,
                "zone": k.zone,
                "role": k.role.as_str(),
                "algorithm": k.algorithm.as_str(),
                "key_tag": k.key_tag,
                "state": k.state.as_str(),
                "dnskey": k.dnskey,
                "created_unix": k.created_unix,
                "changed_unix": k.changed_unix,
                "next": next_step(k, ttl, max_ttl, ksks, newest),
            });
            if !k.ds.is_empty()
                && let Some(o) = v.as_object_mut()
            {
                o.insert("ds".into(), json!(k.ds));
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}

fn rollover(s: &mut Session, p: &Value) -> Result<Value> {
    let zone = signed_zone(s, p)?;
    let role: KeyRole = req_parse(p, "key")?;
    let state = s.dnssec_state();
    let busy = match role {
        KeyRole::Zsk => state
            .keys_of(&zone)
            .any(|k| k.role == KeyRole::Zsk && k.state == KeyState::Published),
        KeyRole::Ksk => {
            state
                .keys_of(&zone)
                .filter(|k| k.role == KeyRole::Ksk && k.state == KeyState::Active)
                .count()
                > 1
        }
    };
    if busy || state.rollovers.iter().any(|r| r.zone == zone && r.role == role) {
        return Err(EngineError::bad(
            "key",
            format!("a {} rollover of {zone} is already going on", role.as_str()),
        ));
    }
    s.dnssec_update(|st| {
        st.rollovers.push(RolloverRequest {
            zone: zone.clone(),
            role,
        });
    })
    .map_err(EngineError::Internal)?;
    Ok(json!({"zone": zone, "key": role.as_str()}))
}

fn ds_published(s: &mut Session, p: &Value) -> Result<Value> {
    let zone = signed_zone(s, p)?;
    let state = s.dnssec_state();
    let active = state
        .keys_of(&zone)
        .filter(|k| k.role == KeyRole::Ksk && k.state == KeyState::Active)
        .count();
    if active < 2 {
        return Err(EngineError::bad(
            "zone",
            format!("no KSK rollover of {zone} waiting for its DS (ip.dns.zone.dnssec.rollover key=ksk)"),
        ));
    }
    s.dnssec_update(|st| {
        if !st.ds_published.contains(&zone) {
            st.ds_published.push(zone.clone());
        }
    })
    .map_err(EngineError::Internal)?;
    Ok(json!({"zone": zone}))
}

fn forget(s: &mut Session, p: &Value) -> Result<Value> {
    let zone = zone_param(p)?;
    let signed = s
        .store()
        .running()
        .ip
        .dns_zones
        .zone(&zone)
        .is_some_and(|z| z.dnssec);
    if signed {
        return Err(EngineError::bad(
            "zone",
            format!("zone {zone} is signed: turn dnssec off first (its DS must leave the parent before)"),
        ));
    }
    let removed = s
        .dnssec_update(|st| {
            let before = st.keys.len();
            st.keys.retain(|k| k.zone != zone);
            st.signed_serial.remove(&zone);
            st.rollovers.retain(|r| r.zone != zone);
            before - st.keys.len()
        })
        .map_err(EngineError::Internal)?;
    Ok(json!({"zone": zone, "keys": removed}))
}
