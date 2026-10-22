//! /ip dns zone (G4.1c): authoritative zones and their records. How they
//! answer is in `proto-dns` (`zone/`, the chain's `zones` stage); the
//! daemon serves transfers and runs the secondaries (`dns_zone.rs` here is
//! its window into the engine).
//!
//! A primary zone's serial moves by itself: every command that changes the
//! zone sets it to the next serial after the running one (`serial_policy`),
//! so all the changes of one transaction share one new serial.

use std::net::IpAddr;

use corerouter_model::ItemId;
use corerouter_model::dns::{MAX_TTL_SECS, usable_server};
use corerouter_model::dns_static::host_name_ok;
use corerouter_model::dns_zone::{
    DnsZones, MAX_ALLOW_TRANSFER, MAX_CAA_VALUE_LEN, MAX_NOTIFY, MAX_PRIMARIES, MAX_RECORDS,
    MAX_TEXT_LEN, MAX_ZONES, RecordType, SerialPolicy, Zone, ZoneRecord, ZoneType, first_serial,
    mailbox_name, next_serial, normalize_host, relative_name_ok, serial_gt,
};
use corerouter_proto_dns::zone::file;
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32, req_parse, req_str};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.dns.zone.add",
        "Add Zone",
        ["IP", "DNS"],
        None,
        "{name: name (the zone: example.com, 88.168.192.in-addr.arpa), type?: primary | secondary (default primary), primary_ns?: name (SOA MNAME; default ns1.<zone>), admin?: email or name (SOA RNAME; default hostmaster.<zone>), serial?: int (default: by serial_policy), serial_policy?: date | increment | unixtime (default date: YYYYMMDDnn), refresh_secs?: int (86400), retry_secs?: int (7200), expire_secs?: int (3600000), minimum_secs?: int (negative TTL, 3600), ttl_secs?: int (default record TTL, 3600), allow_transfer?: [prefix] (who may AXFR/IXFR; default nobody), notify?: [ip] (told on every change, RFC 1996), primaries?: [ip] (secondary: transfer from), dnssec?: bool (sign the zone: KSK + ZSK, NSEC3), dnssec_algorithm?: ecdsa-p256 | ed25519 (default ecdsa-p256), signature_validity_secs?: int 86400..7776000 (default 1209600), update_keys?: [TSIG key name] (may change the zone by RFC 2136 UPDATE), allow_update?: [prefix] (where an UPDATE may come from; without update_keys: unsigned from there), disabled?: bool, comment?: string} → {id, name, serial}",
        always,
        add
    ),
    cmd!(
        "ip.dns.zone.set",
        "Set Zone",
        [],
        None,
        "{id: *hex | name, name?: name, primary_ns?: name, admin?: email or name, serial?: int, serial_policy?: date | increment | unixtime, refresh_secs?: int, retry_secs?: int, expire_secs?: int, minimum_secs?: int, ttl_secs?: int, allow_transfer?: [prefix], notify?: [ip], primaries?: [ip], dnssec?: bool, dnssec_algorithm?: ecdsa-p256 | ed25519, signature_validity_secs?: int, update_keys?: [name], allow_update?: [prefix], disabled?: bool, comment?: string} → {id, name, serial} (\"\" clears a field)",
        has_zones,
        set
    ),
    cmd!(
        "ip.dns.zone.remove",
        "Remove Zone",
        [],
        None,
        "{id: *hex | name} → {id, name, records (removed with it)}",
        has_zones,
        remove
    ),
    cmd!(query "ip.dns.zone.print", "DNS Zones", ["IP", "DNS"], None,
        "{name?: string} → [{id, name, type, primary_ns?, admin?, serial, serial_policy, refresh_secs, retry_secs, expire_secs, minimum_secs, ttl_secs, allow_transfer?, notify?, primaries?, disabled?, comment?, records (count), status: running | disabled | loaded | not-loaded | config-only, loaded_serial?, refreshed_unix?, next_refresh_unix?, error?, signed_serial?, signatures_expire_unix?, ds? ([DS for the parent]), flags (X disabled)}]",
        always, print),
    cmd!(query "ip.dns.zone.file.get", "Zone File", [], None,
        "{zone: name} → {zone, text (RFC 1035 zone file of what the zone serves)}",
        has_zones, file_get),
    cmd!(
        "ip.dns.zone.file.load",
        "Load Zone File",
        [],
        None,
        "{zone: name (a primary zone), text: string (RFC 1035 zone file; $INCLUDE refused)} → {zone, records, serial} (replaces the zone's records; the SOA timers come from the file)",
        has_zones,
        file_load
    ),
    cmd!(
        "ip.dns.zone.refresh",
        "Refresh Zone",
        [],
        None,
        "{zone: name (a secondary zone)} → {zone} (checks the primaries now and transfers if the serial moved)",
        has_zones,
        refresh
    ),
    cmd!(
        "ip.dns.zone.record.add",
        "Add Zone Record",
        ["IP", "DNS"],
        None,
        "{zone: name, name?: string (relative: @ (default), www, *.dev, _sip._udp; or absolute with a final dot), type?: A | AAAA | CAA | CNAME | MX | NS | PTR | SRV | TXT (default A), address?: ip (A, AAAA), target?: name (CNAME, MX, NS, PTR, SRV; fully qualified), priority?: int 0..65535 (MX preference, SRV priority), weight?: int 0..65535 (SRV), port?: int 0..65535 (SRV), text?: string (TXT; CAA value), caa_flags?: int 0..255, caa_tag?: string (issue, issuewild, iodef), ttl_secs?: int (default: the zone's), disabled?: bool, comment?: string} → {id, serial}",
        has_zones,
        record_add
    ),
    cmd!(
        "ip.dns.zone.record.set",
        "Set Zone Record",
        [],
        None,
        "{id: *hex, name?: string, type?: A | AAAA | CAA | CNAME | MX | NS | PTR | SRV | TXT, address?: ip, target?: name, priority?: int, weight?: int, port?: int, text?: string, caa_flags?: int, caa_tag?: string, ttl_secs?: int (\"\" for the zone's), disabled?: bool, comment?: string} → {id, serial}",
        has_records,
        record_set
    ),
    cmd!(
        "ip.dns.zone.record.remove",
        "Remove Zone Record",
        [],
        None,
        "{id: *hex} → {id, serial}",
        has_records,
        record_remove
    ),
    cmd!(query "ip.dns.zone.record.print", "DNS Zone Records", ["IP", "DNS"], None,
        "{zone?: name, name?: string} → [{id, zone, name, fqdn, type, address?, target?, priority?, weight?, port?, text?, caa_flags?, caa_tag?, ttl_secs?, ttl (effective), data, disabled?, comment?, dynamic? (from an UPDATE or a lease), source?, expires_unix?, flags (X disabled, D dynamic)}]",
        always, record_print),
    cmd!(
        "ip.dns.zone.dynamic.remove",
        "Remove Dynamic Record",
        [],
        None,
        "{id: *hex (a D row of ip.dns.zone.record.print)} → {id}",
        always,
        dynamic_remove
    ),
    cmd!(
        "ip.dns.zone.dynamic.flush",
        "Flush Dynamic Records",
        [],
        None,
        "{zone: name} → {zone, removed}",
        has_zones,
        dynamic_flush
    ),
];

fn has_zones(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.dns_zones.zones.is_empty() {
        Err("there are no DNS zones".into())
    } else {
        Ok(())
    }
}

fn has_records(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.dns_zones.records.is_empty() {
        Err("there are no zone records".into())
    } else {
        Ok(())
    }
}

fn zones(s: &Session) -> &DnsZones {
    &s.store().candidate().ip.dns_zones
}

fn shown(s: &str) -> String {
    s.chars().take(64).collect()
}

/// A zone by `*id` or by name.
fn zone_index(s: &Session, p: &Value, key: &str) -> Result<usize> {
    let raw = req_str(p, key)?.trim();
    let dz = zones(s);
    let found = match raw.parse::<ItemId>() {
        Ok(id) if raw.starts_with('*') => dz.zones.iter().position(|z| z.id == id),
        _ => {
            let name = normalize_host(raw);
            dz.zones.iter().position(|z| z.name == name)
        }
    };
    found.ok_or_else(|| EngineError::bad(key, format!("no DNS zone {}", shown(raw))))
}

fn record_index(s: &Session, p: &Value) -> Result<usize> {
    let id: ItemId = req_parse(p, "id")?;
    zones(s)
        .records
        .iter()
        .position(|r| r.id == id)
        .ok_or_else(|| EngineError::bad("id", format!("no zone record {id}")))
}

/// A host name parameter: lowercase, without the final dot; "" clears it.
fn host(p: &Value, key: &str) -> Result<Option<String>> {
    let Some(v) = opt_str(p, key)? else {
        return Ok(None);
    };
    let v = normalize_host(v);
    if !v.is_empty() && !host_name_ok(&v) {
        return Err(EngineError::bad(
            key,
            format!(
                "'{}' is not a DNS name (letters, digits, - and _ in labels of 1..=63)",
                shown(&v)
            ),
        ));
    }
    Ok(Some(v))
}

/// A JSON array of strings or one comma-separated string; "" empties it.
fn list<T: std::str::FromStr>(p: &Value, key: &str, max: usize, what: &str) -> Result<Option<Vec<T>>> {
    let raw: Vec<String> = match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|s| s.trim().to_owned())
                    .ok_or_else(|| EngineError::bad(key, "each item must be a string"))
            })
            .collect::<Result<_>>()?,
        Some(_) => return Err(EngineError::bad(key, format!("must be a list of {what}"))),
    };
    if raw.len() > max {
        return Err(EngineError::bad(key, format!("at most {max} items")));
    }
    raw.iter()
        .map(|s| {
            s.parse::<T>()
                .map_err(|_| EngineError::bad(key, format!("'{}' is not {what}", shown(s))))
        })
        .collect::<Result<Vec<T>>>()
        .map(Some)
}

fn servers(p: &Value, key: &str, max: usize) -> Result<Option<Vec<IpAddr>>> {
    let Some(mut v) = list::<IpAddr>(p, key, max, "an IP address")? else {
        return Ok(None);
    };
    if let Some(bad) = v.iter().find(|ip| !usable_server(**ip)) {
        return Err(EngineError::bad(key, format!("{bad} cannot be a DNS server")));
    }
    v.dedup();
    Ok(Some(v))
}

fn secs(p: &Value, key: &str) -> Result<Option<u32>> {
    let v = opt_u32(p, key)?;
    if v.is_some_and(|v| v > MAX_TTL_SECS) {
        return Err(EngineError::bad(
            key,
            format!("must be at most {MAX_TTL_SECS} (RFC 2181 §8)"),
        ));
    }
    Ok(v)
}

/// Applies the zone fields given in `p` to `z`.
fn apply_zone(z: &mut Zone, p: &Value) -> Result<()> {
    if let Some(v) = host(p, "name")? {
        if v.is_empty() {
            return Err(EngineError::bad("name", "a zone needs a name"));
        }
        z.name = v;
    }
    if let Some(v) = host(p, "primary_ns")? {
        z.primary_ns = v;
    }
    match opt_str(p, "admin")? {
        Some(a) if a.trim().is_empty() => z.admin.clear(),
        Some(a) => z.admin = mailbox_name(a).map_err(|e| EngineError::bad("admin", e))?,
        None => {}
    }
    if let Some(v) = opt_u32(p, "serial")? {
        z.serial = v;
    }
    if let Some(v) = opt_parse::<SerialPolicy>(p, "serial_policy")? {
        z.serial_policy = v;
    }
    for (key, slot) in [
        ("refresh_secs", &mut z.refresh_secs),
        ("retry_secs", &mut z.retry_secs),
        ("expire_secs", &mut z.expire_secs),
        ("minimum_secs", &mut z.minimum_secs),
        ("ttl_secs", &mut z.ttl_secs),
    ] {
        if let Some(v) = secs(p, key)? {
            *slot = v;
        }
    }
    if let Some(v) = list::<IpNet>(p, "allow_transfer", MAX_ALLOW_TRANSFER, "a prefix")? {
        z.allow_transfer = v.into_iter().map(|n| n.trunc()).collect();
    }
    if let Some(v) = servers(p, "notify", MAX_NOTIFY)? {
        z.notify = v;
    }
    if let Some(v) = servers(p, "primaries", MAX_PRIMARIES)? {
        z.primaries = v;
    }
    if let Some(v) = list::<IpNet>(p, "allow_update", MAX_ALLOW_TRANSFER, "a prefix")? {
        z.allow_update = v.into_iter().map(|n| n.trunc()).collect();
    }
    if let Some(v) = list::<String>(p, "update_keys", 8, "a key name")? {
        z.update_keys = v.iter().map(|k| normalize_host(k)).collect();
    }
    if let Some(v) = opt_bool(p, "dnssec")? {
        z.dnssec = v;
    }
    if let Some(v) = opt_parse(p, "dnssec_algorithm")? {
        z.dnssec_algorithm = v;
    }
    if let Some(v) = opt_u32(p, "signature_validity_secs")? {
        z.signature_validity_secs = v;
    }
    if let Some(v) = opt_bool(p, "disabled")? {
        z.disabled = v;
    }
    if let Some(v) = opt_text(p, "comment", 256)? {
        z.comment = v;
    }
    if let Some(why) = z.problem() {
        let key = ["name", "primary_ns", "admin", "retry_secs", "expire_secs", "minimum_secs", "notify", "primaries", "allow_transfer", "signature_validity_secs", "dnssec", "allow_update", "update_keys"]
            .into_iter()
            .find(|k| why.starts_with(k))
            .unwrap_or("type");
        return Err(EngineError::bad(key, why));
    }
    Ok(())
}

/// The candidate's zones after `edit`, checked as a whole (a CNAME next to
/// other data, a duplicate) before they replace the candidate's.
fn commit_zones(s: &mut Session, dz: DnsZones, key: &str) -> Result<()> {
    if let Some(why) = dz.problem() {
        return Err(EngineError::bad(key, why));
    }
    s.store_mut().candidate_mut().ip.dns_zones = dz;
    Ok(())
}

/// The next serial of primary zone `name` (in `dz`): after the running
/// one, so one transaction's changes share it (RFC 1982: always larger).
fn bump(s: &mut Session, dz: &mut DnsZones, name: &str) -> Option<u32> {
    // The daemon's clock (`Session::tick`) when the HAL has none (lab).
    let now = s.now().unwrap_or(0);
    // The serial served after a dynamic update may be ahead of the
    // config's (G4.1c-3): the next one passes it too.
    let dynamic = s.dns_dynamic_serial(name);
    let running = s
        .store()
        .running()
        .ip
        .dns_zones
        .zone(name)
        .map(|z| match dynamic {
            Some(d) if serial_gt(d, z.serial) => d,
            _ => z.serial,
        });
    let z = dz.zones.iter_mut().find(|z| z.name == name)?;
    if z.ztype != ZoneType::Primary {
        return None;
    }
    let next = match running {
        Some(r) => next_serial(z.serial_policy, r, now),
        None => first_serial(z.serial_policy, now),
    };
    // Never backwards: a serial set by hand (or by an imported export)
    // larger than the next one stays.
    if serial_gt(next, z.serial) {
        z.serial = next;
    }
    Some(z.serial)
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let mut dz = zones(s).clone();
    if dz.zones.len() >= MAX_ZONES {
        return Err(EngineError::bad("name", format!("at most {MAX_ZONES} zones")));
    }
    let name = host(p, "name")?.unwrap_or_default();
    if name.is_empty() {
        return Err(EngineError::bad("name", "is required"));
    }
    if dz.zone(&name).is_some() {
        return Err(EngineError::bad("name", format!("zone {name} already exists")));
    }
    let mut z = Zone::new(ItemId(0), &name);
    if let Some(t) = opt_parse::<ZoneType>(p, "type")? {
        z.ztype = t;
    }
    apply_zone(&mut z, p)?;
    z.id = dz.next_id();
    let (id, explicit) = (z.id, opt_u32(p, "serial")?.is_some());
    dz.zones.push(z);
    let serial = if explicit {
        dz.zone(&name).map_or(0, |z| z.serial)
    } else {
        bump(s, &mut dz, &name).unwrap_or(0)
    };
    commit_zones(s, dz, "name")?;
    Ok(json!({"id": id, "name": name, "serial": serial}))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    if p.get("type").is_some() {
        return Err(EngineError::bad(
            "type",
            "the type of a zone cannot change: remove it and add it again",
        ));
    }
    let i = zone_index(s, p, "id")?;
    let mut dz = zones(s).clone();
    let Some(mut z) = dz.zones.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such zone"));
    };
    let old = z.name.clone();
    let old_alg = z.dnssec_algorithm;
    apply_zone(&mut z, p)?;
    if z.dnssec_algorithm != old_alg && s.dnssec_state().keys_of(&old).next().is_some() {
        return Err(EngineError::bad(
            "dnssec_algorithm",
            "the zone has keys of the other algorithm: an algorithm rollover is not supported yet \
             (turn dnssec off, wait for the DS to leave the parent, forget the keys)",
        ));
    }
    if z.name != old && s.dnssec_state().keys_of(&old).next().is_some() {
        return Err(EngineError::bad(
            "name",
            "a zone with DNSSEC keys cannot be renamed (its DS belongs to the old name)",
        ));
    }
    if z.name != old {
        if dz.zone(&z.name).is_some() {
            return Err(EngineError::bad("name", format!("zone {} already exists", z.name)));
        }
        for r in dz.records.iter_mut().filter(|r| r.zone == old) {
            r.zone.clone_from(&z.name);
        }
    }
    let (id, name) = (z.id, z.name.clone());
    if let Some(slot) = dz.zones.get_mut(i) {
        *slot = z;
    }
    let serial = if opt_u32(p, "serial")?.is_some() {
        dz.zone(&name).map_or(0, |z| z.serial)
    } else {
        bump(s, &mut dz, &name).unwrap_or(0)
    };
    commit_zones(s, dz, "id")?;
    Ok(json!({"id": id, "name": name, "serial": serial}))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = zone_index(s, p, "id")?;
    let dz = &mut s.store_mut().candidate_mut().ip.dns_zones;
    let z = dz.zones.remove(i);
    let before = dz.records.len();
    dz.records.retain(|r| r.zone != z.name);
    let removed = before - dz.records.len();
    Ok(json!({"id": z.id, "name": z.name, "records": removed}))
}

fn print(s: &mut Session, p: &Value) -> Result<Value> {
    let filter = opt_str(p, "name")?.map(normalize_host);
    let status = s.zone_backend().map(|b| b.status());
    let keys = s.dnssec_state();
    let dz = zones(s);
    let rows: Vec<Value> = dz
        .zones
        .iter()
        .filter(|z| filter.as_ref().is_none_or(|f| z.name.contains(f.as_str())))
        .filter_map(|z| {
            let mut v = serde_json::to_value(z).ok()?;
            let o = v.as_object_mut()?;
            o.insert("records".into(), json!(dz.records_of(&z.name).count()));
            let st = status
                .as_ref()
                .and_then(|all| all.iter().find(|st| st.zone == z.name));
            let state = match (z.disabled, z.ztype, &status, st) {
                (true, _, _, _) => "disabled",
                (_, _, None, _) => "config-only",
                (_, ZoneType::Primary, Some(_), _) => "running",
                (_, ZoneType::Secondary, Some(_), Some(st)) if st.loaded_serial.is_some() => {
                    "loaded"
                }
                _ => "not-loaded",
            };
            o.insert("status".into(), json!(state));
            if let Some(st) = st {
                if let Some(n) = st.records.filter(|_| z.ztype == ZoneType::Secondary) {
                    o.insert("records".into(), json!(n));
                }
                for (k, val) in [
                    ("loaded_serial", st.loaded_serial.map(u64::from)),
                    ("refreshed_unix", st.refreshed_unix),
                    ("next_refresh_unix", st.next_refresh_unix),
                ] {
                    if let Some(val) = val {
                        o.insert(k.into(), json!(val));
                    }
                }
                if !st.error.is_empty() {
                    o.insert("error".into(), json!(st.error));
                }
                for (k, val) in [
                    ("signed_serial", st.signed_serial.map(u64::from)),
                    ("signatures_expire_unix", st.signatures_expire_unix),
                ] {
                    if let Some(val) = val {
                        o.insert(k.into(), json!(val));
                    }
                }
                if st.signed {
                    o.insert("signed".into(), json!(true));
                }
            }
            let ds: Vec<&str> = keys
                .keys_of(&z.name)
                .filter(|k| !k.ds.is_empty() && k.state != corerouter_model::dnssec::KeyState::Retired)
                .map(|k| k.ds.as_str())
                .collect();
            if !ds.is_empty() {
                o.insert("ds".into(), json!(ds));
            }
            o.insert("flags".into(), json!(if z.disabled { "X" } else { "" }));
            Some(v)
        })
        .collect();
    Ok(Value::Array(rows))
}

fn file_get(s: &mut Session, p: &Value) -> Result<Value> {
    let i = zone_index(s, p, "zone")?;
    let (_, dyn_state) = s.dns_dynamic();
    let dz = zones(s);
    let Some(z) = dz.zones.get(i) else {
        return Err(EngineError::bad("zone", "no such zone"));
    };
    let text = match z.ztype {
        ZoneType::Primary => {
            let recs: Vec<&ZoneRecord> = dz.records_of(&z.name).collect();
            let dynamic: Vec<&ZoneRecord> =
                dyn_state.records_of(&z.name).map(|d| &d.record).collect();
            let serial = dyn_state.serials.get(&z.name).copied();
            corerouter_proto_dns::zone::served(z, &recs, &dynamic, serial)
                .map(|d| d.to_file())
                .ok_or_else(|| EngineError::bad("zone", "the zone cannot be built"))?
        }
        ZoneType::Secondary => s
            .zone_backend()
            .and_then(|b| b.file(&z.name))
            .ok_or_else(|| {
                EngineError::bad(
                    "zone",
                    format!("secondary zone {} is not loaded (yet)", z.name),
                )
            })?,
    };
    Ok(json!({"zone": z.name, "text": text}))
}

fn file_load(s: &mut Session, p: &Value) -> Result<Value> {
    let i = zone_index(s, p, "zone")?;
    let text = req_str(p, "text")?;
    let mut dz = zones(s).clone();
    let Some(z) = dz.zones.get(i).cloned() else {
        return Err(EngineError::bad("zone", "no such zone"));
    };
    if z.ztype != ZoneType::Primary {
        return Err(EngineError::bad(
            "zone",
            "a secondary zone gets its records by transfer",
        ));
    }
    let got = file::import(&z.name, text).map_err(|e| EngineError::bad("text", e))?;
    let others = dz.records.iter().filter(|r| r.zone != z.name).count();
    if others + got.records.len() > MAX_RECORDS {
        return Err(EngineError::bad(
            "text",
            format!("at most {MAX_RECORDS} zone records in all"),
        ));
    }
    let mut nz = z.clone();
    if let Some(t) = got.default_ttl {
        nz.ttl_secs = t;
    }
    let mut file_serial = None;
    if let Some(soa) = &got.soa {
        nz.primary_ns.clone_from(&soa.mname);
        nz.admin.clone_from(&soa.rname);
        nz.refresh_secs = soa.refresh;
        nz.retry_secs = soa.retry;
        nz.expire_secs = soa.expire;
        nz.minimum_secs = soa.minimum;
        if got.default_ttl.is_none() && soa.ttl > 0 {
            nz.ttl_secs = soa.ttl;
        }
        file_serial = Some(soa.serial);
    }
    if let Some(why) = nz.problem() {
        return Err(EngineError::bad("text", format!("the SOA: {why}")));
    }
    dz.records.retain(|r| r.zone != z.name);
    let count = got.records.len();
    for mut r in got.records {
        if r.ttl_secs == Some(nz.ttl_secs) {
            r.ttl_secs = None;
        }
        r.id = dz.next_record_id();
        dz.records.push(r);
    }
    if let Some(slot) = dz.zones.get_mut(i) {
        *slot = nz;
    }
    let mut serial = bump(s, &mut dz, &z.name).unwrap_or(0);
    // A serial in the file larger than ours wins (the secondaries already
    // know it, if the zone came from another server).
    if let Some(fs) = file_serial.filter(|fs| serial_gt(*fs, serial))
        && let Some(slot) = dz.zones.get_mut(i)
    {
        slot.serial = fs;
        serial = fs;
    }
    commit_zones(s, dz, "text")?;
    Ok(json!({"zone": z.name, "records": count, "serial": serial}))
}

fn refresh(s: &mut Session, p: &Value) -> Result<Value> {
    let i = zone_index(s, p, "zone")?;
    let Some(z) = zones(s).zones.get(i).cloned() else {
        return Err(EngineError::bad("zone", "no such zone"));
    };
    if z.ztype != ZoneType::Secondary {
        return Err(EngineError::bad("zone", format!("{} is not a secondary zone", z.name)));
    }
    let b = s.zone_backend().ok_or_else(|| {
        EngineError::bad("zone", "zones are transferred by the daemon (corerouter-daemon)")
    })?;
    b.refresh(&z.name).map_err(|e| EngineError::bad("zone", e))?;
    Ok(json!({"zone": z.name}))
}

/// A record name: relative to `zone` (`@`, `www`), or absolute with a final
/// dot inside the zone; lowercase.
fn record_name(text: &str, zone: &str) -> Result<String> {
    let t = text.trim().to_ascii_lowercase();
    let rel = if t.is_empty() || t == "@" {
        "@".to_owned()
    } else if let Some(abs) = t.strip_suffix('.') {
        if abs == zone {
            "@".to_owned()
        } else if let Some(r) = abs.strip_suffix(&format!(".{zone}")) {
            r.to_owned()
        } else {
            return Err(EngineError::bad(
                "name",
                format!("{} is outside the zone {zone}", shown(abs)),
            ));
        }
    } else {
        t
    };
    if !relative_name_ok(&rel) {
        return Err(EngineError::bad(
            "name",
            format!("'{}' is not a record name (@, www, *.dev, _sip._udp)", shown(&rel)),
        ));
    }
    Ok(rel)
}

fn small(p: &Value, key: &str) -> Result<Option<u16>> {
    opt_u32(p, key)?
        .map(|v| u16::try_from(v).map_err(|_| EngineError::bad(key, "must be 0..=65535")))
        .transpose()
}

/// Applies the record fields given in `p` to `r`; fields the type does not
/// use are cleared.
fn apply_record(r: &mut ZoneRecord, p: &Value) -> Result<()> {
    if let Some(n) = opt_str(p, "name")? {
        r.name = record_name(n, &r.zone)?;
    }
    if let Some(t) = opt_parse::<RecordType>(p, "type")? {
        r.rtype = t;
    }
    match opt_str(p, "address")? {
        Some("") => r.address = None,
        Some(_) => r.address = opt_parse(p, "address")?,
        None => {}
    }
    match opt_str(p, "target")? {
        Some(t) if t.trim() == "@" => r.target.clone_from(&r.zone),
        Some(_) => r.target = host(p, "target")?.unwrap_or_default(),
        None => {}
    }
    for (key, slot) in [
        ("priority", &mut r.priority),
        ("weight", &mut r.weight),
        ("port", &mut r.port),
    ] {
        if let Some(v) = small(p, key)? {
            *slot = v;
        }
    }
    let max = if r.rtype == RecordType::Caa {
        MAX_CAA_VALUE_LEN
    } else {
        MAX_TEXT_LEN
    };
    if let Some(v) = opt_str(p, "text")? {
        if v.len() > max {
            return Err(EngineError::bad("text", format!("at most {max} bytes")));
        }
        if v.chars().any(char::is_control) {
            return Err(EngineError::bad("text", "control characters are not allowed"));
        }
        v.clone_into(&mut r.text);
    }
    if let Some(v) = opt_u32(p, "caa_flags")? {
        r.caa_flags = u8::try_from(v).map_err(|_| EngineError::bad("caa_flags", "must be 0..=255"))?;
    }
    if let Some(v) = opt_str(p, "caa_tag")? {
        r.caa_tag = v.trim().to_ascii_lowercase();
    }
    match opt_str(p, "ttl_secs") {
        Ok(Some("")) => r.ttl_secs = None,
        _ => {
            if let Some(v) = secs(p, "ttl_secs")? {
                r.ttl_secs = Some(v);
            }
        }
    }
    if let Some(v) = opt_bool(p, "disabled")? {
        r.disabled = v;
    }
    if let Some(v) = opt_text(p, "comment", 256)? {
        r.comment = v;
    }
    use RecordType as T;
    let t = r.rtype;
    if !matches!(t, T::A | T::Aaaa) {
        r.address = None;
    }
    if matches!(t, T::A | T::Aaaa | T::Txt | T::Caa) {
        r.target.clear();
    }
    if !matches!(t, T::Mx | T::Srv) {
        r.priority = 0;
    }
    if t != T::Srv {
        r.weight = 0;
        r.port = 0;
    }
    if !matches!(t, T::Txt | T::Caa) {
        r.text.clear();
    }
    if t != T::Caa {
        r.caa_flags = 0;
        r.caa_tag.clear();
    }
    if let Some(why) = r.problem() {
        let key = ["name", "target", "text", "ttl_secs"]
            .into_iter()
            .find(|k| why.starts_with(k))
            .unwrap_or("type");
        return Err(EngineError::bad(key, why));
    }
    Ok(())
}

fn record_add(s: &mut Session, p: &Value) -> Result<Value> {
    let i = zone_index(s, p, "zone")?;
    let mut dz = zones(s).clone();
    let Some(z) = dz.zones.get(i).cloned() else {
        return Err(EngineError::bad("zone", "no such zone"));
    };
    if z.ztype != ZoneType::Primary {
        return Err(EngineError::bad(
            "zone",
            format!("{} is a secondary zone: it gets its records by transfer", z.name),
        ));
    }
    if dz.records.len() >= MAX_RECORDS {
        return Err(EngineError::bad(
            "zone",
            format!("at most {MAX_RECORDS} zone records"),
        ));
    }
    let mut r = ZoneRecord::new(ItemId(0), &z.name, "@");
    apply_record(&mut r, p)?;
    r.id = dz.next_record_id();
    let id = r.id;
    dz.records.push(r);
    let serial = bump(s, &mut dz, &z.name).unwrap_or(0);
    commit_zones(s, dz, "name")?;
    Ok(json!({"id": id, "serial": serial}))
}

fn record_set(s: &mut Session, p: &Value) -> Result<Value> {
    if p.get("zone").is_some() {
        return Err(EngineError::bad(
            "zone",
            "a record cannot move to another zone: add it there and remove this one",
        ));
    }
    let i = record_index(s, p)?;
    let mut dz = zones(s).clone();
    let Some(mut r) = dz.records.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such record"));
    };
    apply_record(&mut r, p)?;
    let (id, zone) = (r.id, r.zone.clone());
    if let Some(slot) = dz.records.get_mut(i) {
        *slot = r;
    }
    let serial = bump(s, &mut dz, &zone).unwrap_or(0);
    commit_zones(s, dz, "id")?;
    Ok(json!({"id": id, "serial": serial}))
}

fn record_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = record_index(s, p)?;
    let mut dz = zones(s).clone();
    let r = dz.records.remove(i);
    let serial = bump(s, &mut dz, &r.zone).unwrap_or(0);
    commit_zones(s, dz, "id")?;
    Ok(json!({"id": r.id, "serial": serial}))
}

fn record_print(s: &mut Session, p: &Value) -> Result<Value> {
    let zone = opt_str(p, "zone")?.map(normalize_host);
    let name = opt_str(p, "name")?.map(|n| n.trim().to_ascii_lowercase());
    let (_, dynamic) = s.dns_dynamic();
    let dz = zones(s);
    let wanted = |r: &ZoneRecord| {
        zone.as_ref().is_none_or(|z| r.zone == *z)
            && name.as_ref().is_none_or(|n| r.name.contains(n.as_str()))
    };
    let row = |r: &ZoneRecord, flags: &str| -> Option<Value> {
        let z = dz.zone(&r.zone)?;
        let mut v = serde_json::to_value(r).ok()?;
        let o = v.as_object_mut()?;
        o.insert("fqdn".into(), json!(z.owner(&r.name)));
        o.insert("ttl".into(), json!(r.ttl_secs.unwrap_or(z.ttl_secs)));
        o.insert("data".into(), json!(r.data()));
        o.insert("flags".into(), json!(flags));
        Some(v)
    };
    let mut rows: Vec<Value> = dz
        .records
        .iter()
        .filter(|r| wanted(r))
        .filter_map(|r| row(r, if r.disabled { "X" } else { "" }))
        .collect();
    // Dynamic records (G4.1c-3): `D`, like RouterOS's dynamic entries;
    // their ids are of their own space (`ip.dns.zone.dynamic.remove`).
    rows.extend(dynamic.records.iter().filter(|d| wanted(&d.record)).filter_map(|d| {
        let mut v = row(&d.record, "D")?;
        let o = v.as_object_mut()?;
        o.insert("dynamic".into(), json!(true));
        o.insert("source".into(), json!(d.source));
        if let Some(e) = d.expires_unix {
            o.insert("expires_unix".into(), json!(e));
        }
        Some(v)
    }));
    Ok(Value::Array(rows))
}

fn dynamic_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let now = s.now().unwrap_or(0);
    let n = s
        .dns_dynamic_remove(|d| d.record.id == id, now)
        .map_err(EngineError::Internal)?;
    if n == 0 {
        return Err(EngineError::bad("id", format!("no dynamic record {id}")));
    }
    Ok(json!({"id": id}))
}

fn dynamic_flush(s: &mut Session, p: &Value) -> Result<Value> {
    let i = zone_index(s, p, "zone")?;
    let Some(name) = zones(s).zones.get(i).map(|z| z.name.clone()) else {
        return Err(EngineError::bad("zone", "no such zone"));
    };
    let now = s.now().unwrap_or(0);
    let n = s
        .dns_dynamic_remove(|d| d.record.zone == name, now)
        .map_err(EngineError::Internal)?;
    Ok(json!({"zone": name, "removed": n}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(s: &mut Session, id: &str, p: Value) -> Result<Value> {
        s.execute(id, &p)
    }

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        run(
            &mut s,
            "ip.dns.zone.add",
            json!({"name": "Example.COM.", "allow_transfer": "192.0.2.0/24", "admin": "noc@example.com"}),
        )
        .unwrap();
        s
    }

    #[test]
    fn zones_and_records_by_command() {
        let mut s = lab();
        let rows = run(&mut s, "ip.dns.zone.print", json!({})).unwrap();
        assert_eq!(rows[0]["name"], "example.com", "lowercase, no final dot");
        assert_eq!(rows[0]["admin"], "noc.example.com");
        assert_eq!(rows[0]["status"], "config-only");
        let first = rows[0]["serial"].as_u64().unwrap();
        // The lab has no clock: the date policy starts from 1970-01-01.
        assert_eq!(first, 1_970_010_100);
        let a = run(
            &mut s,
            "ip.dns.zone.record.add",
            json!({"zone": "example.com", "name": "www", "address": "192.0.2.80"}),
        )
        .unwrap();
        assert!(a["serial"].as_u64().unwrap() > first, "serial moved");
        run(
            &mut s,
            "ip.dns.zone.record.add",
            json!({"zone": "example.com", "name": "@", "type": "MX", "target": "mail.example.com.", "priority": 10}),
        )
        .unwrap();
        run(
            &mut s,
            "ip.dns.zone.record.add",
            json!({"zone": "example.com", "name": "mail.example.com.", "type": "AAAA", "address": "2001:db8::25", "ttl_secs": 300}),
        )
        .unwrap();
        run(
            &mut s,
            "ip.dns.zone.record.add",
            json!({"zone": "example.com", "type": "CAA", "caa_tag": "issue", "text": "letsencrypt.org"}),
        )
        .unwrap();
        let rows = run(&mut s, "ip.dns.zone.record.print", json!({"zone": "example.com"})).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 4);
        assert_eq!(rows[1]["data"], "10 mail.example.com.");
        assert_eq!(rows[2]["name"], "mail", "absolute name made relative");
        assert_eq!(rows[2]["ttl"], 300);
        assert_eq!(rows[0]["fqdn"], "www.example.com");
        // Type change clears what the new type does not use.
        run(
            &mut s,
            "ip.dns.zone.record.set",
            json!({"id": a["id"], "type": "CNAME", "target": "@"}),
        )
        .unwrap();
        let rows = run(&mut s, "ip.dns.zone.record.print", json!({"name": "www"})).unwrap();
        assert_eq!(rows[0]["target"], "example.com");
        assert!(rows[0].get("address").is_none());
        // The zone file, and back.
        let f = run(&mut s, "ip.dns.zone.file.get", json!({"zone": "example.com"})).unwrap();
        let text = f["text"].as_str().unwrap().to_owned();
        assert!(text.contains("www 3600 IN CNAME example.com."), "{text}");
        assert!(text.contains("IN NS ns1.example.com."), "{text}");
        let back = run(
            &mut s,
            "ip.dns.zone.file.load",
            json!({"zone": "example.com", "text": text}),
        )
        .unwrap();
        assert_eq!(back["records"], 5, "the stand-in NS became a record");
        // Rename carries the records along; remove takes them.
        run(&mut s, "ip.dns.zone.set", json!({"id": "example.com", "name": "example.net"})).unwrap();
        let rows = run(&mut s, "ip.dns.zone.record.print", json!({"zone": "example.net"})).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 5);
        let r = run(&mut s, "ip.dns.zone.remove", json!({"id": "example.net"})).unwrap();
        assert_eq!(r["records"], 5);
        assert!(zones(&s).records.is_empty());
    }

    #[test]
    fn one_transaction_one_serial() {
        let mut s = lab();
        let start = zones(&s).zones[0].serial;
        s.execute("config.mode.set", &json!({"mode": "transactional"}))
            .unwrap();
        for n in ["a", "b", "c"] {
            run(
                &mut s,
                "ip.dns.zone.record.add",
                json!({"zone": "example.com", "name": n, "address": "192.0.2.1"}),
            )
            .unwrap();
        }
        let after = zones(&s).zones[0].serial;
        assert!(serial_gt(after, start));
        assert_eq!(after, next_serial(SerialPolicy::Date, start, s.now().unwrap_or(0)));
        s.execute("config.commit", &json!({})).unwrap();
        run(
            &mut s,
            "ip.dns.zone.record.add",
            json!({"zone": "example.com", "name": "d", "address": "192.0.2.1"}),
        )
        .unwrap();
        assert!(serial_gt(zones(&s).zones[0].serial, after));
    }

    #[test]
    fn bad_zones_and_records_are_refused() {
        let mut s = lab();
        for p in [
            json!({"name": "bad name"}),
            json!({"name": "example.com"}),
            json!({"name": "x.example", "type": "secondary"}),
            json!({"name": "x.example", "primaries": "192.0.2.1"}),
            json!({"name": "x.example", "retry_secs": 100_000}),
            json!({"name": "x.example", "allow_transfer": "10.0.0.0/33"}),
            json!({"name": "x.example", "notify": "224.0.0.1"}),
            json!({"name": "x.example", "admin": "john.doe@x.example"}),
            json!({"name": "x.example", "serial_policy": "weekly"}),
        ] {
            let err = run(&mut s, "ip.dns.zone.add", p.clone()).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        run(
            &mut s,
            "ip.dns.zone.record.add",
            json!({"zone": "example.com", "name": "www", "address": "192.0.2.80"}),
        )
        .unwrap();
        for p in [
            json!({"zone": "nowhere.example", "address": "192.0.2.1"}),
            json!({"zone": "example.com", "name": "www", "address": "192.0.2.80"}),
            json!({"zone": "example.com", "name": "www", "type": "CNAME", "target": "x.example.com"}),
            json!({"zone": "example.com", "type": "CNAME", "target": "x.example.com"}),
            json!({"zone": "example.com", "name": "www.other.org.", "address": "192.0.2.1"}),
            json!({"zone": "example.com", "name": "a.*", "address": "192.0.2.1"}),
            json!({"zone": "example.com", "type": "MX", "target": "bad name"}),
            json!({"zone": "example.com", "type": "TXT", "text": "a\nb"}),
            json!({"zone": "example.com", "type": "CAA", "caa_tag": "", "text": "x"}),
            json!({"zone": "example.com", "type": "A", "address": "2001:db8::1"}),
            json!({"zone": "example.com", "type": "SOA"}),
        ] {
            let err = run(&mut s, "ip.dns.zone.record.add", p.clone()).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        assert_eq!(zones(&s).records.len(), 1);
        let err = run(
            &mut s,
            "ip.dns.zone.file.load",
            json!({"zone": "example.com", "text": "$INCLUDE /etc/passwd\n"}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("$INCLUDE"), "{err}");
        assert_eq!(zones(&s).records.len(), 1, "a refused file changes nothing");
        // Secondaries: no records by hand, no file load.
        run(
            &mut s,
            "ip.dns.zone.add",
            json!({"name": "sec.example", "type": "secondary", "primaries": ["192.0.2.53"]}),
        )
        .unwrap();
        assert!(run(&mut s, "ip.dns.zone.record.add", json!({"zone": "sec.example", "address": "192.0.2.1"})).is_err());
        assert!(run(&mut s, "ip.dns.zone.refresh", json!({"zone": "sec.example"})).is_err(), "no daemon");
        let rows = run(&mut s, "ip.dns.zone.print", json!({"name": "sec"})).unwrap();
        assert_eq!(rows[0]["type"], "secondary");
        assert_eq!(rows[0]["serial"], 0, "a secondary's serial is the primary's");
    }

    #[test]
    fn rollback_drops_the_zone() {
        let mut s = Session::virtual_lab();
        s.execute("config.mode.set", &json!({"mode": "transactional"}))
            .unwrap();
        run(&mut s, "ip.dns.zone.add", json!({"name": "lan.example"})).unwrap();
        run(
            &mut s,
            "ip.dns.zone.record.add",
            json!({"zone": "lan.example", "name": "nas", "address": "192.168.88.10"}),
        )
        .unwrap();
        s.execute("config.discard", &json!({})).unwrap();
        assert!(zones(&s).is_empty());
    }
}
