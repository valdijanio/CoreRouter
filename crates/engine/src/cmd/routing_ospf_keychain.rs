//! /routing ospf keychain (G3.4): several keys per chain, each with a
//! window to be sent in and a window to be accepted in, so a key is
//! replaced without dropping an adjacency (RFC 5709 §3.3 for v2, RFC 7166
//! §4.2 for v3; the model is RFC 8177's). The list says, at the router's
//! clock, which key is sent now and where a rotation would drop
//! neighbors: a moment no key is sent, or an old key that stops being
//! accepted before the new one starts being sent (the far end may still
//! send it).
//!
//! `key_string` arrives in clear and is sealed at once; no answer, log or
//! journal shows it.

use corerouter_model::ospf::{AuthType, MAX_KEYCHAINS, MAX_KEYS, OspfKey, OspfKeychain};
use corerouter_proto_ospf::frr::date;
use serde_json::{Value, json};

use super::args::{opt_text, req_str};
use super::routing_ospf::{Given, check_name, cut, given, number, text};
use super::routing_ospf_template::check_key;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("routing.ospf.keychain.add", "Add OSPF Key Chain", ["Routing", "OSPF"], None,
        "{name: string, comment?: string} → {name}",
        always, keychain_add),
    cmd!("routing.ospf.keychain.set", "Set OSPF Key Chain", [], None,
        "{id: string (the name), name?: string, comment?: string} → {name}",
        has_keychains, keychain_set),
    cmd!("routing.ospf.keychain.remove", "Remove OSPF Key Chain", [], None,
        "{id: string (the name)} → {name}",
        has_keychains, keychain_remove),
    cmd!(query "routing.ospf.keychain.list", "OSPF Key Chains", ["Routing", "OSPF"], None,
        "{} → [{name, comment, used_by: [template], keys: [{id, algorithm, key_set, send_from, send_until, accept_from, accept_until, sending (now), accepting (now)}], sending: [id] (now), rotation: [{level, message}]}] (times: Unix seconds; the router's clock, UTC)",
        always, keychain_list),
    cmd!("routing.ospf.keychain.key.add", "Add OSPF Key", ["Routing", "OSPF"], None,
        "{keychain: string, id: u16 (key id on the wire: 0..=255 for v2), key_string: string (sealed at once), algorithm?: string (md5, sha1, sha256, sha384, sha512; default sha256), send_from?: u64 | date string | null, send_until?: u64 | date string | null, accept_from?: u64 | date string | null, accept_until?: u64 | date string | null} → {keychain, id} (dates: \"2026-11-01\" or \"2026-11-01 03:00\", UTC)",
        has_keychains, key_add),
    cmd!("routing.ospf.keychain.key.set", "Set OSPF Key", [], None,
        "{keychain: string, id: u16, key_string?: string, algorithm?: string, send_from?: u64 | date string | null, send_until?: u64 | date string | null, accept_from?: u64 | date string | null, accept_until?: u64 | date string | null} → {keychain, id}",
        has_keychains, key_set),
    cmd!("routing.ospf.keychain.key.remove", "Remove OSPF Key", [], None,
        "{keychain: string, id: u16} → {keychain, id}",
        has_keychains, key_remove),
];

fn has_keychains(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().routing.ospf.keychains.is_empty() {
        Err("there are no OSPF key chains (routing.ospf.keychain.add)".into())
    } else {
        Ok(())
    }
}

fn keychain_add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = req_str(p, "name")?.trim().to_owned();
    check_name("name", &name)?;
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let ospf = &mut s.store_mut().candidate_mut().routing.ospf;
    if ospf.keychains.contains_key(&name) {
        return Err(EngineError::bad("name", format!("key chain {name:?} already exists")));
    }
    if ospf.keychains.len() >= MAX_KEYCHAINS {
        return Err(EngineError::bad("name", format!("at most {MAX_KEYCHAINS} key chains")));
    }
    ospf.keychains.insert(name.clone(), OspfKeychain { name: name.clone(), keys: Vec::new(), comment });
    Ok(json!({ "name": name }))
}

fn keychain_set(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?.to_owned();
    let ospf = &mut s.store_mut().candidate_mut().routing.ospf;
    let mut kc = ospf
        .keychains
        .get(&id)
        .cloned()
        .ok_or_else(|| EngineError::bad("id", format!("no OSPF key chain {:?}", cut(&id))))?;
    if let Some(c) = opt_text(p, "comment", 256)? {
        kc.comment = c;
    }
    if let Given::Value(v) = given(p, "name") {
        let n = text("name", v)?;
        check_name("name", n)?;
        if n != id && ospf.keychains.contains_key(n) {
            return Err(EngineError::bad("name", format!("key chain {n:?} already exists")));
        }
        kc.name = n.to_owned();
    }
    let name = kc.name.clone();
    if name != id {
        ospf.keychains.remove(&id);
        for t in ospf.templates.iter_mut().filter(|t| t.keychain.as_deref() == Some(id.as_str())) {
            t.keychain = Some(name.clone());
        }
    }
    ospf.keychains.insert(name.clone(), kc);
    Ok(json!({ "name": name }))
}

fn keychain_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_str(p, "id")?;
    let ospf = &mut s.store_mut().candidate_mut().routing.ospf;
    if !ospf.keychains.contains_key(id) {
        return Err(EngineError::bad("id", format!("no OSPF key chain {:?}", cut(id))));
    }
    let users: Vec<String> = ospf
        .templates
        .iter()
        .filter(|t| t.keychain.as_deref() == Some(id))
        .map(|t| t.id.to_string())
        .collect();
    if !users.is_empty() {
        return Err(EngineError::bad(
            "id",
            format!("key chain {id:?} is used by interface template(s) {}: change them first", users.join(", ")),
        ));
    }
    ospf.keychains.remove(id);
    Ok(json!({ "name": id }))
}

/// Unix seconds from a number or a UTC date (`2026-11-01`,
/// `2026-11-01 03:00`, `2026-11-01T03:00:00`).
pub(super) fn time_of(key: &str, v: &Value) -> Result<u64> {
    if let Value::Number(_) = v {
        return number(key, v, 0, u64::from(u32::MAX));
    }
    let t = text(key, v)?;
    if let Ok(n) = t.parse::<u64>() {
        return Ok(n);
    }
    parse_date(t).ok_or_else(|| {
        EngineError::bad(key, format!("{:?}: Unix seconds or a UTC date (2026-11-01 03:00)", cut(t)))
    })
}

/// `YYYY-MM-DD[( |T)HH:MM[:SS]]` as Unix seconds (UTC).
pub(super) fn parse_date(t: &str) -> Option<u64> {
    let (d, time) = match t.split_once([' ', 'T']) {
        Some((d, h)) => (d, h.trim_end_matches('Z')),
        None => (t, "00:00"),
    };
    let mut ds = d.split('-').map(|x| x.parse::<u64>().ok());
    let (y, m, day) = (ds.next()??, ds.next()??, ds.next()??);
    if ds.next().is_some() || !(1970..=2105).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&day) {
        return None;
    }
    let mut hs = time.split(':').map(|x| x.parse::<u64>().ok());
    let (h, mi) = (hs.next()??, hs.next()??);
    let sec = match hs.next() {
        Some(s) => s?,
        None => 0,
    };
    if h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    // H. Hinnant's days_from_civil.
    let (yy, mm) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = yy / 400;
    let yoe = yy - era * 400;
    let doy = (153 * mm + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let unix = days * 86_400 + h * 3600 + mi * 60 + sec;
    // A day past the month's end (2026-02-30) is refused.
    (corerouter_proto_ospf::frr::date(unix).contains(&format!(" {day:>2} {y}"))).then_some(unix)
}

fn window(p: &Value, key: &str, slot: &mut Option<u64>) -> Result<()> {
    match given(p, key) {
        Given::Absent => {}
        Given::Unset => *slot = None,
        Given::Value(v) => *slot = Some(time_of(key, v)?),
    }
    Ok(())
}

fn key_apply(s: &mut Session, p: &Value, add: bool) -> Result<Value> {
    let chain = req_str(p, "keychain")?.trim().to_owned();
    let id = match given(p, "id") {
        Given::Value(v) => u16::try_from(number("id", v, 0, 65_535)?).unwrap_or(0),
        _ => return Err(EngineError::bad("id", "is required (the key id on the wire)")),
    };
    let sealed = match given(p, "key_string") {
        Given::Value(v) => {
            let k = v.as_str().ok_or_else(|| EngineError::bad("key_string", "must be a string"))?;
            check_key("key_string", k, Some(AuthType::Sha256))?;
            let key = crate::sealing::key(s).map_err(EngineError::Internal)?;
            Some(key.seal(k).map_err(EngineError::Internal)?)
        }
        _ if add => return Err(EngineError::bad("key_string", "is required")),
        _ => None,
    };
    let ospf = &mut s.store_mut().candidate_mut().routing.ospf;
    let kc = ospf
        .keychains
        .get_mut(&chain)
        .ok_or_else(|| EngineError::bad("keychain", format!("no OSPF key chain {:?}", cut(&chain))))?;
    let pos = kc.keys.iter().position(|k| k.id == id);
    let mut k = match (pos, add) {
        (Some(_), true) => return Err(EngineError::bad("id", format!("key {id} already exists in {chain}"))),
        (None, false) => return Err(EngineError::bad("id", format!("no key {id} in {chain}"))),
        (Some(i), false) => kc.keys.get(i).cloned().ok_or_else(|| EngineError::bad("id", "gone"))?,
        (None, true) => OspfKey {
            id,
            algorithm: AuthType::DEFAULT,
            key_string: Default::default(),
            send_from: None,
            send_until: None,
            accept_from: None,
            accept_until: None,
        },
    };
    if let Some(b) = sealed {
        k.key_string = b;
    }
    if let Given::Value(v) = given(p, "algorithm") {
        let a = AuthType::parse(text("algorithm", v)?)
            .filter(|a| *a != AuthType::Simple)
            .ok_or_else(|| EngineError::bad("algorithm", "md5, sha1, sha256, sha384 or sha512"))?;
        k.algorithm = a;
    }
    window(p, "send_from", &mut k.send_from)?;
    window(p, "send_until", &mut k.send_until)?;
    window(p, "accept_from", &mut k.accept_from)?;
    window(p, "accept_until", &mut k.accept_until)?;
    match pos {
        Some(i) => {
            if let Some(slot) = kc.keys.get_mut(i) {
                *slot = k;
            }
        }
        None => {
            if kc.keys.len() >= MAX_KEYS {
                return Err(EngineError::bad("id", format!("at most {MAX_KEYS} keys per chain")));
            }
            kc.keys.push(k);
            kc.keys.sort_by_key(|k| k.id);
        }
    }
    Ok(json!({ "keychain": chain, "id": id }))
}

fn key_add(s: &mut Session, p: &Value) -> Result<Value> {
    key_apply(s, p, true)
}

fn key_set(s: &mut Session, p: &Value) -> Result<Value> {
    key_apply(s, p, false)
}

fn key_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let chain = req_str(p, "keychain")?.trim().to_owned();
    let id = match given(p, "id") {
        Given::Value(v) => u16::try_from(number("id", v, 0, 65_535)?).unwrap_or(0),
        _ => return Err(EngineError::bad("id", "is required")),
    };
    let kc = s
        .store_mut()
        .candidate_mut()
        .routing
        .ospf
        .keychains
        .get_mut(&chain)
        .ok_or_else(|| EngineError::bad("keychain", format!("no OSPF key chain {:?}", cut(&chain))))?;
    let before = kc.keys.len();
    kc.keys.retain(|k| k.id != id);
    if kc.keys.len() == before {
        return Err(EngineError::bad("id", format!("no key {id} in {chain}")));
    }
    Ok(json!({ "keychain": chain, "id": id }))
}

/// Within this many seconds a key's end is worth a warning.
const SOON: u64 = 7 * 86_400;

/// The rotation as seen at `now`: what is sent, where a neighbor drops.
pub(crate) fn rotation(keys: &[OspfKey], now: u64) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if keys.is_empty() {
        out.push(("error", "no key: authentication fails on every interface using this chain".to_owned()));
        return out;
    }
    let sending: Vec<u16> = keys.iter().filter(|k| k.sends_at(now)).map(|k| k.id).collect();
    if sending.is_empty() {
        out.push(("error", "no key is valid for sending now: the adjacencies using this chain drop".to_owned()));
    } else if sending.len() > 1 {
        out.push((
            "info",
            format!("keys {sending:?} are all valid for sending; FRR sends the first (the lowest id)"),
        ));
    }
    // The first future moment no key sends.
    let mut edges: Vec<u64> = keys
        .iter()
        .flat_map(|k| [k.send_from, k.send_until])
        .flatten()
        .filter(|t| *t > now)
        .collect();
    edges.sort_unstable();
    edges.dedup();
    if let Some(t) = edges.into_iter().find(|t| !keys.iter().any(|k| k.sends_at(*t))) {
        out.push(("warning", format!("from {} UTC no key is valid for sending: add the next key before then", date(t))));
    }
    // Each hand-over: the old key must still be accepted when the new one
    // starts being sent (the neighbors switch at their own clock), and the
    // new one accepted before it is sent.
    let mut by_start: Vec<&OspfKey> = keys.iter().filter(|k| k.send_from.is_some()).collect();
    by_start.sort_by_key(|k| k.send_from);
    for k in keys {
        if let (Some(sf), Some(af)) = (k.send_from, k.accept_from)
            && af > sf
        {
            out.push(("warning", format!("key {} is sent before it is accepted: accept it from {} or earlier", k.id, date(sf))));
        }
        if let Some(until) = k.send_until {
            let next = by_start.iter().find(|n| n.id != k.id && n.send_from.is_some_and(|f| f <= until && f > k.send_from.unwrap_or(0)));
            if let Some(n) = next
                && let Some(au) = k.accept_until
                && au <= n.send_from.unwrap_or(0)
            {
                out.push((
                    "warning",
                    format!(
                        "key {} stops being accepted when key {} starts being sent: a neighbor whose clock is behind drops; accept key {} for a while longer (RFC 8177 §3)",
                        k.id, n.id, k.id
                    ),
                ));
            }
            if until > now && until - now < SOON {
                out.push(("info", format!("key {} stops being sent on {} UTC", k.id, date(until))));
            }
        }
    }
    out
}

fn keychain_list(s: &mut Session, _: &Value) -> Result<Value> {
    // No clock (a lab without one): the windows are judged at the epoch.
    let now = s.hal_mut().now_unix().unwrap_or(0);
    let ospf = &s.store().candidate().routing.ospf;
    let rows = ospf
        .keychains
        .values()
        .map(|kc| {
            json!({
                "name": kc.name,
                "comment": kc.comment,
                "used_by": ospf.templates.iter().filter(|t| t.keychain.as_deref() == Some(kc.name.as_str())).map(|t| t.id.to_string()).collect::<Vec<_>>(),
                "keys": kc.keys.iter().map(|k| json!({
                    "id": k.id,
                    "algorithm": k.algorithm.name(),
                    "key_set": !k.key_string.is_empty(),
                    "send_from": k.send_from,
                    "send_until": k.send_until,
                    "accept_from": k.accept_from,
                    "accept_until": k.accept_until,
                    "sending": k.sends_at(now),
                    "accepting": k.accepts_at(now),
                })).collect::<Vec<_>>(),
                "sending": kc.keys.iter().filter(|k| k.sends_at(now)).map(|k| k.id).collect::<Vec<_>>(),
                "rotation": rotation(&kc.keys, now).into_iter().map(|(level, message)| json!({"level": level, "message": message})).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use corerouter_hal::VirtualHal;
    use corerouter_model::ospf::{AuthType, OspfKey};
    use serde_json::json;

    use super::{parse_date, rotation};
    use crate::Session;

    fn key(id: u16, send: (Option<u64>, Option<u64>), accept: (Option<u64>, Option<u64>)) -> OspfKey {
        OspfKey {
            id,
            algorithm: AuthType::Sha256,
            key_string: "x".into(),
            send_from: send.0,
            send_until: send.1,
            accept_from: accept.0,
            accept_until: accept.1,
        }
    }

    #[test]
    fn dates() {
        assert_eq!(parse_date("1970-01-01"), Some(0));
        assert_eq!(parse_date("2026-10-01 12:34:56"), Some(1_790_858_096));
        assert_eq!(parse_date("2000-02-29T00:00Z"), Some(951_782_400));
        assert_eq!(parse_date("2026-02-30"), None);
        assert_eq!(parse_date("2026-13-01"), None);
        assert_eq!(parse_date("x"), None);
    }

    #[test]
    fn a_good_rotation_has_no_warning() {
        // Key 1 sent until 1000 and accepted until 1100; key 2 accepted from
        // 900 and sent from 1000.
        let keys = [key(1, (None, Some(1000)), (None, Some(1100))), key(2, (Some(1000), None), (Some(900), None))];
        let r = rotation(&keys, 500);
        assert!(r.iter().all(|(l, _)| *l == "info"), "{r:?}");
    }

    #[test]
    fn gaps_and_early_expiry_are_flagged() {
        let keys = [key(1, (None, Some(1000)), (None, Some(1000))), key(2, (Some(1000), None), (Some(1000), None))];
        let r = rotation(&keys, 500);
        assert!(r.iter().any(|(_, m)| m.contains("clock is behind")), "{r:?}");
        let keys = [key(1, (None, Some(1000)), (None, None))];
        let r = rotation(&keys, 500);
        assert!(r.iter().any(|(_, m)| m.contains("no key is valid for sending")), "{r:?}");
        let r = rotation(&keys, 2000);
        assert_eq!(r[0].0, "error");
    }

    #[test]
    fn keys_are_sealed_and_chains_rename() {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        s.execute("routing.ospf.keychain.add", &json!({"name": "core"})).unwrap();
        s.execute("routing.ospf.keychain.key.add", &json!({"keychain": "core", "id": 1, "key_string": "Sup3rS3cret", "send_until": "2035-01-01"}))
            .unwrap();
        let e = s
            .execute("routing.ospf.keychain.key.add", &json!({"keychain": "core", "id": 1, "key_string": "x"}))
            .unwrap_err();
        assert!(e.to_string().contains("already exists"), "{e}");
        let l = s.execute("routing.ospf.keychain.list", &json!({})).unwrap();
        assert_eq!(l[0]["keys"][0]["algorithm"], "sha256");
        assert_eq!(l[0]["keys"][0]["key_set"], true);
        assert!(!serde_json::to_string(&l).unwrap().contains("Sup3rS3cret"));
        assert!(!serde_json::to_string(s.store().running()).unwrap().contains("Sup3rS3cret"));
        assert!(!serde_json::to_string(&s.journal()).unwrap().contains("Sup3rS3cret"));
        s.execute("routing.ospf.keychain.set", &json!({"id": "core", "name": "core2"})).unwrap();
        s.execute("routing.ospf.keychain.key.remove", &json!({"keychain": "core2", "id": 1})).unwrap();
        s.execute("routing.ospf.keychain.remove", &json!({"id": "core2"})).unwrap();
    }
}
