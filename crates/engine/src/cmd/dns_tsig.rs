//! /ip dns tsig-key (G4.1c-3): TSIG keys (RFC 8945) for RFC 2136 UPDATE.
//! The secret never shows in `print` (unless asked for with `show_secret`,
//! to copy it to the DHCP server) nor in `/export`.

use corerouter_model::ItemId;
use corerouter_model::dns_tsig::{TsigAlgorithm, TsigKey, base64_encode};
use corerouter_model::dns_zone::normalize_host;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

/// RFC 8945 §6: as long as the hash (`tsig-keygen` makes 32 bytes).
const GENERATED_BYTES: usize = 32;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.dns.tsig-key.add",
        "Add TSIG Key",
        ["IP", "DNS"],
        None,
        "{name: name (as the DHCP server knows it: dhcp-ddns), algorithm?: hmac-sha256 | hmac-sha384 | hmac-sha512 (default hmac-sha256), secret?: base64 (absent: a random 32-byte one), comment?: string} → {id, name, secret}",
        always,
        add
    ),
    cmd!(
        "ip.dns.tsig-key.set",
        "Set TSIG Key",
        [],
        None,
        "{id: *hex | name, algorithm?: hmac-sha256 | hmac-sha384 | hmac-sha512, secret?: base64, comment?: string} → {id, name}",
        has_keys,
        set
    ),
    cmd!(
        "ip.dns.tsig-key.remove",
        "Remove TSIG Key",
        [],
        None,
        "{id: *hex | name} → {id, name}",
        has_keys,
        remove
    ),
    cmd!(query "ip.dns.tsig-key.print", "DNS TSIG Keys", ["IP", "DNS"], None,
        "{show_secret?: bool} → [{id, name, algorithm, secret? (only with show_secret), comment?, zones (that let it update)}]",
        always, print),
];

fn has_keys(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.dns_tsig.keys.is_empty() {
        Err("there are no TSIG keys".into())
    } else {
        Ok(())
    }
}

fn index(s: &Session, p: &Value) -> Result<usize> {
    let raw = opt_str(p, "id")?.ok_or_else(|| EngineError::bad("id", "is required"))?;
    let keys = &s.store().candidate().ip.dns_tsig.keys;
    let found = match raw.trim().parse::<ItemId>() {
        Ok(id) if raw.trim().starts_with('*') => keys.iter().position(|k| k.id == id),
        _ => {
            let n = normalize_host(raw);
            keys.iter().position(|k| k.name == n)
        }
    };
    found.ok_or_else(|| EngineError::bad("id", "no such TSIG key"))
}

fn random_secret() -> Result<String> {
    let mut b = [0u8; GENERATED_BYTES];
    crate::auth::random_bytes(&mut b).map_err(|e| EngineError::bad("secret", e))?;
    Ok(base64_encode(&b))
}

fn apply(k: &mut TsigKey, p: &Value) -> Result<()> {
    if let Some(a) = opt_parse::<TsigAlgorithm>(p, "algorithm")? {
        k.algorithm = a;
    }
    if let Some(sec) = opt_str(p, "secret")? {
        k.secret = sec.trim().to_owned();
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        k.comment = c;
    }
    if let Some(why) = k.problem() {
        let key = if why.starts_with("name") { "name" } else { "secret" };
        return Err(EngineError::bad(key, why));
    }
    Ok(())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = normalize_host(opt_str(p, "name")?.unwrap_or_default());
    if name.is_empty() {
        return Err(EngineError::bad("name", "is required"));
    }
    let t = &s.store().candidate().ip.dns_tsig;
    if t.get(&name).is_some() {
        return Err(EngineError::bad("name", format!("TSIG key {name} already exists")));
    }
    if t.keys.len() >= corerouter_model::dns_tsig::MAX_KEYS {
        return Err(EngineError::bad("name", "too many TSIG keys"));
    }
    let secret = match opt_str(p, "secret")? {
        Some(s) => s.trim().to_owned(),
        None => random_secret()?,
    };
    let mut k = TsigKey {
        id: ItemId(0),
        name: name.clone(),
        algorithm: TsigAlgorithm::default(),
        secret,
        comment: String::new(),
    };
    let mut q = p.clone();
    if let Some(o) = q.as_object_mut() {
        o.remove("secret");
    }
    apply(&mut k, &q)?;
    let t = &mut s.store_mut().candidate_mut().ip.dns_tsig;
    k.id = t.next_id();
    let (id, secret) = (k.id, k.secret.clone());
    t.keys.push(k);
    Ok(json!({"id": id, "name": name, "secret": secret}))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    if p.get("name").is_some() {
        return Err(EngineError::bad(
            "name",
            "a TSIG key cannot be renamed: the DHCP server knows it by name (add a new one)",
        ));
    }
    let i = index(s, p)?;
    let Some(mut k) = s.store().candidate().ip.dns_tsig.keys.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such TSIG key"));
    };
    apply(&mut k, p)?;
    let (id, name) = (k.id, k.name.clone());
    if let Some(slot) = s.store_mut().candidate_mut().ip.dns_tsig.keys.get_mut(i) {
        *slot = k;
    }
    Ok(json!({"id": id, "name": name}))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let Some(k) = s.store().candidate().ip.dns_tsig.keys.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such TSIG key"));
    };
    let used: Vec<String> = s
        .store()
        .candidate()
        .ip
        .dns_zones
        .zones
        .iter()
        .filter(|z| z.update_keys.contains(&k.name))
        .map(|z| z.name.clone())
        .collect();
    if !used.is_empty() {
        return Err(EngineError::bad(
            "id",
            format!("zones {} still use it (update_keys)", used.join(", ")),
        ));
    }
    s.store_mut().candidate_mut().ip.dns_tsig.keys.remove(i);
    Ok(json!({"id": k.id, "name": k.name}))
}

fn print(s: &mut Session, p: &Value) -> Result<Value> {
    let show = opt_bool(p, "show_secret")?.unwrap_or(false);
    let cand = s.store().candidate();
    let rows: Vec<Value> = cand
        .ip
        .dns_tsig
        .keys
        .iter()
        .map(|k| {
            let zones: Vec<&str> = cand
                .ip
                .dns_zones
                .zones
                .iter()
                .filter(|z| z.update_keys.contains(&k.name))
                .map(|z| z.name.as_str())
                .collect();
            let mut v = json!({"id": k.id, "name": k.name, "algorithm": k.algorithm.as_str(), "zones": zones});
            if let Some(o) = v.as_object_mut() {
                if show {
                    o.insert("secret".into(), json!(k.secret));
                }
                if !k.comment.is_empty() {
                    o.insert("comment".into(), json!(k.comment));
                }
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_by_command() {
        let mut s = Session::virtual_lab();
        let k = s
            .execute("ip.dns.tsig-key.add", &json!({"name": "DHCP-DDNS."}))
            .unwrap();
        assert_eq!(k["name"], "dhcp-ddns");
        assert_eq!(
            corerouter_model::dns_tsig::base64_decode(k["secret"].as_str().unwrap())
                .unwrap()
                .len(),
            32
        );
        let rows = s.execute("ip.dns.tsig-key.print", &json!({})).unwrap();
        assert!(rows[0].get("secret").is_none(), "hidden by default");
        let rows = s
            .execute("ip.dns.tsig-key.print", &json!({"show_secret": true}))
            .unwrap();
        assert_eq!(rows[0]["secret"], k["secret"]);
        // Zones refer to it; then it cannot go.
        s.execute(
            "ip.dns.zone.add",
            &json!({"name": "lan.example", "update_keys": "dhcp-ddns"}),
        )
        .unwrap();
        assert!(s.execute("ip.dns.tsig-key.remove", &json!({"id": "dhcp-ddns"})).is_err());
        s.execute("ip.dns.zone.set", &json!({"id": "lan.example", "update_keys": ""}))
            .unwrap();
        s.execute("ip.dns.tsig-key.remove", &json!({"id": "dhcp-ddns"}))
            .unwrap();
    }

    #[test]
    fn bad_keys_are_refused() {
        let mut s = Session::virtual_lab();
        for p in [
            json!({"name": "bad name"}),
            json!({"name": "k", "secret": "c2hvcnQ="}),
            json!({"name": "k", "secret": "!!!"}),
            json!({"name": "k", "algorithm": "hmac-md5"}),
        ] {
            assert!(s.execute("ip.dns.tsig-key.add", &p).is_err(), "{p}");
        }
        assert!(s.store().candidate().ip.dns_tsig.keys.is_empty());
    }
}
