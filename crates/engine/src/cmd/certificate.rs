//! `/certificate` (G1.6zs): the certificates the router serves TLS with.
//!
//! - `add` makes a self-signed certificate at once (RouterOS splits it in
//!   `add`, a template, and `sign`): ECDSA P-256 by default, the router's
//!   identity as CN and, unless told otherwise, the identity and every
//!   address of the router in subjectAltName (clients check the SAN, never
//!   the CN: RFC 8310 §8.1, RFC 9462 §4.2), valid for 825 days from the day
//!   before (Apple refuses TLS server certificates valid for longer;
//!   RouterOS defaults to 365).
//! - `import` takes the operator's PEM (certificate, then its chain) and its
//!   key, checked against each other the way the TLS servers load them.
//! - The key is sealed at rest (`corerouter_model::sealed`); `export` gives
//!   it back only to group `full` (RouterOS's `sensitive` policy).
//! - A service names one (`ip.service.www-ssl.set certificate=<name>`); a
//!   certificate in use cannot be removed, and a rename follows into the
//!   services.
//!
//! Nothing changes by itself when an address changes: clients that pinned a
//! certificate (the CLI's and GUI's `known_hosts`) would be asked again.

use corerouter_model::ItemId;
use corerouter_model::certificate::{self as model, Certificate, Certificates, MAX_CERTIFICATES, Origin};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text, opt_u32};
use super::{CommandSpec, always};
use crate::x509::{self, Info, NewCert};
use crate::{EngineError, Result, Session};

/// Apple's limit for a TLS server certificate (support.apple.com/103769).
pub(crate) const DEFAULT_DAYS: u32 = 825;
const MAX_DAYS: u32 = 3650;
/// A certificate this close to its end is flagged `expiring`.
const EXPIRING_DAYS: i64 = 30;
const KEY_TYPES: [&str; 2] = ["ecdsa-p256", "ecdsa-p384"];

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "certificate.add",
        "Add Certificate",
        ["System", "Certificates"],
        None,
        "{name: name, common_name?: string (default: the identity), subject_alt_name?: string (DNS:… and IP:…, comma-separated; default: the identity and every address of the router), key_type?: ecdsa-p256 | ecdsa-p384 (default ecdsa-p256), days_valid?: int 1..3650 (default 825), comment?: string} → {id, name, fingerprint, not_after}",
        always,
        add
    ),
    cmd!(
        "certificate.import",
        "Import Certificate",
        ["System", "Certificates"],
        None,
        "{name: name, certificate: string (PEM: the certificate, then its chain), private_key?: string (PEM, not encrypted), comment?: string} → {id, name, fingerprint, not_after, warnings: [string]}",
        always,
        import
    ),
    cmd!(
        "certificate.set",
        "Set Certificate",
        [],
        None,
        "{id: *hex | name, name?: name (the services that use it follow), comment?: string} → {id, name}",
        has_any,
        set
    ),
    cmd!(
        "certificate.remove",
        "Remove Certificate",
        [],
        None,
        "{id: *hex | name} → {id, name}",
        has_any,
        remove
    ),
    cmd!(query "certificate.print", "Certificates", ["System", "Certificates"], None,
        "{} → [{id, name, common_name, issuer, subject_alt_names: [string], self_signed, ca, key_type, private_key: bool, not_before, not_after, days_left?, state: valid | expiring | expired | not-yet-valid | invalid, fingerprint, spki_pin, serial, chain, origin: generated | imported, used_by: [string], warnings: [string], comment?}]",
        always, print),
    cmd!(query "certificate.export", "Export Certificate", [], None,
        "{id: *hex | name, private_key?: bool (group full only)} → {name, certificate, private_key?}",
        has_any, export),
    cmd!(query "certificate.check", "Check Certificate", [], None,
        "{id?: *hex | name (editing), name?: string, common_name?: string, subject_alt_name?: string, key_type?: string, days_valid?: string, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param?}], commands: [{command, params}]}",
        always, check),
    cmd!(query "certificate.check-import", "Check Certificate Import", [], None,
        "{name?: string, certificate?: string, private_key?: string, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param?}], commands: [{command, params}]}",
        always, check_import),
];

fn has_any(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().system.certificates.list.is_empty() {
        Err("there are no certificates".into())
    } else {
        Ok(())
    }
}

fn store(s: &Session) -> &Certificates {
    &s.store().candidate().system.certificates
}

fn index(s: &Session, p: &Value) -> Result<usize> {
    let raw = opt_str(p, "id")?.ok_or_else(|| EngineError::bad("id", "is required"))?.trim();
    let list = &store(s).list;
    let found = match raw.parse::<ItemId>() {
        Ok(id) if raw.starts_with('*') => list.iter().position(|c| c.id == id),
        _ => list.iter().position(|c| c.name == raw),
    };
    found.ok_or_else(|| {
        let hint = crate::error::suggest(raw, list.iter().map(|c| c.name.as_str()))
            .map(|n| format!(" (did you mean {n}?)"))
            .unwrap_or_default();
        EngineError::bad("id", format!("no such certificate{hint}"))
    })
}

/// A new name: well formed and free (`except` is the item being renamed).
fn new_name(s: &Session, name: &str, except: Option<ItemId>) -> Result<String> {
    let name = name.trim();
    if !model::name_ok(name) {
        let shown: String = name.chars().take(64).collect();
        return Err(EngineError::bad("name", format!("'{shown}': letters, digits, - _ . only, at most 63")));
    }
    if store(s).list.iter().any(|c| c.name == name && Some(c.id) != except) {
        return Err(EngineError::bad("name", format!("certificate {name} already exists")));
    }
    Ok(name.to_owned())
}

/// The services that serve with `name`.
pub(crate) fn used_by(cfg: &corerouter_model::Config, name: &str) -> Vec<&'static str> {
    let mut out = Vec::new();
    if cfg.system.web.www_ssl.certificate == name {
        out.push("www-ssl");
    }
    out
}

/// The identity as a DNS name, when it can be one (`Core Router` →
/// `core-router`).
fn identity_host(s: &Session) -> Option<String> {
    let h: String = s
        .store()
        .candidate()
        .system
        .identity
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '-' })
        .collect();
    let h = h.trim_matches(|c| c == '-' || c == '.').to_owned();
    corerouter_model::dns_static::host_name_ok(&h).then_some(h)
}

/// What `add` puts in subjectAltName without `subject_alt_name`: the
/// identity and the router's own addresses (not the disabled ones).
fn default_sans(s: &Session) -> Vec<String> {
    let mut out: Vec<String> = identity_host(s).into_iter().map(|h| format!("DNS:{h}")).collect();
    for a in s.store().candidate().ip.addresses.iter().filter(|a| !a.disabled && a.from_pool.is_none()) {
        let ip = format!("IP:{}", a.address.addr());
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// `DNS:x, IP:y` as typed (a bare name or address takes its prefix).
fn parse_sans(text: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for raw in text.split([',', ' ', '\n']).map(str::trim).filter(|t| !t.is_empty()) {
        let shown: String = raw.chars().take(64).collect();
        let (kind, value) = match raw.split_once(':') {
            Some((k, v)) if k.eq_ignore_ascii_case("dns") => ("DNS", v.trim()),
            Some((k, v)) if k.eq_ignore_ascii_case("ip") => ("IP", v.trim()),
            _ if raw.parse::<std::net::IpAddr>().is_ok() => ("IP", raw),
            _ => ("DNS", raw),
        };
        let entry = if kind == "IP" {
            let ip: std::net::IpAddr = value
                .parse()
                .map_err(|_| EngineError::bad("subject_alt_name", format!("'{shown}' is not an address")))?;
            format!("IP:{ip}")
        } else {
            let host = value.trim_end_matches('.').to_ascii_lowercase();
            let bare = host.strip_prefix("*.").unwrap_or(&host);
            if !corerouter_model::dns_static::host_name_ok(bare) {
                return Err(EngineError::bad("subject_alt_name", format!("'{shown}' is not a DNS name")));
            }
            format!("DNS:{host}")
        };
        if !out.contains(&entry) {
            out.push(entry);
        }
    }
    if out.len() > 100 {
        return Err(EngineError::bad("subject_alt_name", "at most 100 names"));
    }
    Ok(out)
}

/// The certificate `add` would make, from the parameters.
fn new_cert(s: &Session, p: &Value) -> Result<NewCert> {
    let common_name = match opt_text(p, "common_name", 64)? {
        Some(cn) if !cn.trim().is_empty() => cn.trim().to_owned(),
        _ => s.store().candidate().system.identity.chars().take(64).collect(),
    };
    let subject_alt_names = match opt_str(p, "subject_alt_name")? {
        Some(t) if !t.trim().is_empty() => parse_sans(t)?,
        _ => default_sans(s),
    };
    if subject_alt_names.is_empty() {
        return Err(EngineError::bad(
            "subject_alt_name",
            "no names: the identity is not a DNS name and the router has no address; give one (DNS:router.lan)",
        ));
    }
    let key_type = opt_str(p, "key_type")?.map(str::trim).filter(|k| !k.is_empty()).unwrap_or("ecdsa-p256");
    if !KEY_TYPES.contains(&key_type) {
        return Err(EngineError::bad(
            "key_type",
            "ecdsa-p256 or ecdsa-p384 (RSA keys cannot be made here; import one instead)",
        ));
    }
    let days_valid = opt_days(p)?.unwrap_or(DEFAULT_DAYS);
    Ok(NewCert {
        common_name,
        subject_alt_names,
        key_type: key_type.to_owned(),
        days_valid,
        now: s.now().unwrap_or(0),
    })
}

/// `days_valid` as a number or a numeric string (the modal's field).
fn opt_days(p: &Value) -> Result<Option<u32>> {
    let v = match p.get("days_valid") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(t)) if t.trim().is_empty() => return Ok(None),
        Some(Value::String(t)) => t
            .trim()
            .parse::<u32>()
            .map_err(|_| EngineError::bad("days_valid", "a number of days, 1..3650"))?,
        Some(_) => opt_u32(p, "days_valid")?.unwrap_or(DEFAULT_DAYS),
    };
    if !(1..=MAX_DAYS).contains(&v) {
        return Err(EngineError::bad("days_valid", format!("1..{MAX_DAYS} days")));
    }
    Ok(Some(v))
}

fn seal(s: &mut Session, key_pem: &str) -> Result<corerouter_model::sealed::Sealed> {
    let k = crate::sealing::key(s).map_err(EngineError::Internal)?;
    k.seal(key_pem).map_err(EngineError::Internal)
}

fn push(s: &mut Session, mut c: Certificate) -> Result<ItemId> {
    if store(s).list.len() >= MAX_CERTIFICATES {
        return Err(EngineError::bad("name", format!("at most {MAX_CERTIFICATES} certificates")));
    }
    let st = &mut s.store_mut().candidate_mut().system.certificates;
    c.id = st.next_id();
    let id = c.id;
    st.list.push(c);
    Ok(id)
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = new_name(s, opt_str(p, "name")?.unwrap_or_default(), None)?;
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let n = new_cert(s, p)?;
    if n.now == 0 {
        return Err(EngineError::bad("days_valid", "the router has no clock yet: a certificate needs today's date"));
    }
    let (cert, key) = x509::generate(&n).map_err(|e| EngineError::bad("key_type", e))?;
    let info = x509::inspect(&cert).map_err(EngineError::Internal)?;
    let private_key = seal(s, &key)?;
    let id = push(s, Certificate { id: ItemId(0), name: name.clone(), certificate: cert, private_key, origin: Origin::Generated, comment })?;
    Ok(json!({"id": id, "name": name, "fingerprint": info.fingerprint, "not_after": info.not_after}))
}

/// The certificate and key text of an import, checked.
fn imported(p: &Value) -> Result<(String, Info, Option<String>)> {
    let cert = opt_str(p, "certificate")?
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| EngineError::bad("certificate", "is required (PEM: -----BEGIN CERTIFICATE-----…)"))?;
    let info = x509::inspect(cert).map_err(|e| EngineError::bad("certificate", e))?;
    let key = opt_str(p, "private_key")?.map(str::trim).filter(|t| !t.is_empty());
    if let Some(k) = key {
        x509::check_pair(cert, k).map_err(|e| {
            let param = if e.starts_with("certificate") { "certificate" } else { "private_key" };
            EngineError::bad(param, e)
        })?;
    }
    Ok((format!("{cert}\n"), info, key.map(|k| format!("{k}\n"))))
}

fn import(s: &mut Session, p: &Value) -> Result<Value> {
    let name = new_name(s, opt_str(p, "name")?.unwrap_or_default(), None)?;
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let (cert, info, key) = imported(p)?;
    let private_key = match &key {
        Some(k) => seal(s, k)?,
        None => Default::default(),
    };
    let warnings = warnings(&info, key.is_some(), s.now());
    let id = push(s, Certificate { id: ItemId(0), name: name.clone(), certificate: cert, private_key, origin: Origin::Imported, comment })?;
    Ok(json!({"id": id, "name": name, "fingerprint": info.fingerprint, "not_after": info.not_after, "warnings": warnings}))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let Some(mut c) = store(s).list.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such certificate"));
    };
    let old = c.name.clone();
    if let Some(n) = opt_str(p, "name")? {
        c.name = new_name(s, n, Some(c.id))?;
    }
    if let Some(t) = opt_text(p, "comment", 256)? {
        c.comment = t;
    }
    let (id, name) = (c.id, c.name.clone());
    let cfg = s.store_mut().candidate_mut();
    if let Some(slot) = cfg.system.certificates.list.get_mut(i) {
        *slot = c;
    }
    if name != old && cfg.system.web.www_ssl.certificate == old {
        cfg.system.web.www_ssl.certificate.clone_from(&name);
    }
    Ok(json!({"id": id, "name": name}))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let Some(c) = store(s).list.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such certificate"));
    };
    let used = used_by(s.store().candidate(), &c.name);
    if !used.is_empty() {
        return Err(EngineError::bad(
            "id",
            format!("{} still serve(s) with it: pick another certificate there first", used.join(", ")),
        ));
    }
    s.store_mut().candidate_mut().system.certificates.list.remove(i);
    Ok(json!({"id": c.id, "name": c.name}))
}

/// `valid`, `expiring`, `expired`, `not-yet-valid` at `now`; days left.
fn state(info: &Info, now: Option<u64>) -> (&'static str, Option<i64>) {
    let Some(now) = now.and_then(|n| i64::try_from(n).ok()) else {
        return ("valid", None);
    };
    let left = (info.not_after - now).div_euclid(86_400);
    if now < info.not_before {
        ("not-yet-valid", Some(left))
    } else if now > info.not_after {
        ("expired", Some(left))
    } else if left < EXPIRING_DAYS {
        ("expiring", Some(left))
    } else {
        ("valid", Some(left))
    }
}

/// What the operator should know before serving with it.
fn warnings(info: &Info, has_key: bool, now: Option<u64>) -> Vec<String> {
    let mut w = Vec::new();
    match state(info, now) {
        ("expired", _) => w.push("expired: clients that check certificates refuse it".to_owned()),
        ("not-yet-valid", _) => w.push("not valid yet (is the router's clock right?)".to_owned()),
        ("expiring", Some(d)) => w.push(format!("expires in {d} days")),
        _ => {}
    }
    if !has_key {
        w.push("no private key: no service can serve with it".to_owned());
    }
    if info.self_signed {
        w.push(
            "self-signed: browsers, iOS, macOS and Windows do not trust it unless told to; Android's automatic DNS over TLS does not check it"
                .to_owned(),
        );
    }
    if info.subject_alt_names.is_empty() {
        w.push("no subjectAltName: clients ignore the CN, so no name matches (RFC 6125)".to_owned());
    }
    if info.ca {
        w.push("a CA certificate: serve with a server certificate it signed instead".to_owned());
    }
    if let Some(bits) = info.key_type.strip_prefix("rsa-").and_then(|b| b.parse::<u32>().ok())
        && bits < 2048
    {
        w.push(format!("RSA {bits} bits: under the 2048 of RFC 9325 §4.5"));
    }
    if info.not_after - info.not_before > i64::from(DEFAULT_DAYS + 1) * 86_400 {
        w.push(format!("valid for more than {DEFAULT_DAYS} days: Apple devices refuse it as a TLS server certificate"));
    }
    w
}

fn row(c: &Certificate, cfg: &corerouter_model::Config, now: Option<u64>) -> Value {
    let mut v = match x509::inspect(&c.certificate) {
        Ok(i) => {
            let (st, left) = state(&i, now);
            json!({
                "common_name": i.common_name, "issuer": i.issuer, "subject_alt_names": i.subject_alt_names,
                "self_signed": i.self_signed, "ca": i.ca, "key_type": i.key_type,
                "not_before": i.not_before, "not_after": i.not_after, "days_left": left, "state": st,
                "fingerprint": i.fingerprint, "spki_pin": i.spki_pin, "serial": i.serial, "chain": i.chain,
                "warnings": warnings(&i, !c.private_key.is_empty(), now),
            })
        }
        Err(e) => json!({"state": "invalid", "warnings": [e]}),
    };
    if let Some(o) = v.as_object_mut() {
        o.insert("id".into(), json!(c.id));
        o.insert("name".into(), json!(c.name));
        o.insert("private_key".into(), json!(!c.private_key.is_empty()));
        o.insert("origin".into(), json!(c.origin.as_str()));
        o.insert("used_by".into(), json!(used_by(cfg, &c.name)));
        if !c.comment.is_empty() {
            o.insert("comment".into(), json!(c.comment));
        }
    }
    v
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let now = s.now();
    let cfg = s.store().candidate();
    Ok(Value::Array(cfg.system.certificates.list.iter().map(|c| row(c, cfg, now)).collect()))
}

fn export(s: &mut Session, p: &Value) -> Result<Value> {
    let with_key = opt_bool(p, "private_key")?.unwrap_or(false);
    if with_key {
        s.permit(crate::auth::Group::Full).map_err(|reason| EngineError::Denied {
            id: "certificate.export".into(),
            reason: format!("private_key: {reason}"),
        })?;
    }
    let i = index(s, p)?;
    let Some(c) = store(s).list.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such certificate"));
    };
    let mut out = json!({"name": c.name, "certificate": c.certificate});
    if with_key {
        let k = crate::sealing::key(s).map_err(EngineError::Internal)?;
        let key = k.open(&c.private_key).ok_or_else(|| EngineError::bad("private_key", "this certificate has no private key"))?;
        if let Some(o) = out.as_object_mut() {
            o.insert("private_key".into(), json!(key));
        }
    }
    Ok(out)
}

/// Checks that a service may name `name` (empty or `none`: the router's
/// own): it exists and has its key. The name as stored.
pub(crate) fn pick(certs: &Certificates, name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() || name == "none" {
        return Ok(String::new());
    }
    let Some(c) = certs.get(name) else {
        let hint = crate::error::suggest(name, certs.list.iter().map(|c| c.name.as_str()))
            .map(|n| format!(" (did you mean {n}?)"))
            .unwrap_or_default();
        return Err(EngineError::bad("certificate", format!("no certificate {name} in /certificate{hint}")));
    };
    if c.private_key.is_empty() {
        return Err(EngineError::bad("certificate", format!("{name} has no private key: a server cannot use it")));
    }
    Ok(name.to_owned())
}

fn check_row(level: &str, check: &str, message: impl Into<String>, param: Option<&str>) -> Value {
    let mut c = json!({"level": level, "check": check, "message": message.into()});
    if let (Some(p), Some(o)) = (param, c.as_object_mut()) {
        o.insert("param".into(), json!(p));
    }
    c
}

fn error_check(e: &EngineError) -> Value {
    match e {
        EngineError::BadParam { param, reason } => check_row("error", param, reason.clone(), Some(param)),
        other => check_row("error", "error", other.to_string(), None),
    }
}

fn day(t: i64) -> String {
    let (y, m, d) = x509::civil_day(t);
    format!("{y:04}-{m:02}-{d:02}")
}

/// The preview of the Add modal (and of editing: name and comment).
fn check(s: &mut Session, p: &Value) -> Result<Value> {
    let mut computed = Vec::new();
    let mut checks = Vec::new();
    let mut commands = Vec::new();
    let text = |k: &str| p.get(k).and_then(Value::as_str).map(str::trim).unwrap_or("").to_owned();
    if p.get("id").is_some_and(|v| !v.is_null() && v != "") {
        let i = match index(s, p) {
            Ok(i) => i,
            Err(e) => return Ok(json!({"computed": [], "checks": [error_check(&e)], "commands": []})),
        };
        let c = store(s).list.get(i).cloned();
        if let Some(c) = c {
            let mut params = serde_json::Map::new();
            let name = text("name");
            if !name.is_empty() && name != c.name {
                match new_name(s, &name, Some(c.id)) {
                    Ok(n) => {
                        params.insert("name".into(), json!(n));
                        for svc in used_by(s.store().candidate(), &c.name) {
                            checks.push(check_row("info", "used_by", format!("{svc} follows the new name"), Some("name")));
                        }
                    }
                    Err(e) => checks.push(error_check(&e)),
                }
            }
            if text("comment") != c.comment {
                params.insert("comment".into(), json!(text("comment")));
            }
            if !params.is_empty() {
                params.insert("id".into(), json!(c.name));
                commands.push(json!({"command": "certificate.set", "params": params}));
            }
        }
        return Ok(json!({"computed": computed, "checks": checks, "commands": commands}));
    }
    let name = text("name");
    if name.is_empty() {
        checks.push(check_row("error", "name", "a name is required (dns-lan, router)", Some("name")));
    } else if let Err(e) = new_name(s, &name, None) {
        checks.push(error_check(&e));
    }
    match new_cert(s, p) {
        Ok(n) => {
            computed.push(json!({"label": "Common Name", "value": n.common_name}));
            computed.push(json!({"label": "Subject Alt Names", "value": n.subject_alt_names.join(", ")}));
            let until = i64::try_from(n.now).unwrap_or(0) + i64::from(n.days_valid) * 86_400;
            if n.now > 0 {
                computed.push(json!({"label": "Valid Until", "value": day(until)}));
            } else {
                checks.push(check_row("error", "days_valid", "the router has no clock yet: a certificate needs today's date", Some("days_valid")));
            }
            computed.push(json!({"label": "Key", "value": n.key_type}));
            checks.push(check_row(
                "info",
                "self_signed",
                "self-signed: browsers, iOS, macOS and Windows warn unless told to trust it; Android's automatic DNS over TLS takes it",
                None,
            ));
            if n.days_valid > DEFAULT_DAYS {
                checks.push(check_row(
                    "warning",
                    "days_valid",
                    format!("over {DEFAULT_DAYS} days: Apple devices refuse it as a TLS server certificate"),
                    Some("days_valid"),
                ));
            }
            if text("subject_alt_name").is_empty() {
                checks.push(check_row(
                    "info",
                    "subject_alt_name",
                    "the identity and the router's addresses; it is not remade when they change",
                    Some("subject_alt_name"),
                ));
            }
        }
        Err(e) => checks.push(error_check(&e)),
    }
    if !checks.iter().any(|c| c["level"] == "error") {
        let mut params = serde_json::Map::new();
        for k in ["name", "common_name", "subject_alt_name", "key_type", "days_valid", "comment"] {
            let t = text(k);
            if !t.is_empty() {
                let v = if k == "days_valid" { json!(t.parse::<u32>().unwrap_or(DEFAULT_DAYS)) } else { json!(t) };
                params.insert(k.into(), v);
            }
        }
        commands.push(json!({"command": "certificate.add", "params": params}));
    }
    Ok(json!({"computed": computed, "checks": checks, "commands": commands}))
}

/// The preview of the Import modal: what the PEM says, the key against it.
fn check_import(s: &mut Session, p: &Value) -> Result<Value> {
    let mut computed = Vec::new();
    let mut checks = Vec::new();
    let mut commands = Vec::new();
    let text = |k: &str| p.get(k).and_then(Value::as_str).map(str::trim).unwrap_or("").to_owned();
    let name = text("name");
    if name.is_empty() {
        checks.push(check_row("error", "name", "a name is required", Some("name")));
    } else if let Err(e) = new_name(s, &name, None) {
        checks.push(error_check(&e));
    }
    match imported(p) {
        Ok((_, info, key)) => {
            computed.push(json!({"label": "Common Name", "value": info.common_name}));
            computed.push(json!({"label": "Issuer", "value": info.issuer}));
            computed.push(json!({"label": "Subject Alt Names", "value": info.subject_alt_names.join(", ")}));
            computed.push(json!({"label": "Valid Until", "value": day(info.not_after)}));
            computed.push(json!({"label": "Key", "value": info.key_type}));
            computed.push(json!({"label": "Chain", "value": info.chain.to_string()}));
            if key.is_some() {
                checks.push(check_row("ok", "private_key", "the key belongs to this certificate", Some("private_key")));
            }
            for w in warnings(&info, key.is_some(), s.now()) {
                checks.push(check_row("warning", "certificate", w, Some("certificate")));
            }
        }
        Err(e) => checks.push(error_check(&e)),
    }
    if !checks.iter().any(|c| c["level"] == "error") {
        let mut params = serde_json::Map::new();
        for k in ["name", "certificate", "private_key", "comment"] {
            let t = text(k);
            if !t.is_empty() {
                params.insert(k.into(), json!(t));
            }
        }
        commands.push(json!({"command": "certificate.import", "params": params}));
    }
    Ok(json!({"computed": computed, "checks": checks, "commands": commands}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.tick(1_794_441_600); // 2026-11-12, the daemon's clock
        s.execute("system.identity.set", &json!({"name": "Router Lab"})).unwrap();
        s.execute("ip.address.add", &json!({"address": "192.168.88.1/24", "interface": "ether2"})).unwrap();
        s
    }

    #[test]
    fn add_makes_a_self_signed_certificate_with_the_routers_names() {
        let mut s = lab();
        let r = s.execute("certificate.add", &json!({"name": "dns-lan"})).unwrap();
        assert_eq!(r["name"], "dns-lan");
        let rows = s.execute("certificate.print", &json!({})).unwrap();
        let c = &rows[0];
        assert_eq!(c["common_name"], "Router Lab");
        assert_eq!(c["subject_alt_names"], json!(["DNS:router-lab", "IP:192.168.88.1"]));
        assert_eq!(c["self_signed"], true);
        assert_eq!(c["private_key"], true);
        assert_eq!(c["key_type"], "ecdsa-p256");
        assert_eq!(c["origin"], "generated");
        assert_eq!(c["state"], "valid");
        assert_eq!(c["used_by"], json!([]));
        // The key is sealed in every copy of the config.
        let saved = serde_json::to_string(s.store().candidate()).unwrap();
        assert!(!saved.contains("PRIVATE KEY"), "the key is stored sealed");
        assert!(saved.contains("$cr1$"));
    }

    #[test]
    fn export_gives_the_key_only_to_full() {
        let mut s = lab();
        s.execute("certificate.add", &json!({"name": "a", "subject_alt_name": "router.lan, 10.0.0.1"})).unwrap();
        let e = s.execute("certificate.export", &json!({"id": "a"})).unwrap();
        assert!(e["certificate"].as_str().unwrap().contains("BEGIN CERTIFICATE"));
        assert!(e.get("private_key").is_none());
        let e = s.execute("certificate.export", &json!({"id": "a", "private_key": true})).unwrap();
        let key = e["private_key"].as_str().unwrap();
        crate::x509::check_pair(e["certificate"].as_str().unwrap(), key).unwrap();
        // A read-only user does not get it.
        s.execute("user.add", &json!({"name": "noc", "group": "write", "password": "noc-password"})).unwrap();
        let noc = crate::Caller::new(1, "x").with_principal(crate::auth::Principal::User("noc".into()));
        let e = s.execute_as(&noc, "certificate.export", &json!({"id": "a", "private_key": true})).unwrap_err().to_string();
        assert!(e.contains("full"), "{e}");
        assert!(s.execute_as(&noc, "certificate.export", &json!({"id": "a"})).is_ok());
    }

    #[test]
    fn import_checks_the_key_and_keeps_the_chain() {
        let mut s = lab();
        let n = NewCert {
            common_name: "dns.example.net".into(),
            subject_alt_names: vec!["DNS:dns.example.net".into()],
            key_type: "ecdsa-p384".into(),
            days_valid: 90,
            now: s.now().unwrap(),
        };
        let (cert, key) = x509::generate(&n).unwrap();
        let (_, other) = x509::generate(&n).unwrap();
        let e = s
            .execute("certificate.import", &json!({"name": "le", "certificate": cert, "private_key": other}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("not the key of this certificate"), "{e}");
        let r = s.execute("certificate.import", &json!({"name": "le", "certificate": cert, "private_key": key})).unwrap();
        assert!(r["warnings"].as_array().unwrap().iter().any(|w| w.as_str().unwrap().starts_with("self-signed")));
        let rows = s.execute("certificate.print", &json!({})).unwrap();
        assert_eq!(rows[0]["origin"], "imported");
        assert_eq!(rows[0]["key_type"], "ecdsa-p384");
        // Without a key: allowed, flagged, and no service may use it.
        s.execute("certificate.import", &json!({"name": "pub", "certificate": cert})).unwrap();
        let rows = s.execute("certificate.print", &json!({})).unwrap();
        assert_eq!(rows[1]["private_key"], false);
        assert!(s.execute("ip.service.www-ssl.set", &json!({"certificate": "pub"})).is_err());
    }

    #[test]
    fn a_certificate_in_use_cannot_go_and_a_rename_follows() {
        let mut s = lab();
        s.execute("certificate.add", &json!({"name": "web"})).unwrap();
        let r = s.execute("ip.service.www-ssl.set", &json!({"certificate": "web"})).unwrap();
        assert_eq!(r["certificate"], "web");
        assert!(r["warning"].as_str().unwrap().contains("pinned"), "{r}");
        let e = s.execute("certificate.remove", &json!({"id": "web"})).unwrap_err().to_string();
        assert!(e.contains("www-ssl"), "{e}");
        s.execute("certificate.set", &json!({"id": "web", "name": "web2"})).unwrap();
        assert_eq!(s.store().candidate().system.web.www_ssl.certificate, "web2");
        let rows = s.execute("certificate.print", &json!({})).unwrap();
        assert_eq!(rows[0]["used_by"], json!(["www-ssl"]));
        s.execute("ip.service.www-ssl.set", &json!({"certificate": "none"})).unwrap();
        s.execute("certificate.remove", &json!({"id": "web2"})).unwrap();
        let e = s.execute("ip.service.www-ssl.set", &json!({"certificate": "wbe"})).unwrap_err().to_string();
        assert!(e.contains("no certificate wbe"), "{e}");
    }

    #[test]
    fn bad_parameters_change_nothing() {
        let mut s = lab();
        s.execute("certificate.add", &json!({"name": "a"})).unwrap();
        let before = s.store().candidate().clone();
        for (id, p) in [
            ("certificate.add", json!({"name": "a"})),
            ("certificate.add", json!({"name": "has space"})),
            ("certificate.add", json!({"name": "b", "key_type": "rsa-2048"})),
            ("certificate.add", json!({"name": "b", "days_valid": 0})),
            ("certificate.add", json!({"name": "b", "subject_alt_name": "IP:300.1.1.1"})),
            ("certificate.add", json!({"name": "b", "subject_alt_name": "DNS:bad name!"})),
            ("certificate.import", json!({"name": "b", "certificate": "nope"})),
            ("certificate.import", json!({"name": "b"})),
            ("certificate.set", json!({"id": "zz"})),
            ("certificate.remove", json!({"id": "*99"})),
            ("ip.service.www.set", json!({"certificate": "a"})),
        ] {
            assert!(s.execute(id, &p).is_err(), "{id} {p}");
        }
        assert_eq!(*s.store().candidate(), before);
    }

    #[test]
    fn rollback_brings_back_the_removed_certificate() {
        let mut s = lab();
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        s.execute("certificate.add", &json!({"name": "a"})).unwrap();
        s.execute("config.commit", &json!({})).unwrap();
        let fp = s.execute("certificate.print", &json!({})).unwrap()[0]["fingerprint"].clone();
        s.execute("certificate.remove", &json!({"id": "a"})).unwrap();
        s.execute("config.discard", &json!({})).unwrap();
        let rows = s.execute("certificate.print", &json!({})).unwrap();
        assert_eq!(rows[0]["fingerprint"], fp);
    }

    #[test]
    fn previews_say_what_add_and_import_would_do() {
        let mut s = lab();
        let v = s.execute("certificate.check", &json!({"name": "x", "days_valid": "900"})).unwrap();
        assert_eq!(v["commands"][0]["command"], "certificate.add");
        assert!(v["checks"].as_array().unwrap().iter().any(|c| c["level"] == "warning" && c["check"] == "days_valid"));
        let v = s.execute("certificate.check", &json!({"name": "", "key_type": "rsa"})).unwrap();
        assert!(v["commands"].as_array().unwrap().is_empty());
        let v = s.execute("certificate.check-import", &json!({"name": "i", "certificate": "junk"})).unwrap();
        assert!(v["checks"][0]["param"] == "certificate" || v["checks"][1]["param"] == "certificate", "{v}");
        s.execute("certificate.add", &json!({"name": "x"})).unwrap();
        let v = s.execute("certificate.check", &json!({"id": "x", "name": "y", "comment": "c"})).unwrap();
        assert_eq!(v["commands"][0]["command"], "certificate.set");
    }
}
