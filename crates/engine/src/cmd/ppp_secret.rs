//! `/ppp secret` (G4.3d, RouterOS v7): local subscribers. The password is
//! write-only (`***` in the list; `password` is masked in the journal,
//! `auth::SECRET_KEYS`). Changes apply to the next login; an active
//! session is ended with `ppp.active.remove`.

use corerouter_model::MacAddr;
use corerouter_model::ppp::{MAX_PASSWORD, MAX_SECRETS, PppSecret, PppService};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text};
use super::dhcp_server::{find, opt_ip};
use super::ppp_common::opt_name;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("ppp.secret.add", "Add PPP Secret", [], None,
        "{name: string, password?: string (write-only; CHAP and MS-CHAP need it in clear), service?: any|pppoe|l2tp|pptp|sstp|ovpn|async|ipoe (default any; ipoe: a DHCP subscriber named by MAC or option 82, no password), profile?: string (default default), local_address?: ipv4, remote_address?: ipv4 (a fixed address; wins over the profile's pool), caller_id?: mac (PPPoE: only from this MAC; empty: any), limit_bytes_in?: int (bytes per session the subscriber sends; 0: none), limit_bytes_out?: int, comment?: string, disabled?: bool} → {id, name, warnings}",
        always, add),
    cmd!("ppp.secret.set", "Set PPP Secret", [], None,
        "{id: *hex | name, name?: string, password?: string (write-only; CHAP and MS-CHAP need it in clear), service?: any|pppoe|l2tp|pptp|sstp|ovpn|async|ipoe (default any; ipoe: a DHCP subscriber named by MAC or option 82, no password), profile?: string (default default), local_address?: ipv4, remote_address?: ipv4 (a fixed address; wins over the profile's pool), caller_id?: mac (PPPoE: only from this MAC; empty: any), limit_bytes_in?: int (bytes per session the subscriber sends; 0: none), limit_bytes_out?: int, comment?: string, disabled?: bool} → {id, name, warnings}",
        has_secrets, set),
    cmd!("ppp.secret.remove", "Remove PPP Secret", [], None,
        "{id: *hex | name} → {id, name, active (sessions of this user still up: ppp.active.remove ends them)}",
        has_secrets, remove),
    cmd!("ppp.secret.enable", "Enable PPP Secret", [], None,
        "{id: *hex | name} → {id, name}", has_secrets, enable),
    cmd!("ppp.secret.disable", "Disable PPP Secret", [], None,
        "{id: *hex | name} → {id, name, active}", has_secrets, disable),
    cmd!(query "ppp.secret.list", "PPP Secrets", [], None,
        "{find?: string (in name, comment, caller id or address), profile?: string, limit?: int (default all), offset?: int} → [{id, name, password: \"***\", service, profile, local_address?, remote_address?, caller_id?, limit_bytes_in?, limit_bytes_out?, comment?, disabled, active (up now), flags (X disabled)}]",
        always, list),
    cmd!(query "ppp.secret.preview", "PPP Secret Preview", [], None,
        "{id?: *hex | name, name?: string, password?: string, service?: string, profile?: string, local_address?: ipv4, remote_address?: ipv4, caller_id?: mac, limit_bytes_in?: int, limit_bytes_out?: int, comment?: string, disabled?: bool} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}]}",
        always, preview),
    cmd!(query "ppp.secret.count", "PPP Secret Count", [], None,
        "{find?: string, profile?: string} → {total, disabled, active}",
        always, count),
];

fn has_secrets(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ppp.secrets.is_empty() {
        Err("there are no PPP secrets (ppp.secret.add)".into())
    } else {
        Ok(())
    }
}

fn u64_of(p: &Value, key: &str) -> Result<Option<u64>> {
    match p.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| EngineError::bad(key, "bytes, a non-negative integer")),
    }
}

fn apply(s: &Session, x: &mut PppSecret, p: &Value) -> Result<()> {
    if let Some(n) = opt_name(p, "name")? {
        x.name = n;
    }
    if let Some(pw) = opt_str(p, "password")? {
        if pw.len() > MAX_PASSWORD || pw.chars().any(char::is_control) {
            return Err(EngineError::bad(
                "password",
                format!("at most {MAX_PASSWORD} bytes without control characters"),
            ));
        }
        x.password = pw.to_owned();
    }
    if let Some(t) = opt_str(p, "service")? {
        x.service = PppService::parse(t).ok_or_else(|| {
            EngineError::bad("service", "one of any, pppoe, l2tp, pptp, sstp, ovpn, async, ipoe")
        })?;
    }
    if let Some(t) = opt_str(p, "profile")? {
        let t = t.trim();
        if s.store().candidate().ppp.profile(t).is_none() {
            let shown: String = t.chars().take(64).collect();
            return Err(EngineError::bad("profile", format!("no profile '{shown}' (ppp.profile.add)")));
        }
        t.clone_into(&mut x.profile);
    }
    if let Some(ip) = opt_ip(p, "local_address")? {
        x.local_address = ip;
    }
    if let Some(ip) = opt_ip(p, "remote_address")? {
        x.remote_address = ip;
    }
    if let Some(t) = opt_str(p, "caller_id")? {
        x.caller_id = if t.trim().is_empty() {
            None
        } else {
            Some(t.parse::<MacAddr>().map_err(|e| {
                EngineError::bad("caller_id", format!("{e} (PPPoE caller id is the CPE's MAC)"))
            })?)
        };
    }
    if let Some(v) = u64_of(p, "limit_bytes_in")? {
        x.limit_bytes_in = v;
    }
    if let Some(v) = u64_of(p, "limit_bytes_out")? {
        x.limit_bytes_out = v;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        x.comment = c;
    }
    if let Some(d) = opt_bool(p, "disabled")? {
        x.disabled = d;
    }
    Ok(())
}

/// Addresses that two secrets (or a secret and a pool) would both hand out.
fn warnings(s: &Session, x: &PppSecret) -> Vec<String> {
    let mut w = Vec::new();
    let c = s.store().candidate();
    // IPoE subscribers have no password (a DHCP client is its MAC or line).
    if x.password.is_empty() && x.service != PppService::Ipoe {
        w.push("empty password: anyone who knows the name logs in".into());
    }
    if let Some(ip) = x.remote_address {
        if let Some(other) = c.ppp.secrets.iter().find(|o| o.id != x.id && o.remote_address == Some(ip)) {
            w.push(format!("remote_address {ip} is also the address of secret {}", other.name));
        }
        if let Some(pool) = c.ip.pools.pools.iter().find(|p| p.contains(ip)) {
            w.push(format!("remote_address {ip} is inside pool {}: the pool may lend it to another subscriber", pool.name));
        }
    }
    w
}

fn index(s: &Session, p: &Value) -> Result<usize> {
    find(&s.store().candidate().ppp.secrets, p, |x| x.id, |x| Some(x.name.as_str()), "secret")
}

fn active_of(s: &Session, name: &str) -> usize {
    s.ppp_active().iter().filter(|a| a.name == name).count()
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = opt_name(p, "name")?.ok_or_else(|| EngineError::bad("name", "is required"))?;
    let ppp = &s.store().candidate().ppp;
    if ppp.secret(&name).is_some() {
        return Err(EngineError::bad("name", format!("secret '{name}' exists")));
    }
    if ppp.secrets.len() >= MAX_SECRETS {
        return Err(EngineError::bad("name", format!("at most {MAX_SECRETS} secrets (use RADIUS)")));
    }
    let mut x = PppSecret {
        name,
        profile: corerouter_model::ppp::DEFAULT_PROFILE.into(),
        ..PppSecret::default()
    };
    apply(s, &mut x, p)?;
    x.id = s.store_mut().candidate_mut().ppp.next_id();
    let w = warnings(s, &x);
    let out = json!({"id": x.id, "name": x.name, "warnings": w});
    s.store_mut().candidate_mut().ppp.secrets.push(x);
    Ok(out)
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let Some(mut x) = s.store().candidate().ppp.secrets.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such secret"));
    };
    let old = x.name.clone();
    apply(s, &mut x, p)?;
    if x.name != old && s.store().candidate().ppp.secret(&x.name).is_some() {
        return Err(EngineError::bad("name", format!("secret '{}' exists", x.name)));
    }
    let w = warnings(s, &x);
    let out = json!({"id": x.id, "name": x.name, "warnings": w});
    if let Some(slot) = s.store_mut().candidate_mut().ppp.secrets.get_mut(i) {
        *slot = x;
    }
    Ok(out)
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let secrets = &mut s.store_mut().candidate_mut().ppp.secrets;
    if i >= secrets.len() {
        return Err(EngineError::bad("id", "no such secret"));
    }
    let x = secrets.remove(i);
    let active = active_of(s, &x.name);
    Ok(json!({"id": x.id, "name": x.name, "active": active}))
}

fn toggle(s: &mut Session, p: &Value, disabled: bool) -> Result<Value> {
    let i = index(s, p)?;
    let Some(x) = s.store_mut().candidate_mut().ppp.secrets.get_mut(i) else {
        return Err(EngineError::bad("id", "no such secret"));
    };
    x.disabled = disabled;
    let (id, name) = (x.id, x.name.clone());
    let active = active_of(s, &name);
    Ok(json!({"id": id, "name": name, "active": active}))
}

fn enable(s: &mut Session, p: &Value) -> Result<Value> {
    toggle(s, p, false).map(|mut v| {
        if let Some(o) = v.as_object_mut() {
            o.remove("active");
        }
        v
    })
}

fn disable(s: &mut Session, p: &Value) -> Result<Value> {
    toggle(s, p, true)
}

/// The modal's preview: the checks of `add`/`set`, and what the login
/// gets from its profile.
fn preview(s: &mut Session, p: &Value) -> Result<Value> {
    super::ppp_common::preview(s, p, ("ppp.secret.add", "ppp.secret.set"), (add, set), |s, v| {
        let cand = s.store().candidate();
        let name = v.get("name").and_then(Value::as_str).unwrap_or_default();
        let Some(sec) = cand.ppp.secret(name) else {
            return Vec::new();
        };
        let e = cand.ppp.effective(Some(sec), &sec.profile, corerouter_model::ppp::DEFAULT_PROFILE);
        let addr = match &e.remote_address {
            Some(corerouter_model::ppp::AddrOrPool::Address(ip)) => format!("{ip} (fixed)"),
            Some(corerouter_model::ppp::AddrOrPool::Pool(pool)) => format!("from pool {pool}"),
            None => "none: only RADIUS or the server's default profile can give one".into(),
        };
        vec![
            json!({"label": "Profile", "value": e.profile}),
            json!({"label": "Address", "value": addr}),
            json!({"label": "Rate limit", "value": e.rate_limit.unwrap_or_else(|| "none".into())}),
            json!({"label": "Only one", "value": if e.only_one { "yes" } else { "no" }}),
        ]
    })
}

/// The secrets `find` and `profile` select.
fn matching<'a>(secrets: &'a [PppSecret], needle: Option<&str>, profile: Option<&str>) -> Vec<&'a PppSecret> {
    secrets
        .iter()
        .filter(|x| profile.is_none_or(|pr| x.profile == pr))
        .filter(|x| {
            needle.is_none_or(|n| {
                x.name.to_lowercase().contains(n)
                    || x.comment.to_lowercase().contains(n)
                    || x.caller_id.is_some_and(|m| m.to_string().to_lowercase().contains(n))
                    || x.remote_address.is_some_and(|ip| ip.to_string().contains(n))
            })
        })
        .collect()
}

fn count(s: &mut Session, p: &Value) -> Result<Value> {
    let needle = opt_text(p, "find", 128)?.map(|t| t.to_lowercase());
    let profile = opt_str(p, "profile")?.map(str::to_owned);
    let active = s.ppp_active();
    let up: std::collections::HashSet<&str> = active.iter().map(|a| a.name.as_str()).collect();
    let hits = matching(&s.store().candidate().ppp.secrets, needle.as_deref(), profile.as_deref());
    Ok(json!({
        "total": hits.len(),
        "disabled": hits.iter().filter(|x| x.disabled).count(),
        "active": hits.iter().filter(|x| up.contains(x.name.as_str())).count(),
    }))
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let needle = opt_text(p, "find", 128)?.map(|t| t.to_lowercase());
    let profile = opt_str(p, "profile")?.map(str::to_owned);
    let limit = super::args::opt_u32(p, "limit")?.unwrap_or(u32::MAX);
    let offset = super::args::opt_u32(p, "offset")?.unwrap_or(0) as usize;
    let active = s.ppp_active();
    let up: std::collections::HashSet<&str> = active.iter().map(|a| a.name.as_str()).collect();
    let secrets = &s.store().candidate().ppp.secrets;
    let hits = matching(secrets, needle.as_deref(), profile.as_deref());
    let rows: Vec<Value> = hits
        .iter()
        .skip(offset)
        .take(limit as usize)
        .map(|x| {
            let mut v = json!({
                "id": x.id,
                "name": x.name,
                "password": "***",
                "service": x.service.as_str(),
                "profile": x.profile,
                "disabled": x.disabled,
                "active": up.contains(x.name.as_str()),
                "flags": if x.disabled { "X" } else { "" },
            });
            if let Some(o) = v.as_object_mut() {
                if let Some(ip) = x.local_address {
                    o.insert("local_address".into(), json!(ip));
                }
                if let Some(ip) = x.remote_address {
                    o.insert("remote_address".into(), json!(ip));
                }
                if let Some(m) = x.caller_id {
                    o.insert("caller_id".into(), json!(m.to_string()));
                }
                if x.limit_bytes_in > 0 {
                    o.insert("limit_bytes_in".into(), json!(x.limit_bytes_in));
                }
                if x.limit_bytes_out > 0 {
                    o.insert("limit_bytes_out".into(), json!(x.limit_bytes_out));
                }
                if !x.comment.is_empty() {
                    o.insert("comment".into(), json!(x.comment));
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
    fn add_list_set_and_password_is_write_only() {
        let mut s = Session::virtual_lab();
        let r = s
            .execute("ppp.secret.add", &json!({
                "name": "joao@isp", "password": "s3nh4", "service": "pppoe",
                "caller_id": "aa:bb:cc:00:00:01", "remote_address": "100.64.0.10",
                "limit_bytes_out": 1_000_000_000u64, "comment": "João da Silva"
            }))
            .unwrap();
        assert!(r["warnings"].as_array().unwrap().is_empty(), "{r}");
        let l = s.execute("ppp.secret.list", &json!({})).unwrap();
        assert_eq!(s.execute("ppp.secret.count", &json!({})).unwrap()["total"], 1);
        let row = &l[0];
        assert_eq!(row["password"], "***");
        assert_eq!(row["caller_id"], "AA:BB:CC:00:00:01");
        assert_eq!(row["profile"], "default");
        assert!(!l.to_string().contains("s3nh4"));
        assert_eq!(s.store().running().ppp.secret("joao@isp").unwrap().password, "s3nh4");
        let j = serde_json::to_string(&s.journal()).unwrap();
        assert!(!j.contains("s3nh4"), "journal leaks the password: {j}");
        s.execute("ppp.secret.disable", &json!({"id": "joao@isp"})).unwrap();
        assert!(s.store().running().ppp.secrets[0].disabled);
        s.execute("ppp.secret.set", &json!({"id": "joao@isp", "caller_id": ""})).unwrap();
        assert!(s.store().running().ppp.secrets[0].caller_id.is_none());
        let l = s.execute("ppp.secret.list", &json!({"find": "silva"})).unwrap();
        assert_eq!(l.as_array().unwrap().len(), 1);
        s.execute("ppp.secret.remove", &json!({"id": "joao@isp"})).unwrap();
        assert!(s.store().running().ppp.secrets.is_empty());
    }

    #[test]
    fn bad_values_and_duplicates_are_refused() {
        let mut s = Session::virtual_lab();
        s.execute("ppp.secret.add", &json!({"name": "a", "password": "x"})).unwrap();
        for p in [
            json!({"name": "a"}),
            json!({"name": "b", "service": "telnet"}),
            json!({"name": "b", "profile": "nope"}),
            json!({"name": "b", "caller_id": "zz"}),
            json!({"name": "b", "remote_address": "1.2.3"}),
            json!({"name": "b", "limit_bytes_in": -1}),
            json!({"name": "b", "password": "a\u{0}b"}),
            json!({"name": "x".repeat(65)}),
        ] {
            let err = s.execute("ppp.secret.add", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        assert_eq!(s.store().candidate().ppp.secrets.len(), 1);
    }

    #[test]
    fn warnings_and_rollback() {
        let mut s = Session::virtual_lab();
        s.execute("ip.pool.add", &json!({"name": "c", "ranges": "100.64.0.0/24"})).unwrap();
        s.execute("ppp.secret.add", &json!({"name": "a", "password": "x", "remote_address": "100.64.0.9"})).unwrap();
        let r = s.execute("ppp.secret.add", &json!({"name": "b", "remote_address": "100.64.0.9"})).unwrap();
        let w = r["warnings"].to_string();
        assert!(w.contains("empty password") && w.contains("secret a") && w.contains("pool c"), "{w}");
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        s.execute("ppp.secret.remove", &json!({"id": "a"})).unwrap();
        s.execute("config.discard", &json!({})).unwrap();
        assert_eq!(s.store().candidate().ppp.secrets.len(), 2);
    }

    #[test]
    fn ten_thousand_secrets_list_in_pages() {
        // An import is one atomic batch: one snapshot for the whole batch,
        // so 10 k adds do not copy the table 10 k times (one command alone
        // copies the secrets it writes: copy-on-write of the section).
        let mut s = Session::virtual_lab();
        let steps: Vec<Value> = (0..10_000)
            .map(|i| json!({"command": "ppp.secret.add", "params": {"name": format!("u{i}"), "password": "x"}}))
            .collect();
        s.batch(&Value::Array(steps), true).unwrap();
        let l = s.execute("ppp.secret.list", &json!({"limit": 50, "offset": 100})).unwrap();
        assert_eq!(s.execute("ppp.secret.count", &json!({})).unwrap()["total"], 10_000);
        assert_eq!(l.as_array().unwrap().len(), 50);
        assert_eq!(l[0]["name"], "u100");
    }
}
