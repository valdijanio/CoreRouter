//! `/ppp profile` (G4.3d, RouterOS v7): what a PPP session gets when the
//! secret (or RADIUS) does not say. The built-in `default` and
//! `default-encryption` always exist; changing one stores a copy, and they
//! cannot be removed. Changes apply to new sessions.

use corerouter_model::ItemId;
use corerouter_model::ppp::{AddrOrPool, MAX_PROFILES, PppProfile, Tri};
use serde_json::{Value, json};

use super::args::{opt_str, opt_text};
use super::dhcp_server::{opt_ips, opt_secs};
use super::ppp_common::{opt_address_list, opt_hooks, opt_name, opt_rate_limit};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("ppp.profile.add", "Add PPP Profile", [], None,
        "{name: string, local_address?: ipv4 | pool (our side; empty: unnumbered), remote_address?: ipv4 | pool (the subscriber's), dns_server?: [ipv4] | string (at most 2), rate_limit?: string (RouterOS rate-limit, rx/tx from the router: 10M/50M [burst [threshold [time [priority [min]]]]]; empty clears), address_list?: string (firewall list the subscriber's address joins while up), only_one?: default|yes|no, change_tcp_mss?: default|yes|no, idle_timeout?: duration (empty: none), session_timeout?: duration (empty: none), on_up?: [{command, params?}] | string (the same list as JSON text; $user, $remote-address, $local-address, $caller-id, $interface, $service in string values), on_down?: [{command, params?}], comment?: string} → {id, name, warnings}",
        always, add),
    cmd!("ppp.profile.set", "Set PPP Profile", [], None,
        "{id: *hex | name, name?: string, local_address?: ipv4 | pool (our side; empty: unnumbered), remote_address?: ipv4 | pool (the subscriber's), dns_server?: [ipv4] | string (at most 2), rate_limit?: string (RouterOS rate-limit, rx/tx from the router: 10M/50M [burst [threshold [time [priority [min]]]]]; empty clears), address_list?: string (firewall list the subscriber's address joins while up), only_one?: default|yes|no, change_tcp_mss?: default|yes|no, idle_timeout?: duration (empty: none), session_timeout?: duration (empty: none), on_up?: [{command, params?}] | string (the same list as JSON text; $user, $remote-address, $local-address, $caller-id, $interface, $service in string values), on_down?: [{command, params?}], comment?: string} → {id, name, warnings}",
        always, set),
    cmd!("ppp.profile.remove", "Remove PPP Profile", [], None,
        "{id: *hex | name} → {id, name}", always, remove),
    cmd!(query "ppp.profile.preview", "PPP Profile Preview", [], None,
        "{id?: *hex | name, name?: string, local_address?: string, remote_address?: string, dns_server?: string, rate_limit?: string, address_list?: string, only_one?: string, change_tcp_mss?: string, idle_timeout?: string, session_timeout?: string, on_up?: string, on_down?: string, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}]}",
        always, preview),
    cmd!(query "ppp.profile.list", "PPP Profiles", [], None,
        "{} → [{id, name, builtin, default (built in), local_address?, remote_address?, dns_server, rate_limit?, address_list?, only_one, change_tcp_mss, idle_timeout?, session_timeout?, on_up (JSON text), on_down, comment?, secrets (that use it), active (sessions up with it)}]",
        always, list),
];

fn tri(p: &Value, key: &str) -> Result<Option<Tri>> {
    opt_str(p, key)?
        .map(|t| Tri::parse(t).ok_or_else(|| EngineError::bad(key, "default, yes or no")))
        .transpose()
}

fn addr(s: &Session, p: &Value, key: &str) -> Result<Option<Option<AddrOrPool>>> {
    let Some(t) = opt_str(p, key)? else {
        return Ok(None);
    };
    if t.trim().is_empty() {
        return Ok(Some(None));
    }
    let a: AddrOrPool = t.parse().map_err(|e| EngineError::bad(key, format!("{e}")))?;
    if let AddrOrPool::Pool(name) = &a
        && s.store().candidate().ip.pools.get(name).is_none()
    {
        let shown: String = name.chars().take(64).collect();
        return Err(EngineError::bad(key, format!("no /ip pool '{shown}' (ip.pool.add)")));
    }
    Ok(Some(Some(a)))
}

fn timeout(p: &Value, key: &str) -> Result<Option<Option<u32>>> {
    if matches!(p.get(key), Some(Value::String(t)) if t.trim().is_empty() || t.trim() == "none") {
        return Ok(Some(None));
    }
    Ok(opt_secs(p, key)?.map(|v| (v != 0).then_some(v)))
}

fn apply(s: &Session, pr: &mut PppProfile, p: &Value) -> Result<()> {
    if let Some(n) = opt_name(p, "name")? {
        pr.name = n;
    }
    if let Some(a) = addr(s, p, "local_address")? {
        pr.local_address = a;
    }
    if let Some(a) = addr(s, p, "remote_address")? {
        pr.remote_address = a;
    }
    if let Some(d) = opt_ips(p, "dns_server")? {
        if d.len() > 2 {
            return Err(EngineError::bad("dns_server", "at most 2 (RFC 1877: primary and secondary)"));
        }
        pr.dns_server = d;
    }
    if let Some(r) = opt_rate_limit(p)? {
        pr.rate_limit = r;
    }
    if let Some(l) = opt_address_list(p)? {
        pr.address_list = l;
    }
    if let Some(t) = tri(p, "only_one")? {
        pr.only_one = t;
    }
    if let Some(t) = tri(p, "change_tcp_mss")? {
        pr.change_tcp_mss = t;
    }
    if let Some(t) = timeout(p, "idle_timeout")? {
        pr.idle_timeout = t;
    }
    if let Some(t) = timeout(p, "session_timeout")? {
        pr.session_timeout = t;
    }
    if let Some(h) = opt_hooks(p, "on_up")? {
        pr.on_up = h;
    }
    if let Some(h) = opt_hooks(p, "on_down")? {
        pr.on_down = h;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        pr.comment = c;
    }
    Ok(())
}

fn warnings(pr: &PppProfile) -> Vec<String> {
    let mut w = Vec::new();
    if pr.remote_address.is_none() && pr.name != corerouter_model::ppp::DEFAULT_ENCRYPTION {
        w.push("no remote_address: subscribers get an address only from their secret or RADIUS (Framed-IP-Address / Framed-Pool)".into());
    }
    if pr.change_tcp_mss == Tri::Yes {
        w.push("change_tcp_mss=yes clamps the MSS per session; with many subscribers one mangle rule (change-mss) is lighter".into());
    }
    w
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = opt_name(p, "name")?.ok_or_else(|| EngineError::bad("name", "is required"))?;
    let ppp = &s.store().candidate().ppp;
    if ppp.profile(&name).is_some() {
        return Err(EngineError::bad("name", format!("profile '{name}' exists")));
    }
    if ppp.profiles.len() >= MAX_PROFILES {
        return Err(EngineError::bad("name", "too many profiles"));
    }
    let mut pr = PppProfile { name, ..PppProfile::default() };
    apply(s, &mut pr, p)?;
    let ppp = &mut s.store_mut().candidate_mut().ppp;
    pr.id = ppp.next_id();
    let out = json!({"id": pr.id, "name": pr.name, "warnings": warnings(&pr)});
    ppp.profiles.push(pr);
    Ok(out)
}

/// The profile `p["id"]` names (stored or built-in).
fn named(s: &Session, p: &Value) -> Result<PppProfile> {
    let raw = opt_str(p, "id")?.ok_or_else(|| EngineError::bad("id", "is required"))?.trim();
    let ppp = &s.store().candidate().ppp;
    let found = if raw.starts_with('*') {
        let id: ItemId = raw.parse().map_err(|e| EngineError::bad("id", format!("{e}")))?;
        ppp.all_profiles().into_iter().find(|x| x.id == id)
    } else {
        ppp.profile(raw)
    };
    found.ok_or_else(|| {
        let shown: String = raw.chars().take(64).collect();
        EngineError::bad("id", format!("no profile '{shown}'"))
    })
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let mut pr = named(s, p)?;
    let old = pr.name.clone();
    apply(s, &mut pr, p)?;
    if pr.name != old {
        if PppProfile::is_builtin_name(&old) {
            return Err(EngineError::bad("name", format!("'{old}' is built in and keeps its name")));
        }
        let ppp = &s.store().candidate().ppp;
        if ppp.profile(&pr.name).is_some() {
            return Err(EngineError::bad("name", format!("profile '{}' exists", pr.name)));
        }
        let used = ppp.profile_users(&old);
        if !used.is_empty() {
            return Err(EngineError::bad(
                "name",
                format!("{} use it by name: change them first", used.iter().take(5).cloned().collect::<Vec<_>>().join(", ")),
            ));
        }
    }
    let out = json!({"id": pr.id, "name": pr.name, "warnings": warnings(&pr)});
    let ppp = &mut s.store_mut().candidate_mut().ppp;
    // A built-in set back to what it ships with needs no stored copy.
    if PppProfile::builtin(&pr.name).as_ref() == Some(&pr) {
        ppp.profiles.retain(|x| x.name != pr.name);
        return Ok(out);
    }
    match ppp.profiles.iter_mut().find(|x| x.name == old) {
        Some(slot) => *slot = pr,
        None => ppp.profiles.push(pr),
    }
    Ok(out)
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let pr = named(s, p)?;
    if PppProfile::is_builtin_name(&pr.name) {
        return Err(EngineError::bad("id", format!("'{}' is built in and cannot be removed", pr.name)));
    }
    let used = s.store().candidate().ppp.profile_users(&pr.name);
    if !used.is_empty() {
        let n = used.len();
        let first: Vec<String> = used.into_iter().take(5).collect();
        return Err(EngineError::bad("id", format!("in use by {n}: {}", first.join(", "))));
    }
    s.store_mut().candidate_mut().ppp.profiles.retain(|x| x.name != pr.name);
    Ok(json!({"id": pr.id, "name": pr.name}))
}

/// The modal's preview: the checks of `add`/`set`, and what a session
/// with this profile gets once the built-in `default` fills the gaps.
fn preview(s: &mut Session, p: &Value) -> Result<Value> {
    super::ppp_common::preview(s, p, ("ppp.profile.add", "ppp.profile.set"), (add, set), |s, v| {
        let name = v.get("name").and_then(Value::as_str).unwrap_or_default();
        let e = s.store().candidate().ppp.effective(None, name, corerouter_model::ppp::DEFAULT_PROFILE);
        let opt = |o: Option<String>| o.unwrap_or_else(|| "none".into());
        vec![
            json!({"label": "Remote address", "value": opt(e.remote_address.map(|a| a.to_string()))}),
            json!({"label": "Rate limit", "value": opt(e.rate_limit)}),
            json!({"label": "Only one", "value": if e.only_one { "yes" } else { "no" }}),
            json!({"label": "Change TCP MSS", "value": if e.change_tcp_mss { "yes" } else { "no" }}),
        ]
    })
}

/// Hooks as one JSON text (what `add` takes back, so `/export` round-trips).
fn hooks_text(h: &[corerouter_model::ppp::PppHook]) -> String {
    if h.is_empty() {
        String::new()
    } else {
        serde_json::to_string(h).unwrap_or_default()
    }
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    let active = s.ppp_active();
    let ppp = &s.store().candidate().ppp;
    let rows: Vec<Value> = ppp
        .all_profiles()
        .into_iter()
        .map(|pr| {
            let secrets = ppp.secrets.iter().filter(|x| x.profile == pr.name).count();
            let up = active.iter().filter(|a| a.profile == pr.name).count();
            let mut v = json!({
                "id": pr.id,
                "name": pr.name,
                "builtin": PppProfile::is_builtin_name(&pr.name),
                // Built in: every config has it (`/export` writes a `set`).
                "default": PppProfile::is_builtin_name(&pr.name),
                "dns_server": pr.dns_server,
                "only_one": pr.only_one.as_str(),
                "change_tcp_mss": pr.change_tcp_mss.as_str(),
                "on_up": hooks_text(&pr.on_up),
                "on_down": hooks_text(&pr.on_down),
                "secrets": secrets,
                "active": up,
            });
            if let Some(o) = v.as_object_mut() {
                for (k, val) in [
                    ("local_address", pr.local_address.as_ref().map(ToString::to_string)),
                    ("remote_address", pr.remote_address.as_ref().map(ToString::to_string)),
                    ("rate_limit", pr.rate_limit.clone()),
                    ("address_list", pr.address_list.clone()),
                    ("idle_timeout", pr.idle_timeout.map(super::dhcp_server::secs_text)),
                    ("session_timeout", pr.session_timeout.map(super::dhcp_server::secs_text)),
                    ("comment", Some(pr.comment.clone()).filter(|c| !c.is_empty())),
                ] {
                    if let Some(val) = val {
                        o.insert(k.into(), json!(val));
                    }
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

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.execute("ip.pool.add", &json!({"name": "clientes", "ranges": "100.64.0.1-100.64.3.254"})).unwrap();
        s
    }

    #[test]
    fn builtins_exist_and_add_set_remove_work() {
        let mut s = lab();
        let l = s.execute("ppp.profile.list", &json!({})).unwrap();
        assert_eq!(l.as_array().unwrap().len(), 2);
        assert_eq!(l[0]["name"], "default");
        assert_eq!(l[0]["change_tcp_mss"], "yes");
        let r = s
            .execute("ppp.profile.add", &json!({
                "name": "plano-100M", "remote_address": "clientes", "local_address": "100.64.255.254",
                "dns_server": "1.1.1.1,8.8.8.8", "rate_limit": "50M/100M", "address_list": "assinantes",
                "only_one": "yes", "session_timeout": "1d",
                "on_up": [{"command": "ip.firewall.address-list.add", "params": {"list": "online", "address": "$remote-address", "comment": "$user", "timeout": "1d"}}]
            }))
            .unwrap();
        assert_eq!(r["name"], "plano-100M");
        let l = s.execute("ppp.profile.list", &json!({})).unwrap();
        let row = &l[2];
        assert_eq!(row["remote_address"], "clientes");
        assert_eq!(row["rate_limit"], "50M/100M");
        assert_eq!(row["session_timeout"], "1d");
        s.execute("ppp.profile.set", &json!({"id": "plano-100M", "rate_limit": ""})).unwrap();
        assert!(s.store().running().ppp.profile("plano-100M").unwrap().rate_limit.is_none());
        // Editing a built-in stores a copy; removing it is refused.
        s.execute("ppp.profile.set", &json!({"id": "default", "dns_server": "9.9.9.9"})).unwrap();
        assert_eq!(s.store().running().ppp.profiles.len(), 2);
        assert!(s.execute("ppp.profile.remove", &json!({"id": "default"})).is_err());
        assert!(s.execute("ppp.profile.set", &json!({"id": "default", "name": "x"})).is_err());
        s.execute("ppp.profile.set", &json!({"id": "default", "dns_server": ""})).unwrap();
        assert_eq!(s.store().running().ppp.profiles.len(), 1, "back to the built-in: no copy");
        let err = s.execute("ip.pool.remove", &json!({"id": "clientes"})).unwrap_err();
        assert!(err.to_string().contains("ppp profile plano-100M"), "{err}");
        s.execute("ppp.profile.remove", &json!({"id": "plano-100M"})).unwrap();
        assert!(s.store().running().ppp.profile("plano-100M").is_none());
    }

    #[test]
    fn bad_values_are_refused() {
        let mut s = lab();
        for p in [
            json!({"name": ""}),
            json!({"name": "a", "remote_address": "nopool"}),
            json!({"name": "a", "rate_limit": "fast"}),
            json!({"name": "a", "dns_server": "1.1.1.1,1.0.0.1,8.8.8.8"}),
            json!({"name": "a", "only_one": "maybe"}),
            json!({"name": "a", "address_list": "with space"}),
            json!({"name": "a", "on_up": [{"command": "no.such.command"}]}),
            json!({"name": "a", "on_up": [{"command": "ppp.secret.remove", "params": {"id": "$user"}}]}),
            json!({"name": "a", "on_up": [{"command": "ip.firewall.address-list.add", "params": {"nope": 1}}]}),
            json!({"name": "default"}),
        ] {
            let err = s.execute("ppp.profile.add", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        assert!(s.store().candidate().ppp.profiles.is_empty());
    }

    #[test]
    fn in_use_profiles_and_rollback() {
        let mut s = lab();
        s.execute("ppp.profile.add", &json!({"name": "p1"})).unwrap();
        s.execute("ppp.secret.add", &json!({"name": "joao", "password": "x", "profile": "p1"})).unwrap();
        let err = s.execute("ppp.profile.remove", &json!({"id": "p1"})).unwrap_err();
        assert!(err.to_string().contains("secret joao"), "{err}");
        assert!(s.execute("ppp.profile.set", &json!({"id": "p1", "name": "p2"})).is_err());
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        s.execute("ppp.profile.add", &json!({"name": "p3"})).unwrap();
        s.execute("config.discard", &json!({})).unwrap();
        assert!(s.store().candidate().ppp.profile("p3").is_none());
    }
}
