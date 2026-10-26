//! `/ppp secret` (G4.3d, RouterOS v7): local subscribers. The password is
//! write-only (`***` in the list; `password` is masked in the journal,
//! `auth::SECRET_KEYS`). Changes apply to the next login; an active
//! session is ended with `ppp.active.remove`.

use std::net::IpAddr;

use corerouter_model::cow_list::CowList;
use corerouter_model::MacAddr;
use corerouter_model::framed_route::{FramedRoute, overlaps};
use corerouter_model::ppp::{MAX_PASSWORD, MAX_SECRETS, PppSecret, PppService};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text};
use super::dhcp_server::opt_ip;
use super::ppp_common::opt_name;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("ppp.secret.add", "Add PPP Secret", [], None,
        "{name: string, password?: string (write-only; CHAP and MS-CHAP need it in clear), service?: any|pppoe|l2tp|pptp|sstp|ovpn|async|ipoe (default any; ipoe: a DHCP subscriber named by MAC or option 82, no password), profile?: string (default default), local_address?: ipv4, remote_address?: ipv4 (a fixed address; wins over the profile's pool), caller_id?: mac (PPPoE: only from this MAC; empty: any), limit_bytes_in?: int (bytes per session the subscriber sends; 0: none), limit_bytes_out?: int, routes?: string (blocks routed to the subscriber while up, RouterOS dst-address [gateway] [metric], comma-separated, IPv4 or IPv6; gateway 0.0.0.0, :: or none = the subscriber; empty: none), comment?: string, disabled?: bool} → {id, name, warnings}",
        always, add),
    cmd!("ppp.secret.set", "Set PPP Secret", [], None,
        "{id: *hex | name, name?: string, password?: string (write-only; CHAP and MS-CHAP need it in clear), service?: any|pppoe|l2tp|pptp|sstp|ovpn|async|ipoe (default any; ipoe: a DHCP subscriber named by MAC or option 82, no password), profile?: string (default default), local_address?: ipv4, remote_address?: ipv4 (a fixed address; wins over the profile's pool), caller_id?: mac (PPPoE: only from this MAC; empty: any), limit_bytes_in?: int (bytes per session the subscriber sends; 0: none), limit_bytes_out?: int, routes?: string (blocks routed to the subscriber while up, RouterOS dst-address [gateway] [metric], comma-separated, IPv4 or IPv6; gateway 0.0.0.0, :: or none = the subscriber; empty: none), comment?: string, disabled?: bool} → {id, name, warnings}",
        has_secrets, set),
    cmd!("ppp.secret.remove", "Remove PPP Secret", [], None,
        "{id: *hex | name} → {id, name, active (sessions of this user still up: ppp.active.remove ends them)}",
        has_secrets, remove),
    cmd!("ppp.secret.enable", "Enable PPP Secret", [], None,
        "{id: *hex | name} → {id, name}", has_secrets, enable),
    cmd!("ppp.secret.disable", "Disable PPP Secret", [], None,
        "{id: *hex | name} → {id, name, active}", has_secrets, disable),
    cmd!(query "ppp.secret.list", "PPP Secrets", [], None,
        "{find?: string (in name, comment, caller id, address or routes), profile?: string, limit?: int (default all), offset?: int} → [{id, name, password: \"***\", service, profile, local_address?, remote_address?, caller_id?, limit_bytes_in?, limit_bytes_out?, routes?: string (RouterOS text, comma-separated), comment?, disabled, active (up now), flags (X disabled)}]",
        always, list),
    cmd!(query "ppp.secret.preview", "PPP Secret Preview", [], None,
        "{id?: *hex | name, name?: string, password?: string, service?: string, profile?: string, local_address?: ipv4, remote_address?: ipv4, caller_id?: mac, limit_bytes_in?: int, limit_bytes_out?: int, routes?: string, comment?: string, disabled?: bool} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}]}",
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
        // The secret modal (and the terminal) send the field as text; an
        // empty one is "not given" (it made every edit of a secret without
        // limits fail).
        Some(Value::String(t)) if t.trim().is_empty() => Ok(None),
        Some(Value::String(t)) => t
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_| EngineError::bad(key, "bytes, a non-negative integer")),
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
    if let Some(items) = super::dhcp_client::opt_list(p, "routes")? {
        x.routes = FramedRoute::parse_list(&items.join(","))
            .map_err(|e| EngineError::bad("routes", e.to_string()))?;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        x.comment = c;
    }
    if let Some(d) = opt_bool(p, "disabled")? {
        x.disabled = d;
    }
    Ok(())
}

/// G4.3cd: what makes a secret's `routes` unusable, refused with the
/// reason (a block routed to two places, or over the router's own or a
/// pool's addresses, blackholes someone). The rest comes back as warnings.
/// Cost per route: O(log n) in the secrets' route index, O(pools) and
/// O(addresses); the walk of fixed addresses runs only for a secret with
/// routes (business customers, a few per thousand).
fn check_routes(s: &Session, x: &PppSecret) -> Result<Vec<String>> {
    let mut w = Vec::new();
    if x.routes.is_empty() {
        return Ok(w);
    }
    let c = s.store().candidate();
    let bad = |why: String| Err(EngineError::bad("routes", why));
    for r in &x.routes {
        let dst = r.dst;
        if let Some(why) = r.martian() {
            return bad(format!("{dst}: {why}"));
        }
        if let Some((n, o)) = c.ppp.secrets.route_owners(&dst).into_iter().find(|(_, o)| o.id != x.id) {
            return bad(format!("{dst} overlaps {n}, routed to secret {}", o.name));
        }
        for pool in &c.ip.pools.pools {
            if let Some(range) = pool.ranges.iter().find(|g| {
                overlaps_range(&dst, IpAddr::V4(g.start), IpAddr::V4(g.end))
            }) {
                return bad(format!("{dst} overlaps {range} of pool {}: the pool lends those addresses to other subscribers", pool.name));
            }
        }
        if let Some(pool) = c.ipv6.dhcp_server.pools.iter().find(|q| overlaps(&dst, &ipnet::IpNet::V6(q.prefix))) {
            return bad(format!("{dst} overlaps IPv6 pool {} ({})", pool.name, pool.prefix));
        }
        for a in c.ip.addresses.iter().filter(|a| !a.disabled && a.from_pool.is_none()) {
            if dst.contains(&a.address.addr()) {
                return bad(format!("{dst} holds {}, the router's own address on {}", a.address.addr(), a.interface));
            }
            if a.address.prefix_len() < a.address.max_prefix_len() && a.address.trunc().contains(&dst) {
                w.push(format!("{dst} is inside {} of {}: hosts of that network in the block stop being reachable there", a.address.trunc(), a.interface));
            }
        }
        if let Some(o) = c.ppp.secrets.iter().find(|o| {
            o.id != x.id && o.remote_address.is_some_and(|ip| dst.contains(&IpAddr::V4(ip)))
        }) {
            return bad(format!("{dst} holds {}, the fixed address of secret {}", o.remote_address.map_or_else(String::new, |ip| ip.to_string()), o.name));
        }
        match (r.gateway, x.remote_address) {
            (Some(IpAddr::V4(g)), Some(ip)) if g != ip => {
                return bad(format!("{dst}: gateway {g} is not the subscriber ({ip}); use 0.0.0.0 or {ip}"));
            }
            (Some(IpAddr::V4(g)), None) => w.push(format!(
                "{dst}: gateway {g} must be the address the subscriber gets, else the route is refused at login (0.0.0.0 = always the subscriber)"
            )),
            _ => {}
        }
        if let Some((n, h)) = s
            .ext::<crate::framed::FramedTable>()
            .and_then(|t| t.conflict(&dst, ""))
            .filter(|(_, h)| h.user != x.name)
        {
            w.push(format!("{dst} overlaps {n} held now by {} ({}): refused at login while that session is up", h.user, h.origin.label()));
        }
    }
    Ok(w)
}

/// A pool range that overlaps a secret's routed block: the reason to
/// refuse it (`ip.pool`, `ipv6.pool`).
pub(super) fn routed_in(s: &Session, first: IpAddr, last: IpAddr) -> Option<String> {
    s.store()
        .candidate()
        .ppp
        .secrets
        .route_owners_in(first, last)
        .first()
        .map(|(n, o)| format!("overlaps {n}, routed to secret {} (ppp.secret routes)", o.name))
}

/// Whether block `n` shares an address with `first..=last`.
fn overlaps_range(n: &ipnet::IpNet, first: IpAddr, last: IpAddr) -> bool {
    match (n, first, last) {
        (ipnet::IpNet::V4(n), IpAddr::V4(a), IpAddr::V4(b)) => {
            u32::from(n.network()) <= u32::from(b) && u32::from(a) <= u32::from(n.broadcast())
        }
        (ipnet::IpNet::V6(n), IpAddr::V6(a), IpAddr::V6(b)) => {
            u128::from(n.network()) <= u128::from(b) && u128::from(a) <= u128::from(n.broadcast())
        }
        _ => false,
    }
}

/// Addresses that two secrets (or a secret and a pool) would both hand out;
/// `routes` that cannot be used are refused here.
fn warnings(s: &Session, x: &PppSecret) -> Result<Vec<String>> {
    let mut w = check_routes(s, x)?;
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
        if let Some((n, o)) = c.ppp.secrets.route_owners(&ipnet::IpNet::from(IpAddr::V4(ip))).into_iter().find(|(_, o)| o.id != x.id) {
            return Err(EngineError::bad("remote_address", format!("{ip} is inside {n}, routed to secret {}", o.name)));
        }
    }
    Ok(w)
}

/// Position of the secret `id` names (`*hex` or the name): O(log n) by id,
/// O(1) by name through the index (G4.3gb).
fn index(s: &Session, p: &Value) -> Result<usize> {
    let raw = opt_str(p, "id")?.ok_or_else(|| EngineError::bad("id", "is required"))?;
    let raw = raw.trim();
    let secrets = &s.store().candidate().ppp.secrets;
    let id = match raw.strip_prefix('*').and_then(|_| raw.parse::<corerouter_model::ItemId>().ok()) {
        Some(id) => Some(id),
        None => secrets.by_name(raw).map(|x| x.id),
    };
    id.and_then(|id| secrets.position(id)).ok_or_else(|| {
        let shown: String = raw.chars().take(64).collect();
        EngineError::bad("id", format!("no secret '{shown}'"))
    })
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
    let w = warnings(s, &x)?;
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
    let w = warnings(s, &x)?;
    let out = json!({"id": x.id, "name": x.name, "warnings": w});
    s.store_mut().candidate_mut().ppp.secrets.update(i, |slot| *slot = x);
    Ok(out)
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let Some(x) = s.store_mut().candidate_mut().ppp.secrets.remove(i) else {
        return Err(EngineError::bad("id", "no such secret"));
    };
    let active = active_of(s, &x.name);
    Ok(json!({"id": x.id, "name": x.name, "active": active}))
}

fn toggle(s: &mut Session, p: &Value, disabled: bool) -> Result<Value> {
    let i = index(s, p)?;
    let Some((id, name)) = s.store_mut().candidate_mut().ppp.secrets.update(i, |x| {
        x.disabled = disabled;
        (x.id, x.name.clone())
    }) else {
        return Err(EngineError::bad("id", "no such secret"));
    };
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
            json!({"label": "Routes", "value": if sec.routes.is_empty() { "none".to_owned() } else { FramedRoute::list_text(&sec.routes) }}),
        ]
    })
}

/// The secrets `find` and `profile` select.
fn matching<'a>(secrets: &'a CowList<PppSecret>, needle: Option<&str>, profile: Option<&str>) -> Vec<&'a PppSecret> {
    secrets
        .iter()
        .filter(|x| profile.is_none_or(|pr| x.profile == pr))
        .filter(|x| {
            needle.is_none_or(|n| {
                x.name.to_lowercase().contains(n)
                    || x.comment.to_lowercase().contains(n)
                    || x.caller_id.is_some_and(|m| m.to_string().to_lowercase().contains(n))
                    || x.remote_address.is_some_and(|ip| ip.to_string().contains(n))
                    || x.routes.iter().any(|r| r.dst.to_string().contains(n))
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
                if !x.routes.is_empty() {
                    o.insert("routes".into(), json!(FramedRoute::list_text(&x.routes)));
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
        assert!(s.store().running().ppp.secrets.get(0).unwrap().disabled);
        s.execute("ppp.secret.set", &json!({"id": "joao@isp", "caller_id": ""})).unwrap();
        assert!(s.store().running().ppp.secrets.get(0).unwrap().caller_id.is_none());
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
    fn limits_as_text_like_the_modal_sends_them() {
        let mut s = Session::virtual_lab();
        s.execute("ppp.secret.add", &json!({"name": "a", "password": "x", "limit_bytes_in": "", "limit_bytes_out": "1000"})).unwrap();
        let x = &s.store().running().ppp.secrets.get(0).unwrap();
        assert_eq!((x.limit_bytes_in, x.limit_bytes_out), (0, 1000));
        s.execute("ppp.secret.set", &json!({"id": "a", "limit_bytes_in": " ", "comment": "c"})).unwrap();
        assert!(s.execute("ppp.secret.set", &json!({"id": "a", "limit_bytes_in": "-1"})).is_err());
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

    #[test]
    fn routes_parse_list_and_round_trip() {
        let mut s = Session::virtual_lab();
        let r = s
            .execute("ppp.secret.add", &json!({
                "name": "empresa", "password": "x", "remote_address": "100.64.9.1",
                "routes": "203.0.113.8/29 0.0.0.0 1, 2001:db8:100::/48 :: 5,198.51.100.0/30 100.64.9.1"
            }))
            .unwrap();
        assert!(r["warnings"].as_array().unwrap().is_empty(), "{r}");
        let l = s.execute("ppp.secret.list", &json!({"find": "203.0.113"})).unwrap();
        assert_eq!(l[0]["routes"], "203.0.113.8/29,2001:db8:100::/48 :: 5,198.51.100.0/30 100.64.9.1 1");
        // A JSON list works too; "" clears.
        s.execute("ppp.secret.set", &json!({"id": "empresa", "routes": ["203.0.113.8/29", "203.0.113.16/28"]})).unwrap();
        assert_eq!(s.store().running().ppp.secrets.get(0).unwrap().routes.len(), 2);
        s.execute("ppp.secret.set", &json!({"id": "empresa", "routes": ""})).unwrap();
        assert!(s.store().running().ppp.secrets.get(0).unwrap().routes.is_empty());
        // Saved as text (and read back by the persisted config).
        s.execute("ppp.secret.set", &json!({"id": "empresa", "routes": "203.0.113.8/29"})).unwrap();
        let j = serde_json::to_value(&s.store().running().ppp.secrets).unwrap();
        assert_eq!(j[0]["routes"][0], "203.0.113.8/29");
        let preview = s.execute("ppp.secret.preview", &json!({"id": "empresa", "comment": "x"})).unwrap();
        assert!(preview["computed"].to_string().contains("203.0.113.8/29"), "{preview}");
    }

    #[test]
    fn routes_that_would_blackhole_someone_are_refused() {
        let mut s = Session::virtual_lab();
        s.execute("ip.pool.add", &json!({"name": "cgnat", "ranges": "100.64.0.0/22"})).unwrap();
        s.execute("ipv6.pool.add", &json!({"name": "pd", "prefix": "2001:db8:200::/40", "prefix_length": 56})).unwrap();
        s.execute("ip.address.add", &json!({"address": "198.51.100.1/24", "interface": "ether1"})).unwrap();
        s.execute("ppp.secret.add", &json!({"name": "a", "password": "x", "routes": "203.0.113.8/29"})).unwrap();
        s.execute("ppp.secret.add", &json!({"name": "fixo", "password": "x", "remote_address": "192.0.2.77"})).unwrap();
        for (routes, why) in [
            ("203.0.113.0/24", "secret a"),
            ("203.0.113.12/30", "secret a"),
            ("100.64.1.0/29", "pool cgnat"),
            ("2001:db8:200::/48", "IPv6 pool pd"),
            ("198.51.100.0/29", "router's own address"),
            ("192.0.2.72/29", "secret fixo"),
            ("0.0.0.0/0", "wider"),
            ("127.0.0.0/30", "loopback"),
            ("fe80::/64", "link-local"),
            ("10.0.0.1/24", "host bits"),
            ("10.1.0.0/24,10.1.0.0/25", "same list"),
        ] {
            let err = s.execute("ppp.secret.add", &json!({"name": "b", "password": "x", "routes": routes})).unwrap_err();
            assert!(err.to_string().contains(why), "{routes}: {err}");
        }
        // A gateway that is not the subscriber's fixed address is a typo.
        let err = s
            .execute("ppp.secret.add", &json!({"name": "b", "password": "x", "remote_address": "192.0.2.9", "routes": "203.0.114.0/29 203.0.114.1"}))
            .unwrap_err();
        assert!(err.to_string().contains("not the subscriber"), "{err}");
        // Without a fixed address it is only a warning.
        let r = s.execute("ppp.secret.add", &json!({"name": "c", "password": "x", "routes": "203.0.114.0/29 203.0.114.1"})).unwrap();
        assert!(r["warnings"].to_string().contains("refused at login"), "{r}");
        // A block inside a connected network warns.
        let r = s.execute("ppp.secret.add", &json!({"name": "d", "password": "x", "routes": "198.51.100.64/29"})).unwrap();
        assert!(r["warnings"].to_string().contains("inside 198.51.100.0/24"), "{r}");
        // The other way round: pools and fixed addresses over a routed block.
        let e = s.execute("ip.pool.add", &json!({"name": "p2", "ranges": "203.0.113.10-203.0.113.20"})).unwrap_err();
        assert!(e.to_string().contains("secret a"), "{e}");
        s.execute("ppp.secret.set", &json!({"id": "c", "routes": "2001:db8:300::/48"})).unwrap();
        let e = s.execute("ipv6.pool.add", &json!({"name": "p6", "prefix": "2001:db8:300::/44", "prefix_length": 64})).unwrap_err();
        assert!(e.to_string().contains("secret c"), "{e}");
        let e = s.execute("ppp.secret.set", &json!({"id": "fixo", "remote_address": "203.0.113.9"})).unwrap_err();
        assert!(e.to_string().contains("secret a"), "{e}");
        // Its own routes do not conflict with themselves on set.
        s.execute("ppp.secret.set", &json!({"id": "a", "routes": "203.0.113.8/29,203.0.113.16/29"})).unwrap();
        // Rollback restores the routes and the index.
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        s.execute("ppp.secret.remove", &json!({"id": "a"})).unwrap();
        s.execute("ppp.secret.add", &json!({"name": "e", "password": "x", "routes": "203.0.113.8/29"})).unwrap();
        s.execute("config.discard", &json!({})).unwrap();
        let e = s.execute("ppp.secret.add", &json!({"name": "e", "password": "x", "routes": "203.0.113.8/29"})).unwrap_err();
        assert!(e.to_string().contains("secret a"), "{e}");
    }

    #[test]
    fn ten_thousand_secrets_with_routes_import_in_one_batch() {
        let mut s = Session::virtual_lab();
        let steps: Vec<Value> = (0..10_000u32)
            .map(|i| {
                let net = format!("{}.{}.{}.0/29", 20 + i / 65536, (i / 256) % 256, i % 256);
                json!({"command": "ppp.secret.add", "params": {"name": format!("u{i}"), "password": "x", "routes": net}})
            })
            .collect();
        let t = std::time::Instant::now();
        s.batch(&Value::Array(steps), true).unwrap();
        // O(log n) per route: a walk of every secret would be 50 M checks.
        assert!(t.elapsed() < std::time::Duration::from_secs(60), "{:?}", t.elapsed());
        let e = s.execute("ppp.secret.add", &json!({"name": "x", "password": "x", "routes": "20.0.7.0/24"})).unwrap_err();
        assert!(e.to_string().contains("secret u7"), "{e}");
    }
}
