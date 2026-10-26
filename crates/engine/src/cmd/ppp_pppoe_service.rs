//! The Service-Name table of a PPPoE server (G4.3k), row by row: one server
//! per access port with several services, each with its profile and what a
//! PADI for it gets (Junos `service-name-tables`: terminate, delay, drop),
//! plus the rows of the empty name and of any other name. The whole table
//! is also `services` of `interface.pppoe-server.server.add/set`.
//!
//! A change applies to new sessions: the ones up keep going (the BNG
//! re-reads the table without closing its port).

use corerouter_model::ppp::{MAX_PADO_DELAY, PppoeServer};
use corerouter_model::pppoe_services::{
    PppoeService, ServiceAction, ServiceName, normalize,
};
use serde_json::{Map, Value, json};

use super::args::{opt_str, opt_u32, req_str};
use super::dhcp_server::find;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("interface.pppoe-server.server.service.add", "Add PPPoE Service Name", [], None,
        "{server: *hex | name, name: string (a Service-Name, or empty | any), profile?: string (empty: the server's default_profile), action?: terminate|delay|drop (default terminate), pado_delay?: int 0..30000 (ms, with delay), max_sessions?: int (0: no limit), padi_limit?: int (PADIs per second, 0: no limit)} → {server, name, warnings}",
        has_servers, add),
    cmd!("interface.pppoe-server.server.service.set", "Set PPPoE Service Name", [], None,
        "{server: *hex | name, name: string (the row: a Service-Name, empty or any), new_name?: string (rename a named row), profile?: string (empty: the server's default_profile), action?: terminate|delay|drop, pado_delay?: int 0..30000, max_sessions?: int, padi_limit?: int} → {server, name, warnings}",
        has_servers, set),
    cmd!("interface.pppoe-server.server.service.remove", "Remove PPPoE Service Name", [], None,
        "{server: *hex | name, name: string (a named row; empty and any always exist: set their action)} → {server, name}",
        has_servers, remove),
    cmd!(query "interface.pppoe-server.server.service.list", "PPPoE Service Names", [], None,
        "{server: *hex | name (the table travels in the server's services; /export writes it there)} → [{server, name, special (empty or any row), profile?, action, pado_delay, max_sessions, padi_limit, sessions (up now)}]",
        always, list),
];

fn has_servers(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ppp.pppoe_servers.is_empty() {
        Err("there are no PPPoE servers (interface.pppoe-server.server.add)".into())
    } else {
        Ok(())
    }
}

fn bad_row(e: impl std::fmt::Display) -> EngineError {
    EngineError::bad("services", e.to_string())
}

/// One row from `{name, profile?, action?, …}`; `base` is the row being
/// changed (its values stay where a key is absent).
fn row(o: &Value, base: Option<&PppoeService>, key: &str) -> Result<PppoeService> {
    let name: ServiceName = match (opt_str(o, "name")?, base) {
        (Some(n), _) => n.parse().map_err(|e| EngineError::bad(key, format!("{e}")))?,
        (None, Some(b)) => b.name.clone(),
        (None, None) => return Err(EngineError::bad(key, "name is required (a Service-Name, empty or any)")),
    };
    let mut r = base.cloned().unwrap_or_else(|| PppoeService::new(name.clone(), ServiceAction::Terminate));
    r.name = name;
    if let Some(t) = opt_str(o, "profile")? {
        let t = t.trim();
        r.profile = (!t.is_empty()).then(|| t.chars().take(64).collect());
    }
    if let Some(t) = opt_str(o, "action")? {
        r.action = ServiceAction::parse(t).ok_or_else(|| EngineError::bad(key, "action: terminate, delay or drop"))?;
    }
    if let Some(n) = opt_u32(o, "pado_delay")? {
        if n > MAX_PADO_DELAY {
            return Err(EngineError::bad(key, format!("pado_delay: 0..={MAX_PADO_DELAY} ms")));
        }
        r.pado_delay = n;
    }
    for (k, slot) in [("max_sessions", &mut r.max_sessions), ("padi_limit", &mut r.padi_limit)] {
        if let Some(n) = opt_u32(o, k)? {
            if n > 1_000_000 {
                return Err(EngineError::bad(key, format!("{k}: 0..=1000000")));
            }
            *slot = n;
        }
    }
    // `delay` without a delay is a typo for terminate; a delay asked for
    // makes the action delay (the modal fills one field, not two).
    if r.pado_delay > 0 && r.action == ServiceAction::Terminate && opt_str(o, "action")?.is_none() {
        r.action = ServiceAction::Delay;
    }
    Ok(r)
}

const ROW_KEYS: [&str; 6] = ["name", "profile", "action", "pado_delay", "max_sessions", "padi_limit"];

/// `services`: `[{name, profile?, action?, pado_delay?, max_sessions?,
/// padi_limit?}]`, or the same list as JSON text (the terminal). `None`
/// when absent.
pub(super) fn opt_services(p: &Value) -> Result<Option<Vec<PppoeService>>> {
    let parsed;
    let items = match p.get("services") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(t)) if t.trim().is_empty() => return Ok(Some(Vec::new())),
        Some(Value::String(t)) if t.len() <= 65_536 => {
            parsed = serde_json::from_str::<Value>(t).map_err(|_| bad_row("a list of {name, profile?, action?, …} (JSON)"))?;
            parsed.as_array().ok_or_else(|| bad_row("a list of {name, profile?, action?, …}"))?
        }
        Some(Value::Array(a)) => a,
        Some(_) => return Err(bad_row("a list of {name, profile?, action?, …}")),
    };
    if items.len() > corerouter_model::pppoe_services::MAX_SERVICES + 2 {
        return Err(bad_row(format!("at most {} rows", corerouter_model::pppoe_services::MAX_SERVICES + 2)));
    }
    let mut out = Vec::with_capacity(items.len());
    for it in items {
        let Some(o) = it.as_object() else {
            return Err(bad_row("each row is {name, profile?, action?, …}"));
        };
        if let Some(k) = o.keys().find(|k| !ROW_KEYS.contains(&k.as_str())) {
            let shown: String = k.chars().take(32).collect();
            return Err(bad_row(format!("unknown key '{shown}' in a row ({})", ROW_KEYS.join(", "))));
        }
        out.push(row(it, None, "services")?);
    }
    Ok(Some(out))
}

/// The table's rows checked against the config: profiles exist. Risks
/// come back as warnings.
pub(super) fn check_rows(s: &Session, rows: &[PppoeService]) -> Result<Vec<String>> {
    let cfg = s.store().candidate();
    let mut w = Vec::new();
    for r in rows {
        if let Some(p) = &r.profile
            && cfg.ppp.profile(p).is_none()
        {
            return Err(EngineError::bad("services", format!("{}: no profile '{p}' (ppp.profile.add)", r.name)));
        }
        match (&r.name, r.action) {
            (ServiceName::Empty, ServiceAction::Drop) => w.push(
                "the empty Service-Name is dropped: most CPEs ask for no name and get no answer".to_owned(),
            ),
            (ServiceName::Any, ServiceAction::Drop) if rows.iter().any(|x| !x.name.is_special()) => w.push(
                "names not in the table are dropped: the silence tells a scanner which names exist (RFC 2516 §9 recommends never refusing by name)".to_owned(),
            ),
            _ => {}
        }
    }
    if rows.iter().all(|r| !r.accepts()) {
        w.push("every row drops: this server answers no one".into());
    }
    Ok(w)
}

/// The JSON of one row (`list`, the servers' list).
fn row_json(server: &str, r: &PppoeService, sessions: usize) -> Value {
    let mut m = Map::new();
    m.insert("server".into(), json!(server));
    m.insert("name".into(), json!(r.name.to_string()));
    m.insert("special".into(), json!(r.name.is_special()));
    if let Some(p) = &r.profile {
        m.insert("profile".into(), json!(p));
    }
    m.insert("action".into(), json!(r.action.as_str()));
    m.insert("pado_delay".into(), json!(r.pado_delay));
    m.insert("max_sessions".into(), json!(r.max_sessions));
    m.insert("padi_limit".into(), json!(r.padi_limit));
    m.insert("sessions".into(), json!(sessions));
    Value::Object(m)
}

fn server_index(s: &Session, p: &Value) -> Result<usize> {
    let id = req_str(p, "server")?;
    find(&s.store().candidate().ppp.pppoe_servers, &json!({"id": id}), |x| x.id, |x| Some(x.name.as_str()), "PPPoE server")
        .map_err(|e| match e {
            EngineError::BadParam { reason, .. } => EngineError::bad("server", reason),
            other => other,
        })
}

/// Runs `f` on the server's table, normalizes and checks it, and stores.
fn edit(
    s: &mut Session,
    p: &Value,
    f: impl FnOnce(&mut Vec<PppoeService>) -> Result<String>,
) -> Result<Value> {
    let i = server_index(s, p)?;
    let Some(mut v) = s.store().candidate().ppp.pppoe_servers.get(i).cloned() else {
        return Err(EngineError::bad("server", "no such server"));
    };
    let mut rows = v.service_table();
    let name = f(&mut rows)?;
    let rows = normalize(rows).map_err(|e| EngineError::bad("name", e))?;
    let w = check_rows(s, &rows)?;
    v.services = rows;
    v.service_name.clear();
    let out = json!({"server": v.name, "name": name, "warnings": w});
    if let Some(slot) = s.store_mut().candidate_mut().ppp.pppoe_servers.get_mut(i) {
        *slot = v;
    }
    Ok(out)
}

fn named(p: &Value) -> Result<ServiceName> {
    req_str(p, "name")?.parse().map_err(|e| EngineError::bad("name", format!("{e}")))
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let r = row(p, None, "name")?;
    edit(s, p, |rows| {
        if let Some(old) = rows.iter_mut().find(|x| x.name == r.name) {
            if !r.name.is_special() {
                return Err(EngineError::bad("name", format!("'{}' is already in the table (service.set)", r.name)));
            }
            // empty and any always exist: add sets them.
            *old = r.clone();
        } else {
            rows.insert(0, r.clone());
        }
        Ok(r.name.to_string())
    })
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let name = named(p)?;
    let new_name = opt_str(p, "new_name")?
        .map(|t| t.parse::<ServiceName>().map_err(|e| EngineError::bad("new_name", format!("{e}"))))
        .transpose()?;
    edit(s, p, |rows| {
        let Some(at) = rows.iter().position(|x| x.name == name) else {
            return Err(EngineError::bad("name", format!("no row '{name}' in the table")));
        };
        let mut q = p.clone();
        if let Some(o) = q.as_object_mut() {
            o.remove("name");
        }
        let mut r = row(&q, rows.get(at), "name")?;
        if let Some(n) = new_name {
            if name.is_special() || n.is_special() {
                return Err(EngineError::bad("new_name", "the empty and any rows keep their names"));
            }
            r.name = n;
        }
        let shown = r.name.to_string();
        if let Some(slot) = rows.get_mut(at) {
            *slot = r;
        }
        Ok(shown)
    })
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let name = named(p)?;
    if name.is_special() {
        return Err(EngineError::bad("name", "the empty and any rows always exist: set their action (drop) instead"));
    }
    let out = edit(s, p, |rows| {
        let before = rows.len();
        rows.retain(|x| x.name != name);
        if rows.len() == before {
            return Err(EngineError::bad("name", format!("no row '{name}' in the table")));
        }
        Ok(name.to_string())
    })?;
    Ok(json!({"server": out.get("server"), "name": out.get("name")}))
}

/// Sessions up per (server, Service-Name).
fn counts(s: &Session) -> std::collections::HashMap<(String, String), usize> {
    let mut m = std::collections::HashMap::new();
    for a in s.ppp_active() {
        *m.entry((a.server, a.service_name.unwrap_or_default())).or_insert(0) += 1;
    }
    m
}

/// Sessions of a row: its name's, and for `empty`/`any` those that landed
/// there.
fn row_sessions(
    counts: &std::collections::HashMap<(String, String), usize>,
    v: &PppoeServer,
    rows: &[PppoeService],
    r: &PppoeService,
) -> usize {
    match &r.name {
        ServiceName::Name(n) => counts.get(&(v.name.clone(), n.clone())).copied().unwrap_or(0),
        ServiceName::Empty => counts.get(&(v.name.clone(), String::new())).copied().unwrap_or(0),
        ServiceName::Any => counts
            .iter()
            .filter(|((srv, n), _)| {
                *srv == v.name && !n.is_empty() && !rows.iter().any(|x| x.name == ServiceName::Name(n.clone()))
            })
            .map(|(_, c)| *c)
            .sum(),
    }
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let i = server_index(s, p)?;
    let Some(v) = s.store().candidate().ppp.pppoe_servers.get(i).cloned() else {
        return Err(EngineError::bad("server", "no such server"));
    };
    let c = counts(s);
    let rows = v.service_table();
    Ok(Value::Array(rows.iter().map(|r| row_json(&v.name, r, row_sessions(&c, &v, &rows, r))).collect()))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use corerouter_model::ppp::ActiveSession;

    use super::*;
    use crate::cmd::ppp_pppoe_server::tests::Fake;

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.execute("ppp.profile.add", &json!({"name": "iptv"})).unwrap();
        s.execute("interface.pppoe-server.server.add", &json!({"interface": "ether2"})).unwrap();
        s
    }

    fn table(s: &Session) -> Vec<PppoeService> {
        s.store().running().ppp.pppoe_servers[0].service_table()
    }

    #[test]
    fn a_new_server_serves_every_name() {
        let s = lab();
        let t = table(&s);
        assert_eq!(t.len(), 2);
        assert!(t.iter().all(PppoeService::accepts));
    }

    #[test]
    fn rows_add_set_remove_and_list() {
        let mut s = lab();
        s.execute("interface.pppoe-server.server.service.add", &json!({"server": "pppoe-ether2", "name": "internet"})).unwrap();
        s.execute("interface.pppoe-server.server.service.add", &json!({"server": "pppoe-ether2", "name": "tv", "profile": "iptv", "pado_delay": 300, "max_sessions": 10})).unwrap();
        let r = s.execute("interface.pppoe-server.server.service.set", &json!({"server": "pppoe-ether2", "name": "any", "action": "drop"})).unwrap();
        assert!(r["warnings"].to_string().contains("RFC 2516 §9"), "{r}");
        let t = table(&s);
        let names: Vec<String> = t.iter().map(|r| r.name.to_string()).collect();
        assert_eq!(names, ["tv", "internet", "empty", "any"]);
        assert_eq!(t[0].action, ServiceAction::Delay, "a delay makes the action delay");
        assert_eq!(t[0].profile.as_deref(), Some("iptv"));
        s.execute("interface.pppoe-server.server.service.set", &json!({"server": "pppoe-ether2", "name": "tv", "new_name": "iptv", "action": "terminate", "pado_delay": 0})).unwrap();
        assert_eq!(table(&s)[0].name, ServiceName::Name("iptv".into()));
        let up = |n: &str, svc: Option<&str>| ActiveSession {
            id: format!("*1-{n}"),
            name: n.into(),
            server: "pppoe-ether2".into(),
            service_name: svc.map(Into::into),
            ..ActiveSession::default()
        };
        s.set_ppp_backend(Arc::new(Fake(vec![up("a", Some("iptv")), up("b", Some("iptv")), up("c", Some("")), up("d", Some("other"))])));
        let l = s.execute("interface.pppoe-server.server.service.list", &json!({"server": "pppoe-ether2"})).unwrap();
        let by = |n: &str| l.as_array().unwrap().iter().find(|r| r["name"] == n).unwrap().clone();
        assert_eq!(by("iptv")["sessions"], 2);
        assert_eq!(by("empty")["sessions"], 1);
        assert_eq!(by("any")["sessions"], 1);
        assert_eq!(by("any")["special"], true);
        s.execute("interface.pppoe-server.server.service.remove", &json!({"server": "pppoe-ether2", "name": "internet"})).unwrap();
        assert_eq!(table(&s).len(), 3);
    }

    #[test]
    fn bad_rows_are_refused_and_nothing_changes() {
        let mut s = lab();
        s.execute("interface.pppoe-server.server.service.add", &json!({"server": "pppoe-ether2", "name": "internet"})).unwrap();
        let before = table(&s);
        for (cmd, p) in [
            ("add", json!({"server": "pppoe-ether2", "name": "internet"})),
            ("add", json!({"server": "pppoe-ether2", "name": "x", "profile": "nope"})),
            ("add", json!({"server": "pppoe-ether2", "name": "x", "action": "maybe"})),
            ("add", json!({"server": "pppoe-ether2", "name": "x", "action": "delay"})),
            ("add", json!({"server": "pppoe-ether2", "name": "x", "pado_delay": 60000})),
            ("add", json!({"server": "nope", "name": "x"})),
            ("set", json!({"server": "pppoe-ether2", "name": "nope", "action": "drop"})),
            ("set", json!({"server": "pppoe-ether2", "name": "any", "new_name": "x"})),
            ("remove", json!({"server": "pppoe-ether2", "name": "empty"})),
            ("remove", json!({"server": "pppoe-ether2", "name": "nope"})),
        ] {
            let err = s.execute(&format!("interface.pppoe-server.server.service.{cmd}"), &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{cmd} {p}: {err}");
        }
        assert_eq!(table(&s), before);
    }

    #[test]
    fn the_whole_table_through_the_server_and_rollback() {
        let mut s = lab();
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        s.execute("interface.pppoe-server.server.set", &json!({"id": "pppoe-ether2", "services": [
            {"name": "internet", "profile": "iptv"},
            {"name": "empty", "action": "drop"},
        ]})).unwrap();
        let t = s.store().candidate().ppp.pppoe_servers[0].service_table();
        assert_eq!(t.len(), 3);
        assert_eq!(t[1].action, ServiceAction::Drop);
        for bad in [
            json!([{"name": "a"}, {"name": "a"}]),
            json!([{"name": "empty"}, {"name": "empty", "action": "drop"}]),
            json!([{"name": "a", "colour": "red"}]),
            json!("not json"),
        ] {
            let e = s.execute("interface.pppoe-server.server.set", &json!({"id": "pppoe-ether2", "services": bad})).unwrap_err();
            assert!(matches!(e, EngineError::BadParam { .. }), "{bad}: {e}");
        }
        s.execute("config.discard", &json!({})).unwrap();
        assert_eq!(s.store().candidate().ppp.pppoe_servers[0].service_table().len(), 2);
    }

    #[test]
    fn a_routeros_service_name_is_migrated_on_the_first_change() {
        let mut s = lab();
        // A config from before G4.3k: only `service_name`.
        let mut cfg = s.store().running().clone();
        cfg.ppp.pppoe_servers[0].service_name = "isp".into();
        cfg.ppp.pppoe_servers[0].services.clear();
        s.store_mut().candidate_mut().ppp = cfg.ppp;
        s.execute("config.commit", &json!({})).ok();
        let v = &s.store().candidate().ppp.pppoe_servers[0];
        assert!(v.services.is_empty());
        let t = v.service_table();
        assert_eq!(t.iter().map(|r| r.name.to_string()).collect::<Vec<_>>(), ["isp", "empty", "any"]);
        assert!(!t[2].accepts(), "RouterOS: another name is not served");
        s.execute("interface.pppoe-server.server.set", &json!({"id": "pppoe-ether2", "max_mtu": 1400})).unwrap();
        let v = &s.store().candidate().ppp.pppoe_servers[0];
        assert!(v.service_name.is_empty());
        assert_eq!(v.services, t, "written as the table it meant");
        // `service_name` still works (RouterOS, the importer).
        s.execute("interface.pppoe-server.server.set", &json!({"id": "pppoe-ether2", "service_name": ""})).unwrap();
        assert!(s.store().candidate().ppp.pppoe_servers[0].service_table().iter().all(PppoeService::accepts));
    }
}
