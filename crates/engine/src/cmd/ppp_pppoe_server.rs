//! `/interface pppoe-server server` (G4.3d, RouterOS v7): a PPPoE access
//! concentrator on one access interface, served by the daemon's `pppoe`
//! service (`proto-pppoe` + the XDP session map of G4.3c). Defaults follow
//! RouterOS, plus the safe ones it lacks (AC-Cookie, PADI limits, a cap on
//! new sessions per second, `pado_delay_by_load`). A change that ends
//! sessions (interface, disable, remove) says how many and needs
//! `force=yes`.

use corerouter_model::ppp::{
    LoadDelay, MAX_MTU, MAX_PADO_DELAY, MAX_PPPOE_SERVERS, MIN_MTU, PppAuth, PppoeServer,
    VlanRange,
};
use corerouter_model::{IfName, ItemId};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32};
use super::dhcp_client::opt_list;
use super::dhcp_server::find;
use super::ppp_common::{guard_drops, opt_name};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("interface.pppoe-server.server.add", "Add PPPoE Server", [], None,
        "{interface: string, name?: string (default pppoe-<interface>), service_name?: string (empty: any), max_mtu?: int 64..1492 (default 1480), max_mru?: int 64..1492 (default 1480), mrru?: int 512..65535 | disabled, authentication?: [mschap2|mschap1|chap|pap] | string (default all four), keepalive_timeout?: int 1..3600 (s; disabled: no LCP echo) , one_session_per_host?: bool (default yes), max_sessions?: int 0..65534 (0: no limit), pado_delay?: int 0..30000 (ms), default_profile?: string (default default), pppoe_over_vlan_range?: string (100-115,120) | [string], accept_untagged?: bool (default yes), ac_cookie?: bool (default yes, RFC 2516 §9), padi_limit?: int (PADIs answered per second, default 2000; 0: none), mac_padi_limit?: int (per MAC per second, default 1; 0: none), new_session_rate?: int (sessions accepted per second, default 2000; 0: none), pado_delay_by_load?: string (sessions:ms,… as 5000:100,20000:300) | [string], disabled?: bool, comment?: string} → {id, name, warnings}",
        always, add),
    cmd!("interface.pppoe-server.server.set", "Set PPPoE Server", [], None,
        "{id: *hex | name, interface?: string, name?: string, service_name?: string, max_mtu?: int 64..1492, max_mru?: int 64..1492, mrru?: int 512..65535 | disabled, authentication?: [mschap2|mschap1|chap|pap] | string, keepalive_timeout?: int 1..3600 | disabled, one_session_per_host?: bool, max_sessions?: int 0..65534, pado_delay?: int 0..30000, default_profile?: string, pppoe_over_vlan_range?: string | [string], accept_untagged?: bool, ac_cookie?: bool, padi_limit?: int, mac_padi_limit?: int, new_session_rate?: int, pado_delay_by_load?: string | [string], disabled?: bool, comment?: string, force?: bool (apply even if it drops active sessions)} → {id, name, warnings, dropped}",
        has_servers, set),
    cmd!("interface.pppoe-server.server.remove", "Remove PPPoE Server", [], None,
        "{id: *hex | name, force?: bool (remove even with sessions up)} → {id, name, dropped}",
        has_servers, remove),
    cmd!("interface.pppoe-server.server.enable", "Enable PPPoE Server", [], None,
        "{id: *hex | name} → {id, name}", has_servers, enable),
    cmd!("interface.pppoe-server.server.disable", "Disable PPPoE Server", [], None,
        "{id: *hex | name, force?: bool (disable even with sessions up)} → {id, name, dropped}",
        has_servers, disable),
    cmd!(query "interface.pppoe-server.server.list", "PPPoE Servers", [], None,
        "{} → [{id, name, interface, service_name?, max_mtu, max_mru, mrru, authentication, keepalive_timeout, one_session_per_host, max_sessions, pado_delay, default_profile, pppoe_over_vlan_range, accept_untagged, ac_cookie, padi_limit, mac_padi_limit, new_session_rate, pado_delay_by_load, disabled, comment?, flags (X disabled), sessions (up now), warnings}]",
        always, list),
    cmd!(query "interface.pppoe-server.monitor", "PPPoE Server Monitor", [], None,
        "{} → {running, sessions, padi, pado, padr, pads, padt_rx, padt_tx, auth_accept, auth_reject, throttled, dataplane, last_error?}",
        always, monitor),
];

fn has_servers(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ppp.pppoe_servers.is_empty() {
        Err("there are no PPPoE servers (interface.pppoe-server.server.add)".into())
    } else {
        Ok(())
    }
}

fn mtu(p: &Value, key: &str) -> Result<Option<u16>> {
    opt_u32(p, key)?
        .map(|v| {
            u16::try_from(v)
                .ok()
                .filter(|v| (MIN_MTU..=MAX_MTU).contains(v))
                .ok_or_else(|| {
                    EngineError::bad(key, format!("{MIN_MTU}..={MAX_MTU} (RFC 2516 §7: at most 1492 over Ethernet)"))
                })
        })
        .transpose()
}

/// An integer, or `disabled` (`Some(None)`).
fn int_or_disabled(p: &Value, key: &str, range: std::ops::RangeInclusive<u32>) -> Result<Option<Option<u32>>> {
    if let Some(Value::String(t)) = p.get(key) {
        let t = t.trim();
        if t == "disabled" || t == "none" || t.is_empty() {
            return Ok(Some(None));
        }
        return t
            .parse::<u32>()
            .ok()
            .filter(|v| range.contains(v))
            .map(|v| Some(Some(v)))
            .ok_or_else(|| EngineError::bad(key, format!("{}..={} or disabled", range.start(), range.end())));
    }
    opt_u32(p, key)?
        .map(|v| {
            range
                .contains(&v)
                .then_some(Some(v))
                .ok_or_else(|| EngineError::bad(key, format!("{}..={} or disabled", range.start(), range.end())))
        })
        .transpose()
}

fn auths(p: &Value) -> Result<Option<Vec<PppAuth>>> {
    let Some(items) = opt_list(p, "authentication")? else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for t in items {
        let a = PppAuth::parse(&t).ok_or_else(|| {
            let shown: String = t.chars().take(32).collect();
            EngineError::bad("authentication", format!("'{shown}': mschap2, mschap1, chap or pap"))
        })?;
        if !out.contains(&a) {
            out.push(a);
        }
    }
    if out.is_empty() {
        return Err(EngineError::bad(
            "authentication",
            "at least one method (a server without authentication would let anyone in)",
        ));
    }
    out.sort();
    Ok(Some(out))
}

fn vlans(p: &Value) -> Result<Option<Vec<VlanRange>>> {
    let Some(items) = opt_list(p, "pppoe_over_vlan_range")? else {
        return Ok(None);
    };
    let mut out = items
        .iter()
        .map(|t| t.parse::<VlanRange>().map_err(|e| EngineError::bad("pppoe_over_vlan_range", e.to_string())))
        .collect::<Result<Vec<_>>>()?;
    out.sort();
    out.dedup();
    Ok(Some(out))
}

fn tiers(p: &Value) -> Result<Option<Vec<LoadDelay>>> {
    let Some(items) = opt_list(p, "pado_delay_by_load")? else {
        return Ok(None);
    };
    if items.len() > 8 {
        return Err(EngineError::bad("pado_delay_by_load", "at most 8 tiers"));
    }
    let mut out = items
        .iter()
        .map(|t| t.parse::<LoadDelay>().map_err(|e| EngineError::bad("pado_delay_by_load", e.to_string())))
        .collect::<Result<Vec<_>>>()?;
    out.sort();
    Ok(Some(out))
}

fn apply(s: &Session, v: &mut PppoeServer, p: &Value) -> Result<()> {
    let cfg = s.store().candidate();
    if let Some(i) = opt_parse::<IfName>(p, "interface")? {
        if !cfg.interfaces.contains_key(&i) {
            return Err(EngineError::bad("interface", format!("no interface '{i}'")));
        }
        v.interface = i;
    }
    if let Some(n) = opt_name(p, "name")? {
        v.name = n;
    }
    if let Some(t) = opt_text(p, "service_name", 64)? {
        v.service_name = t.trim().to_owned();
    }
    if let Some(m) = mtu(p, "max_mtu")? {
        v.max_mtu = m;
    }
    if let Some(m) = mtu(p, "max_mru")? {
        v.max_mru = m;
    }
    if let Some(m) = int_or_disabled(p, "mrru", 512..=65535)? {
        v.mrru = m.and_then(|m| u16::try_from(m).ok());
    }
    if let Some(a) = auths(p)? {
        v.authentication = a;
    }
    if let Some(k) = int_or_disabled(p, "keepalive_timeout", 1..=3600)? {
        v.keepalive_timeout = k;
    }
    for (key, slot) in [
        ("one_session_per_host", &mut v.one_session_per_host),
        ("accept_untagged", &mut v.accept_untagged),
        ("ac_cookie", &mut v.ac_cookie),
        ("disabled", &mut v.disabled),
    ] {
        if let Some(b) = opt_bool(p, key)? {
            *slot = b;
        }
    }
    if let Some(n) = opt_u32(p, "max_sessions")? {
        if n > u32::from(proto_max_sid()) {
            return Err(EngineError::bad("max_sessions", "0..=65534 (RFC 2516 §4: one SESSION_ID space)"));
        }
        v.max_sessions = n;
    }
    if let Some(n) = opt_u32(p, "pado_delay")? {
        if n > MAX_PADO_DELAY {
            return Err(EngineError::bad("pado_delay", format!("0..={MAX_PADO_DELAY} ms")));
        }
        v.pado_delay = n;
    }
    for (key, slot) in [
        ("padi_limit", &mut v.padi_limit),
        ("mac_padi_limit", &mut v.mac_padi_limit),
        ("new_session_rate", &mut v.new_session_rate),
    ] {
        if let Some(n) = opt_u32(p, key)? {
            if n > 1_000_000 {
                return Err(EngineError::bad(key, "0..=1000000 per second"));
            }
            *slot = n;
        }
    }
    if let Some(t) = opt_str(p, "default_profile")? {
        let t = t.trim();
        if cfg.ppp.profile(t).is_none() {
            let shown: String = t.chars().take(64).collect();
            return Err(EngineError::bad("default_profile", format!("no profile '{shown}' (ppp.profile.add)")));
        }
        t.clone_into(&mut v.default_profile);
    }
    if let Some(r) = vlans(p)? {
        v.pppoe_over_vlan_range = r;
    }
    if let Some(t) = tiers(p)? {
        v.pado_delay_by_load = t;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        v.comment = c;
    }
    Ok(())
}

fn proto_max_sid() -> u16 {
    65_534
}

/// Conflicts refuse; risks come back as warnings.
fn check(s: &Session, v: &PppoeServer) -> Result<Vec<String>> {
    let cfg = s.store().candidate();
    let others = cfg.ppp.pppoe_servers.iter().filter(|o| o.id != v.id);
    for o in others {
        if o.name == v.name {
            return Err(EngineError::bad("name", format!("server '{}' exists", v.name)));
        }
        // One SESSION_ID space per port (RFC 2516 §4): two servers on one
        // interface would hand out the same ids. Several service names on
        // one port are a later gap.
        if !o.disabled && !v.disabled && o.interface == v.interface {
            return Err(EngineError::bad(
                "interface",
                format!("server {} already serves {} (one enabled PPPoE server per interface)", o.name, v.interface),
            ));
        }
    }
    let mut w = Vec::new();
    if cfg.ip.addresses.iter().any(|a| a.interface == v.interface && !a.disabled) {
        w.push(format!("{} has an IP address: PPPoE does not need one there, and the subscribers' LAN sees the router (RouterOS advises against it)", v.interface));
    }
    if !v.ac_cookie {
        w.push("ac_cookie=no: forged PADRs create sessions (RFC 2516 §9)".into());
    }
    if !v.one_session_per_host {
        w.push("one_session_per_host=no: a CPE that reboots without PADT holds two addresses until the keepalive notices".into());
    }
    if v.authentication.contains(&PppAuth::Pap) && v.authentication.len() == 1 {
        w.push("only pap: the password crosses the access network in clear".into());
    }
    if v.keepalive_timeout.is_none() {
        w.push("keepalive disabled: a dead CPE keeps its session and address until session_timeout".into());
    }
    if let Some(vid) = v.pppoe_over_vlan_range.iter().find_map(|r| {
        cfg.interfaces.values().find_map(|i| match &i.kind {
            corerouter_model::InterfaceKind::Vlan { vlan_id: id, parent }
                if *parent == v.interface && (r.first..=r.last).contains(&id.get()) =>
            {
                Some(id.get())
            }
            _ => None,
        })
    }) {
        w.push(format!("VLAN {vid} of {} is also a VLAN interface: its frames go to that interface, not to this server", v.interface));
    }
    Ok(w)
}

fn index(s: &Session, p: &Value) -> Result<usize> {
    find(&s.store().candidate().ppp.pppoe_servers, p, |x| x.id, |x| Some(x.name.as_str()), "PPPoE server")
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let interface: IfName = opt_parse(p, "interface")?.ok_or_else(|| EngineError::bad("interface", "is required"))?;
    if s.store().candidate().ppp.pppoe_servers.len() >= MAX_PPPOE_SERVERS {
        return Err(EngineError::bad("interface", format!("at most {MAX_PPPOE_SERVERS} PPPoE servers")));
    }
    let mut v: PppoeServer = serde_json::from_value(json!({"id": "*0", "interface": interface.as_str()}))
        .map_err(|e| EngineError::bad("interface", e.to_string()))?;
    v.name = format!("pppoe-{interface}");
    apply(s, &mut v, p)?;
    let ppp = &mut s.store_mut().candidate_mut().ppp;
    v.id = ppp.next_id();
    let w = check(s, &v)?;
    let out = json!({"id": v.id, "name": v.name, "warnings": w});
    s.store_mut().candidate_mut().ppp.pppoe_servers.push(v);
    Ok(out)
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let Some(old) = s.store().candidate().ppp.pppoe_servers.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such server"));
    };
    let mut v = old.clone();
    apply(s, &mut v, p)?;
    let w = check(s, &v)?;
    // What restarts the server's sockets ends its sessions; the rest
    // applies to new sessions.
    let restarts = v.interface != old.interface
        || (v.disabled && !old.disabled)
        || v.service_name != old.service_name
        || v.pppoe_over_vlan_range != old.pppoe_over_vlan_range
        || v.accept_untagged != old.accept_untagged;
    let dropped = if restarts {
        guard_drops(s, p, &format!("this change to {}", old.name), |a| a.server == old.name)?
    } else {
        0
    };
    let out = json!({"id": v.id, "name": v.name, "warnings": w, "dropped": dropped});
    if let Some(slot) = s.store_mut().candidate_mut().ppp.pppoe_servers.get_mut(i) {
        *slot = v;
    }
    Ok(out)
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let Some(v) = s.store().candidate().ppp.pppoe_servers.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such server"));
    };
    let dropped = guard_drops(s, p, &format!("removing {}", v.name), |a| a.server == v.name)?;
    s.store_mut().candidate_mut().ppp.pppoe_servers.retain(|x| x.id != v.id);
    Ok(json!({"id": v.id, "name": v.name, "dropped": dropped}))
}

fn toggle(s: &mut Session, p: &Value, disabled: bool) -> Result<(ItemId, String, usize)> {
    let i = index(s, p)?;
    let Some(mut v) = s.store().candidate().ppp.pppoe_servers.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such server"));
    };
    let dropped = if disabled && !v.disabled {
        guard_drops(s, p, &format!("disabling {}", v.name), |a| a.server == v.name)?
    } else {
        0
    };
    v.disabled = disabled;
    check(s, &v)?;
    let out = (v.id, v.name.clone(), dropped);
    if let Some(slot) = s.store_mut().candidate_mut().ppp.pppoe_servers.get_mut(i) {
        *slot = v;
    }
    Ok(out)
}

fn enable(s: &mut Session, p: &Value) -> Result<Value> {
    let (id, name, _) = toggle(s, p, false)?;
    Ok(json!({"id": id, "name": name}))
}

fn disable(s: &mut Session, p: &Value) -> Result<Value> {
    let (id, name, dropped) = toggle(s, p, true)?;
    Ok(json!({"id": id, "name": name, "dropped": dropped}))
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    let active = s.ppp_active();
    let servers = s.store().candidate().ppp.pppoe_servers.clone();
    let rows: Vec<Value> = servers
        .iter()
        .map(|v| {
            let mut row = json!({
                "id": v.id,
                "name": v.name,
                "interface": v.interface,
                "max_mtu": v.max_mtu,
                "max_mru": v.max_mru,
                "mrru": v.mrru.map_or_else(|| json!("disabled"), |m| json!(m)),
                "authentication": v.authentication.iter().map(|a| a.as_str()).collect::<Vec<_>>(),
                "keepalive_timeout": v.keepalive_timeout.map_or_else(|| json!("disabled"), |k| json!(k)),
                "one_session_per_host": v.one_session_per_host,
                "max_sessions": v.max_sessions,
                "pado_delay": v.pado_delay,
                "default_profile": v.default_profile,
                "pppoe_over_vlan_range": v.pppoe_over_vlan_range.iter().map(ToString::to_string).collect::<Vec<_>>().join(","),
                "accept_untagged": v.accept_untagged,
                "ac_cookie": v.ac_cookie,
                "padi_limit": v.padi_limit,
                "mac_padi_limit": v.mac_padi_limit,
                "new_session_rate": v.new_session_rate,
                "pado_delay_by_load": v.pado_delay_by_load.iter().map(ToString::to_string).collect::<Vec<_>>().join(","),
                "disabled": v.disabled,
                "flags": if v.disabled { "X" } else { "" },
                "sessions": active.iter().filter(|a| a.server == v.name).count(),
                "warnings": check(s, v).unwrap_or_default(),
            });
            if let Some(o) = row.as_object_mut() {
                if !v.service_name.is_empty() {
                    o.insert("service_name".into(), json!(v.service_name));
                }
                if !v.comment.is_empty() {
                    o.insert("comment".into(), json!(v.comment));
                }
            }
            row
        })
        .collect();
    Ok(Value::Array(rows))
}

fn monitor(s: &mut Session, _: &Value) -> Result<Value> {
    let Some(b) = s.ppp_backend() else {
        return Ok(json!({"running": false, "sessions": 0, "padi": 0, "pado": 0, "padr": 0, "pads": 0,
            "padt_rx": 0, "padt_tx": 0, "auth_accept": 0, "auth_reject": 0, "throttled": 0, "dataplane": false}));
    };
    let st = b.stats();
    let mut v = serde_json::to_value(&st).map_err(|e| EngineError::bad("stats", e.to_string()))?;
    if let Some(o) = v.as_object_mut() {
        o.insert("running".into(), json!(true));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use corerouter_model::MacAddr;
    use corerouter_model::ppp::{ActiveSession, HistoryEntry, ServiceStats, Why};

    use super::*;
    use crate::ppp::PppBackend;

    pub(crate) struct Fake(pub Vec<ActiveSession>);

    impl PppBackend for Fake {
        fn active(&self) -> Vec<ActiveSession> {
            self.0.clone()
        }
        fn terminate(&self, ids: &[String]) -> usize {
            self.0.iter().filter(|a| ids.contains(&a.id)).count()
        }
        fn history(&self) -> Vec<HistoryEntry> {
            Vec::new()
        }
        fn why(&self, _: Option<&str>, _: Option<MacAddr>) -> Why {
            Why::default()
        }
        fn stats(&self) -> ServiceStats {
            ServiceStats { sessions: self.0.len() as u64, ..ServiceStats::default() }
        }
    }

    #[test]
    fn add_list_set_remove() {
        let mut s = Session::virtual_lab();
        let r = s
            .execute("interface.pppoe-server.server.add", &json!({
                "interface": "ether2", "service_name": "isp", "authentication": "pap,chap",
                "pppoe_over_vlan_range": "100-115,120", "pado_delay_by_load": "5000:100,1000:20",
                "keepalive_timeout": "disabled"
            }))
            .unwrap();
        assert_eq!(r["name"], "pppoe-ether2");
        assert!(r["warnings"].to_string().contains("keepalive disabled"), "{r}");
        let l = s.execute("interface.pppoe-server.server.list", &json!({})).unwrap();
        let row = &l[0];
        assert_eq!(row["authentication"], json!(["chap", "pap"]));
        assert_eq!(row["pppoe_over_vlan_range"], "100-115,120");
        assert_eq!(row["pado_delay_by_load"], "1000:20,5000:100");
        assert_eq!(row["keepalive_timeout"], "disabled");
        assert_eq!(row["max_mtu"], 1480);
        assert_eq!(row["ac_cookie"], true);
        s.execute("interface.pppoe-server.server.set", &json!({"id": "pppoe-ether2", "max_mru": 1492, "keepalive_timeout": 30})).unwrap();
        let v = &s.store().running().ppp.pppoe_servers[0];
        assert_eq!((v.max_mru, v.keepalive_timeout), (1492, Some(30)));
        s.execute("interface.pppoe-server.server.disable", &json!({"id": "pppoe-ether2"})).unwrap();
        assert!(s.store().running().ppp.pppoe_servers[0].disabled);
        s.execute("interface.pppoe-server.server.remove", &json!({"id": "pppoe-ether2"})).unwrap();
        assert!(s.store().running().ppp.pppoe_servers.is_empty());
    }

    #[test]
    fn bad_values_and_conflicts_are_refused() {
        let mut s = Session::virtual_lab();
        s.execute("interface.pppoe-server.server.add", &json!({"interface": "ether2"})).unwrap();
        for p in [
            json!({"interface": "nope0"}),
            json!({"interface": "ether2", "name": "other"}),
            json!({"interface": "ether2", "name": "other", "service_name": "x"}),
            json!({"interface": "ether3", "max_mtu": 1500}),
            json!({"interface": "ether3", "authentication": ""}),
            json!({"interface": "ether3", "authentication": "eap"}),
            json!({"interface": "ether3", "max_sessions": 70000}),
            json!({"interface": "ether3", "pado_delay": 60000}),
            json!({"interface": "ether3", "pppoe_over_vlan_range": "0-10"}),
            json!({"interface": "ether3", "default_profile": "nope"}),
            json!({"interface": "ether3", "mrru": 100}),
            json!({"interface": "ether3", "pado_delay_by_load": "x"}),
            json!({"interface": "ether3", "name": "pppoe-ether2"}),
        ] {
            let err = s.execute("interface.pppoe-server.server.add", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        assert_eq!(s.store().candidate().ppp.pppoe_servers.len(), 1);
    }

    #[test]
    fn changes_that_drop_sessions_need_force_and_rollback_restores() {
        let mut s = Session::virtual_lab();
        s.execute("interface.pppoe-server.server.add", &json!({"interface": "ether2"})).unwrap();
        let up = |i: u16| ActiveSession { id: format!("*1-{i}"), name: format!("u{i}"), server: "pppoe-ether2".into(), ..ActiveSession::default() };
        s.set_ppp_backend(Arc::new(Fake((1..=3).map(up).collect())));
        let err = s.execute("interface.pppoe-server.server.disable", &json!({"id": "pppoe-ether2"})).unwrap_err();
        assert!(err.to_string().contains("drops 3 active session"), "{err}");
        assert!(s.execute("interface.pppoe-server.server.set", &json!({"id": "pppoe-ether2", "interface": "ether3"})).is_err());
        assert!(s.execute("interface.pppoe-server.server.remove", &json!({"id": "pppoe-ether2"})).is_err());
        // Changes for new sessions only go through.
        s.execute("interface.pppoe-server.server.set", &json!({"id": "pppoe-ether2", "max_mtu": 1400})).unwrap();
        let l = s.execute("interface.pppoe-server.server.list", &json!({})).unwrap();
        assert_eq!(l[0]["sessions"], 3);
        assert_eq!(s.execute("interface.pppoe-server.monitor", &json!({})).unwrap()["sessions"], 3);
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        let r = s.execute("interface.pppoe-server.server.remove", &json!({"id": "pppoe-ether2", "force": true})).unwrap();
        assert_eq!(r["dropped"], 3);
        s.execute("config.discard", &json!({})).unwrap();
        assert_eq!(s.store().candidate().ppp.pppoe_servers.len(), 1);
    }
}
