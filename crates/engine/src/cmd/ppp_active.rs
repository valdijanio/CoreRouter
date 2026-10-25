//! `/ppp active` (G4.3d): the sessions up now, ending one, and the
//! diagnosis the WinBox lacks: `ppp.why` (how far the logins of a user or
//! MAC get, and why the last one stopped) and `ppp.history`. All read the
//! daemon's `pppoe` service from memory ([`crate::ppp::PppBackend`]).

use corerouter_model::MacAddr;
use corerouter_model::ppp::ActiveSession;
use serde_json::{Value, json};

use super::args::{opt_str, opt_text, opt_u32};
use super::dhcp_client::opt_list;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "ppp.active.list", "PPP Active Connections", [], None,
        "{find?: string (in name, caller id, address, IPv6 prefixes or circuit id), server?: string, limit?: int 1..100000 (default 10000)} → {total, running (the pppoe service is up), rows: [{id, name, service, caller_id, address?, uptime, uptime_secs, session_id, server, interface, vlan?, circuit_id?, remote_id?, rate_limit?, profile, encoding, radius, rx_bytes, tx_bytes, rx_packets, tx_packets, mtu, limit_bytes_in?, limit_bytes_out?, ipv6_prefix? (the link's /64, RA), delegated_prefix? (DHCPv6-PD), delegated_bound (held by the CPE's DHCPv6), link_local? (IPv6CP)}]}",
        always, list),
    cmd!("ppp.active.remove", "Disconnect PPP Session", [], None,
        "{id?: string | [string] (the session ids of ppp.active.list; at most 100000), name?: string (every session of this user), server?: string (every session of this PPPoE server)} → {removed}",
        has_service, remove),
    cmd!(query "ppp.why", "Why PPP?", [], None,
        "{name?: string (the user), mac?: mac (the CPE)} → {query, active?, attempts: [{stage, count}], last_stage?, last?: {at, event, stage?, reason, hint, reply_message?, address?, uptime_secs}}",
        always, why),
    cmd!(query "ppp.history", "PPP History", [], None,
        "{name?: string, mac?: mac, event?: up|down|failed, limit?: int 1..10000 (default 500, newest first)} → [{at, name, caller_id, server, event, stage?, reason?, hint?, reply_message?, address?, uptime_secs, rx_bytes, tx_bytes}]",
        always, history),
];

fn has_service(s: &Session) -> std::result::Result<(), String> {
    if s.ppp_backend().is_none() {
        Err("the pppoe service is not running (daemon only)".into())
    } else {
        Ok(())
    }
}

/// `1h2m3s`, RouterOS style.
pub(super) fn uptime_text(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    let mut out = String::new();
    if d > 0 {
        out.push_str(&format!("{d}d"));
    }
    if h > 0 {
        out.push_str(&format!("{h}h"));
    }
    if m > 0 {
        out.push_str(&format!("{m}m"));
    }
    if s > 0 || out.is_empty() {
        out.push_str(&format!("{s}s"));
    }
    out
}

fn row(a: &ActiveSession) -> Value {
    let mut v = serde_json::to_value(a).unwrap_or_else(|_| json!({}));
    if let Some(o) = v.as_object_mut() {
        o.insert("uptime".into(), json!(uptime_text(a.uptime_secs)));
        if a.address.is_none() {
            o.remove("address");
        }
    }
    v
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let needle = opt_text(p, "find", 128)?.map(|t| t.to_lowercase());
    let server = opt_str(p, "server")?.map(str::to_owned);
    let limit = opt_u32(p, "limit")?.unwrap_or(10_000);
    if !(1..=100_000).contains(&limit) {
        return Err(EngineError::bad("limit", "1..=100000"));
    }
    let Some(b) = s.ppp_backend() else {
        return Ok(json!({"total": 0, "running": false, "rows": []}));
    };
    let keep = |a: &ActiveSession| {
        server.as_deref().is_none_or(|v| a.server == v)
            && needle.as_ref().is_none_or(|n| {
                a.name.to_lowercase().contains(n)
                    || a.caller_id.to_lowercase().contains(n)
                    || a.address.is_some_and(|ip| ip.to_string().contains(n))
                    || a.circuit_id.as_deref().is_some_and(|c| c.to_lowercase().contains(n))
                    || [a.ipv6_prefix, a.delegated_prefix].iter().flatten().any(|p| p.to_string().contains(n))
            })
    };
    let (total, page) = b.active_page(&keep, limit as usize);
    let rows: Vec<Value> = page.iter().map(row).collect();
    Ok(json!({"total": total, "running": true, "rows": rows}))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let ids: Vec<String> = match p.get("id") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(a)) if a.len() <= 100_000 => a
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or_else(|| EngineError::bad("id", "a list of session ids")))
            .collect::<Result<_>>()?,
        Some(Value::Array(_)) => return Err(EngineError::bad("id", "at most 100000 ids")),
        Some(_) => opt_list(p, "id")?.unwrap_or_default(),
    };
    let name = opt_str(p, "name")?.map(str::to_owned);
    let server = opt_str(p, "server")?.map(str::to_owned);
    if ids.is_empty() && name.is_none() && server.is_none() {
        return Err(EngineError::bad("id", "give id (from ppp.active.list), name or server"));
    }
    let Some(b) = s.ppp_backend() else {
        return Err(EngineError::bad("id", "the pppoe service is not running"));
    };
    let mut targets = ids;
    if name.is_some() || server.is_some() {
        targets.extend(
            b.active()
                .into_iter()
                .filter(|a| name.as_ref().is_some_and(|n| &a.name == n) || server.as_ref().is_some_and(|v| &a.server == v))
                .map(|a| a.id),
        );
    }
    let removed = b.terminate(&targets);
    if removed == 0 {
        let shown: String = targets.join(",").chars().take(64).collect();
        let what = if shown.is_empty() { name.or(server).unwrap_or_default() } else { shown };
        return Err(EngineError::bad("id", format!("no active session '{what}'")));
    }
    Ok(json!({"removed": removed}))
}

fn mac(p: &Value) -> Result<Option<MacAddr>> {
    opt_str(p, "mac")?
        .map(|t| t.parse::<MacAddr>().map_err(|e| EngineError::bad("mac", e.to_string())))
        .transpose()
}

fn why(s: &mut Session, p: &Value) -> Result<Value> {
    let name = opt_text(p, "name", 64)?;
    let mac = mac(p)?;
    if name.is_none() && mac.is_none() {
        return Err(EngineError::bad("name", "give name or mac"));
    }
    let Some(b) = s.ppp_backend() else {
        return Ok(json!({"query": name.unwrap_or_default(), "attempts": [], "running": false}));
    };
    let w = b.why(name.as_deref(), mac);
    let attempts: Vec<Value> = w
        .attempts
        .iter()
        .map(|(stage, n)| json!({"stage": stage.as_str(), "count": n}))
        .collect();
    let mut v = json!({"query": w.query, "attempts": attempts});
    if let Some(o) = v.as_object_mut() {
        if let Some(a) = &w.active {
            o.insert("active".into(), json!(a));
        }
        if let Some(st) = w.last_stage {
            o.insert("last_stage".into(), json!(st.as_str()));
        }
        if let Some(l) = &w.last {
            o.insert("last".into(), serde_json::to_value(l).unwrap_or(Value::Null));
        }
    }
    Ok(v)
}

fn history(s: &mut Session, p: &Value) -> Result<Value> {
    let name = opt_text(p, "name", 64)?;
    let mac = mac(p)?.map(|m| m.to_string());
    let event = opt_str(p, "event")?.map(str::to_owned);
    if let Some(e) = &event
        && !matches!(e.as_str(), "up" | "down" | "failed")
    {
        return Err(EngineError::bad("event", "up, down or failed"));
    }
    let limit = opt_u32(p, "limit")?.unwrap_or(500);
    if !(1..=10_000).contains(&limit) {
        return Err(EngineError::bad("limit", "1..=10000"));
    }
    let Some(b) = s.ppp_backend() else {
        return Ok(json!([]));
    };
    let rows: Vec<Value> = b
        .history()
        .iter()
        .rev()
        .filter(|h| name.as_deref().is_none_or(|n| h.name == n))
        .filter(|h| mac.as_deref().is_none_or(|m| h.caller_id.eq_ignore_ascii_case(m)))
        .filter(|h| event.as_deref().is_none_or(|e| h.event == e))
        .take(limit as usize)
        .map(|h| serde_json::to_value(h).unwrap_or(Value::Null))
        .collect();
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use corerouter_model::ppp::{HistoryEntry, ServiceStats, Stage, Why};

    use super::*;
    use crate::ppp::PppBackend;

    #[derive(Default)]
    struct Fake {
        up: Mutex<Vec<ActiveSession>>,
    }

    impl PppBackend for Fake {
        fn active(&self) -> Vec<ActiveSession> {
            self.up.lock().unwrap().clone()
        }
        fn terminate(&self, ids: &[String]) -> usize {
            let mut up = self.up.lock().unwrap();
            let before = up.len();
            up.retain(|a| !ids.contains(&a.id));
            before - up.len()
        }
        fn history(&self) -> Vec<HistoryEntry> {
            vec![
                HistoryEntry { at: 1, name: "ana".into(), caller_id: "AA:BB:CC:00:00:01".into(), event: "failed".into(), stage: Some(Stage::Auth), reason: "wrong password".into(), ..HistoryEntry::default() },
                HistoryEntry { at: 2, name: "ana".into(), event: "up".into(), ..HistoryEntry::default() },
            ]
        }
        fn why(&self, name: Option<&str>, _: Option<MacAddr>) -> Why {
            Why {
                query: name.unwrap_or_default().into(),
                attempts: vec![(Stage::Padi, 3), (Stage::Auth, 3)],
                last_stage: Some(Stage::Auth),
                last: self.history().into_iter().next(),
                ..Why::default()
            }
        }
        fn stats(&self) -> ServiceStats {
            ServiceStats::default()
        }
    }

    fn lab() -> (Session, Arc<Fake>) {
        let mut s = Session::virtual_lab();
        let f = Arc::new(Fake::default());
        *f.up.lock().unwrap() = (1..=3u16)
            .map(|i| ActiveSession {
                id: format!("*1-{i}"),
                name: if i == 3 { "ana".into() } else { format!("u{i}") },
                address: Some(std::net::Ipv4Addr::new(100, 64, 0, i as u8)),
                uptime_secs: 3723,
                ..ActiveSession::default()
            })
            .collect();
        s.set_ppp_backend(f.clone());
        (s, f)
    }

    #[test]
    fn list_find_and_remove() {
        let (mut s, f) = lab();
        let l = s.execute("ppp.active.list", &json!({})).unwrap();
        assert_eq!(l["total"], 3);
        assert_eq!(l["rows"][0]["name"], "ana");
        assert_eq!(l["rows"][0]["uptime"], "1h2m3s");
        let l = s.execute("ppp.active.list", &json!({"find": "100.64.0.2"})).unwrap();
        assert_eq!(l["total"], 1);
        assert_eq!(s.execute("ppp.active.remove", &json!({"id": "*1-1"})).unwrap()["removed"], 1);
        assert_eq!(s.execute("ppp.active.remove", &json!({"name": "ana"})).unwrap()["removed"], 1);
        assert_eq!(f.up.lock().unwrap().len(), 1);
        let err = s.execute("ppp.active.remove", &json!({"id": "*9-9"})).unwrap_err();
        assert!(matches!(err, EngineError::BadParam { .. }));
        assert!(s.execute("ppp.active.remove", &json!({})).is_err());
    }

    #[test]
    fn why_and_history() {
        let (mut s, _) = lab();
        let w = s.execute("ppp.why", &json!({"name": "ana"})).unwrap();
        assert_eq!(w["last_stage"], "auth");
        assert_eq!(w["attempts"][1]["count"], 3);
        assert_eq!(w["last"]["reason"], "wrong password");
        let h = s.execute("ppp.history", &json!({"name": "ana"})).unwrap();
        assert_eq!(h[0]["event"], "up", "newest first");
        let h = s.execute("ppp.history", &json!({"event": "failed"})).unwrap();
        assert_eq!(h.as_array().unwrap().len(), 1);
        assert!(s.execute("ppp.why", &json!({})).is_err());
        assert!(s.execute("ppp.why", &json!({"mac": "zz"})).is_err());
        assert!(s.execute("ppp.history", &json!({"event": "boom"})).is_err());
    }

    #[test]
    fn without_the_service() {
        let mut s = Session::virtual_lab();
        let l = s.execute("ppp.active.list", &json!({})).unwrap();
        assert_eq!((l["total"].clone(), l["running"].clone()), (json!(0), json!(false)));
        assert!(s.execute("ppp.active.remove", &json!({"id": "*1-1"})).is_err());
        assert_eq!(s.execute("ppp.history", &json!({})).unwrap(), json!([]));
    }
}
