//! /ip dhcp-server alert (G4.2a): DHCP servers heard on a link that are
//! not the router nor in `valid_server` (a home router plugged in the
//! wrong way, a rogue). Each is logged under `dhcp,critical` when first
//! heard and again after `alert_timeout` of being heard; `print` lists them.

use corerouter_model::dhcp_server::{Alert, DEFAULT_ALERT_TIMEOUT, MAX_LIST};
use corerouter_model::{IfName, MacAddr};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_text, req_parse};
use super::dhcp_client::opt_list;
use super::dhcp_server::{find, opt_secs, secs_text, verdict};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.dhcp-server.alert.add",
        "Add DHCP Alert",
        ["IP", "DHCP Server"],
        None,
        "{interface: string, valid_server?: [mac] | string (servers allowed on the link), alert_timeout?: duration (default 1h: a server heard again after this is alerted again; at least 1m), disabled?: bool, comment?: string} → {id, warnings}",
        always,
        add
    ),
    cmd!(
        "ip.dhcp-server.alert.set",
        "Set DHCP Alert",
        [],
        None,
        "{id: *hex | interface, interface?: string, valid_server?: [mac] | string, alert_timeout?: duration, disabled?: bool, comment?: string} → {id, warnings}",
        has_alerts,
        set
    ),
    cmd!(
        "ip.dhcp-server.alert.remove",
        "Remove DHCP Alert",
        [],
        None,
        "{id: *hex | interface} → {id, interface}",
        has_alerts,
        remove
    ),
    cmd!(
        "ip.dhcp-server.alert.reset-alert",
        "Reset Alert",
        [],
        None,
        "{id: *hex | interface} → {interface, forgotten}",
        has_alerts,
        reset
    ),
    cmd!(query "ip.dhcp-server.alert.print", "DHCP Alerts", [], None,
        "{} → [{id, interface, valid_server, alert_timeout, alert_timeout_secs, disabled, comment?, unknown_server: [{mac, address, server_id?, first_seen_secs (ago), last_seen_secs (ago), replies}]}]",
        always, print),
];

fn has_alerts(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.dhcp_server.alerts.is_empty() {
        Err("there are no DHCP alerts".into())
    } else {
        Ok(())
    }
}

fn apply(a: &mut Alert, p: &Value) -> Result<()> {
    if let Some(i) = opt_parse::<IfName>(p, "interface")? {
        a.interface = i;
    }
    if let Some(items) = opt_list(p, "valid_server")? {
        if items.len() > MAX_LIST {
            return Err(EngineError::bad("valid_server", format!("at most {MAX_LIST}")));
        }
        a.valid_server = items
            .iter()
            .map(|t| t.parse::<MacAddr>().map_err(|e| EngineError::bad("valid_server", e.to_string())))
            .collect::<Result<Vec<_>>>()?;
    }
    if let Some(t) = opt_secs(p, "alert_timeout")? {
        a.alert_timeout = t;
    }
    if let Some(b) = opt_bool(p, "disabled")? {
        a.disabled = b;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        a.comment = c;
    }
    Ok(())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let interface: IfName = req_parse(p, "interface")?;
    let d = &mut s.store_mut().candidate_mut().ip.dhcp_server;
    if d.alerts.len() >= corerouter_model::dhcp_server::MAX_ALERTS {
        return Err(EngineError::bad("interface", "too many alerts"));
    }
    let mut a = Alert {
        id: d.next_id(),
        interface,
        valid_server: Vec::new(),
        alert_timeout: DEFAULT_ALERT_TIMEOUT,
        disabled: false,
        comment: String::new(),
    };
    apply(&mut a, p)?;
    let id = a.id;
    d.alerts.push(a);
    let warnings = verdict(s, "alerts", id)?;
    Ok(json!({"id": id, "warnings": warnings}))
}

fn index(s: &Session, p: &Value) -> Result<usize> {
    find(&s.store().candidate().ip.dhcp_server.alerts, p, |x| x.id, |x| Some(x.interface.as_str()), "alert")
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let d = &mut s.store_mut().candidate_mut().ip.dhcp_server;
    let Some(mut a) = d.alerts.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such alert"));
    };
    apply(&mut a, p)?;
    let id = a.id;
    if let Some(slot) = d.alerts.get_mut(i) {
        *slot = a;
    }
    let warnings = verdict(s, "alerts", id)?;
    Ok(json!({"id": id, "warnings": warnings}))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let a = s.store_mut().candidate_mut().ip.dhcp_server.alerts.remove(i);
    Ok(json!({"id": a.id, "interface": a.interface}))
}

fn reset(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let Some(iface) = s.store().candidate().ip.dhcp_server.alerts.get(i).map(|a| a.interface.clone()) else {
        return Err(EngineError::bad("id", "no such alert"));
    };
    let n = s.dhcp_server_mut().map_or(0, |c| c.reset_alert(&iface));
    Ok(json!({"interface": iface, "forgotten": n}))
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let now = s.dhcp_server_clock().unix;
    let core = s.dhcp_server();
    let rows: Vec<Value> = s
        .store()
        .candidate()
        .ip
        .dhcp_server
        .alerts
        .iter()
        .map(|a| {
            let seen: Vec<Value> = core
                .map(|c| {
                    c.seen()
                        .filter(|x| x.interface == a.interface)
                        .map(|x| {
                            let mut v = json!({
                                "mac": MacAddr(x.mac).to_string(),
                                "address": x.ip,
                                "first_seen_secs": now.saturating_sub(x.first),
                                "last_seen_secs": now.saturating_sub(x.last),
                                "replies": x.count,
                            });
                            if let (Some(id), Some(o)) = (x.server_id, v.as_object_mut()) {
                                o.insert("server_id".into(), json!(id));
                            }
                            v
                        })
                        .collect()
                })
                .unwrap_or_default();
            let mut v = json!({
                "id": a.id,
                "interface": a.interface,
                "valid_server": a.valid_server.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "alert_timeout": secs_text(a.alert_timeout),
                "alert_timeout_secs": a.alert_timeout,
                "disabled": a.disabled,
                "unknown_server": seen,
            });
            if !a.comment.is_empty()
                && let Some(o) = v.as_object_mut()
            {
                o.insert("comment".into(), json!(a.comment));
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}
