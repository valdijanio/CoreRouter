//! /ip dhcp-relay (G4.2b): relays and what they did.

use corerouter_model::IfName;
use corerouter_model::dhcp_relay::DhcpRelay;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_text, req_parse};
use super::dhcp_server::{about, check_rows, find, opt_ip, opt_ips, verdict};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.dhcp-relay.add",
        "Add DHCP Relay",
        ["IP", "DHCP Relay"],
        None,
        "{name?: string (default relayN), interface: string (where the clients are), dhcp_server: [ipv4] | string (servers each request goes to, all of them), local_address?: ipv4 (giaddr; empty: the interface's address), add_relay_info?: bool (add option 82: circuit id = the interface's name, remote id = the client's MAC), relay_info_remote_id?: string (remote id instead of the MAC), relay_info_trusted?: bool (relay requests that already carry option 82 without a giaddr, added by a layer-2 agent; default no: they are dropped), disabled?: bool, comment?: string} → {id, name, warnings}",
        always,
        add
    ),
    cmd!(
        "ip.dhcp-relay.set",
        "Set DHCP Relay",
        [],
        None,
        "{id: *hex | name, name?: string, interface?: string, dhcp_server?: [ipv4] | string, local_address?: ipv4, add_relay_info?: bool, relay_info_remote_id?: string, relay_info_trusted?: bool, disabled?: bool, comment?: string} → {id, name, warnings}",
        has_relays,
        set
    ),
    cmd!(
        "ip.dhcp-relay.remove",
        "Remove DHCP Relay",
        [],
        None,
        "{id: *hex | name} → {id, name}",
        has_relays,
        remove
    ),
    cmd!(query "ip.dhcp-relay.print", "DHCP Relay", ["IP", "DHCP Relay"], None,
        "{} → [{id, name, interface, dhcp_server, local_address?, add_relay_info, relay_info_remote_id?, relay_info_trusted, disabled, comment?, status (running | disabled | invalid | starting | error), giaddr?, error?, requests (sent up), replies (sent down), dropped: {reason: count}, checks: [{label, level, text}]}]",
        always, print),
];

fn has_relays(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.dhcp_relays.relays.is_empty() {
        Err("there are no DHCP relays (ip.dhcp-relay.add)".into())
    } else {
        Ok(())
    }
}

fn apply(r: &mut DhcpRelay, p: &Value) -> Result<()> {
    if let Some(n) = opt_text(p, "name", 63)? {
        r.name = n.trim().to_owned();
    }
    if let Some(i) = opt_parse::<IfName>(p, "interface")? {
        r.interface = i;
    }
    if let Some(v) = opt_ips(p, "dhcp_server")? {
        r.dhcp_server = v;
    }
    if let Some(ip) = opt_ip(p, "local_address")? {
        r.local_address = ip;
    }
    if let Some(b) = opt_bool(p, "add_relay_info")? {
        r.add_relay_info = b;
    }
    if let Some(t) = opt_text(p, "relay_info_remote_id", 64)? {
        r.relay_info_remote_id = t;
    }
    if let Some(b) = opt_bool(p, "relay_info_trusted")? {
        r.relay_info_trusted = b;
    }
    if let Some(b) = opt_bool(p, "disabled")? {
        r.disabled = b;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        r.comment = c;
    }
    Ok(())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let interface: IfName = req_parse(p, "interface")?;
    if p.get("dhcp_server").is_none() {
        return Err(EngineError::bad("dhcp_server", "is required"));
    }
    let relays = &mut s.store_mut().candidate_mut().ip.dhcp_relays;
    if relays.relays.len() >= corerouter_model::dhcp_relay::MAX_RELAYS {
        return Err(EngineError::bad("interface", "too many relays"));
    }
    let id = relays.next_id();
    let name = (1..)
        .map(|n| format!("relay{n}"))
        .find(|n| !relays.relays.iter().any(|r| r.name == *n))
        .unwrap_or_else(|| "relay".into());
    let mut r = DhcpRelay::new(id, name, interface);
    apply(&mut r, p)?;
    let name = r.name.clone();
    relays.relays.push(r);
    let warnings = verdict(s, "relays", id)?;
    Ok(json!({"id": id, "name": name, "warnings": warnings}))
}

fn index(s: &Session, p: &Value) -> Result<usize> {
    find(&s.store().candidate().ip.dhcp_relays.relays, p, |x| x.id, |x| Some(x.name.as_str()), "DHCP relay")
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let relays = &mut s.store_mut().candidate_mut().ip.dhcp_relays.relays;
    let Some(mut r) = relays.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such DHCP relay"));
    };
    apply(&mut r, p)?;
    let (id, name) = (r.id, r.name.clone());
    if let Some(slot) = relays.get_mut(i) {
        *slot = r;
    }
    let warnings = verdict(s, "relays", id)?;
    Ok(json!({"id": id, "name": name, "warnings": warnings}))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let r = s.store_mut().candidate_mut().ip.dhcp_relays.relays.remove(i);
    Ok(json!({"id": r.id, "name": r.name}))
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let cand = s.store().candidate();
    let all = corerouter_proto_dhcp::server::checks::checks(cand);
    let status = s.dhcp_relay_status();
    let rows: Vec<Value> = cand
        .ip
        .dhcp_relays
        .relays
        .iter()
        .map(|r| {
            let st = status.iter().find(|x| x.name == r.name);
            let invalid = all
                .iter()
                .any(|c| about("relays", r.id)(c) && c.level == corerouter_proto_dhcp::server::checks::Level::Error);
            let state = if r.disabled {
                "disabled"
            } else if invalid {
                "invalid"
            } else if st.is_some_and(|x| x.error.is_some()) {
                "error"
            } else if st.is_some_and(|x| x.listening) {
                "running"
            } else {
                "starting"
            };
            let counters = st.map(|x| x.counters.clone()).unwrap_or_default();
            let mut v = json!({
                "id": r.id,
                "name": r.name,
                "interface": r.interface,
                "dhcp_server": r.dhcp_server,
                "add_relay_info": r.add_relay_info,
                "relay_info_trusted": r.relay_info_trusted,
                "disabled": r.disabled,
                "status": state,
                "requests": counters.requests,
                "replies": counters.replies,
                "dropped": counters.dropped,
                "checks": check_rows(&all, "relays", r.id),
            });
            if let Some(o) = v.as_object_mut() {
                if let Some(a) = r.local_address {
                    o.insert("local_address".into(), json!(a));
                }
                if !r.relay_info_remote_id.is_empty() {
                    o.insert("relay_info_remote_id".into(), json!(r.relay_info_remote_id));
                }
                if !r.comment.is_empty() {
                    o.insert("comment".into(), json!(r.comment));
                }
                if let Some(g) = st.and_then(|x| x.giaddr) {
                    o.insert("giaddr".into(), json!(g));
                }
                if let Some(e) = st.and_then(|x| x.error.clone()) {
                    o.insert("error".into(), json!(e));
                }
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}
