//! /ip dhcp-server lease (G4.2a): static leases are config; dynamic ones
//! are the server's state, named by their address. `print` shows both,
//! one row per address, like RouterOS (flag D for dynamic).

use std::net::Ipv4Addr;

use corerouter_model::dhcp_server::{StaticLease, format_client_id, parse_client_id};
use corerouter_model::firewall::Name;
use corerouter_model::MacAddr;
use corerouter_proto_dhcp::server::leases::{Lease, State};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text};
use super::dhcp_server::{find, opt_lists, opt_ref, opt_secs, opt_strings, secs_text, verdict};
use super::{CommandSpec, always};
use crate::dhcp_client::duration_text;
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.dhcp-server.lease.add",
        "Add DHCP Lease",
        ["IP", "DHCP Server"],
        None,
        "{address: ipv4, mac_address?: mac, client_id?: string (option 61 as RouterOS prints it, 1:aa:bb:cc:dd:ee:ff, or 0x…; matches instead of the MAC), agent_circuit_id?: string (option 82 circuit id the request must carry: a fixed address per OLT/switch port; text or 0x…), agent_remote_id?: string (option 82 remote id), server?: string (all, the default, or a server's name), lease_time?: duration (empty or 0: the server's), block_access?: bool (the client gets its address but no gateway nor DNS), address_lists?: [string] | string, dhcp_option?: [string] | string, dhcp_option_set?: string, always_broadcast?: bool, host_name?: string (its name in the DNS; empty: the client's), rate_limit?: string (RouterOS rate-limit rx/tx from the router, 10M/50M [burst …]: on an ipoe server the subscriber's XDP policer; empty clears), disabled?: bool, comment?: string} → {id, warnings}",
        always,
        add
    ),
    cmd!(
        "ip.dhcp-server.lease.set",
        "Set DHCP Lease",
        [],
        None,
        "{id: *hex | address (a static lease; make a dynamic one static first), address?: ipv4, mac_address?: mac, client_id?: string, agent_circuit_id?: string, agent_remote_id?: string, server?: string, lease_time?: duration, block_access?: bool, address_lists?: [string] | string, dhcp_option?: [string] | string, dhcp_option_set?: string, always_broadcast?: bool, host_name?: string, rate_limit?: string, disabled?: bool, comment?: string} → {id, warnings}",
        always,
        set
    ),
    cmd!(
        "ip.dhcp-server.lease.remove",
        "Remove DHCP Lease",
        [],
        None,
        "{id: *hex | address (a static lease leaves the config; a dynamic one is forgotten, its DNS and address lists go)} → {address, static}",
        always,
        remove
    ),
    cmd!(
        "ip.dhcp-server.lease.make-static",
        "Make Static",
        [],
        None,
        "{address: ipv4 (a dynamic lease)} → {id, address}",
        always,
        make_static
    ),
    cmd!(
        "ip.dhcp-server.lease.release",
        "Release",
        [],
        None,
        "{address: ipv4} → {address, status}",
        always,
        release
    ),
    cmd!(
        "ip.dhcp-server.lease.block",
        "Block",
        [],
        None,
        "{address: ipv4, block?: bool (default true; false lets it through again)} → {id, address, block_access}",
        always,
        block
    ),
    cmd!(
        "ip.dhcp-server.lease.check-status",
        "Check Status",
        [],
        None,
        "{address: ipv4 (a conflict or declined lease: probed again, freed if nobody answers within 0.5 s)} → {address, status}",
        always,
        check_status
    ),
    cmd!(query "ip.dhcp-server.lease.print", "DHCP Leases", [], None,
        "{server?: string, status?: string} → [{id? (static leases), address, dynamic, status (waiting | testing | offered | bound | conflict | declined), mac_address?, client_id?, host_name?, server?, expires_after?, expires_after_secs?, last_seen_secs?, vendor_class?, blocked, rate_limit? (a static lease's), dns? (the name it has in the DNS), address_lists, reason? (of a conflict), lease_time?, always_broadcast, dhcp_option, dhcp_option_set?, disabled, comment?, agent_info? (option 82, hex), agent_circuit_id? (the request's, or the static lease's), agent_remote_id?}]",
        always, print),
];

fn address(p: &Value) -> Result<Ipv4Addr> {
    let t = opt_str(p, "address")?
        .or(opt_str(p, "id")?)
        .ok_or_else(|| EngineError::bad("address", "is required"))?;
    t.trim()
        .parse()
        .map_err(|_| EngineError::bad("address", "an IPv4 address"))
}

fn apply(l: &mut StaticLease, p: &Value) -> Result<()> {
    if let Some(a) = opt_parse::<Ipv4Addr>(p, "address")? {
        l.address = a;
    }
    match opt_str(p, "mac_address")? {
        Some(t) if t.trim().is_empty() => l.mac_address = None,
        Some(_) => l.mac_address = opt_parse::<MacAddr>(p, "mac_address")?,
        None => {}
    }
    if let Some(c) = opt_text(p, "client_id", 255)? {
        let c = c.trim().to_owned();
        if !c.is_empty() && parse_client_id(&c).is_none() {
            return Err(EngineError::bad(
                "client_id",
                "write it as RouterOS prints it (1:aa:bb:cc:dd:ee:ff) or 0x…",
            ));
        }
        l.client_id = c;
    }
    for (key, slot) in [
        ("agent_circuit_id", &mut l.agent_circuit_id),
        ("agent_remote_id", &mut l.agent_remote_id),
    ] {
        if let Some(t) = opt_text(p, key, 512)? {
            let t = t.trim().to_owned();
            if !t.is_empty() && corerouter_proto_dhcp::server::agent::parse(&t).is_none() {
                return Err(EngineError::bad(key, "text, or 0x… bytes; at most 255"));
            }
            *slot = t;
        }
    }
    if let Some(sv) = opt_ref(p, "server", &["all"])? {
        l.server = sv;
    }
    if p.get("lease_time").is_some() {
        match opt_str(p, "lease_time")? {
            Some(t) if t.trim().is_empty() => l.lease_time = None,
            _ => l.lease_time = opt_secs(p, "lease_time")?.filter(|t| *t > 0),
        }
    }
    if let Some(b) = opt_bool(p, "block_access")? {
        l.block_access = b;
    }
    if let Some(r) = super::ppp_common::opt_rate_limit(p)? {
        l.rate_limit = r.unwrap_or_default();
    }
    if let Some(v) = opt_lists(p, "address_lists")? {
        l.address_lists = v;
    }
    if let Some(v) = opt_strings(p, "dhcp_option")? {
        l.dhcp_option = v;
    }
    if let Some(v) = opt_ref(p, "dhcp_option_set", &["none"])? {
        l.dhcp_option_set = v;
    }
    if let Some(b) = opt_bool(p, "always_broadcast")? {
        l.always_broadcast = b;
    }
    if let Some(h) = opt_text(p, "host_name", 63)? {
        l.host_name = h.trim().to_ascii_lowercase();
    }
    if let Some(b) = opt_bool(p, "disabled")? {
        l.disabled = b;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        l.comment = c;
    }
    Ok(())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let addr: Ipv4Addr = super::args::req_parse(p, "address")?;
    let d = &mut s.store_mut().candidate_mut().ip.dhcp_server;
    if d.leases.len() >= corerouter_model::dhcp_server::MAX_STATIC_LEASES {
        return Err(EngineError::bad("address", "too many static leases"));
    }
    let mut l = StaticLease::new(d.next_id(), addr);
    apply(&mut l, p)?;
    let id = l.id;
    d.leases.push(l);
    let warnings = verdict(s, "leases", id)?;
    Ok(json!({"id": id, "warnings": warnings}))
}

/// The static lease `p["id"]` names (`*hex` or its address).
fn static_index(s: &Session, p: &Value) -> Result<usize> {
    let leases = &s.store().candidate().ip.dhcp_server.leases;
    find(leases, p, |x| x.id, |_| None, "static lease").or_else(|e| {
        let ip = opt_str(p, "id")?.and_then(|t| t.trim().parse::<Ipv4Addr>().ok());
        ip.and_then(|ip| leases.iter().position(|l| l.address == ip))
            .ok_or(e)
    })
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = static_index(s, p).map_err(|e| {
        let dynamic = address(p)
            .ok()
            .and_then(|ip| s.dhcp_server().and_then(|c| c.leases().get(ip)))
            .is_some();
        if dynamic {
            EngineError::bad("id", "a dynamic lease: make it static first (ip.dhcp-server.lease.make-static)")
        } else {
            e
        }
    })?;
    let d = &mut s.store_mut().candidate_mut().ip.dhcp_server;
    let Some(mut l) = d.leases.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such static lease"));
    };
    apply(&mut l, p)?;
    let id = l.id;
    if let Some(slot) = d.leases.get_mut(i) {
        *slot = l;
    }
    let warnings = verdict(s, "leases", id)?;
    Ok(json!({"id": id, "warnings": warnings}))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    if let Ok(i) = static_index(s, p) {
        let l = s.store_mut().candidate_mut().ip.dhcp_server.leases.remove(i);
        return Ok(json!({"address": l.address, "static": true}));
    }
    let ip = address(p)?;
    let Some(core) = s.dhcp_server_mut() else {
        return Err(EngineError::bad("id", format!("no lease for {ip}")));
    };
    if core.leases().get(ip).is_none() {
        return Err(EngineError::bad("id", format!("no lease for {ip}")));
    }
    let fx = core.forget(ip);
    s.dhcp_server_effects(fx);
    Ok(json!({"address": ip, "static": false}))
}

fn dynamic(s: &Session, ip: Ipv4Addr) -> Result<Lease> {
    s.dhcp_server()
        .and_then(|c| c.leases().get(ip).cloned())
        .ok_or_else(|| EngineError::bad("address", format!("no dynamic lease for {ip}")))
}

fn make_static(s: &mut Session, p: &Value) -> Result<Value> {
    let ip = address(p)?;
    let l = dynamic(s, ip)?;
    if !matches!(l.state, State::Bound | State::Offered) {
        return Err(EngineError::bad("address", format!("{ip} is {}", l.state.as_str())));
    }
    let d = &mut s.store_mut().candidate_mut().ip.dhcp_server;
    if d.leases.iter().any(|x| x.address == ip) {
        return Err(EngineError::bad("address", format!("{ip} is static already")));
    }
    let mut st = StaticLease::new(d.next_id(), ip);
    st.server = Some(l.server.clone());
    st.mac_address = Some(MacAddr(l.mac));
    st.client_id = l.client_id.as_deref().map(format_client_id).unwrap_or_default();
    st.host_name = corerouter_proto_dhcp::server::dns_label(&l.host_name);
    let id = st.id;
    d.leases.push(st);
    verdict(s, "leases", id)?;
    Ok(json!({"id": id, "address": ip}))
}

fn release(s: &mut Session, p: &Value) -> Result<Value> {
    let ip = address(p)?;
    let now = s.dhcp_server_clock();
    let Some(core) = s.dhcp_server_mut() else {
        return Err(EngineError::bad("address", format!("no lease for {ip}")));
    };
    let fx = core.release(ip, now).map_err(|e| EngineError::bad("address", e))?;
    s.dhcp_server_effects(fx);
    Ok(json!({"address": ip, "status": "released"}))
}

fn block(s: &mut Session, p: &Value) -> Result<Value> {
    let ip = address(p)?;
    let on = opt_bool(p, "block")?.unwrap_or(true);
    let has_static = s
        .store()
        .candidate()
        .ip
        .dhcp_server
        .leases
        .iter()
        .any(|l| l.address == ip);
    if !has_static {
        make_static(s, &json!({"address": ip.to_string()}))?;
    }
    let d = &mut s.store_mut().candidate_mut().ip.dhcp_server;
    let Some(l) = d.leases.iter_mut().find(|l| l.address == ip) else {
        return Err(EngineError::bad("address", format!("no lease for {ip}")));
    };
    l.block_access = on;
    let id = l.id;
    Ok(json!({"id": id, "address": ip, "block_access": on}))
}

fn check_status(s: &mut Session, p: &Value) -> Result<Value> {
    let ip = address(p)?;
    let now = s.dhcp_server_clock();
    let Some(core) = s.dhcp_server_mut() else {
        return Err(EngineError::bad("address", format!("no lease for {ip}")));
    };
    let fx = core.check_status(ip, now).map_err(|e| EngineError::bad("address", e))?;
    s.dhcp_server_effects(fx);
    Ok(json!({"address": ip, "status": "testing"}))
}

fn mac(m: [u8; 6]) -> String {
    MacAddr(m).to_string()
}

fn print(s: &mut Session, p: &Value) -> Result<Value> {
    let want_server = opt_str(p, "server")?.map(str::to_owned);
    let want_status = opt_str(p, "status")?.map(str::to_owned);
    let cand = s.store().candidate();
    let now = s.dhcp_server_clock().unix;
    let core = s.dhcp_server();
    let testing: Vec<Ipv4Addr> = core.map(|c| c.testing().into_iter().map(|(ip, _)| ip).collect()).unwrap_or_default();
    let mut rows: Vec<(u32, Value)> = Vec::new();
    let lists = |v: &[Name]| v.iter().map(Name::as_str).map(str::to_owned).collect::<Vec<_>>();
    let dynamic_row = |l: &Lease| {
        let mut v = json!({
            "address": l.address,
            "dynamic": true,
            "status": l.state.as_str(),
            "mac_address": mac(l.mac),
            "server": l.server,
            "blocked": false,
            "address_lists": Vec::<String>::new(),
            "always_broadcast": false,
            "dhcp_option": Vec::<String>::new(),
            "disabled": false,
            "lease_time": secs_text(l.lease_time),
        });
        if let Some(o) = v.as_object_mut() {
            if l.state == State::Bound || l.state == State::Offered || matches!(l.state, State::Conflict | State::Declined) {
                let left = l.left(now);
                o.insert("expires_after".into(), json!(duration_text(left)));
                o.insert("expires_after_secs".into(), json!(left));
            }
            o.insert("last_seen_secs".into(), json!(now.saturating_sub(l.last_seen)));
            if let Some(c) = &l.client_id {
                o.insert("client_id".into(), json!(format_client_id(c)));
            }
            if !l.host_name.is_empty() {
                o.insert("host_name".into(), json!(l.host_name));
            }
            if !l.vendor_class.is_empty() {
                o.insert("vendor_class".into(), json!(l.vendor_class));
            }
            if !l.reason.is_empty() {
                o.insert("reason".into(), json!(l.reason));
            }
            if let Some(r) = &l.relay_info {
                use corerouter_proto_dhcp::server::agent;
                o.insert("agent_info".into(), json!(corerouter_proto_dhcp::v4::hex(r)));
                for (key, code) in [("agent_circuit_id", agent::CIRCUIT_ID), ("agent_remote_id", agent::REMOTE_ID)] {
                    if let Some(v) = agent::get(r, code) {
                        o.insert(key.into(), json!(agent::text(v)));
                    }
                }
            }
        }
        v
    };
    for st in &cand.ip.dhcp_server.leases {
        let live = core
            .and_then(|c| c.leases().get(st.address))
            .filter(|l| l.state.active() || matches!(l.state, State::Conflict | State::Declined));
        let mut v = match live {
            Some(l) => dynamic_row(l),
            None => json!({"address": st.address, "status": if testing.contains(&st.address) { "testing" } else { "waiting" }}),
        };
        if let Some(o) = v.as_object_mut() {
            o.insert("id".into(), json!(st.id));
            o.insert("dynamic".into(), json!(false));
            o.insert("blocked".into(), json!(st.block_access));
            if !st.rate_limit.is_empty() {
                o.insert("rate_limit".into(), json!(st.rate_limit));
            }
            o.insert("address_lists".into(), json!(lists(&st.address_lists)));
            o.insert("always_broadcast".into(), json!(st.always_broadcast));
            o.insert("dhcp_option".into(), json!(st.dhcp_option));
            o.insert("disabled".into(), json!(st.disabled));
            o.insert("server".into(), json!(st.server.clone().unwrap_or_else(|| "all".into())));
            if let Some(m) = st.mac_address {
                o.insert("mac_address".into(), json!(m.to_string()));
            }
            if !st.client_id.is_empty() {
                o.insert("client_id".into(), json!(st.client_id));
            }
            for (key, v) in [("agent_circuit_id", &st.agent_circuit_id), ("agent_remote_id", &st.agent_remote_id)] {
                if !v.is_empty() && !o.contains_key(key) {
                    o.insert(key.into(), json!(v));
                }
            }
            if !st.host_name.is_empty() && live.is_none_or(|l| l.host_name.is_empty()) {
                o.insert("host_name".into(), json!(st.host_name));
            }
            if let Some(t) = st.lease_time {
                o.insert("lease_time".into(), json!(secs_text(t)));
            }
            if let Some(set) = &st.dhcp_option_set {
                o.insert("dhcp_option_set".into(), json!(set));
            }
            if !st.comment.is_empty() {
                o.insert("comment".into(), json!(st.comment));
            }
        }
        rows.push((u32::from(st.address), v));
    }
    if let Some(c) = core {
        for l in c.leases().iter() {
            let shown = l.state.active() || matches!(l.state, State::Conflict | State::Declined);
            if !shown || cand.ip.dhcp_server.leases.iter().any(|x| x.address == l.address) {
                continue;
            }
            let mut v = dynamic_row(l);
            if testing.contains(&l.address)
                && let Some(o) = v.as_object_mut()
            {
                o.insert("status".into(), json!("testing"));
            }
            rows.push((u32::from(l.address), v));
        }
        for (ip, _) in c.testing() {
            if !rows.iter().any(|(k, _)| *k == u32::from(ip)) {
                rows.push((u32::from(ip), json!({"address": ip, "dynamic": true, "status": "testing", "blocked": false, "address_lists": [], "always_broadcast": false, "dhcp_option": [], "disabled": false})));
            }
        }
    }
    // What the runtime registered: the DNS name and lists of each lease.
    for (k, v) in &mut rows {
        let ip = Ipv4Addr::from(*k);
        if let Some((zone, host)) = s.dhcp_server_dns(ip)
            && let Some(o) = v.as_object_mut()
        {
            o.insert("dns".into(), json!(format!("{host}.{zone}")));
        }
        if let Some(l) = s.dhcp_server_lists(ip)
            && !l.is_empty()
            && let Some(o) = v.as_object_mut()
        {
            o.insert("address_lists".into(), json!(l));
        }
    }
    rows.sort_by_key(|(k, _)| *k);
    let rows: Vec<Value> = rows
        .into_iter()
        .map(|(_, v)| v)
        .filter(|v| {
            want_server
                .as_deref()
                .is_none_or(|w| v.get("server").and_then(Value::as_str).is_some_and(|x| x == w || x == "all"))
        })
        .filter(|v| {
            want_status
                .as_deref()
                .is_none_or(|w| v.get("status").and_then(Value::as_str) == Some(w))
        })
        .collect();
    Ok(Value::Array(rows))
}
