//! /ip address

use corerouter_model::{AddressEntry, IfName, ItemId};
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_text, req_parse};
use super::{CommandSpec, always};
use corerouter_hal::Learned;

use crate::dhcp_client::{duration_text, is_dynamic};
use crate::dhcp6_client::{is_dynamic6, ra_id};
use crate::validate::{MAX_ADDRESSES, v6_twice};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.address.add",
        "Add Address",
        ["IP", "Addresses"],
        None,
        "{address: cidr (10.0.0.1/24 | 2001:db8::1/64; with from_pool the bits after the pool's prefix: ::1/64, 0:0:0:1::1/64), interface: string, disabled?: bool, comment?: string, from_pool?: string (IPv6 pool a DHCPv6 client delegates into)} → {id}",
        always,
        add
    ),
    cmd!(
        "ip.address.remove",
        "Remove Address",
        [],
        None,
        "{id: *hex, force?: bool (remove it even if it cuts this session's own connection)} → {id}",
        has_addresses,
        remove
    ),
    cmd!(query "ip.address.list", "Addresses", ["IP", "Addresses"], None,
        "{interface?: string} → [{id, flags (X disabled, I invalid, D dynamic), address, network, interface, disabled, dynamic, comment, from_pool, origin (static | dhcp | dhcpv6 | ra | pool), valid_after, preferred_after, reason, state (active | disabled | invalid | tentative | dad-failed | deprecated), family (ipv4 | ipv6), vrf, access (why this session depends on it, or null)}]",
        always, list),
];

fn has_addresses(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.addresses.is_empty() {
        Err("there are no IP addresses".into())
    } else {
        Ok(())
    }
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let address: IpNet = req_parse(p, "address")?;
    let interface: IfName = req_parse(p, "interface")?;
    super::interface::refuse_unmanaged(s, p, &["interface"])?;
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let from_pool = opt_text(p, "from_pool", 63)?
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty());
    if from_pool.is_some() && !matches!(address, IpNet::V6(_)) {
        return Err(EngineError::bad(
            "from_pool",
            "only IPv6 addresses come from a pool (write ::1/64)",
        ));
    }

    let cfg = s.store_mut().candidate_mut();
    if !cfg.interfaces.contains_key(&interface) {
        return Err(EngineError::bad(
            "interface",
            format!("no interface '{interface}' (see interface.list)"),
        ));
    }
    if cfg
        .ip
        .addresses
        .iter()
        .any(|a| a.address == address && a.interface == interface)
    {
        return Err(EngineError::bad(
            "address",
            format!("{address} already exists on {interface}"),
        ));
    }
    if let IpNet::V6(net) = address
        && let Some(other) = cfg
            .ip
            .addresses
            .iter()
            .find(|a| {
                a.interface == interface
                    && a.address.addr() == address.addr()
                    && a.from_pool == from_pool
            })
    {
        return Err(EngineError::bad(
            "address",
            v6_twice(net.addr(), &interface, other.address),
        ));
    }
    if cfg.ip.addresses.len() >= MAX_ADDRESSES {
        return Err(EngineError::bad(
            "address",
            format!("at most {MAX_ADDRESSES} addresses"),
        ));
    }
    let id = cfg.ip.next_address_id();
    cfg.ip.addresses.push(AddressEntry {
        id,
        address,
        interface,
        disabled,
        comment,
        from_pool,
    });
    Ok(json!({ "id": id }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    if is_dynamic(id) {
        return Err(super::ip_address::dynamic_error(id));
    }
    crate::lockout::take_force(s, p)?;
    let list = &mut s.store_mut().candidate_mut().ip.addresses;
    let before = list.len();
    list.retain(|a| a.id != id);
    if list.len() == before {
        return Err(EngineError::bad("id", format!("no address {id}")));
    }
    Ok(json!({ "id": id }))
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let filter: Option<IfName> = opt_parse(p, "interface")?;
    let wanted = |i: &IfName| filter.as_ref().is_none_or(|f| f == i);
    let learned = s.hal_mut().ipv6_learned().unwrap_or_else(|e| {
        log::debug!("ipv6 learned state: {e}");
        Vec::new()
    });
    let candidate = s.store().candidate();
    // With the addresses DHCP clients obtained (flag D, as in RouterOS) and
    // the ones taken from pools, resolved.
    let cfg = s.effective(candidate);
    let mut rows: Vec<Value> = cfg
        .ip
        .addresses
        .iter()
        .filter(|a| wanted(&a.interface))
        .map(|a| {
            let dynamic = is_dynamic(a.id);
            let mut flags = String::new();
            if a.disabled {
                flags.push('X');
            }
            if dynamic {
                flags.push('D');
            }
            let origin = if is_dynamic6(a.id) {
                "dhcpv6"
            } else if dynamic {
                "dhcp"
            } else if a.from_pool.is_some() {
                "pool"
            } else {
                "static"
            };
            json!({
                "id": a.id,
                "flags": flags,
                "address": a.address.to_string(),
                "network": a.address.trunc().to_string(),
                "interface": a.interface,
                "disabled": a.disabled,
                "dynamic": dynamic,
                "comment": a.comment,
                "from_pool": a.from_pool,
                "origin": origin,
            })
        })
        .collect();
    // Addresses waiting for their pool: shown invalid, with the reason.
    for a in candidate
        .ip
        .addresses
        .iter()
        .filter(|a| wanted(&a.interface))
    {
        let Some(pool) = &a.from_pool else {
            continue;
        };
        if cfg.ip.addresses.iter().any(|e| e.id == a.id) {
            continue;
        }
        let (address, reason) = super::ipv6::pool_view(s, candidate, pool, a.address);
        let mut flags = String::new();
        if a.disabled {
            flags.push('X');
        }
        flags.push('I');
        rows.push(json!({
            "id": a.id,
            "flags": flags,
            "address": address,
            "network": a.address.trunc().to_string(),
            "interface": a.interface,
            "disabled": a.disabled,
            "dynamic": false,
            "comment": a.comment,
            "from_pool": a.from_pool,
            "origin": "pool",
            "reason": reason,
        }));
    }
    // What the kernel learned from Router Advertisements (G4.7b).
    for (n, l) in learned.iter().enumerate() {
        if let Learned::Address {
            interface,
            address,
            valid_secs,
            preferred_secs,
        } = l
            && wanted(interface)
        {
            rows.push(json!({
                "id": ra_id(n),
                "flags": "D",
                "address": address.to_string(),
                "network": address.trunc().to_string(),
                "interface": interface,
                "disabled": false,
                "dynamic": true,
                "comment": "",
                "from_pool": null,
                "origin": "ra",
                "valid_after": valid_secs.map(|v| duration_text(u64::from(v))),
                "preferred_after": preferred_secs.map(|v| duration_text(u64::from(v))),
            }));
        }
    }
    decorate(s, &mut rows);
    Ok(Value::Array(rows))
}

/// What G1.28 adds to every row: `state`, `family`, `vrf` and `access`
/// (the flags stay for the terminal).
fn decorate(s: &mut Session, rows: &mut [Value]) {
    let states = s.hal_mut().address_states().unwrap_or_else(|e| {
        log::debug!("address states: {e}");
        Vec::new()
    });
    let cfg = s.effective(s.store().candidate()).into_owned();
    let access: Vec<(ItemId, String)> = s
        .caller()
        .link
        .map(|l| crate::lockout::access_addresses(&cfg, &l))
        .unwrap_or_default();
    for row in rows.iter_mut() {
        let text = |k: &str| row.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
        let (address, interface, flags) = (text("address"), text("interface"), text("flags"));
        let iface: Option<IfName> = interface.parse().ok();
        let link = iface.as_ref().and_then(|i| cfg.interfaces.get(i));
        let kernel = states
            .iter()
            .find(|k| k.interface.as_str() == interface && k.address.to_string() == address);
        let state = if flags.contains('X') {
            "disabled"
        } else if flags.contains('I') || link.is_none_or(|l| l.disabled) {
            "invalid"
        } else if let Some(k) = kernel {
            if k.dad_failed {
                "dad-failed"
            } else if k.tentative {
                "tentative"
            } else {
                "deprecated"
            }
        } else {
            "active"
        };
        let family = if address.contains(':') { "ipv6" } else { "ipv4" };
        let vrf = iface
            .as_ref()
            .map(|i| corerouter_model::route::table_of(&cfg, i).to_string())
            .unwrap_or_default();
        let id = row.get("id").and_then(Value::as_str).and_then(|i| i.parse::<ItemId>().ok());
        let why = id.and_then(|id| access.iter().find(|(a, _)| *a == id).map(|(_, w)| w.clone()));
        if let Some(o) = row.as_object_mut() {
            o.insert("state".into(), json!(state));
            o.insert("family".into(), json!(family));
            o.insert("vrf".into(), json!(vrf));
            o.insert("access".into(), json!(why));
            if let Some(k) = kernel
                && !o.get("valid_after").is_some_and(|v| !v.is_null())
            {
                o.insert("valid_after".into(), json!(k.valid_secs.map(|v| duration_text(u64::from(v)))));
                o.insert("preferred_after".into(), json!(k.preferred_secs.map(|v| duration_text(u64::from(v)))));
            }
        }
    }
}
