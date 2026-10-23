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
        "{id: *hex} → {id}",
        has_addresses,
        remove
    ),
    cmd!(query "ip.address.list", "Addresses", ["IP", "Addresses"], None,
        "{interface?: string} → [{id, flags (X disabled, I invalid, D dynamic), address, network, interface, disabled, dynamic, comment, from_pool, origin (static | dhcp | dhcpv6 | ra | pool), valid_after, preferred_after, reason}]",
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
        return Err(EngineError::bad(
            "id",
            format!(
                "{id} is dynamic (a DHCP client's lease or a Router Advertisement); release, \
                 disable or remove the client instead (ip.dhcp-client.*, ipv6.dhcp-client.*), or \
                 stop accepting RA (ipv6.settings.set)"
            ),
        ));
    }
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
    Ok(Value::Array(rows))
}
