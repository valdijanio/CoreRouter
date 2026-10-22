//! /ip address

use corerouter_model::{AddressEntry, IfName, ItemId};
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_text, req_parse};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.address.add",
        "Add Address",
        ["IP", "Addresses"],
        None,
        "{address: cidr (10.0.0.1/24 | 2001:db8::1/64), interface: string, disabled?: bool, comment?: string} → {id}",
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
        "{interface?: string} → [{id, address, network, interface, disabled, comment}]",
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
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();

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
    let id = cfg.ip.next_address_id();
    cfg.ip.addresses.push(AddressEntry {
        id,
        address,
        interface,
        disabled,
        comment,
    });
    Ok(json!({ "id": id }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
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
    let rows = s
        .store()
        .candidate()
        .ip
        .addresses
        .iter()
        .filter(|a| filter.as_ref().is_none_or(|f| *f == a.interface))
        .map(|a| {
            json!({
                "id": a.id,
                "address": a.address.to_string(),
                "network": a.address.trunc().to_string(),
                "interface": a.interface,
                "disabled": a.disabled,
                "comment": a.comment,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}
