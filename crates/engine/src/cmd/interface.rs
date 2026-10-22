//! /interface

use corerouter_model::IfName;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text, opt_u32, req_parse};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "interface.list", "Interfaces", ["Interfaces"], None,
        "{type?: ether|vlan|bridge|loopback} → [{name, type, mtu, disabled, running, rx_bytes, tx_bytes, rx_packets, tx_packets, comment}]",
        always, list),
    cmd!(
        "interface.set",
        "Set Interface",
        [],
        None,
        "{name: string, mtu?: u32 (68..=9216), disabled?: bool, comment?: string} → {name}",
        always,
        set
    ),
];

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let filter = opt_str(p, "type")?;
    let live = s.hal_mut().poll();
    let rows = s
        .store()
        .candidate()
        .interfaces
        .values()
        .filter(|i| filter.is_none_or(|t| i.kind.label() == t))
        .map(|i| {
            let st = live.iter().find(|l| l.name == i.name);
            json!({
                "name": i.name,
                "type": i.kind.label(),
                "mtu": i.mtu,
                "disabled": i.disabled,
                "running": st.is_some_and(|l| l.running),
                "rx_bytes": st.map_or(0, |l| l.rx_bytes),
                "tx_bytes": st.map_or(0, |l| l.tx_bytes),
                "rx_packets": st.map_or(0, |l| l.rx_packets),
                "tx_packets": st.map_or(0, |l| l.tx_packets),
                "comment": i.comment,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    let mtu = opt_u32(p, "mtu")?;
    let disabled = opt_bool(p, "disabled")?;
    let comment = opt_text(p, "comment", 256)?;
    let iface = s
        .store_mut()
        .candidate_mut()
        .interfaces
        .get_mut(&name)
        .ok_or_else(|| EngineError::bad("name", format!("no interface '{name}'")))?;
    if let Some(mtu) = mtu {
        iface.mtu = u16::try_from(mtu)
            .ok()
            .filter(|m| (68..=9216).contains(m))
            .ok_or_else(|| EngineError::bad("mtu", "must be 68..=9216"))?;
    }
    if let Some(d) = disabled {
        iface.disabled = d;
    }
    if let Some(c) = comment {
        iface.comment = c;
    }
    Ok(json!({ "name": name }))
}
