//! /interface wifi peer (G1.30m): the station-bridges of other routers that
//! one of this router's access points takes. Each peer is an interface of
//! its own (type `wifi-peer`) with a fixed name: its four-address link,
//! there while the peer is associated, a bridge port or a bonding slave
//! like any other. Its configuration waits for it while it is away, as a
//! port's does (`corerouter_hal::absent`).
//!
//! Only the registered peers get four addresses: hostapd sends away any
//! other station that asks (`crate::wifi_ap`). RouterOS has no such list:
//! its `station-bridge` is taken by any RouterOS access point with the
//! passphrase (`bridge-mode`), which this makes explicit.
//!
//! What is refused, so that the mistake is not made:
//! - a peer on a radio that is not an access point taking station-bridges
//!   (`station_bridge` yes or only);
//! - a MAC already registered on that radio, a name already taken.

use corerouter_model::wifi::{StationBridge, WifiMode, WifiPeer};
use corerouter_model::{IfName, Interface, InterfaceKind, MacAddr};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_text, req_parse};
use super::wifi::has_radios;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

/// Peers per access point at most.
pub const MAX_PEERS: usize = 32;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "interface.wifi.peer.add",
        "Add Wi-Fi Peer",
        ["Interfaces", "Wi-Fi"],
        None,
        "{radio: string (an access point with station_bridge yes or only), name: string (the peer's link, an interface name: peer1), mac_address: string (the peer station's MAC), comment?: string, disabled?: bool} → {name, warnings}",
        has_radios,
        add
    ),
    cmd!(
        "interface.wifi.peer.remove",
        "Remove Wi-Fi Peer",
        [],
        None,
        "{name: string (nothing may depend on it: take it out of its bridge or bond first)} → {name}",
        has_peers,
        remove
    )
    .positional("name"),
    cmd!(query "interface.wifi.peer.print", "Wi-Fi Peers", [], None,
        "{radio?: string} → [{name, radio, mac_address, comment, disabled, state (up | away | disabled), bridge, bond, signal, tx_rate, rx_rate, uptime_secs, retry_percent}]",
        always, print),
];

fn has_peers(s: &Session) -> std::result::Result<(), String> {
    let any = s
        .store()
        .candidate()
        .interfaces
        .values()
        .any(|i| matches!(i.kind, InterfaceKind::WifiPeer(_)));
    if any {
        Ok(())
    } else {
        Err("no Wi-Fi peer registered".into())
    }
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let radio: IfName = req_parse(p, "radio")?;
    let name: IfName = req_parse(p, "name")?;
    let mac: MacAddr = req_parse(p, "mac_address")?;
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let cfg = s.store().candidate();
    let (_, st) = super::wifi::radio_of(cfg, &radio).map_err(|_| {
        EngineError::bad("radio", format!("no Wi-Fi interface '{radio}' (see interface.wifi.list)"))
    })?;
    if st.mode != WifiMode::Ap {
        return Err(EngineError::bad(
            "radio",
            format!(
                "'{radio}' is not an access point: peers join an access point (interface.wifi.set \
                 name={radio} mode=ap station_bridge=yes)"
            ),
        ));
    }
    let mut warnings = Vec::new();
    if st.station_bridge == StationBridge::No {
        warnings.push(format!(
            "'{radio}' takes no station-bridges yet: interface.wifi.set name={radio} \
             station_bridge=yes (or only)"
        ));
    }
    if cfg.interfaces.contains_key(&name) {
        return Err(EngineError::bad(
            "name",
            format!("there is an interface '{name}' already"),
        ));
    }
    let peers: Vec<&WifiPeer> = cfg
        .interfaces
        .values()
        .filter_map(|i| match &i.kind {
            InterfaceKind::WifiPeer(p) if p.radio == radio => Some(&**p),
            _ => None,
        })
        .collect();
    if peers.iter().any(|p| p.mac == mac) {
        return Err(EngineError::bad(
            "mac_address",
            format!("{mac} is a peer of '{radio}' already"),
        ));
    }
    if peers.len() >= MAX_PEERS {
        return Err(EngineError::bad(
            "radio",
            format!("'{radio}' has {MAX_PEERS} peers, the most it takes"),
        ));
    }
    let mut iface = Interface::new(
        name.clone(),
        InterfaceKind::WifiPeer(Box::new(WifiPeer { radio, mac })),
    );
    iface.comment = comment;
    iface.disabled = disabled;
    s.store_mut().candidate_mut().interfaces.insert(name.clone(), iface);
    Ok(json!({ "name": name, "warnings": warnings }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    match s.store().candidate().interfaces.get(&name).map(|i| &i.kind) {
        Some(InterfaceKind::WifiPeer(_)) => {}
        Some(k) => {
            return Err(EngineError::bad(
                "name",
                format!("'{name}' is a {}, not a Wi-Fi peer", k.label()),
            ));
        }
        None => {
            return Err(EngineError::bad(
                "name",
                format!("no Wi-Fi peer '{name}' (see interface.wifi.peer.print)"),
            ));
        }
    }
    super::interface::remove(s, &json!({ "name": name }))
}

fn print(s: &mut Session, p: &Value) -> Result<Value> {
    let only: Option<IfName> = opt_parse(p, "radio")?;
    let cfg = s.store().candidate();
    let rt = s.wifi();
    let rows: Vec<Value> = cfg
        .interfaces
        .values()
        .filter_map(|i| match &i.kind {
            InterfaceKind::WifiPeer(p) if only.as_ref().is_none_or(|o| *o == p.radio) => {
                Some((i, p))
            }
            _ => None,
        })
        .map(|(i, p)| {
            let mac = p.mac.to_string().to_ascii_lowercase();
            let client = rt
                .and_then(|rt| rt.aps.get(&p.radio))
                .and_then(|a| a.status.clients.iter().find(|c| c.mac == mac));
            let up = client.is_some_and(|c| c.peer.is_some());
            let l = client.map(|c| &c.link);
            json!({
                "name": i.name,
                "radio": p.radio,
                "mac_address": mac,
                "comment": i.comment,
                "disabled": i.disabled,
                "state": if i.disabled { "disabled" } else if up { "up" } else { "away" },
                "bridge": i.bridge,
                "bond": i.bond,
                "signal": l.and_then(|l| l.signal_avg_dbm),
                "tx_rate": l.and_then(|l| l.tx.as_ref()).map(super::wifi::rate_json),
                "rx_rate": l.and_then(|l| l.rx.as_ref()).map(super::wifi::rate_json),
                "uptime_secs": l.and_then(|l| l.connected_secs),
                "retry_percent": l.and_then(|l| super::wifi::retry_percent(l.tx_retries, l.tx_packets)),
            })
        })
        .collect();
    Ok(Value::Array(rows))
}
