//! `/interface ethernet set` and `cable-test` (G1.20): link settings of a
//! physical port, checked against what the port says it can do before
//! anything is applied, and the PHY's cable test as a task.
//!
//! The settings live in the config (`Interface::ethernet`), so they are in
//! the journal, the history and `config.rollback`, and Safe Mode undoes
//! them. A change that renegotiates the link of the port this connection
//! comes in through is refused outside Safe Mode unless `force` says the
//! operator means it: a speed or duplex mismatch keeps the link down, and
//! with it the only way back in.

use std::collections::BTreeSet;
use std::net::IpAddr;

use corerouter_hal::nic::mode_speed;
use corerouter_hal::{EthernetMonitor, HalError, Offload};
use corerouter_model::{Config, EthernetSettings, FlowControl, IfName, InterfaceKind};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, req_parse};
use super::interface::refuse_unmanaged;
use super::interface_info::rate;
use super::{CommandSpec, always};
use crate::tasks::can_run;
use crate::{Caller, EngineError, Result, Session};

/// Hostile-input bound on `advertise` and `offloads`.
const MAX_LIST: usize = 128;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("interface.ethernet.set", "Set Ethernet", [], None,
        "{name: string, auto_negotiation?: bool (default true: the port negotiates), speed?: string (forced rate with auto_negotiation=false: 10Mbps | 100Mbps | 1Gbps | 2.5Gbps | 10Gbps | … or a link mode: 100M-baseT-full, 1000baseT/Full), duplex?: full|half (forced, with auto_negotiation=false), advertise?: [string] | string (link modes to advertise, kernel or RouterOS names, comma-separated; all = every one the port supports), rx_flow_control?: on|off|auto, tx_flow_control?: on|off|auto, offloads?: string | object (gro:off,tso:on or {\"rx-gro\": false}; short or kernel names), reset?: bool (forget every setting: back to the port's own), force?: bool (change the link of the port this connection uses outside Safe Mode; turn LRO on)} → {name, ethernet, warnings}",
        always, set)
    .positional("name"),
    // `/interface ethernet print` (G3.9hl): the ports with what
    // `interface.ethernet.set` changed on them, as `set` takes it back
    // (`/export` writes it from here).
    cmd!(query "interface.ethernet.list", "Ethernet", [], None,
        "{} → [{name, mtu, mac_address, auto_negotiation, speed, duplex, advertise, rx_flow_control, tx_flow_control, offloads (name:on|off,…), disabled, running, comment}]",
        always, list),
    cmd!(query "interface.ethernet.cable-test", "Cable Test", [], None,
        "{name: string, force?: bool (test the port this connection uses: its link drops for a few seconds)} → {id, task_id, columns}",
        can_run, cable_test)
    .positional("name")
    .task(),
];

/// RouterOS v7.12+ link mode names → the kernel modes they stand for.
const ROUTEROS_MODES: &[(&str, &[&str])] = &[
    ("10M-baseT-half", &["10baseT/Half"]),
    ("10M-baseT-full", &["10baseT/Full"]),
    ("100M-baseT-half", &["100baseT/Half"]),
    ("100M-baseT-full", &["100baseT/Full"]),
    ("100M-baseFX-full", &["100baseFX/Full"]),
    ("1G-baseT-half", &["1000baseT/Half"]),
    ("1G-baseT-full", &["1000baseT/Full"]),
    ("1G-baseX", &["1000baseX/Full", "1000baseKX/Full"]),
    ("2.5G-baseT", &["2500baseT/Full"]),
    ("2.5G-baseX", &["2500baseX/Full"]),
    ("5G-baseT", &["5000baseT/Full"]),
    ("10G-baseT", &["10000baseT/Full"]),
    (
        "10G-baseSR-LR",
        &[
            "10000baseSR/Full",
            "10000baseLR/Full",
            "10000baseLRM/Full",
            "10000baseER/Full",
        ],
    ),
    ("10G-baseCR", &["10000baseCR/Full"]),
    ("25G-baseSR-LR", &["25000baseSR/Full"]),
    ("25G-baseCR", &["25000baseCR/Full"]),
    (
        "40G-baseSR4-LR4",
        &["40000baseSR4/Full", "40000baseLR4/Full"],
    ),
    ("40G-baseCR4", &["40000baseCR4/Full"]),
    ("50G-baseSR2-LR2", &["50000baseSR2/Full"]),
    ("50G-baseCR2", &["50000baseCR2/Full"]),
    (
        "100G-baseSR4-LR4",
        &["100000baseSR4/Full", "100000baseLR4_ER4/Full"],
    ),
    ("100G-baseCR4", &["100000baseCR4/Full"]),
];

/// Offload short names (as `interface.hardware` shows them) → feature.
const OFFLOAD_ALIASES: &[(&str, &str)] = &[
    ("tso", "tx-tcp-segmentation"),
    ("tso6", "tx-tcp6-segmentation"),
    ("gso", "tx-generic-segmentation"),
    ("gro", "rx-gro"),
    ("lro", "rx-lro"),
    ("rx-checksum", "rx-checksum"),
    ("rxcsum", "rx-checksum"),
    ("sg", "tx-scatter-gather"),
    ("rxvlan", "rx-vlan-hw-parse"),
    ("txvlan", "tx-vlan-hw-insert"),
    ("rxhash", "rx-hashing"),
    ("ntuple", "rx-ntuple-filter"),
];

fn shown(s: &str) -> String {
    s.chars().take(64).collect()
}

/// The modes `raw` names among `supported` (rate modes only).
fn resolve_mode(raw: &str, supported: &[String]) -> std::result::Result<Vec<String>, String> {
    let raw = raw.trim();
    if let Some(m) = supported
        .iter()
        .find(|m| m.eq_ignore_ascii_case(raw) && mode_speed(m).is_some())
    {
        return Ok(vec![m.clone()]);
    }
    let Some((_, kernel)) = ROUTEROS_MODES
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(raw))
    else {
        return Err(if mode_speed(raw).is_some() {
            format!("this port does not support {}", shown(raw))
        } else {
            format!("'{}' is not a link mode", shown(raw))
        });
    };
    let found: Vec<String> = supported
        .iter()
        .filter(|m| kernel.contains(&m.as_str()))
        .cloned()
        .collect();
    if found.is_empty() {
        return Err(format!("this port does not support {}", shown(raw)));
    }
    Ok(found)
}

/// "can: 100baseT/Full, 1000baseT/Full".
fn can_do(supported: &[String]) -> String {
    let rates: Vec<&str> = supported
        .iter()
        .filter(|m| mode_speed(m).is_some())
        .map(String::as_str)
        .collect();
    if rates.is_empty() {
        "the driver lists no link modes".into()
    } else {
        format!("it can do {}", rates.join(", "))
    }
}

/// `advertise`: a list or a comma-separated string.
fn advertise(p: &Value, supported: &[String]) -> Result<Option<Vec<String>>> {
    let raw: Vec<String> = match p.get("advertise") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.split(',').map(str::to_owned).collect(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| EngineError::bad("advertise", "must be link mode names"))
            })
            .collect::<Result<_>>()?,
        Some(_) => return Err(EngineError::bad("advertise", "must be link mode names")),
    };
    if raw.len() > MAX_LIST {
        return Err(EngineError::bad(
            "advertise",
            format!("at most {MAX_LIST} modes"),
        ));
    }
    let raw: Vec<&str> = raw
        .iter()
        .map(|r| r.trim())
        .filter(|r| !r.is_empty())
        .collect();
    let mut out = BTreeSet::new();
    for r in raw.iter().copied() {
        if r.eq_ignore_ascii_case("all") {
            out.extend(
                supported
                    .iter()
                    .filter(|m| mode_speed(m).is_some())
                    .cloned(),
            );
            continue;
        }
        let modes = resolve_mode(r, supported).map_err(|why| {
            EngineError::bad("advertise", format!("{why} ({})", can_do(supported)))
        })?;
        out.extend(modes);
    }
    if out.is_empty() {
        return Err(EngineError::bad(
            "advertise",
            format!("name at least one link mode ({})", can_do(supported)),
        ));
    }
    Ok(Some(out.into_iter().collect()))
}

/// `speed`: a rate (`1Gbps`, `100Mbps`, `1000`) or a link mode; the mode
/// also gives the duplex.
fn speed(raw: &str, supported: &[String]) -> Result<(u32, Option<bool>)> {
    let t = raw.trim();
    let lower = t.to_ascii_lowercase();
    let num = |s: &str, scale: f64| -> Option<u32> {
        let v: f64 = s.trim().parse().ok()?;
        let mbps = v * scale;
        (mbps.is_finite() && (1.0..=1_000_000.0).contains(&mbps)).then(|| mbps.round() as u32)
    };
    let parsed = if let Some(g) = lower
        .strip_suffix("gbps")
        .or_else(|| lower.strip_suffix('g'))
    {
        num(g, 1000.0)
    } else if let Some(m) = lower
        .strip_suffix("mbps")
        .or_else(|| lower.strip_suffix('m'))
    {
        num(m, 1.0)
    } else {
        num(&lower, 1.0)
    };
    if let Some(mbps) = parsed {
        return Ok((mbps, None));
    }
    let modes = resolve_mode(t, supported)
        .map_err(|why| EngineError::bad("speed", format!("{why} ({})", can_do(supported))))?;
    let (mbps, full) = modes
        .first()
        .and_then(|m| mode_speed(m))
        .ok_or_else(|| EngineError::bad("speed", format!("'{}' has no rate", shown(t))))?;
    Ok((mbps, Some(full)))
}

fn flow(p: &Value, key: &str) -> Result<Option<FlowControl>> {
    match opt_str(p, key)? {
        None => Ok(None),
        Some("on") => Ok(Some(FlowControl::On)),
        Some("off") => Ok(Some(FlowControl::Off)),
        Some("auto") => Ok(Some(FlowControl::Auto)),
        Some(other) => Err(EngineError::bad(
            key,
            format!("'{}' is not on, off or auto", shown(other)),
        )),
    }
}

/// `offloads`: `{feature: bool}` or `gro:off,tso:on`.
fn offloads(p: &Value) -> Result<Vec<(String, bool)>> {
    let on_off = |v: &str| match v.trim().to_ascii_lowercase().as_str() {
        "on" | "yes" | "true" => Some(true),
        "off" | "no" | "false" => Some(false),
        _ => None,
    };
    let pairs: Vec<(String, bool)> = match p.get("offloads") {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Object(o)) => o
            .iter()
            .map(|(k, v)| {
                let on = match v {
                    Value::Bool(b) => Some(*b),
                    Value::String(s) => on_off(s),
                    _ => None,
                };
                on.map(|b| (k.clone(), b)).ok_or_else(|| {
                    EngineError::bad("offloads", format!("'{}' must be on or off", shown(k)))
                })
            })
            .collect::<Result<_>>()?,
        Some(Value::String(s)) => s
            .split(',')
            .filter(|x| !x.trim().is_empty())
            .map(|item| {
                let (k, v) = item
                    .split_once(':')
                    .or_else(|| item.split_once('='))
                    .ok_or_else(|| {
                        EngineError::bad(
                            "offloads",
                            format!("'{}' is not name:on|off", shown(item)),
                        )
                    })?;
                let on = on_off(v).ok_or_else(|| {
                    EngineError::bad("offloads", format!("'{}' must be on or off", shown(item)))
                })?;
                Ok((k.trim().to_owned(), on))
            })
            .collect::<Result<_>>()?,
        Some(_) => {
            return Err(EngineError::bad(
                "offloads",
                "must be name:on|off pairs or an object",
            ));
        }
    };
    if pairs.len() > MAX_LIST {
        return Err(EngineError::bad(
            "offloads",
            format!("at most {MAX_LIST} offloads"),
        ));
    }
    Ok(pairs)
}

/// The offload `name` (short like `GRO`, or the kernel feature) among the
/// port's.
fn find_offload<'a>(name: &str, known: &'a [Offload]) -> Option<&'a Offload> {
    let lower = name.trim().to_ascii_lowercase();
    let feature = OFFLOAD_ALIASES
        .iter()
        .find(|(a, _)| *a == lower)
        .map_or(lower.as_str(), |(_, f)| f);
    known.iter().find(|o| {
        o.feature == feature || o.name.eq_ignore_ascii_case(name.trim()) || o.feature == lower
    })
}

/// The interfaces whose physical ports carry `cfg` interface `name`
/// (VLAN parents, bridge, bond and VRF members), bounded.
fn physical(cfg: &Config, name: &IfName, depth: u8, out: &mut BTreeSet<IfName>) {
    let Some(iface) = cfg.interfaces.get(name) else {
        return;
    };
    if depth > 8 {
        return;
    }
    match &iface.kind {
        InterfaceKind::Ethernet => {
            out.insert(name.clone());
        }
        InterfaceKind::Vlan { parent, .. } => physical(cfg, parent, depth + 1, out),
        InterfaceKind::PppoeClient(c) => physical(cfg, &c.interface, depth + 1, out),
        InterfaceKind::Bridge => {
            for m in cfg
                .interfaces
                .values()
                .filter(|i| i.bridge.as_ref() == Some(name))
            {
                physical(cfg, &m.name, depth + 1, out);
            }
        }
        InterfaceKind::Bonding { .. } => {
            for m in cfg
                .interfaces
                .values()
                .filter(|i| i.bond.as_ref() == Some(name))
            {
                physical(cfg, &m.name, depth + 1, out);
            }
        }
        InterfaceKind::Vrf { .. } => {
            for m in cfg
                .interfaces
                .values()
                .filter(|i| i.vrf.as_ref() == Some(name))
            {
                physical(cfg, &m.name, depth + 1, out);
            }
        }
        InterfaceKind::Loopback => {}
    }
}

/// The remote address of a control-channel caller (`tcp 10.0.0.9:51234`).
fn peer(caller: &Caller) -> Option<IpAddr> {
    if caller.id == Caller::LOCAL_ID {
        return None;
    }
    let addr = caller.name.rsplit(' ').next()?;
    let ip: IpAddr = match addr.parse::<std::net::SocketAddr>() {
        Ok(sa) => sa.ip(),
        Err(_) => addr.parse().ok()?,
    };
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    (!ip.is_loopback()).then_some(ip)
}

/// Physical ports this connection may come in through: those under the
/// addresses whose subnet holds the caller; when none does (a routed
/// connection), every port under any address.
pub(super) fn management_ports(s: &Session) -> Option<(IpAddr, BTreeSet<IfName>)> {
    let ip = peer(s.caller())?;
    let cfg = s.store().running();
    let addrs: Vec<_> = cfg.ip.addresses.iter().filter(|a| !a.disabled).collect();
    let direct: Vec<&IfName> = addrs
        .iter()
        .filter(|a| a.address.contains(&ip))
        .map(|a| &a.interface)
        .collect();
    let via: Vec<&IfName> = if direct.is_empty() {
        addrs.iter().map(|a| &a.interface).collect()
    } else {
        direct
    };
    let mut ports = BTreeSet::new();
    for i in via {
        physical(cfg, i, 0, &mut ports);
    }
    Some((ip, ports))
}

/// Refuse to disturb the link of the port this connection uses, unless in
/// Safe Mode (losing the connection undoes it) or `force`.
fn guard_link(s: &Session, name: &IfName, force: bool, what: &str) -> Result<Option<String>> {
    let Some((ip, ports)) = management_ports(s) else {
        return Ok(None);
    };
    if !ports.contains(name) {
        return Ok(None);
    }
    if s.in_safe_mode() {
        return Ok(Some(format!(
            "'{name}' carries this connection (from {ip}); in Safe Mode, losing it undoes the change"
        )));
    }
    if force {
        return Ok(Some(format!(
            "'{name}' carries this connection (from {ip}): forced outside Safe Mode"
        )));
    }
    Err(EngineError::bad(
        "name",
        format!(
            "'{name}' carries this connection (from {ip}): {what}. Enter Safe Mode first \
             (config.safe-mode.enter) so that losing the connection undoes it, or pass \
             force=yes"
        ),
    ))
}

/// The config interface `name`, which must be a physical port.
fn port(s: &mut Session, p: &Value) -> Result<IfName> {
    let name: IfName = req_parse(p, "name")?;
    refuse_unmanaged(s, p, &["name"])?;
    let iface = s.store().candidate().interfaces.get(&name).ok_or_else(|| {
        EngineError::bad(
            "name",
            format!("no interface '{name}' (see interface.list)"),
        )
    })?;
    if iface.kind != InterfaceKind::Ethernet {
        return Err(EngineError::bad(
            "name",
            format!(
                "'{name}' is a {}: Ethernet settings are for physical ports",
                iface.kind.label()
            ),
        ));
    }
    Ok(name)
}

/// What the port can do now, or why the driver will not say.
fn capabilities(s: &mut Session, name: &IfName) -> Result<EthernetMonitor> {
    s.hal_mut().ethernet_monitor(name).map_err(|e| match e {
        HalError::Unsupported(why) | HalError::Rejected(why) | HalError::Io(why) => {
            EngineError::bad(
                "name",
                format!("the driver of '{name}' does not let CoreRouter read its link: {why}"),
            )
        }
    })
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    let rows = super::interface::typed(s, |k| matches!(k, InterfaceKind::Ethernet))
        .into_iter()
        .map(|(i, st)| {
            let e = &i.ethernet;
            let offloads = (!e.offloads.is_empty()).then(|| {
                e.offloads
                    .iter()
                    .map(|(k, on)| format!("{k}:{}", if *on { "on" } else { "off" }))
                    .collect::<Vec<_>>()
                    .join(",")
            });
            let mac = st
                .as_ref()
                .and_then(|l| l.mac.clone())
                .or_else(|| i.mac.map(|m| m.to_string()));
            json!({
                "name": i.name,
                "mtu": i.mtu,
                "mac_address": mac,
                "auto_negotiation": e.auto_negotiation,
                "speed": e.speed_mbps.map(rate),
                "duplex": e.full_duplex.map(|f| if f { "full" } else { "half" }),
                "advertise": e.advertise,
                "rx_flow_control": e.rx_flow_control.map(FlowControl::label),
                "tx_flow_control": e.tx_flow_control.map(FlowControl::label),
                "offloads": offloads,
                "disabled": i.disabled,
                "running": st.as_ref().is_some_and(|l| l.running),
                "comment": i.comment,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let name = port(s, p)?;
    let force = opt_bool(p, "force")?.unwrap_or(false);
    let old = s
        .store()
        .candidate()
        .interfaces
        .get(&name)
        .map(|i| i.ethernet.clone())
        .unwrap_or_default();
    let mut new = if opt_bool(p, "reset")? == Some(true) {
        EthernetSettings::default()
    } else {
        old.clone()
    };
    let link_keys = ["auto_negotiation", "speed", "duplex", "advertise"];
    let wants_link = link_keys
        .iter()
        .any(|k| p.get(*k).is_some_and(|v| !v.is_null()));
    let wants_pause = ["rx_flow_control", "tx_flow_control"]
        .iter()
        .any(|k| p.get(*k).is_some_and(|v| !v.is_null()));
    let wanted_offloads = offloads(p)?;
    let mut warnings = Vec::new();

    if wants_link || wants_pause {
        let caps = capabilities(s, &name)?;
        let supported: Vec<String> = caps
            .supported
            .iter()
            .filter(|m| mode_speed(m).is_some())
            .cloned()
            .collect();
        if wants_link {
            if supported.is_empty() && caps.autoneg.is_none() {
                return Err(EngineError::bad(
                    "name",
                    format!("the driver of '{name}' reports no link modes: its link cannot be set"),
                ));
            }
            if let Some(a) = opt_bool(p, "auto_negotiation")? {
                new.auto_negotiation = Some(a);
                if a {
                    new.speed_mbps = None;
                    new.full_duplex = None;
                } else {
                    new.advertise = None;
                }
            }
            let autoneg = new.auto_negotiation.or(caps.autoneg).unwrap_or(true);
            let adv = advertise(p, &caps.supported)?;
            let sp = opt_str(p, "speed")?
                .map(|r| speed(r, &caps.supported))
                .transpose()?;
            let duplex = match opt_str(p, "duplex")? {
                None => None,
                Some("full") => Some(true),
                Some("half") => Some(false),
                Some(other) => {
                    return Err(EngineError::bad(
                        "duplex",
                        format!("'{}' is not full or half", shown(other)),
                    ));
                }
            };
            if autoneg {
                if sp.is_some() || duplex.is_some() {
                    return Err(EngineError::bad(
                        if sp.is_some() { "speed" } else { "duplex" },
                        "speed and duplex force the link: add auto_negotiation=false, or keep \
                         auto-negotiation and limit what it offers with advertise",
                    ));
                }
                if let Some(a) = adv {
                    new.advertise = Some(a);
                }
            } else {
                if adv.is_some() {
                    return Err(EngineError::bad(
                        "advertise",
                        "advertise applies while auto-negotiating: add auto_negotiation=true",
                    ));
                }
                if let Some((mbps, mode_duplex)) = sp {
                    new.speed_mbps = Some(mbps);
                    if let Some(d) = mode_duplex {
                        new.full_duplex = Some(d);
                    }
                }
                if let Some(d) = duplex {
                    new.full_duplex = Some(d);
                }
                // Forcing without a rate keeps the one in use, written down.
                if new.speed_mbps.is_none() {
                    new.speed_mbps = caps.speed_mbps.or_else(|| {
                        supported
                            .iter()
                            .filter_map(|m| mode_speed(m))
                            .map(|(s, _)| s)
                            .max()
                    });
                }
                if new.full_duplex.is_none() {
                    new.full_duplex = Some(caps.full_duplex.unwrap_or(true));
                }
                let (Some(mbps), Some(full)) = (new.speed_mbps, new.full_duplex) else {
                    return Err(EngineError::bad(
                        "speed",
                        "give the rate to force (speed=1Gbps)",
                    ));
                };
                let modes: Vec<&String> = supported
                    .iter()
                    .filter(|m| mode_speed(m) == Some((mbps, full)))
                    .collect();
                if modes.is_empty() {
                    return Err(EngineError::bad(
                        "speed",
                        format!(
                            "this port cannot be forced to {} {} duplex ({})",
                            rate(mbps),
                            if full { "full" } else { "half" },
                            can_do(&supported)
                        ),
                    ));
                }
                // IEEE 802.3 cl. 40/55/126: BASE-T at 1G and up needs
                // auto-negotiation (master/slave, training); forced, the
                // link never comes up.
                if mbps >= 1000 && modes.iter().all(|m| m.contains("baseT")) {
                    return Err(EngineError::bad(
                        "auto_negotiation",
                        format!(
                            "{} over twisted pair needs auto-negotiation (IEEE 802.3); keep it \
                             and advertise only that rate: advertise={}",
                            rate(mbps),
                            modes.first().map_or("", |m| m.as_str())
                        ),
                    ));
                }
            }
        }
        if wants_pause {
            if caps.rx_flow_control.is_none() && caps.tx_flow_control.is_none() {
                return Err(EngineError::bad(
                    "rx_flow_control",
                    format!("the driver of '{name}' has no flow control (pause frames)"),
                ));
            }
            if let Some(f) = flow(p, "rx_flow_control")? {
                new.rx_flow_control = Some(f);
            }
            if let Some(f) = flow(p, "tx_flow_control")? {
                new.tx_flow_control = Some(f);
            }
            let auto =
                [new.rx_flow_control, new.tx_flow_control].contains(&Some(FlowControl::Auto));
            if auto && new.auto_negotiation == Some(false) {
                warnings.push(
                    "flow control auto is resolved by auto-negotiation, which is off: \
                     the driver uses on"
                        .to_owned(),
                );
            }
        }
    } else {
        // Validate the enums even when nothing else asks the port.
        flow(p, "rx_flow_control")?;
        flow(p, "tx_flow_control")?;
    }

    if !wanted_offloads.is_empty() {
        let hw = s.hal_mut().hardware(&name).map_err(|e| {
            EngineError::bad(
                "offloads",
                format!("the driver of '{name}' does not report its offloads: {e}"),
            )
        })?;
        for (raw, on) in wanted_offloads {
            let Some(o) = find_offload(&raw, &hw.offloads) else {
                let names: Vec<&str> = hw.offloads.iter().map(|o| o.name.as_str()).collect();
                return Err(EngineError::bad(
                    "offloads",
                    format!(
                        "'{}' is not an offload of this port ({})",
                        shown(&raw),
                        names.join(", ")
                    ),
                ));
            };
            if o.fixed && o.active != on {
                return Err(EngineError::bad(
                    "offloads",
                    format!(
                        "{} is fixed {} by the driver of '{name}'",
                        o.name,
                        if o.active { "on" } else { "off" }
                    ),
                ));
            }
            if o.feature == "rx-lro" && on && !force {
                return Err(EngineError::bad(
                    "offloads",
                    "LRO merges received packets: a router or bridge forwards them wrong \
                     (Linux turns it off on forwarding ports); GRO is the safe one. \
                     Pass force=yes to turn it on anyway",
                ));
            }
            new.offloads.insert(o.feature.clone(), on);
        }
    }

    if old.touches_link(&new) {
        if let Some(w) = guard_link(
            s,
            &name,
            force,
            "changing its speed, duplex or auto-negotiation drops the link for a moment, \
             and a mismatch keeps it down",
        )? {
            warnings.push(w);
        }
        if new.auto_negotiation == Some(false) {
            warnings.push(
                "auto-negotiation is off: set the other end to the same rate and duplex".into(),
            );
        }
    }
    let ethernet = serde_json::to_value(&new).unwrap_or(Value::Null);
    if let Some(iface) = s.store_mut().candidate_mut().interfaces.get_mut(&name) {
        iface.ethernet = new;
    }
    Ok(json!({ "name": name, "ethernet": ethernet, "warnings": warnings }))
}

/// `ok,open:4.0,…`: RouterOS `cable-pairs`.
pub(crate) fn cable_pairs(pairs: &[corerouter_hal::CablePair]) -> String {
    pairs
        .iter()
        .map(|p| match p.distance_m {
            Some(d) => format!("{}:{d:.1}", p.status),
            None => p.status.clone(),
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn cable_test(s: &mut Session, p: &Value) -> Result<Value> {
    let name = port(s, p)?;
    let force = opt_bool(p, "force")?.unwrap_or(false);
    guard_link(
        s,
        &name,
        force,
        "a cable test takes its link down for a few seconds",
    )?;
    let mut tester = s.hal_mut().cable_tester(&name).map_err(|e| match e {
        HalError::Unsupported(why) => EngineError::bad("name", format!("not supported: {why}")),
        other => EngineError::Hal(other.to_string()),
    })?;
    let label = name.to_string();
    let id = s.start_task(
        "cable-test",
        format!("cable test {name}"),
        move |ctx| match tester.run(&|d| ctx.sleep(d)) {
            Ok(r) => {
                for pair in &r.pairs {
                    ctx.emit(json!({
                        "pair": pair.pair,
                        "status": pair.status,
                        "distance_m": pair.distance_m,
                    }));
                }
                let all_ok = !r.pairs.is_empty() && r.pairs.iter().all(|x| x.status == "ok");
                ctx.summary(json!({
                    "name": label,
                    "status": if all_ok { "ok" } else { "fault" },
                    "cable_pairs": cable_pairs(&r.pairs),
                    "pairs": r.pairs,
                    "notes": r.notes,
                }));
                Ok(())
            }
            Err(_) if ctx.stopped() => Ok(()),
            Err(HalError::Unsupported(why)) => Err(format!("not supported: {why}")),
            Err(e) => Err(e.to_string()),
        },
    )?;
    Ok(json!({
        "id": id,
        "task_id": id,
        "columns": ["pair", "status", "distance_m"],
    }))
}

/// The settings stored for `name`, as the Ethernet tab shows them.
pub(super) fn configured(s: &Session, name: &IfName) -> Value {
    s.store()
        .candidate()
        .interfaces
        .get(name)
        .filter(|i| i.kind == InterfaceKind::Ethernet)
        .map_or(Value::Null, |i| {
            serde_json::to_value(&i.ethernet).unwrap_or(Value::Null)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modes(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn routeros_and_kernel_mode_names() {
        let sup = modes(&[
            "100baseT/Full",
            "1000baseT/Full",
            "10000baseSR/Full",
            "Autoneg",
        ]);
        assert_eq!(
            resolve_mode("1G-baseT-full", &sup).unwrap(),
            ["1000baseT/Full"]
        );
        assert_eq!(
            resolve_mode("1000baset/full", &sup).unwrap(),
            ["1000baseT/Full"]
        );
        assert_eq!(
            resolve_mode("10G-baseSR-LR", &sup).unwrap(),
            ["10000baseSR/Full"]
        );
        assert!(resolve_mode("Autoneg", &sup).is_err());
        assert!(
            resolve_mode("10M-baseT-half", &sup)
                .unwrap_err()
                .contains("does not support")
        );
        assert!(
            resolve_mode("fast", &sup)
                .unwrap_err()
                .contains("not a link mode")
        );
    }

    #[test]
    fn speeds() {
        let sup = modes(&["100baseT/Full", "1000baseT/Full"]);
        assert_eq!(speed("1Gbps", &sup).unwrap(), (1000, None));
        assert_eq!(speed("2.5Gbps", &sup).unwrap(), (2500, None));
        assert_eq!(speed("100Mbps", &sup).unwrap(), (100, None));
        assert_eq!(speed("100", &sup).unwrap(), (100, None));
        assert_eq!(speed("100M-baseT-full", &sup).unwrap(), (100, Some(true)));
        assert!(speed("0", &sup).is_err());
        assert!(speed("fast", &sup).is_err());
    }

    #[test]
    fn callers_and_peers() {
        assert_eq!(peer(&Caller::local()), None);
        assert_eq!(peer(&Caller::new(3, "tcp 127.0.0.1:5000")), None);
        assert_eq!(
            peer(&Caller::new(3, "tcp 10.0.0.9:5000")),
            Some("10.0.0.9".parse().unwrap())
        );
        assert_eq!(
            peer(&Caller::new(3, "ws [::ffff:10.0.0.9]:5000")),
            Some("10.0.0.9".parse().unwrap())
        );
        assert_eq!(peer(&Caller::new(3, "x")), None);
    }
}
