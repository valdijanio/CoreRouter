//! /ip firewall fastpath (G2.4): the flowtable (RouterOS FastTrack) and
//! hardware flow offload, with what each port's card can do.
//!
//! The rules themselves are `corerouter_firewall::fastpath` (a chain after
//! the firewall's forward chain feeds the flowtable, so only accepted
//! connections enter it); the backend installs them at commit and says
//! what it got (`Hal::fastpath_state`).

use corerouter_hal::fastpath::{Eswitch, EswitchMode};
use corerouter_model::IfName;
use corerouter_model::config::InterfaceKind;
use corerouter_model::fastpath::{HwOffload, MAX_INTERFACES};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str};
use super::dhcp_client::opt_list;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.firewall.fastpath.set",
        "Fast Path",
        [],
        None,
        "{enabled?: bool, interfaces?: [string] | string (the flowtable's ports, comma-separated; empty: every Ethernet and bond port), hw_offload?: auto | yes | no (auto: ask the card, fall back to software; yes: refuse when the card refuses), counters?: bool (flowtable counters, kernel 5.7+)} → {enabled, interfaces, hw_offload, counters}",
        always,
        set
    ),
    cmd!(query "ip.firewall.fastpath.get", "Fast Path", [], None,
        "{} → {enabled, interfaces, hw_offload, counters}",
        always, get),
    cmd!(query "ip.firewall.fastpath.status", "Fast Path Status", [], None,
        "{} → {enabled, active, hardware, note?, hw_offload, ports: [{name, in_flowtable, offload (hardware | software | off), driver?, firmware?, devlink?, eswitch? (legacy | switchdev), representor, hw_tc_offload?, why?, fix? (what to run for hardware offload)}], flows: {total, software, hardware}}",
        always, status),
];

fn view(fp: &corerouter_model::fastpath::FastPath) -> Value {
    json!({
        "enabled": fp.enabled,
        "interfaces": fp.interfaces.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "hw_offload": fp.hw_offload.as_str(),
        "counters": fp.counters,
    })
}

/// Hardware offload is possible on this port (the card says so).
fn capable(e: &Eswitch) -> bool {
    e.mode == Some(EswitchMode::Switchdev) && e.hw_tc_offload == Some(true)
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let enabled = opt_bool(p, "enabled")?;
    let hw = match opt_str(p, "hw_offload")? {
        None => None,
        Some(t) => Some(HwOffload::parse(t).ok_or_else(|| {
            EngineError::bad("hw_offload", "auto, yes or no")
        })?),
    };
    let counters = opt_bool(p, "counters")?;
    let names = opt_list(p, "interfaces")?;
    let mut interfaces: Option<Vec<IfName>> = None;
    if let Some(list) = names {
        if list.len() > MAX_INTERFACES {
            return Err(EngineError::bad("interfaces", format!("at most {MAX_INTERFACES}")));
        }
        let cfg = s.store().candidate();
        let mut out: Vec<IfName> = Vec::new();
        for n in list {
            let name: IfName = n
                .parse()
                .map_err(|_| EngineError::bad("interfaces", format!("'{}' is not an interface name", trunc(&n))))?;
            let Some(i) = cfg.interfaces.get(&name) else {
                return Err(EngineError::bad("interfaces", format!("no interface '{name}'")));
            };
            match &i.kind {
                InterfaceKind::Ethernet | InterfaceKind::Bonding { .. } => {}
                // Kernel 5.13+: the flowtable finds the real device of a
                // VLAN itself; naming the VLAN is refused (EOPNOTSUPP).
                InterfaceKind::Vlan { parent, .. } => {
                    return Err(EngineError::bad(
                        "interfaces",
                        format!("'{name}' is a VLAN: name its port '{parent}' (the flowtable follows VLANs on it)"),
                    ));
                }
                _ => {
                    return Err(EngineError::bad(
                        "interfaces",
                        format!("'{name}' is not an Ethernet or bond port"),
                    ));
                }
            }
            if let Some(bond) = &i.bond {
                return Err(EngineError::bad(
                    "interfaces",
                    format!("'{name}' is a slave of bond '{bond}': name the bond"),
                ));
            }
            if !out.contains(&name) {
                out.push(name);
            }
        }
        interfaces = Some(out);
    }
    // hw_offload=yes: refuse now what the commit would be refused for.
    let mut next = s.store().candidate().ip.fastpath.clone();
    if let Some(v) = enabled {
        next.enabled = v;
    }
    if let Some(v) = hw {
        next.hw_offload = v;
    }
    if let Some(v) = counters {
        next.counters = v;
    }
    if let Some(v) = interfaces {
        next.interfaces = v;
    }
    if next.enabled && next.hw_offload == HwOffload::Yes {
        let cfg = s.store().candidate().clone();
        let ports = corerouter_firewall::fastpath::devices(&next, &cfg, |_| true);
        let any = ports.iter().any(|n| {
            n.parse::<IfName>()
                .ok()
                .and_then(|n| s.hal_mut().eswitch(&n).ok())
                .is_some_and(|e| capable(&e))
        });
        if !any {
            return Err(EngineError::bad(
                "hw_offload",
                "no port of the fast path can offload in hardware (it needs a card in switchdev mode with hw-tc-offload on: see ip.firewall.fastpath.status); use auto to run in software meanwhile",
            ));
        }
    }
    let out = view(&next);
    s.store_mut().candidate_mut().ip.fastpath = next;
    if let Some(c) = s.ext_mut::<super::firewall_connection::ConnCache>() {
        c.forget();
    }
    Ok(out)
}

fn trunc(s: &str) -> String {
    s.chars().take(40).collect()
}

fn get(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(view(&s.store().candidate().ip.fastpath))
}

fn status(s: &mut Session, _: &Value) -> Result<Value> {
    let cfg = s.store().running().clone();
    let fp = cfg.ip.fastpath.clone();
    let state = s.hal_mut().fastpath_state();
    let candidates = corerouter_firewall::fastpath::devices(
        &corerouter_model::fastpath::FastPath {
            interfaces: Vec::new(),
            ..fp.clone()
        },
        &cfg,
        |_| true,
    );
    // Every Ethernet and bond port, plus named ones (the table shows why a
    // port is in the flowtable or not).
    let mut names = candidates;
    for n in &fp.interfaces {
        let n = n.to_string();
        if !names.contains(&n) {
            names.push(n);
        }
    }
    let mut ports = Vec::new();
    for n in names {
        let Ok(name) = n.parse::<IfName>() else { continue };
        let e = s.hal_mut().eswitch(&name).unwrap_or_default();
        let in_ft = state.active && state.devices.contains(&n);
        let hw = in_ft && state.hardware && capable(&e);
        let offload = if hw {
            "hardware"
        } else if in_ft {
            "software"
        } else {
            "off"
        };
        let mut row = json!({
            "name": n,
            "in_flowtable": in_ft,
            "offload": offload,
            "representor": e.representor,
        });
        let o = row.as_object_mut();
        if let Some(o) = o {
            for (k, v) in [("driver", &e.driver), ("firmware", &e.firmware), ("devlink", &e.devlink)] {
                if let Some(v) = v {
                    o.insert(k.into(), json!(v));
                }
            }
            if let Some(m) = e.mode {
                o.insert("eswitch".into(), json!(m.as_str()));
            }
            if let Some(t) = e.hw_tc_offload {
                o.insert("hw_tc_offload".into(), json!(t));
            }
            let (why, fix) = advice(&n, &e, in_ft, &fp);
            if let Some(w) = why {
                o.insert("why".into(), json!(w));
            }
            if let Some(f) = fix {
                o.insert("fix".into(), json!(f));
            }
        }
        ports.push(row);
    }
    let mut flows = json!({"total": 0, "software": 0, "hardware": 0});
    if let Ok(conns) = s.hal_mut().connections() {
        let (mut soft, mut hard) = (0u64, 0u64);
        for c in &conns {
            match c.via() {
                corerouter_hal::conntrack::Via::Software => soft += 1,
                corerouter_hal::conntrack::Via::Hardware => hard += 1,
                corerouter_hal::conntrack::Via::Rules => {}
            }
        }
        flows = json!({"total": conns.len(), "software": soft, "hardware": hard});
    }
    let mut out = json!({
        "enabled": fp.enabled,
        "active": state.active,
        "hardware": state.hardware,
        "hw_offload": fp.hw_offload.as_str(),
        "ports": ports,
        "flows": flows,
    });
    if let (Some(n), Some(o)) = (state.note, out.as_object_mut()) {
        o.insert("note".into(), json!(n));
    }
    Ok(out)
}

/// Why port `n` is not offloaded in hardware, and what to run for it.
fn advice(
    n: &str,
    e: &Eswitch,
    in_ft: bool,
    fp: &corerouter_model::fastpath::FastPath,
) -> (Option<String>, Option<String>) {
    if !fp.enabled {
        return (Some("the fast path is off".into()), Some("ip.firewall.fastpath.set {\"enabled\": true}".into()));
    }
    if !in_ft {
        return (Some("not a port of the flowtable".into()), None);
    }
    if fp.hw_offload == HwOffload::No {
        return (Some("hardware offload is off (hw_offload=no)".into()), None);
    }
    if capable(e) {
        return (None, None);
    }
    match (e.mode, e.hw_tc_offload, &e.devlink) {
        (Some(EswitchMode::Legacy), _, Some(dl)) => (
            Some("the card's eSwitch is in legacy mode: flow offload needs switchdev".into()),
            Some(format!(
                "devlink dev eswitch set {dl} mode switchdev   (as root; the card restarts and its links drop for a few seconds)"
            )),
        ),
        (Some(EswitchMode::Switchdev), Some(false), _) => (
            Some("hw-tc-offload is off".into()),
            Some(format!("interface.ethernet.set {{\"name\": \"{n}\", \"offloads\": \"hw-tc-offload:on\"}}")),
        ),
        _ => (Some("this card has no flow offload: software only".into()), None),
    }
}
