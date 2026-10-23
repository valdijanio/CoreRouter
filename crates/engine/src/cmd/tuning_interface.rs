//! /system tuning interface (G1.26b): each port's rings, queues, interrupt
//! coalescing, offloads, flow control, transmit queue and `rp_filter`,
//! with the value each profile wants. Rings, queues, coalescing,
//! `txqueuelen`, qdisc and `rp_filter` live in `system.tuning.ports`; the
//! offload and flow-control rows edit the port's `ethernet` settings, the
//! ones `interface.ethernet.set` keeps (G1.20), so there is one place each.

use std::collections::BTreeMap;

use corerouter_hal::tuning::PortTuning;
use corerouter_hal::{EthernetMonitor, NicHardware};
use corerouter_model::tuning::{PORT_PARAMS, Param, offload_feature, port_param};
use corerouter_model::{FlowControl, IfName, InterfaceKind};
use serde_json::{Value, json};

use super::args::{opt_str, req_parse, req_str};
use super::interface::refuse_unmanaged;
use super::tuning::{machine, tab_id};
use super::{CommandSpec, always};
use crate::tuning::{Machine, Profile, Rec};
use crate::tuning_port::{Port, port_range, recommend_port};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "system.tuning.interface.print", "Port Tuning", [], None,
        "{} → [{name, key, value}]",
        always, print_set),
    cmd!(query "system.tuning.interface.parameter.print", "Port Tuning", [], None,
        "{name?: string, profile?: conservative|balanced|throughput|latency} → {profile, ports: [{name, driver, model, speed_mbps, notes, params: [{name, tab, section, current, configured, recommended, why, why_id, why_args, min, max, unit, choices, default, link_flap, ethernet, fixed}]}]}",
        always, print),
    cmd!(
        "system.tuning.interface.set",
        "Set Port Tuning",
        [],
        None,
        "{name: string, key: string, value: int} → {name, key, value, warnings}",
        always,
        set
    ),
    cmd!(
        "system.tuning.interface.unset",
        "Unset Port Tuning",
        [],
        None,
        "{name: string, key: string} → {name, key}",
        always,
        unset
    ),
    cmd!(
        "system.tuning.interface.apply",
        "Apply Tuning Profile to Ports",
        [],
        None,
        "{profile: conservative|balanced|throughput|latency, names?: [string]} → {profile, changed: [{name, key, from, to, link_flap}]}",
        always,
        apply
    ),
];

/// Most ports one command looks at (hostile input, and genetlink calls).
const MAX_PORTS: usize = 256;

/// One port: what the HAL says and what the config sets.
struct PortData {
    name: IfName,
    hw: NicHardware,
    mon: Option<EthernetMonitor>,
    tuning: PortTuning,
}

fn ports(s: &mut Session, only: Option<&IfName>) -> Vec<PortData> {
    let names: Vec<IfName> = s
        .store()
        .candidate()
        .interfaces
        .iter()
        .filter(|(n, i)| i.kind == InterfaceKind::Ethernet && only.is_none_or(|o| o == *n))
        .map(|(n, _)| n.clone())
        .take(MAX_PORTS)
        .collect();
    names
        .into_iter()
        .filter_map(|name| {
            let hal = s.hal_mut();
            let tuning = hal.port_tuning(&name).ok()?;
            let hw = hal.hardware(&name).unwrap_or_default();
            let mon = hal.ethernet_monitor(&name).ok();
            Some(PortData {
                name,
                hw,
                mon,
                tuning,
            })
        })
        .collect()
}

fn on(b: bool) -> i64 {
    i64::from(b)
}

/// Current value of `key` on the port; offloads and pause from the NIC.
fn current(d: &PortData, key: &str) -> Option<i64> {
    if let Some(f) = offload_feature(key) {
        return d.hw.offloads.iter().find(|o| o.feature == f).map(|o| on(o.active));
    }
    match key {
        "rx_pause" => d.mon.as_ref()?.rx_flow_control.map(on),
        "tx_pause" => d.mon.as_ref()?.tx_flow_control.map(on),
        _ => d.tuning.values.get(key).copied().flatten(),
    }
}

/// An offload the driver keeps as it is.
fn fixed(d: &PortData, key: &str) -> bool {
    offload_feature(key).is_some_and(|f| {
        d.hw.offloads
            .iter()
            .find(|o| o.feature == f)
            .is_none_or(|o| o.fixed)
    })
}

fn flow(f: Option<FlowControl>) -> Option<i64> {
    match f? {
        FlowControl::On => Some(1),
        FlowControl::Off => Some(0),
        FlowControl::Auto => None,
    }
}

/// What the config sets for `key` on `name`.
fn configured(s: &Session, name: &IfName, key: &str) -> Option<i64> {
    let cfg = s.store().candidate();
    let eth = cfg.interfaces.get(name).map(|i| &i.ethernet);
    if let Some(f) = offload_feature(key) {
        return eth?.offloads.get(f).map(|b| on(*b));
    }
    match key {
        "rx_pause" => flow(eth?.rx_flow_control),
        "tx_pause" => flow(eth?.tx_flow_control),
        _ => cfg.system.tuning.ports.get(name)?.get(key).copied(),
    }
}

fn view(d: &PortData) -> Port {
    Port {
        name: d.name.to_string(),
        now: d.tuning.values.clone(),
        max: d.tuning.max.clone(),
        numa_node: d.hw.numa_node,
        tx_queues: d
            .tuning
            .values
            .get("combined_channels")
            .copied()
            .flatten()
            .or_else(|| d.tuning.values.get("tx_channels").copied().flatten())
            .and_then(|v| u32::try_from(v).ok())
            .or(d.hw.tx_queues),
    }
}

fn profile_param(p: &Value, required: bool) -> Result<Profile> {
    match opt_str(p, "profile")? {
        None if required => Err(EngineError::bad("profile", "is required")),
        None => Ok(Profile::Balanced),
        Some(id) => Profile::parse(id).ok_or_else(|| {
            EngineError::bad(
                "profile",
                "must be conservative, balanced, throughput or latency",
            )
        }),
    }
}

fn row(s: &Session, d: &PortData, p: &Param, rec: Option<&Rec>) -> Value {
    let port = Port {
        max: d.tuning.max.clone(),
        ..Port::default()
    };
    let (min, max) = port_range(p, &port);
    json!({
        "name": p.name,
        "tab": tab_id(p.tab),
        "section": p.section,
        "current": current(d, p.name),
        "configured": configured(s, &d.name, p.name),
        "recommended": rec.map(|r| r.value),
        "why": rec.map(|r| r.why.clone()),
        "why_id": rec.map(|r| r.why_id),
        "why_args": rec.map(|r| r.why_args.clone()),
        "min": min,
        "max": max,
        "unit": p.unit,
        "choices": p.choices.iter().map(|(v, n)| json!({"value": v, "name": n})).collect::<Vec<_>>(),
        "default": p.default,
        "link_flap": p.link_flap,
        "ethernet": p.ethernet,
        "fixed": fixed(d, p.name),
    })
}

/// Rows of the port: the keys it has (and every offload and pause row
/// the NIC reports).
fn shown(d: &PortData, p: &Param) -> bool {
    current(d, p.name).is_some()
}

fn print(s: &mut Session, p: &Value) -> Result<Value> {
    let profile = profile_param(p, false)?;
    let only: Option<IfName> = match opt_str(p, "name")? {
        Some(_) => Some(req_parse(p, "name")?),
        None => None,
    };
    let m = machine(s).unwrap_or_default();
    let list = ports(s, only.as_ref());
    if let Some(o) = &only
        && list.is_empty()
    {
        return Err(EngineError::bad(
            "name",
            format!("no Ethernet port '{o}' with settings this backend can read"),
        ));
    }
    let out: Vec<Value> = list
        .iter()
        .map(|d| {
            let recs = recommend_port(profile, &m, &view(d));
            let params: Vec<Value> = PORT_PARAMS
                .iter()
                .filter(|p| shown(d, p))
                .map(|p| row(s, d, p, recs.get(p.name)))
                .collect();
            json!({
                "name": d.name.as_str(),
                "driver": d.hw.driver,
                "model": d.hw.model,
                "speed_mbps": m.nics.iter().find(|n| n.name == d.name.as_str()).and_then(|n| n.speed_mbps),
                "notes": d.tuning.notes,
                "params": params,
            })
        })
        .collect();
    Ok(json!({"profile": profile.id(), "ports": out}))
}

fn print_set(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(Value::Array(
        s.store()
            .candidate()
            .system
            .tuning
            .ports
            .iter()
            .flat_map(|(n, m)| {
                m.iter()
                    .map(move |(k, v)| json!({"name": n.as_str(), "key": k, "value": v}))
            })
            .collect(),
    ))
}

fn key(p: &Value) -> Result<&'static Param> {
    let k = req_str(p, "key")?;
    port_param(k).ok_or_else(|| {
        let keys: Vec<&str> = PORT_PARAMS.iter().map(|p| p.name).collect();
        EngineError::bad(
            "key",
            format!(
                "'{}' is not a port setting; one of {}",
                k.chars().take(32).collect::<String>(),
                keys.join(", ")
            ),
        )
    })
}

fn one_port(s: &mut Session, p: &Value) -> Result<PortData> {
    let name: IfName = req_parse(p, "name")?;
    refuse_unmanaged(s, p, &["name"])?;
    let iface = s.store().candidate().interfaces.get(&name).ok_or_else(|| {
        EngineError::bad("name", format!("no interface '{name}' (see interface.list)"))
    })?;
    if iface.kind != InterfaceKind::Ethernet {
        return Err(EngineError::bad(
            "name",
            format!(
                "'{name}' is a {}: port settings are for physical ports",
                iface.kind.label()
            ),
        ));
    }
    ports(s, Some(&name)).pop().ok_or_else(|| {
        EngineError::bad(
            "name",
            format!("this backend cannot read the settings of '{name}'"),
        )
    })
}

/// Write `value` of `prm` for port `name` into the candidate.
fn put(s: &mut Session, name: &IfName, prm: &Param, value: i64) {
    let cfg = s.store_mut().candidate_mut();
    if let Some(f) = offload_feature(prm.name) {
        if let Some(i) = cfg.interfaces.get_mut(name) {
            i.ethernet.offloads.insert(f.to_owned(), value != 0);
        }
    } else if prm.name.ends_with("_pause") {
        if let Some(i) = cfg.interfaces.get_mut(name) {
            let f = Some(if value != 0 {
                FlowControl::On
            } else {
                FlowControl::Off
            });
            if prm.name == "rx_pause" {
                i.ethernet.rx_flow_control = f;
            } else {
                i.ethernet.tx_flow_control = f;
            }
        }
    } else {
        cfg.system
            .tuning
            .ports
            .entry(name.clone())
            .or_default()
            .insert(prm.name.to_owned(), value);
    }
}

/// Why `value` cannot be set for `prm` on `d`, if it cannot.
fn refuse(d: &PortData, prm: &Param, value: i64) -> Result<()> {
    if current(d, prm.name).is_none() {
        return Err(EngineError::bad(
            "key",
            format!(
                "{}: the NIC (driver {}) of '{}' does not let CoreRouter read or change it",
                prm.name,
                d.hw.driver.as_deref().unwrap_or("unknown"),
                d.name
            ),
        ));
    }
    if fixed(d, prm.name) {
        return Err(EngineError::bad(
            "key",
            format!("{}: the driver of '{}' keeps it fixed", prm.name, d.name),
        ));
    }
    if prm.name == "lro" && value != 0 {
        return Err(EngineError::bad(
            "value",
            "LRO on a router corrupts forwarded packets (the kernel turns it off with forwarding); \
             use interface.ethernet.set with force=yes if this port only terminates traffic",
        ));
    }
    let port = Port {
        max: d.tuning.max.clone(),
        ..Port::default()
    };
    let (min, max) = port_range(prm, &port);
    if !(min..=max).contains(&value) {
        let why = if d.tuning.max.contains_key(prm.name) {
            " (the maximum of this NIC)"
        } else {
            ""
        };
        return Err(EngineError::bad(
            "value",
            format!("{} must be {min}..={max}{why}", prm.name),
        ));
    }
    Ok(())
}

fn flap_warning(prm: &Param, name: &IfName) -> Option<String> {
    prm.link_flap.then(|| {
        format!(
            "changing {} resets '{name}': its link drops for a moment (use Safe Mode on a port \
             you manage the router through)",
            prm.name
        )
    })
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let prm = key(p)?;
    let value = match p.get("value") {
        Some(v) => v
            .as_i64()
            .ok_or_else(|| EngineError::bad("value", "must be an integer"))?,
        None => return Err(EngineError::bad("value", "is required")),
    };
    let d = one_port(s, p)?;
    refuse(&d, prm, value)?;
    put(s, &d.name, prm, value);
    let warnings: Vec<String> = flap_warning(prm, &d.name).into_iter().collect();
    Ok(json!({"name": d.name.as_str(), "key": prm.name, "value": value, "warnings": warnings}))
}

fn unset(s: &mut Session, p: &Value) -> Result<Value> {
    let prm = key(p)?;
    let name: IfName = req_parse(p, "name")?;
    let cfg = s.store_mut().candidate_mut();
    let gone = if let Some(f) = offload_feature(prm.name) {
        cfg.interfaces
            .get_mut(&name)
            .and_then(|i| i.ethernet.offloads.remove(f))
            .is_some()
    } else if prm.name.ends_with("_pause") {
        cfg.interfaces.get_mut(&name).is_some_and(|i| {
            let f = if prm.name == "rx_pause" {
                &mut i.ethernet.rx_flow_control
            } else {
                &mut i.ethernet.tx_flow_control
            };
            f.take().is_some()
        })
    } else {
        let ports = &mut cfg.system.tuning.ports;
        let gone = ports
            .get_mut(&name)
            .and_then(|m| m.remove(prm.name))
            .is_some();
        if ports.get(&name).is_some_and(BTreeMap::is_empty) {
            ports.remove(&name);
        }
        gone
    };
    if !gone {
        return Err(EngineError::bad(
            "key",
            format!("{} is not set on '{name}': the port's own value is in use", prm.name),
        ));
    }
    Ok(json!({"name": name.as_str(), "key": prm.name}))
}

fn apply(s: &mut Session, p: &Value) -> Result<Value> {
    let profile = profile_param(p, true)?;
    let only: Option<Vec<IfName>> = match p.get("names") {
        None | Some(Value::Null) => None,
        Some(Value::Array(a)) if a.len() <= MAX_PORTS => Some(
            a.iter()
                .map(|v| {
                    v.as_str()
                        .and_then(|n| n.parse().ok())
                        .ok_or_else(|| EngineError::bad("names", "each item must be a port name"))
                })
                .collect::<Result<_>>()?,
        ),
        Some(_) => {
            return Err(EngineError::bad(
                "names",
                format!("must be a list of at most {MAX_PORTS} port names"),
            ));
        }
    };
    let m: Machine = machine(s).unwrap_or_default();
    let list = ports(s, None);
    let mut changed = Vec::new();
    let mut plan: Vec<(IfName, &'static Param, i64)> = Vec::new();
    for d in &list {
        if only.as_ref().is_some_and(|o| !o.contains(&d.name)) {
            continue;
        }
        for (k, r) in recommend_port(profile, &m, &view(d)) {
            let Some(prm) = port_param(k) else {
                continue;
            };
            let now = current(d, k);
            let have = configured(s, &d.name, k).or(now);
            if have == Some(r.value) || refuse(d, prm, r.value).is_err() {
                continue;
            }
            changed.push(json!({
                "name": d.name.as_str(),
                "key": k,
                "from": have,
                "to": r.value,
                "link_flap": prm.link_flap,
            }));
            plan.push((d.name.clone(), prm, r.value));
        }
    }
    for (name, prm, v) in plan {
        put(s, &name, prm, v);
    }
    Ok(json!({"profile": profile.id(), "changed": changed}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(s: &mut Session, id: &str, p: Value) -> Result<Value> {
        s.execute(id, &p)
    }

    fn rows(v: &Value, port: &str) -> Vec<Value> {
        v["ports"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == port)
            .unwrap()["params"]
            .as_array()
            .unwrap()
            .clone()
    }

    fn field(rows: &[Value], key: &str, f: &str) -> Value {
        rows.iter().find(|r| r["name"] == key).unwrap()[f].clone()
    }

    #[test]
    fn ports_show_their_settings_and_the_profile() {
        let mut s = Session::virtual_lab();
        let v = run(&mut s, "system.tuning.interface.parameter.print", json!({})).unwrap();
        assert_eq!(v["ports"].as_array().unwrap().len(), 8);
        let r = rows(&v, "ether1");
        assert_eq!(field(&r, "rx_ring", "current"), 1024);
        assert_eq!(field(&r, "rx_ring", "max"), 4096);
        assert_eq!(field(&r, "rx_ring", "recommended"), 2048);
        assert_eq!(field(&r, "rx_ring", "link_flap"), true);
        assert_eq!(field(&r, "combined_channels", "recommended"), 8, "node 0: 8 CPUs");
        assert_eq!(field(&r, "gro", "current"), 1);
        assert_eq!(field(&r, "lro", "fixed"), true);
        assert_eq!(field(&r, "qdisc", "recommended"), 3);
        assert!(r.iter().all(|x| x["name"] != "rx_channels"), "combined NIC");
        let one = run(
            &mut s,
            "system.tuning.interface.parameter.print",
            json!({"name": "ether2", "profile": "throughput"}),
        )
        .unwrap();
        assert_eq!(one["ports"].as_array().unwrap().len(), 1);
        assert_eq!(field(&rows(&one, "ether2"), "rx_ring", "recommended"), 4096);
    }

    #[test]
    fn set_validates_against_the_nic_and_unset_restores() {
        let mut s = Session::virtual_lab();
        let ok = run(
            &mut s,
            "system.tuning.interface.set",
            json!({"name": "ether1", "key": "rx_ring", "value": 4096}),
        )
        .unwrap();
        assert!(ok["warnings"][0].as_str().unwrap().contains("link drops"));
        let v = run(&mut s, "system.tuning.interface.parameter.print", json!({"name": "ether1"})).unwrap();
        assert_eq!(field(&rows(&v, "ether1"), "rx_ring", "current"), 4096);
        assert_eq!(
            run(&mut s, "system.tuning.interface.print", json!({})).unwrap(),
            json!([{"name": "ether1", "key": "rx_ring", "value": 4096}])
        );

        let mut err = |p: Value| run(&mut s, "system.tuning.interface.set", p).unwrap_err().to_string();
        assert!(err(json!({"name": "ether1", "key": "rx_ring", "value": 8192})).contains("maximum of this NIC"));
        assert!(err(json!({"name": "ether1", "key": "rx_channels", "value": 2})).contains("does not let"));
        assert!(err(json!({"name": "ether1", "key": "lro", "value": 1})).contains("fixed"));
        assert!(err(json!({"name": "ether1", "key": "warp", "value": 1})).contains("one of rx_ring"));
        assert!(err(json!({"name": "nope9", "key": "rx_ring", "value": 1024})).contains("no interface"));

        // Offloads and flow control go to the port's Ethernet settings.
        run(&mut s, "system.tuning.interface.set", json!({"name": "ether1", "key": "rx_pause", "value": 0})).unwrap();
        assert_eq!(
            s.store().candidate().interfaces[&"ether1".parse::<IfName>().unwrap()]
                .ethernet
                .rx_flow_control,
            Some(FlowControl::Off)
        );
        run(&mut s, "system.tuning.interface.unset", json!({"name": "ether1", "key": "rx_ring"})).unwrap();
        assert!(s.store().running().system.tuning.ports.is_empty());
        assert!(run(&mut s, "system.tuning.interface.unset", json!({"name": "ether1", "key": "rx_ring"})).is_err());
    }

    #[test]
    fn apply_sets_every_port_in_one_commit() {
        let mut s = Session::virtual_lab();
        let rev = s.store().current_revision();
        let out = run(
            &mut s,
            "system.tuning.interface.apply",
            json!({"profile": "throughput", "names": ["ether1", "ether2"]}),
        )
        .unwrap();
        let changed = out["changed"].as_array().unwrap();
        assert!(changed.iter().all(|c| c["name"] == "ether1" || c["name"] == "ether2"));
        assert!(changed.iter().any(|c| c["key"] == "rx_ring" && c["to"] == 4096 && c["link_flap"] == true));
        let ports = &s.store().running().system.tuning.ports;
        assert_eq!(ports.len(), 2);
        run(&mut s, "config.rollback", json!({"revision": rev})).unwrap();
        assert!(s.store().running().system.tuning.ports.is_empty());
        assert!(run(&mut s, "system.tuning.interface.apply", json!({})).is_err());
    }
}
