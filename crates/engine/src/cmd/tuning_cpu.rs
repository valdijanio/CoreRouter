//! /system tuning cpu (G1.26c): the CPU frequency governor, the C-state
//! limit (a PM QoS request the daemon holds while it runs) and the
//! hardware watchdog, with the value each profile wants. Each port's IRQ
//! affinity, RPS and XPS are port settings (`system.tuning.interface.*`,
//! section "CPU and IRQ").

use corerouter_model::tuning::{CPU_PARAMS, Param, cpu_param};
use serde_json::{Value, json};

use super::args::{opt_str, req_str};
use super::tuning::tab_id;
use super::{CommandSpec, always};
use crate::tuning::{Profile, Rec};
use crate::tuning_port::recommend_cpu;
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "system.tuning.cpu.print", "CPU Tuning", [], None,
        "{} → [{key, value}]",
        always, print_set),
    cmd!(query "system.tuning.cpu.parameter.print", "CPU Tuning", [], None,
        "{profile?: conservative|balanced|throughput|latency} → {profile, irqbalance: bool, notes, params: [{name, tab, section, current, configured, recommended, why, why_id, why_args, min, max, unit, choices, default}]}",
        always, print),
    cmd!(
        "system.tuning.cpu.set",
        "Set CPU Tuning",
        [],
        None,
        "{key: string, value: int} → {key, value}",
        always,
        set
    ),
    cmd!(
        "system.tuning.cpu.unset",
        "Unset CPU Tuning",
        [],
        None,
        "{key: string} → {key}",
        always,
        unset
    ),
];

fn profile_param(p: &Value) -> Result<Profile> {
    match opt_str(p, "profile")? {
        None => Ok(Profile::Balanced),
        Some(id) => Profile::parse(id).ok_or_else(|| {
            EngineError::bad(
                "profile",
                "must be conservative, balanced, throughput or latency",
            )
        }),
    }
}

fn row(p: &Param, current: Option<i64>, configured: Option<i64>, rec: Option<&Rec>) -> Value {
    json!({
        "name": p.name,
        "tab": tab_id(p.tab),
        "section": p.section,
        "current": current,
        "configured": configured,
        "recommended": rec.map(|r| r.value),
        "why": rec.map(|r| r.why.clone()),
        "why_id": rec.map(|r| r.why_id),
        "why_args": rec.map(|r| r.why_args.clone()),
        "min": p.min,
        "max": p.max,
        "unit": p.unit,
        "choices": p.choices.iter().map(|(v, n)| json!({"value": v, "name": n})).collect::<Vec<_>>(),
        "default": p.default,
    })
}

fn print(s: &mut Session, p: &Value) -> Result<Value> {
    let profile = profile_param(p)?;
    let cpu = s.hal_mut().cpu_tuning().map_err(|e| EngineError::bad("profile", e.to_string()))?;
    let recs = recommend_cpu(profile, &cpu.values);
    let cfg = s.store().candidate().system.tuning.cpu.clone();
    let params: Vec<Value> = CPU_PARAMS
        .iter()
        .map(|p| {
            row(
                p,
                cpu.values.get(p.name).copied().flatten(),
                cfg.get(p.name).copied(),
                recs.get(p.name),
            )
        })
        .collect();
    Ok(json!({
        "profile": profile.id(),
        "irqbalance": cpu.irqbalance,
        "notes": cpu.notes,
        "params": params,
    }))
}

fn print_set(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(Value::Array(
        s.store()
            .candidate()
            .system
            .tuning
            .cpu
            .iter()
            .map(|(k, v)| json!({"key": k, "value": v}))
            .collect(),
    ))
}

fn key(p: &Value) -> Result<&'static Param> {
    let k = req_str(p, "key")?;
    cpu_param(k).ok_or_else(|| {
        let keys: Vec<&str> = CPU_PARAMS.iter().map(|p| p.name).collect();
        EngineError::bad(
            "key",
            format!(
                "'{}' is not a CPU setting; one of {}",
                k.chars().take(32).collect::<String>(),
                keys.join(", ")
            ),
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
    if !(prm.min..=prm.max).contains(&value) {
        return Err(EngineError::bad(
            "value",
            format!("{} must be {}..={}", prm.name, prm.min, prm.max),
        ));
    }
    let cpu = s.hal_mut().cpu_tuning().map_err(|e| EngineError::bad("key", e.to_string()))?;
    // cpu_dma_latency is `None` while no limit is held: always settable.
    if prm.name != "cpu_dma_latency" && cpu.values.get(prm.name).copied().flatten().is_none() {
        let why = match prm.name {
            "governor" => "this machine has no cpufreq (a VM, or the firmware keeps the clock)",
            "hw_watchdog" => "this machine has no /dev/watchdog",
            _ => "this machine does not have it",
        };
        return Err(EngineError::bad("key", format!("{}: {why}", prm.name)));
    }
    s.store_mut()
        .candidate_mut()
        .system
        .tuning
        .cpu
        .insert(prm.name.to_owned(), value);
    Ok(json!({"key": prm.name, "value": value}))
}

fn unset(s: &mut Session, p: &Value) -> Result<Value> {
    let prm = key(p)?;
    s.store_mut()
        .candidate_mut()
        .system
        .tuning
        .cpu
        .remove(prm.name)
        .ok_or_else(|| {
            EngineError::bad(
                "key",
                format!("{} is not set: the machine's own value is in use", prm.name),
            )
        })?;
    Ok(json!({"key": prm.name}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(s: &mut Session, id: &str, p: Value) -> Result<Value> {
        s.execute(id, &p)
    }

    fn field(v: &Value, key: &str, f: &str) -> Value {
        v["params"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == key)
            .unwrap()[f]
            .clone()
    }

    #[test]
    fn cpu_settings_show_set_and_unset() {
        let mut s = Session::virtual_lab();
        let v = run(&mut s, "system.tuning.cpu.parameter.print", json!({"profile": "latency"})).unwrap();
        assert_eq!(v["irqbalance"], true);
        assert_eq!(field(&v, "governor", "current"), 1);
        assert_eq!(field(&v, "governor", "recommended"), 0);
        assert_eq!(field(&v, "cpu_dma_latency", "recommended"), 1);
        assert_eq!(field(&v, "hw_watchdog", "recommended"), 1);

        run(&mut s, "system.tuning.cpu.set", json!({"key": "governor", "value": 0})).unwrap();
        run(&mut s, "system.tuning.cpu.set", json!({"key": "cpu_dma_latency", "value": 1})).unwrap();
        let v = run(&mut s, "system.tuning.cpu.parameter.print", json!({})).unwrap();
        assert_eq!(field(&v, "governor", "current"), 0);
        assert_eq!(field(&v, "cpu_dma_latency", "current"), 1);
        assert_eq!(
            run(&mut s, "system.tuning.cpu.print", json!({})).unwrap(),
            json!([{"key": "cpu_dma_latency", "value": 1}, {"key": "governor", "value": 0}])
        );
        let err = run(&mut s, "system.tuning.cpu.set", json!({"key": "governor", "value": 9})).unwrap_err();
        assert!(err.to_string().contains("0..=4"), "{err}");
        let err = run(&mut s, "system.tuning.cpu.set", json!({"key": "turbo", "value": 1})).unwrap_err();
        assert!(err.to_string().contains("one of governor"), "{err}");
        run(&mut s, "system.tuning.cpu.unset", json!({"key": "governor"})).unwrap();
        assert!(run(&mut s, "system.tuning.cpu.unset", json!({"key": "governor"})).is_err());
        let v = run(&mut s, "system.tuning.cpu.parameter.print", json!({})).unwrap();
        assert_eq!(field(&v, "governor", "current"), 1, "back to schedutil");
    }

    #[test]
    fn port_irq_rps_xps_go_through_the_port_commands() {
        let mut s = Session::virtual_lab();
        let v = run(
            &mut s,
            "system.tuning.interface.parameter.print",
            json!({"name": "ether1"}),
        )
        .unwrap();
        let port = &v["ports"][0];
        assert_eq!(port["irqs"].as_array().unwrap().len(), 4);
        assert_eq!(port["irqs"][0]["cpus"], "0-15");
        run(
            &mut s,
            "system.tuning.interface.set",
            json!({"name": "ether1", "key": "irq_affinity", "value": 1}),
        )
        .unwrap();
        let v = run(
            &mut s,
            "system.tuning.interface.parameter.print",
            json!({"name": "ether1"}),
        )
        .unwrap();
        assert_eq!(v["ports"][0]["irqs"][1]["cpus"], "1", "one CPU of node 0 per IRQ");
    }
}
