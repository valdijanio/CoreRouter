//! /system tuning boot (G1.26d): kernel command-line parameters of the
//! image, valid from the next boot. The image is immutable and A/B
//! (`docs/architecture.md`): there is no GRUB to edit. Until the A/B image
//! exists (G1.6), the parameters are kept in the config, shown as pending
//! and handed to the image's command line when it does (G1.26h); a failed
//! boot then falls back to the previous image.

use std::collections::BTreeMap;

use corerouter_model::tuning::{BOOT_PARAMS, BootKind, BootParam, boot_param, boot_value, cmdline, parse_cmdline};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, req_str};
use super::{CommandSpec, always};
use crate::tuning::{Profile, Rec, why};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "system.tuning.boot.print", "Boot Tuning", [], None,
        "{} → [{key, value}]",
        always, print_set),
    cmd!(query "system.tuning.boot.parameter.print", "Boot Tuning", [], None,
        "{profile?: conservative|balanced|throughput|latency} → {profile, running_cmdline, next_cmdline, image_ab: bool, params: [{name, section, running, configured, recommended, why, why_id, why_args, kind, choices, min, max, danger}]}",
        always, print),
    cmd!(
        "system.tuning.boot.set",
        "Set Boot Parameter",
        [],
        None,
        "{key: string, value: string, confirm?: bool (needed for mitigations=off)} → {key, value, next_cmdline}",
        always,
        set
    ),
    cmd!(
        "system.tuning.boot.unset",
        "Unset Boot Parameter",
        [],
        None,
        "{key: string} → {key, next_cmdline}",
        always,
        unset
    ),
];

/// Whether the A/B image that boots these parameters exists (G1.6).
const IMAGE_AB: bool = false;

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

/// What `profile` puts on the command line. CPU isolation and
/// `mitigations` are never recommended: they depend on what runs here, and
/// the second weakens security.
fn recommend(profile: Profile) -> BTreeMap<&'static str, (String, Rec)> {
    let mut out = BTreeMap::new();
    let mut put = |k: &'static str, v: &str, id: &'static str| {
        out.insert(k, (v.to_owned(), why(id, 0, &[])));
    };
    if matches!(profile, Profile::Throughput | Profile::Latency) {
        put("iommu", "pt", "boot_iommu_pt");
    }
    if profile == Profile::Latency {
        put("intel_idle.max_cstate", "1", "boot_cstate");
        put("processor.max_cstate", "1", "boot_cstate");
        put("pcie_aspm", "off", "boot_aspm");
    }
    out
}

fn kind_json(p: &BootParam) -> (Value, Value, Value, Value) {
    match p.kind {
        BootKind::Cpus => (json!("cpus"), json!([]), Value::Null, Value::Null),
        BootKind::Int(a, b) => (json!("int"), json!([]), json!(a), json!(b)),
        BootKind::Choice(c) => (json!("choice"), json!(c), Value::Null, Value::Null),
    }
}

fn print(s: &mut Session, p: &Value) -> Result<Value> {
    let profile = profile_param(p)?;
    let running_text = s.hal_mut().boot_cmdline().unwrap_or_default();
    let running = parse_cmdline(&running_text);
    let cfg = s.store().candidate().system.tuning.boot.clone();
    let recs = recommend(profile);
    let params: Vec<Value> = BOOT_PARAMS
        .iter()
        .map(|b| {
            let r = recs.get(b.name);
            let (kind, choices, min, max) = kind_json(b);
            json!({
                "name": b.name,
                "section": b.section,
                "running": running.get(b.name),
                "configured": cfg.get(b.name),
                "recommended": r.map(|(v, _)| v),
                "why": r.map(|(_, r)| r.why.clone()),
                "why_id": r.map(|(_, r)| r.why_id),
                "why_args": r.map(|(_, r)| r.why_args.clone()),
                "kind": kind,
                "choices": choices,
                "min": min,
                "max": max,
                "danger": b.danger,
            })
        })
        .collect();
    Ok(json!({
        "profile": profile.id(),
        "running_cmdline": running_text,
        "next_cmdline": cmdline(&cfg),
        "image_ab": IMAGE_AB,
        "params": params,
    }))
}

fn print_set(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(Value::Array(
        s.store()
            .candidate()
            .system
            .tuning
            .boot
            .iter()
            .map(|(k, v)| json!({"key": k, "value": v}))
            .collect(),
    ))
}

fn key(p: &Value) -> Result<&'static BootParam> {
    let k = req_str(p, "key")?;
    boot_param(k).ok_or_else(|| {
        let keys: Vec<&str> = BOOT_PARAMS.iter().map(|p| p.name).collect();
        EngineError::bad(
            "key",
            format!(
                "'{}' is not a boot parameter CoreRouter sets; one of {}",
                k.chars().take(32).collect::<String>(),
                keys.join(", ")
            ),
        )
    })
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let prm = key(p)?;
    let raw = req_str(p, "value")?;
    let cpus = s.hal_mut().system_info().ok().map(|i| i.cpus).filter(|n| *n > 0);
    let value = boot_value(prm, raw, cpus).map_err(|e| EngineError::bad("value", e))?;
    if prm.danger && value == "off" && opt_bool(p, "confirm")? != Some(true) {
        return Err(EngineError::bad(
            "confirm",
            "mitigations=off turns off the CPU's defenses against Spectre/Meltdown-class attacks: \
             anything that runs here (the API, a BGP peer's input, a container) may read the \
             memory of other processes. A router that runs nothing of others gains a few percent. \
             Repeat with confirm=yes to keep it",
        ));
    }
    let boot = &mut s.store_mut().candidate_mut().system.tuning.boot;
    boot.insert(prm.name.to_owned(), value.clone());
    let next = cmdline(boot);
    Ok(json!({"key": prm.name, "value": value, "next_cmdline": next}))
}

fn unset(s: &mut Session, p: &Value) -> Result<Value> {
    let prm = key(p)?;
    let boot = &mut s.store_mut().candidate_mut().system.tuning.boot;
    boot.remove(prm.name).ok_or_else(|| {
        EngineError::bad(
            "key",
            format!("{} is not set for the next boot", prm.name),
        )
    })?;
    let next = cmdline(boot);
    Ok(json!({"key": prm.name, "next_cmdline": next}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(s: &mut Session, id: &str, p: Value) -> Result<Value> {
        s.execute(id, &p)
    }

    #[test]
    fn boot_parameters_wait_for_the_next_boot() {
        let mut s = Session::virtual_lab();
        let v = run(&mut s, "system.tuning.boot.parameter.print", json!({"profile": "latency"})).unwrap();
        assert_eq!(v["image_ab"], false);
        assert!(v["running_cmdline"].as_str().unwrap().contains("corerouter-a"));
        let row = |v: &Value, k: &str| {
            v["params"].as_array().unwrap().iter().find(|r| r["name"] == k).unwrap().clone()
        };
        assert_eq!(row(&v, "intel_idle.max_cstate")["recommended"], "1");
        assert_eq!(row(&v, "mitigations")["recommended"], Value::Null, "never recommended");
        assert_eq!(row(&v, "mitigations")["danger"], true);

        let out = run(&mut s, "system.tuning.boot.set", json!({"key": "isolcpus", "value": "2-7"})).unwrap();
        assert_eq!(out["next_cmdline"], "isolcpus=2-7");
        let err = run(&mut s, "system.tuning.boot.set", json!({"key": "mitigations", "value": "off"})).unwrap_err();
        assert!(err.to_string().contains("confirm=yes"), "{err}");
        run(
            &mut s,
            "system.tuning.boot.set",
            json!({"key": "mitigations", "value": "off", "confirm": true}),
        )
        .unwrap();
        let v = run(&mut s, "system.tuning.boot.parameter.print", json!({})).unwrap();
        assert_eq!(v["next_cmdline"], "isolcpus=2-7 mitigations=off");
        assert_eq!(row(&v, "isolcpus")["running"], Value::Null, "pending until a reboot");
        assert_eq!(
            run(&mut s, "system.tuning.boot.print", json!({})).unwrap(),
            json!([{"key": "isolcpus", "value": "2-7"}, {"key": "mitigations", "value": "off"}])
        );

        let mut err = |p: Value| run(&mut s, "system.tuning.boot.set", p).unwrap_err().to_string();
        assert!(err(json!({"key": "isolcpus", "value": "0-3"})).contains("CPU 0"));
        assert!(err(json!({"key": "isolcpus", "value": "2-99"})).contains("does not exist"));
        assert!(err(json!({"key": "isolcpus", "value": "2 quiet init=/bin/sh"})).contains("CPU list"));
        assert!(err(json!({"key": "init", "value": "/bin/sh"})).contains("not a boot parameter"));
        assert!(err(json!({"key": "processor.max_cstate", "value": "12"})).contains("0..=9"));

        // One transaction like the rest: a rollback takes it back.
        let rev = s.store().current_revision();
        run(&mut s, "system.tuning.boot.unset", json!({"key": "mitigations"})).unwrap();
        run(&mut s, "config.rollback", json!({"revision": rev})).unwrap();
        assert_eq!(s.store().running().system.tuning.boot.len(), 2);
    }
}
