//! /system tuning (G1.26): kernel parameters for a box that forwards
//! packets, the machine they are calculated from, profiles and the
//! diagnosis from the counters. The values live in
//! `Config::system.tuning`, so a change is a transaction like any other
//! (diff, Safe Mode, rollback); the HAL writes them (`/proc/sys` on Linux).

use std::collections::BTreeMap;

use corerouter_hal::HalError;
use corerouter_hal::nic::mode_speed;
use corerouter_hal::tuning::{KernelStats, Sysctls};
use corerouter_model::tuning::{PARAMS, Param, Tab, param};
use corerouter_model::{IfName, InterfaceKind};
use serde_json::{Value, json};

use super::args::{opt_str, req_str};
use super::{CommandSpec, always};
use crate::tuning::{Machine, Nic, Profile, Rec, diagnose, range, recommend};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "system.tuning.print", "Tuning", [], None,
        "{} → [{name, value}]",
        always, print_set),
    cmd!(query "system.tuning.parameter.print", "Tuning", ["System", "Tuning"], None,
        "{profile?: conservative|balanced|throughput|latency, tab?: kernel|interfaces|cpu|boot} → {profile, machine: bool, params: [{name, tab, section, current, configured, recommended, why, why_id, why_args, min, max, unit, choices, default (the kernel's), router_default (CoreRouter's, kept while not configured), init_ns_only, obsolete, control_plane}]}",
        always, print),
    cmd!(
        "system.tuning.set",
        "Set Tuning Parameter",
        [],
        None,
        "{name: string, value: int} → {name, value}",
        always,
        set
    ),
    cmd!(
        "system.tuning.unset",
        "Unset Tuning Parameter",
        [],
        None,
        "{name: string} → {name, was}",
        always,
        unset
    ),
    cmd!(
        "system.tuning.profile.apply",
        "Apply Tuning Profile",
        [],
        None,
        "{profile: conservative|balanced|throughput|latency, names?: [string]} → {profile, changed: [{name, from, to}]}",
        always,
        apply_profile
    ),
    cmd!(query "system.tuning.profile.diff", "Tuning Profile Differences", [], None,
        "{profile?: conservative|balanced|throughput|latency} → [{name, current, configured, recommended, why}]",
        always, profile_diff),
    cmd!(query "system.tuning.hardware", "Tuning Hardware", [], None,
        "{} → {cpus, cpu_model, numa: [{id, cpus, mem_kib}], mem_kib, kernel, nics: [{name, driver, model, speed_mbps, numa_node, queues, queues_max, ring_rx, ring_rx_max, ring_tx, ring_tx_max, rx_missed}]}",
        always, hardware),
    cmd!(query "system.tuning.diagnose", "Tuning Diagnosis", [], None,
        "{} → {findings: [{severity: info|warning|critical, id, text, args, param, suggest}]}",
        always, diagnosis),
];

/// Seconds the machine (CPUs, ports, rings) is reused between commands:
/// the window asks every second and a port's genetlink calls are not free.
const MACHINE_TTL_SECS: u64 = 10;

/// The machine as last read (`Session::ext`).
#[derive(Default)]
struct MachineCache {
    at: Option<u64>,
    machine: Option<Machine>,
}

fn hal_err(e: HalError) -> EngineError {
    match e {
        HalError::Unsupported(why) | HalError::Rejected(why) | HalError::Io(why) => {
            EngineError::bad("name", why)
        }
    }
}

fn read_machine(s: &mut Session) -> Option<Machine> {
    let sys = s.hal_mut().system_info().ok()?;
    let ports: Vec<IfName> = s
        .store()
        .candidate()
        .interfaces
        .iter()
        .filter(|(_, i)| i.kind == InterfaceKind::Ethernet)
        .map(|(n, _)| n.clone())
        .collect();
    let nics = ports
        .into_iter()
        .map(|name| {
            let hal = s.hal_mut();
            let hw = hal.hardware(&name).unwrap_or_default();
            let mon = hal.ethernet_monitor(&name).ok();
            let speed = mon.as_ref().and_then(|m| {
                m.supported
                    .iter()
                    .filter_map(|mode| mode_speed(mode).map(|(s, _)| s))
                    .max()
                    .or(m.speed_mbps)
            });
            let pause = mon.as_ref().and_then(|m| {
                Some(m.rx_flow_control? || m.tx_flow_control.unwrap_or(false))
            });
            let lro = hw
                .offloads
                .iter()
                .find(|o| o.feature == "rx-lro")
                .map(|o| o.active);
            let rx_missed = hal.counters(&name).ok().and_then(|c| {
                c.groups
                    .iter()
                    .filter(|g| g.name == "interface")
                    .flat_map(|g| &g.counters)
                    .find(|c| c.name == "rx_missed_errors")
                    .map(|c| c.value)
            });
            Nic {
                name: name.to_string(),
                driver: hw.driver,
                model: hw.model,
                speed_mbps: speed,
                numa_node: hw.numa_node,
                queues: hw.combined_channels.or(hw.rx_queues),
                queues_max: hw.combined_channels_max,
                ring_rx: hw.ring_rx,
                ring_rx_max: hw.ring_rx_max,
                ring_tx: hw.ring_tx,
                ring_tx_max: hw.ring_tx_max,
                rx_missed,
                lro,
                pause,
            }
        })
        .collect();
    let irqbalance = s.hal_mut().cpu_tuning().is_ok_and(|c| c.irqbalance);
    Some(Machine {
        sys,
        nics,
        irqbalance,
    })
}

/// The machine, read again after [`MACHINE_TTL_SECS`]; `None`: the
/// backend cannot describe it (ranges then come from the catalog only).
pub(super) fn machine(s: &mut Session) -> Option<Machine> {
    let now = s.hal_now();
    if let Some(c) = s.ext::<MachineCache>()
        && let (Some(at), Some(now), Some(m)) = (c.at, now, &c.machine)
        && now.saturating_sub(at) < MACHINE_TTL_SECS
    {
        return Some(m.clone());
    }
    let m = read_machine(s);
    if let Some(c) = s.ext_mut::<MachineCache>() {
        c.at = now;
        c.machine = m.clone();
    }
    m
}

fn names() -> Vec<&'static str> {
    PARAMS.iter().map(|p| p.name).collect()
}

fn current(s: &mut Session) -> Sysctls {
    s.hal_mut().sysctls(&names()).unwrap_or_default()
}

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

pub(super) fn tab_id(t: Tab) -> &'static str {
    match t {
        Tab::Kernel => "kernel",
        Tab::Interfaces => "interfaces",
        Tab::Cpu => "cpu",
        Tab::Boot => "boot",
    }
}

/// The recommendation for `p`, or, for the conservative profile, "keep"
/// with the current value.
fn recommended(
    p: &Param,
    profile: Profile,
    recs: &BTreeMap<&'static str, Rec>,
    now: Option<i64>,
) -> Option<Rec> {
    if let Some(r) = recs.get(p.name) {
        return Some(r.clone());
    }
    let now = now?;
    (profile == Profile::Conservative && !p.obsolete).then(|| {
        let mut args = BTreeMap::new();
        args.insert("profile", profile.id().to_owned());
        Rec {
            value: now,
            why: crate::tuning::fill(
                crate::tuning::WHY
                    .iter()
                    .find(|(k, _)| *k == "keep")
                    .map_or("", |(_, t)| *t),
                &args,
            ),
            why_id: "keep",
            why_args: args,
        }
    })
}

fn print(s: &mut Session, p: &Value) -> Result<Value> {
    let profile = profile_param(p)?;
    let tab = opt_str(p, "tab")?;
    if let Some(t) = tab
        && !["kernel", "interfaces", "cpu", "boot"].contains(&t)
    {
        return Err(EngineError::bad(
            "tab",
            "must be kernel, interfaces, cpu or boot",
        ));
    }
    let m = machine(s);
    let cur = current(s);
    let recs = recommend(profile, &m.clone().unwrap_or_default());
    let configured = s.store().candidate().system.tuning.sysctl.clone();
    let params: Vec<Value> = PARAMS
        .iter()
        .filter(|p| tab.is_none_or(|t| tab_id(p.tab) == t))
        .map(|p| {
            let now = cur.get(p.name).copied().flatten();
            let (min, max) = range(p, m.as_ref());
            let r = recommended(p, profile, &recs, now);
            json!({
                "name": p.name,
                "tab": tab_id(p.tab),
                "section": p.section,
                "current": now,
                "configured": configured.get(p.name),
                "recommended": r.as_ref().map(|r| r.value),
                "why": r.as_ref().map(|r| r.why.clone()),
                "why_id": r.as_ref().map(|r| r.why_id),
                "why_args": r.as_ref().map(|r| r.why_args.clone()),
                "min": min,
                "max": max,
                "unit": p.unit,
                "choices": p.choices.iter().map(|(v, n)| json!({"value": v, "name": n})).collect::<Vec<_>>(),
                "default": p.default,
                "router_default": corerouter_model::tuning::default_of(p.name),
                "init_ns_only": p.init_ns_only,
                "obsolete": p.obsolete,
                "control_plane": p.control_plane,
            })
        })
        .collect();
    Ok(json!({"profile": profile.id(), "machine": m.is_some(), "params": params}))
}

/// What the config sets (`/export` writes it back as `set` lines).
fn print_set(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(Value::Array(
        s.store()
            .candidate()
            .system
            .tuning
            .sysctl
            .iter()
            .map(|(name, value)| json!({"name": name, "value": value}))
            .collect(),
    ))
}

fn known(p: &Value) -> Result<&'static Param> {
    let name = req_str(p, "name")?;
    param(name).ok_or_else(|| {
        let near = PARAMS
            .iter()
            .map(|p| p.name)
            .find(|n| n.ends_with(name.rsplit('.').next().unwrap_or(name)));
        let hint = near.map_or_else(String::new, |n| format!(" (did you mean {n}?)"));
        EngineError::bad(
            "name",
            format!(
                "'{}' is not a tunable parameter{hint}; see system.tuning.parameter.print",
                name.chars().take(64).collect::<String>()
            ),
        )
    })
}

/// Check `value` for `p` against its range and against the other
/// parameters it must agree with (`gc_thresh1 ≤ 2 ≤ 3`), as `cfg` will be.
fn check(
    p: &Param,
    value: i64,
    m: Option<&Machine>,
    cfg: &BTreeMap<String, i64>,
    cur: &Sysctls,
) -> Result<()> {
    let (min, max) = range(p, m);
    if !(min..=max).contains(&value) {
        let why = if max < p.max {
            " (the upper limit follows this machine's RAM)"
        } else {
            ""
        };
        return Err(EngineError::bad(
            "value",
            format!("{} must be {min}..={max}{why}", p.name),
        ));
    }
    if let Some(stem) = p.name.strip_suffix(|c: char| ['1', '2', '3'].contains(&c))
        && let Some(stem) = stem.strip_suffix("gc_thresh")
    {
        let get = |i: u8| {
            let n = format!("{stem}gc_thresh{i}");
            if n == p.name {
                Some(value)
            } else {
                cfg.get(&n).copied().or_else(|| cur.get(&n).copied().flatten())
            }
        };
        if let (Some(a), Some(b), Some(c)) = (get(1), get(2), get(3))
            && !(a <= b && b <= c)
        {
            return Err(EngineError::bad(
                "value",
                format!(
                    "{stem}gc_thresh1 ≤ gc_thresh2 ≤ gc_thresh3 must hold (would be {a}, {b}, {c}): \
                     the garbage collector starts at 1, hurries at 2 and refuses new neighbors at 3"
                ),
            ));
        }
    }
    Ok(())
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let prm = known(p)?;
    let value = match p.get("value") {
        Some(v) => v
            .as_i64()
            .ok_or_else(|| EngineError::bad("value", "must be an integer"))?,
        None => return Err(EngineError::bad("value", "is required")),
    };
    if prm.obsolete {
        return Err(EngineError::bad(
            "name",
            format!(
                "{} is obsolete: this kernel ignores it (kept only for compatibility)",
                prm.name
            ),
        ));
    }
    let m = machine(s);
    let cur = current(s);
    if cur.get(prm.name).copied().flatten().is_none() {
        let why = if corerouter_model::tuning::is_conntrack(prm.name) {
            "connection tracking is not loaded (no NAT or stateful firewall rule yet)"
        } else if prm.init_ns_only {
            "only the host's first network namespace has it (a container does not)"
        } else {
            "this kernel does not have it"
        };
        return Err(EngineError::bad("name", format!("{}: {why}", prm.name)));
    }
    let cfg = s.store().candidate().system.tuning.sysctl.clone();
    check(prm, value, m.as_ref(), &cfg, &cur)?;
    s.store_mut()
        .candidate_mut()
        .system
        .tuning
        .sysctl
        .insert(prm.name.to_owned(), value);
    Ok(json!({"name": prm.name, "value": value}))
}

fn unset(s: &mut Session, p: &Value) -> Result<Value> {
    let prm = known(p)?;
    let was = s
        .store_mut()
        .candidate_mut()
        .system
        .tuning
        .sysctl
        .remove(prm.name)
        .ok_or_else(|| {
            let in_use = match corerouter_model::tuning::default_of(prm.name) {
                Some(d) => format!("CoreRouter's default ({d}) is in use"),
                None => "the kernel's own value is in use".to_owned(),
            };
            EngineError::bad("name", format!("{} is not set: {in_use}", prm.name))
        })?;
    Ok(json!({"name": prm.name, "was": was}))
}

/// A parameter a profile would change: the catalog entry, the kernel's
/// value, the configured one and the recommendation.
type Change = (&'static Param, Option<i64>, Option<i64>, Rec);

/// Parameters of `profile` whose recommendation differs from what the
/// config sets (or, when unset, from the kernel's value).
fn differences(s: &mut Session, profile: Profile) -> (Vec<Change>, Option<Machine>, Sysctls) {
    let m = machine(s);
    let cur = current(s);
    let recs = recommend(profile, &m.clone().unwrap_or_default());
    let cfg = s.store().candidate().system.tuning.sysctl.clone();
    let out = PARAMS
        .iter()
        .filter_map(|p| {
            let r = recs.get(p.name)?;
            let now = cur.get(p.name).copied().flatten();
            let set = cfg.get(p.name).copied();
            // The kernel lacks it here: nothing to apply.
            now?;
            (set.or(now) != Some(r.value)).then(|| (p, now, set, r.clone()))
        })
        .collect();
    (out, m, cur)
}

fn profile_diff(s: &mut Session, p: &Value) -> Result<Value> {
    let profile = profile_param(p)?;
    let (diff, ..) = differences(s, profile);
    Ok(Value::Array(
        diff.into_iter()
            .map(|(p, now, set, r)| {
                json!({
                    "name": p.name,
                    "current": now,
                    "configured": set,
                    "recommended": r.value,
                    "why": r.why,
                })
            })
            .collect(),
    ))
}

fn apply_profile(s: &mut Session, p: &Value) -> Result<Value> {
    let profile = match opt_str(p, "profile")? {
        Some(_) => profile_param(p)?,
        None => return Err(EngineError::bad("profile", "is required")),
    };
    let only: Option<Vec<String>> = match p.get("names") {
        None | Some(Value::Null) => None,
        Some(Value::Array(a)) if a.len() <= PARAMS.len() => Some(
            a.iter()
                .map(|v| {
                    let n = v
                        .as_str()
                        .ok_or_else(|| EngineError::bad("names", "each item must be a string"))?;
                    param(n).map(|p| p.name.to_owned()).ok_or_else(|| {
                        EngineError::bad(
                            "names",
                            format!(
                                "'{}' is not a tunable parameter",
                                n.chars().take(64).collect::<String>()
                            ),
                        )
                    })
                })
                .collect::<Result<_>>()?,
        ),
        Some(_) => {
            return Err(EngineError::bad(
                "names",
                format!("must be a list of at most {} parameter names", PARAMS.len()),
            ));
        }
    };
    let (diff, m, cur) = differences(s, profile);
    let mut cfg = s.store().candidate().system.tuning.sysctl.clone();
    let mut changed = Vec::new();
    for (prm, now, set, r) in diff {
        if only.as_ref().is_some_and(|o| !o.iter().any(|n| n == prm.name)) {
            continue;
        }
        cfg.insert(prm.name.to_owned(), r.value);
        changed.push(json!({"name": prm.name, "from": set.or(now), "to": r.value}));
    }
    // Checked as a whole: the gc_thresh order holds across the batch.
    for (name, value) in &cfg {
        if let Some(prm) = param(name) {
            check(prm, *value, m.as_ref(), &cfg, &cur)?;
        }
    }
    s.store_mut().candidate_mut().system.tuning.sysctl = cfg;
    Ok(json!({"profile": profile.id(), "changed": changed}))
}

fn hardware(s: &mut Session, _: &Value) -> Result<Value> {
    let m = machine(s).ok_or_else(|| {
        let why = s
            .hal_mut()
            .system_info()
            .err()
            .map_or_else(|| "unknown".to_owned(), |e| e.to_string());
        hal_err(HalError::Unsupported(why))
    })?;
    serde_json::to_value(m).map_err(|e| EngineError::bad("name", e.to_string()))
}

fn diagnosis(s: &mut Session, _: &Value) -> Result<Value> {
    let m = machine(s).unwrap_or_default();
    let stats = s.hal_mut().kernel_stats().unwrap_or_else(|_| KernelStats::default());
    let cur = current(s);
    Ok(json!({"findings": diagnose(&m, &stats, &cur)}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lab() -> Session {
        Session::virtual_lab()
    }

    fn run(s: &mut Session, id: &str, p: Value) -> Result<Value> {
        s.execute(id, &p)
    }

    fn row<'a>(v: &'a Value, name: &str) -> &'a Value {
        v["params"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == name)
            .unwrap()
    }

    #[test]
    fn print_shows_current_configured_and_recommended() {
        let mut s = lab();
        let v = run(&mut s, "system.tuning.parameter.print", json!({})).unwrap();
        assert_eq!(v["profile"], "balanced");
        assert_eq!(v["machine"], true);
        let b = row(&v, "net.core.netdev_budget");
        assert_eq!(b["current"], 300);
        assert_eq!(b["configured"], Value::Null);
        assert_eq!(b["recommended"], 600);
        assert_eq!(b["section"], "Packet receive");
        let ct = row(&v, "net.netfilter.nf_conntrack_max");
        // 32 GiB lab: a quarter of the RAM at 320 B per entry.
        assert_eq!(ct["max"], (32i64 << 30) / 4 / 320);
        assert!(ct["why"].as_str().unwrap().contains("1/16"));
        let v4 = row(&v, "net.ipv4.route.max_size");
        assert_eq!(v4["obsolete"], true);
        assert_eq!(v4["recommended"], Value::Null);
        let cons = run(&mut s, "system.tuning.parameter.print", json!({"profile": "conservative", "tab": "kernel"})).unwrap();
        assert_eq!(row(&cons, "net.core.netdev_budget")["why_id"], "keep");
        assert_eq!(row(&cons, "net.core.netdev_budget")["recommended"], 300);
        assert!(run(&mut s, "system.tuning.parameter.print", json!({"profile": "turbo"})).is_err());
        assert!(run(&mut s, "system.tuning.parameter.print", json!({"tab": "gpu"})).is_err());
    }

    #[test]
    fn set_validates_and_unset_restores() {
        let mut s = lab();
        let ok = run(&mut s, "system.tuning.set", json!({"name": "net.core.netdev_budget", "value": 600})).unwrap();
        assert_eq!(ok["value"], 600);
        let v = run(&mut s, "system.tuning.parameter.print", json!({})).unwrap();
        let b = row(&v, "net.core.netdev_budget");
        assert_eq!(b["configured"], 600);
        assert_eq!(b["current"], 600, "the lab kernel follows the applied config");

        let mut err = |p: Value| run(&mut s, "system.tuning.set", p).unwrap_err().to_string();
        assert!(err(json!({"name": "net.core.netdev_budget", "value": 10})).contains("50..=100000"));
        assert!(err(json!({"name": "net.core.netdev_budget", "value": "600"})).contains("integer"));
        assert!(err(json!({"name": "netdev_budget", "value": 600})).contains("did you mean net.core.netdev_budget"));
        assert!(err(json!({"name": "kernel.core_pattern", "value": 1})).contains("not a tunable"));
        assert!(err(json!({"name": "net.ipv4.route.max_size", "value": 1})).contains("obsolete"));
        let big = err(json!({"name": "net.netfilter.nf_conntrack_max", "value": 1 << 26}));
        assert!(big.contains("RAM"), "{big}");
        // gc_thresh3 under gc_thresh2 (512 in the lab) is refused.
        let order = err(json!({"name": "net.ipv4.neigh.default.gc_thresh3", "value": 256}));
        assert!(order.contains("gc_thresh1 ≤ gc_thresh2 ≤ gc_thresh3"), "{order}");

        let listed = run(&mut s, "system.tuning.print", json!({})).unwrap();
        assert_eq!(listed, json!([{"name": "net.core.netdev_budget", "value": 600}]));
        let un = run(&mut s, "system.tuning.unset", json!({"name": "net.core.netdev_budget"})).unwrap();
        assert_eq!(un["was"], 600);
        let v = run(&mut s, "system.tuning.parameter.print", json!({})).unwrap();
        assert_eq!(row(&v, "net.core.netdev_budget")["current"], 300);
        assert!(run(&mut s, "system.tuning.unset", json!({"name": "net.core.netdev_budget"})).is_err());
    }

    #[test]
    fn profile_apply_is_one_transaction_with_rollback() {
        let mut s = lab();
        let diff = run(&mut s, "system.tuning.profile.diff", json!({"profile": "throughput"})).unwrap();
        let n = diff.as_array().unwrap().len();
        assert!(n > 10, "{diff}");
        assert!(diff.as_array().unwrap().iter().all(|d| d["why"].is_string()));

        let before = s.store().running().clone();
        let rev = s.store().current_revision();
        let out = run(&mut s, "system.tuning.profile.apply", json!({"profile": "throughput"})).unwrap();
        assert_eq!(out["changed"].as_array().unwrap().len(), n);
        let after = run(&mut s, "system.tuning.profile.diff", json!({"profile": "throughput"})).unwrap();
        assert_eq!(after, json!([]), "nothing left to change");
        assert_eq!(
            s.store().running().system.tuning.sysctl["net.netfilter.nf_conntrack_tcp_timeout_established"],
            7440
        );
        // One commit: rolling it back restores the whole profile at once.
        run(&mut s, "config.rollback", json!({"revision": rev})).unwrap();
        assert_eq!(s.store().running().system.tuning, before.system.tuning);

        // Only some names.
        let some = run(
            &mut s,
            "system.tuning.profile.apply",
            json!({"profile": "balanced", "names": ["net.core.netdev_budget"]}),
        )
        .unwrap();
        assert_eq!(some["changed"], json!([{"name": "net.core.netdev_budget", "from": 300, "to": 600}]));
        assert!(run(&mut s, "system.tuning.profile.apply", json!({})).is_err());
        assert!(run(&mut s, "system.tuning.profile.apply", json!({"profile": "balanced", "names": ["x"]})).is_err());
    }

    /// G1.26i: nothing configured, the router forwards and says where the
    /// value comes from; the operator's 0 is kept, with the critical
    /// finding; unset goes back to forwarding; no profile writes a
    /// forwarding entry into the config any more.
    #[test]
    fn a_router_forwards_by_default_and_an_explicit_off_is_kept() {
        use corerouter_model::tuning::{IP_FORWARD, IPV6_FORWARDING};
        let mut s = lab();
        let forwarding = |s: &mut Session| {
            let d = run(s, "system.tuning.diagnose", json!({})).unwrap();
            d["findings"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|f| f["id"].as_str().map(str::to_owned))
                .filter(|id| id.starts_with("forwarding"))
                .collect::<Vec<_>>()
        };
        let v = run(&mut s, "system.tuning.parameter.print", json!({})).unwrap();
        for name in [IP_FORWARD, IPV6_FORWARDING] {
            let r = row(&v, name);
            assert_eq!(r["current"], 1, "{name}");
            assert_eq!(r["configured"], Value::Null, "{name}: not in the config");
            assert_eq!(r["router_default"], 1, "{name}");
            assert_eq!(r["default"], 0, "{name}: the kernel's own default");
            assert_eq!(r["recommended"], 1, "{name}");
        }
        assert_eq!(row(&v, "net.core.netdev_budget")["router_default"], Value::Null);
        assert!(forwarding(&mut s).is_empty());
        assert_eq!(run(&mut s, "system.tuning.print", json!({})).unwrap(), json!([]));
        let e = run(&mut s, "system.tuning.unset", json!({"name": IP_FORWARD}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("CoreRouter's default (1) is in use"), "{e}");
        // Every profile leaves forwarding out of the config.
        for profile in Profile::ALL {
            let diff = run(&mut s, "system.tuning.profile.diff", json!({"profile": profile.id()})).unwrap();
            assert!(!diff.to_string().contains("forward"), "{profile:?}: {diff}");
        }

        run(&mut s, "system.tuning.set", json!({"name": IP_FORWARD, "value": 0})).unwrap();
        let v = run(&mut s, "system.tuning.parameter.print", json!({})).unwrap();
        assert_eq!(row(&v, IP_FORWARD)["current"], 0);
        assert_eq!(row(&v, IP_FORWARD)["configured"], 0);
        assert_eq!(row(&v, IPV6_FORWARDING)["current"], 1, "IPv6 on its own");
        assert_eq!(forwarding(&mut s), ["forwarding_off"]);
        assert_eq!(
            run(&mut s, "system.tuning.print", json!({})).unwrap(),
            json!([{"name": IP_FORWARD, "value": 0}]),
            "the export keeps the operator's 0"
        );
        run(&mut s, "system.tuning.set", json!({"name": IPV6_FORWARDING, "value": 0})).unwrap();
        assert_eq!(forwarding(&mut s), ["forwarding_off", "forwarding6_off"]);

        let un = run(&mut s, "system.tuning.unset", json!({"name": IP_FORWARD})).unwrap();
        assert_eq!(un["was"], 0);
        run(&mut s, "system.tuning.unset", json!({"name": IPV6_FORWARDING})).unwrap();
        let v = run(&mut s, "system.tuning.parameter.print", json!({})).unwrap();
        assert_eq!(row(&v, IP_FORWARD)["current"], 1);
        assert!(forwarding(&mut s).is_empty());
    }

    /// A config written before G1.26i, by a router that applied a profile
    /// (forwarding 1 among the rest) or that turned forwarding off, loads
    /// as it is and means the same.
    #[test]
    fn a_config_from_before_the_default_loads_the_same() {
        use corerouter_model::Config;
        use corerouter_model::tuning::{IP_FORWARD, IPV6_FORWARDING};
        let old: Config = serde_json::from_value(json!({"system": {"tuning": {"sysctl": {
            IP_FORWARD: 1, IPV6_FORWARDING: 0, "net.core.netdev_budget": 600,
        }}}}))
        .unwrap();
        let t = &old.system.tuning;
        assert_eq!(t.sysctl.len(), 3);
        assert_eq!(t.effective_sysctl().get(IP_FORWARD), Some(&1));
        assert_eq!(t.effective_sysctl().get(IPV6_FORWARDING), Some(&0));
        // Written back unchanged: no migration, nothing added.
        let back = serde_json::to_value(&old).unwrap();
        assert_eq!(back["system"]["tuning"]["sysctl"].as_object().unwrap().len(), 3);
        // One with no tuning at all (most routers): forwards now.
        let bare: Config = serde_json::from_value(json!({})).unwrap();
        assert!(bare.system.tuning.is_default());
        assert_eq!(bare.system.tuning.effective_sysctl().get(IPV6_FORWARDING), Some(&1));
    }

    #[test]
    fn hardware_and_diagnosis_of_the_lab() {
        let mut s = lab();
        let hw = run(&mut s, "system.tuning.hardware", json!({})).unwrap();
        assert_eq!(hw["cpus"], 16);
        assert_eq!(hw["numa"].as_array().unwrap().len(), 2);
        let nics = hw["nics"].as_array().unwrap();
        assert_eq!(nics.len(), 8);
        assert_eq!(nics[7]["speed_mbps"], 10_000, "the lab's SFP+ port");
        assert_eq!(nics[0]["ring_rx_max"], 4096);
        let d = run(&mut s, "system.tuning.diagnose", json!({})).unwrap();
        let ids: Vec<&str> = d["findings"].as_array().unwrap().iter().filter_map(|f| f["id"].as_str()).collect();
        assert!(ids.contains(&"conntrack_full"), "{ids:?}");
        assert!(ids.contains(&"softnet_squeeze"), "{ids:?}");
        assert!(ids.contains(&"neigh_full"), "{ids:?}");
        // Raising nf_conntrack_max clears that finding.
        run(&mut s, "system.tuning.set", json!({"name": "net.netfilter.nf_conntrack_max", "value": 2_097_152})).unwrap();
        let d = run(&mut s, "system.tuning.diagnose", json!({})).unwrap();
        assert!(!d.to_string().contains("conntrack_full"));
    }
}
