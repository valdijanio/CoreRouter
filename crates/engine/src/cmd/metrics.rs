//! `system.metrics` (G4.4): every counter a monitoring system scrapes, in
//! one query, so the daemon's Prometheus `/metrics` (and an MCP agent) pay
//! one lock and one platform poll per scrape instead of one per interface.
//!
//! Interfaces are the config's plus the platform's links outside it
//! (unmanaged ones included: their traffic is still the router's). Error
//! and drop counters are those of the platform's `interface` counter group
//! (`interface.stats`); a platform that has none reports `null`, never a
//! made-up zero. They ride on the poll itself (`LinkState::errors`, Linux
//! `IFLA_STATS64`): asking `counters` per link meant a netlink and an
//! ethtool round trip per interface under the session lock, per scrape.
//!
//! G1.6qd: memory, filesystems, the router's own processes (daemon, init,
//! FRR: memory, threads, descriptors, CPU) and the health checks, from the
//! `health` service's last reading (taken outside the lock), so an alarm on
//! a leak or a full `/config` needs nothing but Prometheus.

use std::collections::BTreeMap;

use corerouter_hal::LinkState;
use corerouter_model::IfName;
use corerouter_model::service::ServiceTable;
use serde_json::{Value, json};

use super::{CommandSpec, always};
use crate::health_check::{evaluate, overall};
use crate::{Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "system.metrics", "Metrics", [], None,
    "{} → {revision, mode (immediate | transactional), safe_mode, engine: {changes_ok, changes_failed, queries_ok, queries_failed, unknown, commits_ok, commits_failed}, interfaces: [{name, type, managed, disabled, running, rx_bytes, tx_bytes, rx_packets, tx_packets, rx_errors, tx_errors, rx_dropped, tx_dropped, link_downs}], services: [{name, state, up, restarts}], dhcp_server (null until a DHCP server ran; else as ip.dhcp-server.statistics.print), memory: {total, available, free, swap_total, swap_free}|null, filesystems: [{mount, device, fs, total, free, available}], processes: [{name, pid, rss_bytes, threads, fds, cpu_seconds}] (the daemon, the init and FRR), health: {status, checks: [{key, severity}]}}",
    always, metrics)];

fn metrics(s: &mut Session, _: &Value) -> Result<Value> {
    let live = s.hal_mut().poll();
    s.watch_links(&live);
    let by_name: BTreeMap<&IfName, &LinkState> = live.iter().map(|l| (&l.name, l)).collect();
    let mut names: Vec<(IfName, Option<&LinkState>)> = s
        .store()
        .candidate()
        .interfaces
        .keys()
        .map(|n| (n.clone(), by_name.get(n).copied()))
        .collect();
    names.extend(
        live.iter()
            .filter(|l| !s.store().candidate().interfaces.contains_key(&l.name))
            .map(|l| (l.name.clone(), Some(l))),
    );
    let machine = machine(s);
    let mut rows = Vec::with_capacity(names.len());
    for (name, st) in names {
        let errors = st.and_then(|l| l.errors);
        let cfg = s.store().candidate().interfaces.get(&name);
        let kind = cfg.map_or_else(
            || st.map_or("", |l| l.kind.as_str()).to_owned(),
            |i| i.kind.label().to_owned(),
        );
        rows.push(json!({
            "name": name,
            "type": kind,
            "managed": cfg.is_some() && st.is_none_or(|l| l.unmanaged.is_none()),
            "disabled": cfg.is_some_and(|i| i.disabled),
            "running": st.is_some_and(|l| l.running),
            "rx_bytes": st.map(|l| l.rx_bytes),
            "tx_bytes": st.map(|l| l.tx_bytes),
            "rx_packets": st.map(|l| l.rx_packets),
            "tx_packets": st.map(|l| l.tx_packets),
            "rx_errors": errors.map(|e| e.rx_errors),
            "tx_errors": errors.map(|e| e.tx_errors),
            "rx_dropped": errors.map(|e| e.rx_dropped),
            "tx_dropped": errors.map(|e| e.tx_dropped),
            "link_downs": s.links.get(&name).map(|t| t.downs),
        }));
    }
    Ok(json!({
        "revision": s.store().current_revision(),
        "mode": s.mode(),
        "safe_mode": s.in_safe_mode(),
        "engine": s.counters,
        "interfaces": rows,
        "services": services(s),
        "dhcp_server": super::dhcp_server_stats::snapshot(s),
        "memory": machine.memory,
        "filesystems": machine.filesystems,
        "processes": machine.processes,
        "health": health(s),
    }))
}

/// What the last reading of the machine says (G1.6qd).
#[derive(Default)]
struct Machine {
    memory: Value,
    filesystems: Vec<Value>,
    processes: Vec<Value>,
}

fn machine(s: &mut Session) -> Machine {
    let Some(l) = s.resource_for_metrics().and_then(|m| m.last.as_ref()) else {
        return Machine { memory: Value::Null, ..Machine::default() };
    };
    let m = &l.memory;
    let hz = f64::from(l.hz.max(1));
    Machine {
        memory: if m.total > 0 {
            json!({
                "total": m.total, "available": m.available, "free": m.free,
                "swap_total": m.swap_total, "swap_free": m.swap_free,
            })
        } else {
            Value::Null
        },
        filesystems: l
            .disks
            .iter()
            .map(|d| {
                json!({
                    "mount": d.mount, "device": d.device, "fs": d.fs,
                    "total": d.total, "free": d.free, "available": d.available,
                })
            })
            .collect(),
        processes: l
            .router
            .iter()
            .map(|p| {
                json!({
                    "name": p.name, "pid": p.pid, "rss_bytes": p.rss_bytes,
                    "threads": p.threads, "fds": p.fds,
                    "cpu_seconds": p.cpu_ticks as f64 / hz,
                })
            })
            .collect(),
    }
}

/// The health checks now, as `system.health.check` judges them (never
/// logged here: the alerts are the `health` service's).
fn health(s: &mut Session) -> Value {
    let checks = evaluate(&s.health_inputs());
    json!({
        "status": overall(&checks).as_str(),
        "checks": checks
            .iter()
            .map(|c| json!({"key": c.key, "severity": c.severity.as_str()}))
            .collect::<Vec<_>>(),
    })
}

/// The supervised services (G0.10); none without a daemon.
fn services(s: &Session) -> Vec<Value> {
    s.ext::<ServiceTable>()
        .filter(|t| t.supervised)
        .map(|t| {
            t.rows
                .iter()
                .map(|r| {
                    json!({
                        "name": r.name,
                        "state": r.state.as_str(),
                        "up": r.state.is_up(),
                        "restarts": r.restarts,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}
