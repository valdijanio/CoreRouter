//! `/system resource` (G4.8a, RouterOS `/system resource`,
//! `/system resource cpu` and `/tool profile`): the machine now — uptime,
//! CPU, memory and pressure, disks, temperature — per CPU, per link and per
//! process. Loads and rates are between the last two readings
//! (`crate::system_resource`); the first call of a lab session reads twice.

use corerouter_hal::system_resource::{MAX_PROCESSES, Sample, SensorKind};
use serde_json::{Value, json};

use super::args::{opt_str, opt_u32};
use super::{CommandSpec, always};
use crate::system_resource::{ResourceMonitor, hottest, load, memory_used, percent};
use crate::{EngineError, Result, Session};

/// Points of history `print` returns (5 s apart: 5 min).
const HISTORY_POINTS: usize = 60;
const DEFAULT_PROCESSES: u32 = 100;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "system.resource.print", "Resources", ["System", "Resources"], None,
        "{} → {uptime_secs, version, architecture, board_name, cpu_model, cpu_count, cpu_frequency_mhz, cpu_max_mhz, cpu_load, load_avg: {one, five, fifteen, running, tasks}|null, total_memory, free_memory, memory_used_percent, memory: {total, free, available, buffers, cached, swap_total, swap_free}, pressure: {cpu, memory, io: {some10, some60, some300, full10, full60, full300}|null}, total_hdd_space, free_hdd_space, disks: [{mount, device, fs, total, free, available, used_percent}], disk_io: [{name, read_rate, write_rate}], write_sect_since_reboot, temperature: {value, crit, sensor}|null, fan_rpm, conntrack: {count, max}|null, oom_kills, history: [{t, cpu, memory, temperature}]}",
        always, print),
    cmd!(query "system.resource.cpu.print", "Resources CPU", [], None,
        "{} → [{cpu, load, user, system, irq, softirq, iowait, steal, frequency_mhz, irq_rate, softirq_rate, net_rx_rate, net_tx_rate}]",
        always, cpu_print),
    cmd!(query "system.resource.process.print", "Resources Processes", [], None,
        "{sort?: cpu|memory|name|pid|threads, limit?: int} → [{pid, ppid, name, state, threads, cpu, memory}]",
        always, process_print),
    cmd!(query "system.resource.network.print", "Resources Network", [], None,
        "{} → [{name, running, speed_mbps, rx_bits_per_second, tx_bits_per_second, rx_packets_per_second, tx_packets_per_second, rx_errors, tx_errors, rx_drops, tx_drops, errors_per_second, drops_per_second}]",
        always, network_print),
];

/// One decimal, for people.
pub(crate) fn r1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

fn r1f(v: f32) -> f64 {
    r1(f64::from(v))
}

/// Fresh readings, or the reason there are none.
pub(crate) fn monitor(s: &mut Session, processes: bool) -> Result<&ResourceMonitor> {
    watched(s, processes, true)
}

/// [`monitor`], saying whether someone watches (see
/// `Session::resource_refresh`).
pub(crate) fn watched(s: &mut Session, processes: bool, looking: bool) -> Result<&ResourceMonitor> {
    s.resource_refresh(processes, looking)
        .map_err(EngineError::Hal)?;
    s.ext::<ResourceMonitor>()
        .ok_or_else(|| EngineError::Internal("system.resource".into()))
}

fn last(m: &ResourceMonitor) -> Result<&Sample> {
    m.last
        .as_ref()
        .ok_or_else(|| EngineError::Hal("no reading of the machine yet".into()))
}

fn psi(p: Option<corerouter_hal::system_resource::Psi>) -> Value {
    match p {
        None => Value::Null,
        Some(p) => json!({
            "some10": r1f(p.some10), "some60": r1f(p.some60), "some300": r1f(p.some300),
            "full10": p.full10.map(r1f), "full60": p.full60.map(r1f), "full300": p.full300.map(r1f),
        }),
    }
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let m = monitor(s, false)?;
    let l = last(m)?;
    let cpu = m.cpu();
    let mhz = (!l.core_mhz.is_empty())
        .then(|| l.core_mhz.iter().map(|m| u64::from(*m)).sum::<u64>() / l.core_mhz.len() as u64);
    let disks: Vec<Value> = l
        .disks
        .iter()
        .map(|d| {
            json!({
                "mount": d.mount, "device": d.device, "fs": d.fs,
                "total": d.total, "free": d.free, "available": d.available,
                "used_percent": percent(d.total.saturating_sub(d.available), d.total).map(r1f),
            })
        })
        .collect();
    // The router's own disk: `/`, else the first one.
    let root = l.disks.iter().find(|d| d.mount == "/").or(l.disks.first());
    let disk_io: Vec<Value> = l
        .disk_io
        .iter()
        .map(|d| {
            let find = |x: &Sample| x.disk_io.iter().find(|y| y.name == d.name).cloned();
            json!({
                "name": d.name,
                "read_rate": m.rate(|x| find(x).map(|y| y.read_sectors.saturating_mul(512))).map(r1),
                "write_rate": m.rate(|x| find(x).map(|y| y.write_sectors.saturating_mul(512))).map(r1),
            })
        })
        .collect();
    let fan = l
        .sensors
        .iter()
        .filter(|x| x.kind == SensorKind::Fan)
        .map(|x| x.value)
        .fold(None, |a: Option<f64>, v| Some(a.map_or(v, |a| a.max(v))));
    let mem = &l.memory;
    Ok(json!({
        "uptime_secs": l.uptime_ms / 1000,
        "version": env!("CARGO_PKG_VERSION"),
        "architecture": std::env::consts::ARCH,
        "board_name": l.board,
        "cpu_model": l.cpu_model,
        "cpu_count": l.cores.len(),
        "cpu_frequency_mhz": mhz,
        "cpu_max_mhz": l.max_mhz,
        "cpu_load": cpu.map(|c| r1f(c.load)),
        "load_avg": l.load.map(|a| json!({"one": r1f(a.one), "five": r1f(a.five), "fifteen": r1f(a.fifteen), "running": a.running, "tasks": a.tasks})),
        "total_memory": mem.total,
        // What programs can still get (`MemAvailable`), not RouterOS's
        // unused RAM: on Linux the page cache makes "unused" look full.
        "free_memory": mem.available,
        "memory_used_percent": memory_used(l).map(r1f),
        "memory": mem,
        "pressure": {"cpu": psi(l.pressure.cpu), "memory": psi(l.pressure.memory), "io": psi(l.pressure.io)},
        "total_hdd_space": root.map(|d| d.total),
        "free_hdd_space": root.map(|d| d.available),
        "disks": disks,
        "disk_io": disk_io,
        "write_sect_since_reboot": l.disk_io.iter().map(|d| d.write_sectors).fold(0u64, u64::saturating_add),
        "temperature": hottest(l).map(|(v, crit, sensor)| json!({"value": r1(v), "crit": crit.map(r1), "sensor": sensor})),
        "fan_rpm": fan.map(|f| f.round()),
        "conntrack": l.conntrack.map(|c| json!({"count": c, "max": l.conntrack_max})),
        "oom_kills": l.oom_kills,
        "history": m.recent(HISTORY_POINTS),
    }))
}

fn cpu_print(s: &mut Session, _: &Value) -> Result<Value> {
    let m = monitor(s, false)?;
    let l = last(m)?;
    let rows: Vec<Value> = l
        .cores
        .iter()
        .enumerate()
        .map(|(i, now)| {
            let before = m.pair().and_then(|(a, ..)| a.cores.get(i));
            let ld = before.and_then(|b| load(b, now));
            let irq = |f: fn(&corerouter_hal::system_resource::CpuIrqs) -> u64| {
                m.rate(|x| x.irqs.get(i).map(f)).map(r1)
            };
            json!({
                "cpu": i,
                "load": ld.map(|x| r1f(x.load)),
                "user": ld.map(|x| r1f(x.user)),
                "system": ld.map(|x| r1f(x.system)),
                "irq": ld.map(|x| r1f(x.irq)),
                "softirq": ld.map(|x| r1f(x.softirq)),
                "iowait": ld.map(|x| r1f(x.iowait)),
                "steal": ld.map(|x| r1f(x.steal)),
                "frequency_mhz": l.core_mhz.get(i),
                "irq_rate": irq(|c| c.irqs),
                "softirq_rate": irq(|c| c.softirqs),
                "net_rx_rate": irq(|c| c.net_rx),
                "net_tx_rate": irq(|c| c.net_tx),
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

fn process_print(s: &mut Session, p: &Value) -> Result<Value> {
    let sort = opt_str(p, "sort")?.unwrap_or("cpu");
    if !matches!(sort, "cpu" | "memory" | "name" | "pid" | "threads") {
        return Err(EngineError::bad("sort", "must be cpu, memory, name, pid or threads"));
    }
    let limit = opt_u32(p, "limit")?.unwrap_or(DEFAULT_PROCESSES);
    if limit == 0 || limit as usize > MAX_PROCESSES {
        return Err(EngineError::bad("limit", format!("must be 1..={MAX_PROCESSES}")));
    }
    let m = monitor(s, true)?;
    let cpu = m.process_cpu();
    let Some((_, list)) = &m.procs_last else {
        return Ok(json!([]));
    };
    let mut rows: Vec<_> = list.iter().map(|x| (x, cpu.get(&x.pid).copied())).collect();
    match sort {
        "memory" => rows.sort_by_key(|a| std::cmp::Reverse(a.0.rss_bytes)),
        "name" => rows.sort_by(|a, b| a.0.name.cmp(&b.0.name)),
        "pid" => rows.sort_by_key(|x| x.0.pid),
        "threads" => rows.sort_by_key(|a| std::cmp::Reverse(a.0.threads)),
        _ => rows.sort_by(|a, b| {
            b.1.unwrap_or(-1.0)
                .total_cmp(&a.1.unwrap_or(-1.0))
                .then(b.0.rss_bytes.cmp(&a.0.rss_bytes))
        }),
    }
    rows.truncate(limit as usize);
    Ok(Value::Array(
        rows.into_iter()
            .map(|(x, c)| {
                json!({
                    "pid": x.pid, "ppid": x.ppid, "name": x.name,
                    "state": x.state.to_string(), "threads": x.threads,
                    "cpu": c.map(r1f), "memory": x.rss_bytes,
                })
            })
            .collect(),
    ))
}

fn network_print(s: &mut Session, _: &Value) -> Result<Value> {
    let m = monitor(s, false)?;
    let l = last(m)?;
    let rows: Vec<Value> = l
        .net
        .iter()
        .map(|d| {
            let r = |f: fn(&corerouter_hal::system_resource::NetDev) -> u64| {
                m.rate(|x| x.net.iter().find(|y| y.name == d.name).map(f))
            };
            json!({
                "name": d.name,
                "running": d.up,
                "speed_mbps": d.speed_mbps,
                "rx_bits_per_second": r(|y| y.rx_bytes.saturating_mul(8)).map(f64::round),
                "tx_bits_per_second": r(|y| y.tx_bytes.saturating_mul(8)).map(f64::round),
                "rx_packets_per_second": r(|y| y.rx_packets).map(f64::round),
                "tx_packets_per_second": r(|y| y.tx_packets).map(f64::round),
                "rx_errors": d.rx_errors,
                "tx_errors": d.tx_errors,
                "rx_drops": d.rx_dropped,
                "tx_drops": d.tx_dropped,
                "errors_per_second": r(|y| y.rx_errors.saturating_add(y.tx_errors)).map(r1),
                "drops_per_second": r(|y| y.rx_dropped.saturating_add(y.tx_dropped)).map(r1),
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lab_has_numbers_on_the_first_call() {
        let mut s = Session::virtual_lab();
        let v = s.execute("system.resource.print", &json!({})).unwrap();
        assert_eq!(v["cpu_count"], 16);
        assert!(v["cpu_load"].as_f64().is_some(), "{v}");
        assert!(v["total_memory"].as_u64().unwrap() > v["free_memory"].as_u64().unwrap());
        assert_eq!(v["disks"][0]["mount"], "/");
        assert!(v["temperature"]["crit"].as_f64().is_some());
        assert!(v["disk_io"][0]["write_rate"].as_f64().is_some());
        assert_eq!(v["history"].as_array().unwrap().len(), 1);
        let cores = s.execute("system.resource.cpu.print", &json!({})).unwrap();
        let cores = cores.as_array().unwrap();
        assert_eq!(cores.len(), 16);
        assert!(cores[0]["softirq"].as_f64().unwrap() > cores[1]["softirq"].as_f64().unwrap(),
            "core 0 takes the receive work in the lab");
        assert!(cores[0]["net_rx_rate"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn processes_sorted_and_limited() {
        let mut s = Session::virtual_lab();
        let v = s.execute("system.resource.process.print", &json!({"limit": 3})).unwrap();
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["name"], "corerouter-daemon");
        assert!(rows[0]["cpu"].as_f64().unwrap() >= rows[1]["cpu"].as_f64().unwrap());
        let v = s.execute("system.resource.process.print", &json!({"sort": "memory"})).unwrap();
        assert_eq!(v[0]["name"], "bgpd");
        let v = s.execute("system.resource.process.print", &json!({"sort": "name", "limit": 1})).unwrap();
        assert_eq!(v[0]["name"], "accel-pppd");
    }

    #[test]
    fn bad_params_are_refused() {
        let mut s = Session::virtual_lab();
        let e = s.execute("system.resource.process.print", &json!({"sort": "rss"})).unwrap_err();
        assert!(e.to_string().contains("cpu, memory"), "{e}");
        let e = s.execute("system.resource.process.print", &json!({"limit": 0})).unwrap_err();
        assert!(e.to_string().contains("1..="), "{e}");
        let e = s.execute("system.resource.print", &json!({"cpu": 1})).unwrap_err();
        assert!(e.to_string().contains("cpu"), "{e}");
    }

    #[test]
    fn network_rates_and_errors() {
        let mut s = Session::virtual_lab();
        let v = s.execute("system.resource.network.print", &json!({})).unwrap();
        let rows = v.as_array().unwrap();
        assert_eq!(rows.len(), 8);
        assert!(rows[0]["rx_bits_per_second"].as_f64().unwrap() > 1e9);
        assert!(rows[3]["errors_per_second"].as_f64().unwrap() > 0.0, "the lab's bad cable");
        assert_eq!(rows[7]["running"], false);
    }
}
