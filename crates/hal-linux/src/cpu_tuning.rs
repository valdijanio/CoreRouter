//! System › Tuning, CPU and IRQ (G1.26c) on Linux, all plain file I/O
//! (no `irqbalance`, `cpupower`, `tuned`):
//!
//! - frequency governor: `/sys/devices/system/cpu/cpufreq/policy*/scaling_governor`;
//! - C-state limit: a PM QoS request on `/dev/cpu_dma_latency` (a binary
//!   `s32` in µs), which lasts **while the file stays open**: this module
//!   keeps it open for as long as the daemon runs, so if the daemon dies
//!   the limit goes away with it (safe);
//! - hardware watchdog: `/dev/watchdog` held open and fed on every poll;
//!   taken out of the config, the magic close (`V`) stops it;
//! - per port: queue IRQs spread one per CPU of the port's NUMA node
//!   (`/proc/irq/<n>/smp_affinity_list`), RPS (`rps_cpus`) and XPS
//!   (`xps_cpus`) masks of the node's CPUs.
//!
//! Paths hang off [`Root`] so every rule is tested on a scratch directory.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use corerouter_hal::HalError;
use corerouter_hal::tuning::{CpuTuning, MAX_CPUS, parse_cpu_list};
use corerouter_model::tuning::GOVERNORS;

use crate::tuning::Root;

/// Bounded read of a small `/proc` or `/sys` file.
fn read(path: &Path) -> Option<String> {
    let mut text = String::new();
    File::open(path)
        .ok()?
        .take(64 * 1024)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

fn policies(root: &Root) -> Vec<PathBuf> {
    let dir = root.sys.join("devices/system/cpu/cpufreq");
    let mut v: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("policy"))
                })
                .take(MAX_CPUS)
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

fn governor_code(name: &str) -> Option<i64> {
    GOVERNORS.iter().find(|(_, g)| *g == name).map(|(c, _)| *c)
}

fn governor_name(code: i64) -> Option<&'static str> {
    GOVERNORS.iter().find(|(c, _)| *c == code).map(|(_, g)| *g)
}

/// Whether a process named `irqbalance` runs.
fn irqbalance(root: &Root) -> bool {
    std::fs::read_dir(&root.proc)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
                })
                .take(1 << 16)
                .any(|e| read(&e.path().join("comm")).is_some_and(|c| c.trim() == "irqbalance"))
        })
        .unwrap_or(false)
}

/// The CPU knobs CoreRouter holds: the PM QoS request and the watchdog.
#[derive(Debug, Default)]
pub struct Cpu {
    /// `/dev/cpu_dma_latency`, open while a limit is configured.
    latency: Option<(File, i64)>,
    /// `/dev/watchdog`, open (and fed by [`Cpu::feed`]) while configured.
    watchdog: Option<File>,
    /// Each policy's governor before CoreRouter first changed it.
    governor_orig: BTreeMap<PathBuf, String>,
}

impl Cpu {
    /// The settings as they are now.
    pub fn read(&self, root: &Root) -> CpuTuning {
        let mut out = CpuTuning {
            irqbalance: irqbalance(root),
            ..CpuTuning::default()
        };
        let gov = policies(root)
            .first()
            .and_then(|p| read(&p.join("scaling_governor")))
            .map(|g| g.trim().to_owned());
        let code = gov.as_deref().and_then(governor_code);
        if let (Some(g), None) = (&gov, code) {
            out.notes
                .push(format!("governor {g}: not one CoreRouter sets"));
        }
        if gov.is_none() {
            out.notes
                .push("no cpufreq: the CPU frequency is not the kernel's to choose".into());
        }
        out.values.insert("governor".into(), code);
        // A request CoreRouter holds; else whether the device exists.
        let lat = self.latency.as_ref().map(|(_, v)| *v);
        out.values.insert("cpu_dma_latency".into(), lat);
        let wd = root.dev.join("watchdog");
        out.values.insert(
            "hw_watchdog".into(),
            if self.watchdog.is_some() {
                Some(1)
            } else {
                wd.exists().then_some(0)
            },
        );
        out
    }

    /// Bring the CPU settings from `from` to `to`, all or nothing.
    pub fn transition(
        &mut self,
        from: &BTreeMap<String, i64>,
        to: &BTreeMap<String, i64>,
        root: &Root,
    ) -> Result<(), HalError> {
        let mut undo: Vec<(&str, Option<i64>)> = Vec::new();
        for k in ["governor", "cpu_dma_latency", "hw_watchdog"] {
            if from.get(k) == to.get(k) {
                continue;
            }
            if let Err(e) = self.set(k, to.get(k).copied(), root) {
                for (k, back) in undo.iter().rev() {
                    if let Err(b) = self.set(k, *back, root) {
                        log::error!("restoring {k}: {b}");
                    }
                }
                return Err(HalError::Rejected(e));
            }
            undo.push((k, from.get(k).copied()));
        }
        Ok(())
    }

    fn set(&mut self, key: &str, value: Option<i64>, root: &Root) -> Result<(), String> {
        match key {
            "governor" => {
                let pols = policies(root);
                if pols.is_empty() {
                    return Err("governor: this machine has no cpufreq".into());
                }
                for p in &pols {
                    let file = p.join("scaling_governor");
                    let now = read(&file).map(|g| g.trim().to_owned()).unwrap_or_default();
                    let want = match value {
                        Some(v) => governor_name(v).ok_or("governor: unknown code")?.to_owned(),
                        // Taken out: the policy's own, if CoreRouter knows it.
                        None => match self.governor_orig.remove(p) {
                            Some(g) => g,
                            None => continue,
                        },
                    };
                    if value.is_some() {
                        let available =
                            read(&p.join("scaling_available_governors")).unwrap_or_default();
                        if !available.split_whitespace().any(|g| g == want) {
                            return Err(format!(
                                "governor {want}: the cpufreq driver offers only {}",
                                available.trim()
                            ));
                        }
                        self.governor_orig.entry(p.clone()).or_insert(now.clone());
                    }
                    if now != want {
                        std::fs::write(&file, format!("{want}\n"))
                            .map_err(|e| format!("governor {want}: {e}"))?;
                    }
                }
                Ok(())
            }
            "cpu_dma_latency" => {
                // Closing the file drops the request.
                self.latency = None;
                if let Some(us) = value {
                    let v = i32::try_from(us).map_err(|_| "cpu_dma_latency out of range")?;
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .open(root.dev.join("cpu_dma_latency"))
                        .map_err(|e| format!("/dev/cpu_dma_latency: {e}"))?;
                    // pm_qos_interface.rst: a binary s32, in µs.
                    f.write_all(&v.to_ne_bytes())
                        .map_err(|e| format!("/dev/cpu_dma_latency: {e}"))?;
                    self.latency = Some((f, us));
                }
                Ok(())
            }
            "hw_watchdog" => {
                if value == Some(1) {
                    if self.watchdog.is_none() {
                        let f = std::fs::OpenOptions::new()
                            .write(true)
                            .open(root.dev.join("watchdog"))
                            .map_err(|e| format!("/dev/watchdog: {e}"))?;
                        self.watchdog = Some(f);
                    }
                } else if let Some(mut f) = self.watchdog.take() {
                    // watchdog-api.rst: the magic close stops the timer.
                    f.write_all(b"V")
                        .map_err(|e| format!("/dev/watchdog: {e}"))?;
                }
                Ok(())
            }
            _ => Err(format!("unknown CPU setting {key}")),
        }
    }

    /// Keep the hardware watchdog from rebooting the box (each poll).
    pub fn feed(&mut self) {
        if let Some(f) = &mut self.watchdog
            && let Err(e) = f.write_all(b"\0")
        {
            log::error!("feeding /dev/watchdog: {e}");
        }
    }
}

/// The queue IRQs of port `dev`: the MSI vectors whose `/proc/interrupts`
/// name mentions the port (`ens1f0-TxRx-3`), else all of them.
pub(crate) fn port_irqs(root: &Root, dev: &str) -> Vec<u32> {
    let mut all: Vec<u32> =
        std::fs::read_dir(root.sys.join("class/net").join(dev).join("device/msi_irqs"))
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter_map(|e| e.file_name().to_str()?.parse().ok())
                    .take(MAX_CPUS)
                    .collect()
            })
            .unwrap_or_default();
    all.sort_unstable();
    let named: Vec<u32> = read(&root.proc.join("interrupts"))
        .map(|t| {
            t.lines()
                .filter(|l| {
                    l.split_whitespace()
                        .last()
                        .is_some_and(|n| n.starts_with(&format!("{dev}-")))
                })
                .filter_map(|l| l.split(':').next()?.trim().parse().ok())
                .filter(|n| all.contains(n))
                .collect()
        })
        .unwrap_or_default();
    if named.is_empty() { all } else { named }
}

/// CPUs of port `dev`'s NUMA node (all online CPUs when unknown).
pub(crate) fn local_cpus(root: &Root, dev: &str) -> Vec<u32> {
    let node = read(
        &root
            .sys
            .join("class/net")
            .join(dev)
            .join("device/numa_node"),
    )
    .and_then(|t| t.trim().parse::<i32>().ok())
    .filter(|n| *n >= 0);
    let list = match node {
        Some(n) => read(
            &root
                .sys
                .join(format!("devices/system/node/node{n}/cpulist")),
        ),
        None => read(&root.sys.join("devices/system/cpu/online")),
    };
    list.map(|t| parse_cpu_list(&t)).unwrap_or_default()
}

/// One queue per CPU: `irqs[i]` → `cpus[i % len]`.
pub(crate) fn spread(irqs: &[u32], cpus: &[u32]) -> Vec<(u32, u32)> {
    if cpus.is_empty() {
        return Vec::new();
    }
    irqs.iter()
        .enumerate()
        .filter_map(|(i, irq)| Some((*irq, *cpus.get(i % cpus.len())?)))
        .collect()
}

/// The hex mask `rps_cpus`/`xps_cpus` take (32-bit groups, comma-separated).
pub(crate) fn cpu_mask(cpus: &[u32]) -> String {
    let max = cpus.iter().copied().max().unwrap_or(0);
    let words = usize::try_from(max / 32 + 1)
        .unwrap_or(1)
        .min(MAX_CPUS / 32 + 1);
    let mut w = vec![0u32; words];
    for c in cpus {
        if let Some(x) = w.get_mut(usize::try_from(c / 32).unwrap_or(usize::MAX)) {
            *x |= 1 << (c % 32);
        }
    }
    w.iter()
        .rev()
        .map(|x| format!("{x:08x}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// A mask is empty (RPS/XPS off) when every digit is 0.
fn mask_empty(text: &str) -> bool {
    text.trim().chars().all(|c| c == '0' || c == ',')
}

fn queue_files(root: &Root, dev: &str, prefix: &str, file: &str) -> Vec<PathBuf> {
    let dir = root.sys.join("class/net").join(dev).join("queues");
    let mut v: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .is_some_and(|n| n.starts_with(prefix))
                })
                .map(|e| e.path().join(file))
                .filter(|p| p.exists())
                .take(MAX_CPUS)
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Each queue IRQ and the CPUs serving it (`smp_affinity_list`).
type IrqMap = Vec<(u32, String)>;

/// Current `irq_affinity` (1 when every queue IRQ is on its spread CPU),
/// `rps`, `xps`, and the IRQ → CPUs map.
pub(crate) fn read_port(root: &Root, dev: &str) -> (BTreeMap<String, Option<i64>>, IrqMap) {
    let mut out = BTreeMap::new();
    let irqs = port_irqs(root, dev);
    let map: Vec<(u32, String)> = irqs
        .iter()
        .filter_map(|i| {
            let a = read(&root.proc.join(format!("irq/{i}/smp_affinity_list")))?;
            Some((*i, a.trim().to_owned()))
        })
        .collect();
    let want = spread(&irqs, &local_cpus(root, dev));
    let affinity = (!map.is_empty()).then(|| {
        let on = want
            .iter()
            .all(|(irq, cpu)| map.iter().any(|(i, a)| i == irq && *a == cpu.to_string()));
        i64::from(on && !want.is_empty())
    });
    out.insert("irq_affinity".into(), affinity);
    for (key, prefix, file) in [("rps", "rx-", "rps_cpus"), ("xps", "tx-", "xps_cpus")] {
        let files = queue_files(root, dev, prefix, file);
        let v = (!files.is_empty()).then(|| {
            i64::from(
                files
                    .iter()
                    .any(|f| read(f).is_some_and(|t| !mask_empty(&t))),
            )
        });
        out.insert(key.into(), v);
    }
    (out, map)
}

/// The originals a port setting puts back.
#[derive(Debug, Clone, Default)]
pub(crate) struct Saved {
    files: Vec<(PathBuf, String)>,
}

/// Write port `dev`'s `key` = `on`. Returns what to write back to undo.
pub(crate) fn write_port(root: &Root, dev: &str, key: &str, on: bool) -> Result<Saved, String> {
    let cpus = local_cpus(root, dev);
    let mut targets: Vec<(PathBuf, String)> = Vec::new();
    match key {
        "irq_affinity" => {
            let irqs = port_irqs(root, dev);
            if irqs.is_empty() {
                return Err(format!("{dev}: no queue IRQs (a virtual port)"));
            }
            let all = read(&root.sys.join("devices/system/cpu/online"))
                .map(|t| t.trim().to_owned())
                .unwrap_or_else(|| "0".into());
            for (irq, cpu) in spread(&irqs, &cpus) {
                let value = if on { cpu.to_string() } else { all.clone() };
                targets.push((
                    root.proc.join(format!("irq/{irq}/smp_affinity_list")),
                    value,
                ));
            }
        }
        "rps" | "xps" => {
            let (prefix, file) = if key == "rps" {
                ("rx-", "rps_cpus")
            } else {
                ("tx-", "xps_cpus")
            };
            let files = queue_files(root, dev, prefix, file);
            if files.is_empty() {
                return Err(format!("{dev}: no {file} (kernel without RPS/XPS)"));
            }
            let n = files.len();
            for (i, f) in files.into_iter().enumerate() {
                let mask = if !on {
                    cpu_mask(&[])
                } else if key == "xps" && n > 1 {
                    // One transmit queue per CPU, as the IRQs.
                    cpu_mask(
                        &cpus
                            .get(i % cpus.len().max(1))
                            .copied()
                            .into_iter()
                            .collect::<Vec<_>>(),
                    )
                } else {
                    cpu_mask(&cpus)
                };
                targets.push((f, mask));
            }
        }
        _ => return Err(format!("unknown CPU port setting {key}")),
    }
    let mut saved = Saved::default();
    for (path, value) in targets {
        let before = read(&path).map(|t| t.trim().to_owned()).unwrap_or_default();
        if let Err(e) = std::fs::write(&path, format!("{value}\n")) {
            restore(&saved);
            let why = if e.raw_os_error() == Some(5) {
                "a managed IRQ: the driver fixes its CPU (like MikroTik's flag o)".to_owned()
            } else {
                e.to_string()
            };
            return Err(format!("{dev}: {}: {why}", path.display()));
        }
        saved.files.push((path, before));
    }
    Ok(saved)
}

/// Put back what [`write_port`] changed.
pub(crate) fn restore(saved: &Saved) {
    for (path, value) in saved.files.iter().rev() {
        if let Err(e) = std::fs::write(path, format!("{value}\n")) {
            log::error!("restoring {}: {e}", path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(tag: &str) -> (Scratch, Root) {
        let dir = std::env::temp_dir().join(format!("corerouter-cpu-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let root = Root {
            proc: dir.join("proc"),
            sys: dir.join("sys"),
            dev: dir.join("dev"),
        };
        (Scratch(dir), root)
    }

    fn put(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn masks_and_spread() {
        assert_eq!(cpu_mask(&[0, 1, 2, 3]), "0000000f");
        assert_eq!(cpu_mask(&[1, 33]), "00000002,00000002");
        assert_eq!(cpu_mask(&[]), "00000000");
        assert!(mask_empty("00000000,00000000\n"));
        assert!(!mask_empty("0000000f"));
        assert_eq!(spread(&[10, 11, 12], &[4, 5]), [(10, 4), (11, 5), (12, 4)]);
        assert!(spread(&[10], &[]).is_empty());
    }

    #[test]
    fn governor_latency_and_watchdog_come_and_go() {
        let (_s, r) = scratch("cpu");
        for p in ["policy0", "policy1"] {
            let d = r.sys.join("devices/system/cpu/cpufreq").join(p);
            put(&d.join("scaling_governor"), "schedutil\n");
            put(
                &d.join("scaling_available_governors"),
                "performance schedutil powersave\n",
            );
        }
        put(&r.dev.join("cpu_dma_latency"), "");
        put(&r.dev.join("watchdog"), "");
        put(&r.proc.join("4242/comm"), "irqbalance\n");
        let mut cpu = Cpu::default();
        let now = cpu.read(&r);
        assert_eq!(now.values["governor"], Some(1));
        assert_eq!(now.values["hw_watchdog"], Some(0));
        assert!(now.irqbalance);

        let none = BTreeMap::new();
        let mut to = BTreeMap::new();
        to.insert("governor".to_owned(), 0);
        to.insert("cpu_dma_latency".to_owned(), 2);
        to.insert("hw_watchdog".to_owned(), 1);
        cpu.transition(&none, &to, &r).unwrap();
        let gov = r
            .sys
            .join("devices/system/cpu/cpufreq/policy1/scaling_governor");
        assert_eq!(std::fs::read_to_string(&gov).unwrap(), "performance\n");
        assert_eq!(
            std::fs::read(r.dev.join("cpu_dma_latency")).unwrap(),
            2i32.to_ne_bytes()
        );
        cpu.feed();
        assert_eq!(cpu.read(&r).values["cpu_dma_latency"], Some(2));

        // A governor the driver lacks: the whole change goes back.
        let mut bad = to.clone();
        bad.insert("governor".to_owned(), 2); // ondemand
        bad.insert("cpu_dma_latency".to_owned(), 5);
        let err = cpu.transition(&to, &bad, &r).unwrap_err().to_string();
        assert!(err.contains("offers only"), "{err}");
        assert_eq!(cpu.read(&r).values["cpu_dma_latency"], Some(2));

        // Taken out: the policy's own governor, the request dropped, the
        // watchdog stopped with the magic close.
        cpu.transition(&to, &none, &r).unwrap();
        assert_eq!(std::fs::read_to_string(&gov).unwrap(), "schedutil\n");
        assert_eq!(cpu.read(&r).values["cpu_dma_latency"], None);
        assert!(
            std::fs::read(r.dev.join("watchdog"))
                .unwrap()
                .ends_with(b"V")
        );
    }

    #[test]
    fn port_irqs_rps_and_xps() {
        let (_s, r) = scratch("port");
        let dev = r.sys.join("class/net/eth0");
        for irq in [40, 41, 42, 43] {
            put(&dev.join(format!("device/msi_irqs/{irq}")), "msix\n");
            put(
                &r.proc.join(format!("irq/{irq}/smp_affinity_list")),
                "0-7\n",
            );
        }
        put(
            &r.proc.join("interrupts"),
            "40: 1 2 IR-PCI-MSIX eth0\n41: 1 2 IR-PCI-MSIX eth0-TxRx-0\n42: 1 2 IR-PCI-MSIX eth0-TxRx-1\n43: 0 0 IR-PCI-MSIX eth0-TxRx-2\n",
        );
        put(&dev.join("device/numa_node"), "1\n");
        put(&r.sys.join("devices/system/node/node1/cpulist"), "4-5\n");
        put(&r.sys.join("devices/system/cpu/online"), "0-7\n");
        for q in 0..2 {
            put(&dev.join(format!("queues/rx-{q}/rps_cpus")), "00000000\n");
            put(&dev.join(format!("queues/tx-{q}/xps_cpus")), "00000000\n");
        }
        assert_eq!(
            port_irqs(&r, "eth0"),
            [41, 42, 43],
            "the queue vectors only"
        );
        let (now, map) = read_port(&r, "eth0");
        assert_eq!(now["irq_affinity"], Some(0));
        assert_eq!(now["rps"], Some(0));
        assert_eq!(map.len(), 3);

        let saved = write_port(&r, "eth0", "irq_affinity", true).unwrap();
        let aff = |i: u32| {
            std::fs::read_to_string(r.proc.join(format!("irq/{i}/smp_affinity_list"))).unwrap()
        };
        assert_eq!(
            (aff(41), aff(42), aff(43)),
            ("4\n".into(), "5\n".into(), "4\n".into())
        );
        assert_eq!(read_port(&r, "eth0").0["irq_affinity"], Some(1));
        restore(&saved);
        assert_eq!(aff(41), "0-7\n");

        write_port(&r, "eth0", "rps", true).unwrap();
        let rps = std::fs::read_to_string(dev.join("queues/rx-1/rps_cpus")).unwrap();
        assert_eq!(rps, "00000030\n", "CPUs 4 and 5");
        write_port(&r, "eth0", "xps", true).unwrap();
        let x0 = std::fs::read_to_string(dev.join("queues/tx-0/xps_cpus")).unwrap();
        let x1 = std::fs::read_to_string(dev.join("queues/tx-1/xps_cpus")).unwrap();
        assert_eq!(
            (x0.as_str(), x1.as_str()),
            ("00000010\n", "00000020\n"),
            "one CPU per queue"
        );
        assert_eq!(read_port(&r, "eth0").0["xps"], Some(1));
        assert!(write_port(&r, "veth9", "irq_affinity", true).is_err());
    }
}
