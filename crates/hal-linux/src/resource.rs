//! System › Resources and health on Linux (G4.8a): one reading of the
//! machine from `/proc` and `/sys`, without root and without `unsafe`
//! (filesystem sizes through rustix's safe `statvfs`).
//!
//! Every file is treated as hostile: read with a size cap, parsed by pure
//! functions that skip what they do not understand (a field that is not a
//! number, a short line, a value out of any sane range) and never panic —
//! proptest feeds them garbage. Lists are capped (`MAX_*` of
//! `corerouter_hal::system_resource`).
//!
//! What is read (kernel docs: `Documentation/filesystems/proc.rst`,
//! `accounting/psi.rst`, `hwmon/sysfs-interface.rst`,
//! `admin-guide/iostats.rst`):
//!
//! - `/proc/stat` (CPU times), `/proc/meminfo`, `/proc/loadavg`,
//!   `/proc/uptime`, `/proc/pressure/{cpu,memory,io}`;
//! - `/proc/softirqs` and `/proc/interrupts` (work per CPU);
//! - `/proc/mounts` + `statvfs`, `/proc/diskstats` (whole disks:
//!   `/sys/block/<name>`);
//! - `/sys/class/hwmon/*` and the `critical` trip of `/sys/class/thermal`;
//! - `/proc/net/dev` and `/sys/class/net/<if>/{operstate,speed}`;
//! - `/proc/vmstat` (`oom_kill`, `pswpin`, `pswpout`), conntrack count/max;
//! - on demand, `/proc/<pid>/stat` of every process;
//! - on every reading, `/proc/<pid>/stat` and `fd` of the router's own
//!   processes (G1.6qd: this one, the init, FRR), whose pids are kept and
//!   looked for again every [`ROUTER_SCAN_MS`] or when one is gone, and
//!   the `stat` of each of their threads (G1.6qe, `task/<tid>/stat`).

use std::io::Read;
use std::path::{Path, PathBuf};

use corerouter_hal::system_resource::{
    CpuIrqs, CpuTimes, DAEMON_PROCESS, Disk, DiskIo, LoadAvg, MAX_CPUS, MAX_DISKS, MAX_NET,
    MAX_PROCESSES, MAX_SENSORS, MAX_TASKS, Memory, NetDev, Pressure, Process, Psi, ROUTER_PROCESSES,
    ResourceSampler, Sample, Sensor, SensorKind, Task, Want, cut_name,
};

/// Most descriptors counted per process (a reading of the processes lists
/// each `/proc/<pid>/fd`; a runaway process with millions stops here).
const MAX_FDS: usize = 1 << 16;
/// How often (uptime ms) every `/proc/<pid>` is looked at again for the
/// router's processes; a known one that is gone (FRR restarted by
/// `watchfrr`) brings the look forward.
pub const ROUTER_SCAN_MS: u64 = 30_000;
/// Largest file read (`/proc/interrupts` of a 256-CPU box is ~1 MiB).
const MAX_FILE: u64 = 4 << 20;
/// Hottest and coldest temperature believed, °C: outside it is a broken
/// sensor or a placeholder (`temp2_max = 65261850` on an NVMe, `-273150`).
const TEMP_RANGE: std::ops::RangeInclusive<f64> = -60.0..=200.0;
/// How long a sensor reading is reused: some drivers ask the device
/// itself (an NVMe's temperature is an admin command, ~4 ms; the mt7925
/// wifi asks its firmware, ~3.5 ms, **medido**), and temperatures move
/// slowly.
pub const SENSORS_EVERY_MS: u64 = 10_000;
/// Fastest fan believed, rpm.
const MAX_RPM: f64 = 100_000.0;
/// Filesystems that hold data (not `tmpfs`, `proc`, overlays, read-only
/// images like `squashfs`, which are always "full").
const DATA_FS: &[&str] = &[
    "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "vfat", "exfat", "jffs2", "ubifs", "zfs",
    "ntfs3", "bcachefs",
];

fn read(path: &Path) -> Option<String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_FILE)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

fn num<T: std::str::FromStr>(s: Option<&str>) -> Option<T> {
    s?.trim().parse().ok()
}

// ---- parsers (pure) -------------------------------------------------------

fn cpu_times(fields: &[u64]) -> CpuTimes {
    let f = |i: usize| fields.get(i).copied().unwrap_or(0);
    CpuTimes {
        user: f(0),
        nice: f(1),
        system: f(2),
        idle: f(3),
        iowait: f(4),
        irq: f(5),
        softirq: f(6),
        steal: f(7),
    }
}

/// The `cpu` line (all CPUs) and the `cpuN` lines of `/proc/stat`, in
/// order; offline CPUs have no line.
pub fn parse_stat(text: &str) -> (CpuTimes, Vec<CpuTimes>) {
    let mut all = CpuTimes::default();
    let mut cores = Vec::new();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let Some(label) = it.next() else { continue };
        let Some(rest) = label.strip_prefix("cpu") else {
            continue;
        };
        let fields: Vec<u64> = it.take(8).map(|f| f.parse().unwrap_or(0)).collect();
        if rest.is_empty() {
            all = cpu_times(&fields);
        } else if rest.bytes().all(|b| b.is_ascii_digit()) && cores.len() < MAX_CPUS {
            cores.push(cpu_times(&fields));
        }
    }
    (all, cores)
}

/// `/proc/meminfo`, in bytes. Missing fields are 0; without
/// `MemAvailable` (Linux < 3.14) free + buffers + cached stands in.
pub fn parse_meminfo(text: &str) -> Memory {
    let field = |key: &str| -> Option<u64> {
        let kib: u64 = text
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))?
            .split_whitespace()
            .next()?
            .parse()
            .ok()?;
        Some(kib.saturating_mul(1024))
    };
    let free = field("MemFree").unwrap_or(0);
    let buffers = field("Buffers").unwrap_or(0);
    let cached = field("Cached").unwrap_or(0);
    let total = field("MemTotal").unwrap_or(0);
    Memory {
        total,
        free,
        available: field("MemAvailable")
            .unwrap_or_else(|| free.saturating_add(buffers).saturating_add(cached))
            .min(total),
        buffers,
        cached,
        swap_total: field("SwapTotal").unwrap_or(0),
        swap_free: field("SwapFree").unwrap_or(0),
    }
}

fn finite(v: f32) -> Option<f32> {
    v.is_finite().then_some(v)
}

/// `/proc/loadavg`: `0.52 0.58 0.59 2/6050 2889137`.
pub fn parse_loadavg(text: &str) -> Option<LoadAvg> {
    let mut it = text.split_whitespace();
    let one = finite(num(it.next())?)?;
    let five = finite(num(it.next())?)?;
    let fifteen = finite(num(it.next())?)?;
    let (running, tasks) = it
        .next()
        .and_then(|rt| rt.split_once('/'))
        .and_then(|(r, t)| Some((r.parse().ok()?, t.parse().ok()?)))
        .unwrap_or((0, 0));
    Some(LoadAvg {
        one,
        five,
        fifteen,
        running,
        tasks,
    })
}

/// `/proc/uptime` in milliseconds.
pub fn parse_uptime(text: &str) -> Option<u64> {
    let secs: f64 = num(text.split_whitespace().next())?;
    (0.0..1e12)
        .contains(&secs)
        .then_some((secs * 1000.0) as u64)
}

/// `/proc/pressure/<resource>`:
/// `some avg10=0.96 avg60=2.66 avg300=1.05 total=2672692984`
/// and the `full` line (absent for `cpu` before Linux 5.13).
pub fn parse_psi(text: &str) -> Option<Psi> {
    let line = |kind: &str| -> Option<(f32, f32, f32)> {
        let l = text.lines().find(|l| l.starts_with(kind))?;
        let get = |key: &str| -> Option<f32> {
            l.split_whitespace()
                .find_map(|f| f.strip_prefix(key)?.strip_prefix('='))?
                .parse()
                .ok()
                .and_then(finite)
                .map(|v: f32| v.clamp(0.0, 100.0))
        };
        Some((get("avg10")?, get("avg60")?, get("avg300")?))
    };
    let (some10, some60, some300) = line("some ")?;
    let full = line("full ");
    Some(Psi {
        some10,
        some60,
        some300,
        full10: full.map(|f| f.0),
        full60: full.map(|f| f.1),
        full300: full.map(|f| f.2),
    })
}

/// Columns of a per-CPU table (`CPU0 CPU1 …` header).
fn cpu_columns(header: &str) -> usize {
    header
        .split_whitespace()
        .filter(|c| c.starts_with("CPU"))
        .count()
        .min(MAX_CPUS)
}

/// `/proc/softirqs`: receive, send and all softirqs per CPU.
pub fn parse_softirqs(text: &str) -> Vec<CpuIrqs> {
    let mut lines = text.lines();
    let n = lines.next().map(cpu_columns).unwrap_or(0);
    let mut out = vec![CpuIrqs::default(); n];
    for line in lines {
        let Some((name, values)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        for (c, v) in out.iter_mut().zip(values.split_whitespace()) {
            let v: u64 = v.parse().unwrap_or(0);
            c.softirqs = c.softirqs.saturating_add(v);
            match name {
                "NET_RX" => c.net_rx = v,
                "NET_TX" => c.net_tx = v,
                _ => {}
            }
        }
    }
    out
}

/// Add the hardware interrupts of `/proc/interrupts` to `cpus`. Rows with
/// fewer counts than CPUs (`ERR:`, `MIS:`) are totals, not per CPU.
pub fn parse_interrupts(text: &str, cpus: &mut Vec<CpuIrqs>) {
    let mut lines = text.lines();
    let n = lines.next().map(cpu_columns).unwrap_or(0);
    if cpus.len() < n {
        cpus.resize(n, CpuIrqs::default());
    }
    for line in lines {
        let Some((_, values)) = line.split_once(':') else {
            continue;
        };
        let counts: Vec<u64> = values
            .split_whitespace()
            .take(n)
            .map_while(|v| v.parse().ok())
            .collect();
        if counts.len() < n {
            continue;
        }
        for (c, v) in cpus.iter_mut().zip(counts) {
            c.irqs = c.irqs.saturating_add(v);
        }
    }
}

/// `/proc/diskstats`: sectors read and written per device (every device;
/// the collector keeps whole disks).
pub fn parse_diskstats(text: &str) -> Vec<DiskIo> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            Some(DiskIo {
                name: cut_name(f.get(2)?),
                read_sectors: num(f.get(5).copied())?,
                write_sectors: num(f.get(9).copied())?,
            })
        })
        .take(4 * MAX_DISKS)
        .collect()
}

/// `oom_kill`, `pswpin` and `pswpout` of `/proc/vmstat`.
pub fn parse_vmstat(text: &str) -> (Option<u64>, Option<u64>, Option<u64>) {
    let get = |key: &str| {
        text.lines().find_map(|l| {
            let (k, v) = l.split_once(' ')?;
            (k == key).then(|| v.trim().parse().ok()).flatten()
        })
    };
    (get("oom_kill"), get("pswpin"), get("pswpout"))
}

/// `/proc/net/dev`: counters per interface (link state comes from sysfs).
pub fn parse_net_dev(text: &str) -> Vec<NetDev> {
    text.lines()
        .filter_map(|l| {
            let (name, rest) = l.split_once(':')?;
            let name = name.trim();
            if name.is_empty() || name.contains(' ') {
                return None;
            }
            let v: Vec<u64> = rest
                .split_whitespace()
                .map(|f| f.parse().unwrap_or(0))
                .collect();
            let g = |i: usize| v.get(i).copied().unwrap_or(0);
            (v.len() >= 12).then(|| NetDev {
                name: cut_name(name),
                rx_bytes: g(0),
                rx_packets: g(1),
                rx_errors: g(2),
                rx_dropped: g(3),
                tx_bytes: g(8),
                tx_packets: g(9),
                tx_errors: g(10),
                tx_dropped: g(11),
                ..NetDev::default()
            })
        })
        .take(MAX_NET)
        .collect()
}

/// `\040` and friends of `/proc/mounts` back to characters.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let octal = b
            .get(i + 1..i + 4)
            .filter(|d| b.get(i) == Some(&b'\\') && d.iter().all(|c| (b'0'..=b'7').contains(c)))
            .map(|d| d.iter().fold(0u32, |a, c| a * 8 + u32::from(c - b'0')));
        match octal.and_then(|v| u8::try_from(v).ok()) {
            Some(v) => {
                out.push(v);
                i += 4;
            }
            None => {
                out.push(b.get(i).copied().unwrap_or(b'?'));
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Data filesystems of `/proc/mounts`: (device, mount point, type), one per
/// device (btrfs subvolumes and bind mounts repeat it), the first mount.
pub fn parse_mounts(text: &str) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = Vec::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        let (Some(dev), Some(mnt), Some(fs)) = (f.first(), f.get(1), f.get(2)) else {
            continue;
        };
        if !DATA_FS.contains(fs) || out.iter().any(|(d, ..)| d == dev) {
            continue;
        }
        out.push((cut_name(&unescape(dev)), unescape(mnt), (*fs).to_owned()));
        if out.len() >= MAX_DISKS {
            break;
        }
    }
    out
}

/// Entries of `/proc/<pid>/fd` (a process's open descriptors), at most
/// [`MAX_FDS`] counted; `None` when the directory cannot be read.
fn count_fds(dir: &std::path::Path) -> Option<u32> {
    let n = std::fs::read_dir(dir).ok()?.take(MAX_FDS).count();
    u32::try_from(n).ok()
}

/// The threads of a process (`/proc/<pid>/task/<tid>/stat`, the same
/// format as a process's), by tid, at most [`MAX_TASKS`].
fn tasks(dir: &Path, page_size: u64) -> Vec<Task> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<Task> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .take(MAX_TASKS)
        .filter_map(|tid| {
            let p = parse_pid_stat(&read(&dir.join(tid.to_string()).join("stat"))?, page_size)?;
            Some(Task {
                tid,
                name: p.name,
                state: p.state,
                cpu_ticks: p.cpu_ticks,
            })
        })
        .collect();
    out.sort_unstable_by_key(|t| t.tid);
    out
}

/// The name of a `/proc/<pid>/stat` (between the first `(` and the last
/// `)`), without parsing the rest.
fn stat_name(text: &str) -> Option<&str> {
    text.get(text.find('(')? + 1..text.rfind(')')?)
}

/// `/proc/<pid>/stat`. The name is between the first `(` and the last `)`
/// (it may hold spaces and parentheses).
pub fn parse_pid_stat(text: &str, page_size: u64) -> Option<Process> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    let pid: u32 = num(text.get(..open))?;
    let name = text.get(open + 1..close)?;
    let f: Vec<&str> = text.get(close + 1..)?.split_whitespace().collect();
    // After the name: state(3) ppid(4) … utime(14) stime(15) …
    // num_threads(20) … rss(24), proc(5) numbering minus 3.
    let n = |i: usize| -> Option<u64> { num(f.get(i).copied()) };
    Some(Process {
        pid,
        ppid: n(1).and_then(|v| u32::try_from(v).ok()).unwrap_or(0),
        name: cut_name(name),
        state: f.first()?.chars().next()?,
        threads: n(17).and_then(|v| u32::try_from(v).ok()).unwrap_or(0),
        cpu_ticks: n(11)?.saturating_add(n(12)?),
        rss_bytes: n(21).unwrap_or(0).saturating_mul(page_size),
        fds: None,
        tasks: Vec::new(),
    })
}

/// Sensors of one hwmon chip from its files: (file name, contents).
/// `temp*` in m°C, `fan*` in rpm, `in*` in mV, `power*` in µW.
pub fn parse_hwmon(chip: &str, files: &[(String, String)]) -> Vec<Sensor> {
    let get = |name: &str| -> Option<f64> {
        let (_, v) = files.iter().find(|(f, _)| f == name)?;
        let v: f64 = v.trim().parse().ok()?;
        v.is_finite().then_some(v)
    };
    let label = |prefix: &str| -> String {
        files
            .iter()
            .find(|(f, _)| *f == format!("{prefix}_label"))
            .map(|(_, v)| cut_name(v.trim()))
            .filter(|l| !l.is_empty())
            .unwrap_or_else(|| prefix.to_owned())
    };
    let mut prefixes: Vec<(&str, u32, SensorKind)> = files
        .iter()
        .filter_map(|(f, _)| {
            let base = f.strip_suffix("_input").or_else(|| {
                f.strip_suffix("_average")
                    .filter(|b| b.starts_with("power"))
            })?;
            let (kind, idx) = [
                ("temp", SensorKind::Temperature),
                ("fan", SensorKind::Fan),
                ("in", SensorKind::Voltage),
                ("power", SensorKind::Power),
            ]
            .into_iter()
            .find_map(|(p, k)| Some((k, base.strip_prefix(p)?.parse::<u32>().ok()?)))?;
            Some((base, idx, kind))
        })
        .collect();
    prefixes.sort_by_key(|(b, i, k)| (*k as u8, *i, b.len()));
    prefixes.dedup_by(|a, b| a.0 == b.0);
    let temp = |v: f64| Some(v / 1000.0).filter(|t| TEMP_RANGE.contains(t));
    let limit = |v: f64| Some(v / 1000.0).filter(|t| *t > 0.0 && *t <= *TEMP_RANGE.end());
    prefixes
        .into_iter()
        .filter_map(|(base, _, kind)| {
            let raw = get(&format!("{base}_input")).or_else(|| get(&format!("{base}_average")))?;
            let (value, max, crit) = match kind {
                SensorKind::Temperature => (
                    temp(raw)?,
                    get(&format!("{base}_max")).and_then(limit),
                    get(&format!("{base}_crit")).and_then(limit),
                ),
                SensorKind::Fan => (
                    Some(raw).filter(|r| (0.0..=MAX_RPM).contains(r))?,
                    None,
                    None,
                ),
                SensorKind::Voltage => (raw / 1000.0, None, None),
                SensorKind::Power => (raw / 1e6, None, None),
            };
            Some(Sensor {
                chip: cut_name(chip),
                label: label(base),
                kind,
                value,
                max,
                crit,
            })
        })
        .take(MAX_SENSORS)
        .collect()
}

/// A thermal zone: (type, temperature °C, critical trip °C).
pub fn parse_thermal_zone(files: &[(String, String)]) -> Option<(String, f64, Option<f64>)> {
    let get = |name: &str| files.iter().find(|(f, _)| f == name).map(|(_, v)| v.trim());
    let kind = cut_name(get("type")?);
    let t: f64 = get("temp")?.parse().ok()?;
    let t = Some(t / 1000.0).filter(|t| TEMP_RANGE.contains(t))?;
    let crit = files
        .iter()
        .filter(|(f, v)| {
            f.starts_with("trip_point_") && f.ends_with("_type") && v.trim() == "critical"
        })
        .find_map(|(f, _)| {
            let temp = f.strip_suffix("_type")?.to_owned() + "_temp";
            let c: f64 = get(&temp)?.parse().ok()?;
            Some(c / 1000.0).filter(|c| *c > 0.0 && *c <= *TEMP_RANGE.end())
        });
    Some((kind, t, crit))
}

/// The first `model name` (x86) or `Model`/`Hardware` (ARM) of
/// `/proc/cpuinfo`.
pub fn parse_cpu_model(text: &str) -> Option<String> {
    ["model name", "Model", "Hardware", "cpu model"]
        .iter()
        .find_map(|key| {
            text.lines().find_map(|l| {
                let (k, v) = l.split_once(':')?;
                (k.trim() == *key && !v.trim().is_empty()).then(|| cut_name(v.trim()))
            })
        })
}

// ---- the collector --------------------------------------------------------

type Statvfs = fn(&Path) -> Option<(u64, u64, u64)>;

/// `(total, free, available)` bytes of the filesystem at `path`.
fn statvfs(path: &Path) -> Option<(u64, u64, u64)> {
    let s = rustix::fs::statvfs(path).ok()?;
    let unit = if s.f_frsize > 0 {
        s.f_frsize
    } else {
        s.f_bsize
    };
    Some((
        s.f_blocks.saturating_mul(unit),
        s.f_bfree.saturating_mul(unit),
        s.f_bavail.saturating_mul(unit),
    ))
}

/// Reads the machine. Cheap to build; caches what never changes (CPU
/// model, board).
pub struct Collector {
    proc: PathBuf,
    sys: PathBuf,
    statvfs: Statvfs,
    hz: u32,
    page_size: u64,
    fixed: Option<(Option<String>, Option<String>)>,
    /// The last sensor reading and when (uptime ms).
    sensors: Option<(u64, Vec<Sensor>)>,
    /// This process (the daemon): first of [`Sample::router`].
    own_pid: u32,
    /// Pids of the router's other processes and when (uptime ms) all of
    /// `/proc` was last looked at for them.
    router_pids: Option<(u64, Vec<u32>)>,
}

impl Default for Collector {
    fn default() -> Self {
        Self::at(Path::new("/proc"), Path::new("/sys"))
    }
}

/// The files of directory `dir` (not following into subdirectories),
/// small ones only.
fn files_of(dir: &Path) -> Vec<(String, String)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .take(512)
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_owned();
            let keep = ["temp", "fan", "in", "power", "name", "type", "trip_point_"]
                .iter()
                .any(|p| name.starts_with(p));
            if !keep || !e.file_type().ok()?.is_file() {
                return None;
            }
            let mut text = String::new();
            std::fs::File::open(e.path())
                .ok()?
                .take(256)
                .read_to_string(&mut text)
                .ok()?;
            Some((name, text))
        })
        .collect()
}

fn sorted_dir(dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|r| {
            r.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
                .map(|e| e.path())
                .take(MAX_SENSORS)
                .collect()
        })
        .unwrap_or_default();
    // hwmon10 after hwmon9.
    v.sort_by_key(|p| {
        let n = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let digits: String = n.chars().filter(char::is_ascii_digit).collect();
        (digits.parse::<u64>().unwrap_or(u64::MAX), n)
    });
    v
}

impl Collector {
    /// A collector reading `proc` and `sys` (a fixture tree in tests).
    pub fn at(proc: &Path, sys: &Path) -> Self {
        Self {
            proc: proc.to_owned(),
            sys: sys.to_owned(),
            statvfs,
            hz: u32::try_from(rustix::param::clock_ticks_per_second())
                .unwrap_or(100)
                .max(1),
            page_size: u64::try_from(rustix::param::page_size()).unwrap_or(4096),
            fixed: None,
            sensors: None,
            own_pid: std::process::id(),
            router_pids: None,
        }
    }

    /// Take `pid` as the daemon's (tests: a pid of the fixture tree).
    pub fn with_own_pid(mut self, pid: u32) -> Self {
        self.own_pid = pid;
        self
    }

    /// Replace `statvfs` (tests: the fixture's mounts are not real).
    pub fn with_statvfs(mut self, f: Statvfs) -> Self {
        self.statvfs = f;
        self
    }

    fn proc(&self, rel: &str) -> Option<String> {
        read(&self.proc.join(rel))
    }

    fn sys(&self, rel: &str) -> Option<String> {
        read(&self.sys.join(rel))
    }

    fn fixed(&mut self) -> (Option<String>, Option<String>) {
        if let Some(f) = &self.fixed {
            return f.clone();
        }
        let model = self.proc("cpuinfo").and_then(|t| parse_cpu_model(&t));
        let board = ["class/dmi/id/product_name", "class/dmi/id/board_name"]
            .iter()
            .filter_map(|f| self.sys(f))
            .chain(read(&self.sys.join("firmware/devicetree/base/model")))
            .map(|t| cut_name(t.trim_matches(|c: char| c.is_whitespace() || c == '\0')))
            .find(|t| !t.is_empty() && !t.eq_ignore_ascii_case("to be filled by o.e.m."));
        let f = (model, board);
        self.fixed = Some(f.clone());
        f
    }

    /// The sensors, read again once [`SENSORS_EVERY_MS`] passed.
    fn sensors_cached(&mut self, now_ms: u64) -> Vec<Sensor> {
        match &self.sensors {
            Some((at, list)) if now_ms >= *at && now_ms - at < SENSORS_EVERY_MS => list.clone(),
            _ => {
                let list = self.sensors();
                self.sensors = Some((now_ms, list.clone()));
                list
            }
        }
    }

    /// Every sensor, read now.
    pub fn sensors(&self) -> Vec<Sensor> {
        let mut out: Vec<Sensor> = Vec::new();
        for dir in sorted_dir(&self.sys.join("class/hwmon"), "hwmon") {
            let files = files_of(&dir);
            let chip = files
                .iter()
                .find(|(f, _)| f == "name")
                .map(|(_, v)| v.trim().to_owned())
                .unwrap_or_else(|| "hwmon".into());
            out.extend(parse_hwmon(&chip, &files));
        }
        for dir in sorted_dir(&self.sys.join("class/thermal"), "thermal_zone") {
            let Some((kind, t, crit)) = parse_thermal_zone(&files_of(&dir)) else {
                continue;
            };
            // The zone's hwmon twin (`acpitz` → chip `acpitz_0`) gets the
            // critical trip instead of a second row.
            match out.iter_mut().find(|s| {
                s.kind == SensorKind::Temperature && s.chip.starts_with(&kind) && s.crit.is_none()
            }) {
                Some(twin) => twin.crit = crit,
                None => out.push(Sensor {
                    chip: "thermal".into(),
                    label: kind,
                    kind: SensorKind::Temperature,
                    value: t,
                    max: None,
                    crit,
                }),
            }
        }
        out.truncate(MAX_SENSORS);
        out
    }

    fn net(&self) -> Vec<NetDev> {
        let mut net = self
            .proc("net/dev")
            .map(|t| parse_net_dev(&t))
            .unwrap_or_default();
        for d in &mut net {
            // Names come from the kernel but are still checked: never a path.
            if d.name.contains('/') || d.name.starts_with('.') {
                continue;
            }
            let base = format!("class/net/{}", d.name);
            d.up = self
                .sys(&format!("{base}/operstate"))
                .is_some_and(|s| matches!(s.trim(), "up" | "unknown") && d.name != "lo");
            d.speed_mbps = self
                .sys(&format!("{base}/speed"))
                .and_then(|s| s.trim().parse::<i64>().ok())
                .and_then(|s| u32::try_from(s).ok())
                .filter(|s| *s > 0);
        }
        net
    }

    fn disks(&self) -> Vec<Disk> {
        let mounts = self
            .proc("mounts")
            .map(|t| parse_mounts(&t))
            .unwrap_or_default();
        mounts
            .into_iter()
            .filter_map(|(device, mount, fs)| {
                let (total, free, available) = (self.statvfs)(Path::new(&mount))?;
                (total > 0).then(|| Disk {
                    mount: cut_name(&mount),
                    device,
                    fs,
                    total,
                    free,
                    available,
                })
            })
            .collect()
    }

    fn processes(&self) -> Vec<Process> {
        let Ok(entries) = std::fs::read_dir(&self.proc) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
            })
            .take(MAX_PROCESSES)
            .filter_map(|e| {
                let mut p = parse_pid_stat(&read(&e.path().join("stat"))?, self.page_size)?;
                p.fds = count_fds(&e.path().join("fd"));
                Some(p)
            })
            .collect()
    }

    /// One of the router's processes: its stat, descriptors and threads;
    /// `None` when it is gone.
    fn process(&self, pid: u32) -> Option<Process> {
        let dir = self.proc.join(pid.to_string());
        let mut p = parse_pid_stat(&read(&dir.join("stat"))?, self.page_size)?;
        p.fds = count_fds(&dir.join("fd"));
        p.tasks = tasks(&dir.join("task"), self.page_size);
        Some(p)
    }

    /// Every pid whose name is one of [`ROUTER_PROCESSES`] (one small
    /// read per process: done every [`ROUTER_SCAN_MS`], not per reading).
    fn scan_router(&self) -> Vec<u32> {
        let Ok(entries) = std::fs::read_dir(&self.proc) else {
            return Vec::new();
        };
        let mut pids: Vec<u32> = entries
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .filter(|pid| *pid != self.own_pid)
            .take(MAX_PROCESSES)
            .filter(|pid| {
                read(&self.proc.join(pid.to_string()).join("stat"))
                    .and_then(|t| stat_name(&t).map(|n| ROUTER_PROCESSES.contains(&n)))
                    .unwrap_or(false)
            })
            .collect();
        pids.sort_unstable();
        pids
    }

    /// The router's own processes now (G1.6qd): the daemon first, then
    /// the known pids; all of `/proc` again when due or when one is gone
    /// or renamed (a pid reused). Public for the benchmark.
    pub fn router(&mut self, now_ms: u64) -> Vec<Process> {
        let own = self.process(self.own_pid).map(|mut p| {
            p.name = DAEMON_PROCESS.to_owned();
            p
        });
        let read_known = |c: &Self, pids: &[u32]| -> Option<Vec<Process>> {
            pids.iter()
                .map(|pid| {
                    c.process(*pid)
                        .filter(|p| ROUTER_PROCESSES.contains(&p.name.as_str()))
                })
                .collect()
        };
        let known = match &self.router_pids {
            Some((at, pids)) if now_ms >= *at && now_ms - at < ROUTER_SCAN_MS => {
                read_known(self, pids)
            }
            _ => None,
        };
        let others = match known {
            Some(list) => list,
            None => {
                let pids = self.scan_router();
                let list = pids.iter().filter_map(|pid| self.process(*pid)).collect();
                self.router_pids = Some((now_ms, pids));
                list
            }
        };
        own.into_iter().chain(others).collect()
    }

    fn core_mhz(&self, cores: usize) -> (Vec<u32>, Option<u32>) {
        let khz = |cpu: usize, f: &str| -> Option<u32> {
            let v: u64 = num(self
                .sys(&format!("devices/system/cpu/cpu{cpu}/cpufreq/{f}"))
                .as_deref())?;
            u32::try_from(v / 1000).ok()
        };
        let mhz: Vec<u32> = (0..cores)
            .map_while(|c| khz(c, "scaling_cur_freq"))
            .collect();
        (mhz, khz(0, "cpuinfo_max_freq"))
    }
}

impl ResourceSampler for Collector {
    fn sample(&mut self, want: Want) -> Sample {
        let (cpu_model, board) = self.fixed();
        let uptime_ms = self
            .proc("uptime")
            .and_then(|t| parse_uptime(&t))
            .or(want.now_ms)
            .unwrap_or(0);
        let sensors = self.sensors_cached(uptime_ms);
        let (cpu, cores) = self
            .proc("stat")
            .map(|t| parse_stat(&t))
            .unwrap_or_default();
        let (core_mhz, max_mhz) = self.core_mhz(cores.len());
        let mut irqs = self
            .proc("softirqs")
            .map(|t| parse_softirqs(&t))
            .unwrap_or_default();
        if let Some(t) = self.proc("interrupts") {
            parse_interrupts(&t, &mut irqs);
        }
        let psi = |r: &str| {
            self.proc(&format!("pressure/{r}"))
                .and_then(|t| parse_psi(&t))
        };
        let disk_io = self
            .proc("diskstats")
            .map(|t| parse_diskstats(&t))
            .unwrap_or_default()
            .into_iter()
            .filter(|d| {
                !d.name.contains('/')
                    && !d.name.starts_with("loop")
                    && !d.name.starts_with("ram")
                    && self.sys.join("block").join(&d.name).exists()
            })
            .take(MAX_DISKS)
            .collect();
        let (oom_kills, swap_in, swap_out) = self
            .proc("vmstat")
            .map(|t| parse_vmstat(&t))
            .unwrap_or_default();
        let ct = |f: &str| num(self.proc(&format!("sys/net/netfilter/{f}")).as_deref());
        Sample {
            uptime_ms,
            hz: self.hz,
            cpu,
            cores,
            core_mhz,
            max_mhz,
            cpu_model,
            board,
            load: self.proc("loadavg").and_then(|t| parse_loadavg(&t)),
            memory: self
                .proc("meminfo")
                .map(|t| parse_meminfo(&t))
                .unwrap_or_default(),
            pressure: Pressure {
                cpu: psi("cpu"),
                memory: psi("memory"),
                io: psi("io"),
            },
            irqs,
            disks: self.disks(),
            disk_io,
            sensors,
            net: self.net(),
            oom_kills,
            swap_in,
            swap_out,
            conntrack: ct("nf_conntrack_count"),
            conntrack_max: ct("nf_conntrack_max"),
            processes: want.processes.then(|| self.processes()),
            router: self.router(uptime_ms),
        }
    }
}

#[cfg(test)]
mod tests;
