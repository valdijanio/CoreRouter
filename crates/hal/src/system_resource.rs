//! System › Resources and health (G4.8a, RouterOS `/system resource`,
//! `/system resource cpu`, `/system health`, `/tool profile`): one reading
//! of the machine — CPU times per core, memory and pressure (PSI), disks,
//! sensors, network counters, softirqs, OOM kills and, when asked, the
//! processes.
//!
//! A reading is raw counters; the engine turns two of them into loads and
//! rates. It is taken by a [`ResourceSampler`] that lives outside the
//! `Hal` (built once by [`crate::Hal::resource_sampler`]), so the daemon
//! reads `/proc` and `/sys` without holding the session lock. The virtual
//! lab's sampler ([`LabSampler`]) makes up plausible values that move.

use serde::Serialize;

/// Most entries of each list kept from one reading (hostile or huge
/// machines: a list never grows without bound).
pub const MAX_CPUS: usize = 1024;
pub const MAX_SENSORS: usize = 256;
pub const MAX_NET: usize = 1024;
pub const MAX_DISKS: usize = 64;
pub const MAX_PROCESSES: usize = 8192;
/// Longest name kept (process, sensor label, interface, mount).
pub const MAX_NAME: usize = 64;

/// The router's own processes besides the daemon (G1.6qd), read on every
/// reading for the `/metrics` (memory, threads, descriptors): the image's
/// init and the FRR daemons. Matched on the kernel's name (`comm`).
pub const ROUTER_PROCESSES: &[&str] = &[
    "corerouter-init",
    "watchfrr",
    "zebra",
    "mgmtd",
    "staticd",
    "bgpd",
    "ospfd",
    "ospf6d",
    "bfdd",
    "ldpd",
    "isisd",
    "ripd",
    "ripngd",
    "pimd",
    "pim6d",
    "pathd",
    "vrrpd",
    "pbrd",
    "nhrpd",
    "fabricd",
    "eigrpd",
    "babeld",
];

/// The name the daemon's own process gets in [`Sample::router`] (the
/// kernel cuts `comm` to 15 bytes: `corerouter-daem`).
pub const DAEMON_PROCESS: &str = "corerouter-daemon";

/// What the caller wants of a reading.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Want {
    /// Also read every process (hundreds of small files: only on demand).
    pub processes: bool,
    /// Milliseconds on the caller's steady clock, if it has one. The lab
    /// sampler moves its time with it; Linux reads `/proc/uptime`.
    pub now_ms: Option<u64>,
}

/// Takes readings. Built once, used from any thread.
pub trait ResourceSampler: Send {
    fn sample(&mut self, want: Want) -> Sample;
}

/// Time of one CPU (or of all, the first row) in clock ticks, as
/// `/proc/stat` counts them (guest time is already inside user and nice).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CpuTimes {
    pub fn total(&self) -> u64 {
        [
            self.user,
            self.nice,
            self.system,
            self.idle,
            self.iowait,
            self.irq,
            self.softirq,
            self.steal,
        ]
        .iter()
        .fold(0u64, |a, b| a.saturating_add(*b))
    }

    /// Everything but idle and iowait (the CPU could have run something
    /// else while waiting for the disk).
    pub fn busy(&self) -> u64 {
        self.total()
            .saturating_sub(self.idle.saturating_add(self.iowait))
    }
}

/// Bytes, from `/proc/meminfo`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Memory {
    pub total: u64,
    pub free: u64,
    /// What programs can still get without swapping (`MemAvailable`).
    pub available: u64,
    pub buffers: u64,
    pub cached: u64,
    pub swap_total: u64,
    pub swap_free: u64,
}

/// One line pair of `/proc/pressure/<resource>` (PSI): the share of time,
/// in %, some (or all) tasks were stalled on the resource, averaged over
/// 10 s, 60 s and 300 s.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct Psi {
    pub some10: f32,
    pub some60: f32,
    pub some300: f32,
    /// `None` for `cpu` before Linux 5.13 (no `full` line).
    pub full10: Option<f32>,
    pub full60: Option<f32>,
    pub full300: Option<f32>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct Pressure {
    pub cpu: Option<Psi>,
    pub memory: Option<Psi>,
    pub io: Option<Psi>,
}

/// `/proc/loadavg`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct LoadAvg {
    pub one: f32,
    pub five: f32,
    pub fifteen: f32,
    pub running: u32,
    pub tasks: u32,
}

/// Softirqs and hardware interrupts handled by one CPU, since boot
/// (`/proc/softirqs`, `/proc/interrupts`): where the receive work lands
/// shows whether RSS spreads it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CpuIrqs {
    pub net_rx: u64,
    pub net_tx: u64,
    /// Every softirq kind.
    pub softirqs: u64,
    /// Hardware interrupts (numbered and per-CPU lines).
    pub irqs: u64,
}

/// A mounted filesystem, bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Disk {
    pub mount: String,
    pub device: String,
    pub fs: String,
    pub total: u64,
    pub free: u64,
    /// Free for programs (`f_bavail`: without the root reserve).
    pub available: u64,
}

/// A block device's counters (`/proc/diskstats`, whole disks only).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DiskIo {
    pub name: String,
    /// 512-byte sectors since boot.
    pub read_sectors: u64,
    pub write_sectors: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SensorKind {
    /// °C.
    #[default]
    Temperature,
    /// rpm.
    Fan,
    /// V.
    Voltage,
    /// W.
    Power,
}

impl SensorKind {
    pub fn unit(self) -> &'static str {
        match self {
            Self::Temperature => "°C",
            Self::Fan => "rpm",
            Self::Voltage => "V",
            Self::Power => "W",
        }
    }
}

/// One hwmon or thermal-zone reading, in the kind's unit.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Sensor {
    /// The driver (`k10temp`, `nvme`, `acpitz`…).
    pub chip: String,
    /// The driver's label (`Tctl`, `Composite`), else `temp1`.
    pub label: String,
    pub kind: SensorKind,
    pub value: f64,
    /// Where the driver says it gets hot (`*_max`) and where the hardware
    /// shuts down or throttles hard (`*_crit`, or the thermal zone's
    /// `critical` trip point). Nonsense values are left out.
    pub max: Option<f64>,
    pub crit: Option<f64>,
}

/// One interface's counters (`/proc/net/dev`) and link.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NetDev {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    /// `operstate` is `up`.
    pub up: bool,
    /// Mbit/s; `None` when the driver does not say (wifi, virtual links).
    pub speed_mbps: Option<u32>,
}

/// One process (`/proc/<pid>/stat`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Process {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    /// `R` running, `S` sleeping, `D` disk wait, `Z` zombie, `I` idle…
    pub state: char,
    pub threads: u32,
    /// User + system clock ticks since it started.
    pub cpu_ticks: u64,
    pub rss_bytes: u64,
    /// Open file descriptors (`/proc/<pid>/fd`); `None` when unreadable
    /// (G1.6q: a leak of sockets or files shows here first).
    pub fds: Option<u32>,
}

/// One reading of the machine. Fields the platform does not have are
/// `None` or empty.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Sample {
    /// Milliseconds on a steady clock (Linux: since boot); two readings'
    /// difference is the time between them.
    pub uptime_ms: u64,
    /// Clock ticks per second of the CPU times (Linux: 100).
    pub hz: u32,
    /// All CPUs together.
    pub cpu: CpuTimes,
    /// One per CPU, in order.
    pub cores: Vec<CpuTimes>,
    /// Current clock of each CPU, MHz (empty: no cpufreq).
    pub core_mhz: Vec<u32>,
    pub max_mhz: Option<u32>,
    pub cpu_model: Option<String>,
    pub board: Option<String>,
    pub load: Option<LoadAvg>,
    pub memory: Memory,
    pub pressure: Pressure,
    /// One per CPU.
    pub irqs: Vec<CpuIrqs>,
    pub disks: Vec<Disk>,
    pub disk_io: Vec<DiskIo>,
    pub sensors: Vec<Sensor>,
    pub net: Vec<NetDev>,
    /// Processes killed for lack of memory since boot (`oom_kill`).
    pub oom_kills: Option<u64>,
    /// Pages swapped in and out since boot.
    pub swap_in: Option<u64>,
    pub swap_out: Option<u64>,
    pub conntrack: Option<u64>,
    pub conntrack_max: Option<u64>,
    /// `Some` only when [`Want::processes`].
    pub processes: Option<Vec<Process>>,
    /// The router's own processes, on every reading (G1.6qd): this one
    /// (named [`DAEMON_PROCESS`]) first, then those of
    /// [`ROUTER_PROCESSES`] that run, with their descriptors.
    pub router: Vec<Process>,
}

/// Cut `s` to [`MAX_NAME`] bytes at a character boundary.
pub fn cut_name(s: &str) -> String {
    if s.len() <= MAX_NAME {
        return s.to_owned();
    }
    let mut end = MAX_NAME;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or_default().to_owned()
}

/// The virtual lab's readings: 16 CPUs, 32 GiB, a 64 GB disk, eight ports,
/// a few sensors and processes, moving on slow deterministic waves of the
/// time (so a test can count on them and the GUI looks alive).
#[derive(Debug, Default)]
pub struct LabSampler {
    /// Readings taken; the time when the caller has no clock (+1 s each).
    n: u64,
    first_ms: Option<u64>,
    cores: Vec<CpuTimes>,
    net: Vec<NetDev>,
    written: u64,
    /// CPU ticks of each lab process so far.
    procs: Vec<u64>,
    /// Seconds of the last reading.
    last_secs: u64,
}

const LAB_CPUS: usize = 16;
const LAB_MEM: u64 = 32 << 30;
const LAB_DISK: u64 = 64_000_000_000;
const LAB_PORTS: usize = 8;
/// (name, threads, rss MiB, share of the busy CPU in ‰).
const LAB_PROCS: &[(&str, u32, u64, u64)] = &[
    ("corerouter-daemon", 24, 180, 420),
    ("ksoftirqd/0", 1, 0, 160),
    ("ksoftirqd/1", 1, 0, 120),
    ("bgpd", 6, 410, 110),
    ("zebra", 4, 220, 60),
    ("ospfd", 3, 40, 30),
    ("accel-pppd", 12, 96, 50),
    ("chronyd", 1, 4, 5),
    ("sshd", 1, 8, 5),
    ("systemd", 1, 12, 10),
    ("kworker/u32:2", 1, 0, 20),
    ("rcu_preempt", 1, 0, 10),
];

impl LabSampler {
    pub fn new() -> Self {
        Self::default()
    }
}

/// A triangle wave of `t` with `period` going 0..=`amp` and back.
fn wave(t: u64, period: u64, amp: u64) -> u64 {
    let x = t % period.max(1);
    let half = (period / 2).max(1);
    amp * (if x < half { x } else { period - x }) / half
}

impl ResourceSampler for LabSampler {
    fn sample(&mut self, want: Want) -> Sample {
        self.n = self.n.saturating_add(1);
        let ms = match want.now_ms {
            Some(now) => {
                let first = *self.first_ms.get_or_insert(now.saturating_sub(1000));
                now.saturating_sub(first)
            }
            None => self.n.saturating_mul(1000),
        };
        let uptime_ms = 3 * 86_400_000 + 7_380_000 + ms;
        let t = uptime_ms / 1000;
        let hz = 100u64;
        if self.cores.is_empty() {
            self.cores = vec![CpuTimes::default(); LAB_CPUS];
            self.net = (1..=LAB_PORTS)
                .map(|i| NetDev {
                    name: format!("ether{i}"),
                    up: i <= 4,
                    speed_mbps: (i <= 4).then_some(if i <= 2 { 10_000 } else { 1000 }),
                    ..NetDev::default()
                })
                .collect();
            self.procs = vec![0; LAB_PROCS.len()];
        }
        // Ticks since the last reading.
        let elapsed = (ms / 1000).saturating_sub(self.last_secs).max(1);
        let span = hz * elapsed;
        // CPU 15..=45 %, core 0 busier (it takes the receive softirq).
        let load = 15 + wave(t, 600, 30);
        for (i, c) in self.cores.iter_mut().enumerate() {
            let pct = if i == 0 {
                (load + 20).min(95)
            } else {
                load.saturating_sub(i as u64 % 4)
            };
            let busy = span * pct / 100;
            let soft = busy / if i == 0 { 3 } else { 10 };
            let irq = busy / 40;
            let sys = busy / 4;
            c.user += busy.saturating_sub(soft + irq + sys);
            c.system += sys;
            c.softirq += soft;
            c.irq += irq;
            c.idle += span - busy;
        }
        let mut cpu = CpuTimes::default();
        for c in &self.cores {
            cpu.user += c.user;
            cpu.system += c.system;
            cpu.softirq += c.softirq;
            cpu.irq += c.irq;
            cpu.idle += c.idle;
        }
        let irqs = self
            .cores
            .iter()
            .enumerate()
            .map(|(i, c)| CpuIrqs {
                net_rx: c.softirq * if i == 0 { 9 } else { 2 },
                net_tx: c.softirq / 4,
                softirqs: c.softirq * 12,
                irqs: c.irq * 20,
            })
            .collect();
        for (i, d) in self.net.iter_mut().enumerate() {
            if !d.up {
                continue;
            }
            let mbps = d.speed_mbps.unwrap_or(1000) as u64;
            // 10..=60 % of the link, receive heavier than send.
            let rx = mbps * 125_000 * (10 + wave(t + 97 * i as u64, 900, 50)) / 100 * elapsed;
            let tx = rx / 3;
            d.rx_bytes += rx;
            d.tx_bytes += tx;
            d.rx_packets += rx / 800;
            d.tx_packets += tx / 600;
            if i == 3 {
                // One port with a bad cable: errors and drops climb.
                d.rx_errors += 2 * elapsed;
                d.rx_dropped += 15 * elapsed;
            }
        }
        self.written = self.written.saturating_add(2_000 * elapsed);
        let busy = span * load / 100 * LAB_CPUS as u64;
        for (p, (.., share)) in self.procs.iter_mut().zip(LAB_PROCS) {
            *p += busy * share / 1000;
        }
        self.last_secs = ms / 1000;
        let temp = 48.0 + wave(t, 1200, 140) as f64 / 10.0;
        let used = LAB_MEM / 2 - wave(t, 3600, 4 << 30);
        let all: Vec<Process> = LAB_PROCS
                .iter()
                .zip(&self.procs)
                .enumerate()
                .map(|(i, ((name, threads, rss, _), ticks))| Process {
                    pid: if i == 0 { 812 } else { 2 + 37 * i as u32 },
                    ppid: if i == 0 || name.starts_with('k') || name.starts_with('r') {
                        1
                    } else {
                        812
                    },
                    name: (*name).into(),
                    state: if i < 3 { 'R' } else { 'S' },
                    threads: *threads,
                    cpu_ticks: *ticks,
                    rss_bytes: rss << 20,
                    fds: Some(*threads * 3 + 4),
                })
                .collect();
        let router = all
            .iter()
            .filter(|p| p.name == DAEMON_PROCESS || ROUTER_PROCESSES.contains(&p.name.as_str()))
            .cloned()
            .collect();
        let processes = want.processes.then_some(all);
        Sample {
            uptime_ms,
            hz: hz as u32,
            cpu,
            cores: self.cores.clone(),
            core_mhz: (0..LAB_CPUS)
                .map(|i| 2400 + (wave(t + i as u64 * 13, 60, 800)) as u32)
                .collect(),
            max_mhz: Some(3800),
            cpu_model: Some("Virtual CPU (lab)".into()),
            board: Some("CoreRouter virtual lab".into()),
            load: Some(LoadAvg {
                one: (load as f32) * 0.16,
                five: (load as f32) * 0.14,
                fifteen: (load as f32) * 0.12,
                running: 2 + (load / 10) as u32,
                tasks: 412,
            }),
            memory: Memory {
                total: LAB_MEM,
                free: LAB_MEM - used - (6 << 30),
                available: LAB_MEM - used,
                buffers: 256 << 20,
                cached: 6 << 30,
                swap_total: 4 << 30,
                swap_free: (4 << 30) - (64 << 20),
            },
            pressure: Pressure {
                cpu: Some(Psi {
                    some10: (load as f32) / 20.0,
                    some60: (load as f32) / 25.0,
                    some300: (load as f32) / 30.0,
                    ..Psi::default()
                }),
                memory: Some(Psi {
                    full10: Some(0.0),
                    full60: Some(0.0),
                    full300: Some(0.0),
                    ..Psi::default()
                }),
                io: Some(Psi {
                    some10: 0.2,
                    some60: 0.1,
                    some300: 0.1,
                    full10: Some(0.1),
                    full60: Some(0.0),
                    full300: Some(0.0),
                }),
            },
            irqs,
            disks: vec![Disk {
                mount: "/".into(),
                device: "/dev/vda1".into(),
                fs: "ext4".into(),
                total: LAB_DISK,
                free: LAB_DISK * 58 / 100,
                available: LAB_DISK * 55 / 100,
            }],
            disk_io: vec![DiskIo {
                name: "vda".into(),
                read_sectors: 1_200_000,
                write_sectors: self.written,
            }],
            sensors: vec![
                Sensor {
                    chip: "coretemp".into(),
                    label: "Package".into(),
                    kind: SensorKind::Temperature,
                    value: temp,
                    max: Some(90.0),
                    crit: Some(100.0),
                },
                Sensor {
                    chip: "nvme".into(),
                    label: "Composite".into(),
                    kind: SensorKind::Temperature,
                    value: 38.0 + wave(t, 1800, 40) as f64 / 10.0,
                    max: Some(80.0),
                    crit: Some(85.0),
                },
                Sensor {
                    chip: "board".into(),
                    label: "fan1".into(),
                    kind: SensorKind::Fan,
                    value: (2200 + wave(t, 1200, 600)) as f64,
                    max: None,
                    crit: None,
                },
                Sensor {
                    chip: "board".into(),
                    label: "in0 (12V)".into(),
                    kind: SensorKind::Voltage,
                    value: 12.06,
                    max: None,
                    crit: None,
                },
            ],
            net: self.net.clone(),
            oom_kills: Some(0),
            swap_in: Some(310),
            swap_out: Some(1_024),
            conntrack: Some(200_000 + wave(t, 900, 80_000)),
            conntrack_max: Some(1 << 20),
            processes,
            router,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_readings_move_and_add_up() {
        let mut s = LabSampler::new();
        let a = s.sample(Want {
            processes: false,
            now_ms: Some(10_000),
        });
        let b = s.sample(Want {
            processes: true,
            now_ms: Some(15_000),
        });
        assert_eq!(b.uptime_ms - a.uptime_ms, 5_000);
        assert_eq!(b.cores.len(), 16);
        let dt = b.cpu.total() - a.cpu.total();
        assert_eq!(dt, 16 * 100 * 5, "16 CPUs × 100 Hz × 5 s");
        let busy = (b.cpu.busy() - a.cpu.busy()) * 100 / dt;
        assert!((10..=60).contains(&busy), "{busy}");
        assert!(a.processes.is_none());
        assert_eq!(b.processes.as_ref().map(Vec::len), Some(LAB_PROCS.len()));
        // G1.6qd: the router's own on every reading, the daemon first.
        let names: Vec<&str> = a.router.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["corerouter-daemon", "bgpd", "zebra", "ospfd"]);
        assert!(b.net[0].rx_bytes > a.net[0].rx_bytes);
        assert!(b.net[3].rx_errors > a.net[3].rx_errors);
        assert!(b.memory.available < b.memory.total);
    }

    #[test]
    fn lab_without_a_clock_moves_a_second_a_reading() {
        let mut s = LabSampler::new();
        let a = s.sample(Want::default());
        let b = s.sample(Want::default());
        assert_eq!(b.uptime_ms - a.uptime_ms, 1000);
    }

    #[test]
    fn names_are_cut_at_a_char_boundary() {
        let long = "é".repeat(MAX_NAME);
        let c = cut_name(&long);
        assert!(c.len() <= MAX_NAME);
        assert!(c.chars().all(|ch| ch == 'é'));
    }
}
