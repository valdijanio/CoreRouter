//! System › Resources (G4.8a): the last two readings of the machine
//! (`corerouter_hal::system_resource::Sample`), what they mean (CPU load
//! per core, rates of the disks and links, CPU of each process) and a short
//! history for the sparklines. Run-time state in `Session::ext`.
//!
//! Who reads the machine:
//!
//! - in the daemon, the `health` service, every 5 s (every second while
//!   someone looks: [`ResourceMonitor::wanted`]), with its own sampler and
//!   without the session lock; it hands the reading to
//!   [`Session::resource_ingest`], which only does arithmetic;
//! - without a daemon (lab, browser, tests), the commands themselves, with
//!   a sampler from the `Hal`, when the last reading is older than a second.
//!
//! Readings from two samplers are never subtracted from each other: a new
//! source starts the rates over.

use std::collections::{BTreeMap, VecDeque};

use corerouter_hal::system_resource::{
    CpuTimes, Process, ResourceSampler, Sample, SensorKind, Want,
};

use crate::Session;

/// Points of the sparkline history, one each [`HISTORY_STEP_MS`]: 10 min.
pub const HISTORY: usize = 120;
pub const HISTORY_STEP_MS: u64 = 5_000;
/// Two readings closer than this give no rate (noise).
const MIN_DT_MS: u64 = 200;
/// Seconds a command's interest keeps the service at one reading a second.
pub const WANTED_SECS: u64 = 15;
/// A process list older than this (ms of uptime before the last reading)
/// is not served while the service catches up (G1.6q).
const PROCS_STALE_MS: u64 = 2_000;
/// A scrape of `system.metrics` takes the service's reading up to this old
/// (s; it reads every 5 s) instead of reading under the lock (G1.6qd).
pub const METRICS_STALE_SECS: u64 = 15;

/// Where a reading came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The commands' own sampler (no daemon).
    Inline,
    /// The daemon's `health` service.
    Service,
}

/// One point of the history.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
pub struct Point {
    /// Seconds of uptime.
    pub t: u64,
    /// CPU load, %.
    pub cpu: Option<f32>,
    /// Memory in use (total − available), %.
    pub memory: Option<f32>,
    /// The hottest temperature sensor, °C.
    pub temperature: Option<f32>,
}

/// The state of System › Resources.
#[derive(Default)]
pub struct ResourceMonitor {
    sampler: Option<Box<dyn ResourceSampler>>,
    /// Why there are no readings (the `Hal` has no sampler).
    pub unavailable: Option<String>,
    pub prev: Option<Sample>,
    pub last: Option<Sample>,
    source: Option<Source>,
    /// Engine clock (s) of the last reading; `None`: no clock.
    taken_at: Option<u64>,
    pub history: VecDeque<Point>,
    /// The two last process lists: (uptime ms, list).
    procs_prev: Option<(u64, BTreeMap<u32, u64>)>,
    pub procs_last: Option<(u64, Vec<Process>)>,
    /// Engine clock (s) until which someone wants fast readings, and
    /// processes.
    wanted_until: u64,
    procs_until: u64,
}

impl std::fmt::Debug for ResourceMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceMonitor")
            .field("readings", &self.last.is_some())
            .field("history", &self.history.len())
            .finish()
    }
}

/// What the service should read next.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Wanted {
    /// Someone looks: read every second, not every five.
    pub fast: bool,
    pub processes: bool,
}

/// `100 × part / whole`, `None` when `whole` is 0.
pub fn percent(part: u64, whole: u64) -> Option<f32> {
    (whole > 0).then(|| (part as f64 * 100.0 / whole as f64) as f32)
}

/// Load of one CPU between two readings, by kind, %.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct Load {
    pub load: f32,
    pub user: f32,
    pub system: f32,
    pub irq: f32,
    pub softirq: f32,
    pub iowait: f32,
    pub steal: f32,
}

pub fn load(a: &CpuTimes, b: &CpuTimes) -> Option<Load> {
    let total = b.total().checked_sub(a.total()).filter(|t| *t > 0)?;
    let d = |x: u64, y: u64| percent(y.saturating_sub(x), total).unwrap_or(0.0);
    Some(Load {
        load: d(a.busy(), b.busy()).min(100.0),
        user: d(a.user.saturating_add(a.nice), b.user.saturating_add(b.nice)),
        system: d(a.system, b.system),
        irq: d(a.irq, b.irq),
        softirq: d(a.softirq, b.softirq),
        iowait: d(a.iowait, b.iowait),
        steal: d(a.steal, b.steal),
    })
}

/// Memory in use, % (what programs cannot get back: total − available).
pub fn memory_used(s: &Sample) -> Option<f32> {
    let m = &s.memory;
    percent(m.total.saturating_sub(m.available), m.total)
}

/// The hottest temperature sensor: (value, crit, "chip label").
pub fn hottest(s: &Sample) -> Option<(f64, Option<f64>, String)> {
    s.sensors
        .iter()
        .filter(|x| x.kind == SensorKind::Temperature)
        .max_by(|a, b| a.value.total_cmp(&b.value))
        .map(|x| (x.value, x.crit, format!("{} {}", x.chip, x.label)))
}

/// Degrees below `crit` where a temperature turns to warning, and to
/// error (the hardware throttles or shuts down at `crit`).
pub const TEMP_WARN_BELOW_CRIT: f64 = 10.0;
pub const TEMP_ERROR_BELOW_CRIT: f64 = 3.0;

/// How a sensor reads against its limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Warning,
    Error,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// A sensor's level: temperatures against `crit` (and `max`); other kinds
/// have no limits from the drivers, so they are always ok.
pub fn sensor_level(s: &corerouter_hal::system_resource::Sensor) -> Level {
    if s.kind != SensorKind::Temperature {
        return Level::Ok;
    }
    match (s.crit, s.max) {
        (Some(c), _) if s.value >= c - TEMP_ERROR_BELOW_CRIT => Level::Error,
        (Some(c), _) if s.value >= c - TEMP_WARN_BELOW_CRIT => Level::Warning,
        (_, Some(m)) if s.value >= m => Level::Warning,
        _ => Level::Ok,
    }
}

impl ResourceMonitor {
    /// The previous and last readings, when far enough apart for rates.
    pub fn pair(&self) -> Option<(&Sample, &Sample, f64)> {
        let (a, b) = (self.prev.as_ref()?, self.last.as_ref()?);
        let dt = b.uptime_ms.checked_sub(a.uptime_ms).filter(|d| *d >= MIN_DT_MS)?;
        Some((a, b, dt as f64 / 1000.0))
    }

    /// Per second of `f` between the two readings; `None` without a pair
    /// or when the counter went down (a reset).
    pub fn rate(&self, f: impl Fn(&Sample) -> Option<u64>) -> Option<f64> {
        let (a, b, dt) = self.pair()?;
        let d = f(b)?.checked_sub(f(a)?)?;
        Some(d as f64 / dt)
    }

    /// CPU load of all CPUs between the two readings.
    pub fn cpu(&self) -> Option<Load> {
        let (a, b, _) = self.pair()?;
        load(&a.cpu, &b.cpu)
    }

    /// The service's next reading.
    pub fn wanted(&self, now: Option<u64>) -> Wanted {
        let now = now.unwrap_or(0);
        Wanted {
            fast: now < self.wanted_until,
            processes: now < self.procs_until,
        }
    }

    /// CPU % of each process of the last list (of the whole machine, like
    /// RouterOS `/tool profile`); `None` for one not in the previous list.
    pub fn process_cpu(&self) -> BTreeMap<u32, f32> {
        let (Some((t0, prev)), Some((t1, now))) = (&self.procs_prev, &self.procs_last) else {
            return BTreeMap::new();
        };
        let Some(dt) = t1.checked_sub(*t0).filter(|d| *d >= MIN_DT_MS) else {
            return BTreeMap::new();
        };
        let (hz, cpus) = self
            .last
            .as_ref()
            .map(|s| (u64::from(s.hz.max(1)), s.cores.len().max(1) as u64))
            .unwrap_or((100, 1));
        // Ticks the whole machine had in `dt`.
        let capacity = dt as f64 / 1000.0 * hz as f64 * cpus as f64;
        now.iter()
            .filter_map(|p| {
                let before = prev.get(&p.pid)?;
                let used = p.cpu_ticks.checked_sub(*before)?;
                Some((p.pid, ((used as f64 * 100.0 / capacity) as f32).min(100.0)))
            })
            .collect()
    }

    /// G1.6qe: CPU of the router's processes between the two readings: of
    /// each process in % of the whole machine (as [`Self::process_cpu`]),
    /// and of each of its threads in % of **one** CPU (a thread at 100 %
    /// is a full core: work serialized on it). `None` for one that was not
    /// in the previous reading.
    pub fn router_cpu(&self) -> (BTreeMap<u32, f32>, BTreeMap<(u32, u32), f32>) {
        let (mut procs, mut tasks) = (BTreeMap::new(), BTreeMap::new());
        let Some((a, b, dt)) = self.pair() else {
            return (procs, tasks);
        };
        let hz = f64::from(b.hz.max(1));
        let one = dt * hz;
        let all = one * b.cores.len().max(1) as f64;
        for p in &b.router {
            let Some(before) = a.router.iter().find(|x| x.pid == p.pid) else {
                continue;
            };
            if let Some(used) = p.cpu_ticks.checked_sub(before.cpu_ticks) {
                procs.insert(p.pid, ((used as f64 * 100.0 / all) as f32).min(100.0));
            }
            for t in &p.tasks {
                // Sorted by tid (`Process::tasks`): O(log n) per thread.
                let Ok(i) = before.tasks.binary_search_by_key(&t.tid, |x| x.tid) else {
                    continue;
                };
                let Some(t0) = before.tasks.get(i) else {
                    continue;
                };
                if let Some(used) = t.cpu_ticks.checked_sub(t0.cpu_ticks) {
                    tasks.insert((p.pid, t.tid), ((used as f64 * 100.0 / one) as f32).min(100.0));
                }
            }
        }
        (procs, tasks)
    }

    fn push(&mut self, sample: Sample, source: Source, now: Option<u64>) {
        if self.source != Some(source) {
            // Another sampler's counters: no rates across the switch.
            self.last = None;
            self.procs_last = None;
        }
        self.source = Some(source);
        self.taken_at = now;
        if let Some(list) = &sample.processes {
            self.procs_prev = self
                .procs_last
                .take()
                .map(|(t, l)| (t, l.iter().map(|p| (p.pid, p.cpu_ticks)).collect()));
            self.procs_last = Some((sample.uptime_ms, list.clone()));
        }
        self.prev = self.last.take();
        self.last = Some(sample);
        let Some(last) = &self.last else { return };
        let t = last.uptime_ms / 1000;
        let step = HISTORY_STEP_MS / 1000;
        let due = self.history.back().is_none_or(|p| t >= p.t + step || t < p.t);
        if due {
            let point = Point {
                t,
                cpu: self.cpu().map(|l| l.load),
                memory: memory_used(last),
                temperature: hottest(last).map(|h| h.0 as f32),
            };
            if self.history.len() >= HISTORY {
                self.history.pop_front();
            }
            self.history.push_back(point);
        }
    }

    /// The history at an even pace, newest last (`n` points at most).
    pub fn recent(&self, n: usize) -> Vec<Point> {
        let skip = self.history.len().saturating_sub(n);
        self.history.iter().skip(skip).copied().collect()
    }
}

impl Session {
    /// A reading from the daemon's `health` service (taken outside the
    /// lock). Only arithmetic happens here.
    pub fn resource_ingest(&mut self, sample: Sample) {
        let now = self.clock_secs();
        if let Some(m) = self.ext_mut::<ResourceMonitor>() {
            m.push(sample, Source::Service, now);
        }
    }

    /// A sampler of its own for the daemon's `health` service, which reads
    /// with it outside the lock.
    pub fn resource_sampler(&self) -> std::result::Result<Box<dyn ResourceSampler>, String> {
        self.hal().resource_sampler()
    }

    /// What the service should read next (someone asked lately?).
    pub fn resource_wanted(&mut self) -> Wanted {
        let now = self.clock_secs();
        self.ext::<ResourceMonitor>()
            .map(|m| m.wanted(now))
            .unwrap_or_default()
    }

    /// The readings for a scrape (G1.6qd): the service's while recent
    /// enough ([`METRICS_STALE_SECS`]), else fresh ones without marking
    /// them as watched. `None`: the platform has no readings.
    pub(crate) fn resource_for_metrics(&mut self) -> Option<&ResourceMonitor> {
        let now = self.clock_secs();
        let recent = self.ext::<ResourceMonitor>().is_some_and(|m| {
            m.last.is_some()
                && m.source == Some(Source::Service)
                && matches!((now, m.taken_at), (Some(n), Some(t)) if n.saturating_sub(t) <= METRICS_STALE_SECS)
        });
        if !recent {
            self.resource_refresh(false, false).ok()?;
        }
        self.ext::<ResourceMonitor>().filter(|m| m.last.is_some())
    }

    fn clock_secs(&self) -> Option<u64> {
        self.hal().monotonic_secs().or_else(|| self.now())
    }

    /// Make sure the readings are fresh for a command, reading inline when
    /// no service keeps them so; and tell the service someone looks.
    /// `looking`: someone watches (a window, the readout): the service
    /// goes to one reading a second for [`WANTED_SECS`]. The top bar's
    /// health chip asks without looking.
    pub(crate) fn resource_refresh(
        &mut self,
        processes: bool,
        looking: bool,
    ) -> std::result::Result<(), String> {
        let now = self.clock_secs();
        let sampler = match self.ext::<ResourceMonitor>() {
            Some(m) if m.sampler.is_some() || m.unavailable.is_some() => None,
            _ => Some(self.hal().resource_sampler()),
        };
        let Some(m) = self.ext_mut::<ResourceMonitor>() else {
            return Err("system resources: no state".into());
        };
        match sampler {
            Some(Ok(s)) => m.sampler = Some(s),
            Some(Err(why)) => m.unavailable = Some(why),
            None => {}
        }
        if let Some(now) = now.filter(|_| looking) {
            m.wanted_until = now + WANTED_SECS;
            if processes {
                m.procs_until = now + WANTED_SECS;
            }
        }
        // The service's reading is fresh enough (it reads every second
        // while someone looks).
        let age = match (now, m.taken_at) {
            (Some(n), Some(t)) => Some(n.saturating_sub(t)),
            _ => None,
        };
        let fresh = match m.source {
            Some(Source::Service) => age.is_some_and(|a| a <= 2),
            Some(Source::Inline) => age.is_some_and(|a| a < 1),
            None => false,
        };
        let have_procs = !processes
            || m.procs_last.as_ref().is_some_and(|(t, _)| {
                m.last.as_ref().is_some_and(|l| l.uptime_ms == *t)
            });
        if fresh && have_procs && m.last.is_some() {
            return Ok(());
        }
        // The service adds the processes on its next reading; until then a
        // list of the last second or two is good enough. With none (a
        // one-shot CLI/MCP call, G1.6q) or an old one, read now.
        let procs_recent = !processes
            || m.procs_last.as_ref().is_some_and(|(t, _)| {
                m.last
                    .as_ref()
                    .is_some_and(|l| l.uptime_ms.saturating_sub(*t) <= PROCS_STALE_MS)
            });
        if m.source == Some(Source::Service) && age.is_some_and(|a| a <= 2) && procs_recent {
            return Ok(());
        }
        let Some(sampler) = m.sampler.as_mut() else {
            return Err(m.unavailable.clone().unwrap_or_else(|| "no readings".into()));
        };
        let want = Want {
            processes,
            now_ms: now.map(|n| n.saturating_mul(1000)),
        };
        let first = m.last.is_none() || m.source != Some(Source::Inline);
        let sample = sampler.sample(want);
        m.push(sample, Source::Inline, now);
        if first && now.is_none() {
            // No clock (the lab): a second reading gives the rates now.
            if let Some(sampler) = m.sampler.as_mut() {
                let sample = sampler.sample(want);
                m.push(sample, Source::Inline, now);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_hal::system_resource::LabSampler;

    #[test]
    fn loads_rates_and_history() {
        let mut m = ResourceMonitor::default();
        let mut lab = LabSampler::new();
        assert!(m.cpu().is_none());
        for i in 0..30 {
            let s = lab.sample(Want {
                processes: i % 2 == 0,
                now_ms: Some(i * 1000),
            });
            m.push(s, Source::Service, Some(i));
        }
        let cpu = m.cpu().unwrap();
        assert!((10.0..=70.0).contains(&cpu.load), "{cpu:?}");
        assert!(cpu.softirq > 0.0);
        let rx = m.rate(|s| s.net.first().map(|n| n.rx_bytes)).unwrap();
        assert!(rx > 1e8, "{rx}");
        // One point every 5 s.
        assert_eq!(m.history.len(), 6, "{:?}", m.history);
        assert!(m.history.iter().skip(1).all(|p| p.cpu.is_some()));
        let procs = m.process_cpu();
        assert!(!procs.is_empty());
        assert!(procs.values().all(|c| (0.0..=100.0).contains(c)));
    }

    #[test]
    fn a_new_source_starts_the_rates_over() {
        let mut m = ResourceMonitor::default();
        let mut a = LabSampler::new();
        let mut b = LabSampler::new();
        m.push(a.sample(Want { processes: false, now_ms: Some(0) }), Source::Service, Some(0));
        m.push(a.sample(Want { processes: false, now_ms: Some(5000) }), Source::Service, Some(5));
        assert!(m.cpu().is_some());
        m.push(b.sample(Want::default()), Source::Inline, Some(6));
        assert!(m.cpu().is_none(), "never subtract two samplers' counters");
    }

    #[test]
    fn readings_too_close_give_no_rate() {
        let mut m = ResourceMonitor::default();
        let mut lab = LabSampler::new();
        m.push(lab.sample(Want { processes: false, now_ms: Some(1000) }), Source::Service, None);
        m.push(lab.sample(Want { processes: false, now_ms: Some(1050) }), Source::Service, None);
        assert!(m.pair().is_none());
    }
}
