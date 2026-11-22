//! CPU, memory and connection-tracking readings for the traffic graphs
//! (G4.5, RouterOS `/tool graphing resource`): cheap enough to take every
//! second, raw counters only (the engine turns two readings into a load).

use serde::Serialize;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Resources {
    /// CPU time spent busy (everything but idle and iowait) and in all,
    /// summed over CPUs, in any steady unit (Linux: clock ticks of
    /// `/proc/stat`). Two readings give the load.
    pub cpu_busy: u64,
    pub cpu_total: u64,
    /// Bytes of memory in all and available to programs (Linux
    /// `MemAvailable`).
    pub mem_total: u64,
    pub mem_available: u64,
    /// Entries in the conntrack table now; `None`: no conntrack here.
    pub conntrack: Option<u64>,
    pub conntrack_max: Option<u64>,
}

/// Busy and total ticks of the `cpu` line of `/proc/stat`
/// (`user nice system idle iowait irq softirq steal …`; guest time is
/// already inside user and nice).
pub fn parse_proc_stat(text: &str) -> Option<(u64, u64)> {
    let line = text.lines().find(|l| l.starts_with("cpu "))?;
    let v: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .map(|f| f.parse().unwrap_or(0))
        .collect();
    let total: u64 = v.iter().fold(0u64, |a, b| a.saturating_add(*b));
    let idle = v
        .get(3)
        .copied()
        .unwrap_or(0)
        .saturating_add(v.get(4).copied().unwrap_or(0));
    Some((total.saturating_sub(idle), total))
}

/// `MemTotal` and `MemAvailable` of `/proc/meminfo`, in bytes.
pub fn parse_meminfo(text: &str) -> Option<(u64, u64)> {
    let field = |key: &str| -> Option<u64> {
        let kib: u64 = text
            .lines()
            .find_map(|l| l.strip_prefix(key))?
            .split_whitespace()
            .next()?
            .parse()
            .ok()?;
        Some(kib.saturating_mul(1024))
    };
    Some((field("MemTotal:")?, field("MemAvailable:")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_stat_busy_leaves_out_idle_and_iowait() {
        let t = "cpu  100 5 50 1000 20 3 7 0 0 0\ncpu0 1 2 3 4 5 6 7 8\n";
        assert_eq!(parse_proc_stat(t), Some((165, 1185)));
        assert_eq!(parse_proc_stat("intr 1 2"), None);
        assert_eq!(
            parse_proc_stat("cpu  x y"),
            Some((0, 0)),
            "garbage reads as zero"
        );
    }

    #[test]
    fn meminfo_in_bytes() {
        let t = "MemTotal:       16000 kB\nMemFree:  10 kB\nMemAvailable:   8000 kB\n";
        assert_eq!(parse_meminfo(t), Some((16000 * 1024, 8000 * 1024)));
        assert_eq!(parse_meminfo("MemTotal: 5 kB\n"), None);
    }
}
