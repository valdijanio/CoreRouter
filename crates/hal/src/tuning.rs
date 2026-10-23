//! What System › Tuning (G1.26) reads from the platform: the machine
//! (CPUs, NUMA nodes, memory, kernel), the current value of the kernel
//! parameters of `corerouter_model::tuning::PARAMS`, and the counters that
//! say whether they are too small (softnet squeeze and drops, conntrack
//! fill, neighbor table overflows). Writing goes through `Hal::apply`, from
//! `Config::system.tuning`. Per-port data comes from `Hal::hardware` and
//! `Hal::counters`.

use std::collections::BTreeMap;

use serde::Serialize;

/// Bound on CPUs and NUMA nodes read from the platform (a hostile or
/// broken `/sys` cannot make a list without end).
pub const MAX_CPUS: usize = 4096;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NumaNode {
    pub id: u32,
    pub cpus: Vec<u32>,
    pub mem_kib: Option<u64>,
}

/// The machine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SystemInfo {
    /// Online CPUs.
    pub cpus: u32,
    pub cpu_model: Option<String>,
    /// Empty: no NUMA information (one node).
    pub numa: Vec<NumaNode>,
    pub mem_kib: u64,
    /// Kernel release (`6.8.0-45-generic`).
    pub kernel: String,
}

impl SystemInfo {
    /// `(major, minor)` of the kernel release.
    pub fn kernel_version(&self) -> Option<(u32, u32)> {
        let mut it = self.kernel.split(['.', '-']);
        let major = it.next()?.parse().ok()?;
        let minor = it.next()?.parse().ok()?;
        Some((major, minor))
    }
}

/// One CPU's line of `/proc/net/softnet_stat`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SoftnetCpu {
    pub cpu: u32,
    /// Packets taken from the backlog / NAPI.
    pub processed: u64,
    /// Dropped: the backlog (`netdev_max_backlog`) was full.
    pub dropped: u64,
    /// The receive softirq ran out of `netdev_budget` or
    /// `netdev_budget_usecs` with work left.
    pub time_squeeze: u64,
}

/// Counters behind the tuning diagnosis, all since boot.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct KernelStats {
    pub softnet: Vec<SoftnetCpu>,
    /// Entries in the conntrack table now; `None`: conntrack not loaded.
    pub conntrack_count: Option<u64>,
    /// Times the IPv4 / IPv6 neighbor table was full (`table_fulls` of
    /// `/proc/net/stat/arp_cache`, `ndisc_cache`).
    pub neigh_full_v4: Option<u64>,
    pub neigh_full_v6: Option<u64>,
}

/// The current value of each asked kernel parameter; `None`: this kernel
/// (or namespace) does not have it, or conntrack is not loaded.
pub type Sysctls = BTreeMap<String, Option<i64>>;

/// Parse `/proc/net/softnet_stat`: one line per CPU, hex columns; the 13th
/// (`cpu id`, Linux 5.10+) names the CPU, else the line number does.
pub fn parse_softnet(text: &str) -> Vec<SoftnetCpu> {
    text.lines()
        .take(MAX_CPUS)
        .enumerate()
        .filter_map(|(i, line)| {
            let cols: Vec<u64> = line
                .split_whitespace()
                .map(|c| u64::from_str_radix(c, 16))
                .collect::<Result<_, _>>()
                .ok()?;
            let col = |n: usize| cols.get(n).copied();
            Some(SoftnetCpu {
                cpu: col(12)
                    .and_then(|c| u32::try_from(c).ok())
                    .unwrap_or_else(|| u32::try_from(i).unwrap_or(u32::MAX)),
                processed: col(0)?,
                dropped: col(1)?,
                time_squeeze: col(2)?,
            })
        })
        .collect()
}

/// Sum of the `table_fulls` column of `/proc/net/stat/{arp,ndisc}_cache`
/// (a header line naming the columns, then one hex line per CPU).
pub fn parse_neigh_table_fulls(text: &str) -> Option<u64> {
    let mut lines = text.lines();
    let col = lines
        .next()?
        .split_whitespace()
        .position(|h| h == "table_fulls")?;
    let mut total: u64 = 0;
    for line in lines.take(MAX_CPUS) {
        let v = line.split_whitespace().nth(col)?;
        total = total.saturating_add(u64::from_str_radix(v, 16).ok()?);
    }
    Some(total)
}

/// CPU list syntax of `/sys` (`0-3,8,10-11`), bounded.
pub fn parse_cpu_list(text: &str) -> Vec<u32> {
    let mut out = Vec::new();
    for part in text.trim().split(',').filter(|p| !p.is_empty()) {
        let (a, b) = part.split_once('-').unwrap_or((part, part));
        let (Ok(a), Ok(b)) = (a.trim().parse::<u32>(), b.trim().parse::<u32>()) else {
            continue;
        };
        for c in a..=b {
            if out.len() >= MAX_CPUS {
                return out;
            }
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn softnet_lines() {
        // Linux 6.x: 13 columns, the 13th is the CPU id.
        let text = "0001e240 00000002 00000010 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000\n\
                    000000ff 00000000 00000003 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000005 00000000 00000000\n\
                    garbage\n";
        let s = parse_softnet(text);
        assert_eq!(s.len(), 2);
        assert_eq!(
            s[0],
            SoftnetCpu {
                cpu: 0,
                processed: 123_456,
                dropped: 2,
                time_squeeze: 16
            }
        );
        assert_eq!(
            s[1].cpu, 5,
            "offline CPUs are skipped: the id column says which"
        );
        // An old kernel without the CPU column: the line number.
        let old = parse_softnet("0000000a 00000000 00000001\n0000000b 00000000 00000000\n");
        assert_eq!(old[1].cpu, 1);
    }

    #[test]
    fn neigh_fulls_and_cpu_lists() {
        let text = "entries  allocs   destroys hash_grows lookups  hits     res_failed rcv_probes_mcast rcv_probes_ucast periodic_gc_runs forced_gc_runs unresolved_discards table_fulls\n\
                    00000004 00000010 00000000 00000000 00000020 00000010 00000000 00000000 00000000 00000005 00000000 00000000 00000002\n\
                    00000004 00000010 00000000 00000000 00000020 00000010 00000000 00000000 00000000 00000005 00000000 00000000 0000000a\n";
        assert_eq!(parse_neigh_table_fulls(text), Some(12));
        assert_eq!(parse_neigh_table_fulls("nothing here"), None);
        assert_eq!(parse_cpu_list("0-3,8,10-11\n"), [0, 1, 2, 3, 8, 10, 11]);
        assert_eq!(parse_cpu_list("x,2-a,7"), [7]);
        assert_eq!(parse_cpu_list("0-4294967295").len(), MAX_CPUS);
        let si = SystemInfo {
            kernel: "6.8.0-45-generic".into(),
            ..SystemInfo::default()
        };
        assert_eq!(si.kernel_version(), Some((6, 8)));
    }
}
