//! System › Tuning (G1.26) on Linux: plain file I/O on `/proc` and `/sys`,
//! no `sysctl`, `tuned` or `irqbalance`.
//!
//! - kernel parameters: `/proc/sys/<name with / for .>`; the first change
//!   of a name snapshots the value the kernel had, so taking it out of the
//!   config writes that value back (like the Ethernet settings, G1.20);
//! - the machine: `/sys/devices/system/{cpu,node}`, `/proc/meminfo`,
//!   `/proc/cpuinfo`, `kernel.osrelease`;
//! - the diagnosis: `/proc/net/softnet_stat`, `nf_conntrack_count`,
//!   `/proc/net/stat/{arp,ndisc}_cache`.
//!
//! Paths hang off a [`Root`], so the parsing and the all-or-nothing writes
//! are tested on a scratch directory.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use corerouter_hal::HalError;
use corerouter_hal::tuning::{
    self, KernelStats, MAX_CPUS, NumaNode, Sysctls, SystemInfo, parse_cpu_list,
};
use corerouter_model::tuning::{param, proc_path};

/// Written before every other parameter (see [`Sysctl::transition`]).
const FORWARDING: [&str; 2] = ["net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"];

/// Largest `/proc` or `/sys` file read (softnet_stat of 4096 CPUs is
/// ~600 KiB; anything bigger is not what we think it is).
const MAX_FILE: u64 = 1 << 20;

/// Where `/proc`, `/sys` and `/dev` are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    pub proc: PathBuf,
    pub sys: PathBuf,
    /// `/dev` (PM QoS and watchdog devices, G1.26c).
    pub dev: PathBuf,
}

impl Default for Root {
    fn default() -> Self {
        Self {
            proc: "/proc".into(),
            sys: "/sys".into(),
            dev: "/dev".into(),
        }
    }
}

fn read(path: &Path) -> Option<String> {
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_FILE)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

impl Root {
    fn sysctl_path(&self, name: &str) -> Option<PathBuf> {
        // Catalog names only: never a path the caller made up.
        param(name)?;
        Some(self.proc.join("sys").join(proc_path(name)))
    }

    /// The value of kernel parameter `name`, if this kernel has it.
    pub fn sysctl(&self, name: &str) -> Option<i64> {
        read(&self.sysctl_path(name)?)?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    }

    pub fn sysctls(&self, names: &[&str]) -> Sysctls {
        names
            .iter()
            .map(|n| ((*n).to_owned(), self.sysctl(n)))
            .collect()
    }

    fn write_sysctl(&self, name: &str, value: i64) -> Result<(), HalError> {
        let path = self
            .sysctl_path(name)
            .ok_or_else(|| HalError::Rejected(format!("unknown kernel parameter {name}")))?;
        if !path.exists() {
            let why = if corerouter_model::tuning::is_conntrack(name) {
                "connection tracking is not loaded"
            } else {
                "this kernel or network namespace does not have it"
            };
            return Err(HalError::Rejected(format!("{name}: {why}")));
        }
        std::fs::write(&path, format!("{value}\n")).map_err(|e| {
            let why = if e.kind() == std::io::ErrorKind::PermissionDenied {
                "read-only here (a container, or a network namespace other than the host's)"
                    .to_owned()
            } else {
                e.to_string()
            };
            HalError::Rejected(format!("{name} = {value}: {why}"))
        })?;
        // The kernel may clamp or ignore a value without an error.
        match self.sysctl(name) {
            Some(now) if now == value => Ok(()),
            now => Err(HalError::Rejected(format!(
                "{name}: the kernel kept {} instead of {value}",
                now.map_or_else(|| "nothing".into(), |v| v.to_string())
            ))),
        }
    }

    /// The machine.
    pub fn system_info(&self) -> SystemInfo {
        let cpu = self.sys.join("devices/system/cpu");
        let online = read(&cpu.join("online"))
            .map(|t| parse_cpu_list(&t))
            .unwrap_or_default();
        let cpu_model = read(&self.proc.join("cpuinfo")).and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, m)| m.trim().chars().take(128).collect())
        });
        let mem_kib = read(&self.proc.join("meminfo"))
            .and_then(|t| mem_total(&t, "MemTotal:"))
            .unwrap_or(0);
        let node_dir = self.sys.join("devices/system/node");
        let numa = read(&node_dir.join("online"))
            .map(|t| parse_cpu_list(&t))
            .unwrap_or_default()
            .into_iter()
            .take(MAX_CPUS)
            .map(|id| {
                let d = node_dir.join(format!("node{id}"));
                NumaNode {
                    id,
                    cpus: read(&d.join("cpulist"))
                        .map(|t| parse_cpu_list(&t))
                        .unwrap_or_default(),
                    mem_kib: read(&d.join("meminfo")).and_then(|t| {
                        t.lines().find_map(|l| {
                            let (_, rest) = l.split_once("MemTotal:")?;
                            rest.split_whitespace().next()?.parse().ok()
                        })
                    }),
                }
            })
            .collect();
        SystemInfo {
            cpus: u32::try_from(online.len()).unwrap_or(u32::MAX),
            cpu_model,
            numa,
            mem_kib,
            kernel: read(&self.proc.join("sys/kernel/osrelease"))
                .map(|t| t.trim().chars().take(64).collect())
                .unwrap_or_default(),
        }
    }

    /// The kernel command line the system booted with (G1.26d).
    pub fn cmdline(&self) -> Option<String> {
        read(&self.proc.join("cmdline")).map(|t| t.trim().chars().take(4096).collect())
    }

    /// The diagnosis counters.
    pub fn kernel_stats(&self) -> KernelStats {
        let net = self.proc.join("net");
        KernelStats {
            softnet: read(&net.join("softnet_stat"))
                .map(|t| tuning::parse_softnet(&t))
                .unwrap_or_default(),
            conntrack_count: read(&self.proc.join("sys/net/netfilter/nf_conntrack_count"))
                .and_then(|t| t.trim().parse().ok()),
            neigh_full_v4: read(&net.join("stat/arp_cache"))
                .and_then(|t| tuning::parse_neigh_table_fulls(&t)),
            neigh_full_v6: read(&net.join("stat/ndisc_cache"))
                .and_then(|t| tuning::parse_neigh_table_fulls(&t)),
        }
    }
}

impl Root {
    /// CPU, memory and conntrack readings for the graphs (G4.5): four
    /// small `/proc` files, read every second.
    pub fn resources(&self) -> corerouter_hal::resources::Resources {
        use corerouter_hal::resources::{Resources, parse_meminfo, parse_proc_stat};
        let (cpu_busy, cpu_total) = read(&self.proc.join("stat"))
            .and_then(|t| parse_proc_stat(&t))
            .unwrap_or_default();
        let (mem_total, mem_available) = read(&self.proc.join("meminfo"))
            .and_then(|t| parse_meminfo(&t))
            .unwrap_or_default();
        let ct = |f: &str| {
            read(&self.proc.join("sys/net/netfilter").join(f)).and_then(|t| t.trim().parse().ok())
        };
        Resources {
            cpu_busy,
            cpu_total,
            mem_total,
            mem_available,
            conntrack: ct("nf_conntrack_count"),
            conntrack_max: ct("nf_conntrack_max"),
        }
    }
}

fn mem_total(text: &str, key: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix(key))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// The kernel parameters CoreRouter changed, with the value each had
/// before its first change.
#[derive(Debug, Default)]
pub struct Sysctl {
    pub root: Root,
    orig: BTreeMap<String, i64>,
}

impl Sysctl {
    pub fn new(root: Root) -> Self {
        Self {
            root,
            orig: BTreeMap::new(),
        }
    }

    /// Bring the kernel from `from` to `to`, all or nothing: on a failure
    /// the parameters written so far go back.
    pub fn transition(
        &mut self,
        from: &BTreeMap<String, i64>,
        to: &BTreeMap<String, i64>,
    ) -> Result<(), HalError> {
        let mut done: Vec<(String, i64)> = Vec::new();
        let mut wanted: Vec<(&String, Option<i64>)> = to
            .iter()
            .filter(|(n, v)| from.get(*n) != Some(*v))
            .map(|(n, v)| (n, Some(*v)))
            .collect();
        wanted.extend(
            from.keys()
                .filter(|n| !to.contains_key(*n))
                .map(|n| (n, None)),
        );
        // ip-sysctl.rst: changing `ip_forward` resets the configuration
        // parameters to the host or router defaults, so forwarding goes
        // first and the rest is written over it.
        wanted.sort_by_key(|(n, _)| !FORWARDING.contains(&n.as_str()));
        for (name, want) in wanted {
            let now = self.root.sysctl(name);
            let target = match want {
                Some(v) => v,
                // Taken out: back to what the kernel had; never known
                // (the config came from disk at boot) = leave it.
                None => match self.orig.get(name) {
                    Some(v) => *v,
                    None => continue,
                },
            };
            if now == Some(target) {
                if want.is_none() {
                    self.orig.remove(name);
                }
                continue;
            }
            let res = self.root.write_sysctl(name, target);
            if let Err(e) = res {
                for (n, back) in done.iter().rev() {
                    if let Err(b) = self.root.write_sysctl(n, *back) {
                        log::error!("restoring {n}: {b}");
                    }
                }
                return Err(e);
            }
            if let Some(was) = now {
                done.push((name.clone(), was));
                if want.is_some() {
                    self.orig.entry(name.clone()).or_insert(was);
                } else {
                    self.orig.remove(name);
                }
            }
            log::info!("tuning: {name} = {target}");
        }
        Ok(())
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
        let dir =
            std::env::temp_dir().join(format!("corerouter-tuning-{tag}-{}", std::process::id()));
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
    fn reads_the_machine() {
        let (_s, r) = scratch("machine");
        put(&r.sys.join("devices/system/cpu/online"), "0-7\n");
        put(&r.sys.join("devices/system/node/online"), "0-1\n");
        put(&r.sys.join("devices/system/node/node0/cpulist"), "0-3\n");
        put(
            &r.sys.join("devices/system/node/node0/meminfo"),
            "Node 0 MemTotal:       16384000 kB\nNode 0 MemFree: 1 kB\n",
        );
        put(&r.sys.join("devices/system/node/node1/cpulist"), "4-7\n");
        put(
            &r.proc.join("meminfo"),
            "MemTotal:       32768000 kB\nMemFree: 5 kB\n",
        );
        put(
            &r.proc.join("cpuinfo"),
            "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) Gold 6338\n",
        );
        put(&r.proc.join("sys/kernel/osrelease"), "6.8.0-45-generic\n");
        let si = r.system_info();
        assert_eq!(si.cpus, 8);
        assert_eq!(si.mem_kib, 32_768_000);
        assert_eq!(si.cpu_model.as_deref(), Some("Intel(R) Xeon(R) Gold 6338"));
        assert_eq!(si.numa.len(), 2);
        assert_eq!(si.numa[0].cpus, [0, 1, 2, 3]);
        assert_eq!(si.numa[0].mem_kib, Some(16_384_000));
        assert_eq!(si.numa[1].mem_kib, None);
        assert_eq!(si.kernel_version(), Some((6, 8)));

        // An empty /sys and /proc: zeros, not a failure.
        let (_e, empty) = scratch("empty");
        assert_eq!(empty.system_info(), SystemInfo::default());
        assert_eq!(empty.kernel_stats(), KernelStats::default());
    }

    #[test]
    fn writes_all_or_nothing_and_restores_the_original() {
        let (_s, r) = scratch("write");
        let budget = "net.core.netdev_budget";
        let backlog = "net.core.netdev_max_backlog";
        put(&r.proc.join("sys/net/core/netdev_budget"), "300\n");
        put(&r.proc.join("sys/net/core/netdev_max_backlog"), "1000\n");
        let mut s = Sysctl::new(r.clone());
        let none = BTreeMap::new();
        let mut to = BTreeMap::new();
        to.insert(budget.to_owned(), 600);
        to.insert(backlog.to_owned(), 4096);
        s.transition(&none, &to).unwrap();
        assert_eq!(r.sysctl(budget), Some(600));
        assert_eq!(r.sysctl(backlog), Some(4096));

        // A parameter this kernel lacks fails the whole change.
        let mut bad = to.clone();
        bad.insert(budget.to_owned(), 900);
        bad.insert("net.netfilter.nf_conntrack_max".to_owned(), 1 << 20);
        let err = s.transition(&to, &bad).unwrap_err();
        assert!(err.to_string().contains("connection tracking"), "{err}");
        assert_eq!(r.sysctl(budget), Some(600), "rolled back");

        // Taken out: the value from before CoreRouter.
        s.transition(&to, &none).unwrap();
        assert_eq!(r.sysctl(budget), Some(300));
        assert_eq!(r.sysctl(backlog), Some(1000));
        assert!(s.orig.is_empty());

        // Forwarding is written first: the kernel resets other parameters
        // when it changes (a later write must win).
        put(&r.proc.join("sys/net/ipv4/ip_forward"), "0\n");
        put(&r.proc.join("sys/net/ipv4/conf/all/rp_filter"), "1\n");
        let mut fw = BTreeMap::new();
        fw.insert("net.ipv4.conf.all.rp_filter".to_owned(), 2);
        fw.insert("net.ipv4.ip_forward".to_owned(), 1);
        let order: Vec<&str> = {
            let mut w: Vec<(&String, Option<i64>)> =
                fw.iter().map(|(n, v)| (n, Some(*v))).collect();
            w.sort_by_key(|(n, _)| !FORWARDING.contains(&n.as_str()));
            w.into_iter().map(|(n, _)| n.as_str()).collect()
        };
        assert_eq!(
            order,
            ["net.ipv4.ip_forward", "net.ipv4.conf.all.rp_filter"]
        );
        s.transition(&none, &fw).unwrap();
        assert_eq!(r.sysctl("net.ipv4.ip_forward"), Some(1));

        // Never a path outside the catalog.
        assert_eq!(r.sysctl("../../etc/passwd"), None);
        let mut evil = BTreeMap::new();
        evil.insert("kernel.core_pattern".to_owned(), 1);
        assert!(s.transition(&none, &evil).is_err());
    }

    #[test]
    fn reads_the_counters() {
        let (_s, r) = scratch("stats");
        put(
            &r.proc.join("net/softnet_stat"),
            "00000064 00000001 00000002 0 0 0 0 0 0 0 0 0 00000000\n",
        );
        put(
            &r.proc.join("sys/net/netfilter/nf_conntrack_count"),
            "1234\n",
        );
        put(
            &r.proc.join("net/stat/arp_cache"),
            "entries table_fulls\n00000001 00000003\n",
        );
        let k = r.kernel_stats();
        assert_eq!(k.softnet.len(), 1);
        assert_eq!(k.softnet[0].time_squeeze, 2);
        assert_eq!(k.conntrack_count, Some(1234));
        assert_eq!(k.neigh_full_v4, Some(3));
        assert_eq!(k.neigh_full_v6, None);
    }
}
