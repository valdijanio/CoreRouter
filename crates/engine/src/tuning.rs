//! System › Tuning (G1.26): profiles calculated from the hardware, value
//! ranges that depend on it, and the diagnosis from the counters. Pure:
//! the commands (`cmd/tuning.rs`) read the machine through the HAL and
//! hand it here, so every number is tested without a kernel.
//!
//! Each recommendation carries its reason twice: as English text (CLI,
//! MCP) and as a template id with arguments, which the GUI shows in the
//! language of the explanations (`tuning.why.<id>` in `ui::i18n`).

use std::collections::BTreeMap;

use corerouter_hal::tuning::{KernelStats, SystemInfo, Sysctls};
use corerouter_model::tuning::{PARAMS, Param};
use serde::Serialize;

/// Estimated memory per conntrack entry (struct `nf_conn` with its
/// extensions, plus the hash bucket share), bytes. **Estimado**: 256–320 B
/// on x86_64 kernels 5.x–6.x; the larger one keeps the RAM share honest.
pub const CONNTRACK_ENTRY_BYTES: u64 = 320;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Only what is safe everywhere; the rest stays as the kernel has it.
    Conservative,
    Balanced,
    /// Bigger buffers and budgets, shorter conntrack timeouts (CGNAT).
    Throughput,
    /// Smaller budgets: a packet waits less in the receive path.
    Latency,
}

impl Profile {
    pub const ALL: [Profile; 4] = [
        Profile::Conservative,
        Profile::Balanced,
        Profile::Throughput,
        Profile::Latency,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Profile::Conservative => "conservative",
            Profile::Balanced => "balanced",
            Profile::Throughput => "throughput",
            Profile::Latency => "latency",
        }
    }

    pub fn parse(s: &str) -> Option<Profile> {
        Self::ALL.into_iter().find(|p| p.id() == s)
    }
}

/// One port as the profile sees it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Nic {
    pub name: String,
    pub driver: Option<String>,
    pub model: Option<String>,
    /// Fastest rate the port can do (Mb/s).
    pub speed_mbps: Option<u32>,
    pub numa_node: Option<u32>,
    pub queues: Option<u32>,
    pub queues_max: Option<u32>,
    pub ring_rx: Option<u32>,
    pub ring_rx_max: Option<u32>,
    pub ring_tx: Option<u32>,
    pub ring_tx_max: Option<u32>,
    /// Frames the NIC dropped for lack of a free RX descriptor
    /// (`rx_missed_errors`), since the driver loaded.
    pub rx_missed: Option<u64>,
}

/// The machine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Machine {
    #[serde(flatten)]
    pub sys: SystemInfo,
    pub nics: Vec<Nic>,
}

impl Machine {
    fn mem_bytes(&self) -> u64 {
        self.sys.mem_kib.saturating_mul(1024)
    }

    /// Sum of the ports' rates, in Gb/s (at least 1).
    pub fn total_gbps(&self) -> u64 {
        let mbps: u64 = self
            .nics
            .iter()
            .map(|n| u64::from(n.speed_mbps.unwrap_or(1000)))
            .sum();
        (mbps / 1000).max(1)
    }
}

/// A recommended value and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rec {
    pub value: i64,
    /// English, for the CLI and MCP.
    pub why: String,
    /// Template id (`tuning.why.<id>` in the GUI's catalogs).
    pub why_id: &'static str,
    pub why_args: BTreeMap<&'static str, String>,
}

/// English templates; `{name}` is an argument. The GUI's English catalog
/// carries the same text (a test in `ui` compares them).
pub const WHY: &[(&str, &str)] = &[
    ("backlog", "Sized for {gbps} Gb/s of ports: a burst waits in the backlog instead of being dropped."),
    ("budget", "More packets per receive round ({profile}): fewer squeezes under load."),
    ("budget_low", "The kernel's value: shorter receive rounds, less waiting ({profile})."),
    ("ct_buckets", "A quarter of nf_conntrack_max: short hash chains on every lookup."),
    ("ct_max", "{share} of the RAM ({mem}) for connection tracking, ~320 B per entry."),
    ("ct_timeout", "{value} s ({profile}): dead connections leave the table sooner."),
    ("ct_timeout_rfc", "{value} s ({profile}): dead connections leave the table sooner, within {rfc}."),
    ("default", "The kernel's default."),
    ("forward", "A router forwards packets."),
    ("hash_l4", "Spreads flows over equal-cost routes by port too, not only by address."),
    ("keep", "{profile} keeps the kernel's value."),
    ("min_free", "A reserve for allocations in interrupts (NIC rings): {share} of the RAM."),
    ("neigh", "{entries} neighbors for {mem} of RAM; the other thresholds at 1/2 and 1/8 of it."),
    ("oops", "An oops leaves the kernel unsure of itself: treat it as a panic and reboot."),
    ("panic", "Reboot 10 s after a kernel panic instead of hanging."),
    ("rp_loose", "Loose: drops sources with no route at all and keeps asymmetric routing (several uplinks) working."),
    ("rp_off", "Off: no extra route lookup per packet; filter spoofed sources in the firewall."),
    ("sockbuf", "Lets BGP and the API ask for 16 MiB socket buffers (full tables)."),
    ("v6_routes", "Linux {kernel} still caps IPv6 routes at max_size: room for a full table."),
];

fn rec(id: &'static str, value: i64, args: &[(&'static str, String)]) -> Rec {
    let args: BTreeMap<&'static str, String> = args.iter().cloned().collect();
    let template = WHY
        .iter()
        .find(|(k, _)| *k == id)
        .map_or("", |(_, t)| *t);
    Rec {
        value,
        why: fill(template, &args),
        why_id: id,
        why_args: args,
    }
}

/// Put `args` into `{name}` places of `template`.
pub fn fill(template: &str, args: &BTreeMap<&str, String>) -> String {
    let mut out = template.to_owned();
    for (k, v) in args {
        out = out.replace(&format!("{{{k}}}"), v);
    }
    out
}

fn pow2_floor(v: u64) -> u64 {
    if v == 0 { 0 } else { 1 << (63 - v.leading_zeros()) }
}

fn gib(kib: u64) -> String {
    format!("{:.0} GiB", kib as f64 / 1_048_576.0)
}

fn to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// `p`'s range on this machine: some maxima follow the RAM.
pub fn range(p: &Param, m: Option<&Machine>) -> (i64, i64) {
    let Some(m) = m.filter(|m| m.sys.mem_kib > 0) else {
        return (p.min, p.max);
    };
    let cap = match p.name {
        // A quarter of the RAM at most.
        "net.netfilter.nf_conntrack_max" => {
            Some(to_i64(m.mem_bytes() / 4 / CONNTRACK_ENTRY_BYTES))
        }
        // A tenth of the RAM at most (more starves user space).
        "vm.min_free_kbytes" => Some(to_i64(m.sys.mem_kib / 10)),
        _ => None,
    };
    let max = cap.map_or(p.max, |c| c.min(p.max).max(p.min));
    (p.min, max)
}

/// The values of `profile` on machine `m`, by parameter. A parameter with
/// no entry has no recommendation (obsolete, or nothing to say).
pub fn recommend(profile: Profile, m: &Machine) -> BTreeMap<&'static str, Rec> {
    use Profile::*;
    let mut out = BTreeMap::new();
    let pname = || profile.id().to_owned();
    let gbps = m.total_gbps();
    let mem_kib = m.sys.mem_kib.max(1 << 20);
    for p in PARAMS {
        let n = p.name;
        let r = match n {
            "net.ipv4.ip_forward" | "net.ipv6.conf.all.forwarding" => Some(rec("forward", 1, &[])),
            "net.ipv4.fib_multipath_hash_policy" | "net.ipv6.fib_multipath_hash_policy" => {
                Some(rec("hash_l4", 1, &[]))
            }
            "kernel.panic" => Some(rec("panic", 10, &[])),
            "kernel.panic_on_oops" => Some(rec("oops", 1, &[])),
            "net.ipv4.tcp_syncookies" => Some(rec("default", 1, &[])),
            "net.ipv6.route.max_size" => match m.sys.kernel_version() {
                Some(v) if v < (6, 3) => Some(rec(
                    "v6_routes",
                    1 << 20,
                    &[("kernel", format!("{}.{}", v.0, v.1))],
                )),
                _ => None,
            },
            // Conservative: nothing else (the "keep" reason in the GUI).
            _ if profile == Conservative => None,
            "net.core.netdev_max_backlog" => {
                let v = match profile {
                    Latency => 4096,
                    _ => {
                        let base = pow2_floor(gbps.saturating_mul(1000)).clamp(4096, 65_536);
                        if profile == Throughput { base * 2 } else { base }
                    }
                };
                Some(rec("backlog", to_i64(v), &[("gbps", gbps.to_string())]))
            }
            "net.core.netdev_budget" => Some(match profile {
                Latency => rec("budget_low", 300, &[("profile", pname())]),
                Throughput => rec("budget", 1200, &[("profile", pname())]),
                _ => rec("budget", 600, &[("profile", pname())]),
            }),
            "net.core.netdev_budget_usecs" => Some(match profile {
                Latency => rec("budget_low", 2000, &[("profile", pname())]),
                _ => rec("budget", 8000, &[("profile", pname())]),
            }),
            "net.ipv4.conf.all.rp_filter" | "net.ipv4.conf.default.rp_filter" => Some(match profile {
                Throughput | Latency => rec("rp_off", 0, &[]),
                _ => rec("rp_loose", 2, &[]),
            }),
            "net.netfilter.nf_conntrack_max" => Some(ct_max(profile, m)),
            "net.netfilter.nf_conntrack_buckets" => {
                let max = ct_max(profile, m).value;
                let b = pow2_floor(u64::try_from(max / 4).unwrap_or(0)).clamp(1024, 1 << 24);
                Some(rec("ct_buckets", to_i64(b), &[]))
            }
            "net.netfilter.nf_conntrack_tcp_timeout_established" => {
                let v = if profile == Throughput { 7440 } else { 86_400 };
                Some(ct_timeout(v, profile, Some("RFC 5382 REQ-5 (≥ 7440 s)")))
            }
            "net.netfilter.nf_conntrack_udp_timeout" if profile == Throughput => {
                Some(ct_timeout(10, profile, None))
            }
            "net.netfilter.nf_conntrack_udp_timeout_stream" => Some(ct_timeout(
                if profile == Throughput { 120 } else { 180 },
                profile,
                Some("RFC 4787 REQ-5 (≥ 120 s)"),
            )),
            "net.netfilter.nf_conntrack_icmp_timeout" => {
                Some(ct_timeout(60, profile, Some("RFC 5508 REQ-1 (≥ 60 s)")))
            }
            "net.netfilter.nf_conntrack_generic_timeout" if profile == Throughput => {
                Some(ct_timeout(120, profile, None))
            }
            "net.ipv4.neigh.default.gc_thresh3" | "net.ipv6.neigh.default.gc_thresh3" => {
                Some(neigh(profile, mem_kib, 1))
            }
            "net.ipv4.neigh.default.gc_thresh2" | "net.ipv6.neigh.default.gc_thresh2" => {
                Some(neigh(profile, mem_kib, 2))
            }
            "net.ipv4.neigh.default.gc_thresh1" | "net.ipv6.neigh.default.gc_thresh1" => {
                Some(neigh(profile, mem_kib, 8))
            }
            "vm.min_free_kbytes" => {
                let (div, cap, share) = if profile == Throughput {
                    (128, 1 << 20, "1/128")
                } else {
                    (256, 512 << 10, "1/256")
                };
                let v = (mem_kib / div).clamp(65_536, cap);
                Some(rec("min_free", to_i64(v), &[("share", share.into())]))
            }
            "net.core.rmem_max" | "net.core.wmem_max" => Some(rec("sockbuf", 16 << 20, &[])),
            "net.core.somaxconn" => Some(rec("default", 4096, &[])),
            "net.ipv4.tcp_max_syn_backlog" => Some(rec("default", 4096, &[])),
            _ => p.default.map(|d| rec("default", d, &[])),
        };
        if let Some(r) = r {
            out.insert(n, r);
        }
    }
    out
}

fn ct_max(profile: Profile, m: &Machine) -> Rec {
    let (div, share) = match profile {
        Profile::Conservative => (32, "1/32"),
        Profile::Throughput => (8, "1/8"),
        _ => (16, "1/16"),
    };
    let mem_kib = m.sys.mem_kib.max(1 << 20);
    let entries = mem_kib.saturating_mul(1024) / div / CONNTRACK_ENTRY_BYTES;
    let v = (entries / 65_536 * 65_536).clamp(65_536, 8 << 20);
    rec(
        "ct_max",
        to_i64(v),
        &[("share", share.into()), ("mem", gib(mem_kib))],
    )
}

fn ct_timeout(value: i64, profile: Profile, rfc: Option<&str>) -> Rec {
    let mut args = vec![("value", value.to_string()), ("profile", profile.id().into())];
    let id = match rfc {
        Some(r) => {
            args.push(("rfc", r.into()));
            "ct_timeout_rfc"
        }
        None => "ct_timeout",
    };
    rec(id, value, &args)
}

/// `gc_thresh3` from the RAM (2048 per GiB, a power of two), the others
/// at 1/`div` of it (VyOS and the kernel docs: 1/2 and 1/8).
fn neigh(profile: Profile, mem_kib: u64, div: u64) -> Rec {
    let per = pow2_floor((mem_kib / 1_048_576).max(1).saturating_mul(2048));
    let t3 = match profile {
        Profile::Throughput => (per * 2).clamp(8192, 131_072),
        _ => per.clamp(4096, 65_536),
    };
    rec(
        "neigh",
        to_i64(t3 / div),
        &[("entries", t3.to_string()), ("mem", gib(mem_kib))],
    )
}

/// Severity of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// Something the counters say about the settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// Stable id (`softnet_squeeze`): the GUI's text key.
    pub id: &'static str,
    /// English.
    pub text: String,
    /// Arguments of the text (for the GUI's own language).
    pub args: BTreeMap<&'static str, String>,
    /// The parameter to change and the value the balanced profile gives.
    pub param: Option<&'static str>,
    pub suggest: Option<i64>,
}

pub const FINDINGS: &[(&str, &str)] = &[
    ("conntrack_full", "The conntrack table is {pct}% full ({count} of {max}): new connections are dropped when it fills."),
    ("forwarding_off", "IPv4 forwarding is off: this router does not route."),
    ("neigh_full", "The {family} neighbor table overflowed {count} times since boot: hosts lose connectivity."),
    ("nic_missed", "{nics} dropped {count} frames for lack of RX descriptors, with the RX ring below its maximum (Interfaces tab)."),
    ("softnet_dropped", "{count} packets dropped since boot: the backlog was full (CPU {cpu} the most)."),
    ("softnet_squeeze", "The receive softirq ran out of budget {count} times since boot ({ratio} of the packets; CPU {cpu} the most)."),
];

fn finding(
    severity: Severity,
    id: &'static str,
    args: &[(&'static str, String)],
    param: Option<&'static str>,
    suggest: Option<i64>,
) -> Finding {
    let args: BTreeMap<&'static str, String> = args.iter().cloned().collect();
    let template = FINDINGS
        .iter()
        .find(|(k, _)| *k == id)
        .map_or("", |(_, t)| *t);
    Finding {
        severity,
        id,
        text: fill(template, &args),
        args,
        param,
        suggest,
    }
}

/// What the counters say, worst first.
pub fn diagnose(m: &Machine, stats: &KernelStats, cur: &Sysctls) -> Vec<Finding> {
    let mut out = Vec::new();
    let balanced = recommend(Profile::Balanced, m);
    let get = |n: &str| cur.get(n).copied().flatten();
    // The counters run since boot: once the parameter already has the
    // suggested value (or more), the finding stays as a note, no button.
    let suggest = |n: &str| {
        balanced
            .get(n)
            .map(|r| r.value)
            .filter(|v| get(n).is_none_or(|now| now < *v))
    };
    let level = |n: &str, s: Severity| {
        if suggest(n).is_some() { s } else { Severity::Info }
    };

    if get("net.ipv4.ip_forward") == Some(0) {
        out.push(finding(
            Severity::Critical,
            "forwarding_off",
            &[],
            Some("net.ipv4.ip_forward"),
            Some(1),
        ));
    }
    let processed: u64 = stats.softnet.iter().map(|c| c.processed).sum();
    let squeeze: u64 = stats.softnet.iter().map(|c| c.time_squeeze).sum();
    let dropped: u64 = stats.softnet.iter().map(|c| c.dropped).sum();
    let worst = |f: fn(&corerouter_hal::tuning::SoftnetCpu) -> u64| {
        stats
            .softnet
            .iter()
            .max_by_key(|c| f(c))
            .map_or_else(String::new, |c| c.cpu.to_string())
    };
    if dropped > 0 {
        out.push(finding(
            level("net.core.netdev_max_backlog", Severity::Warning),
            "softnet_dropped",
            &[("count", dropped.to_string()), ("cpu", worst(|c| c.dropped))],
            Some("net.core.netdev_max_backlog"),
            suggest("net.core.netdev_max_backlog"),
        ));
    }
    // One squeeze per 10 000 packets is noise; more means the softirq
    // keeps leaving work for the next round.
    if squeeze > 0 && squeeze.saturating_mul(10_000) > processed {
        let ratio = format!("{:.2}%", squeeze as f64 * 100.0 / processed.max(1) as f64);
        out.push(finding(
            level("net.core.netdev_budget", Severity::Warning),
            "softnet_squeeze",
            &[
                ("count", squeeze.to_string()),
                ("ratio", ratio),
                ("cpu", worst(|c| c.time_squeeze)),
            ],
            Some("net.core.netdev_budget"),
            suggest("net.core.netdev_budget"),
        ));
    }
    if let (Some(count), Some(max)) = (
        stats.conntrack_count,
        get("net.netfilter.nf_conntrack_max").filter(|m| *m > 0),
    ) {
        let pct = u64::try_from(max)
            .ok()
            .map_or(0, |max| count.saturating_mul(100) / max.max(1));
        if pct >= 80 {
            out.push(finding(
                if pct >= 95 {
                    Severity::Critical
                } else {
                    Severity::Warning
                },
                "conntrack_full",
                &[
                    ("pct", pct.to_string()),
                    ("count", count.to_string()),
                    ("max", max.to_string()),
                ],
                Some("net.netfilter.nf_conntrack_max"),
                suggest("net.netfilter.nf_conntrack_max"),
            ));
        }
    }
    for (family, n, param) in [
        ("IPv4", stats.neigh_full_v4, "net.ipv4.neigh.default.gc_thresh3"),
        ("IPv6", stats.neigh_full_v6, "net.ipv6.neigh.default.gc_thresh3"),
    ] {
        if let Some(count) = n.filter(|c| *c > 0) {
            out.push(finding(
                level(param, Severity::Warning),
                "neigh_full",
                &[("family", family.into()), ("count", count.to_string())],
                Some(param),
                suggest(param),
            ));
        }
    }
    // One finding for all such ports: the lab (and a big router) has many.
    let short: Vec<(&str, u64)> = m
        .nics
        .iter()
        .filter_map(|n| {
            let (missed, ring, max) = (n.rx_missed?, n.ring_rx?, n.ring_rx_max?);
            (missed > 0 && ring < max).then_some((n.name.as_str(), missed))
        })
        .collect();
    if !short.is_empty() {
        let mut names: Vec<&str> = short.iter().map(|(n, _)| *n).take(4).collect();
        if short.len() > 4 {
            names.push("…");
        }
        let count: u64 = short.iter().map(|(_, c)| *c).fold(0, u64::saturating_add);
        out.push(finding(
            Severity::Info,
            "nic_missed",
            &[("nics", names.join(", ")), ("count", count.to_string())],
            None,
            None,
        ));
    }
    out.sort_by_key(|f| std::cmp::Reverse(f.severity));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_hal::tuning::SoftnetCpu;

    fn machine(mem_gib: u64, nics: &[u32]) -> Machine {
        Machine {
            sys: SystemInfo {
                cpus: 16,
                mem_kib: mem_gib << 20,
                kernel: "6.8.0".into(),
                ..SystemInfo::default()
            },
            nics: nics
                .iter()
                .enumerate()
                .map(|(i, s)| Nic {
                    name: format!("ether{}", i + 1),
                    speed_mbps: Some(*s),
                    ..Nic::default()
                })
                .collect(),
        }
    }

    #[test]
    fn every_recommendation_is_in_range_and_explained() {
        for mem in [1, 4, 32, 512] {
            let m = machine(mem, &[10_000, 10_000, 1000]);
            for profile in Profile::ALL {
                let r = recommend(profile, &m);
                for p in PARAMS {
                    let Some(rec) = r.get(p.name) else {
                        continue;
                    };
                    let (lo, hi) = range(p, Some(&m));
                    assert!(
                        (lo..=hi).contains(&rec.value),
                        "{} {profile:?} {mem} GiB: {} not in {lo}..={hi}",
                        p.name,
                        rec.value
                    );
                    assert!(!rec.why.is_empty() && !rec.why.contains('{'), "{}", rec.why);
                }
                // gc_thresh1 ≤ gc_thresh2 ≤ gc_thresh3.
                for f in ["ipv4", "ipv6"] {
                    let t = |i: u8| {
                        r.get(format!("net.{f}.neigh.default.gc_thresh{i}").as_str())
                            .map(|r| r.value)
                    };
                    if let (Some(a), Some(b), Some(c)) = (t(1), t(2), t(3)) {
                        assert!(a <= b && b <= c, "{f} {a} {b} {c}");
                    }
                }
            }
        }
    }

    #[test]
    fn profiles_follow_the_hardware() {
        let small = machine(4, &[1000, 1000]);
        let big = machine(64, &[100_000, 100_000]);
        let b = |m: &Machine, n: &str| recommend(Profile::Balanced, m)[n].value;
        assert!(b(&big, "net.netfilter.nf_conntrack_max") > b(&small, "net.netfilter.nf_conntrack_max"));
        assert!(b(&big, "net.core.netdev_max_backlog") > b(&small, "net.core.netdev_max_backlog"));
        // 4 GiB, 1/16, 320 B per entry: 838 860 → 786 432 (multiple of 64 Ki).
        assert_eq!(b(&small, "net.netfilter.nf_conntrack_max"), 786_432);
        assert_eq!(b(&small, "net.netfilter.nf_conntrack_buckets"), 131_072);
        assert_eq!(b(&small, "net.ipv4.neigh.default.gc_thresh3"), 8192);
        assert_eq!(b(&small, "net.ipv4.neigh.default.gc_thresh1"), 1024);
        // CGNAT: established never below RFC 5382's 2 h 4 min.
        for p in Profile::ALL {
            if let Some(r) = recommend(p, &big).get("net.netfilter.nf_conntrack_tcp_timeout_established") {
                assert!(r.value >= 7440, "{p:?}");
            }
        }
        // Conservative leaves the receive path alone.
        let c = recommend(Profile::Conservative, &big);
        assert!(!c.contains_key("net.core.netdev_budget"));
        assert_eq!(c["net.ipv4.ip_forward"].value, 1);
        // IPv6 max_size only matters before Linux 6.3; v4's never.
        let mut old = small.clone();
        old.sys.kernel = "5.15.0-100-generic".into();
        assert_eq!(recommend(Profile::Balanced, &old)["net.ipv6.route.max_size"].value, 1 << 20);
        assert!(!recommend(Profile::Balanced, &small).contains_key("net.ipv6.route.max_size"));
        assert!(!recommend(Profile::Balanced, &old).contains_key("net.ipv4.route.max_size"));
    }

    #[test]
    fn ranges_follow_the_ram() {
        let p = corerouter_model::tuning::param("net.netfilter.nf_conntrack_max").unwrap();
        let (_, max) = range(p, Some(&machine(4, &[])));
        assert_eq!(max, (4i64 << 30) / 4 / 320);
        assert_eq!(range(p, None), (p.min, p.max));
        assert_eq!(range(p, Some(&Machine::default())), (p.min, p.max), "unknown RAM");
    }

    #[test]
    fn diagnosis_reads_the_counters() {
        let m = Machine {
            nics: vec![Nic {
                name: "ether1".into(),
                rx_missed: Some(50),
                ring_rx: Some(512),
                ring_rx_max: Some(4096),
                ..Nic::default()
            }],
            ..machine(8, &[])
        };
        let stats = KernelStats {
            softnet: vec![
                SoftnetCpu { cpu: 0, processed: 1_000_000, dropped: 0, time_squeeze: 10 },
                SoftnetCpu { cpu: 1, processed: 1_000_000, dropped: 7, time_squeeze: 900 },
            ],
            conntrack_count: Some(250_000),
            neigh_full_v4: Some(3),
            neigh_full_v6: Some(0),
        };
        let mut cur = Sysctls::new();
        cur.insert("net.netfilter.nf_conntrack_max".into(), Some(262_144));
        cur.insert("net.ipv4.ip_forward".into(), Some(0));
        let f = diagnose(&m, &stats, &cur);
        let ids: Vec<&str> = f.iter().map(|f| f.id).collect();
        assert_eq!(
            ids,
            ["forwarding_off", "conntrack_full", "softnet_dropped", "softnet_squeeze", "neigh_full", "nic_missed"]
        );
        let squeeze = &f[3];
        assert!(squeeze.text.contains("CPU 1"), "{}", squeeze.text);
        assert_eq!(squeeze.suggest, Some(600));
        assert_eq!(f[1].severity, Severity::Critical, "95%: {}", f[1].text);
        // Already at the suggestion: a note without a button.
        cur.insert("net.core.netdev_budget".into(), Some(600));
        let f = diagnose(&m, &stats, &cur);
        let sq = f.iter().find(|f| f.id == "softnet_squeeze").unwrap();
        assert_eq!((sq.severity, sq.suggest), (Severity::Info, None));
        // Quiet counters: nothing to say.
        let calm = KernelStats {
            softnet: vec![SoftnetCpu { cpu: 0, processed: 1_000_000, dropped: 0, time_squeeze: 5 }],
            ..KernelStats::default()
        };
        assert!(diagnose(&machine(8, &[]), &calm, &Sysctls::new()).is_empty());
    }
}
