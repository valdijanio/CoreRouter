//! System › Tuning (G1.26): kernel and hardware settings for a box that
//! forwards packets, applied by CoreRouter itself (no `tuned`, no
//! `sysctl.conf`), so every change is a command with a transaction, Safe
//! Mode, diff and rollback.
//!
//! The config keeps only what the operator (or a profile) set: a parameter
//! missing from [`Tuning::sysctl`] is left as the kernel has it, and taking
//! one out puts back the value the kernel had before CoreRouter first
//! changed it. [`PARAMS`] is the catalog: which kernel parameters exist
//! here, where the window shows them and the values they accept.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Tuning {
    /// Kernel parameters by `sysctl` name (`net.core.netdev_max_backlog`):
    /// the value to keep there. Only names of [`PARAMS`].
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub sysctl: BTreeMap<String, i64>,
}

impl Tuning {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// Tab of the Tuning window a parameter belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tab {
    Kernel,
    Interfaces,
    Cpu,
    Boot,
}

/// One tunable kernel parameter (`/proc/sys/<name with / for .>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Param {
    pub name: &'static str,
    pub tab: Tab,
    /// Group inside the tab (an English label).
    pub section: &'static str,
    pub min: i64,
    pub max: i64,
    /// `""`, `"B"`, `"KiB"`, `"s"`, `"µs"`, `"packets"`, `"entries"`.
    pub unit: &'static str,
    /// Named values (`rp_filter`: 0 off, 1 strict, 2 loose); empty for a
    /// number.
    pub choices: &'static [(i64, &'static str)],
    /// The kernel's own default, when it is fixed (not computed from RAM).
    pub default: Option<i64>,
    /// Only the first network namespace has it (a container or a test
    /// namespace does not).
    pub init_ns_only: bool,
    /// Kept by the kernel only for compatibility: writing it changes
    /// nothing (`net.ipv4.route.max_size` since Linux 3.6).
    pub obsolete: bool,
    /// Affects the router's own sockets (BGP, the API), not forwarded
    /// traffic.
    pub control_plane: bool,
}

const OFF_ON: &[(i64, &str)] = &[(0, "off"), (1, "on")];
const RP_FILTER: &[(i64, &str)] = &[(0, "off"), (1, "strict"), (2, "loose")];
const HASH: &[(i64, &str)] = &[
    (0, "layer 3"),
    (1, "layer 4"),
    (2, "layer 3 inner"),
    (3, "custom"),
];
const SYNCOOKIES: &[(i64, &str)] = &[(0, "off"), (1, "when needed"), (2, "always")];

/// Largest value Linux keeps in an `int` sysctl.
pub const INT_MAX: i64 = i32::MAX as i64;

const fn p(
    name: &'static str,
    section: &'static str,
    (min, max): (i64, i64),
    unit: &'static str,
    default: Option<i64>,
) -> Param {
    Param {
        name,
        tab: Tab::Kernel,
        section,
        min,
        max,
        unit,
        choices: &[],
        default,
        init_ns_only: false,
        obsolete: false,
        control_plane: false,
    }
}

const fn choice(
    name: &'static str,
    section: &'static str,
    choices: &'static [(i64, &'static str)],
    default: i64,
) -> Param {
    let mut out = p(name, section, (0, (choices.len() as i64) - 1), "", Some(default));
    out.choices = choices;
    out
}

const fn init_ns(mut p: Param) -> Param {
    p.init_ns_only = true;
    p
}

const fn obsolete(mut p: Param) -> Param {
    p.obsolete = true;
    p
}

const fn control(mut p: Param) -> Param {
    p.control_plane = true;
    p
}

pub const SEC_RX: &str = "Packet receive";
pub const SEC_ROUTING: &str = "Routing";
pub const SEC_CONNTRACK: &str = "Connection tracking";
pub const SEC_NEIGH: &str = "Neighbor tables";
pub const SEC_STABILITY: &str = "Stability";
pub const SEC_CONTROL: &str = "Control plane (TCP)";

const CT: &str = "net.netfilter.nf_conntrack_";

/// The kernel parameters of the Kernel tab, in display order.
pub const PARAMS: &[Param] = &[
    init_ns(p(
        "net.core.netdev_max_backlog",
        SEC_RX,
        (64, 1 << 20),
        "packets",
        Some(1000),
    )),
    init_ns(p("net.core.netdev_budget", SEC_RX, (50, 100_000), "packets", Some(300))),
    init_ns(p(
        "net.core.netdev_budget_usecs",
        SEC_RX,
        (100, 1_000_000),
        "µs",
        None,
    )),
    init_ns(p("net.core.dev_weight", SEC_RX, (16, 10_000), "packets", Some(64))),
    choice("net.ipv4.ip_forward", SEC_ROUTING, OFF_ON, 0),
    choice("net.ipv6.conf.all.forwarding", SEC_ROUTING, OFF_ON, 0),
    choice("net.ipv4.conf.all.rp_filter", SEC_ROUTING, RP_FILTER, 0),
    choice("net.ipv4.conf.default.rp_filter", SEC_ROUTING, RP_FILTER, 0),
    choice("net.ipv4.fib_multipath_hash_policy", SEC_ROUTING, HASH, 0),
    choice("net.ipv6.fib_multipath_hash_policy", SEC_ROUTING, HASH, 0),
    obsolete(p("net.ipv4.route.max_size", SEC_ROUTING, (0, INT_MAX), "entries", None)),
    p("net.ipv6.route.max_size", SEC_ROUTING, (4096, INT_MAX), "entries", None),
    p(
        "net.netfilter.nf_conntrack_max",
        SEC_CONNTRACK,
        (4096, 1 << 26),
        "entries",
        None,
    ),
    init_ns(p(
        "net.netfilter.nf_conntrack_buckets",
        SEC_CONNTRACK,
        (1024, 1 << 24),
        "entries",
        None,
    )),
    p(
        "net.netfilter.nf_conntrack_tcp_timeout_established",
        SEC_CONNTRACK,
        (60, INT_MAX),
        "s",
        Some(432_000),
    ),
    p(
        "net.netfilter.nf_conntrack_tcp_timeout_syn_sent",
        SEC_CONNTRACK,
        (5, 3600),
        "s",
        Some(120),
    ),
    p(
        "net.netfilter.nf_conntrack_tcp_timeout_syn_recv",
        SEC_CONNTRACK,
        (5, 3600),
        "s",
        Some(60),
    ),
    p(
        "net.netfilter.nf_conntrack_tcp_timeout_fin_wait",
        SEC_CONNTRACK,
        (5, 3600),
        "s",
        Some(120),
    ),
    p(
        "net.netfilter.nf_conntrack_tcp_timeout_close_wait",
        SEC_CONNTRACK,
        (5, 3600),
        "s",
        Some(60),
    ),
    p(
        "net.netfilter.nf_conntrack_tcp_timeout_time_wait",
        SEC_CONNTRACK,
        (5, 3600),
        "s",
        Some(120),
    ),
    p(
        "net.netfilter.nf_conntrack_udp_timeout",
        SEC_CONNTRACK,
        (5, 3600),
        "s",
        Some(30),
    ),
    p(
        "net.netfilter.nf_conntrack_udp_timeout_stream",
        SEC_CONNTRACK,
        (30, 86_400),
        "s",
        Some(120),
    ),
    p(
        "net.netfilter.nf_conntrack_icmp_timeout",
        SEC_CONNTRACK,
        (5, 3600),
        "s",
        Some(30),
    ),
    p(
        "net.netfilter.nf_conntrack_generic_timeout",
        SEC_CONNTRACK,
        (30, 86_400),
        "s",
        Some(600),
    ),
    init_ns(p(
        "net.ipv4.neigh.default.gc_thresh1",
        SEC_NEIGH,
        (0, 1 << 20),
        "entries",
        Some(128),
    )),
    init_ns(p(
        "net.ipv4.neigh.default.gc_thresh2",
        SEC_NEIGH,
        (0, 1 << 20),
        "entries",
        Some(512),
    )),
    init_ns(p(
        "net.ipv4.neigh.default.gc_thresh3",
        SEC_NEIGH,
        (16, 1 << 20),
        "entries",
        Some(1024),
    )),
    init_ns(p(
        "net.ipv6.neigh.default.gc_thresh1",
        SEC_NEIGH,
        (0, 1 << 20),
        "entries",
        Some(128),
    )),
    init_ns(p(
        "net.ipv6.neigh.default.gc_thresh2",
        SEC_NEIGH,
        (0, 1 << 20),
        "entries",
        Some(512),
    )),
    init_ns(p(
        "net.ipv6.neigh.default.gc_thresh3",
        SEC_NEIGH,
        (16, 1 << 20),
        "entries",
        Some(1024),
    )),
    init_ns(p("kernel.panic", SEC_STABILITY, (0, 3600), "s", Some(0))),
    init_ns(choice("kernel.panic_on_oops", SEC_STABILITY, OFF_ON, 0)),
    init_ns(p(
        "vm.min_free_kbytes",
        SEC_STABILITY,
        (1024, 1 << 22),
        "KiB",
        None,
    )),
    control(init_ns(p(
        "net.core.rmem_max",
        SEC_CONTROL,
        (4096, 1 << 30),
        "B",
        Some(4 << 20),
    ))),
    control(init_ns(p(
        "net.core.wmem_max",
        SEC_CONTROL,
        (4096, 1 << 30),
        "B",
        Some(4 << 20),
    ))),
    control(p("net.core.somaxconn", SEC_CONTROL, (128, 65_535), "", Some(4096))),
    control(choice("net.ipv4.tcp_syncookies", SEC_CONTROL, SYNCOOKIES, 1)),
    control(p(
        "net.ipv4.tcp_max_syn_backlog",
        SEC_CONTROL,
        (128, 1 << 20),
        "",
        None,
    )),
];

/// The catalog entry of `name`.
pub fn param(name: &str) -> Option<&'static Param> {
    PARAMS.iter().find(|p| p.name == name)
}

/// Whether `name` is a conntrack parameter (needs `nf_conntrack` loaded).
pub fn is_conntrack(name: &str) -> bool {
    name.starts_with(CT)
}

/// `/proc/sys` path of `name`, relative (`net/core/netdev_budget`). Only
/// for catalog names: they have no `/` and no `..`.
pub fn proc_path(name: &str) -> String {
    name.replace('.', "/")
}

/// The name of `value` among `p`'s choices, or the number.
pub fn value_text(p: &Param, value: i64) -> String {
    p.choices
        .iter()
        .find(|(v, _)| *v == value)
        .map_or_else(|| value.to_string(), |(_, n)| format!("{value} ({n})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_sane() {
        let mut names: Vec<&str> = PARAMS.iter().map(|p| p.name).collect();
        let n = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), n, "each parameter once");
        for p in PARAMS {
            assert!(p.min <= p.max, "{}", p.name);
            if let Some(d) = p.default {
                assert!((p.min..=p.max).contains(&d), "{} default", p.name);
            }
            assert!(
                p.name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._".contains(&b)),
                "{}",
                p.name
            );
            assert!(!p.name.contains(".."), "{}", p.name);
            for (i, (v, _)) in p.choices.iter().enumerate() {
                assert_eq!(*v, i as i64, "{} choices are 0..n", p.name);
            }
        }
        assert_eq!(proc_path("net.core.netdev_budget"), "net/core/netdev_budget");
        assert!(is_conntrack("net.netfilter.nf_conntrack_max"));
        assert!(!is_conntrack("net.core.somaxconn"));
    }

    #[test]
    fn tuning_round_trips_and_stays_out_of_old_configs() {
        let t: Tuning = serde_json::from_str("{}").unwrap();
        assert!(t.is_default());
        assert_eq!(serde_json::to_string(&t).unwrap(), "{}");
        let mut t = Tuning::default();
        t.sysctl.insert("net.core.netdev_budget".into(), 600);
        let back: Tuning = serde_json::from_str(&serde_json::to_string(&t).unwrap()).unwrap();
        assert_eq!(back, t);
        assert_eq!(
            value_text(param("net.ipv4.conf.all.rp_filter").unwrap(), 2),
            "2 (loose)"
        );
    }
}
