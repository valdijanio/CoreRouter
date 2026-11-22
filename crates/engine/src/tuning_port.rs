//! System › Tuning, Interfaces (G1.26b): what each profile wants of a port
//! (rings, queues, coalescing, offloads, flow control, transmit queue,
//! `rp_filter`), from the NIC's own maxima and the machine. Pure, like
//! `tuning.rs`, whose `Rec` and reasons it shares.

use std::collections::BTreeMap;

use corerouter_model::tuning::{PORT_PARAMS, Param};

use crate::tuning::{Machine, Profile, Rec, recommend, why};

/// Code of `noqueue` in `corerouter_model::tuning::QDISCS`.
const NOQUEUE: i64 = 4;

/// One port as the profile sees it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Port {
    pub name: String,
    /// Current value by `PORT_PARAMS` key (`None`: no such knob here).
    pub now: BTreeMap<String, Option<i64>>,
    /// The NIC's maxima (`rx_ring` 4096).
    pub max: BTreeMap<String, i64>,
    pub numa_node: Option<u32>,
    /// Transmit queues the port has (a multi-queue port keeps `mq`).
    pub tx_queues: Option<u32>,
}

/// `p`'s range on this port: rings and queues up to the NIC's maximum.
pub fn port_range(p: &Param, port: &Port) -> (i64, i64) {
    match port.max.get(p.name) {
        Some(m) => (p.min.min(*m), (*m).min(p.max).max(p.min.min(*m))),
        None => (p.min, p.max),
    }
}

/// CPUs of the port's NUMA node (all CPUs when unknown).
fn local_cpus(m: &Machine, port: &Port) -> u32 {
    port.numa_node
        .and_then(|n| m.sys.numa.iter().find(|x| x.id == n))
        .map(|n| u32::try_from(n.cpus.len()).unwrap_or(u32::MAX))
        .filter(|n| *n > 0)
        .unwrap_or(m.sys.cpus.max(1))
}

/// What `profile` wants of `port`, by key. Keys the port lacks, and every
/// key under the conservative profile but the offloads and `rp_filter`,
/// have no recommendation.
pub fn recommend_port(profile: Profile, m: &Machine, port: &Port) -> BTreeMap<&'static str, Rec> {
    use Profile::*;
    let mut out = BTreeMap::new();
    let has = |k: &str| port.now.get(k).is_some_and(Option::is_some);
    let p = profile.id().to_owned();
    let kernel = recommend(profile, m);
    for prm in PORT_PARAMS {
        let k = prm.name;
        // Offloads and flow control are read from elsewhere; they have no
        // value in `now` but are always shown.
        if !prm.ethernet && !has(k) {
            continue;
        }
        let r = match k {
            "gro" => Some(why("gro", 1, &[])),
            "lro" => Some(why("lro", 0, &[])),
            "rp_filter" => kernel
                .get("net.ipv4.conf.all.rp_filter")
                .map(|r| why(r.why_id, r.value, &[])),
            _ if profile == Conservative => None,
            "rx_ring" | "tx_ring" => port.max.get(k).map(|max| {
                let v = match profile {
                    Throughput => *max,
                    Latency => (*max).min(1024),
                    _ => (*max).min(2048),
                };
                why(
                    "ring",
                    v,
                    &[("profile", p.clone()), ("max", max.to_string())],
                )
            }),
            "combined_channels" | "rx_channels" | "tx_channels" => port.max.get(k).map(|max| {
                let cpus = i64::from(local_cpus(m, port));
                why(
                    "queues",
                    cpus.min(*max).max(1),
                    &[("cpus", cpus.to_string()), ("max", max.to_string())],
                )
            }),
            "adaptive_rx" | "adaptive_tx" => Some(match profile {
                Latency => why("coalesce_off", 0, &[]),
                _ => why("coalesce_adaptive", 1, &[]),
            }),
            "rx_usecs" | "tx_usecs" if profile == Latency => Some(why("coalesce_off", 0, &[])),
            "rx_pause" | "tx_pause" => Some(why("pause", 0, &[])),
            "txqueuelen" => Some(why("default", 1000, &[])),
            // A virtual port (veth, dummy) sends at once, with no queue
            // of its own: fq_codel there only costs (netns_forward: −7 %).
            "irq_affinity" => Some(why("irq_local", 1, &[("cpus", local_cpus(m, port).to_string())])),
            // RPS spreads a single-queue port's work over the node's CPUs;
            // with RSS (several queues) it only adds work (MikroTik, kernel).
            "rps" => Some(if port.tx_queues.unwrap_or(1) > 1 {
                why("rps_off", 0, &[])
            } else {
                why("rps_on", 1, &[])
            }),
            "xps" => Some(if port.tx_queues.unwrap_or(1) > 1 {
                why("xps_on", 1, &[])
            } else {
                why("xps_off", 0, &[])
            }),
            "qdisc" => Some(if port.now.get("qdisc").copied().flatten() == Some(NOQUEUE) {
                why("qdisc_noqueue", NOQUEUE, &[])
            } else if port.tx_queues.unwrap_or(1) > 1 {
                why("qdisc_mq", 3, &[])
            } else {
                why("qdisc_fq_codel", 0, &[])
            }),
            _ => None,
        };
        if let Some(r) = r {
            out.insert(k, r);
        }
    }
    out
}

/// What `profile` wants of the CPU settings `now` (keys with `None` are
/// knobs this machine lacks, except `cpu_dma_latency`, which is `None`
/// while no limit is held).
pub fn recommend_cpu(
    profile: Profile,
    now: &BTreeMap<String, Option<i64>>,
) -> BTreeMap<&'static str, Rec> {
    let mut out = BTreeMap::new();
    if profile == Profile::Conservative {
        return out;
    }
    if now.get("governor").is_some_and(Option::is_some) {
        out.insert("governor", why("governor", 0, &[]));
    }
    if profile == Profile::Latency {
        out.insert("cpu_dma_latency", why("c_states", 1, &[]));
    }
    if now.get("hw_watchdog").is_some_and(Option::is_some) {
        out.insert("hw_watchdog", why("watchdog", 1, &[]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_hal::tuning::{NumaNode, SystemInfo};
    use corerouter_model::tuning::port_param;

    fn machine() -> Machine {
        Machine {
            sys: SystemInfo {
                cpus: 16,
                mem_kib: 32 << 20,
                kernel: "6.8.0".into(),
                numa: vec![
                    NumaNode { id: 0, cpus: (0..6).collect(), mem_kib: None },
                    NumaNode { id: 1, cpus: (6..16).collect(), mem_kib: None },
                ],
                ..SystemInfo::default()
            },
            nics: Vec::new(),
            irqbalance: false,
        }
    }

    fn port() -> Port {
        let now = [
            ("rx_ring", 512),
            ("tx_ring", 512),
            ("combined_channels", 4),
            ("adaptive_rx", 1),
            ("rx_usecs", 50),
            ("txqueuelen", 1000),
            ("qdisc", 3),
            ("rp_filter", 1),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), Some(v)))
        .collect();
        let max = [("rx_ring", 4096), ("tx_ring", 4096), ("combined_channels", 63)]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        Port {
            name: "ether1".into(),
            now,
            max,
            numa_node: Some(1),
            tx_queues: Some(4),
        }
    }

    #[test]
    fn port_profiles_follow_the_nic_and_the_numa_node() {
        let m = machine();
        let b = recommend_port(Profile::Balanced, &m, &port());
        assert_eq!(b["rx_ring"].value, 2048);
        assert_eq!(b["combined_channels"].value, 10, "the CPUs of NUMA node 1");
        assert_eq!(b["qdisc"].value, 3, "multi-queue: mq");
        assert_eq!(b["gro"].value, 1);
        assert_eq!(b["lro"].value, 0);
        assert_eq!(b["rx_pause"].value, 0);
        assert_eq!(b["rp_filter"].value, 2, "as the kernel's all.rp_filter");
        assert!(!b.contains_key("rx_usecs"), "adaptive decides");
        assert!(!b.contains_key("tx_channels"), "this NIC has combined queues");
        let t = recommend_port(Profile::Throughput, &m, &port());
        assert_eq!(t["rx_ring"].value, 4096);
        let l = recommend_port(Profile::Latency, &m, &port());
        assert_eq!((l["adaptive_rx"].value, l["rx_usecs"].value), (0, 0));
        let c = recommend_port(Profile::Conservative, &m, &port());
        assert!(!c.contains_key("rx_ring"));
        assert!(c.contains_key("lro"));
        // Every value fits the port's range.
        for profile in Profile::ALL {
            for (k, r) in recommend_port(profile, &m, &port()) {
                let (lo, hi) = port_range(port_param(k).unwrap(), &port());
                assert!((lo..=hi).contains(&r.value), "{k} {profile:?} {}", r.value);
                assert!(!r.why.contains('{'), "{}", r.why);
            }
        }
        // CPU and IRQ (G1.26c): multi-queue → IRQs on the node, XPS, no RPS.
        let mut cpu_port = port();
        for k in ["irq_affinity", "rps", "xps"] {
            cpu_port.now.insert(k.into(), Some(0));
        }
        let r = recommend_port(Profile::Balanced, &m, &cpu_port);
        assert_eq!((r["irq_affinity"].value, r["rps"].value, r["xps"].value), (1, 0, 1));
        cpu_port.tx_queues = Some(1);
        let r = recommend_port(Profile::Balanced, &m, &cpu_port);
        assert_eq!((r["rps"].value, r["xps"].value), (1, 0));
        let mut cpu: BTreeMap<String, Option<i64>> = BTreeMap::new();
        cpu.insert("governor".into(), Some(1));
        cpu.insert("hw_watchdog".into(), None);
        let c = recommend_cpu(Profile::Latency, &cpu);
        assert_eq!(c["governor"].value, 0);
        assert_eq!(c["cpu_dma_latency"].value, 1);
        assert!(!c.contains_key("hw_watchdog"), "no watchdog device");
        assert!(recommend_cpu(Profile::Conservative, &cpu).is_empty());
        // A single-queue port gets fq_codel; a virtual one keeps noqueue.
        let mut one = port();
        one.tx_queues = Some(1);
        assert_eq!(recommend_port(Profile::Balanced, &m, &one)["qdisc"].value, 0);
        one.now.insert("qdisc".into(), Some(NOQUEUE));
        assert_eq!(recommend_port(Profile::Balanced, &m, &one)["qdisc"].value, NOQUEUE);
    }
}
