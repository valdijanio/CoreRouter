//! Virtual lab backend: deterministic fake ports and counters.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use corerouter_model::firewall::DynamicAddress;
use corerouter_model::{Config, FlowControl, IfName, InterfaceKind, ItemId, RouteEntry};

use crate::dhcp::{
    Datagram, Datagram6, Dest, Dhcp6Port, DhcpPort, SharedResponder, SharedResponder6, eui64,
    lab_net, lab_router_mac, link_local,
};
use crate::drift::{self, LinkSnap, Snapshot};
use crate::nic::{
    CablePair, CableTest, CableTestResult, CounterGroup, EthernetMonitor, LinkCounters,
    NicHardware, Offload, base_t_modes, mode_speed,
};
use crate::sff::{self, SfpModule};
use crate::tuning::{
    CpuTuning, KernelStats, NumaNode, PortTuning, SoftnetCpu, Sysctls, SystemInfo,
};
use crate::{
    DynamicChange, Features, Hal, HalError, Learned, LinkErrors, LinkInfo, LinkState, SharedProber,
    SimProber,
};

/// Lab ports that pretend to be NVIDIA ConnectX-6 Dx ports (G2.4): the
/// first in the default `legacy` eSwitch mode (software flowtable only,
/// with the command to switch), the second a switchdev uplink
/// representor with `hw-tc-offload` on.
pub const LAB_MLX5: [&str; 2] = ["ether7", "ether8"];
/// The one of [`LAB_MLX5`] in switchdev mode.
pub const LAB_SWITCHDEV: [&str; 1] = ["ether8"];

#[derive(Clone)]
pub struct VirtualHal {
    ports: Vec<IfName>,
    applied: Config,
    ticks: u64,
    /// Busy and total CPU ticks handed out by `resources` so far.
    cpu: (u64, u64),
    /// `ticks` when the XDP counters were last zeroed (G2.5a).
    xdp_zero: u64,
    applies: u64,
    /// The nftables script the last firewall change would have loaded
    /// (the lab records it; nothing runs it).
    ruleset: Option<String>,
    dynamic: Vec<DynamicAddress>,
    /// Diagnostic tools: the simulated network unless the app swaps in the
    /// host's ICMP (`corerouter-daemon --lab-ping host`).
    prober: SharedProber,
    /// Simulated DHCP server answering the lab's DHCP clients (G4.7).
    dhcp: Option<SharedResponder>,
    /// Simulated DHCPv6 server (G4.7b).
    dhcp6: Option<SharedResponder6>,
    /// Simulated BNG answering the lab's PPPoE clients (G3.9ga).
    pppoe: Option<crate::pppoe_client::SharedPppoeLab>,
    /// Simulated hosts asking the router's DHCP server (G4.2a).
    dhcp_hosts: Option<crate::dhcp_server::SharedLabClients>,
    /// Simulated DHCPv6 clients (G4.2c).
    dhcp6_hosts: Option<crate::dhcp_server::SharedLabClients6>,
    /// Times each port was enabled again (each one is a simulated link
    /// down and up, G1.19).
    reenabled: BTreeMap<IfName, u32>,
    /// Lab connections killed (G2.2), by id.
    killed: std::collections::BTreeSet<u32>,
    /// CGNAT blocks the engine installed (G2.3c), by (pool, subscriber).
    blocks: BTreeMap<(corerouter_model::ItemId, std::net::Ipv4Addr), corerouter_model::cgnat::Slot>,
    /// The CGNAT set `full` the engine keeps (G2.7) and the polls of the
    /// refusals the lab makes up for it.
    cgnat_full: Vec<std::net::Ipv4Addr>,
    exhausted_polls: u64,
    /// The lab's "kernel" (G1.3): what each apply left, which a test (or
    /// a lab script) can change behind CoreRouter's back to make drift.
    kernel: LabKernel,
    /// The lab's made-up OS log (G4.8b).
    oslog: crate::oslog::LabOsLog,
    /// The simulated shaper's counters (G4.9g).
    shaper: crate::queue::lab::LabShaper,
    /// The lab's neighbor tables (G1.27d).
    neigh: crate::lab_neigh::LabNeigh,
}

/// A lab port's own settings (G1.26b); `None`: the NIC has no such knob.
const LAB_PORT: &[(&str, Option<i64>)] = &[
    ("rx_ring", Some(1024)),
    ("tx_ring", Some(1024)),
    ("combined_channels", Some(4)),
    ("rx_channels", None),
    ("tx_channels", None),
    ("adaptive_rx", Some(1)),
    ("rx_usecs", Some(50)),
    ("adaptive_tx", Some(1)),
    ("tx_usecs", Some(50)),
    ("txqueuelen", Some(1000)),
    ("qdisc", Some(3)),
    ("rp_filter", Some(0)),
    ("irq_affinity", Some(0)),
    ("rps", Some(0)),
    ("xps", Some(0)),
];

/// The lab server's CPU settings (G1.26c): schedutil, no C-state limit, a
/// watchdog nobody holds.
const LAB_CPU: &[(&str, i64)] = &[("governor", 1), ("hw_watchdog", 0)];

/// Memory of the lab's made-up server (32 GiB).
const LAB_MEM_KIB: u64 = 32 << 20;

/// A stock kernel's value of `name` on the lab's server (6.8, HZ=250),
/// already forwarding (a router's boot scripts turn that on).
fn lab_sysctl_default(name: &str) -> Option<i64> {
    use corerouter_model::tuning::{INT_MAX, param};
    Some(match name {
        "net.ipv4.ip_forward" | "net.ipv6.conf.all.forwarding" => 1,
        "net.core.netdev_budget_usecs" => 8000,
        "net.netfilter.nf_conntrack_max" | "net.netfilter.nf_conntrack_buckets" => 262_144,
        "net.ipv4.route.max_size" | "net.ipv6.route.max_size" => INT_MAX,
        "vm.min_free_kbytes" => 67_584,
        "net.ipv4.tcp_max_syn_backlog" => 1024,
        _ => param(name)?.default?,
    })
}

/// Handle on the virtual lab's data plane, shared with the [`VirtualHal`].
pub type LabKernel = Arc<Mutex<Snapshot>>;

impl std::fmt::Debug for VirtualHal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualHal")
            .field("ports", &self.ports)
            .field("applies", &self.applies)
            .field("prober", &self.prober.describe())
            .finish_non_exhaustive()
    }
}

impl VirtualHal {
    /// `ports` virtual Ethernet ports named `ether1..=etherN` (RouterOS style).
    pub fn new(ports: u8) -> Self {
        let ports: Vec<IfName> = (1..=ports)
            .filter_map(|i| format!("ether{i}").parse().ok())
            .collect();
        let kernel = Snapshot {
            links: ports
                .iter()
                .map(|p| {
                    let link = LinkSnap {
                        up: true,
                        mtu: 1500,
                        master: None,
                    };
                    (p.clone(), link)
                })
                .collect(),
            ..Snapshot::default()
        };
        Self {
            ports,
            applied: Config::default(),
            ticks: 0,
            cpu: (0, 0),
            xdp_zero: 0,
            applies: 0,
            ruleset: None,
            dynamic: Vec::new(),
            prober: Arc::new(SimProber::default()),
            dhcp: None,
            dhcp6: None,
            pppoe: None,
            dhcp_hosts: None,
            dhcp6_hosts: None,
            reenabled: BTreeMap::new(),
            killed: std::collections::BTreeSet::new(),
            blocks: BTreeMap::new(),
            cgnat_full: Vec::new(),
            exhausted_polls: 0,
            kernel: Arc::new(Mutex::new(kernel)),
            oslog: crate::oslog::LabOsLog::default(),
            neigh: crate::lab_neigh::LabNeigh::default(),
            shaper: crate::queue::lab::LabShaper::default(),
        }
    }

    /// The lab's data plane, to change it behind CoreRouter's back.
    pub fn kernel(&self) -> LabKernel {
        Arc::clone(&self.kernel)
    }

    /// The lab kernel after `from` → `to`: like a real one, only what
    /// changed is touched, so drift elsewhere stays.
    ///
    /// Only the parts whose inputs changed are recomputed: links and
    /// addresses depend on the interfaces and addresses, routes also on the
    /// routes. When only routes changed, only the changed entries are
    /// resolved (the expected state of both whole configs was computed on
    /// every apply: 1000 routes cost ~120 µs per commit, **medido**).
    fn carry(&self, from: &Config, to: &Config) {
        // A comment never reaches the kernel (G0.22: `interface.set
        // comment` with 10 000 routes recomputed them all).
        let ifaces = corerouter_model::sections::interfaces_changed(from, to);
        let addrs = ifaces || from.ip.addresses != to.ip.addresses;
        let routes = from.ip.routes != to.ip.routes;
        if !addrs && !routes {
            return;
        }
        let mut k = self.kernel.lock().unwrap_or_else(PoisonError::into_inner);
        if ifaces {
            let (a, b) = (drift::expected_links(from), drift::expected_links(to));
            for name in a.keys().filter(|n| !b.contains_key(*n)) {
                if drift::recreatable(from, name) {
                    k.links.remove(name);
                }
            }
            for (name, link) in &b {
                if a.get(name) != Some(link) {
                    k.links.insert(name.clone(), link.clone());
                }
            }
        }
        if addrs {
            let (a, b) = (drift::active_addresses(from), drift::active_addresses(to));
            for x in a.difference(&b) {
                k.addresses.remove(x);
            }
            k.addresses.extend(b.difference(&a).cloned());
        }
        // Routes resolve through interfaces and addresses: with those
        // unchanged, an unchanged route entry resolves the same.
        let (a, b) = if addrs {
            (drift::kernel_routes(from), drift::kernel_routes(to))
        } else {
            fn by_id(c: &Config) -> BTreeMap<ItemId, &RouteEntry> {
                c.ip.routes.iter().map(|r| (r.id, r)).collect()
            }
            let (old, new) = (by_id(from), by_id(to));
            let gone = old.iter().filter(|(id, r)| new.get(id) != Some(r));
            let came = new.iter().filter(|(id, r)| old.get(id) != Some(r));
            (
                drift::kernel_routes_of(from, gone.map(|(_, r)| *r)),
                drift::kernel_routes_of(to, came.map(|(_, r)| *r)),
            )
        };
        for r in a.difference(&b) {
            // Another entry of `to` may still put the same route there.
            let kept = !addrs
                && drift::kernel_routes_of(
                    to,
                    to.ip
                        .routes
                        .iter()
                        .filter(|e| e.dst_address.trunc() == r.dst),
                )
                .contains(r);
            if !kept {
                k.routes.remove(r);
            }
        }
        k.routes.extend(b.difference(&a).cloned());
    }

    /// Answer DHCP clients with `server` (a test's own scenario) instead of
    /// the lab server the engine offers.
    pub fn with_dhcp_server(mut self, server: SharedResponder) -> Self {
        self.dhcp = Some(server);
        self
    }

    /// Put `hosts` behind the lab ports instead of the lab's own (G4.2a).
    pub fn with_dhcp_hosts(mut self, hosts: crate::dhcp_server::SharedLabClients) -> Self {
        self.dhcp_hosts = Some(hosts);
        self
    }

    /// Answer DHCPv6 clients with `server` instead of the lab's.
    pub fn with_dhcp6_server(mut self, server: SharedResponder6) -> Self {
        self.dhcp6 = Some(server);
        self
    }

    /// MAC of `name`: the configured one, else the one the lab invents.
    fn mac_of(&self, name: &IfName) -> [u8; 6] {
        let configured = self
            .applied
            .interfaces
            .get(name)
            .and_then(|i| i.mac)
            .map(|m| m.0);
        configured.unwrap_or_else(|| {
            let h = name
                .as_str()
                .bytes()
                .fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(u32::from(b)));
            let [a, b, c, d] = h.to_be_bytes();
            [0x02, 0x00, a, b, c, d]
        })
    }

    /// Probe with `prober` instead of the simulated network.
    pub fn with_prober(mut self, prober: SharedProber) -> Self {
        self.prober = prober;
        self
    }

    pub fn applied(&self) -> &Config {
        &self.applied
    }

    pub fn apply_count(&self) -> u64 {
        self.applies
    }

    /// The firewall script of the last apply that changed the firewall.
    pub fn ruleset(&self) -> Option<&str> {
        self.ruleset.as_deref()
    }

    /// The CGNAT table (G2.3) the last applied config would load.
    pub fn cgnat_script(&self) -> String {
        corerouter_firewall::cgnat::render(&self.applied.ip.cgnat, None).script
    }

    pub fn dynamic(&self) -> &[DynamicAddress] {
        &self.dynamic
    }

    /// Position of a lab port (`ether3` → 2).
    fn port_index(&self, name: &IfName) -> Option<usize> {
        self.ports.iter().position(|p| p == name)
    }

    /// Fastest rate of a lab port: the last one is a 10G port, the rest 1G.
    fn port_speed(&self, index: usize) -> u32 {
        if self.is_sfp(index) { 10_000 } else { 1000 }
    }

    /// The last port (of two or more) is an SFP+ cage with a 10GBASE-SR
    /// module in it (G1.20); the others are copper.
    fn is_sfp(&self, index: usize) -> bool {
        index + 1 == self.ports.len() && index > 0
    }

    /// Link modes lab port `index` can do.
    fn port_modes(&self, index: usize) -> Vec<String> {
        if self.is_sfp(index) {
            vec!["1000baseX/Full".into(), "10000baseSR/Full".into()]
        } else {
            base_t_modes(self.port_speed(index))
        }
    }

    /// An Ethernet port of the lab, by name, and its position.
    fn lab_port(&self, name: &IfName) -> Result<(usize, &corerouter_model::Interface), HalError> {
        let iface = self
            .applied
            .interfaces
            .get(name)
            .ok_or_else(|| self.missing(name))?;
        match (&iface.kind, self.port_index(name)) {
            (InterfaceKind::Ethernet, Some(i)) => Ok((i, iface)),
            _ => Err(HalError::Unsupported(format!(
                "'{name}' is a {}, not an Ethernet port",
                iface.kind.label()
            ))),
        }
    }

    /// The counters `poll` reported last (it advances them; this does not).
    fn sample(&self, name: &IfName) -> Option<LinkState> {
        // Each port's traffic grows with its position, so ports differ.
        let t = self.ticks;
        self.applied
            .interfaces
            .values()
            .enumerate()
            .find(|(_, i)| i.name == *name)
            .map(|(i, iface)| {
                let up = !iface.disabled;
                let rate = if up { 1_000 * (i as u64 + 1) } else { 0 };
                // Traffic swings between half and one and a half times the
                // mean (a triangle of the poll count, a phase per port), so
                // the graphs (G4.5) move; still strictly growing.
                let swing = |t: u64, phase: u64| {
                    let x = t.wrapping_add(phase) % 240;
                    2 * t + if x < 120 { x } else { 240 - x }
                };
                let rx = swing(t, i as u64 * 37);
                let tx = swing(t, i as u64 * 53 + 90);
                LinkState {
                    name: iface.name.clone(),
                    running: up,
                    rx_bytes: rate.wrapping_mul(rx).wrapping_mul(750),
                    tx_bytes: rate.wrapping_mul(tx).wrapping_mul(450),
                    rx_packets: rate.wrapping_mul(t),
                    tx_packets: rate.wrapping_mul(t) / 2,
                    kind: iface.kind.label().to_owned(),
                    mtu: u32::from(iface.mtu),
                    mac: iface.mac.map(|m| m.to_string()),
                    unmanaged: None,
                    // Same numbers as `counters` (its `interface` group).
                    errors: Some(LinkErrors {
                        rx_errors: rate.wrapping_mul(t) / 500_000,
                        tx_errors: 0,
                        rx_dropped: rate.wrapping_mul(t) / 250_000,
                        tx_dropped: 0,
                    }),
                }
            })
    }

    fn missing(&self, name: &IfName) -> HalError {
        HalError::Rejected(format!("no link '{name}' in the virtual lab"))
    }
}

/// Factory MAC of lab port `index` (what `discover_links` reports).
fn lab_mac(index: usize) -> String {
    format!("02:00:00:00:00:{:02X}", (index + 1) & 0xFF)
}

impl Default for VirtualHal {
    fn default() -> Self {
        Self::new(8)
    }
}

impl Hal for VirtualHal {
    fn describe(&self) -> String {
        format!("virtual lab ({} ports)", self.ports.len())
    }

    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        Ok(self
            .ports
            .iter()
            .enumerate()
            .map(|(i, name)| LinkInfo {
                name: name.clone(),
                mac: Some(lab_mac(i)),
                mtu: 1500,
                up: true,
            })
            .collect())
    }

    fn cgnat_blocks(&mut self, changes: &[crate::cgnat::BlockChange]) -> Result<(), HalError> {
        for c in changes {
            match c.slot {
                Some(slot) => {
                    self.blocks.insert((c.pool, c.subscriber), slot);
                }
                None => {
                    self.blocks.remove(&(c.pool, c.subscriber));
                }
            }
        }
        Ok(())
    }

    fn eswitch(&mut self, name: &IfName) -> Result<crate::fastpath::Eswitch, HalError> {
        use crate::fastpath::{Eswitch, EswitchMode};
        let iface = self
            .applied
            .interfaces
            .get(name)
            .ok_or_else(|| self.missing(name))?;
        if iface.kind != InterfaceKind::Ethernet || self.port_index(name).is_none() {
            return Ok(Eswitch {
                notes: vec!["a software interface: its ports' cards decide".into()],
                ..Eswitch::default()
            });
        }
        let Some(i) = LAB_MLX5.iter().position(|p| *p == name.as_str()) else {
            return Ok(Eswitch {
                driver: Some("corerouter-virt".into()),
                notes: vec!["the lab's virtual NIC has no flow offload".into()],
                ..Eswitch::default()
            });
        };
        let switchdev = LAB_SWITCHDEV.contains(&name.as_str());
        Ok(Eswitch {
            driver: Some("mlx5_core".into()),
            firmware: Some("22.39.1002".into()),
            devlink: Some(format!("pci/0000:3b:00.{i}")),
            mode: Some(if switchdev {
                EswitchMode::Switchdev
            } else {
                EswitchMode::Legacy
            }),
            representor: switchdev,
            hw_tc_offload: Some(switchdev),
            notes: vec!["simulated ConnectX-6 Dx (virtual lab)".into()],
        })
    }

    fn fastpath_state(&mut self) -> crate::fastpath::FastPathState {
        let fp = &self.applied.ip.fastpath;
        let devices = crate::lab_conntrack::fastpath_ports(&self.applied);
        if !fp.enabled || devices.is_empty() {
            return crate::fastpath::FastPathState::default();
        }
        let capable = devices.iter().any(|d| LAB_SWITCHDEV.contains(&d.as_str()));
        let asked = fp.hw_offload != corerouter_model::fastpath::HwOffload::No;
        crate::fastpath::FastPathState {
            active: true,
            hardware: asked && capable,
            note: (asked && !capable).then(|| {
                "hardware offload refused (Operation not supported): no port in switchdev mode; running in software".into()
            }),
            devices,
        }
    }

    fn cgnat_full(&mut self, subscribers: &[std::net::Ipv4Addr]) -> Result<(), HalError> {
        self.cgnat_full = subscribers.to_vec();
        Ok(())
    }

    /// The lab's exhaustion: every 10th poll, one in three of the nearly
    /// full subscribers (the same ones each time) had 4 new connections
    /// refused and got 2 ICMP (the rate limit held back the rest).
    fn cgnat_exhausted(
        &mut self,
    ) -> (
        Vec<(std::net::Ipv4Addr, crate::cgnat::Hit)>,
        crate::cgnat::ExhaustionStats,
    ) {
        self.exhausted_polls = self.exhausted_polls.wrapping_add(1);
        if !self.exhausted_polls.is_multiple_of(10) {
            return (Vec::new(), crate::cgnat::ExhaustionStats::default());
        }
        let hits: Vec<_> = self
            .cgnat_full
            .iter()
            .filter(|a| u32::from(**a).is_multiple_of(3))
            .map(|a| {
                (
                    *a,
                    crate::cgnat::Hit {
                        refused: 4,
                        icmp: 2,
                    },
                )
            })
            .collect();
        let n = hits.len() as u64;
        (
            hits,
            crate::cgnat::ExhaustionStats {
                seen: n * 6,
                refused: n * 4,
                icmp: n * 2,
                limited: n * 2,
                untracked: 0,
                overrun: 0,
            },
        )
    }

    fn cgnat_waiting(&mut self) -> Vec<crate::cgnat::Waiting> {
        crate::lab_conntrack::waiting(&self.applied, &self.blocks)
    }

    fn connections(&mut self) -> Result<Vec<crate::conntrack::Conn>, HalError> {
        Ok(crate::lab_conntrack::table(
            &self.applied,
            &self.killed,
            &self.blocks,
        ))
    }

    /// A lab that looks alive: the load and the table follow slow waves of
    /// the poll count (deterministic, so tests can count on it).
    fn os_log(
        &mut self,
        now: Option<u64>,
        max: usize,
    ) -> Result<crate::oslog::OsLogBatch, HalError> {
        Ok(self.oslog.read(now, max))
    }

    fn resources(&mut self) -> Option<crate::resources::Resources> {
        let t = self.ticks;
        let wave = |period: u64, amp: u64| {
            let x = t % period;
            let half = period / 2;
            amp * (if x < half { x } else { period - x }) / half.max(1)
        };
        // 16 CPUs at 100 ticks/s: busy ticks grow 160..=1440 a poll.
        self.cpu.0 = self.cpu.0.wrapping_add(160 + wave(600, 1280));
        self.cpu.1 = self.cpu.1.wrapping_add(1600);
        Some(crate::resources::Resources {
            cpu_busy: self.cpu.0,
            cpu_total: self.cpu.1,
            mem_total: LAB_MEM_KIB * 1024,
            mem_available: LAB_MEM_KIB * 1024 / 2 + wave(3600, 4 << 30),
            conntrack: Some(200_000 + wave(900, 80_000)),
            conntrack_max: Some(1 << 20),
        })
    }

    fn resource_sampler(&self) -> Result<Box<dyn crate::system_resource::ResourceSampler>, String> {
        Ok(Box::new(crate::system_resource::LabSampler::new()))
    }

    fn conntrack_events(&mut self) -> Result<Box<dyn crate::conntrack::EventSource>, HalError> {
        let table = crate::lab_conntrack::table(&self.applied, &self.killed, &self.blocks);
        Ok(Box::new(crate::lab_flow::LabEvents::new(table)))
    }

    fn connection_stats(&mut self) -> Result<crate::conntrack::Stats, HalError> {
        let n = crate::lab_conntrack::table(&self.applied, &self.killed, &self.blocks).len();
        Ok(crate::lab_conntrack::stats(n))
    }

    fn connections_kill(&mut self, conns: &[crate::conntrack::Conn]) -> Result<usize, HalError> {
        let live: std::collections::BTreeSet<u32> =
            crate::lab_conntrack::table(&self.applied, &self.killed, &self.blocks)
                .iter()
                .map(|c| c.id)
                .collect();
        let mut n = 0;
        for c in conns {
            if live.contains(&c.id) && self.killed.insert(c.id) {
                n += 1;
            }
        }
        Ok(n)
    }

    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        if corerouter_firewall::nft::changed(from, to) {
            self.ruleset = Some(corerouter_firewall::script(to, &self.dynamic));
        }
        for (name, iface) in &to.interfaces {
            let was_off = from.interfaces.get(name).is_some_and(|i| i.disabled);
            if was_off && !iface.disabled {
                let n = self.reenabled.entry(name.clone()).or_insert(0);
                *n = n.saturating_add(1);
            }
        }
        self.carry(from, to);
        self.neigh.sync(to);
        self.applied = to.clone();
        self.applies = self.applies.saturating_add(1);
        Ok(())
    }

    fn neighbors(&mut self) -> Result<Vec<crate::neigh::Neighbor>, HalError> {
        Ok(self.neigh.snapshot())
    }

    fn neighbor_feed(&mut self) -> Result<Box<dyn crate::neigh::NeighborFeed>, HalError> {
        Ok(self.neigh.feed())
    }

    fn neighbor_remove(&mut self, items: &[(IfName, std::net::IpAddr)]) -> Result<usize, HalError> {
        Ok(self.neigh.remove(items))
    }

    fn neighbor_static(&mut self, ops: &[crate::neigh::StaticNeigh]) -> Result<(), HalError> {
        self.neigh.statics(ops);
        Ok(())
    }

    fn arp_pinger(&mut self, name: &IfName) -> Result<Box<dyn crate::neigh::ArpPinger>, HalError> {
        if !self.applied.interfaces.contains_key(name) {
            return Err(self.missing(name));
        }
        Ok(self.neigh.pinger(name))
    }

    /// A made-up server (G1.26): 16 CPUs in two NUMA nodes, 32 GiB.
    fn system_info(&mut self) -> Result<SystemInfo, HalError> {
        let node = |id: u32| NumaNode {
            id,
            cpus: (id * 8..id * 8 + 8).collect(),
            mem_kib: Some(LAB_MEM_KIB / 2),
        };
        Ok(SystemInfo {
            cpus: 16,
            cpu_model: Some("Virtual CPU (lab)".into()),
            numa: vec![node(0), node(1)],
            mem_kib: LAB_MEM_KIB,
            kernel: "6.8.0-corerouter-lab".into(),
        })
    }

    /// What the applied config set, else what a stock kernel has.
    fn sysctls(&mut self, names: &[&str]) -> Result<Sysctls, HalError> {
        Ok(names
            .iter()
            .map(|n| {
                let set = self.applied.system.tuning.sysctl.get(*n).copied();
                ((*n).to_owned(), set.or_else(|| lab_sysctl_default(n)))
            })
            .collect())
    }

    /// A lab port's settings: what the applied config set, else a 4-queue
    /// NIC with 1024-descriptor rings (max 4096, 8 queues).
    fn port_tuning(&mut self, name: &IfName) -> Result<PortTuning, HalError> {
        self.lab_port(name)?;
        let mut values: BTreeMap<String, Option<i64>> = LAB_PORT
            .iter()
            .map(|(k, v)| ((*k).to_owned(), *v))
            .collect();
        if let Some(set) = self.applied.system.tuning.ports.get(name) {
            for (k, v) in set {
                if values.get(k).is_some_and(Option::is_some) {
                    values.insert(k.clone(), Some(*v));
                }
            }
        }
        let max = [
            ("rx_ring", 4096),
            ("tx_ring", 4096),
            ("combined_channels", 8),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        // Four queue IRQs per port; the kernel's spread, or one per CPU
        // of the port's NUMA node once `irq_affinity` asks for it.
        let index = self.port_index(name).unwrap_or(0);
        let node = u32::from(index >= self.ports.len() / 2);
        let spread = values.get("irq_affinity").copied().flatten() == Some(1);
        let irqs = (0..4u32)
            .map(|q| {
                let irq = 100 + u32::try_from(index).unwrap_or(0) * 8 + q;
                let cpus = if spread {
                    (node * 8 + q).to_string()
                } else {
                    "0-15".to_owned()
                };
                (irq, cpus)
            })
            .collect();
        Ok(PortTuning {
            values,
            max,
            notes: vec!["separate rx/tx queues: the lab NIC has combined ones only".into()],
            irqs,
        })
    }

    /// The lab "booted" its image A with the stock command line; what the
    /// config sets for the next boot shows up only after a reboot, which
    /// the lab never does.
    fn boot_cmdline(&mut self) -> Result<String, HalError> {
        Ok("BOOT_IMAGE=/boot/corerouter-a root=/dev/vda2 ro quiet".into())
    }

    fn cpu_tuning(&mut self) -> Result<CpuTuning, HalError> {
        let mut values: BTreeMap<String, Option<i64>> = LAB_CPU
            .iter()
            .map(|(k, v)| ((*k).to_owned(), Some(*v)))
            .collect();
        values.insert("cpu_dma_latency".into(), None);
        for (k, v) in &self.applied.system.tuning.cpu {
            values.insert(k.clone(), Some(*v));
        }
        Ok(CpuTuning {
            values,
            irqbalance: true,
            notes: Vec::new(),
        })
    }

    /// The lab's XDP filter: attached natively on its Ethernet ports,
    /// generically elsewhere, with counters that grow with the polls in
    /// proportion to what the filter has turned on, and the first blocked
    /// prefixes as the top sources.
    fn xdp_status(&mut self, top: usize) -> Result<crate::xdp::XdpStatus, HalError> {
        use crate::xdp::{XdpPlan, XdpPort, XdpStatus, XdpTop};
        let plan = XdpPlan::of(&self.applied, &self.dynamic);
        let t = self.ticks.saturating_sub(self.xdp_zero);
        let on = |b: bool, n: u64| if b { t.saturating_mul(n) } else { 0 };
        let mut ports = Vec::new();
        for (name, mode) in &plan.interfaces {
            let ether = self
                .applied
                .interfaces
                .get(name)
                .is_some_and(|i| i.kind == InterfaceKind::Ethernet);
            let generic = *mode == corerouter_model::xdp::XdpMode::Generic;
            let (active, note) = if ether && !generic {
                ("native", None)
            } else if generic {
                ("generic", None)
            } else {
                (
                    "generic",
                    Some("native XDP needs a NIC driver; running generic".to_owned()),
                )
            };
            let packets = [
                on(true, 12_000),
                on(!plan.block.is_empty(), 3_000),
                on(plan.rate_limit > 0, 500),
                on(plan.drop_malformed, 40),
                on(plan.drop_invalid_tcp_flags, 15),
                on(plan.fast_nat, 9_000),
            ];
            ports.push(XdpPort {
                interface: name.clone(),
                mode: *mode,
                active: Some(active),
                note,
                counters: packets
                    .iter()
                    .map(|p| (*p, p.saturating_mul(800)))
                    .collect(),
            });
        }
        let lists = &self.applied.ip.xdp.filter.block_lists;
        let tops = plan
            .block
            .iter()
            .take(top)
            .enumerate()
            .map(|(i, (net, list))| {
                let packets = t.saturating_mul(600) / (i as u64 + 1);
                XdpTop {
                    address: net.network(),
                    packets,
                    bytes: packets.saturating_mul(800),
                    reason: "blocked",
                    list: lists.get(*list as usize).cloned(),
                    last_secs: 0,
                }
            })
            .filter(|t| t.packets > 0)
            .collect();
        Ok(XdpStatus {
            unavailable: None,
            ports,
            top: tops,
            block_prefixes: plan.block.len(),
            fast_nat_flows: 0,
            fast_nat_misses: Vec::new(),
            allow_prefixes: plan.allow.len(),
        })
    }

    fn xdp_reset(&mut self) -> Result<(), HalError> {
        self.xdp_zero = self.ticks;
        Ok(())
    }

    /// Counters that grow with the polls, with a squeezed CPU 3, a
    /// conntrack table near its stock limit and a few neighbor overflows.
    fn kernel_stats(&mut self) -> Result<KernelStats, HalError> {
        let t = self.ticks.saturating_add(1);
        Ok(KernelStats {
            softnet: (0..16u32)
                .map(|cpu| SoftnetCpu {
                    cpu,
                    processed: t.saturating_mul(100_000 + u64::from(cpu) * 1000),
                    dropped: 0,
                    time_squeeze: if cpu == 3 { t.saturating_mul(400) } else { t },
                })
                .collect(),
            conntrack_count: Some(240_000),
            neigh_full_v4: Some(7),
            neigh_full_v6: Some(0),
        })
    }

    fn snapshot(&mut self, cfg: &Config) -> Result<Snapshot, HalError> {
        let _ = cfg;
        Ok(self
            .kernel
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone())
    }

    fn route_get(
        &mut self,
        cfg: &Config,
        q: &crate::route_get::RouteQuery,
    ) -> Result<crate::route_get::KernelLookup, HalError> {
        let k = self.kernel.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(crate::route_get::lookup(cfg, &k, q))
    }

    fn reconcile(&mut self, cfg: &Config) -> Result<(), HalError> {
        let mut k = self.kernel.lock().unwrap_or_else(PoisonError::into_inner);
        *k = drift::repaired(cfg, &k);
        Ok(())
    }

    fn poll(&mut self) -> Vec<LinkState> {
        self.ticks = self.ticks.wrapping_add(1);
        self.applied
            .interfaces
            .keys()
            .filter_map(|n| self.sample(n))
            .collect()
    }

    fn now_unix(&self) -> Option<u64> {
        None
    }

    /// Counted, not shaped (G4.9g): the Queues window moves in the lab.
    fn shaper_apply(&mut self, plan: &crate::queue::ShaperPlan) -> Result<(), HalError> {
        self.shaper.apply(plan);
        Ok(())
    }

    fn shaper_status(&mut self) -> crate::queue::ShaperStatus {
        self.shaper.status()
    }

    fn features(&self) -> Features {
        Features {
            vrf: true,
            mpls: true,
        }
    }

    /// The lab's label table: the static entries applied (G3.5). The lab
    /// runs no LDP, so none of LDP's.
    fn mpls_routes(&mut self) -> Result<Vec<crate::mpls::MplsRoute>, HalError> {
        Ok(crate::mpls::static_routes(&self.applied.routing.mpls))
    }

    fn address_list_dynamic(&mut self, change: DynamicChange<'_>) -> Result<(), HalError> {
        match change {
            DynamicChange::Add(d) => {
                self.dynamic
                    .retain(|x| x.list != d.list || x.address != d.address);
                self.dynamic.push(d.clone());
            }
            DynamicChange::Remove(d) => {
                self.dynamic
                    .retain(|x| x.list != d.list || x.address != d.address);
            }
            DynamicChange::Expired(gone) => {
                let gone: std::collections::BTreeSet<_> =
                    gone.iter().map(|d| (&d.list, d.address)).collect();
                self.dynamic
                    .retain(|x| !gone.contains(&(&x.list, x.address)));
            }
        }
        Ok(())
    }

    fn prober(&self) -> Result<SharedProber, String> {
        Ok(Arc::clone(&self.prober))
    }

    /// The lab's simulated LSPs (`lsp::sim`).
    fn lsp_prober(&self) -> Result<crate::lsp::SharedLspProber, String> {
        Ok(Arc::new(crate::lsp::sim::SimLspProber))
    }

    /// Simulated traffic on any lab port (`capture::SimCapture`).
    fn packet_capture(&self) -> Result<crate::capture::SharedCapture, String> {
        Ok(Arc::new(crate::capture::SimCapture))
    }

    /// Lab ports negotiate their top speed, full duplex, with an equal
    /// partner; each has a few link downs from "before" plus one per
    /// re-enable. What `interface.ethernet.set` applied shows here: forced
    /// rate and duplex, fewer advertised modes, flow control (G1.20).
    fn ethernet_monitor(&mut self, name: &IfName) -> Result<EthernetMonitor, HalError> {
        let (index, iface) = self.lab_port(name)?;
        let up = !iface.disabled;
        let set = &iface.ethernet;
        let modes = self.port_modes(index);
        let autoneg = set.auto_negotiation.unwrap_or(true);
        let advertising = set.advertise.clone().unwrap_or_else(|| modes.clone());
        // The partner can do everything: the best advertised mode wins.
        let best = advertising
            .iter()
            .filter_map(|m| mode_speed(m))
            .max_by_key(|(speed, full)| (*speed, *full));
        let (speed, full) = if autoneg {
            best.unwrap_or((self.port_speed(index), true))
        } else {
            (
                set.speed_mbps.unwrap_or(self.port_speed(index)),
                set.full_duplex.unwrap_or(true),
            )
        };
        let flow = |f: Option<FlowControl>| match f {
            None | Some(FlowControl::Off) => false,
            // The lab partner always agrees to pause frames.
            Some(FlowControl::On | FlowControl::Auto) => true,
        };
        let downs = u32::try_from(index % 3)
            .unwrap_or(0)
            .saturating_add(self.reenabled.get(name).copied().unwrap_or(0));
        let sfp = self.is_sfp(index);
        Ok(EthernetMonitor {
            link_ok: up,
            speed_mbps: up.then_some(speed),
            full_duplex: up.then_some(full),
            autoneg: Some(autoneg),
            port: Some(if sfp { "fibre" } else { "twisted-pair" }.into()),
            mdix: (up && !sfp).then(|| if index % 2 == 0 { "mdi" } else { "mdi-x" }.into()),
            mdix_ctrl: (!sfp).then(|| "auto".into()),
            supported: modes.clone(),
            advertising: if autoneg { advertising } else { Vec::new() },
            partner_advertising: if up && autoneg { modes } else { Vec::new() },
            rx_flow_control: Some(flow(set.rx_flow_control)),
            tx_flow_control: Some(flow(set.tx_flow_control)),
            flow_control_autoneg: Some(
                [set.rx_flow_control, set.tx_flow_control].contains(&Some(FlowControl::Auto)),
            ),
            carrier_changes: Some(downs.saturating_mul(2).saturating_add(u32::from(up))),
            link_downs: Some(downs),
            down_reason: (!up).then(|| "administratively disabled".into()),
            notes: Vec::new(),
        })
    }

    /// The last port's SFP+ module: steady readings, the laser off while
    /// the port is disabled.
    fn sfp_module(&mut self, name: &IfName) -> Result<SfpModule, HalError> {
        let (index, iface) = self.lab_port(name)?;
        if !self.is_sfp(index) {
            return Err(HalError::Unsupported(format!(
                "'{name}' is a copper port: no module cage"
            )));
        }
        let n = index.saturating_add(1);
        let tx = if iface.disabled { sff::MIN_DBM } else { -2.4 };
        let (a0, a2) = sff::lab_sfp_plus(&format!("CRV{n:05}"), 41.2, tx, -3.1);
        let mut m = sff::decode(&a0, Some(&a2));
        m.notes.push("simulated by the virtual lab".into());
        Ok(m)
    }

    /// Copper ports pass, except ether7's damaged cable (pair C shorted
    /// at 23.5 m); a disabled port's cable is open at its far end.
    fn cable_tester(&mut self, name: &IfName) -> Result<Box<dyn CableTest>, HalError> {
        let (index, iface) = self.lab_port(name)?;
        if self.is_sfp(index) {
            return Err(HalError::Unsupported(format!(
                "'{name}' is a fibre port: there are no copper pairs to test"
            )));
        }
        let length = 2.5 + 3.1 * index as f64;
        let pairs = ["A", "B", "C", "D"]
            .into_iter()
            .map(|pair| {
                let (status, distance_m) = match (index, pair, iface.disabled) {
                    (6, "C", _) => ("short", Some(23.5)),
                    (_, _, true) => ("open", Some(length)),
                    _ => ("ok", None),
                };
                CablePair {
                    pair: pair.into(),
                    status: status.into(),
                    distance_m,
                }
            })
            .collect();
        Ok(Box::new(LabCableTest(CableTestResult {
            pairs,
            notes: vec!["simulated by the virtual lab".into()],
        })))
    }

    fn hardware(&mut self, name: &IfName) -> Result<NicHardware, HalError> {
        let iface = self
            .applied
            .interfaces
            .get(name)
            .ok_or_else(|| self.missing(name))?;
        let mac = iface.mac.map(|m| m.to_string());
        let Some(index) = self
            .port_index(name)
            .filter(|_| iface.kind == InterfaceKind::Ethernet)
        else {
            // Software interfaces: what Linux would say about them.
            return Ok(NicHardware {
                mac,
                bus: Some("virtual".into()),
                driver: Some(iface.kind.label().to_owned()),
                min_mtu: Some(68),
                max_mtu: Some(9216),
                rx_queues: Some(1),
                tx_queues: Some(1),
                notes: vec!["a software interface: no NIC behind it".into()],
                ..NicHardware::default()
            });
        };
        let n = u32::try_from(index).unwrap_or(0).saturating_add(1);
        let set = self.applied.system.tuning.ports.get(name);
        let tuned = |k: &str, lab: u32| {
            set.and_then(|m| m.get(k))
                .and_then(|v| u32::try_from(*v).ok())
                .unwrap_or(lab)
        };
        let wanted = &iface.ethernet.offloads;
        let offload = |name: &str, feature: &str, active: bool, fixed: bool| Offload {
            name: name.into(),
            feature: feature.into(),
            active: match wanted.get(feature) {
                Some(on) if !fixed => *on,
                _ => active,
            },
            fixed,
        };
        Ok(NicHardware {
            perm_mac: Some(lab_mac(index)),
            mac: mac.or_else(|| Some(lab_mac(index))),
            min_mtu: Some(68),
            max_mtu: Some(9216),
            bus: Some("virtual".into()),
            bus_address: Some(format!("lab:{n:02}")),
            vendor: Some("CoreRouter".into()),
            model: Some(if self.is_sfp(index) {
                "Virtual NIC 10G SFP+".into()
            } else {
                "Virtual NIC".into()
            }),
            driver: Some("corerouter-virt".into()),
            driver_version: Some(env!("CARGO_PKG_VERSION").into()),
            firmware: Some("lab-1.0".into()),
            serial: Some(format!("CRV{n:05}")),
            // The made-up server has two NUMA nodes (G1.26): half the
            // ports on each.
            numa_node: Some(u32::from(index >= self.ports.len() / 2)),
            rx_queues: Some(4),
            tx_queues: Some(4),
            combined_channels: Some(tuned("combined_channels", 4)),
            combined_channels_max: Some(8),
            ring_rx: Some(tuned("rx_ring", 1024)),
            ring_rx_max: Some(4096),
            ring_tx: Some(tuned("tx_ring", 1024)),
            ring_tx_max: Some(4096),
            offloads: vec![
                offload("TSO", "tx-tcp-segmentation", true, false),
                offload("GSO", "tx-generic-segmentation", true, false),
                offload("GRO", "rx-gro", true, false),
                offload("LRO", "rx-lro", false, true),
                offload("RX checksum", "rx-checksum", true, false),
                offload("TX checksum", "tx-checksum-ip-generic", true, false),
                offload("RX VLAN", "rx-vlan-hw-parse", true, false),
                offload("TX VLAN", "tx-vlan-hw-insert", true, false),
                offload("VLAN filter", "rx-vlan-filter", false, true),
            ],
            notes: vec!["simulated by the virtual lab".into()],
            ..NicHardware::default()
        })
    }

    /// The `poll` counters plus rare, deterministic errors (one CRC error
    /// per half a million frames, …) and the Ethernet groups for ports.
    fn counters(&mut self, name: &IfName) -> Result<LinkCounters, HalError> {
        let st = self.sample(name).ok_or_else(|| self.missing(name))?;
        let ether = self.port_index(name).is_some()
            && self
                .applied
                .interfaces
                .get(name)
                .is_some_and(|i| i.kind == InterfaceKind::Ethernet);
        let rx = st.rx_packets;
        let tx = st.tx_packets;
        let crc = rx / 500_000;
        let dropped = rx / 250_000;
        let multicast = rx / 100;
        let broadcast = rx / 1000;
        let c = |n: &str, v: u64| (n.to_owned(), v);
        let mut groups = vec![CounterGroup::new(
            "interface",
            [
                c("rx_bytes", st.rx_bytes),
                c("tx_bytes", st.tx_bytes),
                c("rx_packets", rx),
                c("tx_packets", tx),
                c("rx_errors", crc),
                c("tx_errors", 0),
                c("rx_dropped", dropped),
                c("tx_dropped", 0),
                c("multicast", multicast),
                c("collisions", 0),
                c("rx_length_errors", 0),
                c("rx_over_errors", 0),
                c("rx_crc_errors", crc),
                c("rx_frame_errors", 0),
                c("rx_fifo_errors", 0),
                c("rx_missed_errors", dropped),
                c("tx_aborted_errors", 0),
                c("tx_carrier_errors", 0),
                c("tx_fifo_errors", 0),
                c("tx_heartbeat_errors", 0),
                c("tx_window_errors", 0),
            ],
        )];
        if ether {
            groups.push(CounterGroup::new(
                "eth-mac",
                [
                    c("tx_frames_ok", tx),
                    c("rx_frames_ok", rx.saturating_sub(crc)),
                    c("fcs_errors", crc),
                    c("alignment_errors", 0),
                    c("tx_octets_ok", st.tx_bytes),
                    c("rx_octets_ok", st.rx_bytes),
                    c("rx_multicast", multicast),
                    c("rx_broadcast", broadcast),
                    c("tx_multicast", tx / 200),
                    c("tx_broadcast", tx / 2000),
                    c("frame_too_long", 0),
                ],
            ));
            groups.push(CounterGroup::new(
                "rmon",
                [
                    c("undersize", 0),
                    c("oversize", 0),
                    c("fragments", crc / 2),
                    c("jabbers", 0),
                    c("rx_64", rx / 4),
                    c("rx_65_127", rx / 8),
                    c("rx_128_255", rx / 16),
                    c("rx_256_511", rx / 16),
                    c("rx_512_1023", rx / 16),
                    c("rx_1024_1518", rx / 2),
                ],
            ));
            groups.push(CounterGroup::new(
                "pause",
                [c("tx_pause_frames", 0), c("rx_pause_frames", 0)],
            ));
        }
        Ok(LinkCounters {
            groups,
            notes: Vec::new(),
        })
    }

    fn dhcp_port(&mut self, name: &IfName) -> Result<Box<dyn DhcpPort>, HalError> {
        if !self.applied.interfaces.contains_key(name) && !self.ports.contains(name) {
            return Err(HalError::Rejected(format!(
                "no interface '{name}' in the lab"
            )));
        }
        Ok(Box::new(SimDhcpPort {
            port: name.clone(),
            mac: self.mac_of(name),
            server: self.dhcp.clone(),
            inbox: VecDeque::new(),
            probing: None,
        }))
    }

    fn pppoe_client_port(
        &mut self,
        client: &IfName,
        uplink: &IfName,
    ) -> Result<Box<dyn crate::pppoe_client::PppoeClientPort>, HalError> {
        if !self.applied.interfaces.contains_key(uplink) && !self.ports.contains(uplink) {
            return Err(HalError::Rejected(format!(
                "no interface '{uplink}' in the lab (PPPoE client '{client}')"
            )));
        }
        Ok(Box::new(crate::pppoe_client::SimPppoePort::new(
            uplink.clone(),
            self.mac_of(uplink),
            self.pppoe.clone(),
        )))
    }

    fn offer_pppoe_lab_server(&mut self, server: crate::pppoe_client::SharedPppoeLab) {
        if self.pppoe.is_none() {
            self.pppoe = Some(server);
        }
    }

    fn offer_dhcp_lab_server(&mut self, server: SharedResponder) {
        if self.dhcp.is_none() {
            self.dhcp = Some(server);
        }
    }

    fn dhcp_server_port(
        &mut self,
        name: &IfName,
    ) -> Result<Box<dyn crate::dhcp_server::DhcpServerPort>, HalError> {
        if !self.applied.interfaces.contains_key(name) && !self.ports.contains(name) {
            return Err(HalError::Rejected(format!(
                "no interface '{name}' in the lab"
            )));
        }
        Ok(Box::new(SimDhcpServerPort {
            port: name.clone(),
            mac: self.mac_of(name),
            hosts: self.dhcp_hosts.clone(),
            now: 0,
            inbox: VecDeque::new(),
            answered: Vec::new(),
        }))
    }

    fn dhcp6_server_port(
        &mut self,
        name: &IfName,
    ) -> Result<Box<dyn crate::dhcp_server::Dhcp6ServerPort>, HalError> {
        if !self.applied.interfaces.contains_key(name) && !self.ports.contains(name) {
            return Err(HalError::Rejected(format!(
                "no interface '{name}' in the lab"
            )));
        }
        Ok(Box::new(SimDhcp6ServerPort {
            port: name.clone(),
            mac: self.mac_of(name),
            hosts: self.dhcp6_hosts.clone(),
            now: 0,
            inbox: VecDeque::new(),
        }))
    }

    fn offer_dhcp6_lab_clients(&mut self, hosts: crate::dhcp_server::SharedLabClients6) {
        if self.dhcp6_hosts.is_none() {
            self.dhcp6_hosts = Some(hosts);
        }
    }

    fn offer_dhcp_lab_clients(&mut self, hosts: crate::dhcp_server::SharedLabClients) {
        if self.dhcp_hosts.is_none() {
            self.dhcp_hosts = Some(hosts);
        }
    }

    fn dhcp6_port(&mut self, name: &IfName) -> Result<Box<dyn Dhcp6Port>, HalError> {
        if !self.applied.interfaces.contains_key(name) && !self.ports.contains(name) {
            return Err(HalError::Rejected(format!(
                "no interface '{name}' in the lab"
            )));
        }
        Ok(Box::new(SimDhcp6Port {
            port: name.clone(),
            mac: self.mac_of(name),
            server: self.dhcp6.clone(),
            inbox: VecDeque::new(),
        }))
    }

    fn offer_dhcp6_lab_server(&mut self, server: SharedResponder6) {
        if self.dhcp6.is_none() {
            self.dhcp6 = Some(server);
        }
    }

    /// The lab router behind port N sends Router Advertisements: prefix
    /// `2001:db8:0:N::/64` (A and L set) and itself as default router, from
    /// `fe80::` + the EUI-64 of `02:DC:00:00:00:N`. Ports that accept RA
    /// (and are up) get a SLAAC address and the routes, like the kernel.
    fn ipv6_learned(&mut self) -> Result<Vec<Learned>, HalError> {
        let cfg = &self.applied;
        let mut out = Vec::new();
        for name in cfg.interfaces.keys() {
            let (mode, _) = corerouter_model::ipv6::ra_mode(cfg, name);
            // The lab forwards IPv6: `yes-if-forwarding-disabled` takes none.
            let accepts = mode == corerouter_model::ipv6::RaMode::On;
            let enslaved = cfg.interfaces.get(name).is_some_and(|i| {
                i.bridge.is_some()
                    || i.bond.is_some()
                    || matches!(i.kind, InterfaceKind::Vrf { .. })
            });
            if !accepts || enslaved || !corerouter_model::route::is_up(cfg, name) {
                continue;
            }
            let n = lab_net(name);
            let prefix = Ipv6Addr::new(0x2001, 0xdb8, 0, u16::from(n), 0, 0, 0, 0);
            let Ok(net) = ipnet::Ipv6Net::new(prefix, 64) else {
                continue;
            };
            let me = Ipv6Addr::from(u128::from(prefix) | u128::from(eui64(self.mac_of(name))));
            let table = corerouter_model::route::table_id(
                cfg,
                &corerouter_model::route::table_of(cfg, name),
            )
            .unwrap_or(corerouter_model::route::MAIN_TABLE_ID);
            if let Ok(address) = ipnet::Ipv6Net::new(me, 64) {
                out.push(Learned::Address {
                    interface: name.clone(),
                    address,
                    valid_secs: Some(2_592_000),
                    preferred_secs: Some(604_800),
                });
            }
            out.push(Learned::Route {
                interface: name.clone(),
                dst: net,
                gateway: None,
                metric: 256,
                table,
                expires_secs: Some(2_592_000),
            });
            out.push(Learned::Route {
                interface: name.clone(),
                dst: ipnet::Ipv6Net::default(),
                gateway: Some(link_local(lab_router_mac(n))),
                metric: 1024,
                table,
                expires_secs: Some(1_800),
            });
        }
        Ok(out)
    }
}

/// A lab DHCPv6 client socket, like [`SimDhcpPort`].
struct SimDhcp6Port {
    port: IfName,
    mac: [u8; 6],
    server: Option<SharedResponder6>,
    inbox: VecDeque<Datagram6>,
}

impl Dhcp6Port for SimDhcp6Port {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn send(&mut self, payload: &[u8]) -> Result<(), HalError> {
        if let Some(server) = &self.server {
            for d in server.answer(&self.port, self.mac, payload) {
                if self.inbox.len() < SIM_INBOX {
                    self.inbox.push_back(d);
                }
            }
        }
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Datagram6>, HalError> {
        Ok(self.inbox.pop_front())
    }
}

/// A lab DHCPv6 server socket (G4.2c).
struct SimDhcp6ServerPort {
    port: IfName,
    mac: [u8; 6],
    hosts: Option<crate::dhcp_server::SharedLabClients6>,
    now: u64,
    inbox: VecDeque<crate::dhcp_server::Heard6>,
}

impl crate::dhcp_server::Dhcp6ServerPort for SimDhcp6ServerPort {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn tick(&mut self, now_unix: u64) {
        self.now = now_unix;
        if let Some(h) = &self.hosts {
            for m in h.poll(&self.port, now_unix) {
                if self.inbox.len() < SIM_INBOX {
                    self.inbox.push_back(m);
                }
            }
        }
    }

    fn recv(&mut self) -> Result<Option<crate::dhcp_server::Heard6>, HalError> {
        Ok(self.inbox.pop_front())
    }

    fn send(&mut self, payload: &[u8], _to: Ipv6Addr, _port: u16) -> Result<(), HalError> {
        if let Some(h) = &self.hosts {
            h.deliver(&self.port, payload, self.now);
        }
        Ok(())
    }

    fn describe(&self) -> String {
        format!("lab hosts on {} (v6)", self.port)
    }
}

/// A lab DHCP server socket (G4.2a): the lab's hosts behind the port talk
/// to it, on the clock the engine hands it.
struct SimDhcpServerPort {
    port: IfName,
    mac: [u8; 6],
    hosts: Option<crate::dhcp_server::SharedLabClients>,
    now: u64,
    inbox: VecDeque<crate::dhcp_server::Heard>,
    answered: Vec<(Ipv4Addr, [u8; 6])>,
}

impl crate::dhcp_server::DhcpServerPort for SimDhcpServerPort {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn tick(&mut self, now_unix: u64) {
        self.now = now_unix;
        if let Some(h) = &self.hosts {
            for m in h.poll(&self.port, now_unix) {
                if self.inbox.len() < SIM_INBOX {
                    self.inbox.push_back(m);
                }
            }
        }
    }

    fn recv(&mut self) -> Result<Option<crate::dhcp_server::Heard>, HalError> {
        Ok(self.inbox.pop_front())
    }

    fn send(
        &mut self,
        payload: &[u8],
        _src: Ipv4Addr,
        to: crate::dhcp_server::ReplyTo,
    ) -> Result<(), HalError> {
        if let Some(h) = &self.hosts {
            h.deliver(&self.port, payload, to, self.now);
        }
        Ok(())
    }

    fn probe(&mut self, ip: Ipv4Addr, _src: Ipv4Addr) -> Result<bool, HalError> {
        if let Some(mac) = self.hosts.as_ref().and_then(|h| h.arp(&self.port, ip)) {
            self.answered.push((ip, mac));
        }
        Ok(true)
    }

    fn probe_replies(&mut self) -> Result<Vec<(Ipv4Addr, [u8; 6])>, HalError> {
        Ok(std::mem::take(&mut self.answered))
    }

    fn describe(&self) -> String {
        format!("lab hosts on {}", self.port)
    }
}

/// A lab DHCP client socket: what it sends reaches the simulated server at
/// once, and the answers wait in `inbox` for the next `recv`.
struct SimDhcpPort {
    port: IfName,
    mac: [u8; 6],
    server: Option<SharedResponder>,
    inbox: VecDeque<Datagram>,
    probing: Option<Ipv4Addr>,
}

/// Answers kept per lab port (a misbehaving responder cannot fill memory).
const SIM_INBOX: usize = 64;

impl DhcpPort for SimDhcpPort {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn send(&mut self, payload: &[u8], _src: Ipv4Addr, dest: Dest) -> Result<(), HalError> {
        if let Some(server) = &self.server {
            for d in server.answer(&self.port, self.mac, payload, dest) {
                if self.inbox.len() < SIM_INBOX {
                    self.inbox.push_back(d);
                }
            }
        }
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Datagram>, HalError> {
        Ok(self.inbox.pop_front())
    }

    fn probe(&mut self, ip: Ipv4Addr) -> Result<bool, HalError> {
        self.probing = Some(ip);
        Ok(true)
    }

    fn conflict(&mut self) -> Result<Option<[u8; 6]>, HalError> {
        Ok(self
            .probing
            .zip(self.server.as_ref())
            .and_then(|(ip, s)| s.conflict(&self.port, ip)))
    }

    fn end_probe(&mut self) {
        self.probing = None;
    }
}

/// The lab's cable test: a short pause, then the precomputed pairs.
struct LabCableTest(CableTestResult);

impl CableTest for LabCableTest {
    fn run(&mut self, wait: &dyn Fn(Duration) -> bool) -> Result<CableTestResult, HalError> {
        if !wait(Duration::from_millis(1500)) {
            return Err(HalError::Io("stopped".into()));
        }
        Ok(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::{Interface, InterfaceKind};

    #[test]
    fn discovers_and_counts() {
        let mut hal = VirtualHal::new(3);
        let links = hal.discover_links().unwrap();
        assert_eq!(links.len(), 3);
        let mut cfg = Config::default();
        for l in links {
            cfg.interfaces.insert(
                l.name.clone(),
                Interface::new(l.name, InterfaceKind::Ethernet),
            );
        }
        hal.apply(&Config::default(), &cfg).unwrap();
        let a = hal.poll();
        let b = hal.poll();
        assert_eq!(a.len(), 3);
        assert!(b[0].rx_bytes > a[0].rx_bytes);
    }

    fn lab(ports: u8) -> (VirtualHal, Config) {
        let mut hal = VirtualHal::new(ports);
        let mut cfg = Config::default();
        for l in hal.discover_links().unwrap() {
            cfg.interfaces.insert(
                l.name.clone(),
                Interface::new(l.name, InterfaceKind::Ethernet),
            );
        }
        hal.apply(&Config::default(), &cfg).unwrap();
        (hal, cfg)
    }

    fn name(n: &str) -> IfName {
        n.parse().unwrap()
    }

    #[test]
    fn ports_negotiate_and_count_link_downs() {
        let (mut hal, cfg) = lab(4);
        let m = hal.ethernet_monitor(&name("ether2")).unwrap();
        assert!(m.link_ok);
        assert_eq!(m.speed_mbps, Some(1000));
        assert_eq!(m.full_duplex, Some(true));
        assert!(m.supported.contains(&"1000baseT/Full".to_owned()));
        assert_eq!(m.partner_advertising, m.advertising);
        assert_eq!(m.link_downs, Some(1));
        // The last port is the 10G one.
        let fast = hal.ethernet_monitor(&name("ether4")).unwrap();
        assert_eq!(fast.speed_mbps, Some(10_000));

        // Disable, then enable: down with no speed, then one more link down.
        let mut off = cfg.clone();
        off.interfaces.get_mut(&name("ether2")).unwrap().disabled = true;
        hal.apply(&cfg, &off).unwrap();
        let down = hal.ethernet_monitor(&name("ether2")).unwrap();
        assert!(!down.link_ok);
        assert_eq!(down.speed_mbps, None);
        assert!(down.partner_advertising.is_empty());
        hal.apply(&off, &cfg).unwrap();
        assert_eq!(
            hal.ethernet_monitor(&name("ether2")).unwrap().link_downs,
            Some(2)
        );
    }

    #[test]
    fn software_interfaces_are_not_ethernet() {
        let (mut hal, mut cfg) = lab(2);
        let before = cfg.clone();
        cfg.interfaces.insert(
            name("br1"),
            Interface::new(name("br1"), InterfaceKind::Bridge),
        );
        hal.apply(&before, &cfg).unwrap();
        assert!(matches!(
            hal.ethernet_monitor(&name("br1")),
            Err(HalError::Unsupported(_))
        ));
        let hw = hal.hardware(&name("br1")).unwrap();
        assert_eq!(hw.driver.as_deref(), Some("bridge"));
        assert_eq!(hw.vendor, None);
        assert!(matches!(
            hal.hardware(&name("nope")),
            Err(HalError::Rejected(_))
        ));
    }

    #[test]
    fn hardware_and_counters_are_deterministic() {
        let (mut hal, _) = lab(3);
        let hw = hal.hardware(&name("ether1")).unwrap();
        assert_eq!(hw.vendor.as_deref(), Some("CoreRouter"));
        assert_eq!(hw.model.as_deref(), Some("Virtual NIC"));
        assert_eq!(hw.perm_mac.as_deref(), Some("02:00:00:00:00:01"));
        assert!(hw.offloads.iter().any(|o| o.name == "TSO" && o.active));
        let a = hal.counters(&name("ether1")).unwrap();
        assert_eq!(
            a,
            hal.counters(&name("ether1")).unwrap(),
            "reading does not advance"
        );
        hal.poll();
        let b = hal.counters(&name("ether1")).unwrap();
        let rx = |c: &LinkCounters| {
            c.groups[0]
                .counters
                .iter()
                .find(|x| x.name == "rx_bytes")
                .unwrap()
                .value
        };
        assert!(rx(&b) > rx(&a));
        let names: Vec<&str> = b.groups.iter().map(|g| g.name.as_str()).collect();
        assert_eq!(names, ["interface", "eth-mac", "rmon", "pause"]);
    }
}
