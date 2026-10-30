//! Linux backend.
//!
//! - `apply`: [`plan::plan`] turns the diff `from` → `to` into ordered kernel
//!   operations (pure, tested everywhere); `netlink` runs them over rtnetlink
//!   and undoes the done ones if one fails (G1.2).
//! - discovery and counters: one `RTM_GETLINK` dump (`netlink::links`), the
//!   same namespace `apply` writes to (G1.7/G1.18); `owner` decides which
//!   links are CoreRouter's. The others are listed but never applied to.
//! - `dhcp`: DHCP client transport (G4.7): frames over `AF_PACKET` with a
//!   BPF filter, unicasts over UDP 68, ARP probe; bytes only (`proto-dhcp`).
//!   `dhcp6`: the DHCPv6 one (UDP 546). `ra`: which interfaces accept
//!   Router Advertisements (sysctl `accept_ra`), synced on every apply, and
//!   what the kernel learned from them (`Hal::ipv6_learned`) (G4.7b).
//! - `l2`: neighbor-discovery I/O — LLDP frames over `AF_PACKET`, passive
//!   MNDP over UDP 5678 (G5.2). Bytes only; the codecs are `proto-lldp` /
//!   `proto-mndp`, glued by the daemon.
//! - firewall (G2.1): `nft` replaces table `inet corerouter` in one
//!   transaction when the rendered ruleset changes (see [`nft`]), before the
//!   netlink plan; if the plan then fails, the old ruleset goes back.
//! - `features`: probed once, on first use, with a throwaway link per
//!   capability (`netlink::features`), then cached (G1.14).
//! - interface dialog (G1.19): `nic` answers `ethernet_monitor`, `hardware`
//!   and `counters` from rtnetlink, the `ethtool`/`devlink` generic netlink
//!   families (`genl`, `ethtool`; never the ioctls) and sysfs device files;
//!   `pci_ids` names the PCI ids.
//! - Ethernet settings (G1.20): `apply` writes what `interface.ethernet.set`
//!   put in the config over ethtool netlink (`ether` computes the target
//!   over a snapshot of the port taken before the first change, so taking
//!   a setting out restores the driver's own); `sfp_module` reads the
//!   module EEPROM and `cable_tester` runs the PHY's cable test.
//! - tuning (G1.26): `apply` writes the kernel parameters of
//!   `system.tuning` under `/proc/sys` (snapshot of the first value, so
//!   taking one out restores it; see [`tuning`]); `system_info`,
//!   `sysctls` and `kernel_stats` read `/proc` and `/sys`.
//!
//! - XDP (G2.5a): `xdp` loads `dataplane-ebpf`'s prebuilt object with aya,
//!   attaches it where `ip.firewall.xdp` says (native, else generic) and
//!   keeps its maps in step with the config, last in `apply` (a failure
//!   there undoes the rest of the apply too).
//!
//! Integration tests run against a real kernel inside a throwaway network
//! namespace, without root: see `tests/netns.rs`.

pub mod owner;
pub mod pci_ids;
pub mod plan;

/// Generic netlink codec (pure) and socket (Linux) for G1.19.
mod genl;

/// `interface.ethernet.set` targets over the port's own settings (G1.20).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod ether;

/// Interface dialog data: ethtool netlink, devlink, sysfs (G1.19).
#[cfg(target_os = "linux")]
mod ethtool;
#[cfg(target_os = "linux")]
mod nic;

#[cfg(target_os = "linux")]
mod netlink;

/// How many times `apply` read the kernel's whole route table in this
/// process (G0.31i): tests check a commit of one route reads none.
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub fn route_dumps() -> u64 {
    netlink::ROUTE_DUMPS.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(target_os = "linux")]
pub mod nft;

/// nf_tables over nfnetlink (G2.3b): the encoder is pure, the socket Linux.
pub mod nfnl;

/// Conntrack over ctnetlink (G2.2): codec pure, socket Linux.
pub mod ctnl;

/// Firewall rule counters in one nfnetlink dump (G2.1c).
pub mod nft_counters;

/// Reading an nf_tables table back over nfnetlink (G2.8).
pub mod nft_read;

/// The firewall's table over nfnetlink, by difference (G2.8).
#[cfg(target_os = "linux")]
pub mod firewall;

/// The firewall commit from what the previous one loaded (G0.31f).
#[cfg(target_os = "linux")]
mod fw_delta;

/// The packet trace (`meta nftrace`, G2.1c): trace table and event codec.
pub mod nft_trace;

/// The CGNAT table in the kernel (G2.3).
#[cfg(target_os = "linux")]
mod cgnat;

/// The fast path (flowtable) in the kernel and the cards' eSwitch (G2.4).
#[cfg(target_os = "linux")]
mod fastpath;

/// The netfilter queue of first packets of blocks-mode subscribers
/// (G2.3c): codec pure, socket Linux.
pub mod nfqueue;

/// The ICMP answer when a CGNAT subscriber's ports run out and the queues
/// that decide it (G2.7): codec pure, sockets Linux.
pub mod cgnat_icmp;

#[cfg(target_os = "linux")]
pub mod l2;

/// DHCP client transport (G4.7): `AF_PACKET` + BPF, UDP, ARP probe.
#[cfg(target_os = "linux")]
pub mod dhcp;

/// DHCP server transport (G4.2a): `AF_PACKET` + BPF, UDP 67, ARP probes.
#[cfg(target_os = "linux")]
pub mod dhcp_server;

/// DHCPv6 server and relay transport (G4.2c): UDP 547, ff02::1:2.
#[cfg(target_os = "linux")]
pub mod dhcp6_server;

/// DHCPv6 client transport (G4.7b): UDP 546 → ff02::1:2.
#[cfg(target_os = "linux")]
pub mod dhcp6;

/// Router Advertisements: `accept_ra` per interface, flush (G4.7b).
#[cfg(target_os = "linux")]
pub mod ra;

/// Host ICMP for the diagnostic tools (G6.2).
#[cfg(target_os = "linux")]
pub mod icmp;

/// UDP and TCP SYN probes for traceroute (G6.4c), next to the ICMP ones.
#[cfg(target_os = "linux")]
pub mod trace;

/// Packet capture for Torch and the sniffer (G6.4a): `AF_PACKET`.
#[cfg(target_os = "linux")]
pub mod capture;

/// PPPoE access ports and the slow path of the BNG (G4.3d): `AF_PACKET`.
#[cfg(target_os = "linux")]
pub mod pppoe_io;

/// The PPPoE client's port and relay (G3.9ga): `AF_PACKET` and a veth.
#[cfg(target_os = "linux")]
pub mod pppoe_client_io;

/// BNG redundancy (G4.3h): the access-side hello (`AF_PACKET`, 0x88b5).
#[cfg(target_os = "linux")]
pub mod ha_io;

/// System › Tuning (G1.26): kernel parameters, the machine, counters.
// System › Resources and health (G4.8a): /proc and /sys readings.
#[cfg(target_os = "linux")]
pub mod resource;

#[cfg(target_os = "linux")]
pub mod tuning;

/// System › Tuning, Interfaces (G1.26b): rings, queues, coalescing,
/// txqueuelen, root qdisc and `rp_filter` of each port.
#[cfg(target_os = "linux")]
mod port_tuning;

/// System › Tuning, CPU and IRQ (G1.26c): governor, PM QoS, watchdog, IRQ
/// affinity, RPS and XPS.
#[cfg(target_os = "linux")]
mod cpu_tuning;

/// The host's OS log (G4.8b): `/dev/kmsg` and the journal.
#[cfg(target_os = "linux")]
pub mod oslog;

/// Neighbor tables over rtnetlink (G1.27d): dump, events, static entries.
pub mod neigh;
/// Link events (G1.3d): ports replugged between two polls.
pub mod link_events;

/// MPLS label switching over rtnetlink (G3.5): the label table, static
/// entries in batches, the `net.mpls` knobs.
pub mod mpls;

/// LSP ping / traceroute (G3.5b): requests over `AF_PACKET`, the responder.
#[cfg(target_os = "linux")]
pub mod lsp;

/// IP › Firewall › XDP (G2.5a): the XDP filter's loader, maps and counters.
#[cfg(target_os = "linux")]
pub mod xdp;

/// The CGNAT fast path's link to the XDP flow map and conntrack (G2.5b).
#[cfg(target_os = "linux")]
pub mod xdp_nat;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};

    use corerouter_hal::absent;
    use corerouter_hal::drift::{LinkSnap, Snapshot};
    use corerouter_hal::tuning::{CpuTuning, KernelStats, PortTuning, Sysctls, SystemInfo};
    use corerouter_hal::{
        CableTest, DynamicChange, EthernetMonitor, Features, Hal, HalError, LinkCounters, LinkInfo,
        LinkState, NicHardware, SfpModule,
    };
    use corerouter_model::{Config, EthernetSettings, IfName, InterfaceKind};

    use crate::ether::{self, EtherState};

    use crate::owner::{self, KernelLink, Owner, Policy};
    use crate::plan::Op;

    #[derive(Debug, Default)]
    pub struct LinuxHal {
        /// Probed on the first `features()` call, not at startup.
        features: OnceLock<Features>,
        /// Host ICMP, detected on the first `prober()` call.
        prober: OnceLock<Result<crate::icmp::HostProber, String>>,
        policy: Policy,
        /// What the last applied config says each name is (`owner` rule 5).
        claims: BTreeMap<IfName, InterfaceKind>,
        /// Whether `ra::sync` ran once (the first one flushes stale RA state).
        ra_synced: bool,
        /// Each port's Ethernet settings before CoreRouter first changed
        /// them (G1.20): what a setting taken out of the config returns to.
        ether_orig: BTreeMap<IfName, EtherState>,
        /// Kernel parameters set by `system.tuning` and their originals.
        sysctl: crate::tuning::Sysctl,
        /// Port settings of `system.tuning.ports` and their originals.
        ports: crate::port_tuning::Ports,
        /// CPU settings of `system.tuning.cpu` (holds the PM QoS request
        /// and the watchdog open while the daemon runs).
        cpu: crate::cpu_tuning::Cpu,
        /// CGNAT blocks installed in the kernel (G2.3c).
        cgnat_blocks: crate::cgnat::Blocks,
        /// The subscribers in the CGNAT set `full` (G2.7).
        cgnat_full: crate::cgnat::Full,
        /// Counters and ICMP limiter of the exhaustion queues (G2.7),
        /// shared with their threads.
        cgnat_exhaustion: std::sync::Arc<corerouter_hal::cgnat::Exhaustion>,
        /// What the last apply installed of the fast path (G2.4).
        fastpath: corerouter_hal::fastpath::FastPathState,
        /// The XDP filter (G2.5a); nothing loaded until configured.
        xdp: crate::xdp::XdpState,
        /// Static ARP entries and ARP modes applied (G1.27d).
        neigh: crate::neigh::Applied,
        /// Physical ports of the applied config that the kernel does not
        /// have (G1.3b): left out of the last apply, or seen gone by `poll`
        /// since. The next apply puts their configuration back if they
        /// returned.
        absent: BTreeSet<IfName>,
        /// The kernel index of each claimed physical port when it got its
        /// configuration (G1.3d). A port gone and back between two polls
        /// (a fast replug, a USB driver reset) has the same name and a new
        /// index, never reused (`dev_index_reserve` in net/core/dev.c
        /// allocates them cyclically up to 2^31), and none of its settings.
        indices: BTreeMap<IfName, u32>,
    }

    impl LinuxHal {
        pub fn new() -> Self {
            Self::default()
        }

        /// With the operator's `--manage` / `--unmanaged` lists.
        pub fn with_policy(policy: Policy) -> Self {
            Self {
                policy,
                ..Self::default()
            }
        }

        /// Every kernel link with its verdict, under `claims`.
        fn view(
            &self,
            claims: &BTreeMap<IfName, InterfaceKind>,
        ) -> Result<Vec<(KernelLink, Owner)>, HalError> {
            let links = crate::netlink::links()?;
            let mut by = owner::classify(&links, claims, &self.policy);
            let mut out: Vec<_> = links
                .into_iter()
                .map(|l| {
                    let o = by
                        .remove(&l.index)
                        .unwrap_or_else(|| Owner::External("not classified".into()));
                    (l, o)
                })
                .collect();
            out.sort_by(|a, b| a.0.name.cmp(&b.0.name));
            Ok(out)
        }
    }

    impl LinuxHal {
        /// `accept_ra` per managed interface of `to` (G4.7b). Best effort:
        /// a failure is logged, never refuses the commit.
        fn sync_ra(&mut self, to: &Config) {
            let mut claims = self.claims.clone();
            claims.extend(claims_of(to));
            let managed: std::collections::BTreeSet<IfName> = match self.view(&claims) {
                // Not the OS loopback (G3.4i): RA never reaches `lo`.
                Ok(v) => v
                    .into_iter()
                    .filter(|(l, o)| *o == Owner::Managed && l.arphrd != owner::ARPHRD_LOOPBACK)
                    .filter_map(|(l, _)| l.name.parse().ok())
                    .collect(),
                Err(e) => {
                    log::warn!("ipv6 RA settings not applied: {e}");
                    return;
                }
            };
            for p in crate::ra::sync(to, &managed, !self.ra_synced) {
                log::warn!("ipv6 RA settings: {p}");
            }
            self.ra_synced = true;
        }

        /// Kernel index → name of the managed links.
        fn managed_indexes(&self) -> Result<BTreeMap<u32, IfName>, HalError> {
            Ok(self
                .view(&self.claims)?
                .into_iter()
                .filter(|(_, o)| *o == Owner::Managed)
                .filter_map(|(l, _)| Some((l.index, l.name.parse().ok()?)))
                .collect())
        }
    }

    /// Ports whose Ethernet settings differ between `from` and `to`.
    fn ether_changes<'a>(
        from: &'a Config,
        to: &'a Config,
    ) -> Vec<(&'a IfName, EthernetSettings, &'a EthernetSettings)> {
        to.interfaces
            .iter()
            .filter(|(_, i)| i.kind == InterfaceKind::Ethernet)
            .filter_map(|(n, i)| {
                let old = from
                    .interfaces
                    .get(n)
                    .map(|o| o.ethernet.clone())
                    .unwrap_or_default();
                (old != i.ethernet).then_some((n, old, &i.ethernet))
            })
            .collect()
    }

    impl LinuxHal {
        /// Bring `name` to `want` over its snapshot (taken now if this is
        /// the first change).
        fn ether_apply(&mut self, name: &IfName, want: &EthernetSettings) -> Result<(), HalError> {
            let mut e = crate::ethtool::Ethtool::open(name.as_str())
                .map_err(|e| HalError::Rejected(format!("{name}: ethtool netlink: {e}")))?;
            let now = e
                .state()
                .map_err(|why| HalError::Rejected(format!("{name}: {why}")))?;
            let orig = self.ether_orig.entry(name.clone()).or_insert(now.clone());
            let t = ether::target(orig, want);
            let fail = |what: &str, err: crate::genl::GenlError| {
                HalError::Rejected(format!("{name}: {what}: {err}"))
            };
            if let Some(link) = &t.link {
                let unchanged = match link {
                    ether::Link::Auto(m) => now.autoneg == Some(true) && now.advertising == *m,
                    ether::Link::Forced {
                        speed_mbps,
                        full_duplex,
                    } => {
                        now.autoneg == Some(false)
                            && now.speed_mbps == Some(*speed_mbps)
                            && now.full_duplex == Some(*full_duplex)
                    }
                };
                if !unchanged {
                    e.set_link(link, &now.supported)
                        .map_err(|err| fail("link modes", err))?;
                }
            }
            if let Some(p) = t.pause
                && now.pause != Some(p)
            {
                e.set_pause(p).map_err(|err| fail("flow control", err))?;
            }
            let changes = ether::feature_changes(&t, &now.features);
            e.set_features(&changes)
                .map_err(|err| fail("offloads", err))?;
            if !changes.is_empty() {
                // The kernel may keep a feature as it was (dependencies,
                // driver limits) without failing the request.
                let after = e
                    .state()
                    .map_err(|why| HalError::Rejected(format!("{name}: {why}")))?;
                let kept: Vec<&str> = changes
                    .iter()
                    .filter(|(f, on)| after.features.get(*f) != Some(*on))
                    .map(|(f, _)| f.as_str())
                    .collect();
                if !kept.is_empty() {
                    return Err(HalError::Rejected(format!(
                        "{name}: the driver did not change {}",
                        kept.join(", ")
                    )));
                }
            }
            Ok(())
        }

        /// Ethernet settings `from` → `to`, all or nothing: on a failure
        /// the ports done so far go back to `from`.
        fn ether_transition(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
            let changes = ether_changes(from, to);
            if changes.is_empty() {
                return Ok(());
            }
            let external: BTreeMap<String, String> = self
                .view(&claims_of(to))?
                .into_iter()
                .filter_map(|(l, o)| match o {
                    Owner::External(r) => Some((l.name, r)),
                    Owner::Managed | Owner::Conflict(_) => None,
                })
                .collect();
            let mut done: Vec<(&IfName, EthernetSettings)> = Vec::new();
            for (name, old, new) in changes {
                if let Some(why) = external.get(name.as_str()) {
                    log::warn!("Ethernet settings of '{name}' not applied ({why})");
                    continue;
                }
                if let Err(e) = self.ether_apply(name, new) {
                    for (n, back) in done.iter().rev() {
                        if let Err(b) = self.ether_apply(n, back) {
                            log::error!("restoring Ethernet settings of '{n}': {b}");
                        }
                    }
                    return Err(e);
                }
                done.push((name, old));
            }
            Ok(())
        }
    }

    impl LinuxHal {
        /// `ports` without the links CoreRouter does not manage (logged).
        fn managed_ports(
            &self,
            cfg: &Config,
            ports: &BTreeMap<IfName, BTreeMap<String, i64>>,
        ) -> Result<BTreeMap<IfName, BTreeMap<String, i64>>, HalError> {
            if ports.is_empty() {
                return Ok(BTreeMap::new());
            }
            let external: BTreeMap<String, String> = self
                .view(&claims_of(cfg))?
                .into_iter()
                .filter_map(|(l, o)| match o {
                    Owner::External(r) => Some((l.name, r)),
                    Owner::Managed | Owner::Conflict(_) => None,
                })
                .collect();
            Ok(ports
                .iter()
                .filter(|(n, _)| match external.get(n.as_str()) {
                    Some(why) => {
                        log::warn!("tuning of '{n}' not applied ({why})");
                        false
                    }
                    None => true,
                })
                .map(|(n, v)| (n.clone(), v.clone()))
                .collect())
        }
    }

    fn claims_of(cfg: &Config) -> BTreeMap<IfName, InterfaceKind> {
        cfg.interfaces
            .iter()
            .map(|(n, i)| (n.clone(), i.kind.clone()))
            .collect()
    }

    impl LinuxHal {
        /// `apply` without XDP. Ops on links CoreRouter does not own are
        /// dropped (logged), so a stale config can never reach another
        /// program's link; conflicts go to the executor, which refuses them
        /// and rolls back.
        fn apply_links(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
            let ops = crate::plan::plan(from, to)?;
            // Before anything changes: port settings only reach links
            // CoreRouter manages, as the Ethernet settings do (another
            // program's link is never touched).
            let (from_ports, to_ports) = (
                self.managed_ports(from, &from.system.tuning.ports)?,
                self.managed_ports(to, &to.system.tuning.ports)?,
            );
            // nftables first (a refusal changes nothing), and only when the
            // firewall changed: a host without nftables still runs the rest.
            let firewall = corerouter_firewall::nft::inputs_changed(from, to);
            if firewall {
                crate::firewall::apply(from, to)?;
            }
            // CGNAT (G2.3): its own table, replaced whole in one batch.
            let cgnat = corerouter_firewall::cgnat::changed(&from.ip.cgnat, &to.ip.cgnat);
            let set = &to.ip.cgnat.settings;
            self.cgnat_exhaustion
                .configure(set.icmp_unreachable, u32::from(set.icmp_rate));
            if cgnat
                && let Err(e) = crate::cgnat::apply(
                    &from.ip.cgnat,
                    &to.ip.cgnat,
                    &mut self.cgnat_blocks,
                    &mut self.cgnat_full,
                )
            {
                if firewall && let Err(back) = crate::firewall::apply(to, from) {
                    log::error!("restoring the previous firewall: {back}");
                }
                return Err(e);
            }
            // The fast path (G2.4): its own table; rebuilt when the firewall
            // changed too, so flows a new rule drops leave the flowtable.
            let fast = corerouter_firewall::fastpath::changed(from, to)
                || (firewall && self.fastpath.active);
            if fast && let Err(e) = crate::fastpath::apply(to, &mut self.fastpath) {
                if cgnat
                    && let Err(back) = crate::cgnat::apply(
                        &to.ip.cgnat,
                        &from.ip.cgnat,
                        &mut self.cgnat_blocks,
                        &mut self.cgnat_full,
                    )
                {
                    log::error!("restoring the previous CGNAT table: {back}");
                }
                if firewall && let Err(back) = crate::firewall::apply(to, from) {
                    log::error!("restoring the previous firewall: {back}");
                }
                return Err(e);
            }
            let undo_cgnat = |me: &mut Self| {
                if cgnat
                    && let Err(back) = crate::cgnat::apply(
                        &to.ip.cgnat,
                        &from.ip.cgnat,
                        &mut me.cgnat_blocks,
                        &mut me.cgnat_full,
                    )
                {
                    log::error!("restoring the previous CGNAT table: {back}");
                }
                if fast && let Err(back) = crate::fastpath::apply(from, &mut me.fastpath) {
                    log::error!("restoring the previous fast path: {back}");
                }
            };
            // Ethernet settings next: validated by the engine against what
            // the port supports, they rarely fail; if the plan below does,
            // they go back too.
            let tuning = (&from.system.tuning.sysctl, &to.system.tuning.sysctl);
            let ports = (&from_ports, &to_ports);
            let root = self.sysctl.root.clone();
            let cpu = (&from.system.tuning.cpu, &to.system.tuning.cpu);
            if let Err(e) = self.cpu.transition(cpu.0, cpu.1, &root) {
                undo_cgnat(self);
                if firewall && let Err(back) = crate::firewall::apply(to, from) {
                    log::error!("restoring the previous firewall: {back}");
                }
                return Err(e);
            }
            let undo_cpu = |me: &mut Self| {
                if let Err(b) = me.cpu.transition(cpu.1, cpu.0, &root) {
                    log::error!("restoring CPU settings: {b}");
                }
            };
            let tuned = self.sysctl.transition(tuning.0, tuning.1).and_then(|()| {
                self.ports
                    .transition(ports.0, ports.1, &root)
                    .and_then(|()| {
                        self.ether_transition(from, to).inspect_err(|_| {
                            if let Err(b) = self.ports.transition(ports.1, ports.0, &root) {
                                log::error!("restoring port settings: {b}");
                            }
                        })
                    })
                    .inspect_err(|_| {
                        if let Err(b) = self.sysctl.transition(tuning.1, tuning.0) {
                            log::error!("restoring kernel parameters: {b}");
                        }
                    })
            });
            if let Err(e) = tuned {
                undo_cpu(self);
                undo_cgnat(self);
                if firewall && let Err(back) = crate::firewall::apply(to, from) {
                    log::error!("restoring the previous firewall: {back}");
                }
                return Err(e);
            }
            if ops.is_empty() {
                self.claims = claims_of(to);
                // After the links exist (a new VLAN has no sysctl before).
                self.sync_ra(to);
                return Ok(());
            }
            let mut claims = claims_of(from);
            claims.extend(claims_of(to));
            let external: BTreeMap<String, String> = self
                .view(&claims)?
                .into_iter()
                .filter_map(|(l, o)| match o {
                    Owner::External(r) => Some((l.name, r)),
                    Owner::Managed | Owner::Conflict(_) => None,
                })
                .collect();
            let (skip, run): (Vec<Op>, Vec<Op>) = ops
                .into_iter()
                .partition(|op| op.link().is_some_and(|l| external.contains_key(l.as_str())));
            for op in &skip {
                let link = op.link().map_or("", |l| l.as_str());
                let why = external.get(link).map_or("", String::as_str);
                log::warn!("not applied: {op} ('{link}' is not managed: {why})");
            }
            let owned = crate::plan::owned_routes(from, to, &run);
            match crate::netlink::apply(&run, &owned) {
                Ok(()) => {
                    self.claims = claims_of(to);
                    self.sync_ra(to);
                    Ok(())
                }
                Err(e) => {
                    self.claims = claims_of(from);
                    if let Err(back) = self.ether_transition(to, from) {
                        log::error!("restoring Ethernet settings: {back}");
                    }
                    if let Err(back) = self.ports.transition(ports.1, ports.0, &root) {
                        log::error!("restoring port settings: {back}");
                    }
                    if let Err(back) = self.sysctl.transition(tuning.1, tuning.0) {
                        log::error!("restoring kernel parameters: {back}");
                    }
                    undo_cpu(self);
                    undo_cgnat(self);
                    if firewall {
                        // The links went back to `from`: so does the firewall.
                        if let Err(back) = crate::firewall::apply(to, from) {
                            return Err(HalError::Rejected(format!(
                                "{e}; restoring the previous firewall also failed: {back}"
                            )));
                        }
                    }
                    Err(e)
                }
            }
        }
    }

    impl LinuxHal {
        /// Every link name of the kernel with its index (one dump).
        fn link_names(&self) -> Result<BTreeMap<String, u32>, HalError> {
            Ok(crate::netlink::links()?
                .into_iter()
                .map(|l| (l.name, l.index))
                .collect())
        }

        /// `apply` with every port there. Everything else first (the
        /// interfaces must exist), XDP last; if XDP refuses, the rest goes
        /// back to `from`.
        fn apply_present(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
            self.apply_links(from, to)?;
            if let Err(e) = self.xdp.sync(to) {
                if let Err(back) = self.xdp.sync(from) {
                    log::error!("restoring the previous XDP filter: {back}");
                }
                if let Err(back) = self.apply_links(to, from) {
                    log::error!("restoring the rest after XDP refused: {back}");
                }
                return Err(e);
            }
            if from.ip.arp != to.ip.arp || from.interfaces != to.interfaces {
                let managed: std::collections::BTreeSet<IfName> = self
                    .managed_indexes()
                    .map(|m| m.into_values().collect())
                    .unwrap_or_default();
                if let Err(e) = self.neigh.sync(to, &|n| managed.contains(n)) {
                    if let Err(back) = self.xdp.sync(from) {
                        log::error!("restoring the previous XDP filter: {back}");
                    }
                    if let Err(back) = self.apply_links(to, from) {
                        log::error!(
                            "restoring the rest after the ARP entries were refused: {back}"
                        );
                    }
                    return Err(e);
                }
            }
            // MPLS (G3.5): the knobs and `/mpls static`, last (its own undo).
            if from.routing.mpls != to.routing.mpls || from.interfaces != to.interfaces {
                let managed: std::collections::BTreeSet<IfName> = self
                    .managed_indexes()
                    .map(|m| m.into_values().collect())
                    .unwrap_or_default();
                if let Err(e) = crate::mpls::sync(from, to, &|n| managed.contains(n)) {
                    if let Err(back) = self.neigh.sync(from, &|n| managed.contains(n)) {
                        log::error!("restoring the ARP entries after MPLS refused: {back}");
                    }
                    if let Err(back) = self.xdp.sync(from) {
                        log::error!("restoring the previous XDP filter: {back}");
                    }
                    if let Err(back) = self.apply_links(to, from) {
                        log::error!("restoring the rest after MPLS refused: {back}");
                    }
                    return Err(e);
                }
            }
            Ok(())
        }
    }

    impl Hal for LinuxHal {
        fn describe(&self) -> String {
            "linux (rtnetlink)".into()
        }

        /// Managed ports only (`owner` rules 6–8); everything else is in
        /// `poll`, marked unmanaged.
        fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
            Ok(self
                .view(&self.claims)?
                .into_iter()
                .filter(|(l, o)| *o == Owner::Managed && l.arphrd != owner::ARPHRD_LOOPBACK)
                .filter_map(|(l, _)| {
                    Some(LinkInfo {
                        name: l.name.parse().ok()?,
                        mtu: u16::try_from(l.mtu).ok()?,
                        mac: l.mac,
                        up: l.up,
                    })
                })
                .collect())
        }

        /// G1.3b: without the physical ports the kernel does not have
        /// ([`absent`]), so a port that is gone never takes the rest (the
        /// management address on another port) down with it. What `from`
        /// had on a port that is gone now, or that the last apply left out,
        /// is not in the kernel either. A port that goes away during the
        /// apply makes it fail and go back to `from`: tried once more
        /// without it. With no port known absent and the interfaces the
        /// same, the link dump is skipped (20.7 ms with 1000 links,
        /// **medido**): `poll` notes a port that goes, and an op that
        /// fails on one sends this through the retry, which looks.
        fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
            let mut retried = false;
            let mut look =
                !self.absent.is_empty() || corerouter_model::sections::interfaces_changed(from, to);
            loop {
                let names = if look { Some(self.link_names()?) } else { None };
                let present =
                    |n: &IfName| names.as_ref().is_none_or(|s| s.contains_key(n.as_str()));
                let gone = absent::missing(to, present);
                let mut was = self.absent.clone();
                was.extend(absent::missing(from, present));
                let (f, t) = (absent::mask(from, &was), absent::mask(to, &gone));
                match self.apply_present(&f, &t) {
                    Ok(()) => {
                        for n in gone.difference(&self.absent) {
                            log::warn!(
                                "'{n}' is not on this machine: its configuration waits for it (invalid)"
                            );
                        }
                        for n in self.absent.difference(&gone) {
                            if to.interfaces.contains_key(n) {
                                log::info!("'{n}' is back: its configuration was applied");
                            }
                        }
                        self.absent = gone;
                        // Every name of the config, absent ones included:
                        // `poll` sees a claimed port go, and one that comes
                        // back is CoreRouter's again.
                        self.claims = claims_of(to);
                        // G1.3d: the links that got the configuration. With
                        // no dump nothing was added nor came back, and an
                        // apply never recreates a physical port.
                        if let Some(names) = &names {
                            for (n, k) in &self.claims {
                                if let (InterfaceKind::Ethernet, Some(i)) =
                                    (k, names.get(n.as_str()))
                                {
                                    self.indices.insert(n.clone(), *i);
                                }
                            }
                        }
                        let claims = &self.claims;
                        self.indices.retain(|n, _| claims.contains_key(n));
                        return Ok(());
                    }
                    Err(e) => {
                        let now = self.link_names().unwrap_or_default();
                        let here = |n: &IfName| now.contains_key(n.as_str());
                        let went = absent::missing(to, here) != gone
                            || !absent::missing(from, here).is_subset(&was);
                        if retried || !went {
                            return Err(e);
                        }
                        log::warn!(
                            "a port went away during the apply ({e}): trying again without it"
                        );
                        retried = true;
                        look = true;
                    }
                }
            }
        }

        fn absent_ports(&self) -> Vec<IfName> {
            self.absent.iter().cloned().collect()
        }

        fn mpls_routes(&mut self) -> Result<Vec<corerouter_hal::mpls::MplsRoute>, HalError> {
            use corerouter_hal::mpls::MplsReader;
            crate::mpls::Reader::open()?.routes()
        }

        fn mpls_reader(&self) -> Result<Box<dyn corerouter_hal::mpls::MplsReader>, HalError> {
            Ok(Box::new(crate::mpls::Reader::open()?))
        }

        fn lsp_prober(&self) -> Result<corerouter_hal::lsp::SharedLspProber, String> {
            Ok(std::sync::Arc::new(crate::lsp::HostLspProber))
        }

        fn lsp_responder(&self) -> Result<Box<dyn corerouter_hal::lsp::LspResponderIo>, HalError> {
            Ok(Box::new(crate::lsp::HostResponder::open()?))
        }

        fn neighbors(&mut self) -> Result<Vec<corerouter_hal::neigh::Neighbor>, HalError> {
            crate::neigh::neighbors()
        }

        fn neighbor_feed(
            &mut self,
        ) -> Result<Box<dyn corerouter_hal::neigh::NeighborFeed>, HalError> {
            Ok(Box::new(crate::neigh::Feed::open()?))
        }

        fn neighbor_remove(
            &mut self,
            items: &[(IfName, std::net::IpAddr)],
        ) -> Result<usize, HalError> {
            crate::neigh::remove(items)
        }

        fn neighbor_static(
            &mut self,
            ops: &[corerouter_hal::neigh::StaticNeigh],
        ) -> Result<(), HalError> {
            let ops: Vec<crate::neigh::StaticOp> = ops
                .iter()
                .map(|o| crate::neigh::StaticOp {
                    interface: o.interface.clone(),
                    ip: std::net::IpAddr::V4(o.address),
                    mac: o.mac,
                    proxy: false,
                })
                .collect();
            crate::neigh::statics(&ops)
        }

        fn arp_pinger(
            &mut self,
            name: &IfName,
        ) -> Result<Box<dyn corerouter_hal::neigh::ArpPinger>, HalError> {
            Ok(Box::new(crate::neigh::Pinger::open(name)?))
        }

        fn xdp_status(&mut self, top: usize) -> Result<corerouter_hal::xdp::XdpStatus, HalError> {
            Ok(self.xdp.status(top))
        }

        fn xdp_reset(&mut self) -> Result<(), HalError> {
            self.xdp.reset()
        }

        fn pppoe_dataplane(&mut self, on: bool, ports: &[IfName]) -> Result<(), HalError> {
            if on {
                self.xdp.pppoe_ready(ports)?;
            }
            self.xdp.set_pppoe(on)
        }

        fn ipoe_dataplane(&mut self, on: bool, ports: &[IfName]) -> Result<(), HalError> {
            let mut idx = std::collections::BTreeSet::new();
            if on {
                self.xdp.pppoe_ready(ports)?;
                for p in ports {
                    let (i, _) =
                        crate::pppoe_io::port_info(p).map_err(|e| HalError::Io(e.to_string()))?;
                    idx.insert(i);
                }
            }
            self.xdp.set_ipoe(idx)
        }

        fn pppoe_apply(&mut self, ops: &[corerouter_hal::pppoe::PppoeOp]) -> Result<(), HalError> {
            self.xdp.pppoe_apply(ops)
        }

        fn shaper_apply(
            &mut self,
            plan: &corerouter_hal::queue::ShaperPlan,
        ) -> Result<(), HalError> {
            self.xdp.shaper_apply(plan)
        }

        fn shaper_status(&mut self) -> corerouter_hal::queue::ShaperStatus {
            self.xdp.shaper_status()
        }

        fn pppoe_counters(
            &mut self,
            slots: &[u32],
        ) -> Vec<(u32, corerouter_hal::pppoe::PppoeCounters)> {
            self.xdp.pppoe_counters_of(slots)
        }

        fn xdp_nat_link(&mut self) -> Result<Box<dyn corerouter_hal::xdp_nat::NatLink>, HalError> {
            self.xdp.nat_link()
        }

        fn system_info(&mut self) -> Result<SystemInfo, HalError> {
            Ok(self.sysctl.root.system_info())
        }

        fn sysctls(&mut self, names: &[&str]) -> Result<Sysctls, HalError> {
            Ok(self.sysctl.root.sysctls(names))
        }

        fn cgnat_blocks(
            &mut self,
            changes: &[corerouter_hal::cgnat::BlockChange],
        ) -> Result<(), HalError> {
            crate::cgnat::set_blocks(changes, &mut self.cgnat_blocks)
        }

        fn eswitch(
            &mut self,
            name: &IfName,
        ) -> Result<corerouter_hal::fastpath::Eswitch, HalError> {
            crate::fastpath::eswitch(name.as_str())
        }

        fn fastpath_state(&mut self) -> corerouter_hal::fastpath::FastPathState {
            self.fastpath.clone()
        }

        fn cgnat_queue(&mut self) -> Result<Box<dyn corerouter_hal::cgnat::CgnatQueue>, HalError> {
            let shared = self.cgnat_exhaustion.clone();
            crate::nfqueue::Queue::open(corerouter_hal::cgnat::QUEUE_NUM).map(|q| {
                Box::new(q.with_icmp(shared)) as Box<dyn corerouter_hal::cgnat::CgnatQueue>
            })
        }

        fn conntrack_scanner(
            &self,
        ) -> Result<Box<dyn corerouter_hal::conntrack::Scanner>, HalError> {
            Ok(Box::new(crate::ctnl::Scanner))
        }

        fn cgnat_full(&mut self, subscribers: &[std::net::Ipv4Addr]) -> Result<(), HalError> {
            let want: crate::cgnat::Full = subscribers.iter().copied().collect();
            if self.cgnat_full == want {
                return Ok(());
            }
            crate::cgnat::set_full(&want, &mut self.cgnat_full)
        }

        fn cgnat_exhaustion_queue(
            &mut self,
            index: u16,
        ) -> Result<Box<dyn corerouter_hal::cgnat::ExhaustionQueue>, HalError> {
            use corerouter_hal::cgnat::{EXHAUSTED_QUEUE, EXHAUSTED_QUEUES};
            if index >= EXHAUSTED_QUEUES {
                return Err(HalError::Rejected(format!(
                    "exhaustion queue {index}: there are {EXHAUSTED_QUEUES}"
                )));
            }
            crate::cgnat_icmp::ExhaustQueue::open(
                EXHAUSTED_QUEUE + index,
                self.cgnat_exhaustion.clone(),
            )
            .map(|q| Box::new(q) as Box<dyn corerouter_hal::cgnat::ExhaustionQueue>)
        }

        fn cgnat_exhausted(
            &mut self,
        ) -> (
            Vec<(std::net::Ipv4Addr, corerouter_hal::cgnat::Hit)>,
            corerouter_hal::cgnat::ExhaustionStats,
        ) {
            self.cgnat_exhaustion.take()
        }

        fn connections(&mut self) -> Result<Vec<corerouter_hal::conntrack::Conn>, HalError> {
            crate::ctnl::dump()
        }

        fn connection_stats(&mut self) -> Result<corerouter_hal::conntrack::Stats, HalError> {
            crate::ctnl::stats()
        }

        fn conntrack_events(
            &mut self,
        ) -> Result<Box<dyn corerouter_hal::conntrack::EventSource>, HalError> {
            Ok(Box::new(crate::ctnl::Events::open()?))
        }

        fn connections_kill(
            &mut self,
            conns: &[corerouter_hal::conntrack::Conn],
        ) -> Result<usize, HalError> {
            crate::ctnl::delete(conns)
        }

        fn resources(&mut self) -> Option<corerouter_hal::resources::Resources> {
            Some(self.sysctl.root.resources())
        }

        fn resource_sampler(
            &self,
        ) -> Result<Box<dyn corerouter_hal::system_resource::ResourceSampler>, String> {
            Ok(Box::new(crate::resource::Collector::default()))
        }

        fn kernel_stats(&mut self) -> Result<KernelStats, HalError> {
            Ok(self.sysctl.root.kernel_stats())
        }

        fn boot_cmdline(&mut self) -> Result<String, HalError> {
            self.sysctl
                .root
                .cmdline()
                .ok_or_else(|| HalError::Io("/proc/cmdline unreadable".into()))
        }

        fn cpu_tuning(&mut self) -> Result<CpuTuning, HalError> {
            Ok(self.cpu.read(&self.sysctl.root))
        }

        fn port_tuning(&mut self, name: &IfName) -> Result<PortTuning, HalError> {
            Ok(crate::port_tuning::read(name, &self.sysctl.root))
        }

        fn poll(&mut self) -> Vec<LinkState> {
            // The hardware watchdog (G1.26c) is fed as long as polls come.
            self.cpu.feed();
            let view = match self.view(&self.claims) {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("link poll failed: {e}");
                    return Vec::new();
                }
            };
            // G1.3b: a claimed port the kernel no longer has lost its
            // configuration with it; the next apply puts it back. G1.3d:
            // so did one with a new index (gone and back since the last
            // look): the engine sees it absent and present, and reapplies.
            let names: BTreeMap<&str, u32> = view
                .iter()
                .map(|(l, _)| (l.name.as_str(), l.index))
                .collect();
            for (n, k) in &self.claims {
                if *k != InterfaceKind::Ethernet {
                    continue;
                }
                match names.get(n.as_str()) {
                    None => {
                        if self.absent.insert(n.clone()) {
                            log::warn!("'{n}' went away: its configuration waits for it (invalid)");
                        }
                    }
                    Some(&i) => match self.indices.insert(n.clone(), i) {
                        Some(was) if was != i => {
                            if self.absent.insert(n.clone()) {
                                log::warn!(
                                    "'{n}' was replugged (link #{was} is now #{i}): its configuration is applied again"
                                );
                            }
                        }
                        _ => {}
                    },
                }
            }
            view.into_iter()
                .filter_map(|(l, o)| {
                    Some(LinkState {
                        name: l.name.parse().ok()?,
                        running: l.running,
                        rx_bytes: l.rx_bytes,
                        tx_bytes: l.tx_bytes,
                        rx_packets: l.rx_packets,
                        tx_packets: l.tx_packets,
                        kind: l.label(),
                        mtu: l.mtu,
                        mac: l.mac,
                        unmanaged: o.reason().map(str::to_owned),
                        errors: l.errors,
                        bus: l.bus,
                    })
                })
                .collect()
        }

        /// Managed links of `cfg` as the kernel has them, and the
        /// addresses and static routes on them (G1.3).
        fn snapshot(&mut self, cfg: &Config) -> Result<Snapshot, HalError> {
            let mut claims = self.claims.clone();
            claims.extend(claims_of(cfg));
            let view = self.view(&claims)?;
            let by_index: BTreeMap<u32, &str> = view
                .iter()
                .map(|(l, _)| (l.index, l.name.as_str()))
                .collect();
            let mut links = BTreeMap::new();
            let mut managed = BTreeMap::new();
            for (l, o) in &view {
                let Ok(name) = l.name.parse::<IfName>() else {
                    continue;
                };
                if *o != Owner::Managed || !cfg.interfaces.contains_key(&name) {
                    continue;
                }
                let master = l
                    .master
                    .and_then(|i| by_index.get(&i))
                    .and_then(|m| m.parse().ok());
                let mut snap = LinkSnap {
                    up: l.up,
                    mtu: l.mtu,
                    master,
                };
                // The OS loopback's state and MTU are the OS's (G3.4i): what
                // the config says, so they are never drift to repair.
                if l.arphrd == owner::ARPHRD_LOOPBACK
                    && let Some(want) = corerouter_hal::drift::expected_links(cfg).remove(&name)
                {
                    snap = want;
                }
                links.insert(name.clone(), snap);
                managed.insert(l.index, name);
            }
            let (mut addresses, routes, discards) = crate::netlink::held(&managed)?;
            // 127.0.0.1/8 and ::1 on `lo` are the OS's, never CoreRouter's.
            addresses.retain(|(link, a)| {
                !(corerouter_model::os_loopback::is_os_loopback(cfg, link)
                    && corerouter_model::os_loopback::is_os_address(a))
            });
            // G1.5a: routes without next hop have no link; those of the
            // config's tables (main and its VRFs) are CoreRouter's to compare.
            let tables: std::collections::BTreeSet<u32> =
                std::iter::once(corerouter_model::route::MAIN_TABLE_ID)
                    .chain(cfg.interfaces.values().filter_map(|i| match i.kind {
                        corerouter_model::InterfaceKind::Vrf { table } => Some(table),
                        _ => None,
                    }))
                    .collect();
            let discards = discards
                .into_iter()
                .filter(|d| tables.contains(&d.table))
                .collect();
            Ok(Snapshot {
                links,
                addresses,
                routes,
                discards,
            })
        }

        /// `RTM_GETROUTE` (G1.27).
        fn route_get(
            &mut self,
            cfg: &Config,
            q: &corerouter_hal::route_get::RouteQuery,
        ) -> Result<corerouter_hal::route_get::KernelLookup, HalError> {
            let _ = cfg;
            crate::netlink::route_get(q)
        }

        /// One round of [`crate::plan::repair`], all or nothing.
        fn reconcile(&mut self, cfg: &Config) -> Result<(), HalError> {
            // G1.3b: a port that is gone now is left to come back.
            let names = self.link_names()?;
            let gone = absent::missing(cfg, |n| names.contains_key(n.as_str()));
            let cfg = &*absent::mask(cfg, &gone);
            let have = self.snapshot(cfg)?;
            let ops = crate::plan::repair(cfg, &have);
            for op in &ops {
                log::info!("reconcile: {op}");
            }
            crate::netlink::apply(&ops, &crate::plan::kernel_routes(cfg))
        }

        fn unmanaged(&mut self) -> Vec<(IfName, String)> {
            match self.view(&self.claims) {
                Ok(v) => v
                    .into_iter()
                    .filter_map(|(l, o)| Some((l.name.parse().ok()?, o.reason()?.to_owned())))
                    .collect(),
                Err(e) => {
                    log::warn!("link dump failed: {e}");
                    Vec::new()
                }
            }
        }

        fn now_unix(&self) -> Option<u64> {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs())
        }

        fn monotonic_secs(&self) -> Option<u64> {
            // CLOCK_MONOTONIC: an NTP step of the wall clock does not move it.
            static START: OnceLock<std::time::Instant> = OnceLock::new();
            Some(
                START
                    .get_or_init(std::time::Instant::now)
                    .elapsed()
                    .as_secs(),
            )
        }

        fn features(&self) -> Features {
            // MPLS again each time (one stat): `modprobe mpls_router`
            // takes effect without a restart.
            Features {
                mpls: crate::mpls::available(),
                ..*self.features.get_or_init(crate::netlink::features)
            }
        }

        fn address_list_dynamic(&mut self, change: DynamicChange<'_>) -> Result<(), HalError> {
            self.xdp.dynamic(change);
            match change {
                DynamicChange::Add(d) => crate::firewall::apply_dynamic(&[(true, d)]),
                DynamicChange::Remove(d) => crate::firewall::apply_dynamic(&[(false, d)]),
                // The set's own timeout already removed them from the
                // kernel: nothing to run (it was one `nft` process per
                // entry, under the session lock).
                DynamicChange::Expired(_) => Ok(()),
            }
        }

        fn address_list_dynamic_many(
            &mut self,
            changes: &[DynamicChange<'_>],
        ) -> Result<(), HalError> {
            let mut ops = Vec::with_capacity(changes.len());
            self.xdp.dynamic_many(changes);
            for c in changes {
                match c {
                    DynamicChange::Add(d) => ops.push((true, *d)),
                    DynamicChange::Remove(d) => ops.push((false, *d)),
                    DynamicChange::Expired(_) => {}
                }
            }
            crate::firewall::apply_dynamic(&ops)
        }

        fn dhcp_port(
            &mut self,
            name: &IfName,
        ) -> Result<Box<dyn corerouter_hal::DhcpPort>, HalError> {
            crate::dhcp::LinuxDhcpPort::open(name)
                .map(|p| Box::new(p) as Box<dyn corerouter_hal::DhcpPort>)
                .map_err(|e| HalError::Io(e.to_string()))
        }

        fn pppoe_client_port(
            &mut self,
            client: &IfName,
            uplink: &IfName,
        ) -> Result<Box<dyn corerouter_hal::pppoe_client::PppoeClientPort>, HalError> {
            let relay = corerouter_model::pppoe_client::relay_peer(client.as_str());
            crate::pppoe_client_io::LinuxPppoeClientPort::open(client, &relay, uplink)
                .map(|p| Box::new(p) as Box<dyn corerouter_hal::pppoe_client::PppoeClientPort>)
                .map_err(|e| HalError::Io(e.to_string()))
        }

        fn dhcp_server_port(
            &mut self,
            name: &IfName,
        ) -> Result<Box<dyn corerouter_hal::dhcp_server::DhcpServerPort>, HalError> {
            crate::dhcp_server::LinuxDhcpServerPort::open(name)
                .map(|p| Box::new(p) as Box<dyn corerouter_hal::dhcp_server::DhcpServerPort>)
                .map_err(|e| HalError::Io(e.to_string()))
        }

        fn dhcp_relay_uplink(
            &mut self,
        ) -> Result<Box<dyn corerouter_hal::dhcp_server::DhcpUplink>, HalError> {
            crate::dhcp_server::LinuxDhcpUplink::open()
                .map(|p| Box::new(p) as Box<dyn corerouter_hal::dhcp_server::DhcpUplink>)
                .map_err(|e| HalError::Io(e.to_string()))
        }

        fn dhcp6_server_port(
            &mut self,
            name: &IfName,
        ) -> Result<Box<dyn corerouter_hal::dhcp_server::Dhcp6ServerPort>, HalError> {
            crate::dhcp6_server::LinuxDhcp6ServerPort::open(name)
                .map(|p| Box::new(p) as Box<dyn corerouter_hal::dhcp_server::Dhcp6ServerPort>)
                .map_err(|e| HalError::Io(e.to_string()))
        }

        fn dhcp6_relay_uplink(
            &mut self,
        ) -> Result<Box<dyn corerouter_hal::dhcp_server::Dhcp6Uplink>, HalError> {
            crate::dhcp6_server::LinuxDhcp6Uplink::open()
                .map(|p| Box::new(p) as Box<dyn corerouter_hal::dhcp_server::Dhcp6Uplink>)
                .map_err(|e| HalError::Io(e.to_string()))
        }

        fn dhcp6_port(
            &mut self,
            name: &IfName,
        ) -> Result<Box<dyn corerouter_hal::Dhcp6Port>, HalError> {
            crate::dhcp6::LinuxDhcp6Port::open(name)
                .map(|p| Box::new(p) as Box<dyn corerouter_hal::Dhcp6Port>)
                .map_err(|e| HalError::Io(e.to_string()))
        }

        fn ipv6_learned(&mut self) -> Result<Vec<corerouter_hal::Learned>, HalError> {
            let names = self.managed_indexes()?;
            crate::netlink::learned(&names)
        }

        fn address_states(
            &mut self,
        ) -> Result<Vec<corerouter_hal::address_state::AddressState>, HalError> {
            let names = self.managed_indexes()?;
            crate::netlink::address_states(&names)
        }

        fn prober(&self) -> Result<corerouter_hal::SharedProber, String> {
            let p = self
                .prober
                .get_or_init(crate::icmp::HostProber::detect)
                .clone()?;
            Ok(std::sync::Arc::new(p))
        }

        fn ethernet_monitor(&mut self, name: &IfName) -> Result<EthernetMonitor, HalError> {
            crate::nic::monitor(name.as_str())
        }

        fn hardware(&mut self, name: &IfName) -> Result<NicHardware, HalError> {
            crate::nic::hardware(name.as_str())
        }

        fn counters(&mut self, name: &IfName) -> Result<LinkCounters, HalError> {
            crate::nic::counters(name.as_str())
        }

        fn sfp_module(&mut self, name: &IfName) -> Result<SfpModule, HalError> {
            crate::nic::sfp_module(name.as_str())
        }

        fn packet_capture(&self) -> Result<corerouter_hal::capture::SharedCapture, String> {
            Ok(std::sync::Arc::new(crate::capture::HostCapture))
        }

        fn usb_tx_timeouts(&mut self, name: &IfName) -> Option<u64> {
            crate::nic::tx_timeouts(&std::path::Path::new("/sys/class/net").join(name.as_str()))
        }

        fn usb_reset(
            &mut self,
            name: &IfName,
            level: corerouter_hal::nic::UsbResetLevel,
        ) -> Result<Box<dyn corerouter_hal::nic::UsbReset>, HalError> {
            Ok(Box::new(crate::nic::usb_reset(name.as_str(), level)?))
        }

        fn cable_tester(&mut self, name: &IfName) -> Result<Box<dyn CableTest>, HalError> {
            crate::netlink::link_detail(name.as_str())?
                .ok_or_else(|| HalError::Rejected(format!("no link '{name}' in the kernel")))?;
            Ok(Box::new(crate::ethtool::LinuxCableTest {
                dev: name.as_str().to_owned(),
            }))
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::LinuxHal;

pub use owner::Policy;
