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

#[cfg(target_os = "linux")]
pub mod nft;

#[cfg(target_os = "linux")]
pub mod l2;

/// DHCP client transport (G4.7): `AF_PACKET` + BPF, UDP, ARP probe.
#[cfg(target_os = "linux")]
pub mod dhcp;

/// DHCPv6 client transport (G4.7b): UDP 546 → ff02::1:2.
#[cfg(target_os = "linux")]
pub mod dhcp6;

/// Router Advertisements: `accept_ra` per interface, flush (G4.7b).
#[cfg(target_os = "linux")]
pub mod ra;

/// Host ICMP for the diagnostic tools (G6.2).
#[cfg(target_os = "linux")]
pub mod icmp;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};

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
                Ok(v) => v
                    .into_iter()
                    .filter(|(_, o)| *o == Owner::Managed)
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

    fn claims_of(cfg: &Config) -> BTreeMap<IfName, InterfaceKind> {
        cfg.interfaces
            .iter()
            .map(|(n, i)| (n.clone(), i.kind.clone()))
            .collect()
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
                .filter(|(_, o)| *o == Owner::Managed)
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

        /// Ops on links CoreRouter does not own are dropped (logged), so a
        /// stale config can never reach another program's link; conflicts
        /// go to the executor, which refuses them and rolls back.
        fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
            let ops = crate::plan::plan(from, to)?;
            // nftables first (a refusal changes nothing), and only when the
            // firewall changed: a host without nftables still runs the rest.
            let firewall =
                corerouter_firewall::render(from, &[]) != corerouter_firewall::render(to, &[]);
            if firewall {
                let dynamic = crate::nft::dynamic();
                crate::nft::run(&corerouter_firewall::script(to, &dynamic))?;
            }
            // Ethernet settings next: validated by the engine against what
            // the port supports, they rarely fail; if the plan below does,
            // they go back too.
            if let Err(e) = self.ether_transition(from, to) {
                if firewall {
                    let dynamic = crate::nft::dynamic();
                    if let Err(back) = crate::nft::run(&corerouter_firewall::script(from, &dynamic))
                    {
                        log::error!("restoring the previous firewall: {back}");
                    }
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
                .partition(|op| external.contains_key(op.link().as_str()));
            for op in &skip {
                let why = external.get(op.link().as_str()).map_or("", String::as_str);
                log::warn!("not applied: {op} ('{}' is not managed: {why})", op.link());
            }
            match crate::netlink::apply(&run) {
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
                    if firewall {
                        // The links went back to `from`: so does the firewall.
                        let dynamic = crate::nft::dynamic();
                        if let Err(back) =
                            crate::nft::run(&corerouter_firewall::script(from, &dynamic))
                        {
                            return Err(HalError::Rejected(format!(
                                "{e}; restoring the previous firewall also failed: {back}"
                            )));
                        }
                    }
                    Err(e)
                }
            }
        }

        fn poll(&mut self) -> Vec<LinkState> {
            let view = match self.view(&self.claims) {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("link poll failed: {e}");
                    return Vec::new();
                }
            };
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
                    })
                })
                .collect()
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

        fn features(&self) -> Features {
            *self.features.get_or_init(crate::netlink::features)
        }

        fn address_list_dynamic(&mut self, change: DynamicChange<'_>) -> Result<(), HalError> {
            match change {
                DynamicChange::Add(d) => crate::nft::add_dynamic(d),
                DynamicChange::Remove(d) => crate::nft::remove_dynamic(d),
            }
        }

        fn dhcp_port(
            &mut self,
            name: &IfName,
        ) -> Result<Box<dyn corerouter_hal::DhcpPort>, HalError> {
            crate::dhcp::LinuxDhcpPort::open(name)
                .map(|p| Box::new(p) as Box<dyn corerouter_hal::DhcpPort>)
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
