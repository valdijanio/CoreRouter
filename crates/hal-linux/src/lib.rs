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
//!
//! Integration tests run against a real kernel inside a throwaway network
//! namespace, without root: see `tests/netns.rs`.

pub mod owner;
pub mod pci_ids;
pub mod plan;

/// Generic netlink codec (pure) and socket (Linux) for G1.19.
mod genl;

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

/// Host ICMP for the diagnostic tools (G6.2).
#[cfg(target_os = "linux")]
pub mod icmp;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};

    use corerouter_hal::{
        DynamicChange, EthernetMonitor, Features, Hal, HalError, LinkCounters, LinkInfo, LinkState,
        NicHardware,
    };
    use corerouter_model::{Config, IfName, InterfaceKind};

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
            if ops.is_empty() {
                self.claims = claims_of(to);
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
                    Ok(())
                }
                Err(e) => {
                    self.claims = claims_of(from);
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
    }
}

#[cfg(target_os = "linux")]
pub use linux::LinuxHal;

pub use owner::Policy;
