//! Linux backend.
//!
//! - `apply`: [`plan::plan`] turns the diff `from` → `to` into ordered kernel
//!   operations (pure, tested everywhere); `netlink` runs them over rtnetlink
//!   and undoes the done ones if one fails (G1.2).
//! - discovery and counters: one `RTM_GETLINK` dump (`netlink::links`), the
//!   same namespace `apply` writes to (G1.7/G1.18); `owner` decides which
//!   links are CoreRouter's. The others are listed but never applied to.
//! - `l2`: neighbor-discovery I/O — LLDP frames over `AF_PACKET`, passive
//!   MNDP over UDP 5678 (G5.2). Bytes only; the codecs are `proto-lldp` /
//!   `proto-mndp`, glued by the daemon.
//! - `features`: probed once, on first use, with a throwaway link per
//!   capability (`netlink::features`), then cached (G1.14).
//!
//! Integration tests run against a real kernel inside a throwaway network
//! namespace, without root: see `tests/netns.rs`.

pub mod owner;
pub mod plan;

#[cfg(target_os = "linux")]
mod netlink;

#[cfg(target_os = "linux")]
pub mod l2;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};

    use corerouter_hal::{Features, Hal, HalError, LinkInfo, LinkState};
    use corerouter_model::{Config, IfName, InterfaceKind};

    use crate::owner::{self, KernelLink, Owner, Policy};
    use crate::plan::Op;

    #[derive(Debug, Default)]
    pub struct LinuxHal {
        /// Probed on the first `features()` call, not at startup.
        features: OnceLock<Features>,
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
    }
}

#[cfg(target_os = "linux")]
pub use linux::LinuxHal;

pub use owner::Policy;
