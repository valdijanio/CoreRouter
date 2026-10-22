//! Virtual lab backend: deterministic fake ports and counters.

use std::sync::Arc;

use corerouter_model::firewall::DynamicAddress;
use corerouter_model::{Config, IfName};

use crate::{DynamicChange, Features, Hal, HalError, LinkInfo, LinkState, SharedProber, SimProber};

#[derive(Clone)]
pub struct VirtualHal {
    ports: Vec<IfName>,
    applied: Config,
    ticks: u64,
    applies: u64,
    /// The nftables script the last firewall change would have loaded
    /// (the lab records it; nothing runs it).
    ruleset: Option<String>,
    dynamic: Vec<DynamicAddress>,
    /// Diagnostic tools: the simulated network unless the app swaps in the
    /// host's ICMP (`corerouter-daemon --lab-ping host`).
    prober: SharedProber,
}

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
        let ports = (1..=ports)
            .filter_map(|i| format!("ether{i}").parse().ok())
            .collect();
        Self {
            ports,
            applied: Config::default(),
            ticks: 0,
            applies: 0,
            ruleset: None,
            dynamic: Vec::new(),
            prober: Arc::new(SimProber::default()),
        }
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

    pub fn dynamic(&self) -> &[DynamicAddress] {
        &self.dynamic
    }
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
                mac: Some(format!("02:00:00:00:00:{:02X}", (i + 1) & 0xFF)),
                mtu: 1500,
                up: true,
            })
            .collect())
    }

    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        if corerouter_firewall::render(from, &[]) != corerouter_firewall::render(to, &[]) {
            self.ruleset = Some(corerouter_firewall::script(to, &self.dynamic));
        }
        self.applied = to.clone();
        self.applies = self.applies.saturating_add(1);
        Ok(())
    }

    fn poll(&mut self) -> Vec<LinkState> {
        self.ticks = self.ticks.wrapping_add(1);
        let t = self.ticks;
        self.applied
            .interfaces
            .values()
            .enumerate()
            .map(|(i, iface)| {
                let up = !iface.disabled;
                let rate = if up { 1_000 * (i as u64 + 1) } else { 0 };
                LinkState {
                    name: iface.name.clone(),
                    running: up,
                    rx_bytes: rate.wrapping_mul(t).wrapping_mul(1_500),
                    tx_bytes: rate.wrapping_mul(t).wrapping_mul(900),
                    rx_packets: rate.wrapping_mul(t),
                    tx_packets: rate.wrapping_mul(t) / 2,
                    kind: iface.kind.label().to_owned(),
                    mtu: u32::from(iface.mtu),
                    mac: iface.mac.map(|m| m.to_string()),
                    unmanaged: None,
                }
            })
            .collect()
    }

    fn now_unix(&self) -> Option<u64> {
        None
    }

    fn features(&self) -> Features {
        Features { vrf: true }
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
        }
        Ok(())
    }

    fn prober(&self) -> Result<SharedProber, String> {
        Ok(Arc::clone(&self.prober))
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
}
