//! Virtual lab backend: deterministic fake ports and counters.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use corerouter_model::firewall::DynamicAddress;
use corerouter_model::{Config, FlowControl, IfName, InterfaceKind};

use crate::nic::{
    CablePair, CableTest, CableTestResult, CounterGroup, EthernetMonitor, LinkCounters,
    NicHardware, Offload, base_t_modes, mode_speed,
};
use crate::sff::{self, SfpModule};
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
    /// Times each port was enabled again (each one is a simulated link
    /// down and up, G1.19).
    reenabled: BTreeMap<IfName, u32>,
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
            reenabled: BTreeMap::new(),
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

    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        if corerouter_firewall::render(from, &[]) != corerouter_firewall::render(to, &[]) {
            self.ruleset = Some(corerouter_firewall::script(to, &self.dynamic));
        }
        for (name, iface) in &to.interfaces {
            let was_off = from.interfaces.get(name).is_some_and(|i| i.disabled);
            if was_off && !iface.disabled {
                let n = self.reenabled.entry(name.clone()).or_insert(0);
                *n = n.saturating_add(1);
            }
        }
        self.applied = to.clone();
        self.applies = self.applies.saturating_add(1);
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
            rx_queues: Some(4),
            tx_queues: Some(4),
            combined_channels: Some(4),
            combined_channels_max: Some(8),
            ring_rx: Some(1024),
            ring_rx_max: Some(4096),
            ring_tx: Some(1024),
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
