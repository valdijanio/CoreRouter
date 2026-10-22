//! Virtual lab backend: deterministic fake ports and counters.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use corerouter_model::firewall::DynamicAddress;
use corerouter_model::{Config, IfName, InterfaceKind};

use crate::dhcp::{
    Datagram, Datagram6, Dest, Dhcp6Port, DhcpPort, SharedResponder, SharedResponder6, eui64,
    lab_net, lab_router_mac, link_local,
};
use crate::nic::{CounterGroup, EthernetMonitor, LinkCounters, NicHardware, Offload, base_t_modes};
use crate::{
    DynamicChange, Features, Hal, HalError, Learned, LinkInfo, LinkState, SharedProber, SimProber,
};

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
    /// Simulated DHCP server answering the lab's DHCP clients (G4.7).
    dhcp: Option<SharedResponder>,
    /// Simulated DHCPv6 server (G4.7b).
    dhcp6: Option<SharedResponder6>,
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
            dhcp: None,
            dhcp6: None,
            reenabled: BTreeMap::new(),
        }
    }

    /// Answer DHCP clients with `server` (a test's own scenario) instead of
    /// the lab server the engine offers.
    pub fn with_dhcp_server(mut self, server: SharedResponder) -> Self {
        self.dhcp = Some(server);
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

    pub fn dynamic(&self) -> &[DynamicAddress] {
        &self.dynamic
    }

    /// Position of a lab port (`ether3` → 2).
    fn port_index(&self, name: &IfName) -> Option<usize> {
        self.ports.iter().position(|p| p == name)
    }

    /// Fastest rate of a lab port: the last one is a 10G port, the rest 1G.
    fn port_speed(&self, index: usize) -> u32 {
        if index + 1 == self.ports.len() && index > 0 {
            10_000
        } else {
            1000
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
    /// re-enable.
    fn ethernet_monitor(&mut self, name: &IfName) -> Result<EthernetMonitor, HalError> {
        let iface = self
            .applied
            .interfaces
            .get(name)
            .ok_or_else(|| self.missing(name))?;
        let index = match (&iface.kind, self.port_index(name)) {
            (InterfaceKind::Ethernet, Some(i)) => i,
            _ => {
                return Err(HalError::Unsupported(format!(
                    "'{name}' is a {}, not an Ethernet port",
                    iface.kind.label()
                )));
            }
        };
        let up = !iface.disabled;
        let speed = self.port_speed(index);
        let modes = base_t_modes(speed);
        let downs = u32::try_from(index % 3)
            .unwrap_or(0)
            .saturating_add(self.reenabled.get(name).copied().unwrap_or(0));
        Ok(EthernetMonitor {
            link_ok: up,
            speed_mbps: up.then_some(speed),
            full_duplex: up.then_some(true),
            autoneg: Some(true),
            port: Some("twisted-pair".into()),
            mdix: up.then(|| if index % 2 == 0 { "mdi" } else { "mdi-x" }.into()),
            mdix_ctrl: Some("auto".into()),
            supported: modes.clone(),
            advertising: modes.clone(),
            partner_advertising: if up { modes } else { Vec::new() },
            rx_flow_control: Some(false),
            tx_flow_control: Some(false),
            flow_control_autoneg: Some(true),
            carrier_changes: Some(downs.saturating_mul(2).saturating_add(u32::from(up))),
            link_downs: Some(downs),
            down_reason: (!up).then(|| "administratively disabled".into()),
            notes: Vec::new(),
        })
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
        let offload = |name: &str, feature: &str, active: bool, fixed: bool| Offload {
            name: name.into(),
            feature: feature.into(),
            active,
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
            model: Some(if self.port_speed(index) > 1000 {
                "Virtual NIC 10G".into()
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

    fn offer_dhcp_lab_server(&mut self, server: SharedResponder) {
        if self.dhcp.is_none() {
            self.dhcp = Some(server);
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
            let enslaved = cfg
                .interfaces
                .get(name)
                .is_some_and(|i| i.bridge.is_some() || matches!(i.kind, InterfaceKind::Vrf { .. }));
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
