//! What the interface dialog shows about one port (G1.19): its live
//! Ethernet state (RouterOS `/interface ethernet monitor`), the NIC behind
//! it, and its counters.
//!
//! A driver that cannot report something is normal, not an error: every
//! field is `None` / empty then, and `notes` says why when the backend
//! knows. The trait methods ([`crate::Hal::ethernet_monitor`],
//! [`crate::Hal::hardware`], [`crate::Hal::counters`]) return
//! [`crate::HalError::Unsupported`] only when the backend has nothing at
//! all for that port.

use std::time::Duration;

use serde::Serialize;

use crate::HalError;

/// Bound on the lists below (link modes, IRQs, offloads, counters): a
/// driver reporting more is hostile or broken, and nobody reads 4096 rows.
pub const MAX_ITEMS: usize = 512;

/// Live link state, like `/interface ethernet monitor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EthernetMonitor {
    /// Carrier: RouterOS `status: link-ok` / `no-link`.
    pub link_ok: bool,
    /// Negotiated (or forced) rate; `None` with no link or when unknown.
    pub speed_mbps: Option<u32>,
    pub full_duplex: Option<bool>,
    /// Auto-negotiation turned on (the outcome is derived by the engine).
    pub autoneg: Option<bool>,
    /// `twisted-pair`, `fibre`, `direct-attach`, `mii`, `aui`, `bnc`,
    /// `none`, `other`.
    pub port: Option<String>,
    /// Resolved MDI state: `mdi` or `mdi-x`.
    pub mdix: Option<String>,
    /// MDI configuration: `auto`, `mdi` or `mdi-x`.
    pub mdix_ctrl: Option<String>,
    /// Link modes the port can do, kernel names (`1000baseT/Full`).
    pub supported: Vec<String>,
    /// Modes advertised while auto-negotiating.
    pub advertising: Vec<String>,
    /// Modes the other end advertises.
    pub partner_advertising: Vec<String>,
    pub rx_flow_control: Option<bool>,
    pub tx_flow_control: Option<bool>,
    /// Pause frames negotiated with auto-negotiation.
    pub flow_control_autoneg: Option<bool>,
    /// Carrier transitions since the driver loaded (up + down).
    pub carrier_changes: Option<u32>,
    /// Times the carrier went down (RouterOS `link-downs`).
    pub link_downs: Option<u32>,
    /// Why the link is down, when the driver says (`no-cable`,
    /// `autoneg`, `link-training-failure`, …).
    pub down_reason: Option<String>,
    pub notes: Vec<String>,
}

/// One offload and whether it is on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Offload {
    /// Short name: `TSO`, `GSO`, `GRO`, `RX checksum`, …
    pub name: String,
    /// Kernel feature behind it (`tx-tcp-segmentation`).
    pub feature: String,
    pub active: bool,
    /// The driver does not let it change.
    pub fixed: bool,
}

/// The NIC behind a port and how the driver set it up.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NicHardware {
    /// Address in use now.
    pub mac: Option<String>,
    /// Factory address (RouterOS `orig-mac-address`).
    pub perm_mac: Option<String>,
    pub min_mtu: Option<u32>,
    /// Largest MTU the driver accepts (the closest Linux has to `l2mtu`).
    pub max_mtu: Option<u32>,
    /// `pci`, `usb`, `virtio`, `platform`, `virtual`.
    pub bus: Option<String>,
    /// `0000:03:00.0`.
    pub bus_address: Option<String>,
    pub vendor_id: Option<u16>,
    pub device_id: Option<u16>,
    pub subsystem_vendor_id: Option<u16>,
    pub subsystem_device_id: Option<u16>,
    /// Names for the ids (`pci.ids`), when the system has the database.
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub subsystem: Option<String>,
    pub driver: Option<String>,
    pub driver_version: Option<String>,
    pub firmware: Option<String>,
    pub serial: Option<String>,
    pub numa_node: Option<u32>,
    pub rx_queues: Option<u32>,
    pub tx_queues: Option<u32>,
    /// Channels in use / maximum (rx+tx pairs; ethtool `combined`).
    pub combined_channels: Option<u32>,
    pub combined_channels_max: Option<u32>,
    pub irqs: Vec<u32>,
    pub ring_rx: Option<u32>,
    pub ring_rx_max: Option<u32>,
    pub ring_tx: Option<u32>,
    pub ring_tx_max: Option<u32>,
    pub offloads: Vec<Offload>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Counter {
    pub name: String,
    pub value: u64,
}

/// Counters of one source: `interface` (the kernel's link counters), then
/// the standard groups the driver fills (`eth-phy`, `eth-mac`, `eth-ctrl`,
/// `rmon`, `pause`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CounterGroup {
    pub name: String,
    pub counters: Vec<Counter>,
}

impl CounterGroup {
    pub fn new(name: &str, counters: impl IntoIterator<Item = (String, u64)>) -> Self {
        Self {
            name: name.to_owned(),
            counters: counters
                .into_iter()
                .take(MAX_ITEMS)
                .map(|(name, value)| Counter { name, value })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LinkCounters {
    pub groups: Vec<CounterGroup>,
    pub notes: Vec<String>,
}

/// Link mode names of the speeds [`crate::VirtualHal`] simulates.
pub(crate) fn base_t_modes(max_mbps: u32) -> Vec<String> {
    [10u32, 100, 1000, 2500, 10_000]
        .into_iter()
        .filter(|s| *s <= max_mbps)
        .flat_map(|s| {
            let half = (s <= 100).then(|| format!("{s}baseT/Half"));
            half.into_iter().chain([format!("{s}baseT/Full")])
        })
        .collect()
}

/// One twisted pair after a cable test (G1.20).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CablePair {
    /// `A`..`D`.
    pub pair: String,
    /// `ok`, `open`, `short` (within the pair), `cross-short` (to another
    /// pair), `impedance-mismatch`, `noise`, `unknown`.
    pub status: String,
    /// Distance to the fault in meters, when the PHY measures it (an open
    /// pair at the far end gives the cable length).
    pub distance_m: Option<f64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct CableTestResult {
    pub pairs: Vec<CablePair>,
    pub notes: Vec<String>,
}

/// A cable test (TDR) that runs away from the session lock: the link
/// goes down while the PHY measures, a few seconds.
pub trait CableTest: Send {
    /// Run to the end. `wait(d)` sleeps up to `d` and returns `false` when
    /// the task was stopped, so a test gives up between steps.
    fn run(&mut self, wait: &dyn Fn(Duration) -> bool) -> Result<CableTestResult, HalError>;
}

/// Rate and duplex of a kernel link mode: `1000baseT/Full` → (1000, true).
/// Bits that are not a rate (`Autoneg`, `TP`, `Pause`, `FEC_RS`) are `None`.
pub fn mode_speed(mode: &str) -> Option<(u32, bool)> {
    let (rate, rest) = mode.split_once("base")?;
    let speed = rate.parse::<u32>().ok().filter(|s| *s > 0)?;
    let full = match rest.rsplit_once('/')?.1 {
        "Full" => true,
        "Half" => false,
        _ => return None,
    };
    Some((speed, full))
}

#[cfg(test)]
mod tests {
    use super::mode_speed;

    #[test]
    fn link_mode_names() {
        assert_eq!(mode_speed("1000baseT/Full"), Some((1000, true)));
        assert_eq!(mode_speed("10baseT/Half"), Some((10, false)));
        assert_eq!(mode_speed("10000baseSR/Full"), Some((10_000, true)));
        assert_eq!(mode_speed("100000baseCR4/Full"), Some((100_000, true)));
        for not in [
            "Autoneg",
            "TP",
            "Pause",
            "Asym_Pause",
            "FEC_RS",
            "basebase/Full",
            "",
        ] {
            assert_eq!(mode_speed(not), None, "{not}");
        }
    }
}
