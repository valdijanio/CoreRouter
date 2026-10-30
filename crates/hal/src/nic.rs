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
    /// The USB device behind a USB adapter (G1.29b); `None` on any other
    /// bus.
    pub usb: Option<UsbInfo>,
    pub notes: Vec<String>,
}

/// A USB Ethernet adapter as the USB core sees it (G1.29b): what it
/// negotiated with its port, what it could do, and how it is doing. sysfs
/// `/sys/bus/usb/devices/<bus>-<port>/` and its port.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UsbInfo {
    /// `4-2`: bus 4, port 2 (`4-1.3`: port 3 of the hub on port 1).
    pub port: String,
    /// Bus rate negotiated with the port: 1.5 → 1 (low speed), 12, 480,
    /// 5000, 10000, 20000.
    pub speed_mbps: Option<u32>,
    /// What the adapter can do: SuperSpeed(Plus) in its BOS descriptor,
    /// else its `bcdUSB` (a SuperSpeed device on a USB 2 port reports
    /// 2.10, so the version alone undersells it).
    pub adapter_max_mbps: Option<u32>,
    /// What the port it sits on can do (its hub's rate).
    pub port_max_mbps: Option<u32>,
    /// `bcdUSB`: `3.00`, `2.10`.
    pub version: Option<String>,
    pub vendor_id: Option<u16>,
    pub product_id: Option<u16>,
    /// Strings the device reports (`Realtek`, `USB 10/100/1000 LAN`).
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    /// `bcdDevice`: the chip's revision (`3100`).
    pub revision: Option<String>,
    /// Current the device asks of the port (`bMaxPower`).
    pub max_power_ma: Option<u32>,
    /// `power/control`: `on` = never autosuspended, `auto` = may sleep.
    pub autosuspend: Option<bool>,
    /// The port's `usb3_lpm_permit` (`u1_u2`, `u1`, `u2`, `0`), USB 3 only.
    pub lpm: Option<String>,
    /// Times the port saw too much current.
    pub over_current: Option<u32>,
    /// The kernel's `NETDEV WATCHDOG` count: transmit queues that stopped
    /// moving (summed over the queues).
    pub tx_timeouts: Option<u64>,
    /// The port can cut its power (`usbN-portM/disable` exists).
    pub port_power_switch: bool,
}

/// sysfs `speed` (`480`, `5000`, `1.5`) in Mbit/s; low speed (1.5) reads 1.
pub fn usb_speed_mbps(s: &str) -> Option<u32> {
    match s.trim() {
        "1.5" => Some(1),
        t => t.parse().ok().filter(|v| *v > 0 && *v <= 1_000_000),
    }
}

/// The fastest rate a BOS descriptor (USB 3.2 §9.6.2) claims:
/// SuperSpeedPlus (capability 0x0A) → 10000 times its lanes' best (here
/// 10000), SuperSpeed (0x03) → 5000; `None` when it claims neither.
/// Hostile bytes: every length is checked, a zero length stops the walk.
pub fn bos_max_mbps(bos: &[u8]) -> Option<u32> {
    // Header: bLength 5, bDescriptorType 0x0F, wTotalLength, bNumDeviceCaps.
    let (&hlen, &kind) = (bos.first()?, bos.get(1)?);
    if hlen < 5 || kind != 0x0F {
        return None;
    }
    let total = usize::from(u16::from_le_bytes([*bos.get(2)?, *bos.get(3)?]));
    let end = total.min(bos.len());
    let mut at = usize::from(hlen);
    let mut best = None;
    while at + 3 <= end {
        let len = usize::from(*bos.get(at)?);
        if len < 3 || at + len > end {
            break;
        }
        // bDescriptorType 0x10: a device capability; byte 2 is its kind.
        if bos.get(at + 1) == Some(&0x10) {
            let rate = match bos.get(at + 2) {
                Some(0x0A) => Some(10_000),
                Some(0x03) => Some(5_000),
                _ => None,
            };
            best = best.max(rate);
        }
        at += len;
    }
    best
}

/// `bcdUSB` → the rate that version tops out at.
pub fn usb_version_mbps(v: &str) -> Option<u32> {
    let major: u32 = v.trim().split('.').next()?.parse().ok()?;
    let minor: u32 = v
        .trim()
        .split('.')
        .nth(1)
        .and_then(|m| m.parse().ok())
        .unwrap_or(0);
    Some(match (major, minor) {
        (3, m) if m >= 20 => 20_000,
        (3, m) if m >= 10 => 10_000,
        (3.., _) => 5_000,
        (2, _) => 480,
        _ => 12,
    })
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

/// How deep a manual USB adapter recovery goes (G1.29c), lightest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UsbResetLevel {
    /// The interface down and up again (~1 s): the driver resets the chip.
    Link,
    /// The driver let go of the USB interface and probe it again
    /// (unbind/bind, ~2–3 s): a new network device, renamed back by PID 1.
    Driver,
    /// The whole USB device again: power off the port and on when its hub
    /// switches power per port, else de-authorize and re-authorize it (the
    /// USB core resets and enumerates it again, ~3–5 s).
    Port,
}

impl UsbResetLevel {
    pub const ALL: [Self; 3] = [Self::Link, Self::Driver, Self::Port];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Driver => "driver",
            Self::Port => "port",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.as_str() == s)
    }
}

/// What a recovery did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UsbResetReport {
    /// Steps in order, one line each ("unbind 2-1:1.0 from r8152").
    pub steps: Vec<String>,
    /// The port's power was cut (not only the device re-authorized).
    pub power_cycled: bool,
    /// The interface came back under its name before the time ran out.
    pub back: bool,
    /// Not back, but a link with the adapter's MAC is there under another
    /// name (`eth0`): PID 1 did not give it its name again (G1.29f).
    pub back_as: Option<String>,
}

/// A recovery under way, run on a task thread (the session is not held
/// while the adapter goes away and comes back).
pub trait UsbReset: Send {
    /// `wait(d)` sleeps up to `d`, `false` when the task was stopped.
    fn run(&mut self, wait: &dyn Fn(Duration) -> bool) -> Result<UsbResetReport, HalError>;
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
    use super::{bos_max_mbps, mode_speed, usb_speed_mbps, usb_version_mbps};

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

    /// The BOS descriptor of a real RTL8153B (0bda:8153, bcdDevice 3100),
    /// read from its sysfs `bos_descriptors`: USB 2.0 Extension, then
    /// SuperSpeed.
    const RTL8153B_BOS: [u8; 22] = [
        0x05, 0x0f, 0x16, 0x00, 0x02, 0x07, 0x10, 0x02, 0x02, 0x00, 0x00, 0x00, 0x0a, 0x10, 0x03,
        0x02, 0x0e, 0x00, 0x02, 0x0a, 0xff, 0x07,
    ];

    #[test]
    fn bos_superspeed() {
        assert_eq!(bos_max_mbps(&RTL8153B_BOS), Some(5000));
        // Only the USB 2.0 Extension: a USB 2 device.
        assert_eq!(bos_max_mbps(RTL8153B_BOS.get(..12).unwrap()), None);
        // SuperSpeedPlus too.
        let mut plus = RTL8153B_BOS.to_vec();
        plus.extend_from_slice(&[0x0c, 0x10, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        plus[2] = u8::try_from(plus.len()).unwrap();
        assert_eq!(bos_max_mbps(&plus), Some(10_000));
        // Broken lengths stop the walk.
        assert_eq!(
            bos_max_mbps(&[0x05, 0x0f, 0xff, 0x00, 0x01, 0x00, 0x10]),
            None
        );
        assert_eq!(bos_max_mbps(&[]), None);
    }

    #[test]
    fn usb_rates() {
        assert_eq!(usb_speed_mbps("5000\n"), Some(5000));
        assert_eq!(usb_speed_mbps("1.5"), Some(1));
        assert_eq!(usb_speed_mbps("unknown"), None);
        assert_eq!(usb_version_mbps(" 3.00"), Some(5000));
        assert_eq!(usb_version_mbps(" 3.10"), Some(10_000));
        assert_eq!(usb_version_mbps("2.10"), Some(480));
        assert_eq!(usb_version_mbps("1.10"), Some(12));
        assert_eq!(usb_version_mbps("x"), None);
    }

    proptest::proptest! {
        #[test]
        fn bos_never_panics(b in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..300)) {
            let _ = bos_max_mbps(&b);
        }
    }
}
