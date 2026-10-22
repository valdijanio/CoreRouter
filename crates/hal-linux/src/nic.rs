//! The interface dialog's Status, Hardware and Statistics data (G1.19):
//! rtnetlink for what the link is, `ethtool` netlink for the PHY and
//! driver setup, and sysfs for the device behind it.
//!
//! sysfs is only read under `/sys/bus/<bus>/devices/<dev>`, with the bus
//! and device the link's own `RTM_NEWLINK` names: devices are not
//! per-namespace, so this is right in a network namespace too (where
//! `/sys/class/net` would show the host's links).

use std::fs;
use std::path::{Path, PathBuf};

use corerouter_hal::nic::MAX_ITEMS;
use corerouter_hal::{CounterGroup, EthernetMonitor, HalError, LinkCounters, NicHardware};

use crate::ethtool::{Ethtool, devlink_info};
use crate::netlink::{LinkDetail, link_detail};
use crate::pci_ids::{self, PciIds};

fn detail(name: &str) -> Result<LinkDetail, HalError> {
    link_detail(name)?.ok_or_else(|| HalError::Rejected(format!("no link '{name}' in the kernel")))
}

/// Run `f` on an `ethtool` connection, or note why there is none.
fn with_ethtool<T>(
    name: &str,
    notes: &mut Vec<String>,
    f: impl FnOnce(&mut Ethtool) -> T,
) -> Option<T> {
    match Ethtool::open(name) {
        Ok(mut e) => {
            let out = f(&mut e);
            notes.append(&mut e.notes);
            Some(out)
        }
        Err(e) => {
            notes.push(format!("ethtool netlink unavailable: {e}"));
            None
        }
    }
}

pub(crate) fn monitor(name: &str) -> Result<EthernetMonitor, HalError> {
    let d = detail(name)?;
    let mut m = EthernetMonitor {
        link_ok: d.link.running,
        carrier_changes: d.carrier_changes,
        link_downs: d.carrier_down_count,
        ..EthernetMonitor::default()
    };
    let mut notes = Vec::new();
    with_ethtool(name, &mut notes, |e| e.monitor(&mut m));
    if !m.link_ok {
        // A stale rate from before the link went down means nothing.
        m.speed_mbps = None;
        m.full_duplex = None;
    }
    m.notes = notes;
    Ok(m)
}

pub(crate) fn hardware(name: &str) -> Result<NicHardware, HalError> {
    let d = detail(name)?;
    let mut hw = NicHardware {
        mac: d.link.mac.clone(),
        perm_mac: d.perm_mac.clone(),
        min_mtu: d.min_mtu,
        max_mtu: d.max_mtu.filter(|m| *m != 0),
        rx_queues: d.rx_queues,
        tx_queues: d.tx_queues,
        ..NicHardware::default()
    };
    let mut notes = Vec::new();
    match (d.parent_bus.as_deref(), d.parent_dev.as_deref()) {
        (Some(bus), Some(dev)) if safe(bus) && safe(dev) => {
            hw.bus = Some(bus.to_owned());
            hw.bus_address = Some(dev.to_owned());
            device(
                Path::new("/sys/bus").join(bus).join("devices").join(dev),
                &mut hw,
            );
            if let Err(e) = devlink_info(bus, dev, &mut hw) {
                notes.push(format!("firmware: {e}"));
            }
        }
        _ => {
            // veth, bridge, dummy…: the kind is the driver, like `ethtool -i`.
            hw.bus = Some("virtual".into());
            hw.driver = d.link.kind.clone();
            notes.push("no device behind this link (a software interface)".into());
        }
    }
    if let Some(drv) = hw.driver.as_deref().filter(|d| safe(d)) {
        hw.driver_version = read_trim(&Path::new("/sys/module").join(drv).join("version"));
    }
    with_ethtool(name, &mut notes, |e| e.hardware(&mut hw));
    hw.notes = notes;
    Ok(hw)
}

pub(crate) fn counters(name: &str) -> Result<LinkCounters, HalError> {
    let d = detail(name)?;
    let mut out = LinkCounters {
        groups: vec![CounterGroup::new("interface", d.stats.clone())],
        notes: Vec::new(),
    };
    let mut notes = Vec::new();
    with_ethtool(name, &mut notes, |e| {
        for (group, counters) in e.std_stats() {
            out.groups.push(CounterGroup::new(group, counters));
        }
        if let Some(pause) = e.pause_stats() {
            out.groups.push(CounterGroup::new("pause", pause));
        }
    });
    out.notes = notes;
    Ok(out)
}

/// A bus/device/driver name usable as one path component.
fn safe(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'.' | b'_' | b'-'))
}

fn read_trim(p: &Path) -> Option<String> {
    let s = fs::read_to_string(p).ok()?;
    let s = s.trim();
    (!s.is_empty() && s.len() <= 256).then(|| s.to_owned())
}

/// `0x8086` → 0x8086.
fn hex_id(p: &Path) -> Option<u16> {
    let s = read_trim(p)?;
    u16::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

/// What sysfs says about the device at `dir`.
fn device(dir: PathBuf, hw: &mut NicHardware) {
    hw.vendor_id = hex_id(&dir.join("vendor"));
    hw.device_id = hex_id(&dir.join("device"));
    hw.subsystem_vendor_id = hex_id(&dir.join("subsystem_vendor"));
    hw.subsystem_device_id = hex_id(&dir.join("subsystem_device"));
    // -1: no NUMA affinity (a single-node machine).
    hw.numa_node = read_trim(&dir.join("numa_node")).and_then(|s| s.parse().ok());
    hw.driver = fs::read_link(dir.join("driver"))
        .ok()
        .and_then(|l| l.file_name().map(|n| n.to_string_lossy().into_owned()));
    hw.irqs = irqs(&dir);
    if hw.bus.as_deref() == Some("pci")
        && let (Some(vendor), Some(device)) = (hw.vendor_id, hw.device_id)
    {
        let ids = PciIds {
            vendor,
            device,
            subsystem: hw.subsystem_vendor_id.zip(hw.subsystem_device_id),
        };
        if let Some(db) = pci_db() {
            let names = pci_ids::lookup(&db, ids);
            hw.vendor = names.vendor;
            hw.model = names.device;
            hw.subsystem = names.subsystem;
        }
    }
}

/// MSI/MSI-X vectors, else the legacy line.
fn irqs(dir: &Path) -> Vec<u32> {
    let mut v: Vec<u32> = fs::read_dir(dir.join("msi_irqs"))
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter_map(|e| e.file_name().to_str()?.parse().ok())
                .take(MAX_ITEMS)
                .collect()
        })
        .unwrap_or_default();
    if v.is_empty() {
        v.extend(
            read_trim(&dir.join("irq"))
                .and_then(|s| s.parse::<u32>().ok())
                .filter(|n| *n != 0),
        );
    }
    v.sort_unstable();
    v
}

/// The system's `pci.ids`, if any (bounded read).
fn pci_db() -> Option<String> {
    pci_ids::PATHS.iter().find_map(|p| {
        let meta = fs::metadata(p).ok()?;
        if meta.len() > pci_ids::MAX_BYTES {
            return None;
        }
        let bytes = fs::read(p).ok()?;
        Some(String::from_utf8_lossy(&bytes).into_owned())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_names_become_paths() {
        assert!(safe("0000:03:00.0"));
        assert!(safe("virtio0"));
        assert!(safe("igb"));
        for bad in ["", ".", "..", "a/b", "../../etc", "x y", &"a".repeat(65)] {
            assert!(!safe(bad), "{bad:?}");
        }
    }
}
