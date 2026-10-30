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
use corerouter_hal::nic::{self as hnic, UsbInfo};
use corerouter_hal::sff::{self, DiagPage, HALF_PAGE, SfpModule};
use corerouter_hal::{CounterGroup, EthernetMonitor, HalError, LinkCounters, NicHardware};

use crate::ethtool::{Ethtool, devlink_info};
use crate::genl::GenlError;
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
            if bus == "usb" {
                hw.usb = usb_info(Path::new(USB_DEVICES), dev, name);
                usb_names(&mut hw);
            }
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

/// The module in `name`'s cage (G1.20): page 0 of address 0x50, then the
/// diagnostics page the identifier calls for.
pub(crate) fn sfp_module(name: &str) -> Result<SfpModule, HalError> {
    detail(name)?;
    let mut e = Ethtool::open(name)
        .map_err(|e| HalError::Unsupported(format!("ethtool netlink unavailable: {e}")))?;
    let half = u32::try_from(HALF_PAGE).unwrap_or(128);
    let lower = match e.module_eeprom(0x50, 0, 0, half) {
        Ok(b) => b,
        Err(err) if err.unsupported() => {
            return Err(HalError::Unsupported(format!(
                "'{name}' has no module EEPROM ({err})"
            )));
        }
        // ENODEV, ENXIO, EIO, EREMOTEIO: an empty cage or a dead module.
        Err(err @ GenlError::Errno(19 | 6 | 5 | 121)) => {
            return Ok(SfpModule::empty(format!(
                "no module in the cage, or it does not answer ({err})"
            )));
        }
        Err(err) => return Err(HalError::Io(format!("module EEPROM: {err}"))),
    };
    let mut page0 = lower;
    let mut notes = Vec::new();
    match e.module_eeprom(0x50, 0, half, half) {
        Ok(upper) => page0.extend(upper),
        Err(err) => notes.push(format!("upper page 00h: {err}")),
    }
    let diag = match sff::diag_page(&page0) {
        DiagPage::A2 => e.module_eeprom(0x51, 0, 0, half),
        DiagPage::Page3 => e.module_eeprom(0x50, 3, half, half),
        DiagPage::None => Ok(Vec::new()),
    };
    let diag = match diag {
        Ok(d) if !d.is_empty() => Some(d),
        Ok(_) => None,
        Err(err) => {
            notes.push(format!("diagnostics page: {err}"));
            None
        }
    };
    let mut m = sff::decode(&page0, diag.as_deref());
    m.notes.extend(notes);
    Ok(m)
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

const USB_DEVICES: &str = "/sys/bus/usb/devices";

/// A USB adapter's ids and strings fill the PCI-shaped rows (Vendor,
/// Model) the Hardware tab already has.
fn usb_names(hw: &mut NicHardware) {
    let Some(u) = &hw.usb else { return };
    hw.vendor_id = hw.vendor_id.or(u.vendor_id);
    hw.device_id = hw.device_id.or(u.product_id);
    hw.vendor = hw.vendor.clone().or_else(|| u.manufacturer.clone());
    hw.model = hw.model.clone().or_else(|| u.product.clone());
    hw.serial = hw.serial.clone().or_else(|| u.serial.clone());
}

/// The USB device behind interface `intf` (`4-2:1.0`) under `root`
/// (`/sys/bus/usb/devices`; a fake tree in tests), and the link `ifname`
/// on it. G1.29b.
fn usb_info(root: &Path, intf: &str, ifname: &str) -> Option<UsbInfo> {
    let port = intf
        .split(':')
        .next()
        .filter(|p| safe(p) && !p.is_empty())?;
    let dev = root.join(port);
    if !dev.is_dir() {
        return None;
    }
    let speed_mbps = read_trim(&dev.join("speed")).and_then(|s| hnic::usb_speed_mbps(&s));
    let version = read_trim(&dev.join("version"));
    let bos = fs::File::open(dev.join("bos_descriptors"))
        .ok()
        .and_then(|f| {
            use std::io::Read;
            let mut b = Vec::new();
            f.take(4096).read_to_end(&mut b).ok()?;
            Some(b)
        });
    let adapter_max_mbps = bos
        .as_deref()
        .and_then(hnic::bos_max_mbps)
        .max(version.as_deref().and_then(hnic::usb_version_mbps))
        .max(speed_mbps);
    // The port: `port` → `../4-0:1.0/usb4-port2`; its hub is two levels up.
    let port_dir = fs::canonicalize(dev.join("port")).ok();
    let port_max_mbps = port_dir
        .as_deref()
        .and_then(|p| p.parent()?.parent())
        .and_then(|hub| read_trim(&hub.join("speed")))
        .and_then(|s| hnic::usb_speed_mbps(&s));
    let lpm = port_dir
        .as_deref()
        .and_then(|p| read_trim(&p.join("usb3_lpm_permit")));
    let over_current = port_dir
        .as_deref()
        .and_then(|p| read_trim(&p.join("over_current_count")))
        .and_then(|s| s.parse().ok());
    let port_power_switch = port_dir
        .as_deref()
        .is_some_and(|p| p.join("disable").exists());
    Some(UsbInfo {
        port: port.to_owned(),
        speed_mbps,
        adapter_max_mbps,
        port_max_mbps,
        version,
        vendor_id: hex_id(&dev.join("idVendor")),
        product_id: hex_id(&dev.join("idProduct")),
        manufacturer: read_trim(&dev.join("manufacturer")),
        product: read_trim(&dev.join("product")),
        serial: read_trim(&dev.join("serial")),
        revision: read_trim(&dev.join("bcdDevice")),
        max_power_ma: read_trim(&dev.join("bMaxPower"))
            .and_then(|s| s.trim_end_matches("mA").trim().parse().ok()),
        autosuspend: read_trim(&dev.join("power/control")).map(|c| c == "auto"),
        lpm,
        over_current,
        tx_timeouts: safe(ifname)
            .then(|| tx_timeouts(&root.join(intf).join("net").join(ifname)))
            .flatten(),
        port_power_switch,
    })
}

/// `NETDEV WATCHDOG` hits, summed over the link's transmit queues
/// (`queues/tx-N/tx_timeout`, kernel 3.3+).
pub(crate) fn tx_timeouts(link: &Path) -> Option<u64> {
    let rd = fs::read_dir(link.join("queues")).ok()?;
    let mut sum = None;
    for e in rd.filter_map(Result::ok).take(MAX_ITEMS) {
        if !e.file_name().to_string_lossy().starts_with("tx-") {
            continue;
        }
        if let Some(n) = read_trim(&e.path().join("tx_timeout")).and_then(|s| s.parse::<u64>().ok())
        {
            sum = Some(sum.unwrap_or(0u64).saturating_add(n));
        }
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RTL8153B of the development machine (0bda:8153 on bus 4,
    /// port 2), as sysfs had it, in a fake tree.
    #[test]
    fn usb_adapter_from_sysfs() {
        let root = std::env::temp_dir().join(format!("cr-usb-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let hub = root.join("usb4");
        let port = hub.join("4-0:1.0/usb4-port2");
        let dev = root.join("4-2");
        let link = root.join("4-2:1.0/net/ether4");
        for d in [
            &port,
            &dev.join("power"),
            &link.join("queues/tx-0"),
            &link.join("queues/rx-0"),
        ] {
            fs::create_dir_all(d).unwrap();
        }
        let w = |p: PathBuf, s: &[u8]| fs::write(p, s).unwrap();
        w(hub.join("speed"), b"10000\n");
        w(port.join("usb3_lpm_permit"), b"u1_u2\n");
        w(port.join("over_current_count"), b"0\n");
        w(port.join("disable"), b"0\n");
        std::os::unix::fs::symlink("../usb4/4-0:1.0/usb4-port2", dev.join("port")).unwrap();
        for (f, v) in [
            ("speed", "5000"),
            ("version", " 3.00"),
            ("idVendor", "0bda"),
            ("idProduct", "8153"),
            ("manufacturer", "Realtek"),
            ("product", "USB 10/100/1000 LAN"),
            ("serial", "001000001"),
            ("bcdDevice", "3100"),
            ("bMaxPower", "288mA"),
            ("power/control", "on"),
        ] {
            w(dev.join(f), format!("{v}\n").as_bytes());
        }
        w(link.join("queues/tx-0/tx_timeout"), b"3\n");
        let u = usb_info(&root, "4-2:1.0", "ether4").unwrap();
        assert_eq!(u.port, "4-2");
        assert_eq!(
            (u.speed_mbps, u.adapter_max_mbps, u.port_max_mbps),
            (Some(5000), Some(5000), Some(10_000))
        );
        assert_eq!((u.vendor_id, u.product_id), (Some(0x0bda), Some(0x8153)));
        assert_eq!(u.max_power_ma, Some(288));
        assert_eq!(u.autosuspend, Some(false));
        assert_eq!(u.lpm.as_deref(), Some("u1_u2"));
        assert_eq!(u.tx_timeouts, Some(3));
        assert!(u.port_power_switch);
        // Same adapter on a USB 2 port: it negotiates 480 and reports 2.10;
        // the BOS descriptor still says SuperSpeed.
        w(dev.join("speed"), b"480\n");
        w(dev.join("version"), b" 2.10\n");
        w(
            dev.join("bos_descriptors"),
            &[
                0x05, 0x0f, 0x0f, 0x00, 0x01, 0x0a, 0x10, 0x03, 0x02, 0x0e, 0x00, 0x02, 0x0a, 0xff,
                0x07,
            ],
        );
        let u = usb_info(&root, "4-2:1.0", "ether4").unwrap();
        assert_eq!((u.speed_mbps, u.adapter_max_mbps), (Some(480), Some(5000)));
        assert!(usb_info(&root, "../x:1.0", "ether4").is_none());
        assert!(usb_info(&root, "9-9:1.0", "ether4").is_none());
        let _ = fs::remove_dir_all(&root);
    }

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
