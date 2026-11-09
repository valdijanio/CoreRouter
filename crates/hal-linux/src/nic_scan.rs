//! The machine's network cards and what the kernel said about them (G1.6ja):
//! PCI and USB devices from sysfs, the PHYs of the `mdio_bus`, and `/dev/kmsg`
//! through the OS log's reader, with its own position. Run by the daemon's
//! `nic_problems` service on its own thread, never under the session lock.
//!
//! sysfs is hostile too: a USB device chooses its own strings. Every read is
//! bounded in bytes, every directory in entries, names go through `clean`.
//!
//! Cost (`slow_scan_cost` below prints it; the number is in the PR): one
//! `class` read per PCI device, a few attributes per USB interface, more only
//! for a network device.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use corerouter_hal::nic_problem::{
    Bus, KernelNotes, MAX_DEVICES, MAX_NAME, NicDevice, NicKind, NicReading, module_for,
    usb_is_ethernet,
};
use corerouter_hal::oslog::{OsSource, clean};

use crate::oslog::Kmsg;

/// Bytes of one sysfs attribute read (`modalias` is the longest we want).
const MAX_ATTR: u64 = 512;
/// Devices looked at per bus: a bound for a broken or hostile sysfs.
const MAX_SCANNED: usize = 4096;
/// `modules.alias` read at most (of every driver of the kernel, ~1 MiB).
const MAX_INDEX: u64 = 16 << 20;
/// Interfaces of one device listed.
const MAX_PORTS: usize = 64;
/// Records of the kernel's log read per scan (a storm waits for the next).
const MAX_LINES: usize = 5000;
/// Answers about modules kept (one per kind of card without a driver).
const MAX_MODULE_CACHE: usize = 64;

/// Where the machine's files are (a temporary tree in the tests).
#[derive(Debug, Clone)]
pub struct Paths {
    pub sys: PathBuf,
    pub cmdline: PathBuf,
    pub modules: PathBuf,
    pub kmsg: PathBuf,
}

impl Default for Paths {
    fn default() -> Self {
        Self {
            sys: PathBuf::from("/sys"),
            cmdline: PathBuf::from("/proc/cmdline"),
            modules: PathBuf::from("/lib/modules"),
            kmsg: PathBuf::from("/dev/kmsg"),
        }
    }
}

fn attr(path: &Path) -> Option<String> {
    let mut s = String::new();
    File::open(path)
        .ok()?
        .take(MAX_ATTR)
        .read_to_string(&mut s)
        .ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_owned())
}

/// A hex attribute, with or without `0x`.
fn hex(path: &Path) -> Option<u32> {
    u32::from_str_radix(attr(path)?.trim_start_matches("0x"), 16).ok()
}

fn four(id: Option<u32>) -> String {
    id.map(|i| format!("{i:04x}")).unwrap_or_default()
}

fn driver_of(dev: &Path) -> Option<String> {
    let link = fs::read_link(dev.join("driver")).ok()?;
    Some(clean(link.file_name()?.to_str()?, 64))
}

/// The interfaces under `dev` (`net/ether3`), and whether one is a radio.
fn ports_of(dev: &Path) -> (Vec<String>, bool) {
    let Ok(dir) = fs::read_dir(dev.join("net")) else {
        return (Vec::new(), false);
    };
    let mut wireless = false;
    let mut ports: Vec<String> = dir
        .flatten()
        .take(MAX_PORTS)
        .filter_map(|e| {
            wireless |= e.path().join("wireless").exists() || e.path().join("phy80211").exists();
            e.file_name().to_str().map(|n| clean(n, 32))
        })
        .collect();
    ports.sort();
    (ports, wireless)
}

/// The entries of a bus's device directory, sorted, bounded.
fn entries(root: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(root)
        .map(|d| {
            d.flatten()
                .take(MAX_SCANNED)
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// PCI network devices. Class `0x02xxxx` is "network controller", `0x0200`
/// Ethernet; anything else on it (`0x0280`: Wi-Fi) is listed, not judged.
fn pci(sys: &Path, out: &mut Vec<NicDevice>) {
    let root = sys.join("bus/pci/devices");
    for name in entries(&root) {
        let dev = root.join(&name);
        let Some(class) = hex(&dev.join("class")) else {
            continue;
        };
        if class >> 16 != 0x02 {
            continue;
        }
        let (ports, _) = ports_of(&dev);
        out.push(NicDevice {
            bus: Bus::Pci,
            address: clean(&name, 64),
            kind: if class >> 8 == 0x0200 {
                NicKind::Ethernet
            } else {
                NicKind::Other
            },
            vendor_id: four(hex(&dev.join("vendor"))),
            product_id: four(hex(&dev.join("device"))),
            vendor: None,
            product: None,
            driver: driver_of(&dev),
            ports,
            virtual_function: dev.join("physfn").exists(),
            module: None,
            safe_mode_queues: false,
        });
    }
}

/// USB interfaces (`4-2:1.0`) that are network cards: with a driver, the ones
/// with an interface under them; without one, by class or known ids. The data
/// interface of a CDC pair (class `0x0a`) never counts by itself.
fn usb(sys: &Path, out: &mut Vec<NicDevice>) {
    let root = sys.join("bus/usb/devices");
    for name in entries(&root) {
        // `usb1` and `4-2` are the devices; interfaces have the colon.
        let Some((parent, _)) = name.split_once(':') else {
            continue;
        };
        let dev = root.join(&name);
        let (ports, wireless) = ports_of(&dev);
        let driver = driver_of(&dev);
        let top = root.join(parent);
        let ids = (hex(&top.join("idVendor")), hex(&top.join("idProduct")));
        let code = |f: &str| hex(&dev.join(f)).and_then(|v| u8::try_from(v).ok());
        let claimed_network = !ports.is_empty();
        let unclaimed_network = driver.is_none()
            && match (
                code("bInterfaceClass"),
                code("bInterfaceSubClass"),
                code("bInterfaceProtocol"),
                ids,
            ) {
                (Some(c), Some(s), Some(p), (Some(v), Some(i))) => usb_is_ethernet(
                    c,
                    s,
                    p,
                    u16::try_from(v).unwrap_or(0),
                    u16::try_from(i).unwrap_or(0),
                ),
                _ => false,
            };
        if !claimed_network && !unclaimed_network {
            continue;
        }
        let text = |f: &str| attr(&top.join(f)).map(|s| clean(&s, MAX_NAME));
        out.push(NicDevice {
            bus: Bus::Usb,
            address: clean(&name, 64),
            kind: if wireless {
                NicKind::Other
            } else {
                NicKind::Ethernet
            },
            vendor_id: four(ids.0),
            product_id: four(ids.1),
            vendor: text("manufacturer"),
            product: text("product"),
            driver,
            ports,
            virtual_function: false,
            module: None,
            safe_mode_queues: false,
        });
    }
}

/// PHYs: never "no driver" (the kernel gives them the generic one), but one
/// can ask for firmware under its own name (`stmmac-0:01`).
fn mdio(sys: &Path, out: &mut Vec<NicDevice>) {
    let root = sys.join("bus/mdio_bus/devices");
    for name in entries(&root) {
        let dev = root.join(&name);
        let port = fs::read_link(dev.join("attached_dev"))
            .ok()
            .and_then(|l| l.file_name()?.to_str().map(|n| clean(n, 32)));
        out.push(NicDevice {
            bus: Bus::Mdio,
            address: clean(&name, 64),
            kind: NicKind::Ethernet,
            vendor_id: String::new(),
            product_id: String::new(),
            vendor: None,
            product: None,
            driver: driver_of(&dev),
            ports: port.into_iter().collect(),
            virtual_function: false,
            module: None,
            safe_mode_queues: false,
        });
    }
}

/// The network devices of the tree at `sys`.
pub fn devices(sys: &Path) -> Vec<NicDevice> {
    let mut out = Vec::new();
    pci(sys, &mut out);
    usb(sys, &mut out);
    mdio(sys, &mut out);
    out.truncate(MAX_DEVICES);
    out
}

/// The machine's `pci.ids`, only when a card needs naming.
fn pci_names(dev: &mut NicDevice) {
    let (Ok(vendor), Ok(device)) = (
        u16::from_str_radix(&dev.vendor_id, 16),
        u16::from_str_radix(&dev.product_id, 16),
    ) else {
        return;
    };
    if let Some(db) = crate::nic::pci_db() {
        let names = crate::pci_ids::lookup(
            &db,
            crate::pci_ids::PciIds {
                vendor,
                device,
                subsystem: None,
            },
        );
        dev.vendor = names.vendor;
        dev.product = names.device;
    }
}

/// `ice` can say one queue at most, on a machine with more than one CPU, only
/// in Safe Mode: the check that survives a log that wrapped or a daemon
/// restarted (`ice_common.c:3249`, `ice_ethtool.c:3803`).
fn ice_one_queue(port: &str) -> bool {
    let cpus = std::thread::available_parallelism().map_or(1, usize::from);
    if cpus < 2 {
        return false;
    }
    let Ok(mut e) = crate::ethtool::Ethtool::open(port) else {
        return false;
    };
    e.tuning()
        .1
        .get("combined_channels")
        .is_some_and(|m| *m == 1)
}

/// The scanner a service keeps: the log's position and what it said so far,
/// and the names and modules it already looked up.
pub struct NicScanner {
    paths: Paths,
    kmsg: Kmsg,
    notes: KernelNotes,
    /// `ids → (vendor, product)`: reading `pci.ids` is ~1 MB.
    names: HashMap<(String, String), (Option<String>, Option<String>)>,
    /// `modalias → module`.
    modules: HashMap<String, Option<String>>,
}

impl NicScanner {
    pub fn new(paths: Paths) -> Self {
        let kmsg = Kmsg::open(&paths.kmsg);
        Self {
            paths,
            kmsg,
            notes: KernelNotes::default(),
            names: HashMap::new(),
            modules: HashMap::new(),
        }
    }

    /// The module the kernel running now has for `modalias`.
    fn module_of(&mut self, modalias: &str) -> Option<String> {
        if let Some(m) = self.modules.get(modalias) {
            return m.clone();
        }
        let release = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
        let index = self
            .paths
            .modules
            .join(release.trim())
            .join("modules.alias");
        let found = bounded(&index).and_then(|t| module_for(&t, modalias));
        if self.modules.len() < MAX_MODULE_CACHE {
            self.modules.insert(modalias.to_owned(), found.clone());
        }
        found
    }

    /// One look at the machine.
    pub fn scan(&mut self) -> NicReading {
        for line in self.kmsg.read(MAX_LINES, "") {
            // A program can write to /dev/kmsg; only the kernel counts.
            if line.source == OsSource::Kernel {
                self.notes.line(&line.message);
            }
        }
        let mut devices = devices(&self.paths.sys);
        for d in &mut devices {
            if d.kind == NicKind::Ethernet && d.driver.as_deref() == Some("ice") {
                d.safe_mode_queues = d.ports.first().is_some_and(|p| ice_one_queue(p));
            }
            if d.bus != Bus::Pci || d.driver.is_some() {
                continue;
            }
            // A PCI name costs a read of the whole database: only for a card
            // with something to say, once.
            let key = (d.vendor_id.clone(), d.product_id.clone());
            if let Some((vendor, product)) = self.names.get(&key) {
                d.vendor.clone_from(vendor);
                d.product.clone_from(product);
            } else {
                pci_names(d);
                if self.names.len() < MAX_MODULE_CACHE {
                    self.names
                        .insert(key, (d.vendor.clone(), d.product.clone()));
                }
            }
        }
        let root = self.paths.sys.join("bus");
        for d in &mut devices {
            if d.driver.is_some() || d.bus == Bus::Mdio {
                continue;
            }
            let bus = if d.bus == Bus::Pci { "pci" } else { "usb" };
            let at = root
                .join(bus)
                .join("devices")
                .join(&d.address)
                .join("modalias");
            if let Some(alias) = attr(&at) {
                d.module = self.module_of(&alias);
            }
        }
        self.notes.keep_devices(&devices);
        let mut r = NicReading {
            notes: self
                .notes
                .iter()
                .map(|(k, v)| (k.to_owned(), v.clone()))
                .collect(),
            devices,
            kernel_log: self.kmsg.ok(),
            kernel_log_reason: self.kmsg.state().reason,
            ..NicReading::default()
        };
        if let Some(line) = attr_long(&self.paths.cmdline) {
            r.boot_options(&line);
        }
        r
    }
}

/// The kernel's command line: at most 4 KiB here (`COMMAND_LINE_SIZE` is 2 KiB
/// on x86).
fn attr_long(path: &Path) -> Option<String> {
    let mut s = String::new();
    File::open(path)
        .ok()?
        .take(4096)
        .read_to_string(&mut s)
        .ok()?;
    Some(s)
}

fn bounded(path: &Path) -> Option<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(MAX_INDEX)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    struct Tree(PathBuf);

    impl Tree {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!("cr-nicscan-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&d);
            fs::create_dir_all(d.join("sys/bus/pci/devices")).unwrap();
            fs::create_dir_all(d.join("sys/bus/usb/devices")).unwrap();
            Self(d)
        }

        fn sys(&self) -> PathBuf {
            self.0.join("sys")
        }

        fn write(&self, rel: &str, text: &str) {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, text).unwrap();
        }

        fn pci(
            &self,
            addr: &str,
            class: &str,
            vendor: &str,
            device: &str,
            driver: Option<&str>,
            port: Option<&str>,
        ) {
            let base = format!("sys/bus/pci/devices/{addr}");
            self.write(&format!("{base}/class"), class);
            self.write(&format!("{base}/vendor"), vendor);
            self.write(&format!("{base}/device"), device);
            self.write(
                &format!("{base}/modalias"),
                &format!(
                    "pci:v0000{}d0000{}sv0sd0bc02sc00i00\n",
                    &vendor[2..].to_uppercase(),
                    &device[2..].to_uppercase()
                ),
            );
            if let Some(d) = driver {
                fs::create_dir_all(self.0.join("drv").join(d)).unwrap();
                symlink(
                    self.0.join("drv").join(d),
                    self.0.join(&base).join("driver"),
                )
                .unwrap();
            }
            if let Some(p) = port {
                fs::create_dir_all(self.0.join(&base).join("net").join(p)).unwrap();
            }
        }

        fn usb_top(&self, dev: &str, vendor: &str, product: &str, name: &str) {
            let base = format!("sys/bus/usb/devices/{dev}");
            self.write(&format!("{base}/idVendor"), vendor);
            self.write(&format!("{base}/idProduct"), product);
            self.write(&format!("{base}/product"), name);
        }

        fn usb_if(
            &self,
            intf: &str,
            codes: (&str, &str, &str),
            driver: Option<&str>,
            port: Option<&str>,
        ) {
            let base = format!("sys/bus/usb/devices/{intf}");
            self.write(&format!("{base}/bInterfaceClass"), codes.0);
            self.write(&format!("{base}/bInterfaceSubClass"), codes.1);
            self.write(&format!("{base}/bInterfaceProtocol"), codes.2);
            if let Some(d) = driver {
                fs::create_dir_all(self.0.join("drv").join(d)).unwrap();
                symlink(
                    self.0.join("drv").join(d),
                    self.0.join(&base).join("driver"),
                )
                .unwrap();
            }
            if let Some(p) = port {
                fs::create_dir_all(self.0.join(&base).join("net").join(p)).unwrap();
            }
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn pci_cards_by_class() {
        let t = Tree::new("pci");
        t.pci(
            "0000:00:02.0",
            "0x030000",
            "0x8086",
            "0x1234",
            Some("i915"),
            None,
        ); // GPU
        t.pci(
            "0000:01:00.0",
            "0x020000",
            "0x8086",
            "0x1592",
            Some("ice"),
            Some("ether1"),
        );
        t.pci("0000:02:00.0", "0x020000", "0x19ee", "0x4000", None, None);
        t.pci("0000:03:00.0", "0x028000", "0x8086", "0x2725", None, None); // Wi-Fi
        t.pci("0000:04:00.0", "0x020000", "0x8086", "0x1889", None, None);
        fs::create_dir_all(t.sys().join("bus/pci/devices/0000:04:00.0/physfn")).unwrap();
        let v = devices(&t.sys());
        assert_eq!(v.len(), 4, "not the GPU");
        let by = |a: &str| v.iter().find(|d| d.address == a).unwrap();
        let ice = by("0000:01:00.0");
        assert_eq!(
            (ice.vendor_id.as_str(), ice.product_id.as_str()),
            ("8086", "1592")
        );
        assert_eq!(ice.driver.as_deref(), Some("ice"));
        assert_eq!(ice.ports, ["ether1"]);
        assert_eq!(by("0000:02:00.0").driver, None);
        assert_eq!(by("0000:02:00.0").kind, NicKind::Ethernet);
        assert_eq!(by("0000:03:00.0").kind, NicKind::Other);
        assert!(by("0000:04:00.0").virtual_function);
    }

    #[test]
    fn usb_cards_by_class_ids_and_port() {
        let t = Tree::new("usb");
        // RTL8153 with its driver, one without any, a CDC-NCM stick with its
        // data interface, a Wi-Fi stick with its driver, a serial dongle, and
        // a hub (no colon, no interface read).
        t.usb_top("4-2", "0bda", "8153", "USB 10/100/1000 LAN");
        t.usb_if("4-2:1.0", ("ff", "ff", "00"), Some("r8152"), Some("ether2"));
        t.usb_top("4-3", "0bda", "8156", "USB 2.5G");
        t.usb_if("4-3:1.0", ("ff", "ff", "00"), None, None);
        t.usb_top("4-4", "1234", "5678", "NCM\u{202e}stick");
        t.usb_if("4-4:1.0", ("02", "0d", "00"), None, None);
        t.usb_if("4-4:1.1", ("0a", "00", "01"), None, None);
        t.usb_top("4-5", "0bda", "b812", "Radio");
        t.usb_if("4-5:1.0", ("ff", "ff", "ff"), Some("rtw88"), Some("wlan0"));
        fs::create_dir_all(t.sys().join("bus/usb/devices/4-5:1.0/net/wlan0/wireless")).unwrap();
        t.usb_top("4-6", "1a86", "7523", "Serial");
        t.usb_if("4-6:1.0", ("ff", "01", "02"), None, None);
        t.usb_top("usb1", "1d6b", "0002", "Hub");
        let v = devices(&t.sys());
        let names: Vec<&str> = v.iter().map(|d| d.address.as_str()).collect();
        assert_eq!(
            names,
            ["4-2:1.0", "4-3:1.0", "4-4:1.0", "4-5:1.0"],
            "{v:#?}"
        );
        let by = |a: &str| v.iter().find(|d| d.address == a).unwrap();
        assert_eq!(by("4-2:1.0").ports, ["ether2"]);
        assert_eq!(by("4-3:1.0").driver, None);
        assert_eq!(by("4-3:1.0").product_id, "8156");
        assert_eq!(by("4-5:1.0").kind, NicKind::Other);
        assert_eq!(
            by("4-4:1.0").product.as_deref(),
            Some("NCMstick"),
            "no bidi control"
        );
    }

    #[test]
    fn a_huge_attribute_is_cut_and_a_broken_tree_is_empty() {
        let t = Tree::new("huge");
        t.usb_top("1-1", "0bda", "8153", &"x".repeat(200_000));
        t.usb_if("1-1:1.0", ("ff", "ff", "00"), None, None);
        t.pci("0000:01:00.0", "not hex", "0x8086", "0x1592", None, None);
        let v = devices(&t.sys());
        assert_eq!(v.len(), 1);
        assert!(v[0].product.as_ref().unwrap().chars().count() <= MAX_NAME + 1);
        assert!(devices(Path::new("/nonexistent/sys")).is_empty());
    }

    #[test]
    fn the_scan_joins_log_module_and_boot() {
        let t = Tree::new("scan");
        t.pci(
            "0000:01:00.0",
            "0x020000",
            "0x8086",
            "0x1592",
            Some("r8169"),
            Some("ether1"),
        );
        t.pci("0000:02:00.0", "0x020000", "0x19ee", "0x4000", None, None);
        t.write("cmdline", "console=ttyS0 corerouter.mode=live\n");
        t.write("kmsg", "");
        let release = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
        t.write(
            &format!("modules/{}/modules.alias", release.trim()),
            "alias pci:v000019EEd00004000sv*sd*bc*sc*i* nfp\n",
        );
        // A regular file reads to the end like the ring's backlog does, one
        // record per read only in the real device: one record here.
        t.write(
            "kmsg",
            "4,1,100,-;r8169 0000:01:00.0: Unable to load firmware rtl_nic/rtl8168h-2.fw (-2)\n SUBSYSTEM=pci\n DEVICE=+pci:0000:01:00.0\n",
        );
        let mut s = NicScanner::new(Paths {
            sys: t.sys(),
            cmdline: t.0.join("cmdline"),
            modules: t.0.join("modules"),
            kmsg: t.0.join("kmsg"),
        });
        let r = s.scan();
        assert!(r.live && !r.modules_off);
        assert!(r.kernel_log);
        assert_eq!(r.devices.len(), 2);
        let none = r.devices.iter().find(|d| d.driver.is_none()).unwrap();
        assert_eq!(none.module.as_deref(), Some("nfp"));
        assert_eq!(r.notes.len(), 1);
        assert_eq!(r.notes[0].1.files[0].0, "rtl_nic/rtl8168h-2.fw");
        // The second look keeps what the log said, and adds nothing to it.
        let again = s.scan();
        assert_eq!(again.notes, r.notes);
    }

    #[test]
    fn no_log_is_said() {
        let t = Tree::new("nolog");
        let mut s = NicScanner::new(Paths {
            sys: t.sys(),
            cmdline: t.0.join("cmdline"),
            modules: t.0.join("modules"),
            kmsg: t.0.join("kmsg-missing"),
        });
        let r = s.scan();
        assert!(!r.kernel_log);
        assert!(r.kernel_log_reason.unwrap().contains("does not exist"));
    }

    /// Slow layer (G1.6ja): the number for the PR, the cost of one scan per
    /// device on a tree in tmpfs/disk; ~0.3 s in a dev build.
    #[test]
    fn slow_scan_cost() {
        let t = Tree::new("cost");
        for i in 0..100 {
            t.pci(
                &format!("0000:{i:02x}:00.0"),
                "0x060400",
                "0x8086",
                "0x1234",
                Some("pcieport"),
                None,
            );
        }
        for i in 0..8 {
            t.pci(
                &format!("0000:a{i}:00.0"),
                "0x020000",
                "0x8086",
                "0x1592",
                Some("igb"),
                Some(&format!("ether{i}")),
            );
        }
        let at = std::time::Instant::now();
        let rounds = 20u32;
        for _ in 0..rounds {
            assert_eq!(devices(&t.sys()).len(), 8);
        }
        let took = at.elapsed() / rounds;
        println!(
            "scan of 108 PCI devices: {took:?} ({:?} per device)",
            took / 108
        );
        // This machine, if it has a sysfs: the real number.
        let at = std::time::Instant::now();
        let found = devices(Path::new("/sys"));
        let pci = entries(Path::new("/sys/bus/pci/devices")).len();
        let usb = entries(Path::new("/sys/bus/usb/devices")).len();
        println!(
            "real /sys: {:?}, {pci} PCI + {usb} USB entries, {} network devices",
            at.elapsed(),
            found.len()
        );
        // And the whole look, with the machine's own log (read only).
        let at = std::time::Instant::now();
        let r = NicScanner::new(Paths::default()).scan();
        println!(
            "real scan: {:?}, kernel_log {}, notes {:?}",
            at.elapsed(),
            r.kernel_log,
            r.notes
        );
    }
}
