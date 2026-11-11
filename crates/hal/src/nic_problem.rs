//! Network cards the kernel could not bring up in full (G1.6ja): what a
//! reading of the machine says (the devices on the buses and what the
//! kernel's log said about their firmware), as plain data, and the parser of
//! those log lines. Reading the real sysfs and `/dev/kmsg` is `hal-linux`'s
//! (`nic_scan`); judging and wording is the engine's (`nic_problems`).
//!
//! The parser takes hostile input: a kernel line can carry a string a USB
//! device chose. Each pattern is anchored right after the line's own
//! `driver device:` head, a file name must look like one, and every field and
//! list has a limit. Never panics (proptest below).
//!
//! The lines were read in the kernel's source, 6.18.59, the image's: the
//! file and line of each are in the table test. Most drivers need no text of
//! their own: `request_firmware` warns by itself
//! (`drivers/base/firmware_loader/main.c:903`); the ones here use the
//! `nowarn`/`direct` variants or say more than it does.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::oslog::clean;

/// Network devices listed at most: more than any machine has.
pub const MAX_DEVICES: usize = 512;
/// Devices the kernel's log may name, and files per device, at most.
pub const MAX_NOTED: usize = 256;
pub const MAX_FILES: usize = 16;
/// Characters of a firmware file's name.
pub const MAX_FILE: usize = 128;
/// Characters of a vendor or product name.
pub const MAX_NAME: usize = 96;
/// A kernel line's `driver device iface:` head.
const MAX_HEAD: usize = 96;

/// The bus a device is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Bus {
    Pci,
    Usb,
    /// A PHY: `drivers/net/phy` asks for firmware under its own name.
    Mdio,
}

/// What kind of network device it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum NicKind {
    /// What the router routes with: judged.
    Ethernet,
    /// PCI class "network, other" and the like (Wi-Fi cards live here), and a
    /// wireless USB adapter: listed and never a warning. A Wi-Fi card with
    /// its driver is an interface of type `wifi` (G1.30, `docs/wifi.md`);
    /// one without is not something every router wants to hear about.
    Other,
}

/// One network device of the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NicDevice {
    pub bus: Bus,
    /// `0000:03:00.0`, `4-2:1.0`, `stmmac-0:01`.
    pub address: String,
    pub kind: NicKind,
    /// `8086`, as four hex digits; "" when the bus has none.
    pub vendor_id: String,
    pub product_id: String,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub driver: Option<String>,
    /// Its network interfaces (`ether3`).
    pub ports: Vec<String>,
    /// An SR-IOV virtual function: no driver is what its owner may want
    /// (handed to a VM, autoprobe off).
    pub virtual_function: bool,
    /// The module of the image's index that claims it, while it has no
    /// driver.
    pub module: Option<String>,
    /// `ice` says only one queue is possible with more than one CPU: Safe
    /// Mode, whatever the log still has (`ice_common.c:3249`,
    /// `ice_ethtool.c:3803`).
    pub safe_mode_queues: bool,
}

/// Why `ice` entered Safe Mode (`ice_log_pkg_init`, `ice_main.c:4254`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SafeModeCause {
    /// No DDP file to read (`ice_main.c:4523`).
    FileMissing,
    /// The file is corrupt or fails its signature.
    FileInvalid,
    /// File, driver and NVM do not fit each other: update one of them.
    Version,
    /// The log said Safe Mode with no reason we know, or it wrapped.
    Unknown,
}

/// What one kernel line says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelNote {
    /// `0000:03:00.0`; `None`: the line names no device.
    pub device: Option<String>,
    /// `None`: a line that names no driver before the device.
    pub driver: Option<String>,
    pub what: NoteKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoteKind {
    /// This file could not be loaded, and the error (`-2`) when it says.
    Firmware {
        file: String,
        error: Option<i32>,
    },
    SafeMode(SafeModeCause),
    /// The package loaded: this device is out of Safe Mode.
    SafeModeOff,
}

/// Firmware a driver looks for and does well without: never a problem.
/// `regulatory.db` is `cfg80211`'s and asked for on any kernel with Wi-Fi
/// support, on a platform device; `cxgb4` falls back to the config in its
/// flash (`cxgb4_main.c:4497`, "On FLASH"); `ice-<serial>.pkg` is the optional
/// per-device override (`ice_main.c:4516`).
pub fn firmware_is_optional(file: &str) -> bool {
    let name = file.rsplit('/').next().unwrap_or(file);
    file.starts_with("regulatory.db")
        || (file.starts_with("cxgb4/") && name.ends_with("-config.txt"))
        || name
            .strip_prefix("ice-")
            .and_then(|n| n.strip_suffix(".pkg"))
            .is_some_and(|n| n.len() == 16 && n.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A PCI address, `0000:03:00.0`.
fn pci_address(t: &str) -> bool {
    let b = t.as_bytes();
    b.len() >= 12
        && b.len() <= 16
        && t.rsplit_once('.').is_some_and(|(head, func)| {
            func.len() == 1
                && func.bytes().all(|c| c.is_ascii_digit())
                && head.split(':').count() == 3
                && head
                    .split(':')
                    .all(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_hexdigit()))
        })
}

/// A USB device or interface, `4-2`, `4-2.1:1.0`.
fn usb_address(t: &str) -> bool {
    let (dev, intf) = t.split_once(':').unwrap_or((t, "1.0"));
    let Some((bus, ports)) = dev.split_once('-') else {
        return false;
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    digits(bus) && ports.split('.').all(digits) && intf.split('.').all(digits)
}

/// A name a kernel line may give a firmware file.
fn file_name(f: &str) -> bool {
    !f.is_empty()
        && f.chars().count() <= MAX_FILE
        && !f.starts_with('/')
        && !f.split('/').any(|p| p.is_empty() || p == "." || p == "..")
        && f.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+' | b'/'))
}

/// The line's head and text: `r8169 0000:02:00.0 eth0: text`.
fn head_and_text(line: &str) -> Option<(&str, &str)> {
    let (head, text) = line.split_once(": ")?;
    (head.len() <= MAX_HEAD).then_some((head, text))
}

/// (driver, device) of a head: the bus address among its words (a netdev line
/// has the interface after it, `e100 0000:01:01.0 (unnamed net_device)`); else
/// the last word when it looks like a PHY (`Microsemi GE VSC8574
/// SyncE stmmac-0:01`). The driver is what comes before.
fn origin(head: &str) -> (Option<String>, Option<String>) {
    let words: Vec<&str> = head.split_whitespace().collect();
    let at = words
        .iter()
        .position(|w| pci_address(w) || (words.len() > 1 && usb_address(w)))
        .or_else(|| {
            words
                .len()
                .checked_sub(1)
                .filter(|i| *i > 0 && words.get(*i).is_some_and(|w| w.contains(':')))
        });
    let Some(at) = at else {
        return (None, None);
    };
    let driver = words
        .get(..at)
        .filter(|d| !d.is_empty())
        .map(|d| clean(&d.join(" "), 64));
    (driver, words.get(at).map(|w| clean(w, 64)))
}

/// The error in the tail of a line: `… failed with error -2`, `… (-2)`,
/// `…: -2`.
fn error_of(tail: &str) -> Option<i32> {
    tail.split_whitespace()
        .next_back()
        .map(|w| w.trim_matches(|c: char| matches!(c, '(' | ')' | ',' | '.')))
        .and_then(|w| w.parse::<i32>().ok())
        .filter(|n| *n < 0)
}

/// (what comes before the file, what ends it; `None`: the end of the line).
const FIRMWARE_TEXTS: [(&str, Option<&str>); 11] = [
    ("Direct firmware load for ", Some(" failed")),
    ("Unable to load firmware ", Some(" (")),
    ("unable to load firmware patch ", Some(" (")),
    ("CPUSaver disabled. Needs \"", Some("\"")),
    ("Failed to load firmware \"", Some("\"")),
    ("unable to load firmware image ", Some(",")),
    ("failed to load firmware: ", Some(",")),
    ("failed to load firmware ", Some(",")),
    ("failed to find FW file ", Some(" (")),
    ("could not upgrade firmware: unable to load ", None),
    ("could not load TP SRAM: unable to load ", None),
];

/// The file this kernel line says is missing and the device it names, any
/// file at all (the live image's network test shows `regulatory.db` to the
/// curious: [`parse_line`] leaves out what is optional).
pub fn missing_firmware(line: &str) -> Option<(Option<String>, String, Option<i32>)> {
    let (head, text) = head_and_text(line.lines().next()?)?;
    let (_, device) = origin(head);
    if text.starts_with("The DDP package file was not found") {
        return Some((device, "intel/ice/ddp/ice.pkg".to_owned(), None));
    }
    FIRMWARE_TEXTS.iter().find_map(|(before, end)| {
        let rest = text.strip_prefix(before)?;
        let (file, tail) = match end {
            Some(e) => rest.split_once(e)?,
            None => (rest, ""),
        };
        file_name(file).then(|| (device.clone(), file.to_owned(), error_of(tail)))
    })
}

fn safe_mode_cause(text: &str) -> Option<SafeModeCause> {
    let says = text.contains("Entering Safe Mode") || text.contains("Entering safe mode");
    if !says {
        return text
            .starts_with("Device is in Safe Mode")
            .then_some(SafeModeCause::Unknown);
    }
    Some(if text.contains("was not found") {
        SafeModeCause::FileMissing
    } else if text.contains("is invalid")
        || text.contains("signature")
        || text.contains("failed to load")
    {
        SafeModeCause::FileInvalid
    } else if text.contains("unknown error") {
        SafeModeCause::Unknown
    } else {
        SafeModeCause::Version
    })
}

/// What a kernel line says about a network card's firmware; one line can say
/// two things (`ice`: the file is missing, and so Safe Mode).
pub fn parse_line(line: &str) -> Vec<KernelNote> {
    let mut out = Vec::new();
    let Some((head, text)) = line.lines().next().and_then(head_and_text) else {
        return out;
    };
    let (driver, device) = origin(head);
    if let Some((_, file, error)) = missing_firmware(line)
        && !firmware_is_optional(&file)
    {
        out.push(KernelNote {
            device: device.clone(),
            driver: driver.clone(),
            what: NoteKind::Firmware { file, error },
        });
    }
    if driver.as_deref() == Some("ice") {
        let what = if text.starts_with("The DDP package was successfully loaded")
            || text.starts_with("DDP package already present")
            || text.contains("a compatible DDP package is already present")
        {
            Some(NoteKind::SafeModeOff)
        } else {
            safe_mode_cause(text).map(NoteKind::SafeMode)
        };
        if let Some(what) = what {
            out.push(KernelNote {
                device,
                driver,
                what,
            });
        }
    }
    out
}

/// What the kernel's log said about one device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DeviceNotes {
    pub driver: Option<String>,
    /// (file, error).
    pub files: Vec<(String, Option<i32>)>,
    pub safe_mode: Option<SafeModeCause>,
}

/// The kernel's log so far, by device: fed line by line, bounded, and an
/// unknown device never grows it past [`MAX_NOTED`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelNotes {
    by_device: BTreeMap<String, DeviceNotes>,
}

impl KernelNotes {
    pub fn line(&mut self, line: &str) {
        for note in parse_line(line) {
            let Some(device) = note.device else { continue };
            if !self.by_device.contains_key(&device) && self.by_device.len() >= MAX_NOTED {
                continue;
            }
            let d = self.by_device.entry(device).or_default();
            if d.driver.is_none() {
                d.driver = note.driver;
            }
            match note.what {
                NoteKind::Firmware { file, error } => {
                    if d.files.len() < MAX_FILES && !d.files.iter().any(|(f, _)| *f == file) {
                        d.files.push((file, error));
                    }
                }
                // "Device is in Safe Mode" comes after the line with the
                // reason: it does not take it away.
                NoteKind::SafeMode(SafeModeCause::Unknown) if d.safe_mode.is_some() => {}
                NoteKind::SafeMode(c) => d.safe_mode = Some(c),
                NoteKind::SafeModeOff => {
                    d.safe_mode = None;
                    d.files.retain(|(f, _)| !f.starts_with("intel/ice/ddp/"));
                }
            }
        }
    }

    /// Only what the kernel said about these devices, so a card unplugged and
    /// plugged again starts clean, and lines about anything else (a GPU, a
    /// Bluetooth chip) go. A USB line may name the device (`4-2`) and the
    /// list the interface (`4-2:1.0`).
    pub fn keep_devices(&mut self, devices: &[NicDevice]) {
        self.by_device
            .retain(|d, _| devices.iter().any(|n| names_device(d, &n.address)));
    }

    /// (device named by the log, what it said).
    pub fn iter(&self) -> impl Iterator<Item = (&str, &DeviceNotes)> {
        self.by_device.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn is_empty(&self) -> bool {
        self.by_device.is_empty()
    }
}

/// Whether a log's device name is this address (`4-2` names `4-2:1.0`).
pub fn names_device(logged: &str, address: &str) -> bool {
    address == logged
        || address
            .strip_prefix(logged)
            .is_some_and(|r| r.starts_with(':'))
}

/// One look at the machine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NicReading {
    pub devices: Vec<NicDevice>,
    /// (device the log names, what it said), only of [`Self::devices`].
    pub notes: Vec<(String, DeviceNotes)>,
    /// Booted from the ISO (`corerouter.mode=live`): its kernel has neither
    /// firmware files nor modules (G1.6j).
    pub live: bool,
    /// `corerouter.modules=off`: PID 1 was told not to load drivers.
    pub modules_off: bool,
    /// `/dev/kmsg` is readable. `false`: firmware problems cannot be seen.
    pub kernel_log: bool,
    /// Why the log cannot be read.
    pub kernel_log_reason: Option<String>,
}

impl NicReading {
    /// What `kernel_cmdline` says about the boot.
    pub fn boot_options(&mut self, kernel_cmdline: &str) {
        for w in kernel_cmdline.split_ascii_whitespace() {
            match w {
                "corerouter.mode=live" => self.live = true,
                "corerouter.modules=off" => self.modules_off = true,
                _ => {}
            }
        }
    }
}

/// `*`, `?` and `[a-z]`, what `modules.alias` uses (the single pass with a
/// restart at the last `*`; `O(pattern × text)` at worst, both bounded by the
/// caller). PID 1 has its own (`corerouter-init/src/modules.rs`): it does not
/// link this crate.
pub fn alias_matches(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while let Some(&c) = text.get(t) {
        let (hit, next) = match pattern.get(p) {
            Some(b'*') => {
                star = Some((p + 1, t));
                p += 1;
                continue;
            }
            Some(b'?') => (true, p + 1),
            Some(b'[') => match in_class(pattern.get(p + 1..).unwrap_or_default(), c) {
                Some((hit, len)) => (hit, p + 1 + len),
                None => (c == b'[', p + 1),
            },
            Some(&l) => (l == c, p + 1),
            None => (false, p),
        };
        if hit {
            p = next;
            t += 1;
        } else if let Some((sp, st)) = star {
            star = Some((sp, st + 1));
            p = sp;
            t = st + 1;
        } else {
            return false;
        }
    }
    pattern
        .get(p..)
        .unwrap_or_default()
        .iter()
        .all(|&c| c == b'*')
}

fn in_class(rest: &[u8], c: u8) -> Option<(bool, usize)> {
    let end = rest.iter().position(|&b| b == b']')?;
    let body = rest.get(..end)?;
    let mut hit = false;
    let mut i = 0;
    while let Some(&a) = body.get(i) {
        if let (Some(b'-'), Some(&b)) = (body.get(i + 1), body.get(i + 2)) {
            hit |= (a..=b).contains(&c);
            i += 3;
        } else {
            hit |= a == c;
            i += 1;
        }
    }
    Some((hit, end + 1))
}

/// The module of a `modules.alias` text that claims `modalias`.
pub fn module_for(aliases: &str, modalias: &str) -> Option<String> {
    let bus = modalias.split(':').next()?;
    aliases.lines().find_map(|line| {
        let mut w = line.split_ascii_whitespace();
        let (Some("alias"), Some(pattern), Some(module)) = (w.next(), w.next(), w.next()) else {
            return None;
        };
        (pattern.split(':').next() == Some(bus)
            && alias_matches(pattern.as_bytes(), modalias.as_bytes()))
        .then(|| clean(module, 64))
    })
}

/// USB Ethernet chips whose interfaces say only "vendor specific": no class
/// tells them from a serial dongle. (vendor, product; `None`: all of the
/// vendor's). From the id tables of `drivers/net/usb/` (`r8152.c:10034`,
/// `ax88179_178a.c`, `asix_devices.c`, `lan78xx.c`, `smsc95xx.c`, `aqc111.c`).
const USB_ETHERNET: &[(u16, Option<u16>)] = &[
    (0x0b95, None), // ASIX
    (0x0bda, Some(0x8050)),
    (0x0bda, Some(0x8053)),
    (0x0bda, Some(0x8152)),
    (0x0bda, Some(0x8153)),
    (0x0bda, Some(0x8155)),
    (0x0bda, Some(0x8156)),
    (0x2357, Some(0x0601)), // TP-Link UE300
    (0x2357, Some(0x0602)),
    (0x13b1, Some(0x0041)), // Linksys
    (0x2001, Some(0xb301)), // D-Link
    (0x20f4, Some(0xe02b)), // TRENDnet
    (0x0424, Some(0x7500)), // Microchip LAN75xx/78xx
    (0x0424, Some(0x7505)),
    (0x0424, Some(0x7800)),
    (0x0424, Some(0x7801)),
    (0x0424, Some(0x7850)),
    (0x0424, Some(0x9500)), // SMSC LAN95xx
    (0x0424, Some(0x9505)),
    (0x0424, Some(0xec00)),
    (0x2eca, None), // Aquantia AQC111 boards
];

/// Whether a USB interface without a driver is a network card: the standard
/// classes (CDC ECM, EEM, NCM, MBIM; RNDIS by either of its two codes), or a
/// chip known by its ids.
pub fn usb_is_ethernet(class: u8, subclass: u8, protocol: u8, vendor: u16, product: u16) -> bool {
    matches!(
        (class, subclass, protocol),
        (0x02, 0x06 | 0x0c | 0x0d | 0x0e, _) | (0xe0, 0x01, 0x03) | (0xef, 0x04, 0x01)
    ) || (class == 0xff
        && USB_ETHERNET
            .iter()
            .any(|(v, p)| *v == vendor && p.is_none_or(|p| p == product)))
}

/// The virtual lab's machine: a card without a driver, one in Safe Mode, a
/// Wi-Fi card out of the image's purpose, and `regulatory.db`, which must
/// not count.
pub fn lab_reading() -> NicReading {
    let device = |address: &str,
                  kind,
                  ids: (&str, &str),
                  names: (&str, &str),
                  driver: Option<&str>,
                  port: Option<&str>| NicDevice {
        bus: Bus::Pci,
        address: address.to_owned(),
        kind,
        vendor_id: ids.0.to_owned(),
        product_id: ids.1.to_owned(),
        vendor: Some(names.0.to_owned()),
        product: Some(names.1.to_owned()),
        driver: driver.map(str::to_owned),
        ports: port.map(str::to_owned).into_iter().collect(),
        virtual_function: false,
        module: None,
        safe_mode_queues: false,
    };
    let devices = vec![
        device(
            "0000:03:00.0",
            NicKind::Ethernet,
            ("8086", "1592"),
            ("Intel Corporation", "Ethernet Controller E810-C for QSFP"),
            Some("ice"),
            Some("ether7"),
        ),
        device(
            "0000:05:00.0",
            NicKind::Ethernet,
            ("19ee", "4000"),
            ("Netronome Systems, Inc.", "NFP4000 Network Flow Processor"),
            None,
            None,
        ),
        device(
            "0000:06:00.0",
            NicKind::Other,
            ("8086", "2725"),
            ("Intel Corporation", "Wi-Fi 6E AX210"),
            None,
            None,
        ),
    ];
    let mut notes = KernelNotes::default();
    for l in [
        "platform regulatory.0: Direct firmware load for regulatory.db failed with error -2",
        "ice 0000:03:00.0: Direct firmware load for intel/ice/ddp/ice.pkg failed with error -2",
        "ice 0000:03:00.0: The DDP package file was not found or could not be read. Entering Safe Mode",
    ] {
        notes.line(l);
    }
    notes.keep_devices(&devices);
    NicReading {
        devices,
        notes: notes
            .iter()
            .map(|(k, v)| (k.to_owned(), v.clone()))
            .collect(),
        kernel_log: true,
        ..NicReading::default()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// A line of each driver, as its source prints it (kernel 6.18.59, file
    /// and line beside it), or **measured** where QEMU has the card.
    #[test]
    fn firmware_lines_of_every_driver() {
        let e = |n: i32| Some(n);
        for (line, device, driver, file, error) in [
            // firmware_loader/main.c:903, the generic one. Measured with
            // e100 on QEMU (docs/os-image.md, G1.6j).
            (
                "e100 0000:00:03.0: Direct firmware load for e100/d102e_ucode.bin failed with error -2",
                "0000:00:03.0",
                "e100",
                "e100/d102e_ucode.bin",
                e(-2),
            ),
            (
                "tg3 0000:04:00.0: Direct firmware load for tigon/tg3_tso5.bin failed with error -2",
                "0000:04:00.0",
                "tg3",
                "tigon/tg3_tso5.bin",
                e(-2),
            ),
            (
                "bnx2 0000:05:00.0: Direct firmware load for bnx2/bnx2-mips-09-6.2.1b.fw failed with error -2",
                "0000:05:00.0",
                "bnx2",
                "bnx2/bnx2-mips-09-6.2.1b.fw",
                e(-2),
            ),
            (
                "bnx2x 0000:05:00.1: Direct firmware load for bnx2x/bnx2x-e2-7.13.21.0.fw failed with error -2",
                "0000:05:00.1",
                "bnx2x",
                "bnx2x/bnx2x-e2-7.13.21.0.fw",
                e(-2),
            ),
            (
                "qede 0000:06:00.0: Direct firmware load for qed/qed_init_values_zipped-8.59.1.0.bin failed with error -2",
                "0000:06:00.0",
                "qede",
                "qed/qed_init_values_zipped-8.59.1.0.bin",
                e(-2),
            ),
            (
                "netxen_nic 0000:07:00.0: Direct firmware load for phanfw.bin failed with error -110",
                "0000:07:00.0",
                "netxen_nic",
                "phanfw.bin",
                e(-110),
            ),
            (
                "myri10ge 0000:08:00.0: Direct firmware load for myri10ge_eth_z8e.dat failed with error -2",
                "0000:08:00.0",
                "myri10ge",
                "myri10ge_eth_z8e.dat",
                e(-2),
            ),
            // kaweth asks on the USB device, not the interface (kaweth.c:307).
            (
                "kaweth 1-1: Direct firmware load for kaweth/new_code.bin failed with error -2",
                "1-1",
                "kaweth",
                "kaweth/new_code.bin",
                e(-2),
            ),
            (
                "ice 0000:03:00.0: Direct firmware load for intel/ice/ddp/ice.pkg failed with error -2",
                "0000:03:00.0",
                "ice",
                "intel/ice/ddp/ice.pkg",
                e(-2),
            ),
            // r8169_firmware.c: firmware_request_nowarn and its own line.
            (
                "r8169 0000:02:00.0: Unable to load firmware rtl_nic/rtl8168h-2.fw (-2)",
                "0000:02:00.0",
                "r8169",
                "rtl_nic/rtl8168h-2.fw",
                e(-2),
            ),
            // r8152.c:5296.
            (
                "r8152 4-2:1.0: unable to load firmware patch rtl_nic/rtl8153b-2.fw (-2)",
                "4-2:1.0",
                "r8152",
                "rtl_nic/rtl8153b-2.fw",
                e(-2),
            ),
            // e100.c:1265 and :1270, netif_err: the interface in the head.
            (
                "e100 0000:01:01.0 eth0: Failed to load firmware \"e100/d102e_ucode.bin\": -2",
                "0000:01:01.0",
                "e100",
                "e100/d102e_ucode.bin",
                e(-2),
            ),
            (
                "e100 0000:01:01.0 (unnamed net_device) (uninitialized): CPUSaver disabled. Needs \"e100/d101m_ucode.bin\": -2",
                "0000:01:01.0",
                "e100",
                "e100/d101m_ucode.bin",
                e(-2),
            ),
            // tg3.c:11500, typhoon.c:1283.
            (
                "tg3 0000:04:00.0 eth1: Failed to load firmware \"tigon/tg3_tso.bin\"",
                "0000:04:00.0",
                "tg3",
                "tigon/tg3_tso.bin",
                None,
            ),
            (
                "typhoon 0000:09:00.0 eth2: Failed to load firmware \"3com/typhoon.bin\"",
                "0000:09:00.0",
                "typhoon",
                "3com/typhoon.bin",
                None,
            ),
            // cxgb4_main.c:4823, cxgb3_main.c:1080 and :1129.
            (
                "cxgb4 0000:0a:00.4: unable to load firmware image cxgb4/t5fw-1.27.5.0.bin, error -2",
                "0000:0a:00.4",
                "cxgb4",
                "cxgb4/t5fw-1.27.5.0.bin",
                e(-2),
            ),
            (
                "cxgb3 0000:0b:00.0: could not upgrade firmware: unable to load cxgb3/t3fw-7.12.0.bin",
                "0000:0b:00.0",
                "cxgb3",
                "cxgb3/t3fw-7.12.0.bin",
                None,
            ),
            (
                "cxgb3 0000:0b:00.0: could not load TP SRAM: unable to load cxgb3/t3c_psram-1.1.0.bin",
                "0000:0b:00.0",
                "cxgb3",
                "cxgb3/t3c_psram-1.1.0.bin",
                None,
            ),
            // PHYs: mscc_main.c:1183, aquantia_firmware.c:339, mtk-2p5ge.c:68.
            (
                "Microsemi GE VSC8574 SyncE stmmac-0:01: failed to load firmware microchip/mscc_vsc8574_revb_int8051_29e8.bin, ret: -2",
                "stmmac-0:01",
                "Microsemi GE VSC8574 SyncE",
                "microchip/mscc_vsc8574_revb_int8051_29e8.bin",
                e(-2),
            ),
            (
                "Aquantia AQR113C stmmac-1:08: failed to find FW file aquantia/aqr-firmware.cld (-2)",
                "stmmac-1:08",
                "Aquantia AQR113C",
                "aquantia/aqr-firmware.cld",
                e(-2),
            ),
            (
                "mtk-2p5ge mdio-bus:0f: failed to load firmware: mediatek/mt7988/i2p5ge-phy-pmb.bin, ret: -2",
                "mdio-bus:0f",
                "mtk-2p5ge",
                "mediatek/mt7988/i2p5ge-phy-pmb.bin",
                e(-2),
            ),
        ] {
            let notes = parse_line(line);
            let Some(KernelNote {
                device: d,
                driver: dr,
                what: NoteKind::Firmware { file: f, error: er },
            }) = notes.first()
            else {
                panic!("{line}: {notes:?}");
            };
            assert_eq!(d.as_deref(), Some(device), "{line}");
            assert_eq!(dr.as_deref(), Some(driver), "{line}");
            assert_eq!(f, file, "{line}");
            assert_eq!(*er, error, "{line}");
        }
    }

    /// `ice_log_pkg_init`, `ice_main.c:4254`, and `ice_request_fw`, `:4523`.
    #[test]
    fn ice_safe_mode_lines() {
        use SafeModeCause::{FileInvalid, FileMissing, Unknown, Version};
        let dev = "ice 0000:03:00.0: ";
        for (text, cause) in [
            (
                "The DDP package file was not found or could not be read. Entering Safe Mode",
                FileMissing,
            ),
            (
                "The DDP package file is invalid. Entering Safe Mode.",
                FileInvalid,
            ),
            (
                "The DDP package file failed to load. Entering Safe Mode.",
                FileInvalid,
            ),
            (
                "The DDP package could not be loaded because its signature is not valid.  Please use a valid DDP Package.  Entering Safe Mode.",
                FileInvalid,
            ),
            (
                "The DDP Package could not be loaded because its security revision is too low.  Please use an updated DDP Package.  Entering Safe Mode.",
                Version,
            ),
            (
                "The firmware loaded on the device is not compatible with the DDP package.  Please update the device's NVM.  Entering safe mode.",
                Version,
            ),
            (
                "The DDP package file version is higher than the driver supports.  Please use an updated driver.  Entering Safe Mode.",
                Version,
            ),
            (
                "The DDP package file version is lower than the driver supports.  The driver requires version 1.3.x.x.  Please use an updated DDP Package file.  Entering Safe Mode.",
                Version,
            ),
            (
                "The device has a DDP package that is not supported by the driver.  The device has package 'ICE OS Default Package' version 1.2.x.x.  The driver requires version 1.3.x.x.  Entering Safe Mode.",
                Version,
            ),
            (
                "An unknown error occurred when loading the DDP package.  Entering Safe Mode.",
                Unknown,
            ),
            (
                "Device is in Safe Mode - not enabling advanced netdev features",
                Unknown,
            ),
        ] {
            let line = format!("{dev}{text}");
            let notes = parse_line(&line);
            assert_eq!(
                notes.last().map(|n| n.what.clone()),
                Some(NoteKind::SafeMode(cause)),
                "{text}"
            );
        }
        // The file is named too.
        let notes = parse_line(
            "ice 0000:03:00.0: The DDP package file was not found or could not be read. Entering Safe Mode",
        );
        assert_eq!(notes.len(), 2);
        assert!(
            matches!(&notes[0].what, NoteKind::Firmware { file, .. } if file == "intel/ice/ddp/ice.pkg")
        );
        // Back out of it.
        for text in [
            "The DDP package was successfully loaded: ICE OS Default Package version 1.3.43.0",
            "DDP package already present on device: ICE OS Default Package version 1.3.43.0",
        ] {
            assert_eq!(
                parse_line(&format!("{dev}{text}"))
                    .last()
                    .map(|n| n.what.clone()),
                Some(NoteKind::SafeModeOff),
                "{text}"
            );
        }
        // Another driver saying these words is not ice.
        assert!(parse_line("e1000e 0000:00:1f.6: Entering Safe Mode").is_empty());
    }

    #[test]
    fn what_must_not_warn() {
        for line in [
            // The false alarm the gap names.
            "platform regulatory.0: Direct firmware load for regulatory.db failed with error -2",
            "platform regulatory.0: Direct firmware load for regulatory.db.p7s failed with error -2",
            "cfg80211: failed to load regulatory.db",
            // cxgb4 falls back to its flash.
            "cxgb4 0000:0a:00.4: Direct firmware load for cxgb4/t5-config.txt failed with error -2",
            // The optional per-device DDP.
            "ice 0000:03:00.0: Direct firmware load for intel/ice/ddp/ice-0123456789abcdef.pkg failed with error -2",
            "r8169 0000:02:00.0 ether1: Link is Down",
            "ice 0000:03:00.0: The DDP package was retrieved",
            // A USB device chooses its product string: only the text right
            // after the head counts.
            "usb 1-1: Product: Direct firmware load for evil.bin failed with error -2",
            "usb 1-1: Direct firmware load for ../../etc/passwd failed with error -2",
            "usb 1-1: Direct firmware load for /etc/passwd failed with error -2",
            "",
            "no colon at all",
        ] {
            let n = parse_line(line);
            assert!(
                n.iter().all(|x| x.what == NoteKind::SafeModeOff) || n.is_empty(),
                "{line}: {n:?}"
            );
        }
        assert!(parse_line("ice 0000:03:00.0: The DDP package was retrieved").is_empty());
        // The live network test still shows it to the curious.
        let (d, f, _) = missing_firmware(
            "platform regulatory.0: Direct firmware load for regulatory.db failed with error -2",
        )
        .unwrap();
        assert_eq!((d, f.as_str()), (None, "regulatory.db"));
    }

    #[test]
    fn notes_fold_and_forget() {
        let mut n = KernelNotes::default();
        let nic = |address: &str| NicDevice {
            bus: Bus::Usb,
            address: address.to_owned(),
            kind: NicKind::Ethernet,
            vendor_id: String::new(),
            product_id: String::new(),
            vendor: None,
            product: None,
            driver: None,
            ports: vec![],
            virtual_function: false,
            module: None,
            safe_mode_queues: false,
        };
        // The generic line and the driver's, same file: one row.
        n.line("r8152 4-2:1.0: Direct firmware load for rtl_nic/a.fw failed with error -2");
        n.line("r8152 4-2:1.0: unable to load firmware patch rtl_nic/a.fw (-2)");
        n.line("kaweth 1-1: Direct firmware load for kaweth/b.bin failed with error -2");
        n.line("i915 0000:00:02.0: Direct firmware load for i915/x.bin failed with error -2");
        n.keep_devices(&[nic("4-2:1.0"), nic("1-1:1.0")]);
        let v: Vec<_> = n
            .iter()
            .map(|(k, d)| (k.to_owned(), d.files.len()))
            .collect();
        assert_eq!(
            v,
            [("1-1".to_owned(), 1), ("4-2:1.0".to_owned(), 1)],
            "the GPU's line is gone"
        );
        // Unplugged: forgotten.
        n.keep_devices(&[nic("1-1:1.0")]);
        assert_eq!(n.iter().count(), 1);

        // Safe Mode: the reason stays over the later generic line, and a
        // package that loads takes it and its file away.
        let mut n = KernelNotes::default();
        n.line("ice 0000:03:00.0: The DDP package file was not found or could not be read. Entering Safe Mode");
        n.line("ice 0000:03:00.0: Device is in Safe Mode - not enabling advanced netdev features");
        let d = n.iter().next().unwrap().1.clone();
        assert_eq!(d.safe_mode, Some(SafeModeCause::FileMissing));
        assert_eq!(d.files.len(), 1);
        n.line("ice 0000:03:00.0: The DDP package was successfully loaded: ICE OS Default Package version 1.3.43.0");
        let d = n.iter().next().unwrap().1.clone();
        assert_eq!(d.safe_mode, None);
        assert!(d.files.is_empty());

        // Bounded, against a log that names endless devices or files.
        let mut n = KernelNotes::default();
        for i in 0..MAX_NOTED + 50 {
            n.line(&format!(
                "x 1-{i}:1.0: Direct firmware load for a.bin failed with error -2"
            ));
        }
        assert_eq!(n.iter().count(), MAX_NOTED);
        let mut n = KernelNotes::default();
        for i in 0..MAX_FILES + 50 {
            n.line(&format!(
                "x 1-1:1.0: Direct firmware load for a{i}.bin failed with error -2"
            ));
        }
        assert_eq!(n.iter().next().unwrap().1.files.len(), MAX_FILES);
    }

    #[test]
    fn the_module_index() {
        let aliases = "# comment\n\
            alias pci:v00008086d00001592sv*sd*bc*sc*i* ice\n\
            alias usb:v0BDAp8153d*dc*dsc*dp*ic*isc*ip*in* r8152\n\
            alias pci:v000010ECd000081[23]9sv*sd*bc*sc*i* r8169\n\
            bad line\n";
        let pci = "pci:v00008086d00001592sv00008086sd00000002bc02sc00i00";
        assert_eq!(module_for(aliases, pci).as_deref(), Some("ice"));
        assert_eq!(
            module_for(aliases, "pci:v000010ECd00008139sv0sd0bc02sc00i00").as_deref(),
            Some("r8169")
        );
        assert_eq!(
            module_for(aliases, "pci:v000010ECd00008149sv0sd0bc02sc00i00"),
            None
        );
        assert_eq!(
            module_for(aliases, "pci:v00001AF4d00001000sv0sd0bc02sc00i00"),
            None
        );
        assert_eq!(
            module_for(aliases, "usb:v0BDAp8153d3100dc00dsc00dp00icFFisc00ip00in00").as_deref(),
            Some("r8152")
        );
        assert_eq!(module_for(aliases, ""), None);
    }

    #[test]
    fn usb_classes() {
        for (c, s, p) in [
            (0x02, 0x06, 0),
            (0x02, 0x0d, 0),
            (0x02, 0x0e, 0),
            (0xe0, 0x01, 0x03),
            (0xef, 0x04, 0x01),
        ] {
            assert!(
                usb_is_ethernet(c, s, p, 0x1234, 0x5678),
                "{c:x}/{s:x}/{p:x}"
            );
        }
        // A modem's ACM, a Wi-Fi radio (e0/01/01 is Bluetooth), a serial
        // dongle.
        assert!(!usb_is_ethernet(0x02, 0x02, 0, 0x1234, 0x5678));
        assert!(!usb_is_ethernet(0xe0, 0x01, 0x01, 0x1234, 0x5678));
        assert!(!usb_is_ethernet(0xff, 0xff, 0xff, 0x1a86, 0x7523));
        assert!(
            !usb_is_ethernet(0xff, 0, 0, 0x0bda, 0xb812),
            "a Realtek Wi-Fi radio"
        );
        assert!(usb_is_ethernet(0xff, 0xff, 0, 0x0bda, 0x8153));
        assert!(usb_is_ethernet(0xff, 0xff, 0, 0x0b95, 0x1790));
    }

    #[test]
    fn boot_options() {
        let mut r = NicReading::default();
        r.boot_options("console=ttyS0 corerouter.mode=live corerouter.modules=off panic=10");
        assert!(r.live && r.modules_off);
        let mut r = NicReading::default();
        r.boot_options("root=/dev/dm-0 corerouter.modules=on");
        assert!(!r.live && !r.modules_off);
    }

    #[test]
    fn the_lab_has_each_case_and_no_false_alarm() {
        let r = lab_reading();
        assert_eq!(r.notes.len(), 1, "regulatory.0 is not there");
        let (dev, d) = &r.notes[0];
        assert_eq!(dev, "0000:03:00.0");
        assert_eq!(d.safe_mode, Some(SafeModeCause::FileMissing));
    }

    proptest! {
        /// Hostile lines: never a panic, and whatever comes out is bounded
        /// and looks like a file name.
        #[test]
        fn any_line_is_safe(line in "\\PC{0,400}") {
            let mut n = KernelNotes::default();
            n.line(&line);
            for note in parse_line(&line) {
                if let NoteKind::Firmware { file, .. } = note.what {
                    prop_assert!(file_name(&file));
                }
                prop_assert!(note.device.is_none_or(|d| d.chars().count() <= 65));
            }
        }

        /// Close to real lines, with the file and the device mangled.
        #[test]
        fn near_real_lines_are_safe(
            head in "[a-z0-9 :.()_-]{0,120}",
            text in prop::sample::select(FIRMWARE_TEXTS.iter().map(|t| t.0).collect::<Vec<_>>()),
            file in "[ -~]{0,300}",
        ) {
            for note in parse_line(&format!("{head}: {text}{file} failed (-2), x")) {
                if let NoteKind::Firmware { file, .. } = note.what {
                    prop_assert!(file_name(&file));
                }
            }
        }

        #[test]
        fn alias_match_never_panics(p in "[a-z*?\\[\\]-]{0,60}", t in "[a-z]{0,60}") {
            let _ = alias_matches(p.as_bytes(), t.as_bytes());
        }
    }
}
