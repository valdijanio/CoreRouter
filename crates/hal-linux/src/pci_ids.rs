//! Names for PCI ids from the system's `pci.ids` database (G1.19), the
//! file `lspci` reads. Pure: the caller reads the file; a missing or odd
//! database just leaves the names out (the ids are still shown).
//!
//! Format (the parts used): a vendor line is `vvvv  Name` at column 0, a
//! device line is a tab then `dddd  Name`, a subsystem line is two tabs
//! then `ssss tttt  Name`. `#` starts a comment; the class section
//! (`C xx  Name`) ends the vendor list.

/// Where distributions install the database, in the order tried.
pub const PATHS: [&str; 3] = [
    "/usr/share/hwdata/pci.ids",
    "/usr/share/misc/pci.ids",
    "/usr/share/pci.ids",
];

/// The database is ~1.5 MB; anything far larger is not one.
pub const MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Longest name kept (the real database's longest is ~100 bytes).
const MAX_NAME: usize = 128;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PciNames {
    pub vendor: Option<String>,
    pub device: Option<String>,
    pub subsystem: Option<String>,
}

/// The ids to name: vendor/device and, optionally, the subsystem pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciIds {
    pub vendor: u16,
    pub device: u16,
    pub subsystem: Option<(u16, u16)>,
}

/// `vvvv  Name` → (id, name).
fn entry(line: &str) -> Option<(u16, String)> {
    let (id, name) = line.split_once("  ")?;
    if id.len() != 4 {
        return None;
    }
    let id = u16::from_str_radix(id, 16).ok()?;
    Some((id, clip(name)))
}

fn clip(name: &str) -> String {
    name.trim().chars().take(MAX_NAME).collect()
}

/// Look `ids` up in the text of a `pci.ids` file.
pub fn lookup(db: &str, ids: PciIds) -> PciNames {
    let mut out = PciNames::default();
    // Inside the wanted vendor's block / device's block.
    let mut in_vendor = false;
    let mut in_device = false;
    for line in db.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if let Some(sub) = line.strip_prefix("\t\t") {
            if !in_device {
                continue;
            }
            let Some((pair, name)) = sub.split_once("  ") else {
                continue;
            };
            let mut it = pair.split(' ');
            let parsed = (
                it.next().and_then(|v| u16::from_str_radix(v, 16).ok()),
                it.next().and_then(|d| u16::from_str_radix(d, 16).ok()),
            );
            if let (Some(sv), Some(sd)) = parsed
                && ids.subsystem == Some((sv, sd))
            {
                out.subsystem = Some(clip(name));
                return out;
            }
        } else if let Some(dev) = line.strip_prefix('\t') {
            if !in_vendor {
                continue;
            }
            if in_device && ids.subsystem.is_none() {
                return out;
            }
            in_device = false;
            if let Some((id, name)) = entry(dev)
                && id == ids.device
            {
                out.device = Some(name);
                in_device = true;
            }
        } else {
            if in_vendor || line.starts_with("C ") {
                // Left the vendor's block (or reached the classes).
                return out;
            }
            if let Some((id, name)) = entry(line)
                && id == ids.vendor
            {
                out.vendor = Some(name);
                in_vendor = true;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const DB: &str = "\
# comment
0010  Allied Telesis, Inc (Wrong ID)
# This is a relabelled RTL-8139
\t8139  AT-2500TX V3 Ethernet
8086  Intel Corporation
\t10d3  82574L Gigabit Network Connection
\t\t8086 a01f  Gigabit CT Desktop Adapter
\t\t103c 3250  NC112T PCIe Gigabit Server Adapter
\t1533  I210 Gigabit Network Connection
8087  Intel Corporation
\t0024  Bluetooth wireless interface
C 02  Network controller
\t00  Ethernet controller
";

    fn ids(vendor: u16, device: u16, sub: Option<(u16, u16)>) -> PciIds {
        PciIds {
            vendor,
            device,
            subsystem: sub,
        }
    }

    #[test]
    fn names_vendor_device_and_subsystem() {
        let n = lookup(DB, ids(0x8086, 0x10d3, Some((0x103c, 0x3250))));
        assert_eq!(n.vendor.as_deref(), Some("Intel Corporation"));
        assert_eq!(
            n.device.as_deref(),
            Some("82574L Gigabit Network Connection")
        );
        assert_eq!(
            n.subsystem.as_deref(),
            Some("NC112T PCIe Gigabit Server Adapter")
        );
        let n = lookup(DB, ids(0x8086, 0x1533, None));
        assert_eq!(n.device.as_deref(), Some("I210 Gigabit Network Connection"));
        assert_eq!(n.subsystem, None);
    }

    #[test]
    fn unknown_ids_name_what_is_known() {
        let n = lookup(DB, ids(0x8086, 0xffff, Some((1, 2))));
        assert_eq!(n.vendor.as_deref(), Some("Intel Corporation"));
        assert_eq!(n.device, None);
        assert_eq!(lookup(DB, ids(0x1234, 0x10d3, None)), PciNames::default());
        // A device id of another vendor is never borrowed.
        assert_eq!(lookup(DB, ids(0x8087, 0x10d3, None)).device, None);
        // Class lines are not vendors.
        assert_eq!(lookup(DB, ids(0x0002, 0x0000, None)), PciNames::default());
    }

    #[test]
    fn the_system_database_if_any_names_a_common_nic() {
        let Some(db) = PATHS.iter().find_map(|p| std::fs::read_to_string(p).ok()) else {
            return;
        };
        let n = lookup(&db, ids(0x8086, 0x1533, None));
        assert_eq!(n.vendor.as_deref(), Some("Intel Corporation"));
        assert!(n.device.is_some_and(|d| d.contains("I210")));
    }

    proptest! {
        /// Hostile text never panics and names stay short.
        #[test]
        fn hostile_database(db in "(?s).{0,2000}", v in any::<u16>(), d in any::<u16>(),
                            s in proptest::option::of((any::<u16>(), any::<u16>()))) {
            let n = lookup(&db, ids(v, d, s));
            for name in [n.vendor, n.device, n.subsystem].into_iter().flatten() {
                prop_assert!(name.chars().count() <= MAX_NAME);
            }
        }

        /// Any entry put in a generated database is found again.
        #[test]
        fn finds_generated_entries(v in any::<u16>(), d in any::<u16>(),
                                   sv in any::<u16>(), sd in any::<u16>(),
                                   vn in "[A-Za-z][A-Za-z0-9 ,.]{0,40}[a-z]",
                                   dn in "[A-Za-z][A-Za-z0-9 ]{0,40}[a-z]") {
            let db = format!(
                "{other:04x}  Other\n\t{d:04x}  Not this\n{v:04x}  {vn}\n\t{d:04x}  {dn}\n\t\t{sv:04x} {sd:04x}  Sub\n",
                other = v.wrapping_add(1)
            );
            let n = lookup(&db, ids(v, d, Some((sv, sd))));
            prop_assert_eq!(n.vendor.as_deref(), Some(vn.trim()));
            prop_assert_eq!(n.device.as_deref(), Some(dn.trim()));
            prop_assert_eq!(n.subsystem.as_deref(), Some("Sub"));
        }
    }
}
