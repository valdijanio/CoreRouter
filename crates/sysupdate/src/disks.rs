//! The disks an install could write to and the medium it reads (G1.6y): the
//! list the console installer shows and `system.install.print` serves.

use std::fs::File;
use std::path::Path;

use crate::install::{self, Existing, Index, Medium};
use crate::package::Key;

/// Keys that sign an image, on the image.
pub const KEYS: &str = "/etc/corerouter/image-keys";

/// While it exists PID 1 of the live image counts power-button presses
/// instead of powering off; each press is one byte in [`BUTTON_PRESSES`].
pub const CHALLENGE_OPEN: &str = "/run/corerouter/install-challenge";
pub const BUTTON_PRESSES: &str = "/run/corerouter/install-presses";

/// What the install left for the first boot, on the new `/config`; PID 1
/// applies it once and removes it.
pub const FIRST_BOOT: &str = "first-boot.json";
/// More than this is not ours.
pub const FIRST_BOOT_MAX: u64 = 16 << 10;

/// A disk that could be the target.
#[derive(Debug, Clone)]
pub struct Disk {
    pub name: String,
    pub bytes: u64,
    pub lbs: u64,
    pub model: String,
    pub serial: String,
    pub bus: &'static str,
    pub removable: bool,
    pub existing: Existing,
    /// Why it cannot be the target.
    pub refused: Option<String>,
}

pub fn sys(path: &str) -> String {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

pub fn human(bytes: u64) -> String {
    let g = bytes as f64 / (1u64 << 30) as f64;
    if g >= 1.0 {
        format!("{g:.1} GiB")
    } else {
        format!("{} MiB", bytes >> 20)
    }
}

/// Is `/sys/block/<name>` a whole disk an install could look at? Not loop,
/// ram, device-mapper and the like; optical drives only with `optical`.
/// G1.6zi: nor an eMMC's boot areas (`mmcblk0boot0`, `mmcblk0boot1`): two
/// small read-only "disks" of every eMMC, which the firmware boots from.
pub fn whole_disk(name: &str, optical: bool) -> bool {
    let emmc_boot = name.strip_prefix("mmcblk").is_some_and(|n| {
        let area = n.trim_start_matches(|c: char| c.is_ascii_digit());
        area.len() < n.len() && area.starts_with("boot")
    });
    (optical || !name.starts_with("sr"))
        && !emmc_boot
        && !["loop", "ram", "zram", "dm-", "md", "nbd", "fd"]
            .iter()
            .any(|p| name.starts_with(p))
}

/// Whole disks ([`whole_disk`]); optical drives only with `optical` (the
/// medium may be a CD, a target never is).
pub fn block_devices(optical: bool) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir("/sys/block")
        .map(|d| {
            d.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| whole_disk(n, optical))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// One look for the installer medium; `bad` hears of a copy that is damaged
/// or not signed by these keys.
pub fn find_medium(
    keys: &[Key],
    bad: &mut dyn FnMut(&str, &str),
) -> Option<(String, Medium<File>)> {
    for name in block_devices(true) {
        let Ok(mut f) = File::open(format!("/dev/{name}")) else {
            continue;
        };
        if !crate::iso::is_installer(&mut f) {
            continue;
        }
        match Medium::open(f, keys) {
            Ok(m) => return Some((name, m)),
            Err(e) => bad(&name, &e),
        }
    }
    None
}

/// This boot came through a BIOS, not UEFI (G1.6g).
pub fn booted_by_bios() -> bool {
    !Path::new("/sys/firmware/efi").exists()
}

/// G1.6g: a BIOS reads 512-byte blocks: GRUB and its offsets assume them.
pub fn sector_refusal(bios: bool, lbs: u64) -> Option<String> {
    (bios && lbs != 512).then(|| {
        format!("{lbs}-byte sectors: a BIOS cannot boot it (start this installer in UEFI mode)")
    })
}

fn bus(name: &str) -> &'static str {
    let p = std::fs::canonicalize(format!("/sys/block/{name}"))
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    if p.contains("/usb") {
        "USB"
    } else if name.starts_with("nvme") {
        "NVMe"
    } else if p.contains("/virtio") {
        "virtio"
    } else if p.contains("/ata") {
        "SATA"
    } else if name.starts_with("mmcblk") {
        "SD/eMMC"
    } else if name.starts_with("xvd") {
        "Xen"
    } else if name.starts_with("sr") {
        "optical"
    } else {
        "SCSI"
    }
}

/// Anything stacked on the disk (RAID, LVM): `O_EXCL` would refuse it later
/// with a bare "busy".
fn holders(name: &str) -> Vec<String> {
    std::fs::read_dir(format!("/sys/block/{name}/holders"))
        .map(|d| {
            d.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Reads every disk; a few seconds on spinning disks ([`install::existing`]),
/// so never under a lock.
pub fn list(medium: &str, index: &Index, bios: bool) -> Vec<Disk> {
    block_devices(false)
        .into_iter()
        .map(|name| {
            let base = format!("/sys/block/{name}");
            let bytes = sys(&format!("{base}/size")).parse::<u64>().unwrap_or(0) * 512;
            let lbs = sys(&format!("{base}/queue/logical_block_size"))
                .parse()
                .unwrap_or(512);
            let model = [
                sys(&format!("{base}/device/vendor")),
                sys(&format!("{base}/device/model")),
            ]
            .iter()
            // virtio's "vendor" is the PCI id (0x1af4), not a name.
            .filter(|s| !s.is_empty() && !s.starts_with("0x"))
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
            let serial = [format!("{base}/device/serial"), format!("{base}/serial")]
                .iter()
                .map(|p| sys(p))
                .find(|s| !s.is_empty())
                .unwrap_or_default();
            let mut existing = Existing::Unknown;
            let mut refused = None;
            if name == medium {
                refused = Some("the installer medium".into());
            } else if let Some(r) = sector_refusal(bios, lbs) {
                refused = Some(r);
            } else if name.starts_with("sr") {
                refused = Some("optical drive".into());
            } else if sys(&format!("{base}/ro")) == "1" {
                refused = Some("read-only".into());
            } else if bytes < index.min_disk() {
                refused = Some(format!(
                    "smaller than the {} the image needs",
                    human(index.min_disk())
                ));
            } else if let Some(h) = holders(&name).first() {
                refused = Some(format!("in use by {h} (RAID or LVM): stop it first"));
            }
            if let Ok(mut f) = File::open(Path::new("/dev").join(&name)) {
                if crate::iso::is_installer(&mut f) {
                    refused.get_or_insert_with(|| "holds an installer image".into());
                }
                existing = install::existing(&mut f, lbs, index);
            } else {
                refused.get_or_insert_with(|| "cannot be opened".into());
            }
            Disk {
                bus: bus(&name),
                removable: sys(&format!("{base}/removable")) == "1",
                name,
                bytes,
                lbs,
                model,
                serial,
                existing,
                refused,
            }
        })
        .collect()
}

pub fn describe(e: &Existing) -> String {
    match e {
        Existing::Empty => "empty".into(),
        Existing::Gpt(names) if names.is_empty() => "GPT, no partitions".into(),
        Existing::Gpt(names) => format!("GPT: {}", names.join(", ")),
        Existing::CoreRouter { .. } => "CoreRouter".into(),
        Existing::Unknown => "data (MBR or a filesystem)".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// G1.6zi: an eMMC is a disk to install to; its two boot areas are not.
    #[test]
    fn an_emmc_is_a_target_and_its_boot_areas_are_not() {
        for disk in [
            "sda", "vda", "xvda", "nvme0n1", "mmcblk0", "mmcblk1", "mmcblk12",
        ] {
            assert!(whole_disk(disk, false), "{disk}");
        }
        for not in [
            "mmcblk0boot0",
            "mmcblk0boot1",
            "mmcblk12boot0",
            "loop0",
            "ram0",
            "zram0",
            "dm-0",
            "md127",
            "nbd0",
            "fd0",
            "sr0",
        ] {
            assert!(!whole_disk(not, false), "{not}");
        }
        // The medium may be a CD; nothing else changes with it.
        assert!(whole_disk("sr0", true));
        assert!(!whole_disk("mmcblk0boot0", true));
        // Only the boot areas: not a disk that merely starts the same.
        assert!(whole_disk("mmcblkboot", false));
        assert!(whole_disk("mmcblk0rpmb", false));
    }
}
