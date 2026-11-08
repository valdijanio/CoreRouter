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

/// Whole disks (no partitions, loop, ram, device-mapper); optical drives
/// only with `optical` (the medium may be a CD, a target never is).
pub fn block_devices(optical: bool) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir("/sys/block")
        .map(|d| {
            d.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| optical || !n.starts_with("sr"))
                .filter(|n| {
                    !["loop", "ram", "zram", "dm-", "md", "nbd", "fd"]
                        .iter()
                        .any(|p| n.starts_with(p))
                })
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
pub fn list(medium: &str, index: &Index) -> Vec<Disk> {
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
