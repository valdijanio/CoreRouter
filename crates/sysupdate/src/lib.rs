//! The A/B system image (G1.6b, `docs/os-image.md`): two root slots, a
//! signed update package, dm-verity, and a trial boot that falls back to
//! the previous slot unless it is confirmed.
//!
//! - [`package`]: the `.crpkg` format, Ed25519 signature, streamed copy.
//! - [`verity`]: the dm-verity hash tree (built by xtask, re-checked on the
//!   router after a slot is written).
//! - [`efi`]: `Boot####`, `BootOrder`, `BootNext` in efivarfs — the UEFI
//!   boot manager is the bootloader, `BootNext` the boot counter.
//! - [`gpt`]: the slots and the ESP, found by partition name; a new table.
//! - [`iso`], [`install`]: the installer's hybrid ISO and what it writes on
//!   an empty disk (G1.6c).
//! - [`ext4`]: `/config` grown to the rest of the disk (G1.6v, with
//!   [`gpt::grow_last`]).
//! - [`state`]: the trial across the reboot, configuration snapshots.
//! - [`upload`]: a package arriving over the network, read as a stream
//!   (G1.6e).
//! - [`system_disk`]: the system in RAM and the system disk going away
//!   (G1.6zn).
//! - [`ab`]: the operations (status, install, confirm, the boot-time
//!   decision corerouter-init takes).
//!
//! Pure Rust over files: tests and the virtual lab run the same code on a
//! directory that stands in for efivarfs, the ESP and the partitions.

pub mod ab;
pub mod biosboot;
#[cfg(unix)]
pub mod disks;
pub mod efi;
#[cfg(unix)]
pub mod ext4;
pub mod gpt;
#[cfg(unix)]
pub mod install;
pub mod iso;
pub mod package;
pub mod state;
pub mod system_disk;
pub mod upload;
pub mod verity;

use serde::{Deserialize, Serialize};

/// A root slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SlotId {
    A,
    B,
}

impl SlotId {
    pub const ALL: [SlotId; 2] = [SlotId::A, SlotId::B];

    pub fn as_str(self) -> &'static str {
        match self {
            SlotId::A => "a",
            SlotId::B => "b",
        }
    }

    pub fn parse(s: &str) -> Option<SlotId> {
        match s {
            "a" | "A" => Some(SlotId::A),
            "b" | "B" => Some(SlotId::B),
            _ => None,
        }
    }

    pub fn other(self) -> SlotId {
        match self {
            SlotId::A => SlotId::B,
            SlotId::B => SlotId::A,
        }
    }

    /// GPT partition name (`genimage.cfg`).
    pub fn partition(self) -> &'static str {
        match self {
            SlotId::A => "rootfs-a",
            SlotId::B => "rootfs-b",
        }
    }

    /// `Boot####` description: how CoreRouter recognises its entries.
    pub fn label(self) -> &'static str {
        match self {
            SlotId::A => "CoreRouter A",
            SlotId::B => "CoreRouter B",
        }
    }

    /// The slot's kernel on the ESP, relative to its root. Slot A's is the
    /// removable-media path, so a box whose NVRAM was cleared still boots
    /// slot A with the kernel's built-in command line.
    pub fn kernel_file(self) -> &'static str {
        match self {
            SlotId::A => "EFI/BOOT/BOOTX64.EFI",
            SlotId::B => "EFI/COREROUTER/B.EFI",
        }
    }

    /// The slot's signed header on the ESP.
    pub fn header_file(self) -> &'static str {
        match self {
            SlotId::A => "EFI/COREROUTER/A.HDR",
            SlotId::B => "EFI/COREROUTER/B.HDR",
        }
    }

    /// The kernel file as an EFI path (`\EFI\BOOT\BOOTX64.EFI`).
    pub fn efi_path(self) -> String {
        format!("\\{}", self.kernel_file().replace('/', "\\"))
    }
}

/// The kernel's built-in command line (`CONFIG_CMDLINE` in
/// `os/board/x86_64/linux.fragment`, checked equal by `cargo xtask os
/// check`). What a boot entry adds comes after it, and for the parameters
/// given twice the last one counts.
pub const BUILTIN_CMDLINE: &str = "console=tty0 console=ttyS0,115200 root=PARTUUID=3e1088b8-5b4b-4fbb-b756-a271f641d018 rootfstype=squashfs rootwait ro bonding.max_bonds=0 dummy.numdummies=0 init=/usr/sbin/corerouter-init panic=10 quiet";

/// G1.6zm: the ESP's partition GUID in `disk.img` (`partition-uuid` of
/// `efi` in `os/board/x86_64/genimage.cfg`). Every copy of the image has
/// it, so a boot entry written on one copy also "finds" the next image
/// written over it, with the verity hash of the old one in its command line
/// (a Lenovo notebook, 2026-11-11: `verity: metadata block 22096 is
/// corrupted`). The first boot of a copy gives its ESP a GUID of its own
/// ([`gpt::renew_guid`]) before the boot entries are written, and the
/// installer writes one: an entry from an earlier image then names a
/// partition that is not there, the firmware moves on to the next boot
/// option and to the removable-media path (`\EFI\BOOT\BOOTX64.EFI`), and
/// that boot writes the entries anew.
pub const IMAGE_ESP_GUID: &str = "4f9a520b-35f7-4633-a4bb-e9f871d1473c";

/// A random GUID (RFC 9562 §5.4, version 4), as text.
pub fn new_guid() -> Result<String, String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut b = [0u8; 16];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| "no random bytes from the kernel".to_string())?;
    if let Some(v) = b.get_mut(6) {
        *v = (*v & 0x0f) | 0x40;
    }
    if let Some(v) = b.get_mut(8) {
        *v = (*v & 0x3f) | 0x80;
    }
    let hex = |r: std::ops::Range<usize>| {
        b.get(r)
            .unwrap_or_default()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>()
    };
    Ok(format!(
        "{}-{}-{}-{}-{}",
        hex(0..4),
        hex(4..6),
        hex(6..8),
        hex(8..10),
        hex(10..16)
    ))
}

/// Platform parameters carried from the running command line to the slot
/// written next, when not already built in: a serial console on another
/// port or speed, the kernel's own address for a lab, the maintenance
/// shell, the consoles' colour (G1.6zg: a terminal that shows escapes as
/// text keeps `corerouter.color=off`). Like Flatcar's OEM `linux_append`:
/// set once for the box, kept across updates.
pub const CARRY_PREFIXES: &[&str] = &["console=", "ip=", "corerouter.shell=", "corerouter.color="];

/// The kernel parameter a rollback drill adds: an `init` that does not
/// exist, so the kernel panics before userspace (`panic=10` reboots).
pub const DRILL_INIT: &str = "init=/corerouter-rollback-drill";

/// Words of `cmdline`, keeping a quoted value (`dm-mod.create="a b"`) whole.
pub fn cmdline_words(cmdline: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in cmdline.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            c if c.is_ascii_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// The last value of `key=` on the command line. The boot entries write
/// `key="a b"`; GRUB hands the same word over as `"key=a b"`
/// (`grub-core/lib/cmdline.c`), G1.6g.
pub fn cmdline_value(cmdline: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    cmdline_words(cmdline).into_iter().rev().find_map(|w| {
        w.strip_prefix('"')
            .unwrap_or(&w)
            .strip_prefix(&prefix)
            .map(|v| v.trim_matches('"').to_owned())
    })
}

/// The words of the running line that the next slot written carries.
pub fn carried(running: &str) -> Vec<String> {
    let builtin = cmdline_words(BUILTIN_CMDLINE);
    cmdline_words(running)
        .into_iter()
        .filter(|w| CARRY_PREFIXES.iter().any(|p| w.starts_with(p)) && !builtin.contains(w))
        .collect()
}

/// What a slot's boot entry passes to its kernel (after the built-in line).
pub struct SlotCmdline<'a> {
    pub slot: SlotId,
    pub partuuid: &'a str,
    pub manifest: &'a package::Manifest,
    /// `system.tuning.boot` (G1.26h), already checked by the engine.
    pub tuning: &'a [(String, String)],
    /// The running command line, for [`CARRY_PREFIXES`].
    pub running: &'a str,
    pub drill: bool,
}

impl SlotCmdline<'_> {
    pub fn render(&self) -> String {
        let dev = format!("PARTUUID={}", self.partuuid);
        let r = &self.manifest.rootfs;
        let table = verity::table(&dev, r.data_blocks, &r.root_hash, &r.salt);
        let mut w = vec![
            "root=/dev/dm-0".to_owned(),
            format!("dm-mod.waitfor={dev}"),
            format!("dm-mod.create=\"vroot,,,ro,{table}\""),
        ];
        for (k, v) in self.tuning {
            w.push(format!("{k}={v}"));
        }
        for word in carried(self.running) {
            if !w.contains(&word) {
                w.push(word);
            }
        }
        w.push(format!("corerouter.slot={}", self.slot.as_str()));
        if self.drill {
            w.push(DRILL_INIT.to_owned());
        }
        // Last, so nothing above can turn the reboot-on-panic off.
        w.push("panic=10".to_owned());
        w.join(" ")
    }
}

/// Slot A's PARTUUID, the built-in `root=` (it stays the same on every install).
pub fn builtin_rootfs_a() -> Option<&'static str> {
    BUILTIN_CMDLINE
        .split_ascii_whitespace()
        .find_map(|w| w.strip_prefix("root=PARTUUID="))
}

/// The tuning parameters a slot command line carries (G1.26h: shown per
/// slot in Tuning › Boot), out of everything else on it.
pub fn tuning_of(cmdline: &str, keys: &[&str]) -> Vec<(String, String)> {
    cmdline_words(cmdline)
        .into_iter()
        .filter_map(|w| {
            let (k, v) = w.split_once('=')?;
            keys.contains(&k).then(|| (k.to_owned(), v.to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// G1.6g: the same parameter as a boot entry and as GRUB hand it over.
    #[test]
    fn cmdline_value_reads_both_quotings() {
        let t = "vroot,,,ro,0 16 verity 1";
        for line in [
            format!("BOOT_IMAGE=/x root=/dev/dm-0 dm-mod.create=\"{t}\" panic=10"),
            format!("BOOT_IMAGE=/x root=/dev/dm-0 \"dm-mod.create={t}\" panic=10"),
        ] {
            assert_eq!(cmdline_value(&line, "dm-mod.create").as_deref(), Some(t));
            assert_eq!(cmdline_value(&line, "panic").as_deref(), Some("10"));
            assert_eq!(cmdline_value(&line, "create"), None);
        }
    }

    #[test]
    fn words_keep_quotes() {
        let w = cmdline_words("a=1  dm-mod.create=\"x,,,ro,0 8 verity\" b");
        assert_eq!(w, ["a=1", "dm-mod.create=\"x,,,ro,0 8 verity\"", "b"]);
        assert_eq!(
            cmdline_value("root=x root=/dev/dm-0", "root").as_deref(),
            Some("/dev/dm-0")
        );
        assert_eq!(cmdline_value("a=1", "root"), None);
    }

    #[test]
    fn slot_cmdline() {
        let data = vec![1u8; 8192];
        let tree = verity::tree(&data, &[0], 1).unwrap();
        let m = package::tests::manifest(b"k", &[0; 12288], &tree);
        let c = SlotCmdline {
            slot: SlotId::B,
            partuuid: "u-b",
            manifest: &m,
            tuning: &[("isolcpus".into(), "2-3".into())],
            running: &format!("{BUILTIN_CMDLINE} ip=10.0.2.15::::eth0:off corerouter.shell=ttyS0 corerouter.color=off isolcpus=1 panic=0"),
            drill: false,
        }
        .render();
        assert!(c.starts_with("root=/dev/dm-0 dm-mod.waitfor=PARTUUID=u-b dm-mod.create=\"vroot,,,ro,0 16 verity 1 PARTUUID=u-b PARTUUID=u-b 4096 4096 2 2 sha256 "));
        assert!(c.ends_with("isolcpus=2-3 ip=10.0.2.15::::eth0:off corerouter.shell=ttyS0 corerouter.color=off corerouter.slot=b panic=10"));
        assert!(
            !c.contains("console="),
            "built-in consoles are not repeated"
        );
        assert_eq!(
            tuning_of(&c, &["isolcpus", "iommu"]),
            [("isolcpus".into(), "2-3".into())]
        );
    }
}

#[cfg(test)]
mod g16zm_tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    #[test]
    fn a_new_guid_is_version_4_and_new_each_time() {
        let a = super::new_guid().unwrap();
        let b = super::new_guid().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4", "{a}");
        assert!(matches!(&a[19..20], "8" | "9" | "a" | "b"), "{a}");
        assert!(crate::efi::guid_bytes(&a).is_some());
    }

    /// The constant is the image's: genimage writes the ESP with it.
    #[test]
    fn the_image_esp_guid_is_the_one_genimage_writes() {
        let cfg = include_str!("../../../os/board/x86_64/genimage.cfg");
        let efi = cfg
            .split("partition ")
            .find(|p| p.starts_with("efi "))
            .expect("the efi partition in genimage.cfg");
        assert!(
            efi.contains(&format!("partition-uuid = \"{}\"", super::IMAGE_ESP_GUID)),
            "{efi}"
        );
    }
}
