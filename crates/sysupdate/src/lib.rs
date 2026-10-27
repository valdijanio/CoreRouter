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
//! - [`state`]: the trial across the reboot, configuration snapshots.
//! - [`ab`]: the operations (status, install, confirm, the boot-time
//!   decision corerouter-init takes).
//!
//! Pure Rust over files: tests and the virtual lab run the same code on a
//! directory that stands in for efivarfs, the ESP and the partitions.

pub mod ab;
pub mod efi;
pub mod gpt;
#[cfg(unix)]
pub mod install;
pub mod iso;
pub mod package;
pub mod state;
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
pub const BUILTIN_CMDLINE: &str = "console=tty0 console=ttyS0,115200 root=PARTUUID=3e1088b8-5b4b-4fbb-b756-a271f641d018 rootfstype=squashfs rootwait ro init=/usr/sbin/corerouter-init panic=10 quiet";

/// Platform parameters carried from the running command line to the slot
/// written next, when not already built in: a serial console on another
/// port or speed, the kernel's own address for a lab, the maintenance
/// shell. Like Flatcar's OEM `linux_append`: set once for the box, kept
/// across updates.
pub const CARRY_PREFIXES: &[&str] = &["console=", "ip=", "corerouter.shell="];

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

/// The last value of `key=` on the command line.
pub fn cmdline_value(cmdline: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    cmdline_words(cmdline).into_iter().rev().find_map(|w| {
        w.strip_prefix(&prefix)
            .map(|v| v.trim_matches('"').to_owned())
    })
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
        let builtin = cmdline_words(BUILTIN_CMDLINE);
        for word in cmdline_words(self.running) {
            if CARRY_PREFIXES.iter().any(|p| word.starts_with(p))
                && !builtin.contains(&word)
                && !w.contains(&word)
            {
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
            running: &format!("{BUILTIN_CMDLINE} ip=10.0.2.15::::eth0:off corerouter.shell=ttyS0 isolcpus=1 panic=0"),
            drill: false,
        }
        .render();
        assert!(c.starts_with("root=/dev/dm-0 dm-mod.waitfor=PARTUUID=u-b dm-mod.create=\"vroot,,,ro,0 16 verity 1 PARTUUID=u-b PARTUUID=u-b 4096 4096 2 2 sha256 "));
        assert!(c.ends_with("isolcpus=2-3 ip=10.0.2.15::::eth0:off corerouter.shell=ttyS0 corerouter.slot=b panic=10"));
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
