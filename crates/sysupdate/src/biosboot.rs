//! G1.6g: boot by legacy BIOS (`docs/os-image.md`, "Boot por BIOS"). The disk
//! keeps its GPT and its UEFI path untouched and also carries GRUB 2, so the
//! same disk boots either way:
//!
//! - `boot.img` in the first 440 bytes of block 0, next to the partition
//!   record of the protective MBR;
//! - GRUB's `core` in the free gap before the first partition, at
//!   [`CORE_LBA`], with no partition entry (the partition numbers the boot
//!   entries name stay as they are);
//! - on the ESP, under [`DIR`]: [`GRUB_CFG`], one configuration per slot and
//!   `grubenv` (one 512-byte block), which GRUB rewrites in place.
//!
//! What GRUB patches at `grub-install` time, from GRUB 2.12:
//! `util/setup.c:100-108`, `include/grub/i386/pc/boot.h:34-40`.

use crate::{SlotId, cmdline_words};

/// The boot code of a classic MBR: 440 bytes, before the disk signature.
pub const CODE: usize = 440;
/// Where `core` starts on a disk: 64 KiB in, past any GPT of 512-byte blocks.
pub const CORE_LBA: u64 = 128;
/// The first partition starts at 1 MiB: what `core` has between it and that.
pub const MAX_CORE: usize = (2048 - CORE_LBA as usize) * 512;
/// Directory of the ESP with GRUB's files.
pub const DIR: &str = "corerouter";
/// The configuration `core` looks for: `(,gpt1)/corerouter`, the first
/// partition of the disk the BIOS booted (not "the first disk").
pub const PREFIX: &str = "(,gpt1)/corerouter";
pub const ENV_FILE: &str = "grubenv";
pub const CFG_FILE: &str = "grub.cfg";
/// Size of a slot's configuration on the ESP. The installer rewrites slot A's
/// in place (it has no filesystem driver for a disk the kernel has not
/// rescanned), so the file has its final size from the build on. The kernel's
/// command line is at most 2048 bytes on x86: this always holds it.
pub const SLOT_CFG_SIZE: usize = 4096;
const ENV_SIZE: usize = 512;

const ENV_HEADER: &str = "# GRUB Environment Block\n";

/// `grub.cfg`. `primary` plays `BootOrder`, `next` plays `BootNext`: erased
/// before the kernel loads, so a trial gets one attempt. If erasing fails
/// (`save_env` refuses a file it cannot rewrite in place) there is no trial:
/// a kernel that panics would be retried forever.
pub const GRUB_CFG: &str = "\
if serial --unit=0 --speed=115200; then
  terminal_input serial console
  terminal_output serial console
fi
set timeout=0
load_env
set slot=a
set other=b
if [ \"$primary\" = \"b\" ]; then set slot=b; set other=a; fi
if [ -n \"$next\" ]; then
  set want=$next
  set next=
  if save_env next; then
    if [ \"$want\" = \"b\" ]; then set slot=b; set other=a; else set slot=a; set other=b; fi
  fi
fi
echo \"grub: booting slot $slot\"
source $prefix/$slot.cfg
echo \"grub: slot $slot did not load: trying slot $other\"
source $prefix/$other.cfg
echo \"grub: no slot loaded\"
";

/// A slot's configuration file, under [`DIR`].
pub fn cfg_name(slot: SlotId) -> String {
    format!("{}.cfg", slot.as_str())
}

/// The whole `grubenv`: one block, padded with `#` as `grub-editenv` does.
pub fn grubenv(primary: SlotId, next: Option<SlotId>) -> Vec<u8> {
    let mut e = format!(
        "{ENV_HEADER}primary={}\nnext={}\n",
        primary.as_str(),
        next.map_or("", SlotId::as_str)
    )
    .into_bytes();
    e.resize(ENV_SIZE, b'#');
    e
}

/// A slot's configuration: GRUB's script around the kernel's command line,
/// each word in single quotes (`$`, `;` and `#` mean nothing there), padded
/// with a comment to [`SLOT_CFG_SIZE`]. A word GRUB could not hand over intact
/// (it escapes `"` and `\` in a way the kernel does not read back, and nothing
/// can carry a control character) is refused.
pub fn slot_cfg(slot: SlotId, cmdline: &str) -> Result<Vec<u8>, String> {
    let mut args = String::new();
    for word in cmdline_words(cmdline) {
        // `dm-mod.create="a b"`: the quotes are the kernel's, GRUB adds its
        // own around the whole word (`grub-core/lib/cmdline.c`).
        let w = match word.split_once("=\"") {
            Some((k, v)) => format!("{k}={}", v.strip_suffix('"').unwrap_or(v)),
            None => word.clone(),
        };
        if w.chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\\' | '\''))
        {
            let shown: String = w.chars().take(32).collect();
            return Err(format!(
                "kernel parameter '{shown}': GRUB cannot pass quotes, backslashes or control characters"
            ));
        }
        args.push_str(" '");
        args.push_str(&w);
        args.push('\'');
    }
    let mut text = format!(
        "if linux /{}{args}; then\n  boot\nfi\n#",
        slot.kernel_file()
    )
    .into_bytes();
    if text.len() > SLOT_CFG_SIZE - 1 {
        return Err(format!(
            "the kernel command line does not fit {SLOT_CFG_SIZE} bytes"
        ));
    }
    text.resize(SLOT_CFG_SIZE - 1, b'#');
    text.push(b'\n');
    Ok(text)
}

/// What a disk's BIOS boot is: `boot.img`'s code and `core`, both patched for
/// where `core` sits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage {
    pub code: Vec<u8>,
    pub core: Vec<u8>,
}

/// `boot.img` and `core` for `core` at `lba` (of 512 bytes). Input from the
/// build, checked anyway: `core` must still be what `grub-mkimage` wrote (the
/// first block list of `diskboot.S` at its default start, with the length of
/// this image), or something else was handed in.
pub fn stage(boot_img: &[u8], core: &[u8], lba: u64) -> Result<Stage, String> {
    if boot_img.len() != 512 || boot_img.get(510..512) != Some(&[0x55, 0xAA][..]) {
        return Err("boot.img: not a 512-byte boot sector".into());
    }
    let sectors = core.len().div_ceil(512);
    let rest = u16::try_from(sectors.saturating_sub(1))
        .map_err(|_| format!("core of {} bytes is too large", core.len()))?;
    if core.len() < 512
        || core.get(0x1f4..0x1fc) != Some(&2u64.to_le_bytes()[..])
        || core.get(0x1fc..0x1fe) != Some(&rest.to_le_bytes()[..])
        || core.get(0x1fe..0x200) != Some(&0x820u16.to_le_bytes()[..])
    {
        return Err("core: not an unpatched GRUB i386-pc core image".into());
    }
    let mut c = core.to_vec();
    // boot.h: the first block list of diskboot, at the end of core's sector 0.
    put(&mut c, 0x1f4, &(lba + 1).to_le_bytes());
    put(&mut c, 0x1fc, &rest.to_le_bytes());
    let mut b = boot_img.to_vec();
    // GRUB_BOOT_MACHINE_KERNEL_SECTOR.
    put(&mut b, 0x5c, &lba.to_le_bytes());
    // GRUB_BOOT_MACHINE_DRIVE_CHECK: what `grub-install` does on a disk,
    // trust the drive number in DL (a USB stick is not always 0x80).
    put(&mut b, 0x66, &[0x90, 0x90]);
    b.truncate(CODE);
    Ok(Stage { code: b, core: c })
}

impl Stage {
    /// The file on the installer medium: `code` in a block, then `core`.
    pub fn to_file(&self) -> Vec<u8> {
        let mut f = self.code.clone();
        f.resize(512, 0);
        f.extend_from_slice(&self.core);
        f
    }

    pub fn from_file(f: &[u8]) -> Result<Self, String> {
        let (Some(code), Some(core)) = (f.get(..CODE), f.get(512..)) else {
            return Err("BIOS boot stage: too short".into());
        };
        if core.len() > MAX_CORE {
            return Err(format!("BIOS boot stage: core of {} bytes", core.len()));
        }
        Ok(Stage {
            code: code.to_vec(),
            core: core.to_vec(),
        })
    }

    /// Writes the boot code over block 0's, keeping the partition record.
    pub fn set_code(&self, block0: &mut [u8]) {
        put(block0, 0, &self.code);
    }

    /// How many 512-byte blocks `core` takes.
    pub fn core_blocks(&self) -> u64 {
        self.core.len().div_ceil(512) as u64
    }
}

/// Marks the protective partition active. UEFI 2.10 §5.2.3 says implementations
/// ignore the field, but EDK2 refused such a disk until 2021: only the
/// installer running on a BIOS does this, for the BIOSes that want an active
/// partition; the image and the ISO keep 0.
pub fn set_active(block0: &mut [u8]) {
    put(block0, 446, &[0x80]);
}

/// What is left of a disk's own boot stage when its block 0 is rebuilt (the
/// code and the active mark): G1.6v grows `/config` by rewriting the table.
pub fn keep_block0(old: &[u8], new: &mut [u8]) {
    if let Some(code) = old.get(..CODE) {
        put(new, 0, code);
    }
    if let Some(active) = old.get(446) {
        put(new, 446, &[*active]);
    }
}

fn put(b: &mut [u8], at: usize, src: &[u8]) {
    if let Some(d) = b.get_mut(at..at + src.len()) {
        d.copy_from_slice(src);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// What `grub-mkimage` and the GRUB build give, near enough for the patch.
    pub(crate) fn fake_boot_img() -> Vec<u8> {
        let mut b = vec![0xB8; 512];
        b[510] = 0x55;
        b[511] = 0xAA;
        b
    }

    pub(crate) fn fake_core(len: usize) -> Vec<u8> {
        let mut c = vec![0xC0; len];
        c[0x1f4..0x1fc].copy_from_slice(&2u64.to_le_bytes());
        c[0x1fc..0x1fe].copy_from_slice(&((len.div_ceil(512) - 1) as u16).to_le_bytes());
        c[0x1fe..0x200].copy_from_slice(&0x820u16.to_le_bytes());
        c
    }

    /// boot.h + setup.c, the offsets `grub-install` writes.
    #[test]
    fn patches_what_grub_install_patches() {
        let s = stage(&fake_boot_img(), &fake_core(149_497), CORE_LBA).unwrap();
        assert_eq!(s.code.len(), CODE);
        assert_eq!(&s.code[0x5c..0x64], &CORE_LBA.to_le_bytes());
        assert_eq!(&s.code[0x66..0x68], &[0x90, 0x90]);
        assert_eq!(&s.core[0x1f4..0x1fc], &(CORE_LBA + 1).to_le_bytes());
        // 149 497 bytes = 292 blocks, the first one loaded by boot.img.
        assert_eq!(&s.core[0x1fc..0x1fe], &291u16.to_le_bytes());
        assert_eq!(&s.core[0x1fe..0x200], &0x820u16.to_le_bytes());
        assert_eq!(s.core_blocks(), 292);
        assert_eq!(Stage::from_file(&s.to_file()).unwrap(), s);
    }

    #[test]
    fn refuses_what_is_not_grub() {
        assert!(stage(&[0; 512], &fake_core(1024), 128).is_err());
        assert!(stage(&fake_boot_img()[..511], &fake_core(1024), 128).is_err());
        assert!(stage(&fake_boot_img(), &[0; 100], 128).is_err());
        assert!(stage(&fake_boot_img(), &[0; 1024], 128).is_err());
        // Another length than its own, or already patched.
        assert!(stage(&fake_boot_img(), &fake_core(1024)[..512], 128).is_err());
        let once = stage(&fake_boot_img(), &fake_core(1024), 128).unwrap();
        assert!(stage(&fake_boot_img(), &once.core, 128).is_err());
        assert!(Stage::from_file(&[0; 100]).is_err());
        assert!(Stage::from_file(&vec![0; 512 + MAX_CORE + 1]).is_err());
    }

    #[test]
    fn block0_keeps_the_partition_record() {
        let s = stage(&fake_boot_img(), &fake_core(1024), 128).unwrap();
        let mut b0 = vec![0x11; 512];
        s.set_code(&mut b0);
        assert_eq!(&b0[..CODE], &s.code[..]);
        assert!(b0[CODE..].iter().all(|&x| x == 0x11));
        set_active(&mut b0);
        assert_eq!(b0[446], 0x80);
        assert_eq!(b0[447], 0x11);
        let mut new = vec![0u8; 512];
        keep_block0(&b0, &mut new);
        assert_eq!(&new[..CODE], &s.code[..]);
        assert_eq!(new[446], 0x80);
        assert_eq!(new[447], 0);
    }

    /// `load_env` reads exactly this (`grub-core/lib/envblk.c`).
    #[test]
    fn grubenv_is_one_block() {
        let e = grubenv(SlotId::B, Some(SlotId::A));
        assert_eq!(e.len(), 512);
        assert!(e.starts_with(b"# GRUB Environment Block\nprimary=b\nnext=a\n#"));
        assert_eq!(e[511], b'#');
        let e = grubenv(SlotId::A, None);
        assert!(e.starts_with(b"# GRUB Environment Block\nprimary=a\nnext=\n#"));
    }

    #[test]
    fn slot_cfg_quotes_every_word_and_has_one_size() {
        let cfg = slot_cfg(
            SlotId::B,
            "root=/dev/dm-0 dm-mod.create=\"vroot,,,ro,0 16 verity 1\" panic=10",
        )
        .unwrap();
        assert_eq!(cfg.len(), SLOT_CFG_SIZE);
        let text = String::from_utf8(cfg).unwrap();
        assert!(text.starts_with(
            "if linux /EFI/COREROUTER/B.EFI 'root=/dev/dm-0' 'dm-mod.create=vroot,,,ro,0 16 verity 1' 'panic=10'; then\n  boot\nfi\n#"
        ));
        assert!(text.ends_with("#\n"));
        assert_eq!(text.lines().count(), 4);
    }

    /// `system.tuning.boot` and the installer's `append` reach this file: a
    /// value must stay one kernel parameter, whatever it holds.
    #[test]
    fn hostile_parameters_stay_data() {
        for w in ["a=$(reboot)", "a=;reboot", "a=#x", "a=`x`", "a={b}", "a=&&"] {
            let text = String::from_utf8(slot_cfg(SlotId::A, w).unwrap()).unwrap();
            let line = text.lines().next().unwrap();
            assert!(line.contains(&format!(" '{w}'; then")), "{line}");
        }
        for w in [
            "a='; reboot; '",
            "a=\\",
            "a=x\"y",
            "a=\"x\"y\"",
            "a=\u{1b}[2J",
            "a=\u{7f}",
        ] {
            assert!(slot_cfg(SlotId::A, w).is_err(), "{w:?}");
        }
        // A newline ends the word: two parameters, still quoted apart.
        let text = String::from_utf8(slot_cfg(SlotId::A, "a=1\nboot").unwrap()).unwrap();
        assert!(text.starts_with("if linux /EFI/BOOT/BOOTX64.EFI 'a=1' 'boot'; then"));
        assert!(slot_cfg(SlotId::A, &"a".repeat(SLOT_CFG_SIZE)).is_err());
    }

    #[test]
    fn the_configuration_loads_the_slots_by_name() {
        assert!(GRUB_CFG.contains("source $prefix/$slot.cfg"));
        assert_eq!(cfg_name(SlotId::A), "a.cfg");
        assert_eq!(cfg_name(SlotId::B), "b.cfg");
    }
}
