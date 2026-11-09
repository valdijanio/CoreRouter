//! `corerouter-image installer <images>` (G1.6c): after genimage, the
//! install index (layout read from `disk.img`, payload hashes), signed
//! with the image key, and the installer ISO around it.

use std::io::{Cursor, Write};
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::Instant;

use corerouter_sysupdate::biosboot::{self, Stage};
use corerouter_sysupdate::gpt;
use corerouter_sysupdate::install::{self, BiosBoot, Content};
use corerouter_sysupdate::iso;
use corerouter_sysupdate::package::{self, Header};

pub const ISO: &str = "corerouter-install.iso";
const BOOT: &str = "EFIBOOT.IMG";
/// G1.6g: the disk's BIOS boot stage ([`Stage`]), in the signed index.
const BIOS_STAGE: &str = "BIOSBOOT.IMG";

const README: &str = "CoreRouter installer\r\n\
\r\n\
Boot this image (CD or USB stick, UEFI or BIOS) and follow the console (VGA or\r\n\
serial 115200 8N1). It lists the disks, asks you to type the name of the\r\n\
one to erase, writes the A/B image, checks it and makes it bootable.\r\n\
\r\n\
COREROUTER.CRPKG is also the signed update package of this version\r\n\
(system.package.update). docs/os-image.md has the details.\r\n";

pub fn main(args: &[String]) -> Result<(), String> {
    let t = Instant::now();
    let images = Path::new(
        args.first()
            .ok_or("usage: corerouter-image installer <images dir>")?,
    );
    let key_path = std::env::var("CR_SEAL_KEY").map_err(|_| "$CR_SEAL_KEY not set")?;
    let key = crate::read(Path::new(&key_path))?;
    let epoch: u64 = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let pkg = crate::read(&images.join("corerouter.crpkg"))?;
    let header = Header::read(&mut pkg.as_slice())?;
    let esp_full = crate::read(&images.join("efi.vfat"))?;
    let config_full = crate::read(&images.join("config.ext4"))?;
    let boot = crate::read(&images.join("efiboot.vfat"))?;
    // G1.6za: the ISO kernel's modules, for the live image.
    let modules = crate::read(&images.join("live-modules.img"))?;
    let esp = install::trim(&esp_full);
    let config = install::trim(&config_full);
    // The ESP must carry the package's kernel as slot A's (what seal wrote).
    let kernel = crate::read(&images.join("bzImage"))?;
    if package::sha256_hex(&kernel) != header.manifest.kernel.sha256
        || !esp.windows(64).any(|w| Some(w) == kernel.get(..64))
    {
        return Err("efi.vfat does not hold the package's kernel".into());
    }
    let bios_dir = images.join("bios");
    let boot_img = crate::read(&bios_dir.join("boot.img"))?;
    let stage = biosboot::stage(
        &boot_img,
        &crate::read(&bios_dir.join("disk.core"))?,
        biosboot::CORE_LBA,
    )?;
    bios_on_disk(&images.join("disk.img"), &stage)?;
    let stage_file = stage.to_file();
    let slot_a_cfg = slot_cfg_at(
        esp,
        &crate::read(
            &images
                .join("efi-part")
                .join(biosboot::DIR)
                .join(biosboot::cfg_name(corerouter_sysupdate::SlotId::A)),
        )?,
    )?;
    let mut disk =
        std::fs::File::open(images.join("disk.img")).map_err(|e| format!("disk.img: {e}"))?;
    let mut index = install::index_of(
        &mut disk,
        &header.manifest,
        &[
            (install::PACKAGE, &pkg),
            ("ESP.IMG", esp),
            ("CONFIG.IMG", config),
            (BIOS_STAGE, &stage_file),
            (install::LIVE_MODULES, &modules),
        ],
        &[
            (
                "efi",
                Content::Image {
                    file: "ESP.IMG".into(),
                },
            ),
            ("rootfs-a", Content::Rootfs),
            (
                "config",
                Content::Filesystem {
                    file: "CONFIG.IMG".into(),
                },
            ),
        ],
    )?;
    index.bios = Some(BiosBoot {
        file: BIOS_STAGE.into(),
        slot_a_cfg,
    });
    let text = serde_json::to_vec_pretty(&index).map_err(|e| e.to_string())?;
    let sig = package::sign_detached(&text, &key)?;
    let parts: [(&str, &[u8]); 9] = [
        (install::INDEX, &text),
        (install::SIGNATURE, &sig),
        ("README.TXT", README.as_bytes()),
        (install::PACKAGE, &pkg),
        ("ESP.IMG", esp),
        ("CONFIG.IMG", config),
        (BIOS_STAGE, &stage_file),
        (install::LIVE_MODULES, &modules),
        (BOOT, &boot),
    ];
    let mut readers: Vec<Cursor<&[u8]>> = parts.iter().map(|(_, d)| Cursor::new(*d)).collect();
    let mut files: Vec<iso::File<'_>> = parts
        .iter()
        .zip(readers.iter_mut())
        .map(|((n, d), r)| iso::File {
            name: (*n).to_owned(),
            size: d.len() as u64,
            data: r,
        })
        .collect();
    let out_path = images.join(ISO);
    let f = std::fs::File::create(&out_path).map_err(|e| format!("{ISO}: {e}"))?;
    let mut w = std::io::BufWriter::with_capacity(1 << 20, f);
    let cd = crate::read(&bios_dir.join("cd.img"))?;
    let usb = crate::read(&bios_dir.join("usb.core"))?;
    let bios = iso::BiosIso {
        boot_img: &boot_img,
        cd: &cd,
        usb: &usb,
    };
    iso::write(&mut w, &mut files, BOOT, Some(&bios), epoch)?;
    w.flush().map_err(|e| e.to_string())?;
    let size = std::fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
    let _ = writeln!(
        std::io::stderr(),
        "   installer: {ISO} {:.1} MiB (boot image {:.1} MiB, ESP {:.1} MiB, live modules {:.1} MiB, config {} KiB of {} MiB), {} ms",
        size as f64 / 1048576.0,
        boot.len() as f64 / 1048576.0,
        esp.len() as f64 / 1048576.0,
        modules.len() as f64 / 1048576.0,
        config.len() / 1024,
        config_full.len() >> 20,
        t.elapsed().as_millis()
    );
    Ok(())
}

/// G1.6g: GRUB on genimage's `disk.img` (and so on the VM images made from it).
fn bios_on_disk(path: &Path, stage: &Stage) -> Result<(), String> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let mut r = &f;
    let parts = gpt::read(&mut r, 512)?;
    let first = parts.iter().map(|p| p.first_lba).min().unwrap_or(0);
    if biosboot::CORE_LBA + stage.core_blocks() > first {
        return Err(format!(
            "GRUB's core ({} blocks at {}) does not fit before the first partition (block {first})",
            stage.core_blocks(),
            biosboot::CORE_LBA
        ));
    }
    let mut block0 = [0u8; 512];
    f.read_exact_at(&mut block0, 0).map_err(|e| e.to_string())?;
    stage.set_code(&mut block0);
    f.write_all_at(&block0, 0)
        .and_then(|_| f.write_all_at(&stage.core, biosboot::CORE_LBA * 512))
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Where the ESP image holds slot A's GRUB configuration, whole and in one
/// piece: the installer rewrites those bytes in place.
fn slot_cfg_at(esp: &[u8], cfg: &[u8]) -> Result<u64, String> {
    let mut found = (0..esp.len())
        .step_by(512)
        .filter(|at| esp.get(*at..at + cfg.len()) == Some(cfg));
    match (found.next(), found.next()) {
        (Some(at), None) => Ok(at as u64),
        _ => Err("efi.vfat does not hold slot A's GRUB configuration in one piece".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_cfg_is_found_once_and_whole() {
        let cfg = vec![7u8; 4096];
        let mut esp = vec![0u8; 16384];
        esp[2048..2048 + 4096].fill(7);
        assert_eq!(slot_cfg_at(&esp, &cfg).unwrap(), 2048);
        // Cut in two clusters: the installer could not rewrite it in place.
        esp[3000] = 0;
        assert!(slot_cfg_at(&esp, &cfg).is_err());
        esp[3000] = 7;
        // Twice: which one?
        esp[8192..8192 + 4096].fill(7);
        assert!(slot_cfg_at(&esp, &cfg).is_err());
    }
}
