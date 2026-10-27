//! `corerouter-image installer <images>` (G1.6c): after genimage, the
//! install index (layout read from `disk.img`, payload hashes), signed
//! with the image key, and the installer ISO around it.

use std::io::{Cursor, Write};
use std::path::Path;
use std::time::Instant;

use corerouter_sysupdate::install::{self, Content};
use corerouter_sysupdate::iso;
use corerouter_sysupdate::package::{self, Header};

pub const ISO: &str = "corerouter-install.iso";
const BOOT: &str = "EFIBOOT.IMG";

const README: &str = "CoreRouter installer\r\n\
\r\n\
Boot this image (CD or USB stick, UEFI) and follow the console (VGA or\r\n\
serial 115200 8N1). It lists the disks, asks you to type the name of the\r\n\
one to erase, writes the A/B image, checks it and creates the boot entry.\r\n\
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
    let esp = install::trim(&esp_full);
    let config = install::trim(&config_full);
    // The ESP must carry the package's kernel as slot A's (what seal wrote).
    let kernel = crate::read(&images.join("bzImage"))?;
    if package::sha256_hex(&kernel) != header.manifest.kernel.sha256
        || !esp.windows(64).any(|w| Some(w) == kernel.get(..64))
    {
        return Err("efi.vfat does not hold the package's kernel".into());
    }
    let mut disk =
        std::fs::File::open(images.join("disk.img")).map_err(|e| format!("disk.img: {e}"))?;
    let index = install::index_of(
        &mut disk,
        &header.manifest,
        &[
            (install::PACKAGE, &pkg),
            ("ESP.IMG", esp),
            ("CONFIG.IMG", config),
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
    let text = serde_json::to_vec_pretty(&index).map_err(|e| e.to_string())?;
    let sig = package::sign_detached(&text, &key)?;
    let parts: [(&str, &[u8]); 7] = [
        (install::INDEX, &text),
        (install::SIGNATURE, &sig),
        ("README.TXT", README.as_bytes()),
        (install::PACKAGE, &pkg),
        ("ESP.IMG", esp),
        ("CONFIG.IMG", config),
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
    iso::write(&mut w, &mut files, BOOT, epoch)?;
    w.flush().map_err(|e| e.to_string())?;
    let size = std::fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
    let _ = writeln!(
        std::io::stderr(),
        "   installer: {ISO} {:.1} MiB (boot image {:.1} MiB, ESP {:.1} MiB, config {} KiB of {} MiB), {} ms",
        size as f64 / 1048576.0,
        boot.len() as f64 / 1048576.0,
        esp.len() as f64 / 1048576.0,
        config.len() / 1024,
        config_full.len() >> 20,
        t.elapsed().as_millis()
    );
    Ok(())
}
