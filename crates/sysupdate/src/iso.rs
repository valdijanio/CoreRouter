//! The installer's hybrid ISO (G1.6c, `docs/os-image.md`): one image that
//! boots from a CD (El Torito, UEFI "no emulation") and, written to a USB
//! stick, from its GPT (an EFI System partition over the same FAT image).
//!
//! - ISO 9660 (ECMA-119, 4th edition): primary volume descriptor, one root
//!   directory, files in contiguous extents (level 2 names, `NAME.EXT;1`).
//! - El Torito 1.0: boot record, catalog with a validation entry for the
//!   EFI platform (0xEF, UEFI 2.10 §13.3.2.1) and the default entry, a FAT
//!   image of at most 65 535 × 512 bytes (the 16-bit sector count).
//! - The system area (the first 32 KiB, ignored by ISO 9660) holds a
//!   protective MBR and the GPT, the backup at the end of the image, like
//!   the `-isohybrid-gpt-basdat`/`-append_partition` layout of xorriso.
//! - G1.6g, with [`BiosIso`]: the catalog's default entry is the BIOS's (GRUB
//!   for El Torito, no emulation, with its boot info table) and the EFI image
//!   moves to a section of its own (El Torito 1.0 §2.5); a BIOS reading the
//!   image as a disk finds GRUB's `boot.img` in the MBR, pointing at a second
//!   `core` file.
//!
//! [`read_dir`] is the installer's side: it finds the files by name on the
//! raw medium (CD or stick) without a filesystem driver.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::gpt;

pub const SECTOR: u64 = 2048;
/// What the installer looks for (`COREROUTER_INSTALL`, d-characters).
pub const VOLUME_ID: &str = "COREROUTER_INSTALL";
/// Largest El Torito image: the catalog counts 512-byte sectors in 16 bits.
pub const MAX_BOOT_IMAGE: u64 = 65535 * 512;
/// EFI System partition (UEFI 2.10 §5.3.3).
pub const ESP_TYPE: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
/// Largest root directory read back (the installer's has a handful of files).
const MAX_DIR: u64 = 64 << 10;
/// Longest file name (level 2: 30 characters plus `;1`).
const MAX_NAME: usize = 30;

/// A file of the image: its ISO name (`INSTALL.JSON`) and where its bytes
/// come from.
pub struct File<'a> {
    pub name: String,
    pub size: u64,
    pub data: &'a mut dyn Read,
}

/// G1.6g: what lets a BIOS boot the image. GRUB's El Torito image and its disk
/// `core` become files of the image (they need to know their own place).
pub struct BiosIso<'a> {
    /// `boot.img`.
    pub boot_img: &'a [u8],
    /// El Torito: `cdboot.img` + `core` (`grub-mkimage -O i386-pc-eltorito`).
    pub cd: &'a [u8],
    /// As a disk: `core` (`grub-mkimage -O i386-pc`).
    pub usb: &'a [u8],
}

/// Names of the [`BiosIso`] files in the image.
pub const BIOS_CD: &str = "BIOSCD.IMG";
pub const BIOS_USB: &str = "BIOSUSB.IMG";
/// What a BIOS loads of a no-emulation image: `cdboot.img` itself (4 × 512).
const CD_LOAD_SECTORS: u16 = 4;

/// El Torito's boot info table (the `-boot-info-table` of mkisofs): the
/// primary descriptor's place, the file's place and length, the 32-bit sum of
/// everything from byte 64 on. `cdboot.S` reads the length from it.
fn boot_info_table(cd: &mut [u8], lba: u32) -> Result<(), String> {
    let len = u32::try_from(cd.len()).map_err(|_| "El Torito image too large")?;
    let body = cd.get(64..).ok_or("El Torito image too short")?;
    // Whole words only, like mkisofs: an odd tail does not count.
    let sum = body
        .as_chunks::<4>()
        .0
        .iter()
        .fold(0u32, |a, w| a.wrapping_add(u32::from_le_bytes(*w)));
    put(cd, 8, &16u32.to_le_bytes());
    put(cd, 12, &lba.to_le_bytes());
    put(cd, 16, &len.to_le_bytes());
    put(cd, 20, &sum.to_le_bytes());
    Ok(())
}

/// Where a file landed (byte offset in the image, size).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub offset: u64,
    pub size: u64,
}

fn both16(v: u16) -> [u8; 4] {
    let (l, b) = (v.to_le_bytes(), v.to_be_bytes());
    [l[0], l[1], b[0], b[1]]
}

fn both32(v: u32) -> [u8; 8] {
    let (l, b) = (v.to_le_bytes(), v.to_be_bytes());
    [l[0], l[1], l[2], l[3], b[0], b[1], b[2], b[3]]
}

fn put(b: &mut [u8], at: usize, src: &[u8]) {
    if let Some(d) = b.get_mut(at..at + src.len()) {
        d.copy_from_slice(src);
    }
}

/// Unix seconds → (year, month, day, hour, minute, second), UTC.
fn civil(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let days = secs / 86400;
    let rem = secs % 86400;
    // Howard Hinnant's days_from_civil inverse (proleptic Gregorian).
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d, rem / 3600, rem % 3600 / 60, rem % 60)
}

/// The 17-byte date of a volume descriptor (§8.4.26.1).
fn vd_date(secs: u64) -> [u8; 17] {
    let (y, mo, d, h, mi, s) = civil(secs);
    let text = format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}00");
    let mut out = [0u8; 17];
    put(&mut out, 0, text.as_bytes());
    out
}

/// The 7-byte date of a directory record (§9.1.5).
fn dir_date(secs: u64) -> [u8; 7] {
    let (y, mo, d, h, mi, s) = civil(secs);
    [
        u8::try_from(y.saturating_sub(1900)).unwrap_or(u8::MAX),
        mo as u8,
        d as u8,
        h as u8,
        mi as u8,
        s as u8,
        0,
    ]
}

fn dir_record(id: &[u8], extent: u32, size: u32, dir: bool, date: [u8; 7]) -> Vec<u8> {
    let len = 33 + id.len() + usize::from(id.len().is_multiple_of(2));
    let mut r = vec![0u8; len];
    put(&mut r, 0, &[len as u8]);
    put(&mut r, 2, &both32(extent));
    put(&mut r, 10, &both32(size));
    put(&mut r, 18, &date);
    put(&mut r, 25, &[if dir { 2 } else { 0 }]);
    put(&mut r, 28, &both16(1));
    put(&mut r, 32, &[id.len() as u8]);
    put(&mut r, 33, id);
    r
}

/// A name the installer can find: `A-Z 0-9 _` and one dot, at most 30.
pub fn valid_name(name: &str) -> bool {
    name.len() <= MAX_NAME
        && !name.is_empty()
        && name.matches('.').count() <= 1
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
}

fn pad_to_sector(out: &mut dyn Write, written: u64) -> Result<u64, String> {
    let pad = written.next_multiple_of(SECTOR) - written;
    out.write_all(&vec![0u8; pad as usize])
        .map_err(|e| e.to_string())?;
    Ok(written + pad)
}

/// Writes the image: the files in the order given, the one named
/// `boot_image` (a FAT filesystem with `EFI/BOOT/BOOTX64.EFI`) also El
/// Torito's EFI entry and the GPT's EFI System partition; with `bios`, also
/// what a BIOS boots from a CD and from a stick. `epoch` dates everything
/// (reproducible). Returns each file's extent.
pub fn write(
    out: &mut dyn Write,
    files: &mut [File<'_>],
    boot_image: &str,
    bios: Option<&BiosIso<'_>>,
    epoch: u64,
) -> Result<BTreeMap<String, Extent>, String> {
    for f in files.iter() {
        if !valid_name(&f.name) {
            return Err(format!(
                "ISO file name '{}': A-Z, 0-9, _ and one dot",
                f.name
            ));
        }
    }
    let boot = files
        .iter()
        .find(|f| f.name == boot_image)
        .ok_or_else(|| format!("no file {boot_image} for the boot image"))?;
    if boot.size > MAX_BOOT_IMAGE || boot.size == 0 || !boot.size.is_multiple_of(512) {
        return Err(format!(
            "boot image of {} bytes: at most {MAX_BOOT_IMAGE}, a multiple of 512",
            boot.size
        ));
    }
    // Sectors: 0–15 system area, 16 PVD, 17 boot record, 18 terminator,
    // 19 catalog, 20/21 path tables, 22… root directory, then the files.
    let date = dir_date(epoch);
    // `lbas` holds the files' places, then the BIOS's two.
    let mut names: Vec<(String, usize, u64)> = files
        .iter()
        .enumerate()
        .map(|(i, f)| (format!("{};1", f.name), i, f.size))
        .collect();
    if let Some(b) = bios {
        for (i, (n, d)) in [(BIOS_CD, b.cd), (BIOS_USB, b.usb)].iter().enumerate() {
            if files.iter().any(|f| f.name == *n) {
                return Err(format!("{n} is a name of the BIOS boot"));
            }
            names.push((format!("{n};1"), files.len() + i, d.len() as u64));
        }
    }
    names.sort();
    let rec_len = |id_len: usize| 33 + id_len + usize::from(id_len.is_multiple_of(2));
    // Root directory size: records never cross a sector.
    let mut dir_bytes = 0u64;
    for n in [1usize, 1]
        .into_iter()
        .chain(names.iter().map(|(n, _, _)| n.len()))
    {
        let l = rec_len(n) as u64;
        if dir_bytes % SECTOR + l > SECTOR {
            dir_bytes = dir_bytes.next_multiple_of(SECTOR);
        }
        dir_bytes += l;
    }
    let dir_sectors = dir_bytes.div_ceil(SECTOR);
    let root_lba = 22u64;
    let mut next = root_lba + dir_sectors;
    let mut extents = BTreeMap::new();
    let mut lbas = Vec::with_capacity(files.len());
    for f in files.iter() {
        lbas.push(next);
        extents.insert(
            f.name.clone(),
            Extent {
                offset: next * SECTOR,
                size: f.size,
            },
        );
        next += f.size.div_ceil(SECTOR).max(1);
    }
    let mut bios_files: Vec<(u64, Vec<u8>)> = Vec::new();
    if let Some(b) = bios {
        for (n, d) in [(BIOS_CD, b.cd), (BIOS_USB, b.usb)] {
            lbas.push(next);
            extents.insert(
                n.to_owned(),
                Extent {
                    offset: next * SECTOR,
                    size: d.len() as u64,
                },
            );
            bios_files.push((next, d.to_vec()));
            next += (d.len() as u64).div_ceil(SECTOR).max(1);
        }
    }
    // Room for the backup GPT (entries + header, 512-byte blocks) at the end.
    let backup_lbas = (u64::from(gpt::ENTRIES) * 128).div_ceil(512) + 1;
    let total = next + (backup_lbas * 512).div_ceil(SECTOR);
    let total32 = u32::try_from(total).map_err(|_| "image too large for ISO 9660")?;
    let lba32 = |l: u64| u32::try_from(l).map_err(|_| "image too large for ISO 9660".to_string());
    let boot_lba = *extents
        .get(boot_image)
        .map(|e| e.offset / SECTOR)
        .as_ref()
        .ok_or("boot image")?;

    // System area: protective MBR + primary GPT; the backup goes at the end.
    let esp = gpt::NewPart {
        name: "EFI boot".into(),
        type_guid: ESP_TYPE.into(),
        guid: "c0e5b1ac-0a1e-4f11-9c0a-6e1a5c0b0071".into(),
        first_lba: boot_lba * 4,
        last_lba: boot_lba * 4 + boot.size / 512 - 1,
        attrs: 0,
    };
    let (primary, backup_at, backup) = gpt::build(
        total * 4,
        512,
        "c0e5b1ac-0a1e-4f11-9c0a-6e1a5c0b0070",
        &[esp],
    )?;
    if primary.len() as u64 > 16 * SECTOR {
        return Err("GPT does not fit the system area".into());
    }
    let mut head = vec![0u8; (root_lba * SECTOR) as usize];
    put(&mut head, 0, &primary);
    if let (Some(b), [(cd_lba, cd), (usb_lba, usb)]) = (bios, bios_files.as_mut_slice()) {
        boot_info_table(cd, lba32(*cd_lba)?)?;
        let s = crate::biosboot::stage(b.boot_img, usb, *usb_lba * 4)?;
        s.set_code(&mut head);
        *usb = s.core;
    }

    let mut pvd = vec![0u8; SECTOR as usize];
    put(&mut pvd, 0, b"\x01CD001\x01");
    let mut ids = [b' '; 32];
    put(&mut ids, 0, VOLUME_ID.as_bytes());
    put(&mut pvd, 8, &[b' '; 32]);
    put(&mut pvd, 40, &ids);
    put(&mut pvd, 80, &both32(total32));
    put(&mut pvd, 120, &both16(1));
    put(&mut pvd, 124, &both16(1));
    put(&mut pvd, 128, &both16(SECTOR as u16));
    put(&mut pvd, 132, &both32(10));
    put(&mut pvd, 140, &20u32.to_le_bytes());
    put(&mut pvd, 148, &21u32.to_be_bytes());
    let dir_size = lba32(dir_sectors * SECTOR)?;
    put(
        &mut pvd,
        156,
        &dir_record(&[0], lba32(root_lba)?, dir_size, true, date),
    );
    put(&mut pvd, 190, &[b' '; 623]);
    let mut app = [b' '; 128];
    put(&mut app, 0, b"COREROUTER-IMAGE");
    put(&mut pvd, 574, &app);
    put(&mut pvd, 702, &[b' '; 111]);
    let vd = vd_date(epoch);
    put(&mut pvd, 813, &vd);
    put(&mut pvd, 830, &vd);
    let mut unset = [b'0'; 17];
    put(&mut unset, 16, &[0]);
    put(&mut pvd, 847, &unset);
    put(&mut pvd, 864, &vd);
    put(&mut pvd, 881, &[1]);
    put(&mut head, (16 * SECTOR) as usize, &pvd);

    let mut br = vec![0u8; SECTOR as usize];
    put(&mut br, 0, b"\x00CD001\x01EL TORITO SPECIFICATION");
    put(&mut br, 71, &19u32.to_le_bytes());
    put(&mut head, (17 * SECTOR) as usize, &br);
    put(&mut head, (18 * SECTOR) as usize, b"\xffCD001\x01");

    // El Torito 1.0 §2: the validation entry names the default entry's
    // platform, and a section header the next ones'.
    let mut cat = vec![0u8; if bios.is_some() { 128 } else { 64 }];
    put(&mut cat, 0, &[1, if bios.is_some() { 0 } else { 0xEF }]);
    put(&mut cat, 4, b"CoreRouter");
    put(&mut cat, 30, &[0x55, 0xAA]);
    let sum = cat
        .get(..32)
        .unwrap_or(&[])
        .as_chunks::<2>()
        .0
        .iter()
        .fold(0u16, |a, w| a.wrapping_add(u16::from_le_bytes(*w)));
    put(&mut cat, 28, &(0u16.wrapping_sub(sum)).to_le_bytes());
    let efi_at = match bios_files.first() {
        Some((cd_lba, _)) => {
            put(&mut cat, 32, &[0x88, 0]);
            put(&mut cat, 38, &CD_LOAD_SECTORS.to_le_bytes());
            put(&mut cat, 40, &lba32(*cd_lba)?.to_le_bytes());
            // Final section header: platform EFI, one entry.
            put(&mut cat, 64, &[0x91, 0xEF, 1, 0]);
            96
        }
        None => 32,
    };
    put(&mut cat, efi_at, &[0x88, 0]);
    put(
        &mut cat,
        efi_at + 6,
        &((boot.size / 512) as u16).to_le_bytes(),
    );
    put(&mut cat, efi_at + 8, &lba32(boot_lba)?.to_le_bytes());
    put(&mut head, (19 * SECTOR) as usize, &cat);

    // Path tables: the root only (§9.4).
    let root32 = lba32(root_lba)?;
    let mut pl = [0u8; 10];
    put(&mut pl, 0, &[1, 0]);
    put(&mut pl, 2, &root32.to_le_bytes());
    put(&mut pl, 6, &1u16.to_le_bytes());
    put(&mut head, (20 * SECTOR) as usize, &pl);
    let mut pm = [0u8; 10];
    put(&mut pm, 0, &[1, 0]);
    put(&mut pm, 2, &root32.to_be_bytes());
    put(&mut pm, 6, &1u16.to_be_bytes());
    put(&mut head, (21 * SECTOR) as usize, &pm);
    out.write_all(&head).map_err(|e| e.to_string())?;

    let mut dir = Vec::with_capacity(dir_bytes as usize);
    let push = |dir: &mut Vec<u8>, r: Vec<u8>| {
        if dir.len() as u64 % SECTOR + r.len() as u64 > SECTOR {
            dir.resize((dir.len() as u64).next_multiple_of(SECTOR) as usize, 0);
        }
        dir.extend_from_slice(&r);
    };
    push(&mut dir, dir_record(&[0], root32, dir_size, true, date));
    push(&mut dir, dir_record(&[1], root32, dir_size, true, date));
    for (n, i, size) in &names {
        let Some(l) = lbas.get(*i) else {
            continue;
        };
        let size = u32::try_from(*size).map_err(|_| format!("{n}: larger than 4 GiB"))?;
        push(
            &mut dir,
            dir_record(n.as_bytes(), lba32(*l)?, size, false, date),
        );
    }
    dir.resize((dir_sectors * SECTOR) as usize, 0);
    out.write_all(&dir).map_err(|e| e.to_string())?;

    let mut at = (root_lba + dir_sectors) * SECTOR;
    for f in files.iter_mut() {
        let n = std::io::copy(&mut f.data.take(f.size), out).map_err(|e| e.to_string())?;
        if n != f.size {
            return Err(format!("{}: {n} bytes, expected {}", f.name, f.size));
        }
        at = pad_to_sector(out, at + n)?;
        if f.size == 0 {
            out.write_all(&[0u8; SECTOR as usize])
                .map_err(|e| e.to_string())?;
            at += SECTOR;
        }
    }
    for (_, d) in &bios_files {
        out.write_all(d).map_err(|e| e.to_string())?;
        at = pad_to_sector(out, at + d.len() as u64)?;
    }
    let end = total * SECTOR;
    let gap = backup_at
        .checked_sub(at)
        .ok_or("backup GPT overlaps the files")?;
    out.write_all(&vec![0u8; gap as usize])
        .map_err(|e| e.to_string())?;
    out.write_all(&backup).map_err(|e| e.to_string())?;
    if backup_at + backup.len() as u64 != end {
        return Err("image size mismatch".into());
    }
    Ok(extents)
}

/// Is this the installer medium? Reads the primary volume descriptor.
pub fn is_installer(dev: &mut (impl Read + Seek)) -> bool {
    let mut pvd = [0u8; 72];
    if dev.seek(SeekFrom::Start(16 * SECTOR)).is_err() || dev.read_exact(&mut pvd).is_err() {
        return false;
    }
    let id = pvd.get(40..72).unwrap_or(&[]);
    pvd.get(..7) == Some(b"\x01CD001\x01".as_slice())
        && id.get(..VOLUME_ID.len()) == Some(VOLUME_ID.as_bytes())
        && id
            .get(VOLUME_ID.len()..)
            .is_some_and(|r| r.iter().all(|&b| b == b' '))
}

fn u32_le(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The files of the root directory (name without `;1` → extent). Hostile
/// input: sizes are bounded, records that do not parse end the listing.
pub fn read_dir(dev: &mut (impl Read + Seek)) -> Result<BTreeMap<String, Extent>, String> {
    let mut pvd = vec![0u8; SECTOR as usize];
    dev.seek(SeekFrom::Start(16 * SECTOR))
        .and_then(|_| dev.read_exact(&mut pvd))
        .map_err(|e| format!("volume descriptor: {e}"))?;
    if pvd.get(..6) != Some(b"\x01CD001".as_slice()) {
        return Err("not an ISO 9660 volume".into());
    }
    let root = pvd.get(156..190).ok_or("root record")?;
    let lba = u64::from(u32_le(root, 2).ok_or("root record")?);
    let len = u64::from(u32_le(root, 10).ok_or("root record")?);
    if len > MAX_DIR {
        return Err(format!("root directory of {len} bytes"));
    }
    let mut dir = vec![0u8; len as usize];
    dev.seek(SeekFrom::Start(lba * SECTOR))
        .and_then(|_| dev.read_exact(&mut dir))
        .map_err(|e| format!("root directory: {e}"))?;
    let mut out = BTreeMap::new();
    let mut at = 0usize;
    while at < dir.len() {
        let rl = usize::from(dir.get(at).copied().unwrap_or(0));
        if rl == 0 {
            // The rest of this sector is padding.
            at = (at as u64 / SECTOR + 1).saturating_mul(SECTOR) as usize;
            continue;
        }
        let Some(r) = dir.get(at..at + rl) else {
            break;
        };
        let id_len = usize::from(r.get(32).copied().unwrap_or(0));
        let flags = r.get(25).copied().unwrap_or(0);
        if let (Some(id), Some(ext), Some(size)) =
            (r.get(33..33 + id_len), u32_le(r, 2), u32_le(r, 10))
            && flags & 2 == 0
        {
            let name = String::from_utf8_lossy(id);
            let name = name.strip_suffix(";1").unwrap_or(&name).to_owned();
            out.insert(
                name,
                Extent {
                    offset: u64::from(ext) * SECTOR,
                    size: u64::from(size),
                },
            );
        }
        at += rl;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn image(files: &[(&str, Vec<u8>)], boot: &str) -> (Vec<u8>, BTreeMap<String, Extent>) {
        let mut readers: Vec<Cursor<Vec<u8>>> =
            files.iter().map(|(_, d)| Cursor::new(d.clone())).collect();
        let mut fl: Vec<File<'_>> = files
            .iter()
            .zip(readers.iter_mut())
            .map(|((n, d), r)| File {
                name: (*n).into(),
                size: d.len() as u64,
                data: r,
            })
            .collect();
        let mut out = Vec::new();
        let ext = write(&mut out, &mut fl, boot, None, 1_800_000_000).unwrap();
        (out, ext)
    }

    #[test]
    fn writes_a_hybrid_image_the_installer_reads_back() {
        let boot = vec![0xEB; 64 * 1024];
        let (img, ext) = image(
            &[
                ("INSTALL.JSON", b"{}".to_vec()),
                ("EFIBOOT.IMG", boot.clone()),
                ("EMPTY.BIN", vec![]),
                ("COREROUTER.CRPKG", vec![7; 5000]),
            ],
            "EFIBOOT.IMG",
        );
        assert_eq!(img.len() as u64 % SECTOR, 0);
        assert!(is_installer(&mut Cursor::new(&img)));
        let dir = read_dir(&mut Cursor::new(&img)).unwrap();
        assert_eq!(dir, ext);
        let e = dir["COREROUTER.CRPKG"];
        assert_eq!(
            &img[e.offset as usize..(e.offset + e.size) as usize],
            &[7; 5000][..]
        );
        assert_eq!(dir["EMPTY.BIN"].size, 0);
        // El Torito: boot record → catalog → the FAT image.
        assert_eq!(
            &img[17 * 2048 + 7..17 * 2048 + 30],
            b"EL TORITO SPECIFICATION"
        );
        let cat = 19 * 2048;
        assert_eq!(img[cat + 1], 0xEF);
        let sum = img[cat..cat + 32].chunks(2).fold(0u16, |a, w| {
            a.wrapping_add(u16::from_le_bytes([w[0], w[1]]))
        });
        assert_eq!(sum, 0, "validation entry checksum");
        assert_eq!(img[cat + 32], 0x88);
        let count = u16::from_le_bytes([img[cat + 38], img[cat + 39]]);
        assert_eq!(u64::from(count) * 512, boot.len() as u64);
        let lba = u32::from_le_bytes(img[cat + 40..cat + 44].try_into().unwrap());
        assert_eq!(u64::from(lba) * SECTOR, dir["EFIBOOT.IMG"].offset);
        // As a disk (512-byte blocks): the GPT's ESP is the same FAT image.
        let parts = gpt::read(&mut Cursor::new(&img), 512).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].type_guid, ESP_TYPE);
        assert_eq!(parts[0].first_lba * 512, dir["EFIBOOT.IMG"].offset);
        assert_eq!(parts[0].size_lba() * 512, boot.len() as u64);
        let vs = u32::from_le_bytes(img[16 * 2048 + 80..16 * 2048 + 84].try_into().unwrap());
        assert_eq!(u64::from(vs) * SECTOR, img.len() as u64);
        assert_eq!(&img[img.len() - 512..img.len() - 504], b"EFI PART");
    }

    fn bios_image(cd_len: usize, usb_len: usize) -> (Vec<u8>, BTreeMap<String, Extent>) {
        use crate::biosboot::tests::{fake_boot_img, fake_core};
        let boot = vec![0xEB; 64 * 1024];
        let mut r = Cursor::new(boot.clone());
        let mut fl = [File {
            name: "EFIBOOT.IMG".into(),
            size: boot.len() as u64,
            data: &mut r,
        }];
        let cd: Vec<u8> = (0..cd_len).map(|i| i as u8).collect();
        let bios = BiosIso {
            boot_img: &fake_boot_img(),
            cd: &cd,
            usb: &fake_core(usb_len),
        };
        let mut out = Vec::new();
        let ext = write(&mut out, &mut fl, "EFIBOOT.IMG", Some(&bios), 1).unwrap();
        (out, ext)
    }

    /// G1.6g: the layout `xorriso -report_el_torito` showed for the prototype
    /// that booted in SeaBIOS and OVMF, CD and USB.
    #[test]
    fn a_bios_catalog_keeps_the_efi_entry_in_a_section() {
        let (img, ext) = bios_image(8192, 4096);
        assert_eq!(img.len() as u64 % SECTOR, 0);
        let dir = read_dir(&mut Cursor::new(&img)).unwrap();
        assert_eq!(dir, ext);
        let cat = 19 * 2048;
        // Validation entry: platform 0 (x86), checksum over the 32 bytes.
        assert_eq!(&img[cat..cat + 2], &[1, 0]);
        let sum = img[cat..cat + 32].chunks(2).fold(0u16, |a, w| {
            a.wrapping_add(u16::from_le_bytes([w[0], w[1]]))
        });
        assert_eq!(sum, 0);
        // Default entry: bootable, no emulation, 4 × 512 loaded, GRUB's file.
        assert_eq!(&img[cat + 32..cat + 34], &[0x88, 0]);
        assert_eq!(u16::from_le_bytes([img[cat + 38], img[cat + 39]]), 4);
        let at = |o: usize| u32::from_le_bytes(img[o..o + 4].try_into().unwrap());
        assert_eq!(u64::from(at(cat + 40)) * SECTOR, dir[BIOS_CD].offset);
        // The last section: EFI, one entry, the FAT image.
        assert_eq!(&img[cat + 64..cat + 68], &[0x91, 0xEF, 1, 0]);
        assert_eq!(&img[cat + 96..cat + 98], &[0x88, 0]);
        assert_eq!(u16::from_le_bytes([img[cat + 102], img[cat + 103]]), 128);
        assert_eq!(u64::from(at(cat + 104)) * SECTOR, dir["EFIBOOT.IMG"].offset);
    }

    #[test]
    fn the_boot_info_table_describes_the_file() {
        let (img, ext) = bios_image(8192, 4096);
        let e = ext[BIOS_CD];
        let f = &img[e.offset as usize..(e.offset + e.size) as usize];
        let u = |o: usize| u32::from_le_bytes(f[o..o + 4].try_into().unwrap());
        assert_eq!(u(8), 16, "primary volume descriptor");
        assert_eq!(u64::from(u(12)) * SECTOR, e.offset);
        assert_eq!(u64::from(u(16)), e.size);
        let sum = f[64..]
            .as_chunks::<4>()
            .0
            .iter()
            .fold(0u32, |a, w| a.wrapping_add(u32::from_le_bytes(*w)));
        assert_eq!(u(20), sum);
        // The rest of the header is the file's.
        assert_eq!(f[7], 7);
        assert_eq!(f[24], 24);
    }

    #[test]
    fn a_bios_reading_the_stick_finds_its_core() {
        let (img, ext) = bios_image(2048, 4096);
        let e = ext[BIOS_USB];
        let lba = e.offset / 512;
        assert_eq!(&img[0x5c..0x64], &lba.to_le_bytes(), "boot.img → core");
        assert_eq!(&img[0x66..0x68], &[0x90, 0x90]);
        let f = &img[e.offset as usize..(e.offset + e.size) as usize];
        assert_eq!(&f[0x1f4..0x1fc], &(lba + 1).to_le_bytes());
        assert_eq!(&f[0x1fc..0x1fe], &7u16.to_le_bytes());
        // Still a protective MBR and a GPT over the same FAT image.
        assert_eq!(img[446], 0, "not marked active");
        assert_eq!(img[446 + 4], 0xEE);
        assert_eq!(&img[510..512], &[0x55, 0xAA]);
        let parts = gpt::read(&mut Cursor::new(&img), 512).unwrap();
        assert_eq!(parts[0].first_lba * 512, ext["EFIBOOT.IMG"].offset);
        assert_eq!(&img[img.len() - 512..img.len() - 504], b"EFI PART");
        // The header leaves nothing between the table and the partition free.
        let first_usable = u64::from_le_bytes(img[512 + 40..512 + 48].try_into().unwrap());
        assert_eq!(first_usable, parts[0].first_lba);
    }

    #[test]
    fn bios_names_are_reserved() {
        use crate::biosboot::tests::{fake_boot_img, fake_core};
        let mut d = Cursor::new(vec![0u8; 1024]);
        let mut f = [File {
            name: BIOS_CD.into(),
            size: 1024,
            data: &mut d,
        }];
        let bios = BiosIso {
            boot_img: &fake_boot_img(),
            cd: &[0; 2048],
            usb: &fake_core(1024),
        };
        let mut out = Vec::new();
        assert!(write(&mut out, &mut f, BIOS_CD, Some(&bios), 0).is_err());
    }

    #[test]
    fn same_input_same_image() {
        let f = [("A.BIN", vec![1; 3000]), ("BOOT.IMG", vec![2; 1024])];
        assert_eq!(image(&f, "BOOT.IMG").0, image(&f, "BOOT.IMG").0);
    }

    #[test]
    fn refuses_bad_names_and_boot_images() {
        let mut d = Cursor::new(vec![0u8; 1024]);
        let mut out = Vec::new();
        for (name, size, boot) in [
            ("lower.img", 1024, "lower.img"),
            ("A.B.C", 1024, "A.B.C"),
            ("BOOT.IMG", 1000, "BOOT.IMG"),
            ("BOOT.IMG", 1024, "OTHER.IMG"),
        ] {
            let mut f = [File {
                name: name.into(),
                size,
                data: &mut d,
            }];
            assert!(write(&mut out, &mut f, boot, None, 0).is_err(), "{name}");
        }
        assert!(!valid_name(&"A".repeat(31)));
    }

    #[test]
    fn hostile_media_never_panic() {
        assert!(!is_installer(&mut Cursor::new(vec![0u8; 10])));
        assert!(read_dir(&mut Cursor::new(vec![0u8; 100])).is_err());
        let (img, _) = image(&[("BOOT.IMG", vec![2; 1024])], "BOOT.IMG");
        for i in (16 * 2048..23 * 2048).step_by(7) {
            let mut bad = img.clone();
            bad[i] ^= 0xFF;
            let _ = read_dir(&mut Cursor::new(&bad));
            bad.truncate(i);
            let _ = read_dir(&mut Cursor::new(&bad));
        }
    }

    #[test]
    fn dates() {
        assert_eq!(civil(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil(1_800_000_000), (2027, 1, 15, 8, 0, 0));
        assert_eq!(&vd_date(951_782_400)[..16], b"2000022900000000");
    }
}
