//! The GPT of the boot disk (UEFI 2.10 §5.3), read to find the slots by
//! partition name (`rootfs-a`, `rootfs-b`, `efi`, `config`) and to name the
//! ESP in the boot entries. Only the primary header is read; the router
//! never rewrites the table (the layout is fixed since G1.6a). [`build`]
//! writes one (G1.6c): the installer's target disk and the hybrid ISO.

use std::io::{Read, Seek, SeekFrom};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// 1-based entry number (what `HD()` and `/sys/class/block/*/partition` say).
    pub number: u32,
    pub type_guid: String,
    pub guid: String,
    pub first_lba: u64,
    pub last_lba: u64,
    pub name: String,
}

impl Entry {
    pub fn size_lba(&self) -> u64 {
        self.last_lba.saturating_sub(self.first_lba) + 1
    }
}

const MAX_ENTRIES: u32 = 256;

/// The partitions of `disk` (a block device or an image file) with logical
/// block size `lbs`.
pub fn read(disk: &mut (impl Read + Seek), lbs: u64) -> Result<Vec<Entry>, String> {
    let mut hdr = vec![0u8; 92];
    disk.seek(SeekFrom::Start(lbs)).map_err(|e| e.to_string())?;
    disk.read_exact(&mut hdr)
        .map_err(|e| format!("GPT header: {e}"))?;
    parse(&hdr, |lba, len| {
        let mut buf = vec![0u8; len];
        disk.seek(SeekFrom::Start(lba * lbs))
            .map_err(|e| e.to_string())?;
        disk.read_exact(&mut buf)
            .map_err(|e| format!("GPT entries: {e}"))?;
        Ok(buf)
    })
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

fn parse(
    hdr: &[u8],
    mut entries: impl FnMut(u64, usize) -> Result<Vec<u8>, String>,
) -> Result<Vec<Entry>, String> {
    if hdr.get(..8) != Some(b"EFI PART") {
        return Err("no GPT on the boot disk".into());
    }
    let bad = || "GPT header truncated".to_string();
    let lba = u64_at(hdr, 72).ok_or_else(bad)?;
    let count = u32_at(hdr, 80).ok_or_else(bad)?.min(MAX_ENTRIES);
    let size = u32_at(hdr, 84).ok_or_else(bad)?;
    if !(128..=4096).contains(&size) {
        return Err(format!("GPT entry size {size}"));
    }
    let table = entries(lba, (count * size) as usize)?;
    let mut out = Vec::new();
    for (i, e) in table.chunks_exact(size as usize).enumerate() {
        let type_guid = crate::efi::guid_text(e.get(0..16).unwrap_or(&[])).unwrap_or_default();
        if type_guid == "00000000-0000-0000-0000-000000000000" {
            continue;
        }
        let units: Vec<u16> = e
            .get(56..128)
            .unwrap_or(&[])
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|&u| u != 0)
            .collect();
        out.push(Entry {
            number: i as u32 + 1,
            type_guid,
            guid: crate::efi::guid_text(e.get(16..32).unwrap_or(&[])).unwrap_or_default(),
            first_lba: u64_at(e, 32).unwrap_or(0),
            last_lba: u64_at(e, 40).unwrap_or(0),
            name: String::from_utf16_lossy(&units),
        });
    }
    Ok(out)
}

/// A partition [`build`] writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPart {
    pub name: String,
    pub type_guid: String,
    pub guid: String,
    pub first_lba: u64,
    pub last_lba: u64,
    /// Attribute bits (bit 2: legacy BIOS bootable, what genimage's
    /// `bootable = true` sets).
    pub attrs: u64,
}

/// Entries in the table [`build`] writes (the usual 128 × 128 bytes).
pub const ENTRIES: u32 = 128;
const ENTRY_SIZE: u32 = 128;
/// "Revision 1.0" of the header (UEFI 2.10 §5.3.2).
const REVISION: u32 = 0x0001_0000;

/// A GPT for a disk of `disk_lbas` blocks of `lbs` bytes (UEFI 2.10 §5.3):
/// the protective MBR, the primary header and entries (written at byte 0)
/// and the backup entries and header (written at the returned byte
/// offset, the end of the disk). Partitions must fit the usable area and
/// not overlap.
pub fn build(
    disk_lbas: u64,
    lbs: u64,
    disk_guid: &str,
    parts: &[NewPart],
) -> Result<(Vec<u8>, u64, Vec<u8>), String> {
    if !(512..=4096).contains(&lbs) || !lbs.is_power_of_two() {
        return Err(format!("logical block size {lbs}"));
    }
    if parts.len() > ENTRIES as usize {
        return Err(format!("{} partitions", parts.len()));
    }
    let table = u64::from(ENTRIES * ENTRY_SIZE);
    let table_lbas = table.div_ceil(lbs);
    let first_usable = 2 + table_lbas;
    let last_usable = disk_lbas
        .checked_sub(2 + table_lbas)
        .filter(|l| *l > first_usable)
        .ok_or_else(|| format!("disk of {disk_lbas} blocks is too small for a GPT"))?;
    let mut sorted: Vec<&NewPart> = parts.iter().collect();
    sorted.sort_by_key(|p| p.first_lba);
    let mut prev_end = first_usable;
    for p in &sorted {
        if p.first_lba < prev_end || p.last_lba < p.first_lba || p.last_lba > last_usable {
            return Err(format!(
                "partition {} ({}..{}) is outside the usable area or overlaps",
                p.name, p.first_lba, p.last_lba
            ));
        }
        prev_end = p.last_lba + 1;
    }
    let mut entries = vec![0u8; table as usize];
    for (i, p) in parts.iter().enumerate() {
        let e = i * ENTRY_SIZE as usize;
        let t = crate::efi::guid_bytes(&p.type_guid)
            .ok_or_else(|| format!("bad type GUID '{}'", p.type_guid))?;
        let g = crate::efi::guid_bytes(&p.guid).ok_or_else(|| format!("bad GUID '{}'", p.guid))?;
        put(&mut entries, e, &t);
        put(&mut entries, e + 16, &g);
        put(&mut entries, e + 32, &p.first_lba.to_le_bytes());
        put(&mut entries, e + 40, &p.last_lba.to_le_bytes());
        put(&mut entries, e + 48, &p.attrs.to_le_bytes());
        let name: Vec<u16> = p.name.encode_utf16().collect();
        if name.len() > 36 {
            return Err(format!("partition name '{}' is longer than 36", p.name));
        }
        for (j, u) in name.iter().enumerate() {
            put(&mut entries, e + 56 + 2 * j, &u.to_le_bytes());
        }
    }
    let entries_crc = crc32fast::hash(&entries);
    let dg = crate::efi::guid_bytes(disk_guid).ok_or_else(|| format!("bad GUID '{disk_guid}'"))?;
    let last = disk_lbas - 1;
    let header = |my: u64, alt: u64, entries_lba: u64| {
        let mut h = vec![0u8; lbs as usize];
        put(&mut h, 0, b"EFI PART");
        put(&mut h, 8, &REVISION.to_le_bytes());
        put(&mut h, 12, &92u32.to_le_bytes());
        put(&mut h, 24, &my.to_le_bytes());
        put(&mut h, 32, &alt.to_le_bytes());
        put(&mut h, 40, &first_usable.to_le_bytes());
        put(&mut h, 48, &last_usable.to_le_bytes());
        put(&mut h, 56, &dg);
        put(&mut h, 72, &entries_lba.to_le_bytes());
        put(&mut h, 80, &ENTRIES.to_le_bytes());
        put(&mut h, 84, &ENTRY_SIZE.to_le_bytes());
        put(&mut h, 88, &entries_crc.to_le_bytes());
        let crc = crc32fast::hash(h.get(..92).unwrap_or(&[]));
        put(&mut h, 16, &crc.to_le_bytes());
        h
    };
    // Protective MBR (§5.2.3): one 0xEE partition over the whole disk.
    let mut primary = vec![0u8; lbs as usize];
    put(&mut primary, 446 + 1, &[0x00, 0x02, 0x00]);
    put(&mut primary, 446 + 4, &[0xEE]);
    put(&mut primary, 446 + 5, &[0xFF, 0xFF, 0xFF]);
    put(&mut primary, 446 + 8, &1u32.to_le_bytes());
    let size = u32::try_from(disk_lbas - 1).unwrap_or(u32::MAX);
    put(&mut primary, 446 + 12, &size.to_le_bytes());
    put(&mut primary, 510, &[0x55, 0xAA]);
    primary.extend_from_slice(&header(1, last, 2));
    primary.extend_from_slice(&entries);
    primary.resize((first_usable * lbs) as usize, 0);
    let backup_lba = last - table_lbas;
    let mut backup = entries;
    backup.resize((table_lbas * lbs) as usize, 0);
    backup.extend_from_slice(&header(last, 1, backup_lba));
    Ok((primary, backup_lba * lbs, backup))
}

/// `src` into `b` at `at` (the caller sized `b`; nothing past its end).
fn put(b: &mut [u8], at: usize, src: &[u8]) {
    if let Some(d) = b.get_mut(at..at + src.len()) {
        d.copy_from_slice(src);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A disk with two partitions, built by hand like genimage would.
    pub fn disk() -> Vec<u8> {
        let mut d = vec![0u8; 512 * 40];
        d[512..520].copy_from_slice(b"EFI PART");
        d[512 + 72..512 + 80].copy_from_slice(&2u64.to_le_bytes());
        d[512 + 80..512 + 84].copy_from_slice(&4u32.to_le_bytes());
        d[512 + 84..512 + 88].copy_from_slice(&128u32.to_le_bytes());
        let mut put = |i: usize, guid: &str, first: u64, last: u64, name: &str| {
            let e = 1024 + i * 128;
            d[e..e + 16].copy_from_slice(
                &crate::efi::guid_bytes("4f68bce3-e8cd-4db1-96e7-fbcaf984b709").unwrap(),
            );
            d[e + 16..e + 32].copy_from_slice(&crate::efi::guid_bytes(guid).unwrap());
            d[e + 32..e + 40].copy_from_slice(&first.to_le_bytes());
            d[e + 40..e + 48].copy_from_slice(&last.to_le_bytes());
            for (j, u) in name.encode_utf16().enumerate() {
                d[e + 56 + 2 * j..e + 58 + 2 * j].copy_from_slice(&u.to_le_bytes());
            }
        };
        put(
            0,
            "3e1088b8-5b4b-4fbb-b756-a271f641d018",
            10,
            19,
            "rootfs-a",
        );
        put(
            2,
            "868e1d1d-85bb-4c62-a083-f61aa7a5cda2",
            20,
            29,
            "rootfs-b",
        );
        d
    }

    #[test]
    fn reads_entries() {
        let parts = read(&mut std::io::Cursor::new(disk()), 512).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].name, "rootfs-a");
        assert_eq!(parts[1].number, 3);
        assert_eq!(parts[1].guid, "868e1d1d-85bb-4c62-a083-f61aa7a5cda2");
        assert_eq!(parts[1].size_lba(), 10);
        let mut bad = disk();
        bad[512] = b'X';
        assert!(read(&mut std::io::Cursor::new(bad), 512).is_err());
        assert!(read(&mut std::io::Cursor::new(vec![0u8; 600]), 512).is_err());
    }

    fn part(name: &str, first: u64, last: u64) -> NewPart {
        NewPart {
            name: name.into(),
            type_guid: "c12a7328-f81f-11d2-ba4b-00a0c93ec93b".into(),
            guid: "4f9a520b-35f7-4633-a4bb-e9f871d1473c".into(),
            first_lba: first,
            last_lba: last,
            attrs: 4,
        }
    }

    #[test]
    fn built_table_reads_back_both_copies() {
        for lbs in [512u64, 4096] {
            let lbas = (8 << 20) / lbs;
            let first = (1 << 20) / lbs;
            let parts = [
                part("efi", first, first + 10),
                part("config", first + 11, first + 20),
            ];
            let (primary, at, backup) =
                build(lbas, lbs, "39dfcaa2-2c8a-4912-acaa-6af0c68b5350", &parts).unwrap();
            let mut disk = vec![0u8; (lbas * lbs) as usize];
            disk[..primary.len()].copy_from_slice(&primary);
            disk[at as usize..at as usize + backup.len()].copy_from_slice(&backup);
            assert_eq!(
                at as usize + backup.len(),
                disk.len(),
                "backup header is the last block"
            );
            let got = read(&mut std::io::Cursor::new(&disk), lbs).unwrap();
            assert_eq!(got.len(), 2);
            assert_eq!(got[0].name, "efi");
            assert_eq!(got[1].first_lba, first + 11);
            assert_eq!(got[0].guid, "4f9a520b-35f7-4633-a4bb-e9f871d1473c");
            // CRCs (§5.3.2): header with its CRC field zeroed, entry array.
            let h = &disk[lbs as usize..lbs as usize + 92];
            let mut z = h.to_vec();
            z[16..20].fill(0);
            assert_eq!(crc32fast::hash(&z).to_le_bytes(), h[16..20]);
            let b = &disk[disk.len() - lbs as usize..];
            assert_eq!(&b[..8], b"EFI PART");
            assert_eq!(u64::from_le_bytes(b[24..32].try_into().unwrap()), lbas - 1);
            assert_eq!(&disk[510..512], &[0x55, 0xAA]);
            assert_eq!(disk[446 + 4], 0xEE);
        }
    }

    #[test]
    fn bad_layouts_are_refused() {
        let g = "39dfcaa2-2c8a-4912-acaa-6af0c68b5350";
        assert!(
            build(
                16384,
                512,
                g,
                &[part("a", 2048, 4000), part("b", 4000, 5000)]
            )
            .is_err()
        );
        assert!(
            build(16384, 512, g, &[part("a", 10, 400)]).is_err(),
            "inside the table"
        );
        assert!(
            build(16384, 512, g, &[part("a", 2048, 16380)]).is_err(),
            "over the backup"
        );
        assert!(build(40, 512, g, &[]).is_err(), "too small");
        assert!(build(16384, 520, g, &[]).is_err());
        assert!(build(16384, 512, "nope", &[]).is_err());
    }
}
