//! The GPT of the boot disk (UEFI 2.10 §5.3), read to find the slots by
//! partition name (`rootfs-a`, `rootfs-b`, `efi`, `config`) and to name the
//! ESP in the boot entries. Only the primary header is read; the image never
//! rewrites the table (the layout is fixed since G1.6a).

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
}
