//! UEFI boot variables (UEFI 2.10 §3.1 "Firmware Boot Manager", §3.1.3
//! `EFI_LOAD_OPTION`, §10.3 device paths) and the store they live in.
//!
//! The firmware's boot manager is the A/B bootloader:
//!
//! - one `Boot####` per slot, its file path the slot's kernel (an EFI stub)
//!   on the ESP and its optional data the kernel command line (UCS-2, read
//!   by the stub as `LoadOptions`);
//! - `BootOrder` lists the confirmed slot first and the other second (the
//!   firmware tries the next entry when one does not load);
//! - `BootNext` is the trial: the boot manager boots it **once** and
//!   deletes it (§3.1.2), so any failure of the trial — panic, hang ended by
//!   a reset, power cut — boots `BootOrder` again: a boot counter of one.
//!
//! On Linux the store is efivarfs (`docs.kernel.org`
//! filesystems/efivarfs.rst): one file per variable, 4 bytes of attributes
//! then the data, written in one `write`. `Boot*`, `BootOrder` and
//! `BootNext` are among the variables the kernel validates and lets be
//! changed without `chattr -i`.

use std::io::Write;
use std::path::{Path, PathBuf};

pub const GLOBAL: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const NON_VOLATILE: u32 = 0x1;
const BOOTSERVICE: u32 = 0x2;
const RUNTIME: u32 = 0x4;
const ATTRS: u32 = NON_VOLATILE | BOOTSERVICE | RUNTIME;
const LOAD_OPTION_ACTIVE: u32 = 0x1;
/// Longest variable read back (a load option with a 2 KiB command line is
/// ~4.3 KiB in UCS-2; firmware stores rarely allow more than 32 KiB).
const MAX_VAR: u64 = 64 << 10;

/// Where the variables are: efivarfs, or a plain directory with the same
/// file format (tests, the virtual lab).
#[derive(Debug, Clone)]
pub struct Vars {
    dir: PathBuf,
    /// efivarfs: overwrite in place (it has no truncate); a directory:
    /// replace the file.
    efivarfs: bool,
}

impl Vars {
    pub fn efivarfs(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            efivarfs: true,
        }
    }

    pub fn directory(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            efivarfs: false,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}-{GLOBAL}"))
    }

    pub fn get(&self, name: &str) -> std::io::Result<Option<Vec<u8>>> {
        use std::io::Read;
        let f = match std::fs::File::open(self.path(name)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut buf = Vec::new();
        f.take(MAX_VAR).read_to_end(&mut buf)?;
        Ok(Some(buf.get(4..).unwrap_or(&[]).to_vec()))
    }

    pub fn set(&self, name: &str, data: &[u8]) -> std::io::Result<()> {
        let mut buf = Vec::with_capacity(4 + data.len());
        buf.extend_from_slice(&ATTRS.to_le_bytes());
        buf.extend_from_slice(data);
        let path = self.path(name);
        if !self.efivarfs {
            let _ = std::fs::remove_file(&path);
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)?;
        // efivarfs takes the variable from a single write.
        let n = f.write(&buf)?;
        if n != buf.len() {
            return Err(std::io::Error::other(format!(
                "{name}: short write ({n} of {})",
                buf.len()
            )));
        }
        Ok(())
    }

    pub fn remove(&self, name: &str) -> std::io::Result<()> {
        match std::fs::remove_file(self.path(name)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    /// The numbers of every `Boot####` present.
    pub fn boot_numbers(&self) -> Vec<u16> {
        let suffix = format!("-{GLOBAL}");
        let mut out: Vec<u16> = std::fs::read_dir(&self.dir)
            .map(|d| {
                d.flatten()
                    .filter_map(|e| {
                        let n = e.file_name().into_string().ok()?;
                        let hex = n.strip_suffix(&suffix)?.strip_prefix("Boot")?;
                        (hex.len() == 4).then_some(())?;
                        u16::from_str_radix(hex, 16).ok()
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.sort_unstable();
        out
    }

    pub fn u16_list(&self, name: &str) -> std::io::Result<Vec<u16>> {
        Ok(self
            .get(name)?
            .unwrap_or_default()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect())
    }

    pub fn set_u16_list(&self, name: &str, list: &[u16]) -> std::io::Result<()> {
        let data: Vec<u8> = list.iter().flat_map(|n| n.to_le_bytes()).collect();
        self.set(name, &data)
    }

    pub fn boot_order(&self) -> std::io::Result<Vec<u16>> {
        self.u16_list("BootOrder")
    }

    pub fn boot_current(&self) -> Option<u16> {
        self.u16_list("BootCurrent").ok()?.first().copied()
    }

    pub fn boot_next(&self) -> Option<u16> {
        self.u16_list("BootNext").ok()?.first().copied()
    }

    pub fn load_option(&self, number: u16) -> Option<LoadOption> {
        LoadOption::decode(&self.get(&boot_name(number)).ok()??)
    }
}

pub fn boot_name(number: u16) -> String {
    format!("Boot{number:04X}")
}

/// The ESP partition, as the device path names it (`HD(…)`, §10.3.5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// 1-based GPT entry number.
    pub number: u32,
    pub start_lba: u64,
    pub size_lba: u64,
    /// Unique partition GUID, as text.
    pub guid: String,
}

/// An `EFI_LOAD_OPTION`, the parts CoreRouter writes and reads back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadOption {
    pub active: bool,
    pub description: String,
    /// `None` when the device path is not `HD(…)/File(…)`.
    pub partition: Option<Partition>,
    /// `\EFI\COREROUTER\A.EFI`.
    pub file: Option<String>,
    /// The kernel command line (`LoadOptions`), from UCS-2.
    pub cmdline: String,
}

fn ucs2(s: &str, nul: bool) -> Vec<u8> {
    let mut out: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    if nul {
        out.extend_from_slice(&[0, 0]);
    }
    out
}

fn from_ucs2(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// GUID text → the on-disk byte order (first three fields little-endian).
pub fn guid_bytes(s: &str) -> Option<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || s.len() != 36 {
        return None;
    }
    let raw = crate::verity::unhex(&hex)?;
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        let src = match i {
            0..=3 => 3 - i,
            4 | 5 => 9 - i,
            6 | 7 => 13 - i,
            _ => i,
        };
        *o = *raw.get(src)?;
    }
    Some(out)
}

pub fn guid_text(b: &[u8]) -> Option<String> {
    if b.len() != 16 {
        return None;
    }
    let mut raw = [0u8; 16];
    for (i, r) in raw.iter_mut().enumerate() {
        let src = match i {
            0..=3 => 3 - i,
            4 | 5 => 9 - i,
            6 | 7 => 13 - i,
            _ => i,
        };
        *r = b.get(src).copied().unwrap_or(0);
    }
    let h = crate::verity::hex(&raw);
    Some(format!(
        "{}-{}-{}-{}-{}",
        h.get(0..8)?,
        h.get(8..12)?,
        h.get(12..16)?,
        h.get(16..20)?,
        h.get(20..32)?
    ))
}

impl LoadOption {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let part = self
            .partition
            .as_ref()
            .ok_or("load option without a partition")?;
        let file = self.file.as_deref().ok_or("load option without a file")?;
        let sig = guid_bytes(&part.guid).ok_or_else(|| format!("bad GUID '{}'", part.guid))?;
        let mut dp = Vec::new();
        // HD(): media device path, hard drive, 42 bytes.
        dp.extend_from_slice(&[0x04, 0x01, 42, 0]);
        dp.extend_from_slice(&part.number.to_le_bytes());
        dp.extend_from_slice(&part.start_lba.to_le_bytes());
        dp.extend_from_slice(&part.size_lba.to_le_bytes());
        dp.extend_from_slice(&sig);
        dp.extend_from_slice(&[0x02, 0x02]); // GPT, GUID signature
        // File(): media device path, file path.
        let path = ucs2(file, true);
        let len = u16::try_from(4 + path.len()).map_err(|_| "file path too long")?;
        dp.extend_from_slice(&[0x04, 0x04]);
        dp.extend_from_slice(&len.to_le_bytes());
        dp.extend_from_slice(&path);
        dp.extend_from_slice(&[0x7f, 0xff, 4, 0]); // end of the device path
        let mut out = Vec::new();
        let attrs = if self.active { LOAD_OPTION_ACTIVE } else { 0 };
        out.extend_from_slice(&attrs.to_le_bytes());
        out.extend_from_slice(
            &u16::try_from(dp.len())
                .map_err(|_| "device path too long")?
                .to_le_bytes(),
        );
        out.extend_from_slice(&ucs2(&self.description, true));
        out.extend_from_slice(&dp);
        out.extend_from_slice(&ucs2(&self.cmdline, false));
        Ok(out)
    }

    /// Any `Boot####` (also the firmware's own); `None` when malformed.
    pub fn decode(b: &[u8]) -> Option<Self> {
        let attrs = u32::from_le_bytes(b.get(0..4)?.try_into().ok()?);
        let dp_len = usize::from(u16::from_le_bytes(b.get(4..6)?.try_into().ok()?));
        let rest = b.get(6..)?;
        let desc_end = rest.as_chunks::<2>().0.iter().position(|c| c == &[0, 0])? * 2;
        let description = from_ucs2(rest.get(..desc_end)?);
        let dp = rest.get(desc_end + 2..desc_end + 2 + dp_len)?;
        let optional = rest.get(desc_end + 2 + dp_len..)?;
        let mut partition = None;
        let mut file = None;
        let mut at = 0usize;
        while let Some(node) = dp.get(at..at + 4) {
            let (t, st) = (node.first().copied()?, node.get(1).copied()?);
            let len = usize::from(u16::from_le_bytes(node.get(2..4)?.try_into().ok()?));
            if len < 4 {
                return None;
            }
            let body = dp.get(at + 4..at + len)?;
            match (t, st) {
                (0x7f, 0xff) => break,
                (0x04, 0x01) if body.len() >= 38 => {
                    partition = Some(Partition {
                        number: u32::from_le_bytes(body.get(0..4)?.try_into().ok()?),
                        start_lba: u64::from_le_bytes(body.get(4..12)?.try_into().ok()?),
                        size_lba: u64::from_le_bytes(body.get(12..20)?.try_into().ok()?),
                        guid: guid_text(body.get(20..36)?)?,
                    });
                }
                (0x04, 0x04) => file = Some(from_ucs2(body)),
                _ => {}
            }
            at += len;
        }
        Some(Self {
            active: attrs & LOAD_OPTION_ACTIVE != 0,
            description,
            partition,
            file,
            cmdline: from_ucs2(optional),
        })
    }
}

/// Is `dir` an efivarfs this process can use (UEFI boot, mounted)?
pub fn available(dir: &Path) -> bool {
    dir.join(format!("BootOrder-{GLOBAL}")).exists()
        || dir.join(format!("BootCurrent-{GLOBAL}")).exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_round_trip() {
        let g = "4f9a520b-35f7-4633-a4bb-e9f871d1473c";
        let b = guid_bytes(g).unwrap();
        assert_eq!(&b[..4], &[0x0b, 0x52, 0x9a, 0x4f]);
        assert_eq!(&b[8..10], &[0xa4, 0xbb]);
        assert_eq!(guid_text(&b).unwrap(), g);
        assert_eq!(guid_bytes("nope"), None);
    }

    #[test]
    fn load_option_round_trip() {
        let o = LoadOption {
            active: true,
            description: "CoreRouter B".into(),
            partition: Some(Partition {
                number: 1,
                start_lba: 2048,
                size_lba: 65536,
                guid: "4f9a520b-35f7-4633-a4bb-e9f871d1473c".into(),
            }),
            file: Some("\\EFI\\COREROUTER\\B.EFI".into()),
            cmdline: "root=/dev/dm-0 corerouter.slot=b".into(),
        };
        let bytes = o.encode().unwrap();
        // attrs, dp length, "CoreRouter B\0" in UCS-2 (26 bytes), then HD().
        assert_eq!(&bytes[..4], &[1, 0, 0, 0]);
        assert_eq!(bytes[6 + 26], 0x04);
        assert_eq!(LoadOption::decode(&bytes).unwrap(), o);
        for cut in 0..bytes.len() {
            let _ = LoadOption::decode(&bytes[..cut]);
        }
    }

    #[test]
    fn directory_store() {
        let dir = std::env::temp_dir().join(format!("efivars-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let v = Vars::directory(&dir);
        assert_eq!(v.boot_order().unwrap(), Vec::<u16>::new());
        v.set_u16_list("BootOrder", &[3, 1]).unwrap();
        v.set_u16_list("BootNext", &[1]).unwrap();
        v.set("Boot0003", &[1, 0, 0, 0, 4, 0, 0, 0, 0x7f, 0xff, 4, 0])
            .unwrap();
        assert_eq!(v.boot_order().unwrap(), [3, 1]);
        assert_eq!(v.boot_next(), Some(1));
        assert_eq!(v.boot_numbers(), [3]);
        assert_eq!(v.load_option(3).unwrap().description, "");
        v.remove("BootNext").unwrap();
        assert_eq!(v.boot_next(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
