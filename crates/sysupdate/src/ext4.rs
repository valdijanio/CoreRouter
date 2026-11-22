//! G1.6v: growing the `/config` filesystem to its partition. The table is
//! [`crate::gpt::grow_last`]'s; here, the size the filesystem says it has
//! (its superblock) and the grow itself, by e2fsprogs (`e2fsck -f -p`,
//! then `resize2fs`) on the unmounted device, at boot, before the daemon
//! reads the configuration.
//!
//! The superblock (offset 1024, 1024 bytes; kernel `fs/ext4/ext4.h`,
//! `struct ext4_super_block`): `s_blocks_count_lo` at 0x04,
//! `s_log_block_size` at 0x18 (block = 1024 << it), `s_magic` 0xEF53 at
//! 0x38, `s_feature_incompat` at 0x60 (0x80: 64-bit), `s_blocks_count_hi`
//! at 0x150 when 64-bit.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

const SUPER_AT: u64 = 1024;
const MAGIC: u16 = 0xEF53;
const INCOMPAT_64BIT: u32 = 0x80;

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// Bytes of the ext2/3/4 filesystem on `dev` (its block count × block
/// size), from the superblock.
pub fn fs_bytes(dev: &mut (impl Read + Seek)) -> Result<u64, String> {
    let mut sb = vec![0u8; 1024];
    dev.seek(SeekFrom::Start(SUPER_AT))
        .map_err(|e| e.to_string())?;
    dev.read_exact(&mut sb)
        .map_err(|e| format!("ext4 superblock: {e}"))?;
    let magic = sb
        .get(0x38..0x3A)
        .and_then(|m| Some(u16::from_le_bytes(m.try_into().ok()?)));
    if magic != Some(MAGIC) {
        return Err("not an ext2/3/4 filesystem".into());
    }
    let bad = || "ext4 superblock truncated".to_string();
    let lo = u64::from(u32_at(&sb, 0x04).ok_or_else(bad)?);
    let log = u32_at(&sb, 0x18).ok_or_else(bad)?;
    if log > 6 {
        return Err(format!("ext4 block size 1024 << {log}"));
    }
    let incompat = u32_at(&sb, 0x60).ok_or_else(bad)?;
    let hi = if incompat & INCOMPAT_64BIT != 0 {
        u64::from(u32_at(&sb, 0x150).ok_or_else(bad)?)
    } else {
        0
    };
    Ok(((hi << 32) | lo).saturating_mul(1024 << log))
}

/// Grow only for a whole [`crate::gpt::ALIGN`] or more: the filesystem
/// may end a few blocks short of its partition on its own.
pub fn needs_grow(part_bytes: u64, fs_bytes: u64) -> bool {
    part_bytes >= fs_bytes.saturating_add(crate::gpt::ALIGN)
}

/// Where e2fsprogs is: `/sbin` on the image (Buildroot), `/usr/sbin` on a
/// distribution.
pub fn tools(dirs: &[&Path]) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    dirs.iter().find_map(|d| {
        let (f, r) = (d.join("e2fsck"), d.join("resize2fs"));
        (f.is_file() && r.is_file()).then_some((f, r))
    })
}

/// Checks then grows the unmounted filesystem on `dev` to its partition:
/// `e2fsck -f -p` (exit 0 or 1: clean or fixed; anything else stops here,
/// the filesystem is mounted as it is) and `resize2fs`. Returns what to
/// log.
pub fn grow(dev: &Path, e2fsck: &Path, resize2fs: &Path) -> Result<Vec<String>, String> {
    let mut log = Vec::new();
    let t = Instant::now();
    let out = Command::new(e2fsck)
        .args(["-f", "-p"])
        .arg(dev)
        .output()
        .map_err(|e| format!("{}: {e}", e2fsck.display()))?;
    let code = out.status.code().unwrap_or(-1);
    if !matches!(code, 0 | 1) {
        return Err(format!(
            "e2fsck {} exited {code}: not grown ({})",
            dev.display(),
            tail(&out.stdout, &out.stderr)
        ));
    }
    log.push(format!(
        "e2fsck {}: {} in {} ms",
        dev.display(),
        if code == 0 { "clean" } else { "fixed" },
        t.elapsed().as_millis()
    ));
    let t = Instant::now();
    let out = Command::new(resize2fs)
        .arg(dev)
        .output()
        .map_err(|e| format!("{}: {e}", resize2fs.display()))?;
    if !out.status.success() {
        return Err(format!(
            "resize2fs {} failed: {}",
            dev.display(),
            tail(&out.stdout, &out.stderr)
        ));
    }
    log.push(format!(
        "resize2fs {}: grown in {} ms",
        dev.display(),
        t.elapsed().as_millis()
    ));
    Ok(log)
}

/// The last lines a tool printed, for an error (bounded).
fn tail(stdout: &[u8], stderr: &[u8]) -> String {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    );
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let from = lines.len().saturating_sub(3);
    lines
        .get(from..)
        .unwrap_or(&[])
        .join(" / ")
        .chars()
        .take(400)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("sysupdate-ext4-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// `mkfs.ext4` of the host on a file of `mib` MiB; `None` without it.
    fn mkfs(path: &Path, mib: u64) -> Option<()> {
        let f = std::fs::File::create(path).ok()?;
        f.set_len(mib << 20).ok()?;
        let ok = Command::new("/usr/sbin/mkfs.ext4")
            .args(["-q", "-F", "-L", "config"])
            .arg(path)
            .status()
            .ok()?
            .success();
        ok.then_some(())
    }

    #[test]
    fn superblock_size_and_garbage() {
        let mut sb = vec![0u8; 4096];
        sb[1024 + 0x04..1024 + 0x08].copy_from_slice(&16384u32.to_le_bytes());
        sb[1024 + 0x18..1024 + 0x1C].copy_from_slice(&2u32.to_le_bytes());
        sb[1024 + 0x38..1024 + 0x3A].copy_from_slice(&MAGIC.to_le_bytes());
        assert_eq!(fs_bytes(&mut std::io::Cursor::new(&sb)).unwrap(), 64 << 20);
        // 64-bit: the high word counts.
        sb[1024 + 0x60..1024 + 0x64].copy_from_slice(&INCOMPAT_64BIT.to_le_bytes());
        sb[1024 + 0x150..1024 + 0x154].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            fs_bytes(&mut std::io::Cursor::new(&sb)).unwrap(),
            ((1u64 << 32) + 16384) * 4096
        );
        sb[1024 + 0x18] = 40;
        assert!(
            fs_bytes(&mut std::io::Cursor::new(&sb)).is_err(),
            "absurd block size"
        );
        assert!(fs_bytes(&mut std::io::Cursor::new(vec![0u8; 4096])).is_err());
        assert!(fs_bytes(&mut std::io::Cursor::new(vec![0u8; 100])).is_err());
        assert!(needs_grow(300 << 20, 64 << 20));
        assert!(
            !needs_grow((64 << 20) + 4096, 64 << 20),
            "a few blocks short"
        );
    }

    /// The image's 64 MiB `/config` in a partition of 300 MiB: checked and
    /// grown by the host's e2fsprogs, its files intact.
    #[test]
    fn a_small_filesystem_grows_to_its_partition() {
        let Some((e2fsck, resize2fs)) = tools(&[Path::new("/sbin"), Path::new("/usr/sbin")]) else {
            eprintln!("skipped: no e2fsprogs on this host");
            return;
        };
        let d = tmp("grow");
        let img = d.join("config.ext4");
        if mkfs(&img, 64).is_none() {
            eprintln!("skipped: no mkfs.ext4 on this host");
            return;
        }
        let mut f = std::fs::File::open(&img).unwrap();
        assert_eq!(fs_bytes(&mut f).unwrap(), 64 << 20);
        // The partition grew (the table did, at the boot before).
        std::fs::OpenOptions::new()
            .write(true)
            .open(&img)
            .unwrap()
            .set_len(300 << 20)
            .unwrap();
        assert!(needs_grow(300 << 20, fs_bytes(&mut f).unwrap()));
        let log = grow(&img, &e2fsck, &resize2fs).unwrap();
        assert!(log[0].contains("clean"), "{log:?}");
        assert_eq!(fs_bytes(&mut f).unwrap(), 300 << 20);
        assert!(!needs_grow(300 << 20, 300 << 20), "once");
        // Not a filesystem: e2fsck refuses, nothing is grown.
        let junk = d.join("junk");
        std::fs::write(&junk, vec![0u8; 1 << 20]).unwrap();
        assert!(
            grow(&junk, &e2fsck, &resize2fs)
                .unwrap_err()
                .contains("not grown")
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
