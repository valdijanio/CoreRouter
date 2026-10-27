//! Installing the image on an empty disk (G1.6c, `docs/os-image.md`): what
//! the installer (`corerouter-init` booted from the ISO) writes, kept here
//! so it runs on plain files in the tests.
//!
//! The ISO carries `INSTALL.JSON` (this module's [`Index`]: the disk
//! layout, read from the build's `disk.img`, and the payload files with
//! their sizes and SHA-256), its detached Ed25519 signature `INSTALL.SIG`
//! (the image key, the same that signs update packages) and the payload:
//! the update package (`COREROUTER.CRPKG`, whose rootfs is slot A), the ESP
//! and the empty `/config` filesystem. [`install`]:
//!
//! 1. checks the index signature and the package header signature, and
//!    that the target is large enough (nothing is written before);
//! 2. clears the first and last MiB (old partition tables, RAID/LVM
//!    labels): from here the disk has no partition table;
//! 3. streams each partition from the medium (read and hash on one thread,
//!    write on another), checking the hashes;
//! 4. `fsync`, drops the page cache and reads every region back (in
//!    parallel, one thread per region): ESP and `/config` against their
//!    hashes, slot A by recomputing its dm-verity tree (the signed root);
//! 5. writes the GPT last, primary and backup, and reads it back: a cut
//!    before this point leaves a disk the firmware does not boot, never a
//!    half-written one that it does.
//!
//! Slot B is not written (the first update fills it); the boot entry is the
//! caller's (efivarfs, `corerouter-init`).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
use std::time::Instant;

use ring::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};

use crate::efi::Partition;
use crate::gpt::{self, NewPart};
use crate::iso::{self, Extent};
use crate::package::{self, Header, Key, Manifest};
use crate::verity;

pub const INDEX: &str = "INSTALL.JSON";
pub const SIGNATURE: &str = "INSTALL.SIG";
pub const PACKAGE: &str = "COREROUTER.CRPKG";
/// Largest index read (a few hundred bytes in practice).
const MAX_INDEX: u64 = 64 << 10;
/// Cleared at both ends of the target before anything is written.
const WIPE: u64 = 1 << 20;
const CHUNK: usize = 1 << 20;

/// What a partition holds after the install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "kind")]
pub enum Content {
    /// A file of the medium, the rest of the partition left as it was
    /// (the ESP: FAT marks the tail free).
    Image { file: String },
    /// A file of the medium, the rest of the partition zeroed (`/config`:
    /// ext4 metadata may lie anywhere).
    Filesystem { file: String },
    /// The package's rootfs (squashfs + verity tree): slot A.
    Rootfs,
    /// Not written (slot B).
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Part {
    pub name: String,
    pub type_guid: String,
    pub guid: String,
    /// Bytes from the start of the disk; a multiple of 4096.
    pub offset: u64,
    pub size: u64,
    pub attrs: u64,
    pub content: Content,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSum {
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    pub format: u32,
    pub version: String,
    pub build: u64,
    pub commit: String,
    pub disk_guid: String,
    pub partitions: Vec<Part>,
    pub files: BTreeMap<String, FileSum>,
}

impl Index {
    /// Bytes the disk needs: the last partition, plus the backup GPT.
    pub fn min_disk(&self) -> u64 {
        self.partitions
            .iter()
            .map(|p| p.offset + p.size)
            .max()
            .unwrap_or(0)
            + WIPE
    }

    pub fn part(&self, name: &str) -> Option<&Part> {
        self.partitions.iter().find(|p| p.name == name)
    }

    fn check(&self) -> Result<(), String> {
        if self.format != 1 {
            return Err(format!(
                "install index format {} (this build reads 1)",
                self.format
            ));
        }
        if self.partitions.is_empty() || self.partitions.len() > 16 {
            return Err("install index: 1 to 16 partitions".into());
        }
        for p in &self.partitions {
            if !p.offset.is_multiple_of(4096) || !p.size.is_multiple_of(4096) || p.size == 0 {
                return Err(format!(
                    "install index: partition {} is not 4 KiB aligned",
                    p.name
                ));
            }
            let file = match &p.content {
                Content::Image { file } | Content::Filesystem { file } => Some(file),
                Content::Rootfs | Content::Empty => None,
            };
            if let Some(f) = file {
                let s = self
                    .files
                    .get(f)
                    .ok_or_else(|| format!("install index: no file {f}"))?;
                if s.size > p.size {
                    return Err(format!("install index: {f} does not fit {}", p.name));
                }
            }
        }
        if !self.files.contains_key(PACKAGE) {
            return Err(format!("install index: no {PACKAGE}"));
        }
        Ok(())
    }
}

/// The installer medium: the index (signature checked) and where each file
/// is.
pub struct Medium<R> {
    pub dev: R,
    pub index: Index,
    pub files: BTreeMap<String, Extent>,
    pub header: Header,
    pub key: String,
}

fn read_at(dev: &mut (impl Read + Seek), e: Extent, max: u64) -> Result<Vec<u8>, String> {
    if e.size > max {
        return Err(format!("{} bytes (at most {max})", e.size));
    }
    let mut buf = vec![0u8; e.size as usize];
    dev.seek(SeekFrom::Start(e.offset))
        .and_then(|_| dev.read_exact(&mut buf))
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

impl<R: Read + Seek + Send> Medium<R> {
    /// Opens an installer medium (CD, stick, ISO file) and checks the
    /// signatures of the index and of the package header against `keys`.
    pub fn open(mut dev: R, keys: &[Key]) -> Result<Self, String> {
        if !iso::is_installer(&mut dev) {
            return Err("not a CoreRouter installer medium".into());
        }
        let files = iso::read_dir(&mut dev)?;
        let get = |n: &str| {
            files
                .get(n)
                .copied()
                .ok_or_else(|| format!("medium: no {n}"))
        };
        let text =
            read_at(&mut dev, get(INDEX)?, MAX_INDEX).map_err(|e| format!("{INDEX}: {e}"))?;
        let sig =
            read_at(&mut dev, get(SIGNATURE)?, 1024).map_err(|e| format!("{SIGNATURE}: {e}"))?;
        let key = package::verify_detached(&text, &sig, keys)
            .map_err(|e| format!("{INDEX}: {e}"))?
            .id_hex();
        let index: Index = serde_json::from_slice(&text).map_err(|e| format!("{INDEX}: {e}"))?;
        index.check()?;
        for (name, sum) in &index.files {
            let e = get(name)?;
            if e.size != sum.size {
                return Err(format!(
                    "medium: {name} is {} bytes, the index says {}",
                    e.size, sum.size
                ));
            }
        }
        let pkg = get(PACKAGE)?;
        dev.seek(SeekFrom::Start(pkg.offset))
            .map_err(|e| e.to_string())?;
        let header = Header::read(&mut dev)?;
        header.verify(keys)?;
        let m = &header.manifest;
        if header.len() + m.kernel.size + m.rootfs.size != pkg.size {
            return Err(format!("{PACKAGE}: size does not match its manifest"));
        }
        if m.build != index.build || m.commit != index.commit {
            return Err(format!("{PACKAGE} is not the build the index describes"));
        }
        Ok(Medium {
            dev,
            index,
            files,
            header,
            key,
        })
    }

    fn extent(&self, name: &str) -> Result<Extent, String> {
        self.files
            .get(name)
            .copied()
            .ok_or_else(|| format!("medium: no {name}"))
    }
}

/// What the caller asks for.
#[derive(Debug, Clone)]
pub struct Opts {
    /// Keep the `config` partition of an earlier CoreRouter install (same
    /// place, same GUID, an ext4 filesystem in it).
    pub keep_config: bool,
    /// Read and hash on one thread, write on another.
    pub pipelined: bool,
    /// Read the regions back in parallel (one thread each).
    pub parallel_verify: bool,
    /// Threads for the verity tree.
    pub threads: usize,
}

/// How the install went.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    pub bytes_written: u64,
    pub write_ms: u64,
    pub sync_ms: u64,
    pub verify_ms: u64,
    pub total_ms: u64,
    pub kept_config: bool,
    /// The ESP as a boot entry names it, slot A's PARTUUID.
    pub esp: Option<Partition>,
    pub rootfs_a: String,
}

/// What a target disk holds now (shown before asking to erase it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Existing {
    Empty,
    /// A GPT with these partition names.
    Gpt(Vec<String>),
    /// A CoreRouter install (`rootfs-a` and `config`), with whether its
    /// `config` can be kept by this medium.
    CoreRouter {
        config_keepable: bool,
    },
    /// Something else on the first sectors (MBR, a filesystem).
    Unknown,
}

const EXT4_MAGIC_AT: u64 = 1024 + 56;

/// Looks at `disk` (read-only).
pub fn existing(disk: &mut (impl Read + Seek), lbs: u64, index: &Index) -> Existing {
    if let Ok(parts) = gpt::read(disk, lbs) {
        let names: Vec<String> = parts.iter().map(|p| p.name.clone()).collect();
        if names.iter().any(|n| n == "rootfs-a") && names.iter().any(|n| n == "config") {
            return Existing::CoreRouter {
                config_keepable: config_keepable(disk, lbs, index, &parts),
            };
        }
        return Existing::Gpt(names);
    }
    let mut head = vec![0u8; 64 << 10];
    if disk.seek(SeekFrom::Start(0)).is_err() || disk.read(&mut head).is_err() {
        return Existing::Unknown;
    }
    if head.iter().all(|&b| b == 0) {
        Existing::Empty
    } else {
        Existing::Unknown
    }
}

fn config_keepable(
    disk: &mut (impl Read + Seek),
    lbs: u64,
    index: &Index,
    parts: &[gpt::Entry],
) -> bool {
    let (Some(want), Some(have)) = (
        index.part("config"),
        parts.iter().find(|p| p.name == "config"),
    ) else {
        return false;
    };
    let mut magic = [0u8; 2];
    let ok = have.first_lba * lbs == want.offset
        && have.size_lba() * lbs == want.size
        && have.guid.eq_ignore_ascii_case(&want.guid)
        && disk
            .seek(SeekFrom::Start(want.offset + EXT4_MAGIC_AT))
            .is_ok()
        && disk.read_exact(&mut magic).is_ok();
    ok && magic == [0x53, 0xEF]
}

/// A writer at a byte offset of the target (`pwrite`).
struct At<'a> {
    f: &'a File,
    pos: u64,
}

impl Write for At<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.f.write_all_at(b, self.pos)?;
        self.pos += b.len() as u64;
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn zero(f: &File, at: u64, len: u64) -> Result<(), String> {
    let buf = vec![0u8; CHUNK];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(CHUNK as u64) as usize;
        f.write_all_at(buf.get(..n).unwrap_or(&[]), at + done)
            .map_err(|e| format!("write: {e}"))?;
        done += n as u64;
    }
    Ok(())
}

/// SHA-256 of `len` bytes of `f` at `at`, and whether the next `zeros`
/// bytes are all zero.
fn hash_region(f: &File, at: u64, len: u64, zeros: u64) -> Result<(String, bool), String> {
    let mut ctx = Context::new(&SHA256);
    let mut buf = vec![0u8; CHUNK];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(CHUNK as u64) as usize;
        let b = buf.get_mut(..n).ok_or("buffer")?;
        f.read_exact_at(b, at + done)
            .map_err(|e| format!("read back: {e}"))?;
        ctx.update(b);
        done += n as u64;
    }
    let mut clean = true;
    let mut z = 0;
    while z < zeros && clean {
        let n = (zeros - z).min(CHUNK as u64) as usize;
        let b = buf.get_mut(..n).ok_or("buffer")?;
        f.read_exact_at(b, at + len + z)
            .map_err(|e| format!("read back: {e}"))?;
        clean = b.iter().all(|&x| x == 0);
        z += n as u64;
    }
    Ok((verity::hex(ctx.finish().as_ref()), clean))
}

/// Re-reads slot A and recomputes its verity tree (like
/// `Platform::check_slot` after an update).
fn check_rootfs(f: &File, at: u64, m: &Manifest, threads: usize) -> Result<(), String> {
    let mut data = vec![0u8; m.rootfs.size as usize];
    f.read_exact_at(&mut data, at)
        .map_err(|e| format!("read back slot A: {e}"))?;
    if package::sha256_hex(&data) != m.rootfs.sha256 {
        return Err("slot A: what was read back is not the signed rootfs".into());
    }
    let split = (m.rootfs.data_blocks as usize) * verity::BLOCK;
    let (d, on_disk) = data.split_at(split.min(data.len()));
    let salt = verity::unhex(&m.rootfs.salt).ok_or("salt")?;
    let tree = verity::tree(d, &salt, threads)?;
    if verity::hex(&tree.root) != m.rootfs.root_hash || tree.bytes != on_disk {
        return Err("slot A: the verity tree read back does not match the signed root hash".into());
    }
    Ok(())
}

/// Installs the medium's image on `target` (a whole disk of `disk_bytes`
/// with `lbs`-byte logical blocks). `progress(done, total)` after each
/// chunk written.
pub fn install<R: Read + Seek + Send>(
    medium: &mut Medium<R>,
    target: &File,
    disk_bytes: u64,
    lbs: u64,
    opts: &Opts,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<Report, String> {
    let t0 = Instant::now();
    let index = medium.index.clone();
    let m = medium.header.manifest.clone();
    if !(512..=4096).contains(&lbs) || !lbs.is_power_of_two() {
        return Err(format!("logical block size {lbs}"));
    }
    if disk_bytes < index.min_disk() {
        return Err(format!(
            "the disk has {} MiB, the image needs {} MiB",
            disk_bytes >> 20,
            index.min_disk().div_ceil(1 << 20)
        ));
    }
    let keep = opts.keep_config && {
        let mut t = target;
        let parts = gpt::read(&mut t, lbs).unwrap_or_default();
        config_keepable(&mut t, lbs, &index, &parts)
    };
    if opts.keep_config && !keep {
        return Err("the configuration on this disk cannot be kept (no CoreRouter config partition in the same place)".into());
    }
    let pkg = medium.extent(PACKAGE)?;
    let rootfs_at = pkg.offset + medium.header.len() + m.kernel.size;
    // What gets written, in order: (partition, source extent, zero fill).
    let mut jobs: Vec<(Part, Extent, u64)> = Vec::new();
    for p in &index.partitions {
        let (src, fill) = match &p.content {
            Content::Image { file } => (medium.extent(file)?, 0),
            Content::Filesystem { file } if keep && p.name == "config" => {
                let _ = file;
                continue;
            }
            Content::Filesystem { file } => {
                let e = medium.extent(file)?;
                (e, p.size - e.size)
            }
            Content::Rootfs => (
                Extent {
                    offset: rootfs_at,
                    size: m.rootfs.size,
                },
                0,
            ),
            Content::Empty => continue,
        };
        if src.size + fill > p.size {
            return Err(format!("{} does not fit partition {}", src.size, p.name));
        }
        jobs.push((p.clone(), src, fill));
    }
    let total: u64 = jobs.iter().map(|(_, s, f)| s.size + f).sum();

    // 2. No partition table from here until step 5.
    let tw = Instant::now();
    zero(target, 0, WIPE)?;
    zero(target, disk_bytes - WIPE, WIPE)?;
    // 3. Stream, hash, write.
    let mut done = 0u64;
    let mut written: Vec<(Part, u64, u64, Option<String>)> = Vec::new();
    for (p, src, fill) in &jobs {
        medium
            .dev
            .seek(SeekFrom::Start(src.offset))
            .map_err(|e| e.to_string())?;
        let mut w = At {
            f: target,
            pos: p.offset,
        };
        let base = done;
        let mut parts: [(u64, &mut dyn Write); 1] = [(src.size, &mut w)];
        let c = package::copy(&mut medium.dev, &mut parts, opts.pipelined, &mut |n| {
            progress(base + n, total)
        })
        .map_err(|e| format!("{}: {e}", p.name))?;
        let got = c.sha256.first().cloned().unwrap_or_default();
        let want = match &p.content {
            Content::Image { file } | Content::Filesystem { file } => {
                index.files.get(file).map(|s| s.sha256.clone())
            }
            _ => Some(m.rootfs.sha256.clone()),
        };
        if want.as_deref() != Some(got.as_str()) {
            return Err(format!(
                "{}: the medium does not match its signed hash (bad medium?): nothing was made bootable",
                p.name
            ));
        }
        if *fill > 0 {
            zero(target, p.offset + src.size, *fill)?;
        }
        done += src.size + fill;
        progress(done, total);
        written.push((p.clone(), src.size, *fill, want));
    }
    let write_ms = tw.elapsed().as_millis() as u64;
    // 4. On the disk, not in the cache.
    let ts = Instant::now();
    target.sync_all().map_err(|e| format!("sync: {e}"))?;
    crate::ab::drop_cache(target);
    let sync_ms = ts.elapsed().as_millis() as u64;
    let tv = Instant::now();
    let check = |(p, len, fill, want): &(Part, u64, u64, Option<String>)| -> Result<(), String> {
        if p.content == Content::Rootfs {
            return check_rootfs(target, p.offset, &m, opts.threads);
        }
        let (h, clean) = hash_region(target, p.offset, *len, *fill)?;
        if want.as_deref() != Some(h.as_str()) || !clean {
            return Err(format!(
                "{}: what was read back is not what was written (bad disk?)",
                p.name
            ));
        }
        Ok(())
    };
    if opts.parallel_verify {
        std::thread::scope(|s| -> Result<(), String> {
            let handles: Vec<_> = written
                .iter()
                .map(|w| {
                    std::thread::Builder::new()
                        .name(format!("verify-{}", w.0.name))
                        .spawn_scoped(s, || check(w))
                })
                .collect::<Result<_, _>>()
                .map_err(|e| format!("thread: {e}"))?;
            for h in handles {
                h.join()
                    .map_err(|_| "verify thread panicked".to_string())??;
            }
            Ok(())
        })?;
    } else {
        for w in &written {
            check(w)?;
        }
    }
    let verify_ms = tv.elapsed().as_millis() as u64;
    // 5. The partition table, last.
    let new: Vec<NewPart> = index
        .partitions
        .iter()
        .map(|p| NewPart {
            name: p.name.clone(),
            type_guid: p.type_guid.clone(),
            guid: p.guid.clone(),
            first_lba: p.offset / lbs,
            last_lba: (p.offset + p.size) / lbs - 1,
            attrs: p.attrs,
        })
        .collect();
    let (primary, backup_at, backup) = gpt::build(disk_bytes / lbs, lbs, &index.disk_guid, &new)?;
    target
        .write_all_at(&primary, 0)
        .and_then(|_| target.write_all_at(&backup, backup_at))
        .and_then(|_| target.sync_all())
        .map_err(|e| format!("partition table: {e}"))?;
    crate::ab::drop_cache(target);
    let mut t = target;
    let back = gpt::read(&mut t, lbs)?;
    let mut back_b = vec![0u8; backup.len()];
    target
        .read_exact_at(&mut back_b, backup_at)
        .map_err(|e| format!("read back the backup GPT: {e}"))?;
    if back.len() != new.len() || back_b != backup {
        return Err("partition table: what was read back is not what was written".into());
    }
    let esp = index.part("efi").and_then(|p| {
        let e = back.iter().find(|b| b.name == p.name)?;
        Some(Partition {
            number: e.number,
            start_lba: e.first_lba,
            size_lba: e.size_lba(),
            guid: e.guid.clone(),
        })
    });
    Ok(Report {
        bytes_written: done + 2 * WIPE,
        write_ms,
        sync_ms,
        verify_ms,
        total_ms: t0.elapsed().as_millis() as u64,
        kept_config: keep,
        esp,
        rootfs_a: index
            .part("rootfs-a")
            .map(|p| p.guid.clone())
            .unwrap_or_default(),
    })
}

/// The index of a build (`corerouter-image installer`): the layout of
/// `disk` (genimage's `disk.img`, its GPT) and the payload files.
pub fn index_of(
    disk: &mut (impl Read + Seek),
    manifest: &Manifest,
    files: &[(&str, &[u8])],
    contents: &[(&str, Content)],
) -> Result<Index, String> {
    let mut hdr = vec![0u8; 512];
    disk.seek(SeekFrom::Start(512))
        .and_then(|_| disk.read_exact(&mut hdr))
        .map_err(|e| format!("disk image: {e}"))?;
    let dg = crate::efi::guid_text(hdr.get(56..72).unwrap_or(&[])).ok_or("disk GUID")?;
    let parts = gpt::read(disk, 512)?;
    let mut partitions = Vec::new();
    for p in &parts {
        let content = contents
            .iter()
            .find(|(n, _)| *n == p.name)
            .map(|(_, c)| c.clone())
            .unwrap_or(Content::Empty);
        partitions.push(Part {
            name: p.name.clone(),
            type_guid: p.type_guid.clone(),
            guid: p.guid.clone(),
            offset: p.first_lba * 512,
            size: p.size_lba() * 512,
            attrs: gpt_attrs(disk, p.number)?,
            content,
        });
    }
    let files = files
        .iter()
        .map(|(n, d)| {
            (
                (*n).to_owned(),
                FileSum {
                    size: d.len() as u64,
                    sha256: package::sha256_hex(d),
                },
            )
        })
        .collect();
    let index = Index {
        format: 1,
        version: manifest.version.clone(),
        build: manifest.build,
        commit: manifest.commit.clone(),
        disk_guid: dg,
        partitions,
        files,
    };
    index.check()?;
    Ok(index)
}

fn gpt_attrs(disk: &mut (impl Read + Seek), number: u32) -> Result<u64, String> {
    // Entries at LBA 2 of a 512-byte disk image, 128 bytes each.
    let mut a = [0u8; 8];
    disk.seek(SeekFrom::Start(1024 + u64::from(number - 1) * 128 + 48))
        .and_then(|_| disk.read_exact(&mut a))
        .map_err(|e| e.to_string())?;
    Ok(u64::from_le_bytes(a))
}

/// `data` without its trailing all-zero 4 KiB blocks (the ESP and `/config`
/// images are mostly empty).
pub fn trim(data: &[u8]) -> &[u8] {
    let blocks = data.len().div_ceil(4096);
    let last = (0..blocks).rev().find(|b| {
        data.get(b * 4096..((b + 1) * 4096).min(data.len()))
            .is_some_and(|c| c.iter().any(|&x| x != 0))
    });
    match last {
        Some(b) => data.get(..((b + 1) * 4096).min(data.len())).unwrap_or(data),
        None => data.get(..0).unwrap_or(data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct Build {
        iso: Vec<u8>,
        keys: Vec<Key>,
        esp: Vec<u8>,
        config: Vec<u8>,
        rootfs: Vec<u8>,
        disk: Vec<u8>,
    }

    const MIB: u64 = 1 << 20;

    /// A small build: GPT like genimage's, signed package and index, ISO.
    fn build(tamper: impl Fn(&mut Vec<(String, Vec<u8>)>)) -> Build {
        let key = package::generate_key().unwrap();
        let keys = vec![Key::from_hex(&package::public_hex(&key).unwrap()).unwrap()];
        let parts = [
            (
                "efi",
                crate::iso::ESP_TYPE,
                "4f9a520b-35f7-4633-a4bb-e9f871d1473c",
                1,
                2,
                4u64,
            ),
            (
                "rootfs-a",
                "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
                "3e1088b8-5b4b-4fbb-b756-a271f641d018",
                3,
                1,
                0,
            ),
            (
                "rootfs-b",
                "4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
                "868e1d1d-85bb-4c62-a083-f61aa7a5cda2",
                4,
                1,
                0,
            ),
            (
                "config",
                "0fc63daf-8483-4772-8e79-3d69d8477de4",
                "4c6422db-190c-4f35-b930-a98862b6be7d",
                5,
                1,
                0,
            ),
        ];
        let new: Vec<NewPart> = parts
            .iter()
            .map(|(n, t, g, at, size, a)| NewPart {
                name: (*n).into(),
                type_guid: (*t).into(),
                guid: (*g).into(),
                first_lba: at * MIB / 512,
                last_lba: (at + size) * MIB / 512 - 1,
                attrs: *a,
            })
            .collect();
        let (p, at, b) = gpt::build(
            7 * MIB / 512,
            512,
            "39dfcaa2-2c8a-4912-acaa-6af0c68b5350",
            &new,
        )
        .unwrap();
        let mut disk = vec![0u8; 7 * MIB as usize];
        disk[..p.len()].copy_from_slice(&p);
        disk[at as usize..at as usize + b.len()].copy_from_slice(&b);

        let data: Vec<u8> = (0..65536u32).map(|i| (i * 7 % 251) as u8).collect();
        let salt = vec![9u8; 16];
        let tree = verity::tree(&data, &salt, 2).unwrap();
        let mut rootfs = data.clone();
        rootfs.extend_from_slice(&tree.bytes);
        let kernel = vec![0x4d; 10_000];
        let mut man = package::tests::manifest(&kernel, &rootfs, &tree);
        man.rootfs.salt = verity::hex(&salt);
        let header = package::sign(&man, &key).unwrap();
        let mut pkg = header.clone();
        pkg.extend_from_slice(&kernel);
        pkg.extend_from_slice(&rootfs);
        let mut esp = vec![0u8; MIB as usize];
        esp[..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        esp[600_000] = 1;
        let esp = trim(&esp).to_vec();
        assert_eq!(esp.len(), 602_112);
        let mut config = vec![0u8; 8192];
        config[1080..1082].copy_from_slice(&[0x53, 0xEF]);
        let index = index_of(
            &mut Cursor::new(&disk),
            &man,
            &[(PACKAGE, &pkg), ("ESP.IMG", &esp), ("CONFIG.IMG", &config)],
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
        )
        .unwrap();
        assert_eq!(index.part("efi").unwrap().attrs, 4);
        let text = serde_json::to_vec(&index).unwrap();
        let sig = package::sign_detached(&text, &key).unwrap();
        let mut files: Vec<(String, Vec<u8>)> = vec![
            (INDEX.into(), text),
            (SIGNATURE.into(), sig),
            (PACKAGE.into(), pkg),
            ("ESP.IMG".into(), esp.clone()),
            ("CONFIG.IMG".into(), config.clone()),
            ("EFIBOOT.IMG".into(), vec![0; 4096]),
        ];
        tamper(&mut files);
        let mut readers: Vec<Cursor<Vec<u8>>> =
            files.iter().map(|(_, d)| Cursor::new(d.clone())).collect();
        let mut fl: Vec<iso::File<'_>> = files
            .iter()
            .zip(readers.iter_mut())
            .map(|((n, d), r)| iso::File {
                name: n.clone(),
                size: d.len() as u64,
                data: r,
            })
            .collect();
        let mut img = Vec::new();
        iso::write(&mut img, &mut fl, "EFIBOOT.IMG", 0).unwrap();
        Build {
            iso: img,
            keys,
            esp,
            config,
            rootfs,
            disk,
        }
    }

    fn target(len: u64, fill: u8) -> (File, std::path::PathBuf) {
        let p = std::env::temp_dir().join(format!(
            "cr-install-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&p)
            .unwrap();
        f.write_all_at(&vec![fill; len as usize], 0).unwrap();
        (f, p)
    }

    fn opts() -> Opts {
        Opts {
            keep_config: false,
            pipelined: true,
            parallel_verify: true,
            threads: 2,
        }
    }

    #[test]
    fn installs_and_the_disk_reads_back_as_the_image() {
        let b = build(|_| {});
        let mut m = Medium::open(Cursor::new(b.iso.clone()), &b.keys).unwrap();
        assert_eq!(m.index.min_disk(), 7 * MIB);
        for (pipelined, parallel) in [(true, true), (false, false)] {
            let (f, p) = target(16 * MIB, 0xA5);
            let o = Opts {
                pipelined,
                parallel_verify: parallel,
                ..opts()
            };
            let mut last = 0;
            let r = install(&mut m, &f, 16 * MIB, 512, &o, &mut |d, t| {
                assert!(d <= t);
                last = d;
            })
            .unwrap();
            assert_eq!(last, b.esp.len() as u64 + b.rootfs.len() as u64 + MIB);
            let disk = std::fs::read(&p).unwrap();
            let _ = std::fs::remove_file(&p);
            let parts = gpt::read(&mut Cursor::new(&disk), 512).unwrap();
            let names: Vec<&str> = parts.iter().map(|p| p.name.as_str()).collect();
            assert_eq!(names, ["efi", "rootfs-a", "rootfs-b", "config"]);
            let at =
                |n: &str| (parts.iter().find(|p| p.name == n).unwrap().first_lba * 512) as usize;
            assert_eq!(&disk[at("efi")..at("efi") + b.esp.len()], &b.esp[..]);
            assert_eq!(
                &disk[at("rootfs-a")..at("rootfs-a") + b.rootfs.len()],
                &b.rootfs[..]
            );
            assert_eq!(
                &disk[at("config")..at("config") + b.config.len()],
                &b.config[..]
            );
            assert!(
                disk[at("config") + b.config.len()..at("config") + MIB as usize]
                    .iter()
                    .all(|&x| x == 0)
            );
            assert!(
                disk[at("rootfs-b")..at("rootfs-b") + 16]
                    .iter()
                    .all(|&x| x == 0xA5),
                "slot B untouched"
            );
            // Same partitions as the build's disk image, backup GPT at the end.
            assert_eq!(parts, gpt::read(&mut Cursor::new(&b.disk), 512).unwrap());
            assert_eq!(&disk[disk.len() - 512..disk.len() - 504], b"EFI PART");
            assert_eq!(r.esp.as_ref().unwrap().number, 1);
            assert_eq!(r.rootfs_a, "3e1088b8-5b4b-4fbb-b756-a271f641d018");
            assert_eq!(
                existing(&mut Cursor::new(&disk), 512, &m.index),
                Existing::CoreRouter {
                    config_keepable: true
                }
            );
        }
    }

    #[test]
    fn keeps_the_configuration_when_asked() {
        let b = build(|_| {});
        let mut m = Medium::open(Cursor::new(b.iso.clone()), &b.keys).unwrap();
        let (f, p) = target(16 * MIB, 0);
        install(&mut m, &f, 16 * MIB, 512, &opts(), &mut |_, _| {}).unwrap();
        let cfg = m.index.part("config").unwrap().offset;
        f.write_all_at(b"operator config", cfg + 8192).unwrap();
        let r = install(
            &mut m,
            &f,
            16 * MIB,
            512,
            &Opts {
                keep_config: true,
                ..opts()
            },
            &mut |_, _| {},
        )
        .unwrap();
        assert!(r.kept_config);
        let mut got = [0u8; 15];
        f.read_exact_at(&mut got, cfg + 8192).unwrap();
        assert_eq!(&got, b"operator config");
        // A blank disk has nothing to keep: refused before writing.
        let (g, q) = target(16 * MIB, 0x11);
        let e = install(
            &mut m,
            &g,
            16 * MIB,
            512,
            &Opts {
                keep_config: true,
                ..opts()
            },
            &mut |_, _| {},
        )
        .unwrap_err();
        assert!(e.contains("cannot be kept"), "{e}");
        let mut first = [0u8; 4];
        g.read_exact_at(&mut first, 0).unwrap();
        assert_eq!(first, [0x11; 4]);
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(&q);
    }

    #[test]
    fn small_disk_and_bad_media_are_refused_before_writing() {
        let b = build(|_| {});
        let mut m = Medium::open(Cursor::new(b.iso.clone()), &b.keys).unwrap();
        let (f, p) = target(6 * MIB, 0x22);
        let e = install(&mut m, &f, 6 * MIB, 512, &opts(), &mut |_, _| {}).unwrap_err();
        assert!(e.contains("needs 7 MiB"), "{e}");
        let mut first = [0u8; 4];
        f.read_exact_at(&mut first, 0).unwrap();
        assert_eq!(first, [0x22; 4]);
        let _ = std::fs::remove_file(&p);
        // Untrusted key.
        let other = vec![
            Key::from_hex(&package::public_hex(&package::generate_key().unwrap()).unwrap())
                .unwrap(),
        ];
        assert!(
            Medium::open(Cursor::new(b.iso.clone()), &other)
                .err()
                .unwrap()
                .contains("does not trust")
        );
        // A changed index (its signature no longer matches).
        let t = build(|f| {
            let i = f.iter_mut().find(|(n, _)| n == INDEX).unwrap();
            let at = i.1.iter().position(|&c| c == b'0').unwrap();
            i.1[at] = b'1';
        });
        assert!(
            Medium::open(Cursor::new(t.iso), &t.keys)
                .err()
                .unwrap()
                .contains("bad signature")
        );
        assert!(Medium::open(Cursor::new(vec![0u8; 100_000]), &b.keys).is_err());
    }

    #[test]
    fn a_corrupt_payload_is_caught_and_no_table_is_written() {
        // A flipped byte in the ESP image on the medium (index still signed).
        let b = build(|f| {
            let e = f.iter_mut().find(|(n, _)| n == "ESP.IMG").unwrap();
            e.1[100] ^= 1;
        });
        let mut m = Medium::open(Cursor::new(b.iso), &b.keys).unwrap();
        let (f, p) = target(16 * MIB, 0);
        let e = install(&mut m, &f, 16 * MIB, 512, &opts(), &mut |_, _| {}).unwrap_err();
        assert!(e.contains("does not match its signed hash"), "{e}");
        let mut t = &f;
        assert!(gpt::read(&mut t, 512).is_err(), "no partition table");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn trim_keeps_up_to_the_last_used_block() {
        assert_eq!(trim(&[0u8; 10000]).len(), 0);
        let mut d = vec![0u8; 10000];
        d[4096] = 1;
        assert_eq!(trim(&d).len(), 8192);
        d[9999] = 1;
        assert_eq!(trim(&d).len(), 10000);
    }
}
