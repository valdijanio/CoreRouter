//! dm-verity hash tree, format version 1 (`docs.kernel.org`,
//! admin-guide/device-mapper/verity.rst), as `veritysetup format
//! --no-superblock` writes it: SHA-256, 4 KiB data and hash blocks, each
//! digest `sha256(salt ‖ block)`, a hash block holding 128 digests padded
//! with zeros, and the levels stored from the one under the root down to the
//! one over the data. The slot partition holds the data, then the tree at
//! `hash_start_block = data_blocks` (one device for both, as Chrome OS does).
//!
//! Level 0 (one digest per data block) is all the work; it is split over
//! threads by contiguous runs of hash blocks, each thread writing its own
//! part of the level, so nothing is shared or locked.

use ring::digest::{Context, SHA256};

/// Data and hash block size (the kernel's page size: the fast path).
pub const BLOCK: usize = 4096;
const DIGEST: usize = 32;
const PER_BLOCK: usize = BLOCK / DIGEST;
/// Below this, threads cost more than they save (**medido**: 16 MiB hashes
/// in ~8 ms on one core, see `benches/sysupdate.rs`).
const PARALLEL_MIN: usize = 64 << 20;

/// What the kernel's verity table needs besides the devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub data_blocks: u64,
    pub hash_blocks: u64,
    pub root: [u8; DIGEST],
    /// The tree as it goes on disk right after the data.
    pub bytes: Vec<u8>,
}

fn digest(salt: &[u8], block: &[u8]) -> [u8; DIGEST] {
    let mut c = Context::new(&SHA256);
    c.update(salt);
    c.update(block);
    let mut out = [0u8; DIGEST];
    out.copy_from_slice(c.finish().as_ref());
    out
}

/// One level: `n` blocks hashed into hash blocks. `hash(first, count, dst)`
/// writes the digests of blocks `first..first + count` into `dst` (32 bytes
/// each); with `threads` > 1 and at least [`PARALLEL_MIN`] of data, each
/// thread owns a run of whole hash blocks and the data blocks they cover.
fn level_by<H>(n: usize, threads: usize, hash: H) -> Result<Vec<u8>, String>
where
    H: Fn(usize, usize, &mut [u8]) -> Result<(), String> + Sync,
{
    let hash_blocks = n.div_ceil(PER_BLOCK);
    let mut out = vec![0u8; hash_blocks * BLOCK];
    if threads <= 1 || n.saturating_mul(BLOCK) < PARALLEL_MIN {
        // Digests are contiguous across hash blocks (128 per block, no gap).
        hash(0, n, &mut out)?;
        return Ok(out);
    }
    let per = hash_blocks.div_ceil(threads);
    std::thread::scope(|s| -> Result<(), String> {
        let hash = &hash;
        let mut rest: &mut [u8] = &mut out;
        let mut first = 0usize;
        let mut handles = Vec::new();
        while first < hash_blocks {
            let count = per.min(hash_blocks - first);
            let (mine, tail) = std::mem::take(&mut rest).split_at_mut(count * BLOCK);
            rest = tail;
            let start = first * PER_BLOCK;
            let end = ((first + count) * PER_BLOCK).min(n);
            let h = std::thread::Builder::new()
                .name(format!("verity-{}", handles.len()))
                .spawn_scoped(s, move || hash(start, end - start, mine))
                .map_err(|e| format!("verity: thread: {e}"))?;
            handles.push(h);
            first += count;
        }
        for h in handles {
            h.join()
                .map_err(|_| "verity: a thread panicked".to_string())??;
        }
        Ok(())
    })?;
    Ok(out)
}

fn hash_into(salt: &[u8], src: &[u8], dst: &mut [u8]) {
    for (blk, slot) in src.chunks(BLOCK).zip(dst.chunks_mut(DIGEST)) {
        slot.copy_from_slice(&digest(salt, blk));
    }
}

/// One level of `data` (whole blocks, the last zero-padded by the caller).
fn level(salt: &[u8], data: &[u8], threads: usize) -> Result<Vec<u8>, String> {
    level_by(data.len() / BLOCK, threads, |first, count, dst| {
        let src = data
            .get(first * BLOCK..(first + count) * BLOCK)
            .ok_or("verity: past the data")?;
        hash_into(salt, src, dst);
        Ok(())
    })
}

/// The levels over level 0, the root and the tree as stored.
fn above(level0: Vec<u8>, salt: &[u8], data_blocks: usize) -> Result<Tree, String> {
    let mut levels: Vec<Vec<u8>> = Vec::new();
    let mut cur = level0;
    loop {
        let blocks = cur.len() / BLOCK;
        if blocks <= 1 {
            levels.push(cur);
            break;
        }
        let next = level(salt, &cur, 1)?;
        levels.push(cur);
        cur = next;
    }
    let top = levels.last().map(Vec::as_slice).unwrap_or(&[]);
    let root = digest(salt, top);
    let mut bytes = Vec::with_capacity(levels.iter().map(Vec::len).sum());
    for l in levels.iter().rev() {
        bytes.extend_from_slice(l);
    }
    Ok(Tree {
        data_blocks: data_blocks as u64,
        hash_blocks: (bytes.len() / BLOCK) as u64,
        root,
        bytes,
    })
}

fn check_size(data_len: u64) -> Result<(), String> {
    if !data_len.is_multiple_of(BLOCK as u64) || data_len < 2 * BLOCK as u64 {
        return Err(format!(
            "verity: {data_len} bytes is not a multiple of {BLOCK} of at least two blocks"
        ));
    }
    Ok(())
}

/// The tree of `data` (a multiple of [`BLOCK`], at least two blocks).
/// `threads`: level 0 is split over this many when `data` is large.
pub fn tree(data: &[u8], salt: &[u8], threads: usize) -> Result<Tree, String> {
    check_size(data.len() as u64)?;
    above(level(salt, data, threads)?, salt, data.len() / BLOCK)
}

/// What [`check_at`] reads at a time, per thread: 256 data blocks.
pub const READ: usize = 1 << 20;
/// At most this many threads read a slot back, whatever the machine has: a
/// buffer each, and the disk is the limit (**medido**: 128 MiB in 10.5 ms on
/// 8 threads from the page cache, `benches/sysupdate.rs`).
const CHECK_THREADS: usize = 8;

/// Where [`check_at`] reads a slot from: a disk, a partition, a file.
pub trait ReadAt: Sync {
    fn read_exact_at(&self, buf: &mut [u8], at: u64) -> std::io::Result<()>;
}

#[cfg(unix)]
impl ReadAt for std::fs::File {
    fn read_exact_at(&self, buf: &mut [u8], at: u64) -> std::io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(self, buf, at)
    }
}

/// Windows has no `read_exact_at`: `seek_read` reads at an offset but may
/// return fewer bytes, so it is repeated until the buffer is full.
#[cfg(windows)]
impl ReadAt for std::fs::File {
    fn read_exact_at(&self, mut buf: &mut [u8], mut at: u64) -> std::io::Result<()> {
        use std::os::windows::fs::FileExt;
        while !buf.is_empty() {
            match self.seek_read(buf, at) {
                Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => {
                    buf = buf.get_mut(n..).unwrap_or_default();
                    at += n as u64;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Whether the `size` bytes at `at` in `f` are a slot of `data_blocks`
/// blocks followed by their tree, with root `root_hex`: level 0 is computed
/// from the blocks as read, the levels above it from level 0, and the tree
/// stored after the data must be the computed one. That covers every byte.
///
/// It reads [`READ`] bytes at a time on each of at most [`CHECK_THREADS`]
/// threads and holds the tree (1/128 of the data), never the slot: G0.30j, reading a 150 MiB rootfs whole to
/// check it got the daemon of a 448 MiB live image killed by the kernel in
/// the middle of an install.
pub fn check_at<F: ReadAt + ?Sized>(
    f: &F,
    at: u64,
    size: u64,
    data_blocks: u64,
    salt: &[u8],
    root_hex: &str,
    threads: usize,
) -> Result<bool, String> {
    let data_len = data_blocks.saturating_mul(BLOCK as u64);
    check_size(data_len)?;
    let n = usize::try_from(data_blocks).map_err(|_| "verity: too many blocks".to_string())?;
    let read = |off: u64, buf: &mut [u8]| {
        f.read_exact_at(buf, at + off)
            .map_err(|e| format!("read back at {}: {e}", at + off))
    };
    let level0 = level_by(n, threads.min(CHECK_THREADS), |first, count, dst| {
        let mut buf = vec![0u8; READ.min(count * BLOCK)];
        let mut slots = dst.chunks_mut(DIGEST);
        let mut done = 0usize;
        while done < count {
            let blocks = (READ / BLOCK).min(count - done);
            let b = buf.get_mut(..blocks * BLOCK).ok_or("verity: buffer")?;
            read(((first + done) * BLOCK) as u64, b)?;
            for blk in b.chunks(BLOCK) {
                slots
                    .next()
                    .ok_or("verity: level 0")?
                    .copy_from_slice(&digest(salt, blk));
            }
            done += blocks;
        }
        Ok(())
    })?;
    let tree = above(level0, salt, n)?;
    if hex(&tree.root) != root_hex || size.checked_sub(data_len) != Some(tree.bytes.len() as u64) {
        return Ok(false);
    }
    let mut stored = vec![0u8; tree.bytes.len()];
    read(data_len, &mut stored)?;
    Ok(stored == tree.bytes)
}

/// `data` padded with zeros to a whole number of blocks.
pub fn pad(mut data: Vec<u8>) -> Vec<u8> {
    let len = data.len().div_ceil(BLOCK) * BLOCK;
    data.resize(len, 0);
    data
}

/// The `verity` target's table line for `dm-mod.create` (version 1, data
/// and hash on the same device `dev`).
pub fn table(dev: &str, data_blocks: u64, root_hex: &str, salt_hex: &str) -> String {
    format!(
        "0 {} verity 1 {dev} {dev} {BLOCK} {BLOCK} {data_blocks} {data_blocks} sha256 {root_hex} {salt_hex}",
        data_blocks * (BLOCK as u64 / 512)
    )
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || s.len() > 256 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(blocks: usize) -> Vec<u8> {
        (0..blocks * BLOCK).map(|i| (i * 7 % 251) as u8).collect()
    }

    #[test]
    fn two_levels_layout() {
        // 200 blocks: level 0 has 2 hash blocks, level 1 one; stored top first.
        let d = data(200);
        let t = tree(&d, b"salt", 1).unwrap();
        assert_eq!(t.data_blocks, 200);
        assert_eq!(t.hash_blocks, 3);
        let l0_first = digest(b"salt", &d[..BLOCK]);
        assert_eq!(&t.bytes[BLOCK..BLOCK + 32], &l0_first);
        let top = &t.bytes[..BLOCK];
        assert_eq!(t.root, digest(b"salt", top));
        assert_eq!(&top[..32], &digest(b"salt", &t.bytes[BLOCK..2 * BLOCK]));
        // Level 0's second hash block: digests 128..200 then zeros.
        assert!(
            t.bytes[2 * BLOCK + 72 * 32..3 * BLOCK]
                .iter()
                .all(|&b| b == 0)
        );
    }

    #[test]
    fn threads_give_the_same_tree() {
        let d = data((PARALLEL_MIN / BLOCK) + 300);
        let one = tree(&d, b"s", 1).unwrap();
        let many = tree(&d, b"s", 7).unwrap();
        assert_eq!(one, many);
    }

    #[test]
    fn refuses_odd_sizes() {
        assert!(tree(&[0; 100], b"", 1).is_err());
        assert!(tree(&[0; BLOCK], b"", 1).is_err());
        assert_eq!(pad(vec![1; 5]).len(), BLOCK);
        assert_eq!(unhex("0aff"), Some(vec![10, 255]));
        assert_eq!(unhex("0g"), None);
    }

    /// A slot in memory that remembers the largest read it was asked for.
    struct Slot {
        bytes: Vec<u8>,
        largest: std::sync::atomic::AtomicUsize,
    }

    impl ReadAt for Slot {
        fn read_exact_at(&self, buf: &mut [u8], at: u64) -> std::io::Result<()> {
            self.largest
                .fetch_max(buf.len(), std::sync::atomic::Ordering::Relaxed);
            let src = usize::try_from(at)
                .ok()
                .and_then(|a| self.bytes.get(a..a + buf.len()))
                .ok_or(std::io::ErrorKind::UnexpectedEof)?;
            buf.copy_from_slice(src);
            Ok(())
        }
    }

    /// `blocks` of data and their tree, as a slot holds them, at `at`.
    fn slot(blocks: usize, at: usize) -> (Slot, Tree) {
        let d = data(blocks);
        let t = tree(&d, b"salt", 1).unwrap();
        let mut bytes = vec![0xA5; at];
        bytes.extend_from_slice(&d);
        bytes.extend_from_slice(&t.bytes);
        let s = Slot {
            bytes,
            largest: Default::default(),
        };
        (s, t)
    }

    fn check(s: &Slot, at: usize, t: &Tree, threads: usize) -> Result<bool, String> {
        let size = (t.data_blocks as usize * BLOCK + t.bytes.len()) as u64;
        check_at(
            s,
            at as u64,
            size,
            t.data_blocks,
            b"salt",
            &hex(&t.root),
            threads,
        )
    }

    /// G0.30j: the read-back check of a slot (install, update, scrub) read
    /// the whole slot (150 MiB) into memory at once; the kernel killed the
    /// daemon of the 448 MiB live image for it, in the middle of an install.
    /// Now no read is larger than `READ`, whatever the slot's size.
    #[test]
    fn a_slot_is_checked_a_piece_at_a_time() {
        let (s, t) = slot(5 * READ / BLOCK + 77, 8192);
        assert_eq!(check(&s, 8192, &t, 1), Ok(true));
        let largest = s.largest.load(std::sync::atomic::Ordering::Relaxed);
        assert!(largest <= READ, "a read of {largest} bytes");
    }

    #[test]
    fn every_byte_of_the_slot_counts() {
        let at = 4096;
        let (good, t) = slot(300, at);
        assert_eq!(check(&good, at, &t, 1), Ok(true));
        let data_len = 300 * BLOCK;
        // A byte of data, of the tree, of its padding.
        for i in [
            0,
            123_457,
            data_len - 1,
            data_len,
            data_len + t.bytes.len() - 1,
        ] {
            let mut bad = Slot {
                bytes: good.bytes.clone(),
                largest: Default::default(),
            };
            bad.bytes[at + i] ^= 1;
            assert_eq!(check(&bad, at, &t, 1), Ok(false), "byte {i}");
        }
        let size = (data_len + t.bytes.len()) as u64;
        let root = hex(&t.root);
        assert_eq!(
            check_at(&good, at as u64, size + 1, 300, b"salt", &root, 1),
            Ok(false)
        );
        assert_eq!(
            check_at(&good, at as u64, size, 300, b"other", &root, 1),
            Ok(false)
        );
        assert_eq!(
            check_at(&good, at as u64, size, 300, b"salt", &hex(&[0; 32]), 1),
            Ok(false)
        );
        // Shorter than it says: an error, not a pass.
        let mut short = Slot {
            bytes: good.bytes.clone(),
            largest: Default::default(),
        };
        short.bytes.pop();
        assert!(check(&short, at, &t, 1).is_err());
        assert!(check_at(&good, 0, size, 1, b"salt", &root, 1).is_err());
    }

    #[test]
    fn threads_check_the_same_slot() {
        let blocks = PARALLEL_MIN / BLOCK + 300;
        let (good, t) = slot(blocks, 0);
        assert_eq!(check(&good, 0, &t, 7), Ok(true));
        let mut bad = Slot {
            bytes: good.bytes,
            largest: Default::default(),
        };
        bad.bytes[blocks * BLOCK - 5] ^= 1;
        assert_eq!(check(&bad, 0, &t, 7), Ok(false));
    }

    /// Same root hash and tree bytes as `veritysetup format` (cryptsetup),
    /// when the host has it (it runs on plain files, no root needed).
    #[test]
    fn matches_veritysetup() {
        let Ok(dir) = std::env::var("CARGO_TARGET_TMPDIR")
            .or_else(|_| std::env::temp_dir().to_str().map(str::to_owned).ok_or(()))
        else {
            return;
        };
        let dir = std::path::Path::new(&dir).join(format!("verity-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let d = data(1000);
        std::fs::write(dir.join("data"), &d).unwrap();
        let salt = "00112233445566778899aabbccddeeff";
        let out = std::process::Command::new("veritysetup")
            .args(["format", "--no-superblock", "--format=1", "--hash=sha256"])
            .args(["--data-block-size=4096", "--hash-block-size=4096"])
            .arg(format!("--salt={salt}"))
            .arg(dir.join("data"))
            .arg(dir.join("hash"))
            .output();
        let Ok(out) = out else {
            eprintln!("veritysetup not installed: skipped");
            return;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let want = text
            .lines()
            .find_map(|l| l.strip_prefix("Root hash:"))
            .map(|h| h.trim().to_owned())
            .unwrap();
        let t = tree(&d, &unhex(salt).unwrap(), 1).unwrap();
        assert_eq!(hex(&t.root), want);
        assert_eq!(std::fs::read(dir.join("hash")).unwrap(), t.bytes);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
