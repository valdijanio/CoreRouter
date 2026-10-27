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

/// One level: `blocks` (each `BLOCK` long, the last zero-padded by the
/// caller) hashed into hash blocks.
fn level(salt: &[u8], data: &[u8], threads: usize) -> Vec<u8> {
    let n = data.len() / BLOCK;
    let hash_blocks = n.div_ceil(PER_BLOCK);
    let mut out = vec![0u8; hash_blocks * BLOCK];
    let hash_into = |src: &[u8], dst: &mut [u8]| {
        for (blk, slot) in src.chunks(BLOCK).zip(dst.chunks_mut(DIGEST)) {
            slot.copy_from_slice(&digest(salt, blk));
        }
    };
    if threads <= 1 || data.len() < PARALLEL_MIN {
        // Digests are contiguous across hash blocks (128 per block, no gap).
        hash_into(data, &mut out);
        return out;
    }
    // Split by whole hash blocks: thread i owns hash blocks [a, b) and the
    // data blocks they cover.
    let per = hash_blocks.div_ceil(threads);
    std::thread::scope(|s| {
        let mut rest: &mut [u8] = &mut out;
        let mut first = 0usize;
        while first < hash_blocks {
            let count = per.min(hash_blocks - first);
            let (mine, tail) = std::mem::take(&mut rest).split_at_mut(count * BLOCK);
            rest = tail;
            let start = first * PER_BLOCK * BLOCK;
            let end = ((first + count) * PER_BLOCK * BLOCK).min(data.len());
            let src = data.get(start..end).unwrap_or(&[]);
            s.spawn(move || hash_into(src, mine));
            first += count;
        }
    });
    out
}

/// The tree of `data` (a multiple of [`BLOCK`], at least two blocks).
/// `threads`: level 0 is split over this many when `data` is large.
pub fn tree(data: &[u8], salt: &[u8], threads: usize) -> Result<Tree, String> {
    if !data.len().is_multiple_of(BLOCK) || data.len() < 2 * BLOCK {
        return Err(format!(
            "verity: {} bytes is not a multiple of {BLOCK} of at least two blocks",
            data.len()
        ));
    }
    let mut levels: Vec<Vec<u8>> = Vec::new();
    let mut cur = level(salt, data, threads);
    loop {
        let blocks = cur.len() / BLOCK;
        if blocks <= 1 {
            levels.push(cur);
            break;
        }
        let next = level(salt, &cur, 1);
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
        data_blocks: (data.len() / BLOCK) as u64,
        hash_blocks: (bytes.len() / BLOCK) as u64,
        root,
        bytes,
    })
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
