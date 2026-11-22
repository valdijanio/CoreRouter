//! The update package (`.crpkg`): a signed header, then the payload.
//!
//! ```text
//! "CRPKG\0\x01\n"           magic, format 1
//! u32 LE                    manifest length (≤ 16 KiB)
//! manifest                  JSON, [`Manifest`]
//! [8]                       key id: first 8 bytes of SHA-256(public key)
//! [64]                      Ed25519 signature of everything above
//! kernel                    `manifest.kernel.size` bytes (EFI stub)
//! rootfs                    `manifest.rootfs.size` bytes: squashfs padded to
//!                           4 KiB + its dm-verity tree
//! ```
//!
//! The header comes first so the signature is checked before a byte is
//! written; the payload is then streamed to the slot and hashed on the way
//! (SHA-256 of each part, in the signed manifest). A header is also what the
//! ESP keeps next to each slot's kernel (`A.hdr`): the slot's signed
//! description, checked again whenever it is read.

use std::io::{Read, Write};
use std::path::Path;

use ring::digest::{Context, SHA256};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

use crate::verity::{hex, unhex};

pub const MAGIC: &[u8; 8] = b"CRPKG\0\x01\n";
const MAX_MANIFEST: usize = 16 << 10;
pub const MAX_KERNEL: u64 = 128 << 20;
pub const MAX_ROOTFS: u64 = 4 << 30;
const CHUNK: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blob {
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rootfs {
    pub size: u64,
    pub sha256: String,
    pub data_blocks: u64,
    pub hash_blocks: u64,
    pub salt: String,
    pub root_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    /// What the operator reads (`0.1.0`).
    pub version: String,
    /// Orders versions: the commit time of the build (reproducible,
    /// grows along `main`). An update must not go below the running one.
    pub build: u64,
    pub commit: String,
    /// `stable`, `testing`, `long-term`, `development` (RouterOS channels).
    pub channel: String,
    pub kernel_version: String,
    /// The configuration `format_version` this image's daemon reads.
    pub config_format: u32,
    pub kernel: Blob,
    pub rootfs: Rootfs,
}

pub const CHANNELS: &[&str] = &["stable", "testing", "long-term", "development"];

impl Manifest {
    fn check(&self) -> Result<(), String> {
        let bad = |what: &str| Err(format!("package manifest: {what}"));
        if self.format != 1 {
            return bad(&format!("format {} (this build reads 1)", self.format));
        }
        if self.version.is_empty() || self.version.len() > 64 || self.commit.len() > 64 {
            return bad("version or commit missing or too long");
        }
        if !CHANNELS.contains(&self.channel.as_str()) {
            return bad("unknown channel");
        }
        if self.kernel.size == 0 || self.kernel.size > MAX_KERNEL {
            return bad("kernel size");
        }
        let r = &self.rootfs;
        if r.data_blocks < 2
            || r.size != (r.data_blocks + r.hash_blocks) * crate::verity::BLOCK as u64
            || r.size > MAX_ROOTFS
        {
            return bad("rootfs size does not match its blocks");
        }
        for h in [&self.kernel.sha256, &r.sha256, &r.root_hash] {
            if h.len() != 64 || unhex(h).is_none() {
                return bad("hash is not 64 hex digits");
            }
        }
        if unhex(&r.salt).is_none_or(|s| s.is_empty() || s.len() > 64) {
            return bad("salt");
        }
        Ok(())
    }
}

/// A trusted image key (`/etc/corerouter/image-keys/<id>.pub`: the raw
/// Ed25519 public key in hex).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub id: [u8; 8],
    pub public: Vec<u8>,
}

pub fn key_id(public: &[u8]) -> [u8; 8] {
    let d = ring::digest::digest(&SHA256, public);
    let mut id = [0u8; 8];
    id.copy_from_slice(d.as_ref().get(..8).unwrap_or(&[0; 8]));
    id
}

impl Key {
    pub fn from_hex(text: &str) -> Option<Key> {
        let public = unhex(text.trim())?;
        (public.len() == 32).then(|| Key {
            id: key_id(&public),
            public,
        })
    }

    pub fn id_hex(&self) -> String {
        hex(&self.id)
    }
}

/// Every `*.pub` in `dir` (unreadable or malformed files are skipped).
pub fn load_keys(dir: &Path) -> Vec<Key> {
    let mut keys: Vec<Key> = std::fs::read_dir(dir)
        .map(|d| {
            d.flatten()
                .filter(|e| e.path().extension().is_some_and(|x| x == "pub"))
                .filter_map(|e| Key::from_hex(&std::fs::read_to_string(e.path()).ok()?))
                .collect()
        })
        .unwrap_or_default();
    keys.sort_by_key(|k| k.id);
    keys
}

/// The signed header: the manifest and the bytes it was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub manifest: Manifest,
    pub key_id: [u8; 8],
    /// The whole header as on disk (what `A.hdr` holds).
    pub bytes: Vec<u8>,
}

impl Header {
    /// Reads the header from the start of a package; checks the format,
    /// not the signature ([`Header::verify`]).
    pub fn read(r: &mut impl Read) -> Result<Header, String> {
        let mut head = [0u8; 12];
        r.read_exact(&mut head)
            .map_err(|e| format!("package: {e}"))?;
        if head.get(..8) != Some(MAGIC.as_slice()) {
            return Err("not a CoreRouter package (bad magic)".into());
        }
        let len = u32::from_le_bytes([head[8], head[9], head[10], head[11]]) as usize;
        if len == 0 || len > MAX_MANIFEST {
            return Err(format!("package: manifest of {len} bytes"));
        }
        let mut rest = vec![0u8; len + 8 + 64];
        r.read_exact(&mut rest)
            .map_err(|e| format!("package header: {e}"))?;
        let mut bytes = head.to_vec();
        bytes.extend_from_slice(&rest);
        Self::parse(bytes)
    }

    pub fn parse(bytes: Vec<u8>) -> Result<Header, String> {
        let len = bytes
            .get(8..12)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or("package header truncated")? as usize;
        if bytes.get(..8) != Some(MAGIC.as_slice())
            || len > MAX_MANIFEST
            || bytes.len() != 12 + len + 72
        {
            return Err("package header malformed".into());
        }
        let text = bytes.get(12..12 + len).ok_or("package header truncated")?;
        let manifest: Manifest =
            serde_json::from_slice(text).map_err(|e| format!("package manifest: {e}"))?;
        manifest.check()?;
        let mut key_id = [0u8; 8];
        key_id.copy_from_slice(bytes.get(12 + len..20 + len).ok_or("truncated")?);
        Ok(Header {
            manifest,
            key_id,
            bytes,
        })
    }

    pub fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The trusted key that signed it, or why none did.
    pub fn verify<'k>(&self, keys: &'k [Key]) -> Result<&'k Key, String> {
        let signed_len = self.bytes.len().saturating_sub(64);
        let (signed, sig) = self.bytes.split_at(signed_len);
        let key = keys.iter().find(|k| k.id == self.key_id).ok_or_else(|| {
            format!(
                "signed by key {}, which this image does not trust ({} trusted)",
                hex(&self.key_id),
                keys.len()
            )
        })?;
        UnparsedPublicKey::new(&ED25519, &key.public)
            .verify(signed, sig)
            .map_err(|_| format!("bad signature (key {})", key.id_hex()))?;
        Ok(key)
    }
}

/// Builds a package (xtask): the header signed with `pkcs8` (Ed25519).
pub fn sign(manifest: &Manifest, pkcs8: &[u8]) -> Result<Vec<u8>, String> {
    manifest.check()?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|e| format!("signing key: {e}"))?;
    let text = serde_json::to_vec(manifest).map_err(|e| e.to_string())?;
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(
        &u32::try_from(text.len())
            .map_err(|e| e.to_string())?
            .to_le_bytes(),
    );
    out.extend_from_slice(&text);
    out.extend_from_slice(&key_id(pair.public_key().as_ref()));
    let sig = pair.sign(&out);
    out.extend_from_slice(sig.as_ref());
    Ok(out)
}

/// A detached signature of `msg` (G1.6c: the installer's payload index):
/// the signing key's id (8 bytes) then the Ed25519 signature (64).
pub fn sign_detached(msg: &[u8], pkcs8: &[u8]) -> Result<Vec<u8>, String> {
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|e| format!("signing key: {e}"))?;
    let mut out = key_id(pair.public_key().as_ref()).to_vec();
    out.extend_from_slice(pair.sign(msg).as_ref());
    Ok(out)
}

/// The trusted key whose [`sign_detached`] signature `sig` is, or why none.
pub fn verify_detached<'k>(msg: &[u8], sig: &[u8], keys: &'k [Key]) -> Result<&'k Key, String> {
    let (Some(id), Some(s)) = (sig.get(..8), sig.get(8..)) else {
        return Err("signature truncated".into());
    };
    if s.len() != 64 {
        return Err(format!("signature of {} bytes", sig.len()));
    }
    let key = keys.iter().find(|k| k.id == id).ok_or_else(|| {
        format!(
            "signed by key {}, which this image does not trust ({} trusted)",
            hex(id),
            keys.len()
        )
    })?;
    UnparsedPublicKey::new(&ED25519, &key.public)
        .verify(msg, s)
        .map_err(|_| format!("bad signature (key {})", key.id_hex()))?;
    Ok(key)
}

pub fn public_hex(pkcs8: &[u8]) -> Result<String, String> {
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|e| format!("signing key: {e}"))?;
    Ok(hex(pair.public_key().as_ref()))
}

pub fn generate_key() -> Result<Vec<u8>, String> {
    let rng = ring::rand::SystemRandom::new();
    Ed25519KeyPair::generate_pkcs8(&rng)
        .map(|d| d.as_ref().to_vec())
        .map_err(|e| format!("key generation: {e}"))
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(ring::digest::digest(&SHA256, data).as_ref())
}

/// How a payload copy went.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Copied {
    pub bytes: u64,
    pub millis: u64,
    /// Lowercase hex SHA-256 of each part, in order.
    pub sha256: Vec<String>,
}

/// Copies `parts` (sizes, and where each goes) from `src`, hashing each part.
/// With `pipelined`, one thread reads and hashes while this one writes
/// (bounded: four 1 MiB buffers in flight); otherwise read, hash and write
/// take turns. `progress(bytes)` is called after each chunk is written.
pub fn copy<R: Read + Send>(
    src: &mut R,
    parts: &mut [(u64, &mut dyn Write)],
    pipelined: bool,
    progress: &mut dyn FnMut(u64),
) -> Result<Copied, String> {
    let t = std::time::Instant::now();
    let sizes: Vec<u64> = parts.iter().map(|(s, _)| *s).collect();
    let total: u64 = sizes.iter().sum();
    let mut done = 0u64;
    let digests = if pipelined {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Result<(usize, Vec<u8>), String>>(4);
        let (back_tx, back_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        std::thread::scope(|s| -> Result<Vec<String>, String> {
            let reader = std::thread::Builder::new()
                .name("pkg-read".into())
                .spawn_scoped(s, move || {
                    let mut out = Vec::new();
                    for (i, size) in sizes.iter().enumerate() {
                        let mut ctx = Context::new(&SHA256);
                        let mut left = *size;
                        while left > 0 {
                            let n = (left as usize).min(CHUNK);
                            let mut buf = back_rx.try_recv().unwrap_or_default();
                            buf.resize(n, 0);
                            if let Err(e) = src.read_exact(&mut buf) {
                                let _ = tx.send(Err(format!("package payload: {e}")));
                                return out;
                            }
                            ctx.update(&buf);
                            left -= n as u64;
                            if tx.send(Ok((i, buf))).is_err() {
                                return out;
                            }
                        }
                        out.push(hex(ctx.finish().as_ref()));
                    }
                    out
                })
                .map_err(|e| format!("thread: {e}"))?;
            let mut failed = None;
            for msg in rx.iter() {
                match msg {
                    Ok((i, buf)) => {
                        if failed.is_none() {
                            let w = parts.get_mut(i).map(|(_, w)| w);
                            if let Some(w) = w
                                && let Err(e) = w.write_all(&buf)
                            {
                                failed = Some(format!("write: {e}"));
                            }
                            done += buf.len() as u64;
                            progress(done);
                        }
                        let _ = back_tx.send(buf);
                    }
                    Err(e) => failed = Some(e),
                }
                if failed.is_some() {
                    break;
                }
            }
            drop(rx);
            let digests = reader
                .join()
                .map_err(|_| "reader thread panicked".to_string())?;
            match failed {
                Some(e) => Err(e),
                None => Ok(digests),
            }
        })?
    } else {
        let mut out = Vec::new();
        let mut buf = vec![0u8; CHUNK];
        for (size, w) in parts.iter_mut() {
            let mut ctx = Context::new(&SHA256);
            let mut left = *size;
            while left > 0 {
                let n = (left as usize).min(CHUNK);
                let b = buf.get_mut(..n).ok_or("buffer")?;
                src.read_exact(b)
                    .map_err(|e| format!("package payload: {e}"))?;
                ctx.update(b);
                w.write_all(b).map_err(|e| format!("write: {e}"))?;
                left -= n as u64;
                done += n as u64;
                progress(done);
            }
            out.push(hex(ctx.finish().as_ref()));
        }
        out
    };
    if done != total || digests.len() != parts.len() {
        return Err("package payload: short".into());
    }
    Ok(Copied {
        bytes: total,
        millis: t.elapsed().as_millis() as u64,
        sha256: digests,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn manifest(kernel: &[u8], rootfs: &[u8], tree: &crate::verity::Tree) -> Manifest {
        Manifest {
            format: 1,
            version: "0.1.0".into(),
            build: 1000,
            commit: "abc".into(),
            channel: "stable".into(),
            kernel_version: "6.18.59".into(),
            config_format: 1,
            kernel: Blob {
                size: kernel.len() as u64,
                sha256: sha256_hex(kernel),
            },
            rootfs: Rootfs {
                size: rootfs.len() as u64,
                sha256: sha256_hex(rootfs),
                data_blocks: tree.data_blocks,
                hash_blocks: tree.hash_blocks,
                salt: "00".into(),
                root_hash: hex(&tree.root),
            },
        }
    }

    #[test]
    fn sign_and_verify() {
        let key = generate_key().unwrap();
        let other = generate_key().unwrap();
        let trusted = vec![Key::from_hex(&public_hex(&key).unwrap()).unwrap()];
        let data = vec![7u8; 8192];
        let tree = crate::verity::tree(&data, &[0], 1).unwrap();
        let mut rootfs = data.clone();
        rootfs.extend_from_slice(&tree.bytes);
        let m = manifest(b"kernel", &rootfs, &tree);
        let hdr = sign(&m, &key).unwrap();
        let h = Header::read(&mut hdr.as_slice()).unwrap();
        assert_eq!(h.manifest, m);
        assert!(h.verify(&trusted).is_ok());
        // Another key: unknown id.
        let h2 = Header::parse(sign(&m, &other).unwrap()).unwrap();
        assert!(h2.verify(&trusted).unwrap_err().contains("does not trust"));
        // Same key id, a flipped bit in the manifest.
        let mut bad = hdr.clone();
        let at = bad.iter().position(|&b| b == b'6').unwrap();
        bad[at] = b'7';
        let h3 = Header::parse(bad).unwrap();
        assert!(h3.verify(&trusted).unwrap_err().contains("bad signature"));
        // Every truncation is an error, never a panic.
        for cut in 0..hdr.len() {
            assert!(Header::read(&mut &hdr[..cut]).is_err());
        }
    }

    #[test]
    fn detached_signature() {
        let key = generate_key().unwrap();
        let trusted = vec![Key::from_hex(&public_hex(&key).unwrap()).unwrap()];
        let msg = br#"{"files":[]}"#;
        let sig = sign_detached(msg, &key).unwrap();
        assert_eq!(sig.len(), 72);
        assert!(verify_detached(msg, &sig, &trusted).is_ok());
        assert!(
            verify_detached(b"{}", &sig, &trusted)
                .unwrap_err()
                .contains("bad signature")
        );
        let other = sign_detached(msg, &generate_key().unwrap()).unwrap();
        assert!(
            verify_detached(msg, &other, &trusted)
                .unwrap_err()
                .contains("does not trust")
        );
        for cut in 0..sig.len() {
            assert!(verify_detached(msg, &sig[..cut], &trusted).is_err());
        }
    }

    #[test]
    fn manifest_checks() {
        let data = vec![7u8; 8192];
        let tree = crate::verity::tree(&data, &[0], 1).unwrap();
        let mut m = manifest(b"k", &[0; 12288], &tree);
        assert!(m.check().is_ok());
        m.channel = "beta".into();
        assert!(m.check().is_err());
        m.channel = "stable".into();
        m.rootfs.size += 1;
        assert!(m.check().is_err());
    }

    #[test]
    fn copy_both_ways() {
        let payload: Vec<u8> = (0..3_500_000u32).map(|i| (i % 253) as u8).collect();
        for pipelined in [false, true] {
            let mut a = Vec::new();
            let mut b = Vec::new();
            let mut parts: [(u64, &mut dyn Write); 2] = [(1_000_000, &mut a), (2_500_000, &mut b)];
            let mut seen = 0;
            let c = copy(&mut payload.as_slice(), &mut parts, pipelined, &mut |n| {
                seen = n
            })
            .unwrap();
            assert_eq!(seen, 3_500_000);
            assert_eq!(c.sha256[0], sha256_hex(&payload[..1_000_000]));
            assert_eq!(c.sha256[1], sha256_hex(&payload[1_000_000..]));
            assert_eq!(b, &payload[1_000_000..]);
            let mut a = Vec::new();
            let mut parts: [(u64, &mut dyn Write); 1] = [(4_000_000, &mut a)];
            assert!(copy(&mut payload.as_slice(), &mut parts, pipelined, &mut |_| {}).is_err());
        }
    }
}
