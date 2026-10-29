//! processo (release da imagem): the release signing key, kept apart from
//! the development key and encrypted at rest with a passphrase
//! (docs/release.md, "A chave de release").
//!
//! - `release-key init --dir D`: a new Ed25519 pair; `D/release-image-key.enc`
//!   (the PKCS#8 under Argon2id + ChaCha20-Poly1305) and `D/<id>.pub`, the
//!   public key the release images trust. Refuses a directory that already
//!   has a key.
//! - `release-key check --dir D`: decrypts in memory and prints the key id
//!   (the backup check; nothing is written).
//! - `release-key decrypt --dir D --out F`: the PKCS#8 in `F` (0600, a new
//!   file), for the time of one release build; checked against `D/<id>.pub`.
//!
//! The passphrase comes from the terminal (no echo), or from
//! `$COREROUTER_RELEASE_KEY_PASSPHRASE` for automated tests only.
//!
//! File format (all integers little endian):
//! `MAGIC | m_kib u32 | t u32 | p u32 | salt[16] | nonce[12] | ciphertext+tag`,
//! with everything before the ciphertext as the AEAD's associated data (a
//! changed parameter fails the tag, not just the key derivation).

use std::io::Write;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use corerouter_sysupdate::package;
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};

pub const KEY_FILE: &str = "release-image-key.enc";
const MAGIC: &[u8; 8] = b"CRRKEY1\n";
const HEADER: usize = 8 + 12 + 16 + 12;
/// Argon2id: 128 MiB, 3 passes (one derivation per release, ~0.5 s).
const M_KIB: u32 = 128 * 1024;
const T: u32 = 3;
const P: u32 = 1;
/// Hostile file: refuse parameters that would take the machine down.
const MAX_M_KIB: u32 = 1024 * 1024;
const MAX_T: u32 = 16;
const MAX_P: u32 = 16;
const MIN_PASSPHRASE: usize = 12;
/// A PKCS#8 Ed25519 document is 83–85 bytes; anything far bigger is not one.
const MAX_FILE: u64 = 4096;
pub const PASSPHRASE_ENV: &str = "COREROUTER_RELEASE_KEY_PASSPHRASE";

pub fn main(args: &[String]) -> Result<(), String> {
    let (sub, rest) = args
        .split_first()
        .ok_or("usage: corerouter-image release-key <init --dir D | check --dir D | decrypt --dir D --out F>")?;
    let mut dir = None;
    let mut out = None;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        let mut val = || {
            it.next()
                .map(PathBuf::from)
                .ok_or(format!("{a} needs a value"))
        };
        match a.as_str() {
            "--dir" => dir = Some(val()?),
            "--out" => out = Some(val()?),
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    let dir = dir.ok_or("--dir <directory> is required")?;
    match sub.as_str() {
        "init" => {
            let pass = passphrase(true)?;
            let (id, public) = init(&dir, pass.as_bytes())?;
            let out = serde_json::json!({
                "id": id,
                "public": public,
                "key": dir.join(KEY_FILE),
                "pub": dir.join(format!("{id}.pub")),
            });
            let _ = writeln!(std::io::stdout(), "{out}");
            Ok(())
        }
        "decrypt" => {
            let out = out.ok_or("--out <file> is required")?;
            let pass = passphrase(false)?;
            let pk8 = decrypt_dir(&dir, pass.as_bytes())?;
            crate::write_private(&out, &pk8)?;
            let id = package::Key::from_hex(&package::public_hex(&pk8)?)
                .ok_or("public key")?
                .id_hex();
            let _ = writeln!(std::io::stdout(), "{}", serde_json::json!({"id": id}));
            Ok(())
        }
        "check" => {
            let pass = passphrase(false)?;
            let pk8 = decrypt_dir(&dir, pass.as_bytes())?;
            let id = package::Key::from_hex(&package::public_hex(&pk8)?)
                .ok_or("public key")?
                .id_hex();
            let _ = writeln!(std::io::stdout(), "{}", serde_json::json!({"id": id}));
            Ok(())
        }
        other => Err(format!("release-key: unknown subcommand '{other}'")),
    }
}

fn passphrase(new: bool) -> Result<String, String> {
    if let Ok(p) = std::env::var(PASSPHRASE_ENV) {
        if new && p.chars().count() < MIN_PASSPHRASE {
            return Err(format!(
                "the passphrase needs at least {MIN_PASSPHRASE} characters"
            ));
        }
        return Ok(p);
    }
    let read = |prompt: &str| {
        rpassword::prompt_password(prompt)
            .map_err(|e| format!("passphrase (needs a terminal): {e}"))
    };
    if !new {
        return read("release key passphrase: ");
    }
    let p = read(&format!(
        "new release key passphrase (at least {MIN_PASSPHRASE} characters): "
    ))?;
    if p.chars().count() < MIN_PASSPHRASE {
        return Err(format!(
            "the passphrase needs at least {MIN_PASSPHRASE} characters"
        ));
    }
    if read("again: ")? != p {
        return Err("the passphrases differ".into());
    }
    Ok(p)
}

/// A new pair in `dir` (made 0700); returns the key id and public key (hex).
pub fn init(dir: &Path, pass: &[u8]) -> Result<(String, String), String> {
    if pass.len() < MIN_PASSPHRASE {
        return Err(format!(
            "the passphrase needs at least {MIN_PASSPHRASE} characters"
        ));
    }
    let key = dir.join(KEY_FILE);
    if key.exists() {
        return Err(format!(
            "{} already exists: a release key is made once (to replace it, move the directory away first)",
            key.display()
        ));
    }
    make_dir_private(dir)?;
    let pk8 = package::generate_key()?;
    let public = package::public_hex(&pk8)?;
    let id = package::Key::from_hex(&public)
        .ok_or("public key")?
        .id_hex();
    crate::write_private(&key, &encrypt(&pk8, pass, M_KIB, T, P)?)?;
    std::fs::write(dir.join(format!("{id}.pub")), format!("{public}\n"))
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok((id, public))
}

/// The PKCS#8 of `dir`, checked against the one `*.pub` next to it.
pub fn decrypt_dir(dir: &Path, pass: &[u8]) -> Result<Vec<u8>, String> {
    let key = dir.join(KEY_FILE);
    let len = std::fs::metadata(&key)
        .map_err(|e| format!("{}: {e}", key.display()))?
        .len();
    if len > MAX_FILE {
        return Err(format!("{}: {len} bytes, not a release key", key.display()));
    }
    let pk8 = decrypt(&crate::read(&key)?, pass)?;
    let public = package::public_hex(&pk8)?;
    let pubs = pub_files(dir)?;
    if pubs.len() != 1 {
        return Err(format!(
            "{}: {} *.pub files, expected the one of the key",
            dir.display(),
            pubs.len()
        ));
    }
    let want =
        std::fs::read_to_string(pubs.first().ok_or("no .pub")?).map_err(|e| e.to_string())?;
    if want.trim() != public {
        return Err(format!(
            "{}: the public key next to the key is not its own",
            dir.display()
        ));
    }
    Ok(pk8)
}

fn pub_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    Ok(std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "pub"))
        .collect())
}

fn derive(pass: &[u8], salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; 32], String> {
    let params = Params::new(m, t, p, Some(32)).map_err(|e| format!("argon2: {e}"))?;
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pass, salt, &mut out)
        .map_err(|e| format!("argon2: {e}"))?;
    Ok(out)
}

fn aead(key: &[u8; 32]) -> Result<LessSafeKey, String> {
    UnboundKey::new(&CHACHA20_POLY1305, key)
        .map(LessSafeKey::new)
        .map_err(|_| "aead key".into())
}

pub fn encrypt(pk8: &[u8], pass: &[u8], m: u32, t: u32, p: u32) -> Result<Vec<u8>, String> {
    let rng = SystemRandom::new();
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rng.fill(&mut salt).map_err(|_| "random")?;
    rng.fill(&mut nonce).map_err(|_| "random")?;
    let mut out = MAGIC.to_vec();
    for v in [m, t, p] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    let mut sealed = pk8.to_vec();
    aead(&derive(pass, &salt, m, t, p)?)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&out[..]),
            &mut sealed,
        )
        .map_err(|_| "encrypt")?;
    out.extend_from_slice(&sealed);
    Ok(out)
}

pub fn decrypt(file: &[u8], pass: &[u8]) -> Result<Vec<u8>, String> {
    let (head, sealed) = file
        .split_at_checked(HEADER)
        .ok_or("release key: truncated")?;
    if head.get(..8) != Some(MAGIC.as_slice()) {
        return Err("not a CoreRouter release key (bad magic)".into());
    }
    let u32_at = |i: usize| {
        head.get(i..i + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or("release key: header")
    };
    let (m, t, p) = (u32_at(8)?, u32_at(12)?, u32_at(16)?);
    if m > MAX_M_KIB || t > MAX_T || p > MAX_P {
        return Err(format!(
            "release key: argon2 m={m} t={t} p={p} out of range"
        ));
    }
    let salt = head.get(20..36).ok_or("release key: header")?;
    let nonce: [u8; 12] = head
        .get(36..48)
        .and_then(|b| b.try_into().ok())
        .ok_or("release key: header")?;
    let mut buf = sealed.to_vec();
    let plain = aead(&derive(pass, salt, m, t, p)?)?
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(head),
            &mut buf,
        )
        .map_err(|_| "wrong passphrase (or the key file is damaged)")?;
    Ok(plain.to_vec())
}

#[cfg(unix)]
fn make_dir_private(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    // An existing directory keeps its mode under `create`: set it.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("{}: {e}", dir.display()))
}

#[cfg(not(unix))]
fn make_dir_private(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Small Argon2 parameters: the format is the same.
    const TM: u32 = 64;

    #[test]
    fn round_trip_and_wrong_passphrase() {
        let pk8 = package::generate_key().unwrap();
        let f = encrypt(&pk8, b"correct horse battery", TM, 1, 1).unwrap();
        assert_eq!(decrypt(&f, b"correct horse battery").unwrap(), pk8);
        let e = decrypt(&f, b"correct horse batterz").unwrap_err();
        assert!(e.contains("wrong passphrase"), "{e}");
    }

    #[test]
    fn tampered_header_or_body_fails() {
        let pk8 = package::generate_key().unwrap();
        let f = encrypt(&pk8, b"correct horse battery", TM, 1, 1).unwrap();
        // A parameter is associated data: changing it fails the tag.
        let mut g = f.clone();
        g[12] = 2;
        assert!(decrypt(&g, b"correct horse battery").is_err());
        let mut g = f.clone();
        let last = g.len() - 1;
        g[last] ^= 1;
        assert!(decrypt(&g, b"correct horse battery").is_err());
        assert!(decrypt(&f[..HEADER - 1], b"x").is_err());
        let mut g = f;
        g[0] = b'X';
        assert!(
            decrypt(&g, b"correct horse battery")
                .unwrap_err()
                .contains("magic")
        );
    }

    #[test]
    fn hostile_parameters_are_refused_before_deriving() {
        let mut f = MAGIC.to_vec();
        for v in [u32::MAX, 1, 1] {
            f.extend_from_slice(&v.to_le_bytes());
        }
        f.extend_from_slice(&[0u8; 28 + 16]);
        assert!(decrypt(&f, b"x").unwrap_err().contains("out of range"));
    }

    #[test]
    fn init_makes_a_private_dir_and_refuses_twice() {
        let dir = std::env::temp_dir().join(format!("cr-release-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(init(&dir, b"short").unwrap_err().contains("12"));
        let (id, public) = init(&dir, b"a long enough passphrase").unwrap();
        assert_eq!(id.len(), 16);
        let pub_file = std::fs::read_to_string(dir.join(format!("{id}.pub"))).unwrap();
        assert_eq!(pub_file.trim(), public);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir), 0o700);
            assert_eq!(mode(&dir.join(KEY_FILE)), 0o600);
        }
        assert!(
            init(&dir, b"a long enough passphrase")
                .unwrap_err()
                .contains("already exists")
        );
        let pk8 = decrypt_dir(&dir, b"a long enough passphrase").unwrap();
        assert_eq!(package::public_hex(&pk8).unwrap(), public);
        // Another key's public file next to it: refused.
        std::fs::write(dir.join(format!("{id}.pub")), "00".repeat(32)).unwrap();
        assert!(
            decrypt_dir(&dir, b"a long enough passphrase")
                .unwrap_err()
                .contains("not its own")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
