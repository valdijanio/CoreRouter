//! `corerouter-image` (G1.6b): the build side of the A/B image, run by
//! `cargo xtask os` and the Buildroot `post-image.sh` (the xtask may not
//! use workspace crates, `cargo xtask layers`).
//!
//! - `seal <images>`: the squashfs plus its dm-verity tree becomes
//!   `rootfs.img`, the manifest is signed, the ESP gets slot A's kernel
//!   (`BOOTX64.EFI`) and signed header, and `corerouter.crpkg` (this build's
//!   update package) is written. Metadata from `$CR_SEAL_*`.
//! - `key --keys <dir> [--key <pkcs8>]`: the signing key (given, from
//!   `$COREROUTER_IMAGE_KEY`, or a development key made once in `<dir>`)
//!   and `<dir>/pub/<id>.pub`, the public key the image trusts; prints both
//!   paths as JSON.
//! - `package …`: another package of the sealed build.
//! - `info <package>`: the manifest, as JSON.
//! - `genkey <file>`: a fresh Ed25519 key (tests: a key nobody trusts).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use corerouter_sysupdate::package::{self, Blob, Manifest, Rootfs};
use corerouter_sysupdate::verity;

const USAGE: &str = "usage: corerouter-image <seal IMAGES | key --keys DIR [--key PKCS8] | package --images DIR (--keys DIR | --key PKCS8) --out FILE [--version V] [--build N] [--channel C] [--squashfs FILE] | info PACKAGE | genkey FILE>";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or(&[]);
    let res = match args.first().map(String::as_str) {
        Some("seal") => seal(rest),
        Some("key") => key_cmd(rest),
        Some("package") => package_cmd(rest),
        Some("info") => info(rest),
        Some("genkey") => genkey(rest),
        _ => Err(USAGE.into()),
    };
    if let Err(e) = res {
        let _ = writeln!(std::io::stderr(), "corerouter-image: {e}");
        std::process::exit(1);
    }
}

fn key_cmd(args: &[String]) -> Result<(), String> {
    let mut keys = None;
    let mut key = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--keys" => keys = it.next().map(PathBuf::from),
            "--key" => key = it.next().map(PathBuf::from),
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    let (k, pubdir) = ensure_key(&keys.ok_or("--keys <dir> is required")?, key.as_deref())?;
    let out = serde_json::json!({"key": k, "pub": pubdir});
    let _ = writeln!(std::io::stdout(), "{out}");
    Ok(())
}

fn info(args: &[String]) -> Result<(), String> {
    let p = args
        .first()
        .ok_or("usage: corerouter-image info <package>")?;
    let mut f = std::fs::File::open(p).map_err(|e| format!("{p}: {e}"))?;
    let h = package::Header::read(&mut f)?;
    let text = serde_json::to_string(&h.manifest).map_err(|e| e.to_string())?;
    let _ = writeln!(std::io::stdout(), "{text}");
    Ok(())
}

fn genkey(args: &[String]) -> Result<(), String> {
    let p = args
        .first()
        .ok_or("usage: corerouter-image genkey <file>")?;
    let _ = std::fs::remove_file(p);
    write_private(Path::new(p), &package::generate_key()?)
}

/// The development signing key and the directory of public keys the image
/// trusts, made on first use.
fn ensure_key(keys: &Path, given: Option<&Path>) -> Result<(PathBuf, PathBuf), String> {
    let pubdir = keys.join("pub");
    std::fs::create_dir_all(&pubdir).map_err(|e| e.to_string())?;
    let key = match given {
        Some(k) => k.to_owned(),
        None => match std::env::var_os("COREROUTER_IMAGE_KEY") {
            Some(k) => PathBuf::from(k),
            None => {
                let k = keys.join("dev-image-key.pk8");
                if !k.exists() {
                    let pk8 = package::generate_key()?;
                    write_private(&k, &pk8)?;
                    let _ = writeln!(
                        std::io::stderr(),
                        "   generated a development image key: {}",
                        k.display()
                    );
                }
                k
            }
        },
    };
    let pk8 = std::fs::read(&key).map_err(|e| format!("{}: {e}", key.display()))?;
    let public = package::public_hex(&pk8)?;
    let id = package::Key::from_hex(&public)
        .ok_or("public key")?
        .id_hex();
    for e in std::fs::read_dir(&pubdir)
        .map_err(|e| e.to_string())?
        .flatten()
    {
        let _ = std::fs::remove_file(e.path());
    }
    std::fs::write(pubdir.join(format!("{id}.pub")), format!("{public}\n"))
        .map_err(|e| e.to_string())?;
    Ok((key, pubdir))
}

#[cfg(unix)]
fn write_private(p: &Path, data: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(p)
        .map_err(|e| format!("{}: {e}", p.display()))?;
    f.write_all(data).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn write_private(p: &Path, data: &[u8]) -> Result<(), String> {
    std::fs::write(p, data).map_err(|e| format!("{}: {e}", p.display()))
}

/// What a package says about itself, besides its payload.
pub struct Meta {
    pub version: String,
    pub build: u64,
    pub commit: String,
    pub channel: String,
    pub kernel_version: String,
    pub config_format: u32,
}

fn env_meta() -> Result<Meta, String> {
    let get = |k: &str| {
        std::env::var(k).map_err(|_| format!("${k} not set (run through cargo xtask os build)"))
    };
    Ok(Meta {
        version: get("CR_SEAL_VERSION")?,
        build: get("CR_SEAL_BUILD")?.parse().map_err(|_| "CR_SEAL_BUILD")?,
        commit: get("COREROUTER_COMMIT")?,
        channel: get("CR_SEAL_CHANNEL")?,
        kernel_version: get("CR_SEAL_KERNEL_VERSION")?,
        config_format: get("CR_SEAL_CONFIG_FORMAT")?
            .parse()
            .map_err(|_| "CR_SEAL_CONFIG_FORMAT")?,
    })
}

/// The squashfs padded, its tree appended: what a slot partition holds.
fn rootfs_image(squashfs: &[u8]) -> Result<(Vec<u8>, verity::Tree, Vec<u8>), String> {
    let data = verity::pad(squashfs.to_vec());
    // Deterministic salt (reproducible image), different per image.
    let salt = package::sha256_hex(&data);
    let salt = verity::unhex(salt.get(..32).unwrap_or("00")).ok_or("salt")?;
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let tree = verity::tree(&data, &salt, threads)?;
    let mut img = data;
    img.extend_from_slice(&tree.bytes);
    Ok((img, tree, salt))
}

/// Signs and writes a package of `kernel` + `squashfs`; returns the header
/// and the slot image.
pub fn make_package(
    kernel: &[u8],
    squashfs: &[u8],
    meta: &Meta,
    key: &[u8],
    out: &Path,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (img, tree, salt) = rootfs_image(squashfs)?;
    let m = Manifest {
        format: 1,
        version: meta.version.clone(),
        build: meta.build,
        commit: meta.commit.clone(),
        channel: meta.channel.clone(),
        kernel_version: meta.kernel_version.clone(),
        config_format: meta.config_format,
        kernel: Blob {
            size: kernel.len() as u64,
            sha256: package::sha256_hex(kernel),
        },
        rootfs: Rootfs {
            size: img.len() as u64,
            sha256: package::sha256_hex(&img),
            data_blocks: tree.data_blocks,
            hash_blocks: tree.hash_blocks,
            salt: verity::hex(&salt),
            root_hash: verity::hex(&tree.root),
        },
    };
    let header = package::sign(&m, key)?;
    let mut f = std::fs::File::create(out).map_err(|e| format!("{}: {e}", out.display()))?;
    for part in [&header[..], kernel, &img] {
        f.write_all(part).map_err(|e| e.to_string())?;
    }
    Ok((header, img))
}

fn read(p: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))
}

/// `corerouter-image seal <images>` (from post-image.sh).
fn seal(args: &[String]) -> Result<(), String> {
    let t = Instant::now();
    let images = PathBuf::from(
        args.first()
            .ok_or("usage: corerouter-image seal <images dir>")?,
    );
    let key_path = std::env::var("CR_SEAL_KEY").map_err(|_| "$CR_SEAL_KEY not set")?;
    let key = read(Path::new(&key_path))?;
    let meta = env_meta()?;
    let kernel = read(&images.join("bzImage"))?;
    let squashfs = read(&images.join("rootfs.squashfs"))?;
    let pkg = images.join("corerouter.crpkg");
    let (header, img) = make_package(&kernel, &squashfs, &meta, &key, &pkg)?;
    std::fs::write(images.join("rootfs.img"), &img).map_err(|e| e.to_string())?;
    let esp = images.join("efi-part/EFI");
    for d in ["BOOT", "COREROUTER"] {
        std::fs::create_dir_all(esp.join(d)).map_err(|e| e.to_string())?;
    }
    std::fs::write(esp.join("BOOT/BOOTX64.EFI"), &kernel).map_err(|e| e.to_string())?;
    std::fs::write(esp.join("COREROUTER/A.HDR"), &header).map_err(|e| e.to_string())?;
    let size = std::fs::metadata(&pkg).map(|m| m.len()).unwrap_or(0);
    let _ = writeln!(
        std::io::stderr(),
        "   sealed {} ({}): rootfs.img {:.1} MiB (verity tree {} KiB), package {:.1} MiB, {} ms",
        meta.version,
        meta.commit,
        img.len() as f64 / 1048576.0,
        (img.len() - verity::pad(squashfs).len()) / 1024,
        size as f64 / 1048576.0,
        t.elapsed().as_millis()
    );
    Ok(())
}

/// The metadata of the sealed build, from its package.
fn built(images: &Path) -> Result<(Manifest, Vec<u8>, Vec<u8>), String> {
    let mut f = std::fs::File::open(images.join("corerouter.crpkg"))
        .map_err(|e| format!("corerouter.crpkg: {e} (run cargo xtask os build)"))?;
    let h = package::Header::read(&mut f)?;
    let kernel = read(&images.join("bzImage"))?;
    let squashfs = read(&images.join("rootfs.squashfs"))?;
    Ok((h.manifest, kernel, squashfs))
}

fn meta_of(m: &Manifest) -> Meta {
    Meta {
        version: m.version.clone(),
        build: m.build,
        commit: m.commit.clone(),
        channel: m.channel.clone(),
        kernel_version: m.kernel_version.clone(),
        config_format: m.config_format,
    }
}

/// `corerouter-image package --images DIR --keys DIR --out FILE [--version V]
/// [--build N] [--channel C] [--key PKCS8] [--squashfs FILE]`: another package
/// of the sealed build (`--squashfs`: another root file system).
fn package_cmd(args: &[String]) -> Result<(), String> {
    let mut images = None;
    let mut keys = None;
    let mut out = None;
    let mut key = None;
    let mut squashfs_path = None;
    let mut over: Vec<(String, String)> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or(format!("{a} needs a value"));
        match a.as_str() {
            "--images" => images = Some(PathBuf::from(val()?)),
            "--keys" => keys = Some(PathBuf::from(val()?)),
            "--out" => out = Some(PathBuf::from(val()?)),
            "--key" => key = Some(PathBuf::from(val()?)),
            "--squashfs" => squashfs_path = Some(PathBuf::from(val()?)),
            "--version" | "--build" | "--channel" => over.push((a.clone(), val()?)),
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    let images = images.ok_or("--images <dir> is required")?;
    let (m, kernel, mut squashfs) = built(&images)?;
    if let Some(p) = squashfs_path {
        squashfs = read(&p)?;
    }
    let mut meta = meta_of(&m);
    for (k, v) in over {
        match k.as_str() {
            "--version" => meta.version = v,
            "--build" => meta.build = v.parse().map_err(|_| "--build: a number")?,
            _ => meta.channel = v,
        }
    }
    let out = out.ok_or("--out <file> is required")?;
    let key = match (key, keys) {
        (Some(k), _) => k,
        (None, Some(dir)) => ensure_key(&dir, None)?.0,
        (None, None) => return Err("--key <pkcs8> or --keys <dir>".into()),
    };
    make_package(&kernel, &squashfs, &meta, &read(&key)?, &out)?;
    let _ = writeln!(
        std::io::stderr(),
        "{} ({} build {})",
        out.display(),
        meta.version,
        meta.build
    );
    Ok(())
}
