//! processo (build rápido da imagem): where `cargo xtask os` keeps its
//! build — the extracted Buildroot and its output (`O=`), ccache, the cargo
//! targets (image, web GUI, the `push` CLI), the test work directories and
//! the image signing key — and how parallel the top-level `make` runs
//! (docs/os-image.md, "Onde fica o build").
//!
//! The directory, first match:
//! 1. `$COREROUTER_OS_OUT`;
//! 2. `os/out` of the checkout when it already holds a signing key (a
//!    checkout that built before this change keeps its key, and so the
//!    routers it updates keep accepting its packages, until it migrates);
//! 3. `/srv/build/os-out/<checkout>-<hash of its path>` when the build disk
//!    exists (one directory per checkout: two worktrees never share a
//!    build);
//! 4. `os/out`.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

pub const ENV: &str = "COREROUTER_OS_OUT";
/// The machine's build disk (CLAUDE.md, "Disco de builds").
const BUILD_DISK: &str = "/srv/build";

#[derive(Debug, PartialEq)]
pub enum Source {
    Env,
    /// `os/out` with a key in it, from before the build disk.
    Legacy,
    BuildDisk,
    Checkout,
}

#[derive(Debug)]
pub struct Out {
    pub dir: PathBuf,
    pub source: Source,
}

/// The pure choice (tests): `legacy_key` = `os/out/keys` holds a key.
fn choose(root: &Path, env: Option<OsString>, legacy_key: bool, build_disk: Option<&Path>) -> Out {
    let legacy = root.join("os/out");
    if let Some(e) = env.filter(|e| !e.is_empty()) {
        return Out {
            dir: root.join(e),
            source: Source::Env,
        };
    }
    if legacy_key {
        return Out {
            dir: legacy,
            source: Source::Legacy,
        };
    }
    match build_disk {
        Some(disk) => Out {
            dir: disk.join("os-out").join(checkout_name(root)),
            source: Source::BuildDisk,
        },
        None => Out {
            dir: legacy,
            source: Source::Checkout,
        },
    }
}

/// `<directory name>-<8 hex digits of the checkout's path>`: readable, and
/// two clones with the same name elsewhere still get their own build.
fn checkout_name(root: &Path) -> String {
    let name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "corerouter".into());
    let hash = Sha256::digest(root.as_os_str().as_encoded_bytes());
    let hex: String = hash.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("{name}-{hex}")
}

fn has_key(keys: &Path) -> bool {
    std::fs::read_dir(keys).is_ok_and(|mut d| d.next().is_some())
}

pub fn resolve(root: &Path) -> Result<Out, String> {
    let root = std::fs::canonicalize(root).map_err(|e| format!("{}: {e}", root.display()))?;
    let legacy_keys = root.join("os/out/keys");
    let disk = Path::new(BUILD_DISK);
    let writable = std::fs::metadata(disk).is_ok_and(|m| m.is_dir() && !m.permissions().readonly());
    let out = choose(
        &root,
        std::env::var_os(ENV),
        has_key(&legacy_keys),
        writable.then_some(disk),
    );
    // A new directory with no key while the checkout's os/out has one: the
    // build would make another key, and every router updated so far would
    // refuse its packages. Say how to carry the key instead.
    if out.source == Source::Env
        && out.dir != root.join("os/out")
        && !has_key(&out.dir.join("keys"))
        && has_key(&legacy_keys)
    {
        return Err(format!(
            "${ENV}={} has no signing key, and {} has one: copy it first \
             (mkdir -p {dir} && cp -a {legacy} {dir}/), or the routers refuse the new packages \
             (docs/os-image.md, \"Onde fica o build\")",
            out.dir.display(),
            legacy_keys.display(),
            dir = out.dir.display(),
            legacy = legacy_keys.display(),
        ));
    }
    Ok(out)
}

/// One `os build` per directory: an exclusive `flock` held until the
/// build returns (the kernel drops it if the process dies).
pub fn lock(dir: &Path) -> Result<File, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let path = dir.join(".build.lock");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    match file.try_lock() {
        Ok(()) => {
            // Best effort: the note only feeds the message below.
            let _ = file.set_len(0);
            let _ = file.rewind();
            let _ = write!(
                file,
                "pid {} in {}",
                std::process::id(),
                std::env::current_dir().map_or_else(|_| "?".into(), |d| d.display().to_string())
            );
            Ok(file)
        }
        Err(std::fs::TryLockError::WouldBlock) => {
            let mut note = String::new();
            let _ = file.read_to_string(&mut note);
            let note: String = note.trim().chars().take(200).collect();
            Err(format!(
                "another `cargo xtask os build` is using {} ({note})",
                dir.display()
            ))
        }
        Err(std::fs::TryLockError::Error(e)) => Err(format!("{}: {e}", path.display())),
    }
}

/// Top-level `make -j` of `make all` when `--top-jobs` is not given: a
/// quarter of the cores (each package already runs `BR2_JLEVEL` = cores + 1
/// jobs inside), at most one per 4 GiB available, at least 2.
fn top_jobs_for(cpus: usize, mem_available_gib: Option<u64>) -> usize {
    let by_mem =
        mem_available_gib.map_or(usize::MAX, |g| usize::try_from(g / 4).unwrap_or(usize::MAX));
    (cpus / 4).min(by_mem).max(2)
}

fn mem_available_gib(meminfo: &str) -> Option<u64> {
    meminfo
        .lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))
        .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
        .map(|kb| kb / (1024 * 1024))
}

/// `(jobs, cpus)`: `make -j<jobs> -l<cpus>` (the load cap stops starting
/// packages while the machine is already busy, e.g. other sessions' CI).
pub fn auto_top_jobs() -> (usize, usize) {
    let cpus = std::thread::available_parallelism().map_or(4, usize::from);
    let mem = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|m| mem_available_gib(&m));
    (top_jobs_for(cpus, mem), cpus)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn where_the_build_goes() {
        let root = Path::new("/w/CoreRouter");
        let disk = Path::new("/srv/build");
        let o = choose(root, None, false, Some(disk));
        assert_eq!(o.source, Source::BuildDisk);
        let name = o
            .dir
            .strip_prefix("/srv/build/os-out")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(name.starts_with("CoreRouter-") && name.len() == 19, "{o:?}");
        // Another checkout with the same name: another directory.
        let other = choose(Path::new("/x/CoreRouter"), None, false, Some(disk));
        assert_ne!(o.dir, other.dir);
        // Same checkout: same directory (incremental).
        assert_eq!(o.dir, choose(root, None, false, Some(disk)).dir);
        // A checkout that already has a key keeps os/out until it migrates.
        let l = choose(root, None, true, Some(disk));
        assert_eq!((l.source, l.dir), (Source::Legacy, root.join("os/out")));
        // The variable wins; relative to the checkout.
        let e = choose(root, Some("/big/out".into()), true, Some(disk));
        assert_eq!((e.source, e.dir), (Source::Env, PathBuf::from("/big/out")));
        let e = choose(root, Some("rel".into()), false, None);
        assert_eq!(e.dir, root.join("rel"));
        let e = choose(root, Some("".into()), false, None);
        assert_eq!((e.source, e.dir), (Source::Checkout, root.join("os/out")));
    }

    #[test]
    fn top_jobs() {
        assert_eq!(top_jobs_for(32, Some(37)), 8);
        assert_eq!(top_jobs_for(32, Some(13)), 3);
        assert_eq!(top_jobs_for(32, Some(2)), 2);
        assert_eq!(top_jobs_for(4, None), 2);
        assert_eq!(top_jobs_for(64, None), 16);
        let m = "MemTotal:       65000000 kB\nMemAvailable:   38797312 kB\n";
        assert_eq!(mem_available_gib(m), Some(37));
        assert_eq!(mem_available_gib("nothing"), None);
    }

    #[test]
    fn one_build_per_directory() {
        let dir = std::env::temp_dir().join(format!("cr-os-out-lock-{}", std::process::id()));
        let held = lock(&dir).unwrap();
        let err = lock(&dir).unwrap_err();
        assert!(err.contains("another") && err.contains("pid"), "{err}");
        drop(held);
        lock(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
