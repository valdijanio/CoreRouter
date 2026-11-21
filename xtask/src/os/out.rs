//! processo (build rápido da imagem): where `cargo xtask os` keeps its
//! build — the extracted Buildroot and its output (`O=`), ccache, the cargo
//! targets (image, web GUI, the `push` CLI) and the test work directories
//! (not the signing key since G1.6qm: [`dev_keys`]) — and how parallel the
//! top-level `make` runs
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
    let disk = Path::new(BUILD_DISK);
    let writable = std::fs::metadata(disk).is_ok_and(|m| m.is_dir() && !m.permissions().readonly());
    let out = choose(
        &root,
        std::env::var_os(ENV),
        has_key(&root.join("os/out/keys")),
        writable.then_some(disk),
    );
    Ok(out)
}

/// G1.6qm: the variable that moves the development signing key (tests).
pub const DEV_KEY_ENV: &str = "COREROUTER_DEV_KEY_DIR";

/// What [`dev_keys`] does with the shared directory.
#[derive(Debug, PartialEq)]
enum KeyPlan {
    /// It has a key (or none exists anywhere: `corerouter-image key`
    /// makes one there).
    Use,
    /// It has none, and this build directory (or the checkout's old
    /// `os/out`) has one: move a copy there first, so the routers that
    /// trust it keep taking the packages.
    Migrate(PathBuf),
}

fn key_plan(shared_has_key: bool, with_key: &[PathBuf]) -> KeyPlan {
    match with_key.first() {
        Some(from) if !shared_has_key => KeyPlan::Migrate(from.clone()),
        _ => KeyPlan::Use,
    }
}

/// `$XDG_CONFIG_HOME` (absolute only, as the spec says) or `~/.config`.
fn config_home(xdg: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    xdg.map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            home.filter(|h| !h.is_empty())
                .map(|h| PathBuf::from(h).join(".config"))
        })
}

/// The public key ids (`pub/<id>.pub`) in a key directory, sorted.
fn key_ids(keys: &Path) -> Vec<String> {
    let mut ids: Vec<String> = std::fs::read_dir(keys.join("pub"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.strip_suffix(".pub").map(str::to_owned)
        })
        .collect();
    ids.sort();
    ids
}

/// G1.6qm: where the development signing key lives —
/// `$COREROUTER_DEV_KEY_DIR`, or `~/.config/corerouter/dev-image-key/`,
/// one key for every checkout and build directory of the user. It used to
/// live in `<out>/keys/`: deleting a build directory to free disk took the
/// key along, and every router updated from it refused the next package
/// ("signed by key …, which this image does not trust"; the test notebook,
/// 2026-11-21). A build directory that still has its own key hands it over
/// the first time (copied, the old one stays). Without a home directory,
/// `<out>/keys/` as before.
pub fn dev_keys(root: &Path, out: &Path) -> Result<PathBuf, String> {
    let shared = match std::env::var_os(DEV_KEY_ENV).filter(|v| !v.is_empty()) {
        Some(d) => PathBuf::from(d),
        None => match config_home(
            std::env::var_os("XDG_CONFIG_HOME"),
            std::env::var_os("HOME"),
        ) {
            Some(c) => c.join("corerouter/dev-image-key"),
            None => return Ok(out.join("keys")),
        },
    };
    let own = [out.join("keys"), root.join("os/out/keys")];
    let with_key: Vec<PathBuf> = own.iter().filter(|d| has_key(d)).cloned().collect();
    match key_plan(has_key(&shared), &with_key) {
        KeyPlan::Migrate(from) => migrate(&from, &shared)?,
        KeyPlan::Use => {
            let ours = key_ids(&shared);
            for d in &with_key {
                let theirs = key_ids(d);
                if !theirs.is_empty() && theirs != ours {
                    eprintln!(
                        "note: {} holds key {} and the packages are now signed with the shared \
                         key {} ({}); a router updated from that directory refuses them until \
                         it trusts the shared key (docs/os-image.md, \"A chave\")",
                        d.display(),
                        theirs.join(","),
                        ours.join(","),
                        shared.display()
                    );
                }
            }
        }
    }
    Ok(shared)
}

/// Copy `from` (`dev-image-key.pk8`, `pub/*.pub`) to `to` through a
/// temporary directory renamed into place: two builds migrating at once
/// end with one complete copy, never a mix.
fn migrate(from: &Path, to: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let err = |p: &Path, e: std::io::Error| format!("{}: {e}", p.display());
    let parent = to
        .parent()
        .ok_or_else(|| format!("{}: no parent", to.display()))?;
    std::fs::create_dir_all(parent).map_err(|e| err(parent, e))?;
    let tmp = parent.join(format!(".dev-image-key.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("pub")).map_err(|e| err(&tmp, e))?;
    let private = 0o600;
    for (dir, mode) in [(from.to_path_buf(), private), (from.join("pub"), 0o644)] {
        let target = if dir == from {
            tmp.clone()
        } else {
            tmp.join("pub")
        };
        for entry in std::fs::read_dir(&dir).map_err(|e| err(&dir, e))?.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let dst = target.join(entry.file_name());
            std::fs::copy(&path, &dst).map_err(|e| err(&path, e))?;
            std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(mode))
                .map_err(|e| err(&dst, e))?;
        }
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| err(&tmp, e))?;
    match std::fs::rename(&tmp, to) {
        Ok(()) => {
            eprintln!(
                "note: development signing key {} moved to {} (from {}; G1.6qm)",
                key_ids(to).join(","),
                to.display(),
                from.display()
            );
            Ok(())
        }
        // Another build got there first: keep its copy.
        Err(_) if has_key(to) => {
            let _ = std::fs::remove_dir_all(&tmp);
            Ok(())
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            Err(err(to, e))
        }
    }
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
    fn the_dev_key_is_shared_and_migrates_once() {
        let a = PathBuf::from("/srv/build/os-out/a/keys");
        let legacy = PathBuf::from("/w/os/out/keys");
        // Nothing anywhere: the shared directory (the tool makes the key).
        assert_eq!(key_plan(false, &[]), KeyPlan::Use);
        // The shared key wins over a build directory's own.
        assert_eq!(key_plan(true, std::slice::from_ref(&a)), KeyPlan::Use);
        // No shared key yet: the build directory's is carried over, before
        // the checkout's old os/out.
        assert_eq!(key_plan(false, &[a.clone(), legacy]), KeyPlan::Migrate(a));
    }

    #[test]
    fn config_home_follows_xdg() {
        let home = Some(OsString::from("/home/u"));
        assert_eq!(
            config_home(None, home.clone()),
            Some(PathBuf::from("/home/u/.config"))
        );
        assert_eq!(
            config_home(Some("/x/cfg".into()), home.clone()),
            Some(PathBuf::from("/x/cfg"))
        );
        // A relative XDG_CONFIG_HOME is ignored (XDG Base Directory spec).
        assert_eq!(
            config_home(Some("rel".into()), home),
            Some(PathBuf::from("/home/u/.config"))
        );
        assert_eq!(config_home(None, None), None);
        assert_eq!(config_home(None, Some("".into())), None);
    }

    #[test]
    fn migration_copies_the_key_and_keeps_the_old_one() {
        use std::os::unix::fs::PermissionsExt;
        let t = std::env::temp_dir().join(format!("g16qm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        let out = t.join("out/keys");
        std::fs::create_dir_all(out.join("pub")).unwrap();
        std::fs::write(out.join("dev-image-key.pk8"), "secret").unwrap();
        std::fs::write(out.join("pub/abcd.pub"), "pub").unwrap();
        let shared = t.join("cfg/corerouter/dev-image-key");
        migrate(&out, &shared).unwrap();
        assert_eq!(
            std::fs::read_to_string(shared.join("dev-image-key.pk8")).unwrap(),
            "secret"
        );
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&shared.join("dev-image-key.pk8")), 0o600);
        assert_eq!(mode(&shared), 0o700);
        assert_eq!(key_ids(&shared), ["abcd"]);
        assert!(has_key(&out), "the build directory keeps its copy");
        // A second migration (another build that raced) keeps the first.
        std::fs::write(out.join("dev-image-key.pk8"), "other").unwrap();
        migrate(&out, &shared).unwrap();
        assert_eq!(
            std::fs::read_to_string(shared.join("dev-image-key.pk8")).unwrap(),
            "secret"
        );
        std::fs::remove_dir_all(&t).unwrap();
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
