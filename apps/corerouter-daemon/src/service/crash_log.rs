//! What the previous boot left in pstore (G1.6zx), once at start: the
//! kernel's dumps of a panic or oops (`/sys/fs/pstore`, mounted by PID 1)
//! are saved under `<config-dir>/crash/` (written, `fsync`ed and renamed),
//! **then** erased from the firmware's store, and handed to the engine
//! (`corerouter_engine::crash_log`): a `system,critical` line in the
//! router's log saying what happened and in which boot, the trace after it,
//! `system.crash.print` and the `kernel.crash` health check.
//!
//! Erasing is what makes the UEFI backend safe to keep on: its records are
//! UEFI variables in the NVRAM the A/B update writes its boot entries to
//! (`docs/os-image.md`, G1.6zx). After erasing, the service measures that
//! NVRAM (`statfs` of efivarfs) and switches `efi_pstore` off for this boot
//! when less than [`EFI_MIN_FREE`] is left (`pstore_disable` is writable
//! at run time, `drivers/firmware/efi/efi-pstore.c`); the next boot
//! measures again. The measurement repeats every [`EFI_WATCH`] while the
//! backend is on: an oops writes a dump without a reboot, and a run of them
//! in one boot must not take the room of the boot entries either.
//!
//! The live image looks only: the records belong to the installed system,
//! and the live image writes nothing to the machine.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use corerouter_engine::crash_log::{
    AbBoot, Crash, EfiStore, Found, MAX_FILE_BYTES, MAX_FILES, MAX_KEPT, PstoreFile, attribute,
    efi_store_ok, parse,
};
use corerouter_engine::crash_log::EFI_MIN_FREE;
use corerouter_engine::{Shared, lock};

pub(crate) const SERVICE: super::Service = super::Service {
    name: "crash-log",
    flags: &[],
    topic: "system",
    enable: "always on (the image)",
    depends: &[],
    start,
};

/// Where the subdirectory of the config directory keeps the dumps.
const DIR: &str = "crash";
/// A saved dump is read back up to this size.
const MAX_SAVED_BYTES: u64 = 1 << 20;
/// Between two looks at the NVRAM while `efi_pstore` is on: one
/// `QueryVariableInfo` (efivarfs `statfs`), a firmware call of microseconds.
const EFI_WATCH: std::time::Duration = std::time::Duration::from_secs(60);

/// The machine's files this service reads and writes.
#[derive(Debug, Clone)]
struct Paths {
    pstore: PathBuf,
    /// `/sys/module`: `pstore/parameters/backend`, `efi_pstore/parameters/pstore_disable`.
    module: PathBuf,
    efivars: PathBuf,
    crash: Option<PathBuf>,
    /// The A/B state (`<config-dir>/package`) and the kernel's command line.
    ab_state: Option<PathBuf>,
    cmdline: PathBuf,
}

impl Paths {
    fn host(config_dir: Option<&Path>) -> Self {
        Self {
            pstore: "/sys/fs/pstore".into(),
            module: "/sys/module".into(),
            efivars: "/sys/firmware/efi/efivars".into(),
            crash: config_dir.map(|d| d.join(DIR)),
            ab_state: config_dir.map(|d| d.join(corerouter_sysupdate::state::DIR)),
            cmdline: "/proc/cmdline".into(),
        }
    }
}

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let paths = Paths::host(ctx.config_dir.as_deref());
    Ok(Box::new(move |health: &super::Health| {
        let (lab, live) = {
            let s = lock(&session);
            (s.backend().starts_with("virtual lab"), corerouter_engine::live::is_live(&s))
        };
        if lab {
            health.disabled(Some("the virtual lab has no pstore"));
        } else if !paths.pstore.is_dir() {
            health.disabled(Some("no /sys/fs/pstore (not the image, or a kernel without pstore)"));
        } else {
            let found = collect(&paths, live);
            let summary = format!(
                "{} dump(s) from earlier boots, backend {}",
                found.new.len(),
                found.backend.as_deref().unwrap_or("none")
            );
            if !found.problems.is_empty() {
                health.event(found.problems.join("; "));
            }
            let watch = found.efi.as_ref().is_some_and(|e| e.enabled) && !live;
            hand_over(&session, found);
            health.event(summary);
            while watch && health.sleep(EFI_WATCH) {
                health.beat();
                if let Some(e) = efi(&paths, live).filter(|e| e.turned_off) {
                    lock(&session).crash_store_turned_off(e);
                    health.event("efi_pstore turned off: NVRAM short");
                    break;
                }
            }
        }
        health.idle_until_shutdown();
        Ok(())
    }))
}

fn hand_over(session: &Shared, found: Found) {
    lock(session).crash_found(found);
}

/// Read the store, save and erase what is new, look at the NVRAM.
fn collect(p: &Paths, live: bool) -> Found {
    let mut problems = Vec::new();
    let files = read_store(&p.pstore);
    let mut new = parse(&files);
    attribute(&mut new, &ab_boot(p));
    match (&p.crash, live) {
        (_, true) => {
            if !new.is_empty() {
                problems.push(format!(
                    "{} record(s) in pstore left in place: the live image does not erase the installed system's",
                    new.len()
                ));
            }
        }
        (None, false) => {
            if !new.is_empty() {
                problems.push("no --config-dir: pstore records shown, not saved nor erased".into());
            }
        }
        (Some(dir), false) => {
            for c in &new {
                match save(dir, c) {
                    Ok(()) => {
                        for f in &c.files {
                            // Unlinking a pstore file erases the record in
                            // the backend (`pstore_unlink` → `erase`).
                            if let Err(e) = fs::remove_file(p.pstore.join(f)) {
                                problems.push(format!("pstore {f}: not erased: {e}"));
                            }
                        }
                    }
                    Err(e) => problems.push(format!("crash/{}: not saved, record kept in pstore: {e}", c.file_name())),
                }
            }
            prune(dir);
        }
    }
    let saved = p
        .crash
        .as_deref()
        .map(|d| load_saved(d, &new))
        .unwrap_or_default();
    new.truncate(MAX_KEPT);
    Found {
        new,
        saved,
        backend: backend(&p.module),
        efi: efi(p, live),
        problems,
    }
}

/// The slot running now and a fall-back of this boot, from the A/B state.
fn ab_boot(p: &Paths) -> AbBoot {
    let running = read_small_n(&p.cmdline, 4096).and_then(|c| {
        c.split_ascii_whitespace()
            .find_map(|w| w.strip_prefix("corerouter.slot="))
            .filter(|s| s.len() <= 8 && s.bytes().all(|b| b.is_ascii_alphanumeric()))
            .map(str::to_owned)
    });
    let rolled_back = p.ab_state.as_deref().and_then(|d| {
        let (st, _) = corerouter_sysupdate::state::State::load(d);
        st.last
            .filter(|o| o.result == "rolled-back")
            .map(|o| (o.slot.as_str().to_owned(), o.version.chars().take(64).collect(), o.at_unix))
    });
    AbBoot { running, rolled_back }
}

fn read_store(dir: &Path) -> Vec<PstoreFile> {
    let Ok(rd) = fs::read_dir(dir) else {
        return Vec::new();
    };
    rd.flatten()
        .take(MAX_FILES)
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let meta = e.metadata().ok().filter(fs::Metadata::is_file)?;
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |d| d.as_secs());
            let mut buf = Vec::new();
            fs::File::open(e.path())
                .ok()?
                .take(u64::try_from(MAX_FILE_BYTES).unwrap_or(u64::MAX))
                .read_to_end(&mut buf)
                .ok()?;
            Some(PstoreFile {
                name,
                mtime,
                text: String::from_utf8_lossy(&buf).into_owned(),
            })
        })
        .collect()
}

/// Written whole or not at all: temp file, `fsync`, rename, `fsync` of the
/// directory (the record is erased from the firmware right after).
fn save(dir: &Path, c: &Crash) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    let name = c.file_name();
    let tmp = dir.join(format!(".{name}.new"));
    let body = serde_json::to_vec_pretty(c).map_err(std::io::Error::other)?;
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, dir.join(&name))?;
    fs::File::open(dir)?.sync_all()
}

/// The saved dumps, newest first (names sort by time).
fn saved_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .take(4 * MAX_FILES)
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.ends_with(".json") && !n.starts_with('.'))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names.reverse();
    names
}

/// Keep the newest [`MAX_KEPT`] (each up to ~200 KiB: at most ~1.6 MiB of
/// `/config`), and no half-written temp file.
fn prune(dir: &Path) {
    for n in saved_names(dir).into_iter().skip(MAX_KEPT) {
        let _ = fs::remove_file(dir.join(n));
    }
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten().take(4 * MAX_FILES) {
            if e.file_name().to_string_lossy().ends_with(".new") {
                let _ = fs::remove_file(e.path());
            }
        }
    }
}

/// The dumps of earlier boots, without the ones this boot just saved.
fn load_saved(dir: &Path, new: &[Crash]) -> Vec<Crash> {
    let fresh: Vec<String> = new.iter().map(Crash::file_name).collect();
    saved_names(dir)
        .into_iter()
        .filter(|n| !fresh.contains(n))
        .take(MAX_KEPT)
        .filter_map(|n| {
            let mut buf = Vec::new();
            fs::File::open(dir.join(&n))
                .ok()?
                .take(MAX_SAVED_BYTES)
                .read_to_end(&mut buf)
                .ok()?;
            serde_json::from_slice::<Crash>(&buf).ok()
        })
        .collect()
}

fn read_small(p: &Path) -> Option<String> {
    read_small_n(p, 256)
}

fn read_small_n(p: &Path, max: u64) -> Option<String> {
    let mut s = String::new();
    fs::File::open(p).ok()?.take(max).read_to_string(&mut s).ok()?;
    Some(s.trim().to_owned())
}

/// The backend the kernel writes to now: `pstore.backend`, set when one
/// registers (`fs/pstore/platform.c`, `pstore_register`).
fn backend(module: &Path) -> Option<String> {
    read_small(&module.join("pstore/parameters/backend"))
        .filter(|b| !b.is_empty() && b != "(null)")
        .map(|b| b.chars().take(32).collect())
}

/// The UEFI store and the policy: off for this boot when it is short.
fn efi(p: &Paths, live: bool) -> Option<EfiStore> {
    let param = p.module.join("efi_pstore/parameters/pstore_disable");
    let disabled = read_small(&param)?;
    if !p.efivars.is_dir() {
        return None;
    }
    let (total, free) = space(&p.efivars);
    let mut store = EfiStore {
        total,
        free,
        enabled: disabled == "N",
        turned_off: false,
    };
    if store.enabled && !live && !efi_store_ok(free) {
        match fs::write(&param, "Y") {
            Ok(()) => {
                store.enabled = false;
                store.turned_off = true;
            }
            Err(e) => log::warn!("crash log: efi_pstore not turned off ({} B free, needs {EFI_MIN_FREE}): {e}", free.unwrap_or(0)),
        }
    }
    Some(store)
}

/// efivarfs answers `statfs` with the firmware's `QueryVariableInfo`
/// (`fs/efivarfs/super.c`, `efivarfs_statfs`; zeros when the firmware does
/// not have it).
fn space(dir: &Path) -> (Option<u64>, Option<u64>) {
    #[cfg(target_os = "linux")]
    if let Ok(s) = rustix::fs::statvfs(dir) {
        let bs = s.f_frsize.max(1);
        let total = s.f_blocks.saturating_mul(bs);
        if total > 0 {
            return (Some(total), Some(s.f_bavail.saturating_mul(bs)));
        }
    }
    let _ = dir;
    (None, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::crash_log::CrashLog;
    use corerouter_engine::{Session, shared};
    use serde_json::json;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cr-crash-log-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn paths(root: &Path) -> Paths {
        let p = Paths {
            pstore: root.join("pstore"),
            module: root.join("module"),
            efivars: root.join("efivars"),
            crash: Some(root.join("config/crash")),
            ab_state: Some(root.join("config/package")),
            cmdline: root.join("cmdline"),
        };
        fs::write(&p.cmdline, "root=/dev/dm-0 corerouter.slot=a panic=10\n").unwrap();
        fs::create_dir_all(&p.pstore).unwrap();
        fs::create_dir_all(p.module.join("pstore/parameters")).unwrap();
        fs::create_dir_all(p.module.join("efi_pstore/parameters")).unwrap();
        fs::write(p.module.join("pstore/parameters/backend"), "efi_pstore\n").unwrap();
        fs::write(p.module.join("efi_pstore/parameters/pstore_disable"), "N\n").unwrap();
        p
    }

    fn panic_files(p: &Paths, t: u64) {
        fs::write(
            p.pstore.join(format!("dmesg-efi_pstore-{t}101001")),
            "Panic#1 Part1\n<0>[   12.5] Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)\n",
        )
        .unwrap();
        fs::write(
            p.pstore.join(format!("dmesg-efi_pstore-{t}102001")),
            "Panic#1 Part2\n<6>[    0.0] Command line: root=/dev/dm-0 corerouter.slot=b panic=10\n",
        )
        .unwrap();
    }

    #[test]
    fn saves_then_erases_then_lists_from_disk() {
        let root = tmp("save");
        let p = paths(&root);
        panic_files(&p, 1_763_000_000);
        let f = collect(&p, false);
        assert!(f.problems.is_empty(), "{:?}", f.problems);
        assert_eq!(f.new.len(), 1);
        assert_eq!(f.new[0].slot.as_deref(), Some("b"));
        assert_eq!(f.backend.as_deref(), Some("efi_pstore"));
        assert_eq!(fs::read_dir(&p.pstore).unwrap().count(), 0, "erased once saved");
        let saved = saved_names(p.crash.as_ref().unwrap());
        assert_eq!(saved.len(), 1);
        // The next boot: nothing new, the saved one listed.
        let f2 = collect(&p, false);
        assert!(f2.new.is_empty());
        assert_eq!(f2.saved.len(), 1);
        assert_eq!(f2.saved[0].summary, "Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)");
        // In the session: the log line and the command.
        let session = shared(Session::virtual_lab());
        hand_over(&session, f);
        let mut s = lock(&session);
        assert_eq!(s.ext::<CrashLog>().unwrap().new_this_boot, 1);
        let v = s.execute("system.crash.print", &json!({})).unwrap();
        assert_eq!(v["crashes"][0]["slot"], "b");
        let log = s.execute("log.print", &json!({"find": "previous boot ended"})).unwrap();
        assert!(log[0]["message"].as_str().unwrap().contains("slot b"), "{log}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_save_that_fails_keeps_the_record() {
        let root = tmp("nosave");
        let mut p = paths(&root);
        panic_files(&p, 1_763_000_000);
        // A file where the directory should be: create_dir_all fails.
        fs::create_dir_all(root.join("config")).unwrap();
        fs::write(root.join("config/crash"), "x").unwrap();
        let f = collect(&p, false);
        assert_eq!(f.new.len(), 1);
        assert!(f.problems.iter().any(|e| e.contains("not saved, record kept")), "{:?}", f.problems);
        assert_eq!(fs::read_dir(&p.pstore).unwrap().count(), 2, "nothing erased");
        // The live image never erases.
        p.crash = Some(root.join("live-crash"));
        let f = collect(&p, true);
        assert!(f.problems.iter().any(|e| e.contains("live image")));
        assert_eq!(fs::read_dir(&p.pstore).unwrap().count(), 2);
        assert!(!root.join("live-crash").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn keeps_the_newest_and_no_temp_files() {
        let root = tmp("prune");
        let p = paths(&root);
        let dir = p.crash.clone().unwrap();
        fs::create_dir_all(&dir).unwrap();
        for i in 0..12u64 {
            fs::write(dir.join(format!("{:012}-panic-{i}.json", 1_000 + i)), "{}").unwrap();
        }
        fs::write(dir.join(".x.json.new"), "half").unwrap();
        prune(&dir);
        let names = saved_names(&dir);
        assert_eq!(names.len(), MAX_KEPT);
        assert!(names[0].starts_with("000000001011"), "{names:?}");
        assert!(!dir.join(".x.json.new").exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn nvram_without_statfs_keeps_the_backend() {
        let root = tmp("efi");
        let p = paths(&root);
        fs::create_dir_all(&p.efivars).unwrap();
        // A tmpfs directory answers statfs with its own (large) size: the
        // store is kept on. The low-space branch is the engine's
        // `efi_store_ok`, tested there, and the image's ab-test.
        let e = efi(&p, false).unwrap();
        assert!(e.enabled && !e.turned_off, "{e:?}");
        let _ = fs::remove_dir_all(&root);
    }
}
