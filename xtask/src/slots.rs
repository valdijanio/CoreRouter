//! G0.29: at most `COREROUTER_CI_SLOTS` (2) heavy `cargo xtask ci` runs at
//! once on this machine, and none started on a nearly full disk.
//!
//! A slot is an exclusive `flock` on `slot-<i>.lock` in
//! `$XDG_RUNTIME_DIR/corerouter-ci/`. The kernel drops it when the process
//! dies (no stale lock to clean up), and std opens files close-on-exec, so
//! the cargo and test processes the run starts do not inherit it: a stray
//! child left behind cannot hold a slot. The holder writes its pid and
//! directory into the file, so a waiting run says who it waits for.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// A held slot; dropping it frees the slot.
#[derive(Debug)]
pub struct Slot {
    _file: File,
    pub index: usize,
}

/// The slots directory: `$XDG_RUNTIME_DIR/corerouter-ci` (per user, tmpfs,
/// emptied at logout), else the temp directory with the user's name.
pub fn dir() -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(d) if !d.is_empty() => PathBuf::from(d).join("corerouter-ci"),
        _ => {
            let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
            std::env::temp_dir().join(format!("corerouter-ci-{user}"))
        }
    }
}

/// `COREROUTER_CI_SLOTS`, 1 to 64 (default 2).
pub fn count() -> usize {
    std::env::var("COREROUTER_CI_SLOTS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|n| (1..=64).contains(n))
        .unwrap_or(2)
}

/// Take a free slot now, or `Ok(None)` with what the holders wrote.
pub fn try_acquire(
    dir: &Path,
    slots: usize,
    who: &str,
) -> Result<Result<Slot, Vec<String>>, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut holders = Vec::new();
    for index in 0..slots {
        let path = dir.join(format!("slot-{index}.lock"));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        match file.try_lock() {
            Ok(()) => {
                // Best effort: the note only feeds the waiting message.
                let _ = file.set_len(0);
                let _ = file.rewind();
                let _ = file.write_all(who.as_bytes());
                return Ok(Ok(Slot { _file: file, index }));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                let mut note = String::new();
                let _ = file.read_to_string(&mut note);
                let note: String = note.trim().chars().take(200).collect();
                holders.push(if note.is_empty() { "?".into() } else { note });
            }
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(format!("{}: {e}", path.display()));
            }
        }
    }
    Ok(Err(holders))
}

/// Wait for a slot (or not, with `wait == false`: `Ok(None)` and a warning
/// when all are taken). Prints "esperando vaga" once, then every minute.
pub fn acquire(
    dir: &Path,
    slots: usize,
    wait: bool,
    poll: Duration,
) -> Result<Option<Slot>, String> {
    let who = format!(
        "pid {} em {}",
        std::process::id(),
        std::env::current_dir().map_or_else(|_| "?".into(), |d| d.display().to_string())
    );
    let started = Instant::now();
    let mut last_note: Option<Instant> = None;
    loop {
        match try_acquire(dir, slots, &who)? {
            Ok(slot) => {
                if last_note.is_some() {
                    eprintln!(
                        "vaga {} livre depois de {} s",
                        slot.index,
                        started.elapsed().as_secs()
                    );
                }
                return Ok(Some(slot));
            }
            Err(holders) if !wait => {
                eprintln!(
                    "warning: --no-wait: rodando sem vaga ({} rodando: {})",
                    holders.len(),
                    holders.join("; ")
                );
                return Ok(None);
            }
            Err(holders) => {
                if last_note.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
                    eprintln!(
                        "esperando vaga ({} rodando: {}); --no-wait ignora, COREROUTER_CI_SLOTS muda o limite",
                        holders.len(),
                        holders.join("; ")
                    );
                    last_note = Some(Instant::now());
                }
                std::thread::sleep(poll);
            }
        }
    }
}

/// `COREROUTER_CI_MIN_FREE_GB` (default 30): below it a run waits.
pub fn min_free_gb() -> u64 {
    std::env::var("COREROUTER_CI_MIN_FREE_GB")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(30)
}

/// Free space, in GiB, of the file system holding `path` (`df -Pk`).
pub fn free_gb(path: &Path) -> Result<u64, String> {
    let out = Command::new("df")
        .args(["-Pk"])
        .arg(path)
        .output()
        .map_err(|e| format!("df: {e}"))?;
    if !out.status.success() {
        return Err(format!("df: {}", out.status));
    }
    parse_df(&String::from_utf8_lossy(&out.stdout)).ok_or_else(|| "df: unexpected output".into())
}

/// The "Available" column (KiB) of `df -P`, in GiB.
fn parse_df(text: &str) -> Option<u64> {
    let line = text.lines().nth(1)?;
    let kib: u64 = line.split_whitespace().nth(3)?.parse().ok()?;
    Some(kib / (1024 * 1024))
}

/// Wait (up to `limit`) until `path`'s file system has `min` GiB free;
/// without `wait`, only warn. Err when the limit passes.
pub fn wait_for_disk(path: &Path, min: u64, wait: bool, limit: Duration) -> Result<(), String> {
    let started = Instant::now();
    let mut last_note: Option<Instant> = None;
    loop {
        // No df (not Linux, odd mount): do not block the gate on it.
        let Ok(free) = free_gb(path) else {
            return Ok(());
        };
        if free >= min {
            return Ok(());
        }
        let msg = format!(
            "{free} GB livres em {} (mínimo {min} GB, COREROUTER_CI_MIN_FREE_GB): \
             apague target-* de sessões encerradas",
            path.display()
        );
        if !wait {
            eprintln!("warning: --no-wait: {msg}");
            return Ok(());
        }
        if started.elapsed() >= limit {
            return Err(format!("{msg}; esperou {} min", limit.as_secs() / 60));
        }
        if last_note.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
            eprintln!("esperando disco: {msg}");
            last_note = Some(Instant::now());
        }
        std::thread::sleep(Duration::from_secs(30));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;

    #[test]
    fn df_available_column() {
        let text = "Filesystem     1024-blocks      Used Available Capacity Mounted on\n\
                    /dev/nvme0n1p7   302580736 166000000 120586240      58% /home\n";
        assert_eq!(parse_df(text), Some(115));
        assert_eq!(parse_df("header only\n"), None);
        assert_eq!(parse_df(""), None);
    }

    /// Run as a child by `two_processes_hold_both_slots`: takes a slot in
    /// `COREROUTER_SLOT_TEST_DIR`, says so, and holds it until killed (or
    /// its stdin closes: a dead parent leaves no child behind).
    #[test]
    fn slot_holder_child() {
        let Some(dir) = std::env::var_os("COREROUTER_SLOT_TEST_DIR") else {
            return;
        };
        let slot = try_acquire(Path::new(&dir), 2, "child").unwrap().unwrap();
        println!("held {}", slot.index);
        std::io::stdout().flush().unwrap();
        let _ = std::io::stdin().read_to_end(&mut Vec::new());
    }

    fn holder(dir: &Path) -> std::process::Child {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "slots::tests::slot_holder_child", "--nocapture"])
            .env("COREROUTER_SLOT_TEST_DIR", dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let out = child.stdout.take().unwrap();
        let mut line = String::new();
        let mut lines = std::io::BufReader::new(out);
        // The test harness prints its own lines first.
        while !line.starts_with("held") {
            line.clear();
            assert!(lines.read_line(&mut line).unwrap() > 0, "child exited");
        }
        child
    }

    #[test]
    fn two_processes_hold_both_slots_and_death_frees_one() {
        let dir = std::env::temp_dir().join(format!("cr-slots-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut a = holder(&dir);
        let mut b = holder(&dir);
        let holders = try_acquire(&dir, 2, "parent").unwrap().unwrap_err();
        assert_eq!(holders, vec!["child".to_owned(), "child".to_owned()]);
        assert!(
            acquire(&dir, 2, false, Duration::from_millis(10))
                .unwrap()
                .is_none()
        );
        // A killed holder's lock is gone at once: no stale slot.
        a.kill().unwrap();
        a.wait().unwrap();
        let slot = acquire(&dir, 2, true, Duration::from_millis(10))
            .unwrap()
            .unwrap();
        // Held in this process too: a second open of the file conflicts.
        assert!(try_acquire(&dir, 2, "x").unwrap().is_err());
        drop(slot);
        assert!(try_acquire(&dir, 2, "x").unwrap().is_ok());
        b.kill().unwrap();
        b.wait().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn slot_files_are_not_inherited_by_children() {
        let dir = std::env::temp_dir().join(format!("cr-slots-inh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let slot = try_acquire(&dir, 1, "parent").unwrap().unwrap();
        // A child outliving the slot's owner must not keep the lock: std
        // opens with O_CLOEXEC, so the child has no copy of the fd.
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        drop(slot);
        // Another test of this process may be between fork and exec right
        // now (its child holds every fd until exec): retry briefly.
        let free = (0..100).any(|_| {
            let ok = try_acquire(&dir, 1, "again").unwrap().is_ok();
            if !ok {
                std::thread::sleep(Duration::from_millis(10));
            }
            ok
        });
        assert!(free, "the sleep child kept the slot");
        child.kill().unwrap();
        child.wait().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
