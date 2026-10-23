//! The traffic history on disk (G4.5): `<config-dir>/graphs/`, one file
//! per series (`interface-ether1.rrd`, `system.rrd`) in the engine's
//! round-robin format (`corerouter_engine::graph::rrd`), so its size is
//! fixed when the series starts and never grows.
//!
//! The engine collects every second in memory; this service writes what
//! changed every `store_every` seconds (RouterOS `store-every`, 5 min by
//! default) — batches like rrdcached's, because flash wears with every
//! write. A store writes, per series, the buckets of the 1 min, 5 min and
//! 1 h rings closed since the last one (a few hundred bytes), in place;
//! the 1 s ring (the bulk of the writes) only at a clean shutdown
//! ([`final_store`]). A crash therefore loses at most `store_every` of the
//! coarser rings and the last hour at 1 s, which the 1 min ring still has.
//!
//! At boot the files are read back before the history starts again, so a
//! restart loses only the time the router was down (`NaN` slots, holes in
//! the graph). A file that cannot be read is renamed `*.corrupt` and the
//! series starts again.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use corerouter_engine::graph::rrd::{MAX_DS, Rrd};
use corerouter_engine::graph::{GraphDb, Patch};
use corerouter_engine::{Shared, lock};

pub(crate) const SERVICE: super::Service = super::Service {
    name: "graphing",
    flags: &[],
    topic: "system",
    enable: "system.graph.set enabled=yes",
    depends: &[],
    start,
};

/// The subdirectory of `--config-dir`.
pub const DIR: &str = "graphs";
/// Most load errors kept for `system.graph.print`.
const MAX_LOAD_ERRORS: usize = 16;
const TICK: Duration = Duration::from_secs(1);

/// Where the files are, once the service started with a directory (for
/// [`final_store`]).
static STORE_DIR: OnceLock<PathBuf> = OnceLock::new();

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let dir = ctx.config_dir.as_ref().map(|d| d.join(DIR));
    if let Some(dir) = &dir {
        match fs::create_dir_all(dir) {
            Ok(()) => {
                load(&session, dir);
                let _ = STORE_DIR.set(dir.clone());
            }
            Err(e) => log::error!(
                "graphing: cannot use {}: {e}; the traffic history is kept in memory only",
                dir.display()
            ),
        }
    }
    let dir = STORE_DIR.get().cloned();
    Ok(Box::new(move |health: &super::Health| {
        let Some(dir) = &dir else {
            health.disabled(Some("no --config-dir: the history is kept in memory only"));
            while health.sleep(TICK) {
                health.beat();
            }
            return Ok(());
        };
        let mut last = Instant::now();
        while health.sleep(TICK) {
            health.beat();
            let (enabled, every) = {
                let s = lock(&session);
                let g = &s.store().running().system.graphing;
                (g.enabled, u64::from(g.store_every))
            };
            health.disabled((!enabled).then_some("system.graph.set enabled=no"));
            if last.elapsed() < Duration::from_secs(every) {
                continue;
            }
            last = Instant::now();
            match store(&session, dir, false) {
                Ok(n) if n > 0 => {
                    health.clear_error();
                    health.event(format!("stored {n} bytes"));
                }
                Ok(_) => health.clear_error(),
                Err(e) => health.error(e),
            }
        }
        Ok(())
    }))
}

/// Read every file of `dir` into the session's history.
fn load(session: &Shared, dir: &Path) {
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let max = Rrd::size_for(MAX_DS) as u64;
    match fs::read_dir(dir) {
        Ok(entries) => {
            for e in entries.flatten() {
                let Some(name) = e.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if name.ends_with(".tmp") {
                    let _ = fs::remove_file(e.path());
                    continue;
                }
                if !name.ends_with(".rrd") {
                    continue;
                }
                let mut bytes = Vec::new();
                let read = File::open(e.path()).and_then(|f| f.take(max + 1).read_to_end(&mut bytes));
                match read {
                    Ok(_) => files.push((name, bytes)),
                    Err(err) => errors.push(format!("{name}: {err}")),
                }
            }
        }
        Err(e) => errors.push(format!("{}: {e}", dir.display())),
    }
    let mut s = lock(session);
    let cap = s.store().running().system.graphing.max_memory_bytes();
    let Some(db) = s.ext_mut::<GraphDb>() else { return };
    db.set_persistent(&dir.display().to_string());
    let mut loaded = 0;
    for (name, bytes) in files {
        if db.memory_bytes().saturating_add(bytes.len() as u64) > cap {
            errors.push(format!("{name}: over max-memory, not loaded (kept on disk)"));
            continue;
        }
        match db.load(&name, &bytes) {
            Ok(()) => loaded += 1,
            Err(why) => {
                let _ = fs::rename(dir.join(&name), dir.join(format!("{name}.corrupt")));
                errors.push(format!("{name}: {why} (renamed .corrupt)"));
            }
        }
    }
    db.disk.loaded = loaded;
    db.disk.files = loaded;
    for e in &errors {
        log::warn!("graphing: {e}");
    }
    errors.truncate(MAX_LOAD_ERRORS);
    db.disk.load_errors = errors;
    if loaded > 0 {
        log::info!("graphing: {loaded} series read from {}", dir.display());
    }
}

/// Write what changed (`seconds`: the 1 s rings too). Returns the bytes
/// written. The session is locked only to take the patches and to report.
pub(crate) fn store(session: &Shared, dir: &Path, seconds: bool) -> Result<u64, String> {
    let started = Instant::now();
    let patches = match lock(session).ext_mut::<GraphDb>() {
        Some(db) => db.take_patches(seconds),
        None => return Ok(0),
    };
    let mut bytes = 0u64;
    let mut failed: Vec<(String, String)> = Vec::new();
    for p in &patches {
        let (file, r) = match p {
            Patch::Create { file, bytes: b } => (file, create(&dir.join(file), b).map(|()| b.len() as u64)),
            Patch::Write { file, writes } => (file, patch(&dir.join(file), writes)),
            Patch::Remove { file } => (
                file,
                match fs::remove_file(dir.join(file)) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                    _ => Ok(0),
                },
            ),
        };
        match r {
            Ok(n) => bytes += n,
            Err(e) => failed.push((file.clone(), e.to_string())),
        }
    }
    let files = fs::read_dir(dir)
        .map(|d| d.flatten().filter(|e| e.file_name().to_string_lossy().ends_with(".rrd")).count())
        .unwrap_or(0);
    let mut s = lock(session);
    let Some(db) = s.ext_mut::<GraphDb>() else { return Ok(bytes) };
    for (file, _) in &failed {
        db.rewrite(file);
    }
    let d = &mut db.disk;
    d.files = files;
    d.stores += 1;
    d.bytes_written = d.bytes_written.saturating_add(bytes);
    d.last_store_bytes = bytes;
    d.last_store_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    d.last_store = unix_now();
    match failed.first() {
        Some((file, e)) => {
            let msg = format!("{file}: {e} ({} file(s) will be written again)", failed.len());
            d.last_error = Some(msg.clone());
            Err(msg)
        }
        None => {
            d.last_error = None;
            Ok(bytes)
        }
    }
}

fn unix_now() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// A new file: written beside, synced, renamed over (never half a file).
fn create(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("rrd.tmp");
    let mut f = File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_data()?;
    fs::rename(&tmp, path)
}

/// Byte ranges written in place, then synced. A torn write after a power
/// cut leaves some slots of one store half old, half new — values, never
/// the layout (the header fields are each written whole).
fn patch(path: &Path, writes: &[corerouter_engine::graph::rrd::Write]) -> std::io::Result<u64> {
    let mut f = OpenOptions::new().write(true).open(path)?;
    let len = f.metadata()?.len();
    let mut n = 0u64;
    for w in writes {
        if w.offset + w.bytes.len() as u64 > len {
            return Err(std::io::Error::other("the file is shorter than its layout"));
        }
        f.seek(SeekFrom::Start(w.offset))?;
        f.write_all(&w.bytes)?;
        n += w.bytes.len() as u64;
    }
    f.sync_data()?;
    Ok(n)
}

/// The last store, the 1 s rings included, before the daemon exits (called
/// by the shutdown in `main.rs`, which then holds the session).
pub(crate) fn final_store(session: &Shared) {
    let Some(dir) = STORE_DIR.get() else { return };
    let started = Instant::now();
    match store(session, dir, true) {
        Ok(n) => log::info!(
            "shutting down: graph history stored ({n} bytes, {} ms)",
            started.elapsed().as_millis()
        ),
        Err(e) => log::warn!("shutting down: graph history not fully stored: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};

    const T0: u64 = 1_800_000_000;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "cr-graphing-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_restart_reads_back_what_was_stored() {
        let dir = tmp();
        let s = shared(Session::virtual_lab());
        load(&s, &dir);
        for t in 0..300 {
            lock(&s).tick(T0 + t);
        }
        let first = store(&s, &dir, false).unwrap();
        assert!(first > 0, "new files written whole");
        for t in 300..700 {
            lock(&s).tick(T0 + t);
        }
        let second = store(&s, &dir, true).unwrap();
        assert!(second < first, "then only what changed: {second} < {first}");
        let q = serde_json::json!({"series": ["ether1", "system"], "range": "hour", "end": T0 + 690});
        let before = lock(&s).execute("system.graph.query", &q).unwrap();

        let back = shared(Session::virtual_lab());
        load(&back, &dir);
        lock(&back).tick(T0 + 900);
        let after = lock(&back).execute("system.graph.query", &q).unwrap();
        for i in 0..2 {
            let (b, a) = (&before["series"][i], &after["series"][i]);
            assert_eq!(b["data"], a["data"], "series {i}");
            assert_eq!(b["totals"], a["totals"]);
            assert_eq!(b["stats"]["rx_bps"]["p95"], a["stats"]["rx_bps"]["p95"]);
        }
        let p = lock(&back).execute("system.graph.print", &serde_json::json!({})).unwrap();
        assert!(p["disk"]["loaded"].as_u64().unwrap() >= 2, "{p}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_broken_file_is_set_aside_and_rewritten() {
        let dir = tmp();
        fs::write(dir.join("interface-ether1.rrd"), b"garbage").unwrap();
        fs::write(dir.join("system.rrd.tmp"), b"half").unwrap();
        let s = shared(Session::virtual_lab());
        load(&s, &dir);
        assert!(dir.join("interface-ether1.rrd.corrupt").exists());
        assert!(!dir.join("system.rrd.tmp").exists());
        for t in 0..3 {
            lock(&s).tick(T0 + t);
        }
        store(&s, &dir, false).unwrap();
        let bytes = fs::read(dir.join("interface-ether1.rrd")).unwrap();
        assert!(Rrd::decode(&bytes).is_ok());
        // A file that vanished is written whole again by the next store.
        fs::remove_file(dir.join("interface-ether1.rrd")).unwrap();
        for t in 3..130 {
            lock(&s).tick(T0 + t);
        }
        assert!(store(&s, &dir, false).is_err());
        store(&s, &dir, false).unwrap();
        assert!(dir.join("interface-ether1.rrd").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
