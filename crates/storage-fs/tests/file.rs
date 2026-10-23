#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use corerouter_engine::{ConfigStorage, Session, Slot};
use corerouter_hal::VirtualHal;
use corerouter_storage_fs::{CORRUPT_SUFFIX, CURRENT, FileStorage, PREVIOUS, TEMP};
use serde_json::json;

/// A fresh directory under the system temp dir, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "corerouter-storage-fs-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&p);
        Self(p)
    }
}

/// A journal over the read limit: the newest lines are read (the last
/// line wins), starting at a whole line; never the oldest.
#[test]
fn an_oversized_journal_keeps_its_newest_lines() {
    let dir = TempDir::new();
    fs::create_dir_all(&dir.0).unwrap();
    let path = dir.0.join("j.log");
    let text: String = (0..100).map(|n| format!("line {n:03}\n")).collect();
    fs::write(&path, &text).unwrap();
    let tail = corerouter_storage_fs::read_tail(fs::File::open(&path).unwrap(), 35).unwrap();
    let tail = String::from_utf8(tail).unwrap();
    assert_eq!(tail, "line 097\nline 098\nline 099\n");
    let all = corerouter_storage_fs::read_tail(fs::File::open(&path).unwrap(), 10_000).unwrap();
    assert_eq!(all.len(), text.len());
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn boot(dir: &TempDir) -> Session {
    Session::with_storage(
        Box::new(VirtualHal::default()),
        Box::new(FileStorage::open(&dir.0).unwrap()),
    )
}

fn add(s: &mut Session, address: &str) {
    s.execute(
        "ip.address.add",
        &json!({"address": address, "interface": "ether1"}),
    )
    .unwrap();
}

fn addresses(s: &Session) -> Vec<String> {
    s.store()
        .running()
        .ip
        .addresses
        .iter()
        .map(|a| a.address.to_string())
        .collect()
}

#[test]
fn reboot_restores_running_and_history() {
    let dir = TempDir::new();
    let mut s = boot(&dir);
    add(&mut s, "10.0.0.1/24");
    add(&mut s, "10.0.1.1/24");
    let running = s.store().running().clone();
    drop(s);

    let s = boot(&dir);
    assert_eq!(s.store().running(), &running);
    assert_eq!(s.store().current_revision(), 2);
    assert_eq!(s.storage_status().loaded_from, Some("current"));
    assert!(s.storage_status().backend.starts_with("file "));
    let text = fs::read_to_string(dir.0.join(CURRENT)).unwrap();
    assert!(text.contains("\"format_version\":1"));
}

#[test]
fn save_rotates_and_leaves_no_temp_file() {
    let dir = TempDir::new();
    let mut st = FileStorage::open(&dir.0).unwrap();
    assert_eq!(st.load(Slot::Current).unwrap(), None);
    st.save("one").unwrap();
    assert_eq!(st.load(Slot::Previous).unwrap(), None);
    st.save("two").unwrap();
    st.save("three").unwrap();
    assert_eq!(st.load(Slot::Current).unwrap().as_deref(), Some("three"));
    assert_eq!(st.load(Slot::Previous).unwrap().as_deref(), Some("two"));
    assert!(!dir.0.join(TEMP).exists());
}

#[cfg(unix)]
#[test]
fn files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new();
    let mut st = FileStorage::open(&dir.0).unwrap();
    st.save("x").unwrap();
    let mode = fs::metadata(dir.0.join(CURRENT))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn partial_temp_from_a_crash_is_ignored_and_removed() {
    let dir = TempDir::new();
    let mut s = boot(&dir);
    add(&mut s, "10.0.0.1/24");
    drop(s);
    // Crash in the middle of writing the next save.
    fs::write(dir.0.join(TEMP), "{\"format_version\": 1, \"revis").unwrap();
    let s = boot(&dir);
    assert_eq!(addresses(&s), ["10.0.0.1/24"]);
    assert!(s.storage_status().boot_errors.is_empty());
    assert!(!dir.0.join(TEMP).exists());
}

#[test]
fn crash_between_renames_loads_previous() {
    let dir = TempDir::new();
    let mut s = boot(&dir);
    add(&mut s, "10.0.0.1/24");
    add(&mut s, "10.0.1.1/24");
    drop(s);
    // current → prev happened, temp → current did not.
    fs::rename(dir.0.join(PREVIOUS), dir.0.join("older")).unwrap();
    fs::rename(dir.0.join(CURRENT), dir.0.join(PREVIOUS)).unwrap();
    fs::write(dir.0.join(TEMP), "whatever").unwrap();
    let s = boot(&dir);
    assert_eq!(s.storage_status().loaded_from, Some("previous"));
    assert_eq!(addresses(&s), ["10.0.0.1/24", "10.0.1.1/24"]);
}

#[test]
fn corrupt_current_is_quarantined_and_previous_loaded() {
    let dir = TempDir::new();
    let mut s = boot(&dir);
    add(&mut s, "10.0.0.1/24");
    add(&mut s, "10.0.1.1/24");
    drop(s);
    let good = fs::read(dir.0.join(CURRENT)).unwrap();
    let mut bad = good.get(..good.len() / 3).unwrap().to_vec();
    bad.extend_from_slice(&[0xff, 0xfe, 0x00]);
    fs::write(dir.0.join(CURRENT), &bad).unwrap();

    let mut s = boot(&dir);
    assert_eq!(s.storage_status().loaded_from, Some("previous"));
    assert_eq!(addresses(&s), ["10.0.0.1/24"]);
    let quarantined = dir.0.join(format!("{CURRENT}{CORRUPT_SUFFIX}"));
    assert_eq!(fs::read(&quarantined).unwrap(), bad);
    assert!(!dir.0.join(CURRENT).exists());

    // Next commit: the good previous slot is kept, not overwritten.
    add(&mut s, "10.0.2.1/24");
    let prev = fs::read_to_string(dir.0.join(PREVIOUS)).unwrap();
    assert!(prev.contains("\"revision\":1"));
    drop(s);
    assert_eq!(addresses(&boot(&dir)), ["10.0.0.1/24", "10.0.2.1/24"]);
}

#[cfg(unix)]
#[test]
fn failed_save_keeps_the_old_file_and_is_reported() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new();
    let mut s = boot(&dir);
    add(&mut s, "10.0.0.1/24");
    let before = fs::read(dir.0.join(CURRENT)).unwrap();
    // Read-only directory: the temp file cannot be created.
    fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o500)).unwrap();
    if fs::write(dir.0.join("probe"), "x").is_ok() {
        // Running as root: permissions are not enforced; nothing to test.
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o700)).unwrap();
        return;
    }
    add(&mut s, "10.0.1.1/24");
    fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o700)).unwrap();

    // The commit stands (the data plane runs it); the failure is visible.
    assert_eq!(s.store().current_revision(), 2);
    let status = s.inspect(None).unwrap();
    assert!(
        status["storage"]["last_error"]
            .as_str()
            .unwrap()
            .contains(".tmp")
    );
    assert_eq!(fs::read(dir.0.join(CURRENT)).unwrap(), before);

    // The next successful save catches up and clears the error.
    add(&mut s, "10.0.2.1/24");
    assert!(s.storage_status().last_error.is_none());
    drop(s);
    assert_eq!(addresses(&boot(&dir)).len(), 3);
}

#[test]
fn open_rejects_a_file_path() {
    let dir = TempDir::new();
    fs::create_dir_all(&dir.0).unwrap();
    let file = dir.0.join("not-a-dir");
    fs::write(&file, "x").unwrap();
    assert!(FileStorage::open(&file).is_err());
}

#[test]
fn state_lives_beside_the_config_and_survives_reopening() {
    let dir = TempDir::new();
    let mut st = FileStorage::open(&dir.0).unwrap();
    assert_eq!(st.load_state("dhcp-leases").unwrap(), None);
    st.save_state("dhcp-leases", "{\"leases\":[]}").unwrap();
    st.save_state("dhcp-leases", "{\"leases\":[1]}").unwrap();
    let mut again = FileStorage::open(&dir.0).unwrap();
    assert_eq!(
        again.load_state("dhcp-leases").unwrap().as_deref(),
        Some("{\"leases\":[1]}")
    );
    assert!(dir.0.join("state-dhcp-leases.json").exists());
    assert!(!dir.0.join("state-dhcp-leases.json.tmp").exists());
    // Names become file names: nothing that could escape the directory.
    for bad in ["../x", "a/b", "", "UPPER", "x.json"] {
        assert!(st.save_state(bad, "1").is_err(), "{bad}");
        assert!(st.load_state(bad).is_err(), "{bad}");
    }
    // Never part of the config slots.
    assert!(st.load(Slot::Current).unwrap().is_none());
}

/// G4.2a: the DHCP server's journal: appended, read back whole, compacted
/// by an atomic rewrite; a torn last line (a crash mid-append) stays for the
/// reader to skip.
#[test]
fn journals_append_and_compact() {
    let dir = TempDir::new();
    let mut s = FileStorage::open(&dir.0).unwrap();
    assert_eq!(s.load_journal("dhcp-leases").unwrap(), None);
    s.append_journal("dhcp-leases", "{\"a\":1}\n").unwrap();
    s.append_journal("dhcp-leases", "{\"a\":2}\n{\"to").unwrap();
    let text = s.load_journal("dhcp-leases").unwrap().unwrap();
    assert_eq!(text.lines().count(), 3);
    s.rewrite_journal("dhcp-leases", "{\"a\":2}\n").unwrap();
    assert_eq!(
        s.load_journal("dhcp-leases").unwrap().unwrap(),
        "{\"a\":2}\n"
    );
    assert!(!dir.0.join("journal-dhcp-leases.log.tmp").exists());
    assert!(s.append_journal("../x", "y").is_err(), "names become files");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir.0.join("journal-dhcp-leases.log"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

/// Audit #16: a second quarantine of the same slot overwrote the first
/// forensic copy.
#[test]
fn every_quarantine_keeps_its_own_copy() {
    let dir = TempDir::new();
    let mut s = FileStorage::open(&dir.0).unwrap();
    for junk in ["first", "second", "third"] {
        fs::write(dir.0.join(CURRENT), junk).unwrap();
        s.quarantine(Slot::Current).unwrap();
    }
    let first = dir.0.join(format!("{CURRENT}{CORRUPT_SUFFIX}"));
    assert_eq!(fs::read_to_string(first).unwrap(), "first");
    let mut kept: Vec<String> = fs::read_dir(&dir.0)
        .unwrap()
        .map(|e| fs::read_to_string(e.unwrap().path()).unwrap())
        .collect();
    kept.sort();
    assert_eq!(kept, ["first", "second", "third"]);
}

/// Audit #16: temp files of state and journal saves interrupted by a crash
/// were never removed (only the config's was).
#[test]
fn stale_temp_files_of_state_and_journals_are_removed_on_open() {
    let dir = TempDir::new();
    fs::create_dir_all(&dir.0).unwrap();
    for f in [
        "state-dhcp-leases.json.tmp",
        "journal-dhcp-leases.log.tmp",
        "state-dhcp-leases.json",
    ] {
        fs::write(dir.0.join(f), "x").unwrap();
    }
    FileStorage::open(&dir.0).unwrap();
    assert!(!dir.0.join("state-dhcp-leases.json.tmp").exists());
    assert!(!dir.0.join("journal-dhcp-leases.log.tmp").exists());
    assert!(dir.0.join("state-dhcp-leases.json").exists());
}

/// G1.23: each revision is a file of its own, written once; the slot holds
/// the newest only; a revision write cut short is discarded on open.
#[test]
fn revisions_are_files_of_their_own() {
    use corerouter_storage_fs::revision_file;
    let dir = TempDir::new();
    let mut s = boot(&dir);
    add(&mut s, "10.0.0.1/24");
    add(&mut s, "10.0.1.1/24");
    drop(s);
    // The older revisions have files (differences); the newest is the slot.
    for n in 0..=2 {
        assert_eq!(dir.0.join(revision_file(n)).exists(), n < 2, "revision {n}");
    }
    let first = fs::read(dir.0.join(revision_file(1))).unwrap();
    let slot = fs::read_to_string(dir.0.join(CURRENT)).unwrap();
    assert_eq!(slot.matches("\"number\":").count(), 1, "{slot}");
    let torn = dir.0.join(format!("{}.tmp", revision_file(3)));
    fs::write(&torn, "{").unwrap();

    let mut s = boot(&dir);
    assert!(!torn.exists());
    let history: Vec<u32> = s.store().history().iter().map(|r| r.number).collect();
    assert_eq!(history, [0, 1, 2]);
    add(&mut s, "10.0.2.1/24");
    assert_eq!(fs::read(dir.0.join(revision_file(1))).unwrap(), first);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(!dir.0.join(revision_file(3)).exists());
        let mode = fs::metadata(dir.0.join(revision_file(2)))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    s.execute("config.rollback", &json!({"revision": 1}))
        .unwrap();
    assert_eq!(addresses(&s), ["10.0.0.1/24"]);
}
