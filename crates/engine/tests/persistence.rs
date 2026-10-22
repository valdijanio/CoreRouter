//! G0.6: the committed config survives a "reboot" (a new Session on the same
//! storage), and a damaged save falls back to the previous one.
#![allow(clippy::unwrap_used)]

use corerouter_engine::{MemoryStorage, Session, Slot};
use corerouter_hal::VirtualHal;
use serde_json::json;

fn boot(storage: &MemoryStorage) -> Session {
    Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()))
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
fn fresh_storage_starts_from_discovered_ports() {
    let storage = MemoryStorage::default();
    let s = boot(&storage);
    assert_eq!(s.store().current_revision(), 0);
    assert_eq!(s.store().running().interfaces.len(), 8);
    assert_eq!(s.storage_status().loaded_from, None);
    // Nothing is written until the first commit.
    assert_eq!(storage.get(Slot::Current), None);
}

#[test]
fn commit_is_saved_and_restored() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    add(&mut s, "10.0.0.1/24");
    s.execute("system.identity.set", &json!({"name": "edge-1"}))
        .unwrap();
    let running = s.store().running().clone();
    drop(s);

    let mut s = boot(&storage);
    assert_eq!(s.store().running(), &running);
    assert!(!s.store().is_dirty());
    assert_eq!(s.store().current_revision(), 2);
    assert_eq!(s.store().history().len(), 3);
    assert_eq!(s.storage_status().loaded_from, Some("current"));
    let summary = s.inspect(None).unwrap();
    assert_eq!(summary["storage"]["loaded_from"], "current");
    assert_eq!(summary["identity"], "edge-1");

    // Item ids continue after the restored ones; numbering too.
    add(&mut s, "10.0.1.1/24");
    let ids: Vec<_> = s
        .store()
        .running()
        .ip
        .addresses
        .iter()
        .map(|a| a.id.to_string())
        .collect();
    assert_eq!(ids, ["*1", "*2"]);
    assert_eq!(s.store().current_revision(), 3);

    // History survives: roll back to before the first address.
    s.execute("config.rollback", &json!({"revision": 0}))
        .unwrap();
    assert!(addresses(&s).is_empty());
}

#[test]
fn uncommitted_candidate_is_not_saved() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    add(&mut s, "10.0.0.1/24");
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    add(&mut s, "10.0.1.1/24");
    drop(s);
    assert_eq!(addresses(&boot(&storage)), ["10.0.0.1/24"]);
}

#[test]
fn corrupt_current_falls_back_to_previous() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    add(&mut s, "10.0.0.1/24");
    add(&mut s, "10.0.1.1/24");
    drop(s);
    let good = storage.get(Slot::Current).unwrap();
    storage.put(Slot::Current, good.get(..good.len() / 2).map(str::to_owned));

    let mut s = boot(&storage);
    assert_eq!(addresses(&s), ["10.0.0.1/24"]);
    assert_eq!(s.store().current_revision(), 1);
    let status = s.storage_status();
    assert_eq!(status.loaded_from, Some("previous"));
    assert_eq!(status.boot_errors.len(), 1);
    assert!(status.boot_errors[0].starts_with("current:"));
    assert_eq!(storage.quarantined(), 1);
    assert_eq!(storage.get(Slot::Current), None);

    // The next save must not rotate garbage over the good previous slot.
    add(&mut s, "10.0.2.1/24");
    assert!(storage.get(Slot::Previous).unwrap().contains("10.0.0.1/24"));
    drop(s);
    assert_eq!(addresses(&boot(&storage)), ["10.0.0.1/24", "10.0.2.1/24"]);
}

#[test]
fn unknown_version_falls_back_too() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    add(&mut s, "10.0.0.1/24");
    add(&mut s, "10.0.1.1/24");
    drop(s);
    let newer = storage.get(Slot::Current).unwrap().replacen(
        "\"format_version\": 1",
        "\"format_version\": 2",
        1,
    );
    storage.put(Slot::Current, Some(newer));

    let s = boot(&storage);
    assert_eq!(s.storage_status().loaded_from, Some("previous"));
    assert!(s.storage_status().boot_errors[0].contains("format_version 2"));
}

#[test]
fn both_slots_unreadable_starts_fresh_without_panic() {
    let storage = MemoryStorage::default();
    storage.put(Slot::Current, Some("{\"format_version\": 1".into()));
    storage.put(Slot::Previous, Some("\u{0}garbage".into()));
    let s = boot(&storage);
    assert_eq!(s.store().current_revision(), 0);
    assert_eq!(s.store().running().interfaces.len(), 8);
    assert_eq!(s.storage_status().boot_errors.len(), 2);
    assert_eq!(storage.quarantined(), 2);
}

#[test]
fn missing_current_uses_previous() {
    // A crash between "current → previous" and "new → current" renames.
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    add(&mut s, "10.0.0.1/24");
    add(&mut s, "10.0.1.1/24");
    drop(s);
    storage.put(Slot::Current, None);
    let s = boot(&storage);
    assert_eq!(s.storage_status().loaded_from, Some("previous"));
    assert!(s.storage_status().boot_errors.is_empty());
    assert_eq!(addresses(&s), ["10.0.0.1/24"]);
}
