//! G1.23: the history is kept one file per revision, so a commit writes the
//! running config and its own revision, not the whole history again.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use corerouter_engine::{MemoryStorage, Session, Slot};
use corerouter_hal::VirtualHal;
use corerouter_model::{ConfigStore, persist};
use serde_json::json;

fn boot(storage: &MemoryStorage) -> Session {
    Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()))
}

fn rename(s: &mut Session, name: &str) {
    s.execute("system.identity.set", &json!({"name": name}))
        .unwrap();
}

/// A config of ~250 KB (2000 address-list entries) committed once.
fn big(s: &mut Session) {
    let steps: Vec<_> = (0..2000u32)
        .map(|i| {
            json!({"command": "ip.firewall.address-list.add", "params": {
                "list": "customers",
                "address": format!("10.{}.{}.0/24", i / 256, i % 256),
                "comment": "customer with a long enough comment"}})
        })
        .collect();
    s.batch(&json!(steps), true).unwrap();
}

fn numbers(s: &Session) -> Vec<u32> {
    s.store().history().iter().map(|r| r.number).collect()
}

#[test]
fn a_commit_writes_its_revision_not_the_whole_history() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    big(&mut s);
    for i in 0..20 {
        rename(&mut s, &format!("r{i}"));
    }
    let one = persist::encoded_len(s.store().running());
    assert!(one > 100_000, "{one}");
    // The slot holds the running config and its newest revision: twice
    // the config, not 22 copies (it held every revision before G1.23).
    let slot = storage.get(Slot::Current).unwrap().len();
    assert!(slot < 3 * one, "slot of {slot} bytes, config of {one}");
    // Each revision is in a file of its own, written once.
    assert!(storage.revision_bytes() > 20 * one);
    let before = storage.revision(21).unwrap();
    rename(&mut s, "again");
    assert_eq!(storage.revision(21).unwrap(), before, "rewritten");
    assert!(storage.revision(22).unwrap().contains("\"again\""));
}

#[test]
fn the_history_survives_a_reboot_and_old_files_are_deleted() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    for i in 0..70 {
        rename(&mut s, &format!("r{i}"));
    }
    let history = numbers(&s);
    assert_eq!(history.len(), ConfigStore::DEFAULT_MAX_HISTORY);
    drop(s);
    // Only the revisions still in the history have files.
    for n in 0..=70 {
        assert_eq!(storage.revision(n).is_some(), n >= 7, "revision {n}");
    }

    let mut s = boot(&storage);
    assert!(s.storage_status().boot_errors.is_empty());
    assert_eq!(numbers(&s), history);
    assert_eq!(s.store().history()[0].config.system.identity, "r6");
    assert_eq!(s.store().history()[0].comment, "system.identity.set");
    s.execute("config.rollback", &json!({"revision": 7}))
        .unwrap();
    assert_eq!(s.store().running().system.identity, "r6");
}

#[test]
fn an_unreadable_revision_file_costs_that_revision_only() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    for i in 0..5 {
        rename(&mut s, &format!("r{i}"));
    }
    drop(s);
    let good = storage.revision(2).unwrap();
    storage.put_revision(2, Some(good.get(..good.len() / 2).unwrap().into()));
    storage.put_revision(3, Some(storage.revision(4).unwrap()));
    storage.put_revision(1, None);

    let mut s = boot(&storage);
    let errors = &s.storage_status().boot_errors;
    // A deleted file leaves no trace to report; a damaged one is reported.
    assert_eq!(errors.len(), 2, "{errors:?}");
    for n in 2..=3 {
        assert!(
            errors
                .iter()
                .any(|e| e.starts_with(&format!("revision {n}:"))),
            "{errors:?}"
        );
    }
    assert_eq!(numbers(&s), [0, 4, 5]);
    // The next save leaves out the files of the revisions not in the history.
    rename(&mut s, "r5");
    for n in 1..=3 {
        assert_eq!(storage.revision(n), None, "revision {n}");
    }
    drop(s);
    assert_eq!(numbers(&boot(&storage)), [0, 4, 5, 6]);
}

#[test]
fn a_file_with_the_whole_history_from_an_older_build_loads_and_moves_to_files() {
    // What builds before G1.23 wrote: every revision in the slot.
    let mut store = ConfigStore::default();
    for i in 0..10 {
        store.candidate_mut().system.identity = format!("r{i}");
        store.commit("old", None).unwrap();
    }
    let storage = MemoryStorage::default();
    storage.put(Slot::Current, Some(persist::encode(&store).unwrap()));

    let mut s = boot(&storage);
    assert_eq!(numbers(&s), (0..=10).collect::<Vec<_>>());
    rename(&mut s, "new");
    drop(s);
    let slot = persist::decode(&storage.get(Slot::Current).unwrap()).unwrap();
    assert_eq!(slot.history().len(), 1, "the slot keeps the newest only");
    let s = boot(&storage);
    assert_eq!(numbers(&s), (0..=11).collect::<Vec<_>>());
    assert_eq!(s.store().history()[3].config.system.identity, "r2");
    assert_eq!(s.store().history()[3].comment, "old");
}

#[test]
fn a_revision_file_newer_than_the_slot_is_replaced() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    rename(&mut s, "one");
    rename(&mut s, "two");
    drop(s);
    // A save cut short after the file of revision 3, before its slot; and
    // a damaged current slot: the boot falls back to revision 1.
    let stray = storage
        .revision(2)
        .unwrap()
        .replace("\"number\":2", "\"number\":3");
    storage.put_revision(3, Some(stray));
    storage.put(Slot::Current, Some("{".into()));

    let mut s = boot(&storage);
    assert_eq!(s.storage_status().loaded_from, Some("previous"));
    assert_eq!(numbers(&s), [0, 1]);
    rename(&mut s, "other");
    rename(&mut s, "third");
    drop(s);
    let s = boot(&storage);
    assert_eq!(numbers(&s), [0, 1, 2, 3]);
    assert_eq!(s.store().history()[2].config.system.identity, "other");
    assert_eq!(s.store().history()[3].config.system.identity, "third");
}

#[test]
fn safe_mode_saves_nothing_of_its_revisions() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    rename(&mut s, "kept");
    s.execute("config.safe-mode.enter", &json!({})).unwrap();
    rename(&mut s, "unconfirmed");
    rename(&mut s, "unconfirmed-2");
    drop(s);
    assert_eq!(storage.revision(2), None);
    let mut s = boot(&storage);
    assert_eq!(s.store().running().system.identity, "kept");
    assert_eq!(numbers(&s), [0, 1]);
    rename(&mut s, "after");
    drop(s);
    let s = boot(&storage);
    assert_eq!(numbers(&s), [0, 1, 2]);
    assert_eq!(s.store().running().system.identity, "after");
}
