//! G1.23: the history is kept one file per revision, so a commit writes the
//! running config and one revision, not the whole history again.
//! audit-history: each file is the difference to the next newer revision,
//! so the whole history of a big config fits the save budget.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::{Arc, Mutex};

use corerouter_engine::{ConfigStorage, MemoryStorage, Session, Slot, StorageError};
use corerouter_hal::VirtualHal;
use corerouter_model::cow::CowArc;
use corerouter_model::cow_list::CowList;
use corerouter_model::store::Revision;
use corerouter_model::{ConfigStore, Users, persist};
use serde_json::json;

fn boot(storage: &MemoryStorage) -> Session {
    Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()))
}

fn rename(s: &mut Session, name: &str) {
    s.execute("system.identity.set", &json!({"name": name}))
        .unwrap();
}

/// A config with `n` address-list entries (~125 bytes each) committed once.
fn big(s: &mut Session, n: u32) {
    let steps: Vec<_> = (0..n)
        .map(|i| {
            json!({"command": "ip.firewall.address-list.add", "params": {
                "list": "customers",
                "address": format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256),
                "comment": "customer with a long enough comment"}})
        })
        .collect();
    s.batch(&json!(steps), true).unwrap();
}

fn numbers(s: &Session) -> Vec<u32> {
    s.store().history().iter().map(|r| r.number).collect()
}

#[test]
fn a_commit_writes_one_small_revision_file_not_the_whole_history() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    big(&mut s, 2000);
    for i in 0..20 {
        rename(&mut s, &format!("r{i}"));
    }
    let one = persist::encoded_len(s.store().running());
    assert!(one > 100_000, "{one}");
    // The slot holds the running config and its newest revision: twice
    // the config, not 22 copies (it held every revision before G1.23).
    let slot = storage.get(Slot::Current).unwrap().len();
    assert!(slot < 3 * one, "slot of {slot} bytes, config of {one}");
    // Each older revision is a file of its own holding a difference: the
    // 21 of them together are smaller than one copy of the config (they
    // were 21 copies before audit-history).
    assert!(
        storage.revision_bytes() < one,
        "{}",
        storage.revision_bytes()
    );
    // The newest is only in the slot; its file comes with the next commit,
    // and a file is written once.
    assert_eq!(s.store().current_revision(), 21);
    assert_eq!(storage.revision(21), None);
    let before = storage.revision(20).unwrap();
    assert!(before.contains("\"base\":21"), "{before}");
    rename(&mut s, "again");
    assert_eq!(storage.revision(20).unwrap(), before, "rewritten");
    assert!(storage.revision(21).unwrap().contains("\"r19\""));
    assert_eq!(storage.revision(22), None);
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
    // Only the older revisions still in the history have files.
    for n in 0..=70 {
        assert_eq!(
            storage.revision(n).is_some(),
            (7..70).contains(&n),
            "revision {n}"
        );
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

/// Fail-first for audit-history: with full copies a ~750 KB config kept
/// 42 of its 64 revisions in the 32 MiB budget (6 of a 5 MiB config,
/// **medido** in `storage_fs/history64`); as differences all of them fit.
#[test]
fn all_64_revisions_of_a_big_config_survive_a_reboot() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    big(&mut s, 6000);
    for i in 0..63 {
        // Small changes, anywhere in the config.
        if i % 2 == 0 {
            rename(&mut s, &format!("r{i}"));
        } else {
            s.execute(
                "ip.firewall.address-list.set",
                &json!({"id": format!("*{:X}", 1 + i * 90), "comment": format!("c{i}")}),
            )
            .unwrap();
        }
    }
    let one = persist::encoded_len(s.store().running());
    assert!(
        64 * one > persist::SAVE_BUDGET_BYTES,
        "config of {one} bytes"
    );
    let memory: Vec<Revision> = s.store().history().to_vec();
    assert_eq!(memory.len(), 64);
    assert_eq!(s.storage_status().revisions_not_saved, 0);
    drop(s);

    let mut s = boot(&storage);
    assert!(
        s.storage_status().boot_errors.is_empty(),
        "{:?}",
        s.storage_status().boot_errors
    );
    let back = s.store().history();
    assert_eq!(back.len(), 64);
    for (a, b) in memory.iter().zip(back) {
        assert_eq!(
            (a.number, &a.comment, a.timestamp),
            (b.number, &b.comment, b.timestamp)
        );
        assert!(a.config == b.config, "revision {} differs", a.number);
    }
    // Built from each other: a section two neighbours have equal is one
    // allocation (64 revisions cost about one config in memory). The
    // sections no commit touched are one for the whole history.
    for pair in back.windows(2) {
        let (old, new) = (&pair[0].config, &pair[1].config);
        let n = pair[0].number;
        assert_eq!(
            *old.ip == *new.ip,
            CowArc::ptr_eq(&old.ip, &new.ip),
            "ip of {n}"
        );
        let (a, b) = (&old.ip.firewall, &new.ip.firewall);
        assert_eq!(**a == **b, CowArc::ptr_eq(a, b), "firewall of {n}");
        let (a, b) = (&a.address_lists, &b.address_lists);
        assert_eq!(*a == *b, CowList::ptr_eq(a, b), "address lists of {n}");
    }
    let newest = &back[63].config;
    for rev in back {
        let c = &rev.config;
        assert!(CowArc::ptr_eq(&c.interfaces, &newest.interfaces));
        assert!(CowList::ptr_eq(&c.ip.routes, &newest.ip.routes));
        assert!(CowList::ptr_eq(&c.ip.addresses, &newest.ip.addresses));
        assert!(CowList::ptr_eq(
            &c.ip.firewall.filter,
            &newest.ip.firewall.filter
        ));
        assert!(CowArc::ptr_eq(&c.ip.dhcp_server, &newest.ip.dhcp_server));
    }
    // Rolling back to the oldest gives its exact config.
    let oldest = memory[0].number;
    s.execute("config.rollback", &json!({"revision": oldest}))
        .unwrap();
    assert!(*s.store().running() == memory[0].config);
}

#[test]
fn a_broken_revision_file_costs_it_and_the_older_ones_only() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    for i in 0..8 {
        rename(&mut s, &format!("r{i}"));
    }
    drop(s);
    // Revision 4 damaged: 5..8 still restore, 0..3 depended on it.
    let good = storage.revision(4).unwrap();
    storage.put_revision(4, Some(good.get(..good.len() / 2).unwrap().into()));

    let mut s = boot(&storage);
    let errors = s.storage_status().boot_errors.clone();
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(errors[0].starts_with("revision 4:"), "{errors:?}");
    assert!(
        errors[1].starts_with("revisions 0..3: 4 left out"),
        "{errors:?}"
    );
    assert_eq!(numbers(&s), [5, 6, 7, 8]);
    assert_eq!(s.store().history()[0].config.system.identity, "r4");
    // The next save leaves out the files of the revisions not in the history.
    rename(&mut s, "r8");
    for n in 0..=4 {
        assert_eq!(storage.revision(n), None, "revision {n}");
    }
    drop(s);
    let s = boot(&storage);
    assert!(s.storage_status().boot_errors.is_empty());
    assert_eq!(numbers(&s), [5, 6, 7, 8, 9]);
}

#[test]
fn a_difference_that_does_not_fit_its_base_is_refused() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    for i in 0..5 {
        rename(&mut s, &format!("r{i}"));
    }
    drop(s);
    // Hostile or mismatched: a copy run past the end, a delta against a
    // revision that is not the next one, a file holding another number.
    for (n, text) in [
        (
            3,
            r#"{"format_version":1,"number":3,"comment":"x","timestamp":null,"base":4,"delta":{"o":{"interfaces":{"a":[[0,99]]}}}}"#,
        ),
        (
            3,
            r#"{"format_version":1,"number":3,"comment":"x","timestamp":null,"base":5,"delta":{}}"#,
        ),
        (
            3,
            r#"{"format_version":1,"number":3,"comment":"x","timestamp":null,"base":2,"delta":{}}"#,
        ),
        (
            3,
            r#"{"format_version":1,"number":3,"comment":"x","timestamp":null,"base":4,"delta":{"o":{"system":{"=":7}}}}"#,
        ),
    ] {
        let copy = MemoryStorage::default();
        copy.put(Slot::Current, storage.get(Slot::Current));
        for k in 0..5 {
            copy.put_revision(k, storage.revision(k));
        }
        copy.put_revision(n, Some(text.into()));
        let s = boot(&copy);
        assert_eq!(numbers(&s), [4, 5], "{text}");
        assert_eq!(s.store().running().system.identity, "r4");
        assert!(!s.storage_status().boot_errors.is_empty(), "{text}");
    }
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
fn full_copy_revision_files_from_g1_23_load_and_become_differences() {
    // What G1.23 builds wrote: the slot with the newest revision and a
    // full copy in every revision file, the newest's included.
    let mut store = ConfigStore::default();
    for i in 0..10 {
        store.candidate_mut().system.identity = format!("r{i}");
        store.commit("g1.23", None).unwrap();
    }
    let storage = MemoryStorage::default();
    for rev in store.history() {
        let config = persist::encode_config(&rev.config).unwrap();
        storage.put_revision(
            rev.number,
            Some(persist::encode_revision(rev, &config).unwrap()),
        );
    }
    let newest = store.history().last().unwrap();
    let config = persist::encode_config(&newest.config).unwrap();
    storage.put(
        Slot::Current,
        Some(persist::encode_running(newest, &config, &Users::default()).unwrap()),
    );
    let full = storage.revision_bytes();

    let mut s = boot(&storage);
    assert!(s.storage_status().boot_errors.is_empty());
    assert_eq!(numbers(&s), (0..=10).collect::<Vec<_>>());
    rename(&mut s, "new");
    drop(s);
    // Migrated by that commit: every file a difference, the newest none.
    for n in 0..=10 {
        assert!(
            storage.revision(n).unwrap().contains("\"delta\""),
            "revision {n}"
        );
    }
    assert_eq!(storage.revision(11), None);
    assert!(
        storage.revision_bytes() < full,
        "{} ≥ {full}",
        storage.revision_bytes()
    );
    let s = boot(&storage);
    assert_eq!(numbers(&s), (0..=11).collect::<Vec<_>>());
    assert_eq!(s.store().history()[3].config.system.identity, "r2");
    assert_eq!(s.store().history()[3].comment, "g1.23");
}

#[test]
fn a_revision_file_newer_than_the_slot_is_replaced() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    rename(&mut s, "one");
    rename(&mut s, "two");
    drop(s);
    // A save cut short after the file of revision 3, before its slot; and
    // a damaged current slot: the boot falls back to revision 1, and the
    // file of revision 1 (a difference against 2, which is lost) is not
    // used either.
    let stray = storage
        .revision(1)
        .unwrap()
        .replace("\"number\":1", "\"number\":3");
    storage.put_revision(3, Some(stray));
    storage.put(Slot::Current, Some("{".into()));

    let mut s = boot(&storage);
    assert_eq!(s.storage_status().loaded_from, Some("previous"));
    assert_eq!(numbers(&s), [0, 1]);
    assert_eq!(s.store().running().system.identity, "one");
    rename(&mut s, "other");
    rename(&mut s, "third");
    drop(s);
    let s = boot(&storage);
    assert!(s.storage_status().boot_errors.is_empty());
    assert_eq!(numbers(&s), [0, 1, 2, 3]);
    assert_eq!(s.store().history()[1].config.system.identity, "one");
    assert_eq!(s.store().history()[2].config.system.identity, "other");
    assert_eq!(s.store().history()[3].config.system.identity, "third");
}

/// A storage whose next write of `fail` kind fails (a crash between the
/// steps of a save: what was written before it stays, nothing after).
#[derive(Clone, Default)]
struct Flaky {
    inner: MemoryStorage,
    fail: Arc<Mutex<Option<&'static str>>>,
}

impl Flaky {
    fn fail_next(&self, what: &'static str) {
        *self.fail.lock().unwrap() = Some(what);
    }
    fn check(&self, what: &str) -> Result<(), StorageError> {
        let mut f = self.fail.lock().unwrap();
        if *f == Some(what) {
            *f = None;
            return Err(StorageError(format!("{what}: power cut")));
        }
        Ok(())
    }
}

impl ConfigStorage for Flaky {
    fn describe(&self) -> String {
        "flaky".into()
    }
    fn load(&mut self, slot: Slot) -> Result<Option<String>, StorageError> {
        self.inner.load(slot)
    }
    fn save(&mut self, data: &str) -> Result<(), StorageError> {
        self.check("slot")?;
        self.inner.save(data)
    }
    fn quarantine(&mut self, slot: Slot) -> Result<(), StorageError> {
        self.inner.quarantine(slot)
    }
    fn revision_files(&self) -> bool {
        true
    }
    fn list_revisions(&mut self) -> Result<Vec<u32>, StorageError> {
        self.inner.list_revisions()
    }
    fn load_revision(&mut self, number: u32) -> Result<Option<String>, StorageError> {
        self.inner.load_revision(number)
    }
    fn save_revision(&mut self, number: u32, data: &str) -> Result<(), StorageError> {
        self.check("revision")?;
        self.inner.save_revision(number, data)
    }
    fn remove_revision(&mut self, number: u32) -> Result<(), StorageError> {
        self.check("remove")?;
        self.inner.remove_revision(number)
    }
}

#[test]
fn a_crash_between_the_steps_of_a_save_loses_only_that_revision() {
    for step in ["revision", "slot", "remove"] {
        let storage = Flaky::default();
        let mut s =
            Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()));
        for i in 0..70 {
            rename(&mut s, &format!("r{i}"));
        }
        let before = numbers(&s);
        // The crash: this commit's save stops at `step`, the process dies.
        storage.fail_next(step);
        rename(&mut s, "in flight");
        let in_flight = numbers(&s);
        if step == "remove" {
            // Everything was written; only a stale file is left behind.
            assert!(s.storage_status().last_error.is_none());
        } else {
            assert!(s.storage_status().last_error.is_some(), "{step}");
        }
        drop(s);

        let mut s =
            Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()));
        assert!(
            s.storage_status().boot_errors.is_empty(),
            "{step}: {:?}",
            s.storage_status().boot_errors
        );
        let expected = if step == "remove" {
            &in_flight
        } else {
            &before
        };
        assert_eq!(&numbers(&s), expected, "{step}");
        let identity = if step == "remove" { "in flight" } else { "r69" };
        assert_eq!(s.store().running().system.identity, identity, "{step}");
        // And the next commits carry on.
        rename(&mut s, "after");
        let after = numbers(&s);
        drop(s);
        let s = Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()));
        assert!(s.storage_status().boot_errors.is_empty(), "{step}");
        assert_eq!(numbers(&s), after, "{step}");
        assert_eq!(
            s.store().history()[0].config.system.identity,
            format!("r{}", after[0] - 1)
        );
        assert_eq!(
            storage.inner.revision(after[0] - 1),
            None,
            "{step}: stale file left"
        );
    }
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
    assert_eq!(storage.revision(1), None);
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
