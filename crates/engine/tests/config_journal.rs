//! G0.22 — the config journal: a commit appends its delta instead of
//! rewriting the slot with the whole config, and a checkpoint writes the
//! slot now and then. A reboot must give back exactly the store it saved,
//! whatever was cut short; and the previous slot plus the journal must
//! give the newest revision when the current slot is lost.

// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::sync::{Arc, Mutex};

use corerouter_engine::storage::CONFIG_JOURNAL;
use corerouter_engine::{ConfigStorage, MemoryStorage, Session, Slot, StorageError};
use corerouter_hal::VirtualHal;
use serde_json::json;

fn boot(storage: &MemoryStorage) -> Session {
    Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()))
}

fn rename(s: &mut Session, name: &str) {
    s.execute("system.identity.set", &json!({"name": name}))
        .unwrap();
}

fn add(s: &mut Session, i: u32) {
    s.execute(
        "ip.firewall.address-list.add",
        &json!({"list": "l", "address": format!("10.0.{}.{}", i / 256, i % 256)}),
    )
    .unwrap();
}

fn numbers(s: &Session) -> Vec<u32> {
    s.store().history().iter().map(|r| r.number).collect()
}

/// The store `s` holds, compared revision by revision with `t`'s.
fn same_store(s: &Session, t: &Session) {
    assert_eq!(numbers(s), numbers(t));
    for (a, b) in s.store().history().iter().zip(t.store().history()) {
        assert_eq!(a.config, b.config, "revision {}", a.number);
        assert_eq!(a.comment, b.comment);
    }
    assert_eq!(s.store().running(), t.store().running());
}

fn lines(storage: &MemoryStorage) -> usize {
    storage
        .journal(CONFIG_JOURNAL)
        .map_or(0, |j| j.lines().count())
}

#[test]
fn commits_go_to_the_journal_and_a_reboot_gives_the_same_store() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    rename(&mut s, "a");
    rename(&mut s, "b");
    // Both slots written: from now on the slot stays as it is.
    let slot = storage.get(Slot::Current);
    for i in 0..50 {
        add(&mut s, i);
    }
    assert_eq!(storage.get(Slot::Current), slot);
    assert!(lines(&storage) >= 50, "{}", lines(&storage));
    let t = boot(&storage);
    assert!(
        t.storage_status().boot_errors.is_empty(),
        "{:?}",
        t.storage_status().boot_errors
    );
    same_store(&s, &t);
    // A rollback to a revision of before the slot still works after it.
    let mut t = t;
    let old = numbers(&t)[3];
    t.execute("config.rollback", &json!({"revision": old}))
        .unwrap();
    let u = boot(&storage);
    same_store(&t, &u);
}

#[test]
fn a_long_journal_is_checkpointed_into_the_slot() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    for i in 0..1200 {
        add(&mut s, i);
    }
    // The slot was written again past MAX_JOURNAL_LINES lines; the journal
    // keeps the lines past the previous slot only.
    assert!(lines(&storage) < 1200, "{}", lines(&storage));
    let t = boot(&storage);
    assert!(t.storage_status().boot_errors.is_empty());
    same_store(&s, &t);
    // The previous slot plus the journal give the newest too.
    let copy = MemoryStorage::default();
    copy.put(Slot::Previous, storage.get(Slot::Previous));
    copy.put_journal(CONFIG_JOURNAL, storage.journal(CONFIG_JOURNAL));
    for n in 0..1300 {
        copy.put_revision(n, storage.revision(n));
    }
    let u = boot(&copy);
    assert_eq!(u.storage_status().loaded_from, Some("previous"));
    assert_eq!(u.store().running(), s.store().running());
}

#[test]
fn a_torn_last_line_costs_that_commit_only() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    for i in 0..10 {
        add(&mut s, i);
    }
    let before = numbers(&s);
    let j = storage.journal(CONFIG_JOURNAL).unwrap();
    // The crash cut the last line short.
    let cut = j.trim_end().rfind('\n').unwrap() + 1 + 20;
    storage.put_journal(CONFIG_JOURNAL, Some(j.get(..cut).unwrap().into()));
    let mut t = boot(&storage);
    assert!(
        t.storage_status().boot_errors.is_empty(),
        "{:?}",
        t.storage_status().boot_errors
    );
    assert_eq!(numbers(&t), before[..before.len() - 1]);
    // The next commit writes the slot (the journal ends in garbage) and
    // carries on.
    add(&mut t, 500);
    add(&mut t, 501);
    let u = boot(&storage);
    assert!(u.storage_status().boot_errors.is_empty());
    same_store(&t, &u);
}

#[test]
fn a_bad_line_in_the_middle_is_reported_and_the_rest_left_out() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    for i in 0..10 {
        add(&mut s, i);
    }
    let j = storage.journal(CONFIG_JOURNAL).unwrap();
    let mut ls: Vec<String> = j.lines().map(str::to_owned).collect();
    let k = ls.len() / 2;
    ls[k] = ls[k].replace(
        "\"delta\":{",
        "\"delta\":{\"o\":{\"nope\":{\"=\":1}},\"x\":",
    );
    storage.put_journal(CONFIG_JOURNAL, Some(ls.join("\n") + "\n"));
    let t = boot(&storage);
    assert!(!t.storage_status().boot_errors.is_empty());
    assert!(numbers(&t).len() < numbers(&s).len());
}

/// A storage whose next write of `fail` kind fails (the power cut in the
/// middle of a save: what was written before stays, nothing after).
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
    fn load_journal(&mut self, name: &str) -> Result<Option<String>, StorageError> {
        self.inner.load_journal(name)
    }
    fn append_journal(&mut self, name: &str, lines: &str) -> Result<(), StorageError> {
        self.check("append")?;
        self.inner.append_journal(name, lines)
    }
    fn rewrite_journal(&mut self, name: &str, text: &str) -> Result<(), StorageError> {
        self.check("rewrite")?;
        self.inner.rewrite_journal(name, text)
    }
    fn revision_files(&self) -> bool {
        true
    }
    fn config_journal(&self) -> bool {
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

fn boot_flaky(storage: &Flaky) -> Session {
    Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()))
}

/// A power cut at any step of a commit's save, in the journal and at a
/// checkpoint: the reboot has the store as it was, or with the commit in
/// flight, never anything else; and the commits after carry on.
#[test]
fn a_power_cut_at_any_step_loses_at_most_the_commit_in_flight() {
    for commits in [5usize, 1023, 1024, 1025] {
        for step in ["revision", "append", "slot", "rewrite", "remove"] {
            let storage = Flaky::default();
            let mut s = boot_flaky(&storage);
            for i in 0..commits {
                add(&mut s, u32::try_from(i).unwrap());
            }
            let before = s.store().running().clone();
            storage.fail_next(step);
            rename(&mut s, "in flight");
            let in_flight = s.store().running().clone();
            drop(s);
            let mut t = boot_flaky(&storage);
            assert!(
                t.storage_status().boot_errors.is_empty(),
                "{commits} {step}: {:?}",
                t.storage_status().boot_errors
            );
            let got = t.store().running().clone();
            assert!(got == before || got == in_flight, "{commits} {step}");
            rename(&mut t, "after");
            add(&mut t, 60_000);
            let u = boot_flaky(&storage);
            assert!(
                u.storage_status().boot_errors.is_empty(),
                "{commits} {step}"
            );
            same_store(&t, &u);
        }
    }
}

/// The current slot lost after any number of commits: the previous slot
/// and the journal give the newest revision.
#[test]
fn the_previous_slot_and_the_journal_give_the_newest() {
    for commits in [1u32, 2, 3, 40, 1030, 2100] {
        let storage = MemoryStorage::default();
        let mut s = boot(&storage);
        for i in 0..commits {
            add(&mut s, i);
        }
        storage.put(Slot::Current, None);
        let t = boot(&storage);
        if commits == 1 {
            // Only one slot ever written: nothing to fall back on.
            continue;
        }
        assert_eq!(
            t.storage_status().loaded_from,
            Some("previous"),
            "{commits}"
        );
        assert!(
            t.storage_status().boot_errors.is_empty(),
            "{commits}: {:?}",
            t.storage_status().boot_errors
        );
        assert_eq!(t.store().running(), s.store().running(), "{commits}");
    }
}

#[test]
fn a_user_change_is_saved_with_the_slot() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    for i in 0..5 {
        add(&mut s, i);
    }
    s.execute(
        "user.add",
        &json!({"name": "ops", "group": "read", "password": "secret-pass-1"}),
    )
    .unwrap();
    add(&mut s, 99);
    let t = boot(&storage);
    assert!(t.users().get("ops").is_some());
    same_store(&s, &t);
}

#[test]
fn safe_mode_saves_through_the_journal_like_any_commit() {
    for end in ["config.safe-mode.exit", "config.safe-mode.cancel"] {
        let storage = MemoryStorage::default();
        let mut s = boot(&storage);
        for i in 0..5 {
            add(&mut s, i);
        }
        s.execute("config.safe-mode.enter", &json!({})).unwrap();
        for i in 100..103 {
            add(&mut s, i);
        }
        // Unconfirmed: a reboot now boots the config of the entry.
        let t = boot(&storage);
        assert_eq!(
            t.store().running().ip.firewall.address_lists.len(),
            5,
            "{end}"
        );
        s.execute(end, &json!({})).unwrap();
        add(&mut s, 200);
        let u = boot(&storage);
        assert!(u.storage_status().boot_errors.is_empty(), "{end}");
        same_store(&s, &u);
    }
}

/// What a build from before the journal (G0.22) sees of `storage`: the
/// slots and the revision files, no journal.
fn without_journal(storage: &MemoryStorage) -> MemoryStorage {
    let old = MemoryStorage::slots_only();
    old.put(Slot::Current, storage.get(Slot::Current));
    old.put(Slot::Previous, storage.get(Slot::Previous));
    for n in storage.clone().list_revisions().unwrap() {
        old.put_revision(n, storage.revision(n));
    }
    old
}

/// G0.27: the checkpoint of a clean shutdown puts every journaled commit
/// in the slot: a restart replays nothing and gives the same store, a
/// build that ignores the journal (a downgrade) loses no commit, the
/// journal keeps its format (the previous slot plus the journal still
/// give the newest), and a second checkpoint has nothing to write.
#[test]
fn the_shutdown_checkpoint_loses_no_journal_line() {
    for commits in [3u32, 40, 1100] {
        let storage = MemoryStorage::default();
        let mut s = boot(&storage);
        rename(&mut s, "a");
        for i in 0..commits {
            add(&mut s, i);
        }
        assert!(lines(&storage) > 0, "{commits}");
        // Before it, an old build would boot an older revision.
        let stale = boot(&without_journal(&storage));
        assert_ne!(stale.store().running(), s.store().running(), "{commits}");

        assert_eq!(s.checkpoint(), Ok(true), "{commits}");
        assert_eq!(s.checkpoint(), Ok(false), "{commits}");
        let newest = *numbers(&s).last().unwrap();
        let slot = storage.get(Slot::Current).unwrap();
        assert!(
            slot.contains(&format!("\"revision\":{newest}")),
            "{commits}: the slot holds revision {newest}"
        );

        let old = boot(&without_journal(&storage));
        assert!(old.storage_status().boot_errors.is_empty(), "{commits}");
        assert_eq!(old.store().running(), s.store().running(), "{commits}");
        assert_eq!(old.store().current_revision(), newest, "{commits}");

        let mut t = boot(&storage);
        assert!(
            t.storage_status().boot_errors.is_empty(),
            "{commits}: {:?}",
            t.storage_status().boot_errors
        );
        same_store(&s, &t);
        // The restarted session journals again, and nothing was lost.
        add(&mut t, 5000);
        same_store(&t, &boot(&storage));

        // The journal still pairs with the previous slot.
        let lost = MemoryStorage::default();
        lost.put(Slot::Previous, storage.get(Slot::Previous));
        lost.put_journal(CONFIG_JOURNAL, storage.journal(CONFIG_JOURNAL));
        for n in storage.clone().list_revisions().unwrap() {
            lost.put_revision(n, storage.revision(n));
        }
        let u = boot(&lost);
        assert_eq!(u.store().running(), t.store().running(), "{commits}");
    }
}

/// G0.27 in Safe Mode: the checkpoint writes the store of the entry, never
/// the unconfirmed changes.
#[test]
fn the_shutdown_checkpoint_in_safe_mode_saves_the_entry() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    for i in 0..5 {
        add(&mut s, i);
    }
    s.execute("config.safe-mode.enter", &json!({})).unwrap();
    for i in 100..103 {
        add(&mut s, i);
    }
    assert_eq!(s.checkpoint(), Ok(true));
    let old = boot(&without_journal(&storage));
    assert_eq!(old.store().running().ip.firewall.address_lists.len(), 5);
    let t = boot(&storage);
    assert_eq!(t.store().running().ip.firewall.address_lists.len(), 5);
}

/// One step of a random session.
#[derive(Debug, Clone)]
enum Step {
    Add(u16),
    Remove(u16),
    Rename(u8),
    Secret(u16),
    SecretSet(u16),
    SecretRemove(u16),
    Rollback(u8),
    Reboot,
}

fn step() -> impl proptest::strategy::Strategy<Value = Step> {
    use proptest::prelude::*;
    prop_oneof![
        4 => any::<u16>().prop_map(Step::Add),
        2 => any::<u16>().prop_map(Step::Remove),
        1 => any::<u8>().prop_map(Step::Rename),
        3 => (0u16..300).prop_map(Step::Secret),
        2 => (0u16..300).prop_map(Step::SecretSet),
        1 => (0u16..300).prop_map(Step::SecretRemove),
        1 => any::<u8>().prop_map(Step::Rollback),
        1 => Just(Step::Reboot),
    ]
}

fn run(s: &mut Session, st: &Step) {
    // Refusals (a duplicate, a missing item) are part of the sequence.
    let _ = match st {
        Step::Add(i) => s.execute(
            "ip.firewall.address-list.add",
            &json!({"list": "l", "address": format!("10.1.{}.{}", i / 256, i % 256)}),
        ),
        Step::Remove(i) => {
            let id = s
                .store()
                .running()
                .ip
                .firewall
                .address_lists
                .get(usize::from(*i) % s.store().running().ip.firewall.address_lists.len().max(1))
                .map(|e| e.id);
            match id {
                Some(id) => s.execute("ip.firewall.address-list.remove", &json!({"id": id})),
                None => Ok(json!({})),
            }
        }
        Step::Rename(n) => s.execute("system.identity.set", &json!({"name": format!("r{n}")})),
        Step::Secret(n) => s.execute(
            "ppp.secret.add",
            &json!({"name": format!("u{n}"), "password": "p"}),
        ),
        Step::SecretSet(n) => s.execute(
            "ppp.secret.set",
            &json!({"id": format!("u{n}"), "comment": "c"}),
        ),
        Step::SecretRemove(n) => s.execute("ppp.secret.remove", &json!({"id": format!("u{n}")})),
        Step::Rollback(k) => {
            let h = s.store().history();
            let rev = h.get(usize::from(*k) % h.len().max(1)).map(|r| r.number);
            match rev {
                Some(rev) => s.execute("config.rollback", &json!({"revision": rev})),
                None => Ok(json!({})),
            }
        }
        Step::Reboot => Ok(json!({})),
    };
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(48))]
    /// The same commands through the journal and through slot-only saving
    /// (every save writes the slot) give the same store, after every
    /// reboot on the way.
    #[test]
    fn the_journal_saves_what_the_slot_would(steps in proptest::collection::vec(step(), 1..80)) {
        let (journal, slots) = (MemoryStorage::default(), MemoryStorage::slots_only());
        let (mut a, mut b) = (boot(&journal), boot(&slots));
        for st in &steps {
            if matches!(st, Step::Reboot) {
                a = boot(&journal);
                b = boot(&slots);
                proptest::prop_assert!(a.storage_status().boot_errors.is_empty());
            }
            run(&mut a, st);
            run(&mut b, st);
        }
        same_store(&a, &b);
        let c = boot(&journal);
        same_store(&a, &c);
    }
}
