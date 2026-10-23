//! G0.6: the committed config survives a "reboot" (a new Session on the same
//! storage), and a damaged save falls back to the previous one.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use corerouter_engine::{MemoryStorage, Session, Slot};
use corerouter_hal::{Hal, HalError, LinkInfo, LinkState, VirtualHal};
use corerouter_model::Config;
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
        "\"format_version\":1",
        "\"format_version\":2",
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

/// Audit #1: a big config (thousands of address-list entries) with a full history
/// used to make a file over the read limit, so the router booted blank. The
/// save now trims the oldest revisions to fit; the running config always
/// comes back.
#[test]
fn a_big_config_with_a_full_history_still_boots() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    let comment = "c".repeat(200);
    for i in 0..4000u32 {
        s.execute(
            "ip.firewall.address-list.add",
            &json!({"list": "customers",
                    "address": format!("10.{}.{}.0/24", i / 256, i % 256),
                    "comment": comment}),
        )
        .unwrap();
    }
    s.execute("config.commit", &json!({})).unwrap();
    // 64 more revisions, saved once at the end (Safe Mode holds the saves).
    s.execute("config.safe-mode.enter", &json!({})).unwrap();
    for i in 0..64 {
        s.execute("system.identity.set", &json!({"name": format!("r{i}")}))
            .unwrap();
        s.execute("config.commit", &json!({})).unwrap();
    }
    s.execute("config.safe-mode.exit", &json!({})).unwrap();
    assert_eq!(s.storage_status().last_error, None);
    let saved = storage.get(Slot::Current).unwrap();
    assert!(
        saved.len() <= corerouter_model::persist::SAVE_BUDGET_BYTES,
        "{} bytes",
        saved.len()
    );
    let running = s.store().running().clone();
    drop(s);

    let s = boot(&storage);
    let status = s.storage_status();
    assert!(status.boot_errors.is_empty(), "{:?}", status.boot_errors);
    assert_eq!(status.loaded_from, Some("current"));
    assert_eq!(s.store().running(), &running);
    assert_eq!(s.store().current_revision(), 65);
    // Every revision kept: the older ones are differences (audit-history;
    // as full copies only the newest fit).
    assert_eq!(s.store().history().len(), 64);
}

/// Audit #11: a hand-edited file whose id counter is behind its items
/// would hand out an id already in use.
#[test]
fn a_counter_behind_its_items_is_repaired_on_load() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    add(&mut s, "10.0.0.1/24");
    add(&mut s, "10.0.1.1/24");
    drop(s);
    let text = storage.get(Slot::Current).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["running"]["ip"]["next_id"] = 0.into();
    let last = v["history"].as_array().unwrap().len() - 1;
    v["history"][last]["config"]["ip"]["next_id"] = 0.into();
    storage.put(Slot::Current, Some(v.to_string()));

    let mut s = boot(&storage);
    assert_eq!(s.storage_status().loaded_from, Some("current"));
    add(&mut s, "10.0.2.1/24");
    let ids: Vec<_> = s
        .store()
        .running()
        .ip
        .addresses
        .iter()
        .map(|a| a.id.to_string())
        .collect();
    assert_eq!(ids, ["*1", "*2", "*3"]);
}

/// A data plane whose apply fails while `fail` is set (nftables not loaded
/// yet at boot); counts the applies made from an empty config.
struct Flaky {
    inner: VirtualHal,
    fail: Arc<AtomicBool>,
    from_scratch: Arc<AtomicUsize>,
}

impl Hal for Flaky {
    fn describe(&self) -> String {
        "flaky lab".into()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.inner.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(HalError::Rejected("nft not ready".into()));
        }
        if from == &Config::default() {
            self.from_scratch.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.apply(from, to)
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.inner.poll()
    }
    fn now_unix(&self) -> Option<u64> {
        None
    }
}

/// A saved config with one address, booted on a data plane that refuses.
fn boot_on_flaky() -> (Session, Arc<AtomicBool>, Arc<AtomicUsize>) {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    add(&mut s, "10.0.0.1/24");
    drop(s);
    let fail = Arc::new(AtomicBool::new(true));
    let from_scratch = Arc::new(AtomicUsize::new(0));
    let hal = Flaky {
        inner: VirtualHal::default(),
        fail: Arc::clone(&fail),
        from_scratch: Arc::clone(&from_scratch),
    };
    let s = Session::with_storage(Box::new(hal), Box::new(storage));
    (s, fail, from_scratch)
}

fn boot_apply_error(s: &Session) -> serde_json::Value {
    s.inspect(None).unwrap()["storage"]["boot_apply_error"].clone()
}

/// Audit #8: the restored config failing to reach the data plane at boot
/// was only logged; the kernel and `running` then disagreed for good.
#[test]
fn a_failed_boot_apply_is_reported_and_retried() {
    let (mut s, fail, from_scratch) = boot_on_flaky();
    let err = boot_apply_error(&s);
    assert!(
        err.as_str().unwrap_or("").contains("nft not ready"),
        "{err}"
    );
    // Still failing: a tick retries and keeps the error.
    s.tick(1_000);
    assert!(boot_apply_error(&s).is_string());
    // The data plane is back: the next tick installs the whole config.
    fail.store(false, Ordering::SeqCst);
    s.tick(1_001);
    assert_eq!(from_scratch.load(Ordering::SeqCst), 1);
    assert!(boot_apply_error(&s).is_null());
}

/// Audit #8: a commit while the boot apply is still pending applies the
/// whole config, not only the change.
#[test]
fn a_commit_after_a_failed_boot_apply_applies_everything() {
    let (mut s, fail, from_scratch) = boot_on_flaky();
    fail.store(false, Ordering::SeqCst);
    add(&mut s, "10.0.1.1/24");
    assert_eq!(from_scratch.load(Ordering::SeqCst), 1);
    assert!(boot_apply_error(&s).is_null());
}
